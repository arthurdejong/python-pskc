# tripledeskw.py - implementation of Triple DES key wrapping
# coding: utf-8
#
# Copyright (C) 2014-2015 Arthur de Jong
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 2.1 of the License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
# 02110-1301 USA

"""Implement Triple DES key wrapping as described in RFC 3217."""

import binascii

from Crypto import Random
from Crypto.Cipher import DES3
from Crypto.Hash import SHA

from pskc.exceptions import EncryptionError, DecryptionError


def _cms_hash(value):
    """The key checksum algorithm described in RFC 3217 section 2."""
    return SHA.new(value).digest()[:8]


RFC3217_IV = binascii.a2b_hex('4adda22c79e82105')


def wrap(plaintext, key, iv=None):
    """Wrap one key (typically a Triple DES key) with another Triple DES key.

    This uses the algorithm from RFC 3217 to encrypt the plaintext (the key
    to wrap) using the provided key. If the iv is None, it is randomly
    generated."""
    if len(plaintext) % DES3.block_size != 0:
        raise EncryptionError('Plaintext length wrong')
    if iv is None:
        iv = Random.get_random_bytes(8)
    cipher = DES3.new(key, DES3.MODE_CBC, iv)
    tmp = iv + cipher.encrypt(plaintext + _cms_hash(plaintext))
    cipher = DES3.new(key, DES3.MODE_CBC, RFC3217_IV)
    return cipher.encrypt(tmp[::-1])


def unwrap(ciphertext, key):
    """Unwrap a key (typically Triple DES key ) with another Triple DES key.

    This uses the algorithm from RFC 3217 to decrypt the ciphertext (the
    previously wrapped key) using the provided key."""
    if len(ciphertext) % DES3.block_size != 0:
        raise DecryptionError('Ciphertext length wrong')
    cipher = DES3.new(key, DES3.MODE_CBC, RFC3217_IV)
    tmp = cipher.decrypt(ciphertext)[::-1]
    cipher = DES3.new(key, DES3.MODE_CBC, tmp[:8])
    tmp = cipher.decrypt(tmp[8:])
    if tmp[-8:] == _cms_hash(tmp[:-8]):
        return tmp[:-8]
    raise DecryptionError('CMS key checksum error')
