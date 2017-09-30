# tripledeskw.py - implementation of Triple DES key wrapping
# coding: utf-8
#
# Copyright (C) 2014-2017 Arthur de Jong
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
import hashlib
import os

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from pskc.exceptions import DecryptionError, EncryptionError


def _cms_hash(value):
    """Return the key hash algorithm described in RFC 3217 section 2."""
    return hashlib.sha1(value).digest()[:8]


RFC3217_IV = binascii.a2b_hex('4adda22c79e82105')


def wrap(plaintext, key, iv=None):
    """Wrap one key (typically a Triple DES key) with another Triple DES key.

    This uses the algorithm from RFC 3217 to encrypt the plaintext (the key
    to wrap) using the provided key. If the iv is None, it is randomly
    generated.
    """
    if 8 * len(plaintext) % algorithms.TripleDES.block_size != 0:
        raise EncryptionError('Plaintext length wrong')
    if iv is None:
        iv = os.urandom(8)
    backend = default_backend()
    cipher = Cipher(algorithms.TripleDES(key), modes.CBC(iv), backend)
    encryptor = cipher.encryptor()
    tmp = (
        iv + encryptor.update(plaintext + _cms_hash(plaintext)) +
        encryptor.finalize())
    cipher = Cipher(algorithms.TripleDES(key), modes.CBC(RFC3217_IV), backend)
    encryptor = cipher.encryptor()
    return encryptor.update(tmp[::-1]) + encryptor.finalize()


def unwrap(ciphertext, key):
    """Unwrap a key (typically Triple DES key ) with another Triple DES key.

    This uses the algorithm from RFC 3217 to decrypt the ciphertext (the
    previously wrapped key) using the provided key.
    """
    if 8 * len(ciphertext) % algorithms.TripleDES.block_size != 0:
        raise DecryptionError('Ciphertext length wrong')
    backend = default_backend()
    cipher = Cipher(algorithms.TripleDES(key), modes.CBC(RFC3217_IV), backend)
    decryptor = cipher.decryptor()
    tmp = (decryptor.update(ciphertext) + decryptor.finalize())[::-1]
    cipher = Cipher(algorithms.TripleDES(key), modes.CBC(tmp[:8]), backend)
    decryptor = cipher.decryptor()
    tmp = decryptor.update(tmp[8:]) + decryptor.finalize()
    if tmp[-8:] == _cms_hash(tmp[:-8]):
        return tmp[:-8]
    raise DecryptionError('CMS key checksum error')
