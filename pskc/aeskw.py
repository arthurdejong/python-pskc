# aeskw.py - implementation of AES key wrapping
# coding: utf-8
#
# Copyright (C) 2014 Arthur de Jong
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

"""Implement key wrapping as described in RFC 3394."""

from Crypto.Cipher import AES
from Crypto.Util.number import long_to_bytes
from Crypto.Util.strxor import strxor

from pskc.exceptions import EncryptionError, DecryptionError


def _split(value):
    return value[:8], value[8:]


RFC3394_IV = 'a6a6a6a6a6a6a6a6'.decode('hex')


def wrap(plaintext, key):
    """Apply the AES key wrap algorithm to the plaintext."""

    if len(plaintext) % 8 != 0 or len(plaintext) < 16:
        raise EncryptionError('Plaintext length wrong')

    encrypt = AES.new(key).encrypt
    n = len(plaintext) / 8
    A = RFC3394_IV
    R = [plaintext[i * 8:i * 8 + 8]
         for i in range(n)]
    for j in range(6):
        for i in range(n):
            A, R[i] = _split(encrypt(A + R[i]))
            A = strxor(A, long_to_bytes(n * j + i + 1, 8))
    return A + ''.join(R)


def unwrap(ciphertext, key):
    """Apply the AES key unwrap algorithm to the ciphertext."""

    if len(ciphertext) % 8 != 0 or len(ciphertext) < 24:
        raise DecryptionError('Ciphertext length wrong')

    decrypt = AES.new(key).decrypt
    n = len(ciphertext) / 8 - 1
    A = ciphertext[:8]
    R = [ciphertext[(i + 1) * 8:(i + 2) * 8]
         for i in range(n)]
    for j in reversed(range(6)):
        for i in reversed(range(n)):
            A = strxor(A, long_to_bytes(n * j + i + 1, 8))
            A, R[i] = _split(decrypt(A + R[i]))

    if A == RFC3394_IV:
        return ''.join(R)
    raise DecryptionError('IV does not match')
