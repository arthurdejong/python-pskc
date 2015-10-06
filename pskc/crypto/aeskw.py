# aeskw.py - implementation of AES key wrapping
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

"""Implement key wrapping as described in RFC 3394 and RFC 5649."""

import binascii

from Crypto.Cipher import AES
from Crypto.Util.number import bytes_to_long, long_to_bytes
from Crypto.Util.strxor import strxor

from pskc.exceptions import EncryptionError, DecryptionError


def _split(value):
    return value[:8], value[8:]


RFC3394_IV = binascii.a2b_hex('a6a6a6a6a6a6a6a6')
RFC5649_IV = binascii.a2b_hex('a65959a6')


def wrap(plaintext, key, iv=None, pad=None):
    """Apply the AES key wrap algorithm to the plaintext.

    The iv can specify an initial value, otherwise the value from RFC 3394 or
    RFC 5649 will be used, depending on the plaintext length and the value of
    pad.

    If pad is True, padding as described in RFC 5649 will always be used. If
    pad is False, padding is disabled. Other values automatically enable RFC
    5649 padding when needed."""

    if iv is not None:
        pad = False

    mli = len(plaintext)
    if pad is False and (mli % 8 != 0 or mli < 16):
        raise EncryptionError('Plaintext length wrong')
    if mli % 8 != 0 and pad is not False:
        r = (mli + 7) // 8
        plaintext += ((r * 8) - mli) * b'\0'

    if iv is None:
        if len(plaintext) != mli or pad is True:
            iv = RFC5649_IV + long_to_bytes(mli, 4)
        else:
            iv = RFC3394_IV

    encrypt = AES.new(key).encrypt
    n = len(plaintext) // 8

    if n == 1:
        # RFC 5649 shortcut
        return encrypt(iv + plaintext)

    A = iv
    R = [plaintext[i * 8:i * 8 + 8]
         for i in range(n)]
    for j in range(6):
        for i in range(n):
            A, R[i] = _split(encrypt(A + R[i]))
            A = strxor(A, long_to_bytes(n * j + i + 1, 8))
    return A + b''.join(R)


def unwrap(ciphertext, key, iv=None, pad=None):
    """Apply the AES key unwrap algorithm to the ciphertext.

    The iv can specify an initial value, otherwise the value from RFC 3394 or
    RFC 5649 will be used, depending on the value of pad.

    If pad is False, unpadding as described in RFC 5649 will be disabled,
    otherwise checking and removing the padding is automatically done."""

    if iv is not None:
        pad = False

    if len(ciphertext) % 8 != 0 or (pad is False and len(ciphertext) < 24):
        raise DecryptionError('Ciphertext length wrong')

    decrypt = AES.new(key).decrypt
    n = len(ciphertext) // 8 - 1

    if n == 1:
        A, plaintext = _split(decrypt(ciphertext))
    else:
        A = ciphertext[:8]
        R = [ciphertext[(i + 1) * 8:(i + 2) * 8]
             for i in range(n)]
        for j in reversed(range(6)):
            for i in reversed(range(n)):
                A = strxor(A, long_to_bytes(n * j + i + 1, 8))
                A, R[i] = _split(decrypt(A + R[i]))
        plaintext = b''.join(R)

    if iv is None:
        if A == RFC3394_IV and pad is not True:
            return plaintext
        elif A[:4] == RFC5649_IV and pad is not False:
            mli = bytes_to_long(A[4:])
            # check padding length is valid and plaintext only contains zeros
            if 8 * (n - 1) < mli <= 8 * n and \
               plaintext.endswith((len(plaintext) - mli) * b'\0'):
                return plaintext[:mli]
    elif A == iv:
        return plaintext
    raise DecryptionError('IV does not match')
