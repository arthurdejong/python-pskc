# aeskw.py - implementation of AES key wrapping
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

"""Implement key wrapping as described in RFC 3394 and RFC 5649."""

import binascii
import struct

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from pskc.exceptions import DecryptionError, EncryptionError


def _strxor(a, b):
    """Return a XOR b."""
    if isinstance(b'', str):  # pragma: no cover (Python 2 specific)
        return b''.join(chr(ord(x) ^ ord(y)) for (x, y) in zip(a, b))
    else:  # pragma: no cover (Python 3 specific)
        return bytes(x ^ y for (x, y) in zip(a, b))


def _split(value):
    return value[:8], value[8:]


RFC3394_IV = binascii.a2b_hex('a6a6a6a6a6a6a6a6')
RFC5649_IV = binascii.a2b_hex('a65959a6')


def wrap(plaintext, key, iv=None, pad=None, algorithm=algorithms.AES):
    """Apply the AES key wrap algorithm to the plaintext.

    The iv can specify an initial value, otherwise the value from RFC 3394 or
    RFC 5649 will be used, depending on the plaintext length and the value of
    pad.

    If pad is True, padding as described in RFC 5649 will always be used. If
    pad is False, padding is disabled. Other values automatically enable RFC
    5649 padding when needed.
    """
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
            iv = RFC5649_IV + struct.pack('>I', mli)
        else:
            iv = RFC3394_IV

    cipher = Cipher(algorithm(key), modes.ECB(), default_backend())
    encryptor = cipher.encryptor()
    n = len(plaintext) // 8

    if n == 1:
        # RFC 5649 shortcut
        return encryptor.update(iv + plaintext)

    A = iv  # noqa: N806
    R = [plaintext[i * 8:i * 8 + 8]  # noqa: N806
         for i in range(n)]
    for j in range(6):
        for i in range(n):
            A, R[i] = _split(encryptor.update(A + R[i]))  # noqa: N806
            A = _strxor(A, struct.pack('>Q', n * j + i + 1))  # noqa: N806
    return A + b''.join(R)


def unwrap(ciphertext, key, iv=None, pad=None, algorithm=algorithms.AES):
    """Apply the AES key unwrap algorithm to the ciphertext.

    The iv can specify an initial value, otherwise the value from RFC 3394 or
    RFC 5649 will be used, depending on the value of pad.

    If pad is False, unpadding as described in RFC 5649 will be disabled,
    otherwise checking and removing the padding is automatically done.
    """
    if iv is not None:
        pad = False

    if len(ciphertext) % 8 != 0 or (pad is False and len(ciphertext) < 24):
        raise DecryptionError('Ciphertext length wrong')

    cipher = Cipher(algorithm(key), modes.ECB(), default_backend())
    decryptor = cipher.decryptor()
    n = len(ciphertext) // 8 - 1

    if n == 1:
        A, plaintext = _split(decryptor.update(ciphertext))  # noqa: N806
    else:
        A = ciphertext[:8]  # noqa: N806
        R = [ciphertext[(i + 1) * 8:(i + 2) * 8]  # noqa: N806
             for i in range(n)]
        for j in reversed(range(6)):
            for i in reversed(range(n)):
                A = _strxor(A, struct.pack('>Q', n * j + i + 1))  # noqa: N806
                A, R[i] = _split(decryptor.update(A + R[i]))  # noqa: N806
        plaintext = b''.join(R)

    if iv is None:
        if A == RFC3394_IV and pad is not True:
            return plaintext
        elif A[:4] == RFC5649_IV and pad is not False:
            mli = struct.unpack('>I', A[4:])[0]
            # check padding length is valid and plaintext only contains zeros
            if 8 * (n - 1) < mli <= 8 * n and \
               plaintext.endswith((len(plaintext) - mli) * b'\0'):
                return plaintext[:mli]
    elif A == iv:
        return plaintext
    raise DecryptionError('IV does not match')
