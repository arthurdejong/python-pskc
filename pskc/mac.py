# mac.py - module for checking value signatures
# coding: utf-8
#
# Copyright (C) 2014-2025 Arthur de Jong
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

"""Module that provides message authentication for PSKC values.

This module provides a MAC class that is used to store information about
how the MAC should be calculated (including the MAC key) and a ValueMAC
class that provides (H)MAC checking for PSKC key data.

The MAC key is generated specifically for each PSKC file and encrypted
with the PSKC encryption key.
"""

from __future__ import annotations

import hashlib
import os
import re

from pskc import PSKC
from pskc.key import EncryptedValue


_hmac_url_re = re.compile(r'^(.*#)?hmac-(?P<hash>[a-z0-9-]+)$')


def _get_hash_obj(algorithm: str | None, *args: bytes) -> hashlib._Hash:
    """Return an instantiated hash object."""
    from pskc.algorithms import normalise_algorithm
    from pskc.exceptions import DecryptionError
    match = _hmac_url_re.search(normalise_algorithm(algorithm) or '')
    if match:
        try:
            return hashlib.new(match.group('hash'), *args)
        except ValueError:
            pass
    raise DecryptionError('Unsupported MAC algorithm: %r' % algorithm)


def mac(algorithm: str | None, key: bytes | None, value: bytes) -> bytes:
    """Generate the MAC value over the specified value."""
    import hmac
    assert key
    return hmac.new(
        key, value,
        lambda *args: _get_hash_obj(algorithm, *args)).digest()


def mac_key_length(algorithm: str | None) -> int:
    """Recommended minimal key length in bytes for the set algorithm."""
    # https://tools.ietf.org/html/rfc2104#section-3
    # an HMAC key should be at least as long as the hash output length
    from pskc.exceptions import DecryptionError
    try:
        return int(_get_hash_obj(algorithm).digest_size)
    except DecryptionError:
        return 16  # fallback value


class MAC:
    """Class describing the MAC algorithm to use and how to get the key.

    Instances of this class provide the following attributes:

      algorithm: the name of the HMAC to use (currently only HMAC_SHA1)
      key: the binary value of the MAC key if it can be decrypted
    """

    def __init__(self, pskc: PSKC) -> None:
        self.pskc = pskc
        self._algorithm: str | None = None

    @property
    def key(self) -> bytes | None:
        """Provide access to the MAC key binary value if available."""
        value: bytes | EncryptedValue | None = getattr(self, '_key', None)
        if isinstance(value, EncryptedValue):
            return value.get_value(self.pskc)
        elif value:
            return value
        else:
            # fall back to encryption key
            return self.pskc.encryption.key

    @key.setter
    def key(self, value: bytes | EncryptedValue | None) -> None:
        self._key = value

    @property
    def algorithm(self) -> str | None:
        """Provide the MAC algorithm used."""
        if self._algorithm:
            return self._algorithm
        return None

    @algorithm.setter
    def algorithm(self, value: str | None) -> None:
        from pskc.algorithms import normalise_algorithm
        self._algorithm = normalise_algorithm(value)

    @property
    def algorithm_key_length(self) -> int:
        """Recommended minimal key length in bytes for the set algorithm."""
        return mac_key_length(self.algorithm)

    def generate_mac(self, value: bytes) -> bytes:
        """Generate the MAC over the specified value."""
        return mac(self.algorithm, self.key, value)

    def setup(self, key: bytes | None = None, algorithm: str | None = None) -> None:
        """Configure an encrypted MAC key.

        None of the arguments are required. By default HMAC-SHA1 will be used
        as a MAC algorithm. If no key is configured a random key will be
        generated with the length of the output of the configured hash.

        This function will automatically be called when the configured
        encryption algorithm requires a message authentication code.
        """
        if key:
            self.key = key
        if algorithm:
            self.algorithm = algorithm
        # default to HMAC-SHA1
        if not self.algorithm:
            self.algorithm = 'hmac-sha1'
        # generate an HMAC key
        if not self.key:
            self.key = os.urandom(self.algorithm_key_length)
