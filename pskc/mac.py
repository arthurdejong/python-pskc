# mac.py - module for checking value signatures
# coding: utf-8
#
# Copyright (C) 2014-2018 Arthur de Jong
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


import os
import re


_hmac_url_re = re.compile(r'^(.*#)?hmac-(?P<hash>[a-z0-9-]+)$')


def _get_hash_obj(algorithm, *args):
    """Return an instantiated hash object."""
    import hashlib
    from pskc.algorithms import normalise_algorithm
    from pskc.exceptions import DecryptionError
    match = _hmac_url_re.search(normalise_algorithm(algorithm) or '')
    if match:
        try:
            return hashlib.new(match.group('hash'), *args)
        except ValueError:
            pass
    raise DecryptionError('Unsupported MAC algorithm: %r' % algorithm)


def mac(algorithm, key, value):
    """Generate the MAC value over the specified value."""
    import hmac
    return hmac.new(
        key, value,
        lambda *args: _get_hash_obj(algorithm, *args)).digest()


def mac_key_length(algorithm):
    """Recommended minimal key length in bytes for the set algorithm."""
    # https://tools.ietf.org/html/rfc2104#section-3
    # an HMAC key should be at least as long as the hash output length
    from pskc.exceptions import DecryptionError
    try:
        return int(_get_hash_obj(algorithm).digest_size)
    except DecryptionError:
        return 16  # fallback value


class MAC(object):
    """Class describing the MAC algorithm to use and how to get the key.

    Instances of this class provide the following attributes:

      algorithm: the name of the HMAC to use (currently only HMAC_SHA1)
      key: the binary value of the MAC key if it can be decrypted
    """

    def __init__(self, pskc):
        self.pskc = pskc
        self._algorithm = None

    @property
    def key(self):
        """Provide access to the MAC key binary value if available."""
        value = getattr(self, '_key', None)
        if hasattr(value, 'get_value'):
            return value.get_value(self.pskc)
        elif value:
            return value
        else:
            # fall back to encryption key
            return self.pskc.encryption.key

    @key.setter
    def key(self, value):
        self._key = value

    @property
    def algorithm(self):
        """Provide the MAC algorithm used."""
        if self._algorithm:
            return self._algorithm

    @algorithm.setter
    def algorithm(self, value):
        from pskc.algorithms import normalise_algorithm
        self._algorithm = normalise_algorithm(value)

    @property
    def algorithm_key_length(self):
        """Recommended minimal key length in bytes for the set algorithm."""
        return mac_key_length(self.algorithm)

    def generate_mac(self, value):
        """Generate the MAC over the specified value."""
        return mac(self.algorithm, self.key, value)

    def setup(self, key=None, algorithm=None):
        """Configure an encrypted MAC key.

        The following arguments may be supplied:
          key: the MAC key to use
          algorithm: MAC algorithm

        None of the arguments are required, reasonable defaults will be
        chosen for missing arguments.
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
