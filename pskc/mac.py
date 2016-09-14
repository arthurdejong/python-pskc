# mac.py - module for checking value signatures
# coding: utf-8
#
# Copyright (C) 2014-2016 Arthur de Jong
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


import base64
import re


_hmac_url_re = re.compile(r'^.*#hmac-(?P<hash>[a-z0-9]+)$')


def get_hash(algorithm):
    """Return the hash function for the specifies HMAC algorithm."""
    import hashlib
    match = _hmac_url_re.search(algorithm)
    if match:
        return getattr(hashlib, match.group('hash'), None)


def get_hmac(algorithm):
    """Return an HMAC function that takes a secret and a value and returns a
    digest."""
    import hmac
    digestmod = get_hash(algorithm)
    if digestmod is not None:
        return lambda key, value: hmac.new(key, value, digestmod).digest()


def get_mac(algorithm, key, value):
    """Generate the MAC value over the specified value."""
    from pskc.exceptions import DecryptionError
    if key is None:
        raise DecryptionError('No MAC key available')
    if algorithm is None:
        raise DecryptionError('No MAC algorithm set')
    hmacfn = get_hmac(algorithm)
    if hmacfn is None:
        raise DecryptionError(
            'Unsupported MAC algorithm: %r' % algorithm)
    return hmacfn(key, value)


class MAC(object):
    """Class describing the MAC algorithm to use and how to get the key.

    Instances of this class provide the following attributes:

      algorithm: the name of the HMAC to use (currently only HMAC_SHA1)
      key: the binary value of the MAC key if it can be decrypted
    """

    def __init__(self, pskc):
        self.pskc = pskc
        self._algorithm = None
        self.key_plain_value = None
        self.key_cipher_value = None
        self.key_algorithm = None

    def make_xml(self, container):
        from pskc.xml import mk_elem
        if not self.algorithm and not self.key:
            return
        mac_method = mk_elem(
            container, 'pskc:MACMethod', Algorithm=self.algorithm, empty=True)
        mac_key = mk_elem(mac_method, 'pskc:MACKey', empty=True)
        mk_elem(
            mac_key, 'xenc:EncryptionMethod',
            Algorithm=self.pskc.encryption.algorithm)
        cipher_data = mk_elem(mac_key, 'xenc:CipherData', empty=True)
        if self.key_cipher_value:
            mk_elem(
                cipher_data, 'xenc:CipherValue',
                base64.b64encode(self.key_cipher_value).decode())
        elif self.key_plain_value:
            mk_elem(
                cipher_data, 'xenc:CipherValue', base64.b64encode(
                    self.pskc.encryption.encrypt_value(self.key_plain_value)
                ).decode())

    @property
    def key(self):
        """Provides access to the MAC key binary value if available."""
        if self.key_plain_value:
            return self.key_plain_value
        elif self.key_cipher_value:
            return self.pskc.encryption.decrypt_value(
                self.key_cipher_value, self.key_algorithm)
        # fall back to encryption key
        return self.pskc.encryption.key

    @key.setter
    def key(self, value):
        self.key_plain_value = value
        self.key_cipher_value = None

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
        # https://tools.ietf.org/html/rfc2104#section-3
        # an HMAC key should be at least as long as the hash output length
        hashfn = get_hash(self.algorithm)
        if hashfn is not None:
            return int(hashfn().digest_size)
        else:
            return 16

    def generate_mac(self, value):
        """Generate the MAC over the specified value."""
        return get_mac(self.algorithm, self.key, value)

    def check_value(self, value, value_mac):
        """Check if the provided value matches the MAC.

        This will return None if there is no MAC to be checked. It will
        return True if the MAC matches and raise an exception if it fails.
        """
        from pskc.exceptions import DecryptionError
        if self.generate_mac(value) != value_mac:
            raise DecryptionError('MAC value does not match')
        return True

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
            from Crypto import Random
            self.key = Random.get_random_bytes(self.algorithm_key_length)
