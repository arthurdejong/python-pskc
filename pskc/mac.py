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


import re


_hmac_url_re = re.compile(r'^.*#hmac-(?P<hash>[a-z0-9]+)$')


def get_hmac(algorithm):
    """Return an HMAC function that takes a secret and a value and returns a
    digest."""
    import hashlib
    import hmac
    match = _hmac_url_re.search(algorithm)
    if match:
        digestmod = getattr(hashlib, match.group('hash'), None)
        if digestmod is not None:
            return lambda key, value: hmac.new(key, value, digestmod).digest()


class MAC(object):
    """Class describing the MAC algorithm to use and how to get the key.

    Instances of this class provide the following attributes:

      algorithm: the name of the HMAC to use (currently only HMAC_SHA1)
      key: the binary value of the MAC key if it can be decrypted
    """

    def __init__(self, pskc):
        self.pskc = pskc
        self.algorithm = None
        self.key_cipher_value = None
        self.key_algorithm = None

    def parse(self, mac_method):
        """Read MAC information from the <MACMethod> XML tree."""
        from pskc.xml import find, findtext, findbin
        if mac_method is None:
            return
        self.algorithm = mac_method.get('Algorithm')
        mac_key = find(mac_method, 'MACKey')
        if mac_key is not None:
            self.key_cipher_value = findbin(mac_key, 'CipherData/CipherValue')
            encryption_method = find(mac_key, 'EncryptionMethod')
            if encryption_method is not None:
                self.key_algorithm = encryption_method.attrib.get('Algorithm')
        mac_key_reference = findtext(mac_method, 'MACKeyReference')

    @property
    def key(self):
        """Provides access to the MAC key binary value if available."""
        if self.key_cipher_value:
            return self.pskc.encryption.decrypt_value(
                self.key_cipher_value, self.key_algorithm)

    def check_value(self, value, value_mac):
        """Check if the provided value matches the MAC.

        This will return None if there is no MAC to be checked. It will
        return True if the MAC matches and raise an exception if it fails.
        """
        from pskc.exceptions import DecryptionError
        key = self.key
        if key is None:
            raise DecryptionError('No MAC key available')
        hmacfn = get_hmac(self.algorithm)
        if hmacfn is None:
            raise DecryptionError(
                'Unsupported MAC algorithm: %r' % self.algorithm)
        if hmacfn(key, value) != value_mac:
            raise DecryptionError('MAC value does not match')
        return True
