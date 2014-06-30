# mac.py - module for checking value signatures
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


class ValueMAC(object):
    """Provide MAC checking ability to PSKC data values."""

    def __init__(self, mac, value_mac=None):
        self.mac = mac
        self._value_mac = None
        self.parse(value_mac)

    def parse(self, value_mac):
        """Read MAC information from the <ValueMAC> XML tree."""
        from pskc.xml import findbin
        if value_mac is None:
            return
        self._value_mac = findbin(value_mac, '.')

    def check(self, value):
        """Check if the provided value matches the MAC.

        This will return None if there is no MAC to be checked. It will
        return True if the MAC matches and raise an exception if it fails.
        """
        from pskc.exceptions import DecryptionError
        if value is None or self._value_mac is None:
            return  # no MAC present or nothing to check
        key = self.mac.key
        if key is None:
            raise DecryptionError('No MAC key available')
        hmacfn = get_hmac(self.mac.algorithm)
        if hmacfn is None:
            raise DecryptionError(
                'Unsupported MAC algorithm: %r' % self.mac.algorithm)
        if hmacfn(key, value) != self._value_mac:
            raise DecryptionError('MAC value does not match')
        return True


class MAC(object):
    """Class describing the MAC algorithm to use and how to get the key.

    Instances of this class provide the following attributes:

      algorithm: the name of the HMAC to use (currently only HMAC_SHA1)
      key: the binary value of the MAC key if it can be decrypted
    """

    def __init__(self, pskc, mac_method=None):
        from pskc.encryption import EncryptedValue
        self.algorithm = None
        self._mac_key = EncryptedValue(pskc.encryption)
        self.parse(mac_method)

    def parse(self, mac_method):
        """Read MAC information from the <MACMethod> XML tree."""
        from pskc.xml import find, findtext
        if mac_method is None:
            return
        self.algorithm = mac_method.get('Algorithm')
        self._mac_key.parse(find(mac_method, 'pskc:MACKey'))
        mac_key_reference = findtext(mac_method, 'pskc:MACKeyReference')

    @property
    def key(self):
        """Provides access to the MAC key binary value if available."""
        return self._mac_key.decrypt()
