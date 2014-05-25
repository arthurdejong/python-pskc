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


import base64
import hashlib
import hmac

from pskc.encryption import EncryptedValue


class ValueMAC(object):
    """Provide MAC checking ability to PSKC data values."""

    def __init__(self, mac, value_mac=None):
        self.mac = mac
        self._value_mac = None
        self.parse(value_mac)

    def parse(self, value_mac):
        """Read MAC information from the <ValueMAC> XML tree."""
        from pskc.parse import g_e_v
        if value_mac is None:
            return
        value = g_e_v(value_mac, '.')
        if value is not None:
            self._value_mac = base64.b64decode(value)

    def check(self, value):
        """Check if the provided value matches the MAC.

        This will return None if the value cannot be checked (no value,
        no key, etc.) or a boolean otherwise.
        """
        if value is None or self._value_mac is None:
            return
        algorithm = self.mac.algorithm
        key = self.mac.key
        if algorithm.endswith('#hmac-sha1') and key is not None:
            h = hmac.new(key, value, hashlib.sha1).digest()
            return h == self._value_mac


class MAC(object):
    """Class describing the MAC algorithm to use and how to get the key.

    Instances of this class provide the following attributes:

      algorithm: the name of the HMAC to use (currently only HMAC_SHA1)
      key: the binary value of the MAC key if it can be decrypted
    """

    def __init__(self, pskc, mac_method=None):
        self.algorithm = None
        self._mac_key = EncryptedValue(pskc.encryption)
        self.parse(mac_method)

    def parse(self, mac_method):
        """Read MAC information from the <MACMethod> XML tree."""
        from pskc.parse import g_e_v, namespaces
        if mac_method is None:
            return
        self.algorithm = mac_method.attrib.get('Algorithm')
        self._mac_key.parse(mac_method.find(
            'pskc:MACKey', namespaces=namespaces))
        mac_key_reference = g_e_v(mac_method, 'pskc:MACKeyReference')

    @property
    def key(self):
        """Provides access to the MAC key binary value if available."""
        return self._mac_key.decrypt()
