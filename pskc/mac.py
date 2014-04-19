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

import base64
import hashlib
import hmac

from pskc.encryption import EncryptedValue


HMAC_SHA1 = 'http://www.w3.org/2000/09/xmldsig#hmac-sha1'


class ValueMAC(object):

    def __init__(self, mac, value_mac=None):
        self.mac = mac
        self.value_mac = None
        self.parse(value_mac)

    def parse(self, value_mac):
        from pskc.parse import g_e_v
        if value_mac is None:
            return
        value = g_e_v(value_mac, '.')
        if value is not None:
            self.value_mac = base64.b64decode(value)

    def check(self, value):
        if value is None or self.value_mac is None:
            return
        algorithm = self.mac.algorithm
        key = self.mac.key
        if algorithm == HMAC_SHA1 and key is not None:
            h = hmac.new(key, value, hashlib.sha1).digest()
            return h == self.value_mac


class MAC(object):

    def __init__(self, pskc, mac_method=None):
        self.algorithm = None
        self.mac_key = EncryptedValue(pskc.encryption)
        self.parse(mac_method)

    def parse(self, mac_method):
        """Read encryption information from the EncryptionKey XML tree."""
        from pskc.parse import g_e_v, namespaces
        if mac_method is None:
            return
        self.algorithm = mac_method.attrib.get('Algorithm')
        self.mac_key.parse(mac_method.find(
            'pskc:MACKey', namespaces=namespaces))
        mac_key_reference = g_e_v(mac_method, 'pskc:MACKeyReference')

    @property
    def key(self):
        return self.mac_key.decrypt()
