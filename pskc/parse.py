# parse.py - module for reading PSKC files
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

from xml.etree import ElementTree
import base64

import dateutil.parser

from pskc.policy import Policy


# the relevant XML namespaces for PSKC
namespaces = dict(
    # the XML namespace URI for version 1.0 of PSKC
    pskc='urn:ietf:params:xml:ns:keyprov:pskc',
    # the XML Signature namespace
    ds='http://www.w3.org/2000/09/xmldsig#',
    # the XML Encryption namespace
    xenc='http://www.w3.org/2001/04/xmlenc#',
    # the XML Encryption version 1.1 namespace
    xenc11='http://www.w3.org/2009/xmlenc11#',
    # the PKCS #5 namespace
    pkcs5='http://www.rsasecurity.com/rsalabs/pkcs/schemas/pkcs-5v2-0#',
)


def g_e_v(tree, match):
    """Get the text value of an element (or None)."""
    element = tree.find(match, namespaces=namespaces)
    if element is not None:
        return element.text.strip()


def g_e_i(tree, match):
    """Return an element value as an int (or None)."""
    element = tree.find(match, namespaces=namespaces)
    if element is not None:
        return int(element.text.strip())


def g_e_d(tree, match):
    """Return an element value as a datetime (or None)."""
    element = tree.find(match, namespaces=namespaces)
    if element is not None:
        return dateutil.parser.parse(element.text.strip())


class DataType(object):

    def __init__(self, key, element=None):
        from pskc.encryption import EncryptedValue
        self.key = key
        self.plain_value = None
        self.encrypted_value = EncryptedValue(self.key.pskc.encryption)
        self.parse(element)

    def parse(self, element):
        if element is None:
            return
        self.plain_value = g_e_v(element, 'pskc:PlainValue')
        self.encrypted_value.parse(element.find(
            'pskc:EncryptedValue', namespaces=namespaces))


class BinaryDataType(DataType):

    @property
    def value(self):
        # plain value is base64 encoded
        value = self.plain_value
        if value is not None:
            return base64.b64decode(value)
        # encrypted value is in correct format
        value = self.encrypted_value.decrypt()
        if value is not None:
            return value


class IntegerDataType(DataType):

    @property
    def value(self):
        # plain value is a string representation of the number
        value = self.plain_value
        if value:
            return int(value)
        # decrypted value is a
        value = self.encrypted_value.decrypt()
        if value is not None:
            # Python3 has int.from_bytes(value, byteorder='big')
            v = 0
            for x in value:
                v = (v << 8) + ord(x)
            return v


class Key(object):

    def __init__(self, pskc, key_package):

        self.pskc = pskc

        self.manufacturer = g_e_v(key_package, 'pskc:DeviceInfo/pskc:Manufacturer')
        self.serial = g_e_v(key_package, 'pskc:DeviceInfo/pskc:SerialNo')
        self.model = g_e_v(key_package, 'pskc:DeviceInfo/pskc:Model')
        self.issue_no = g_e_v(key_package, 'pskc:DeviceInfo/pskc:IssueNo')
        self.device_binding = g_e_v(key_package, 'pskc:DeviceInfo/pskc:DeviceBinding')
        self.start_date = g_e_d(key_package, 'pskc:DeviceInfo/pskc:StartDate')
        self.expiry_date = g_e_d(key_package, 'pskc:DeviceInfo/pskc:ExpiryDate')
        self.device_userid = g_e_v(key_package, 'pskc:DeviceInfo/pskc:UserId')

        self.crypto_module = g_e_v(key_package, 'pskc:CryptoModuleInfo/pskc:Id')

        self.id = None
        self.algorithm = None

        key = key_package.find('pskc:Key', namespaces=namespaces)
        if key is not None:
            self.id = key.attrib.get('Id')
            self.algorithm = key.attrib.get('Algorithm')

        self.issuer = g_e_v(key_package, 'pskc:Key/pskc:Issuer')
        self.key_profile = g_e_v(key_package, 'pskc:Key/pskc:KeyProfileId')
        self.key_reference = g_e_v(key_package, 'pskc:Key/pskc:KeyReference')
        self.friendly_name = g_e_v(key_package, 'pskc:Key/pskc:FriendlyName')
        # TODO: support multi-language values of <FriendlyName>
        self.userid = g_e_v(key_package, 'pskc:Key/pskc:UserId')

        self.algorithm_suite = g_e_v(key_package, 'pskc:Key/pskc:AlgorithmParameters/pskc:Suite')

        self.challenge_encoding = None
        self.challenge_min = None
        self.challenge_max = None
        self.challenge_check = None

        challenge_format = key_package.find('pskc:Key/pskc:AlgorithmParameters/pskc:ChallengeFormat', namespaces=namespaces)
        if challenge_format is not None:
            self.challenge_encoding = challenge_format.attrib.get('Encoding')
            v = challenge_format.attrib.get('Min')
            if v:
                self.challenge_min = int(v)
            v = challenge_format.attrib.get('Max')
            if v:
                self.challenge_max = int(v)
            v = challenge_format.attrib.get('CheckDigits')
            if v:
                self.challenge_check = v.lower() == 'true'

        self.response_encoding = None
        self.response_length = None
        self.response_check = None

        response_format = key_package.find('pskc:Key/pskc:AlgorithmParameters/pskc:ResponseFormat', namespaces=namespaces)
        if response_format is not None:
            self.response_encoding = response_format.attrib.get('Encoding')
            v = response_format.attrib.get('Length')
            if v:
                self.response_length = int(v)
            v = response_format.attrib.get('CheckDigits')
            if v:
                self.response_check = v.lower() == 'true'

        self._secret = BinaryDataType(self)
        self._counter = IntegerDataType(self)
        self._time_offset = IntegerDataType(self)
        self._time_interval = IntegerDataType(self)
        self._time_drift = IntegerDataType(self)

        data = key_package.find('pskc:Key/pskc:Data', namespaces=namespaces)
        if data is not None:
            self._secret.parse(data.find(
                'pskc:Secret', namespaces=namespaces))
            self._counter.parse(data.find(
                'pskc:Counter', namespaces=namespaces))
            self._time_offset.parse(data.find(
                'pskc:Time', namespaces=namespaces))
            self._time_interval.parse(data.find(
                'pskc:TimeInterval', namespaces=namespaces))
            self._time_drift.parse(data.find(
                'pskc:TimeDrift', namespaces=namespaces))

        self.policy = Policy(self, key_package.find(
            'pskc:Key/pskc:Policy', namespaces=namespaces))

    @property
    def secret(self):
        """The secret key itself."""
        return self._secret.value

    @property
    def counter(self):
        """An event counter for event-based OTP."""
        return self._counter.value

    @property
    def time_offset(self):
        """A time offset for time-based OTP (number of intervals)."""
        return self._time_offset.value

    @property
    def time_interval(self):
        """A time interval in seconds."""
        return self._time_interval.value

    @property
    def time_drift(self):
        """Device clock drift value (number of time intervals)."""
        return self._time_drift.value


class PSKC(object):

    def __init__(self, filename):
        from pskc.encryption import Encryption
        tree = ElementTree.parse(filename)
        container = tree.getroot()
        # the version of the PSKC schema
        self.version = container.attrib.get('Version')
        # unique identifier for the container
        self.id = container.attrib.get('Id')
        # handle EncryptionKey entries
        self.encryption = Encryption(container.find(
            'pskc:EncryptionKey', namespaces=namespaces))
        # handle KeyPackage entries
        self.keys = []
        for package in container.findall('pskc:KeyPackage', namespaces=namespaces):
            self.keys.append(Key(self, package))
