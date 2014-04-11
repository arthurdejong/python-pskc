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

    def __init__(self, element, t=str):
        self.element = element
        self.t = t

    @property
    def plain_value(self):
        if self.element is None:
            return
        plain_value = self.element.find('pskc:PlainValue', namespaces=namespaces)
        if plain_value is not None:
            return plain_value.text.strip()


class BinaryDataType(DataType):

    @property
    def value(self):
        plain_value = self.plain_value
        if plain_value:
            return base64.b64decode(plain_value)
        # TODO: else: see if EncryptedValue is present and decode


class IntegerDataType(DataType):

    @property
    def value(self):
        plain_value = self.plain_value
        if plain_value:
            return int(plain_value)
        # TODO: else: see if EncryptedValue is present and decode


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

        self.secret = None
        self.counter = None
        self.time_offset = None
        self.time_interval = None
        self.time_drift = None

        data = key_package.find('pskc:Key/pskc:Data', namespaces=namespaces)
        if data is not None:
            # the secret key itself
            secret = BinaryDataType(data.find('pskc:Secret', namespaces=namespaces))
            self.secret = secret.value
            # event counter for event-based OTP
            counter = IntegerDataType(data.find('pskc:Counter', namespaces=namespaces))
            self.counter = counter.value
            # time offset for time-based OTP (number of intervals)
            time_offset = IntegerDataType(data.find('pskc:Time', namespaces=namespaces))
            self.time_offset = time_offset.value
            # time interval in seconds
            time_interval = IntegerDataType(data.find('pskc:TimeInterval', namespaces=namespaces))
            self.time_interval = time_interval.value
            # device clock drift value (number of time intervals)
            time_drift = IntegerDataType(data.find('pskc:TimeDrift', namespaces=namespaces))
            self.time_drift = time_drift

        self.policy = Policy(self, key_package.find(
            'pskc:Key/pskc:Policy', namespaces=namespaces))


class PSKC(object):

    def __init__(self, filename):
        tree = ElementTree.parse(filename)
        container = tree.getroot()
        # the version of the PSKC schema
        self.version = container.attrib.get('Version')
        # unique identifier for the container
        self.id = container.attrib.get('Id')
        # handle KeyPackage entries
        self.keys = []
        for package in container.findall('pskc:KeyPackage', namespaces=namespaces):
            self.keys.append(Key(self, package))
