# key.py - module for handling keys from pskc files
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

"""Module that handles keys stored in PSKC files."""


import base64

from pskc.encryption import EncryptedValue
from pskc.mac import ValueMAC
from pskc.policy import Policy


class DataType(object):
    """Provide access to possibly encrypted, MAC'ed information.

    This class is meant to be subclassed to provide typed access to stored
    values. Instances of this class provide the following attributes:

      plain_value: raw unencrypted value if present (possibly base64 encoded)
      encrypted_value: reference to an EncryptedValue instance
      value_mac: reference to a ValueMAC instance
      value: the plaintext value (decrypted if necessary)
    """

    def __init__(self, key, element=None):
        self.plain_value = None
        self.encrypted_value = EncryptedValue(key.pskc.encryption)
        self.value_mac = ValueMAC(key.pskc.mac)
        self.parse(element)

    def parse(self, element):
        """Read information from the provided element.

        The element is expected to contain <PlainValue>, <EncryptedValue>
        and/or ValueMAC elements that contain information on the actual
        value."""
        from pskc.parse import g_e_v, namespaces
        if element is None:
            return
        self.plain_value = g_e_v(element, 'pskc:PlainValue')
        self.encrypted_value.parse(element.find(
            'pskc:EncryptedValue', namespaces=namespaces))
        self.value_mac.parse(element.find(
            'pskc:ValueMAC', namespaces=namespaces))

    def check(self):
        """Check whether the embedded MAC is correct."""
        # this checks the encrypted value
        return self.value_mac.check(self.encrypted_value.cipher_value)


class BinaryDataType(DataType):
    """Subclass of DataType for binary data (e.g. keys)."""

    @property
    def value(self):
        """Provide the raw binary value."""
        # plain value is base64 encoded
        value = self.plain_value
        if value is not None:
            return base64.b64decode(value)
        # encrypted value is in correct format
        value = self.encrypted_value.decrypt()
        if value is not None:
            return value


class IntegerDataType(DataType):
    """Subclass of DataType for integer types (e.g. counters)."""

    @property
    def value(self):
        """Provide the raw integer value."""
        # plain value is a string representation of the number
        value = self.plain_value
        if value:
            return int(value)
        # decrypted value is big endian encoded
        value = self.encrypted_value.decrypt()
        if value is not None:
            # Python3 has int.from_bytes(value, byteorder='big')
            v = 0
            for x in value:
                v = (v << 8) + ord(x)
            return v


class Key(object):
    """Representation of a single key from a PSKC file.

    Instances of this class provide the following properties:

      id: unique key identifier (should be constant between interchanges)
      algorithm: identifier of the PSKC algorithm profile (URI)
      secret: the secret key itself (binary form, automatically decrypted)
      counter: event counter for event-based OTP
      time_offset: time offset for time-based OTP algorithms (in intervals)
      time_interval: time interval for time-based OTP in seconds
      time_drift: device clock drift (negative means device is slow)
      issuer: party that issued the key
      key_profile: reference to pre-shared key profile information
      key_reference: reference to an external key
      friendly_name: human-readable name for the secret key
      key_userid: user distinguished name associated with the key
      manufacturer: name of the organisation that made the device
      serial: serial number of the device
      model: device model description
      issue_no: issue number per serial number
      device_binding: device (class) identifier for the key to be loaded upon
      start_date: key should not be used before this date
      expiry_date: key or device may expire after this date
      device_userid: user distinguished name associated with the device
      crypto_module: id of module to which keys are provisioned within device
      algorithm_suite: additional algorithm characteristics (e.g. used hash)
      challenge_encoding: format of the challenge for CR devices
      challenge_min_length: minimum accepted challenge length by device
      challenge_max_length: maximum size challenge accepted by the device
      challenge_check: whether the device will check an embedded check digit
      response_encoding: format of the response the device will generate
      response_length: the length of the response of the device
      response_check: whether the device appends a Luhn check digit
      policy: reference to policy information (see Policy class)
    """

    def __init__(self, pskc, key_package):

        self.pskc = pskc

        self.id = None
        self.algorithm = None

        self._secret = BinaryDataType(self)
        self._counter = IntegerDataType(self)
        self._time_offset = IntegerDataType(self)
        self._time_interval = IntegerDataType(self)
        self._time_drift = IntegerDataType(self)

        self.issuer = None
        self.key_profile = None
        self.key_reference = None
        self.friendly_name = None
        self.key_userid = None

        self.manufacturer = None
        self.serial = None
        self.model = None
        self.issue_no = None
        self.device_binding = None
        self.start_date = None
        self.expiry_date = None
        self.device_userid = None

        self.crypto_module = None

        self.algorithm_suite = None

        self.challenge_encoding = None
        self.challenge_min_length = None
        self.challenge_max_length = None
        self.challenge_check = None

        self.response_encoding = None
        self.response_length = None
        self.response_check = None

        self.policy = Policy(self)

        self.parse(key_package)

    def parse(self, key_package):
        """Read key information from the provided <KeyPackage> tree."""
        from pskc.parse import g_e_v, g_e_d, namespaces
        if key_package is None:
            return

        key = key_package.find('pskc:Key', namespaces=namespaces)
        if key is not None:
            self.id = key.attrib.get('Id')
            self.algorithm = key.attrib.get('Algorithm')

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

        self.issuer = g_e_v(key_package, 'pskc:Key/pskc:Issuer')
        self.key_profile = g_e_v(key_package, 'pskc:Key/pskc:KeyProfileId')
        self.key_reference = g_e_v(key_package, 'pskc:Key/pskc:KeyReference')
        self.friendly_name = g_e_v(key_package, 'pskc:Key/pskc:FriendlyName')
        # TODO: support multi-language values of <FriendlyName>
        self.key_userid = g_e_v(key_package, 'pskc:Key/pskc:UserId')

        self.manufacturer = g_e_v(
            key_package, 'pskc:DeviceInfo/pskc:Manufacturer')
        self.serial = g_e_v(key_package, 'pskc:DeviceInfo/pskc:SerialNo')
        self.model = g_e_v(key_package, 'pskc:DeviceInfo/pskc:Model')
        self.issue_no = g_e_v(key_package, 'pskc:DeviceInfo/pskc:IssueNo')
        self.device_binding = g_e_v(
            key_package, 'pskc:DeviceInfo/pskc:DeviceBinding')
        self.start_date = g_e_d(key_package, 'pskc:DeviceInfo/pskc:StartDate')
        self.expiry_date = g_e_d(
            key_package, 'pskc:DeviceInfo/pskc:ExpiryDate')
        self.device_userid = g_e_v(key_package, 'pskc:DeviceInfo/pskc:UserId')

        self.crypto_module = g_e_v(
            key_package, 'pskc:CryptoModuleInfo/pskc:Id')

        self.algorithm_suite = g_e_v(
            key_package, 'pskc:Key/pskc:AlgorithmParameters/pskc:Suite')

        challenge_format = key_package.find(
            'pskc:Key/pskc:AlgorithmParameters/pskc:ChallengeFormat',
            namespaces=namespaces)
        if challenge_format is not None:
            self.challenge_encoding = challenge_format.attrib.get('Encoding')
            v = challenge_format.attrib.get('Min')
            if v:
                self.challenge_min_length = int(v)
            v = challenge_format.attrib.get('Max')
            if v:
                self.challenge_max_length = int(v)
            v = challenge_format.attrib.get('CheckDigits')
            if v:
                self.challenge_check = v.lower() == 'true'

        response_format = key_package.find(
            'pskc:Key/pskc:AlgorithmParameters/pskc:ResponseFormat',
            namespaces=namespaces)
        if response_format is not None:
            self.response_encoding = response_format.attrib.get('Encoding')
            v = response_format.attrib.get('Length')
            if v:
                self.response_length = int(v)
            v = response_format.attrib.get('CheckDigits')
            if v:
                self.response_check = v.lower() == 'true'

        self.policy.parse(key_package.find(
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

    def check(self):
        """Check if all MACs in the message are valid."""
        checks = (self._secret.check(), self._counter.check(),
                  self._time_offset.check(), self._time_interval.check(),
                  self._time_drift.check())
        if all(x is None for x in checks):
            return None
        return all(x is not False for x in checks)
