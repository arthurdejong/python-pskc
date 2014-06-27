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

      value: unencrypted value if present
      encrypted_value: reference to an EncryptedValue instance
      value_mac: reference to a ValueMAC instance
    """

    def __init__(self, key, element=None):
        self.value = None
        self.encrypted_value = EncryptedValue(key.pskc.encryption)
        self.value_mac = ValueMAC(key.pskc.mac)
        self.parse(element)

    def parse(self, element):
        """Read information from the provided element.

        The element is expected to contain <PlainValue>, <EncryptedValue>
        and/or ValueMAC elements that contain information on the actual
        value."""
        from pskc.parse import find, findtext
        if element is None:
            return
        value = findtext(element, 'pskc:PlainValue')
        if value is not None:
            self.value = self.from_text(value)
        self.encrypted_value.parse(find(element, 'pskc:EncryptedValue'))
        self.value_mac.parse(find(element, 'pskc:ValueMAC'))

    def get_value(self):
        """Provide the raw binary value."""
        if self.value is not None:
            return self.value
        if self.encrypted_value.cipher_value:
            # check MAC and decrypt
            self.check()
            return self.from_bin(self.encrypted_value.decrypt())

    def set_value(self, value):
        """Set the unencrypted value."""
        self.value = value
        self.encrypted_value.cipher_value = None

    def check(self):
        """Check whether the embedded MAC is correct."""
        # this checks the encrypted value
        return self.value_mac.check(self.encrypted_value.cipher_value)


class BinaryDataType(DataType):
    """Subclass of DataType for binary data (e.g. keys)."""

    def from_text(self, value):
        """Convert the plain value to native representation."""
        return base64.b64decode(value)

    def from_bin(self, value):
        """Convert the unencrypted binary to native representation."""
        return value


class IntegerDataType(DataType):
    """Subclass of DataType for integer types (e.g. counters)."""

    def from_text(self, value):
        """Convert the plain value to native representation."""
        return int(value)

    def from_bin(self, value):
        """Convert the unencrypted binary to native representation."""
        result = 0
        for x in value:
            result = (result << 8) + ord(x)
        return result


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

    def __init__(self, pskc, key_package=None):

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
        from pskc.parse import find, findtext, findtime, getint, getbool
        if key_package is None:
            return

        key = find(key_package, 'pskc:Key')
        if key is not None:
            self.id = key.get('Id')
            self.algorithm = key.get('Algorithm')

        data = find(key_package, 'pskc:Key/pskc:Data')
        if data is not None:
            self._secret.parse(find(data, 'pskc:Secret'))
            self._counter.parse(find(data, 'pskc:Counter'))
            self._time_offset.parse(find(data, 'pskc:Time'))
            self._time_interval.parse(find(data, 'pskc:TimeInterval'))
            self._time_drift.parse(find(data, 'pskc:TimeDrift'))

        self.issuer = findtext(key_package, 'pskc:Key/pskc:Issuer')
        self.key_profile = findtext(key_package, 'pskc:Key/pskc:KeyProfileId')
        self.key_reference = findtext(
            key_package, 'pskc:Key/pskc:KeyReference')
        self.friendly_name = findtext(
            key_package, 'pskc:Key/pskc:FriendlyName')
        # TODO: support multi-language values of <FriendlyName>
        self.key_userid = findtext(key_package, 'pskc:Key/pskc:UserId')

        self.manufacturer = findtext(
            key_package, 'pskc:DeviceInfo/pskc:Manufacturer')
        self.serial = findtext(key_package, 'pskc:DeviceInfo/pskc:SerialNo')
        self.model = findtext(key_package, 'pskc:DeviceInfo/pskc:Model')
        self.issue_no = findtext(key_package, 'pskc:DeviceInfo/pskc:IssueNo')
        self.device_binding = findtext(
            key_package, 'pskc:DeviceInfo/pskc:DeviceBinding')
        self.start_date = findtime(
            key_package, 'pskc:DeviceInfo/pskc:StartDate')
        self.expiry_date = findtime(
            key_package, 'pskc:DeviceInfo/pskc:ExpiryDate')
        self.device_userid = findtext(
            key_package, 'pskc:DeviceInfo/pskc:UserId')

        self.crypto_module = findtext(
            key_package, 'pskc:CryptoModuleInfo/pskc:Id')

        self.algorithm_suite = findtext(
            key_package, 'pskc:Key/pskc:AlgorithmParameters/pskc:Suite')

        challenge_format = find(
            key_package,
            'pskc:Key/pskc:AlgorithmParameters/pskc:ChallengeFormat')
        if challenge_format is not None:
            self.challenge_encoding = challenge_format.get('Encoding')
            self.challenge_min_length = getint(challenge_format, 'Min')
            self.challenge_max_length = getint(challenge_format, 'Max')
            self.challenge_check = getbool(challenge_format, 'CheckDigits')

        response_format = find(
            key_package,
            'pskc:Key/pskc:AlgorithmParameters/pskc:ResponseFormat')
        if response_format is not None:
            self.response_encoding = response_format.get('Encoding')
            self.response_length = getint(response_format, 'Length')
            self.response_check = getbool(response_format, 'CheckDigits')

        self.policy.parse(find(key_package, 'pskc:Key/pskc:Policy'))

    secret = property(
        fget=lambda self: self._secret.get_value(),
        fset=lambda self, x: self._secret.set_value(x),
        doc="The secret key itself.")

    counter = property(
        fget=lambda self: self._counter.get_value(),
        fset=lambda self, x: self._counter.set_value(x),
        doc="An event counter for event-based OTP.")

    time_offset = property(
        fget=lambda self: self._time_offset.get_value(),
        fset=lambda self, x: self._time_offset.set_value(x),
        doc="A time offset for time-based OTP (number of intervals).")

    time_interval = property(
        fget=lambda self: self._time_interval.get_value(),
        fset=lambda self, x: self._time_interval.set_value(x),
        doc="A time interval in seconds.")

    time_drift = property(
        fget=lambda self: self._time_drift.get_value(),
        fset=lambda self, x: self._time_drift.set_value(x),
        doc="Device clock drift value (number of time intervals).")

    def check(self):
        """Check if all MACs in the message are valid."""
        if any((self._secret.check(), self._counter.check(),
                self._time_offset.check(), self._time_interval.check(),
                self._time_drift.check())):
            return True
