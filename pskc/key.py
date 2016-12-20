# key.py - module for handling keys from pskc files
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

"""Module that handles keys stored in PSKC files."""


import array
import base64
import binascii

from pskc.policy import Policy


class DataType(object):
    """Provide access to possibly encrypted, MAC'ed information.

    This class is meant to be subclassed to provide typed access to stored
    values. Instances of this class provide the following attributes:

      value: unencrypted value
      cipher_value: encrypted value
      algorithm: encryption algorithm of encrypted value
      value_mac: MAC of the encrypted value
    """

    def __init__(self, pskc):
        self.pskc = pskc
        self.value = None
        self.cipher_value = None
        self.algorithm = None
        self.value_mac = None

    @staticmethod
    def _from_text(value):
        """Convert the plain value to native representation."""
        raise NotImplementedError  # pragma: no cover

    @staticmethod
    def _from_bin(value):
        """Convert the unencrypted binary to native representation."""
        raise NotImplementedError  # pragma: no cover

    @staticmethod
    def _to_text(value):
        """Convert the value to an unencrypted string representation."""
        raise NotImplementedError  # pragma: no cover

    def get_value(self):
        """Provide the attribute value, decrypting as needed."""
        from pskc.exceptions import DecryptionError
        if self.value is not None:
            return self.value
        if self.cipher_value:
            plaintext = self.pskc.encryption.decrypt_value(
                self.cipher_value, self.algorithm)
            # allow MAC over plaintext or cipertext
            # (RFC6030 implies MAC over ciphertext but older draft used
            # MAC over plaintext)
            if self.value_mac and self.value_mac not in (
                    self.pskc.mac.generate_mac(self.cipher_value),
                    self.pskc.mac.generate_mac(plaintext)):
                raise DecryptionError('MAC value does not match')
            return self._from_bin(plaintext)

    def set_value(self, value):
        """Set the unencrypted value."""
        self.value = value
        self.cipher_value = None
        self.algorithm = None
        self.value_mac = None


class BinaryDataType(DataType):
    """Subclass of DataType for binary data (e.g. keys)."""

    @staticmethod
    def _from_text(value):
        """Convert the plain value to native representation."""
        return base64.b64decode(value)

    @staticmethod
    def _from_bin(value):
        """Convert the unencrypted binary to native representation."""
        return value

    @staticmethod
    def _to_text(value):
        """Convert the value to an unencrypted string representation."""
        # force conversion to bytestring on Python 3
        if not isinstance(value, type(b'')):
            value = value.encode()  # pragma: no cover (Python 3 specific)
        return base64.b64encode(value).decode()

    @staticmethod
    def _to_bin(value):
        """Convert the value to binary representation for encryption."""
        # force conversion to bytestring on Python 3
        if not isinstance(value, type(b'')):
            value = value.encode()  # pragma: no cover (Python 3 specific)
        return value


class IntegerDataType(DataType):
    """Subclass of DataType for integer types (e.g. counters)."""

    @staticmethod
    def _from_text(value):
        """Convert the plain value to native representation."""
        # try normal integer string parsing
        try:
            return int(value)
        except ValueError:
            pass
        # fall back to base64 decoding
        return IntegerDataType._from_bin(base64.b64decode(value))

    @staticmethod
    def _from_bin(value):
        """Convert the unencrypted binary to native representation."""
        # try to handle value as ASCII representation
        if value.isdigit():
            return int(value)
        # fall back to do big-endian decoding
        result = 0
        for x in array.array('B', value):
            result = (result << 8) + x
        return result

    @staticmethod
    def _to_text(value):
        """Convert the value to an unencrypted string representation."""
        return str(value)

    @staticmethod
    def _to_bin(value):
        """Convert the value to binary representation for encryption."""
        value = '%x' % value
        n = len(value)
        return binascii.unhexlify(value.zfill(n + (n & 1)))


class DataTypeProperty(object):
    """A data descriptor that delegates actions to DataType instances."""

    def __init__(self, name, doc):
        self.name = name
        self.__doc__ = doc

    def __get__(self, obj, objtype):
        return getattr(obj, '_' + self.name).get_value()

    def __set__(self, obj, val):
        getattr(obj, '_' + self.name).set_value(val)


class DeviceProperty(object):
    """A data descriptor that delegates actions to the Device instance."""

    def __init__(self, name):
        self.name = name

    def __get__(self, obj, objtype):
        return getattr(obj.device, self.name)

    def __set__(self, obj, val):
        setattr(obj.device, self.name, val)


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
      algorithm_suite: additional algorithm characteristics (e.g. used hash)
      challenge_encoding: format of the challenge for CR devices
      challenge_min_length: minimum accepted challenge length by device
      challenge_max_length: maximum size challenge accepted by the device
      challenge_check: whether the device will check an embedded check digit
      response_encoding: format of the response the device will generate
      response_length: the length of the response of the device
      response_check: whether the device appends a Luhn check digit
      policy: reference to policy information (see Policy class)

    This class also provides access to the manufacturer, serial, model,
    issue_no, device_binding, start_date, expiry_date, device_userid and
    crypto_module properties of the Device class.
    """

    def __init__(self, device):

        self.device = device

        self.id = None
        self.algorithm = None

        self._secret = BinaryDataType(self.device.pskc)
        self._counter = IntegerDataType(self.device.pskc)
        self._time_offset = IntegerDataType(self.device.pskc)
        self._time_interval = IntegerDataType(self.device.pskc)
        self._time_drift = IntegerDataType(self.device.pskc)

        self.issuer = None
        self.key_profile = None
        self.key_reference = None
        self.friendly_name = None
        self.key_userid = None

        self.algorithm_suite = None

        self.challenge_encoding = None
        self.challenge_min_length = None
        self.challenge_max_length = None
        self.challenge_check = None

        self.response_encoding = None
        self.response_length = None
        self.response_check = None

        self.policy = Policy(self)

    secret = DataTypeProperty(
        'secret', 'The secret key itself.')
    counter = DataTypeProperty(
        'counter', 'An event counter for event-based OTP.')
    time_offset = DataTypeProperty(
        'time_offset',
        'A time offset for time-based OTP (number of intervals).')
    time_interval = DataTypeProperty(
        'time_interval', 'A time interval in seconds.')
    time_drift = DataTypeProperty(
        'time_drift', 'Device clock drift value (number of time intervals).')

    manufacturer = DeviceProperty('manufacturer')
    serial = DeviceProperty('serial')
    model = DeviceProperty('model')
    issue_no = DeviceProperty('issue_no')
    device_binding = DeviceProperty('device_binding')
    start_date = DeviceProperty('start_date')
    expiry_date = DeviceProperty('expiry_date')
    device_userid = DeviceProperty('device_userid')
    crypto_module = DeviceProperty('crypto_module')

    def check(self):
        """Check if all MACs in the message are valid."""
        if all(x is not False for x in (
                self.secret, self.counter, self.time_offset,
                self.time_interval, self.time_drift)):
            return True
