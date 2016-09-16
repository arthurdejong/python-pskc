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

    def __init__(self, key):
        self.pskc = key.pskc
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
        if self.value is not None:
            return self.value
        if self.cipher_value:
            # check MAC and decrypt
            self.check()
            return self._from_bin(self.pskc.encryption.decrypt_value(
                self.cipher_value, self.algorithm))

    def set_value(self, value):
        """Set the unencrypted value."""
        self.value = value
        self.cipher_value = None
        self.algorithm = None
        self.value_mac = None

    def check(self):
        """Check whether the embedded MAC is correct."""
        # this checks the encrypted value
        if self.cipher_value and self.value_mac:
            return self.pskc.mac.check_value(
                self.cipher_value, self.value_mac)


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

    def __init__(self, pskc):

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
        if all(x is not False for x in (
                self._secret.check(), self._counter.check(),
                self._time_offset.check(), self._time_interval.check(),
                self._time_drift.check())):
            return True
