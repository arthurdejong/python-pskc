# key.py - module for handling keys from pskc files
# coding: utf-8
#
# Copyright (C) 2014-2025 Arthur de Jong
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

from __future__ import annotations


import array
import binascii
from typing import Any, TYPE_CHECKING, cast

from pskc.policy import Policy

if TYPE_CHECKING:  # pragma: no cover (only for mypy)
    from pskc import PSKC
    from pskc.device import Device


class EncryptedValue:
    """A container for an encrypted value."""

    def __init__(self, cipher_value: bytes, mac_value: bytes | None, algorithm: str | None) -> None:
        self.cipher_value = cipher_value
        self.mac_value = mac_value
        self.algorithm = algorithm

    @classmethod
    def create(cls, pskc: PSKC, value: bytes | bytearray | str) -> EncryptedValue:
        """Construct an encrypted value from a plaintext value."""
        # force conversion to bytestring
        if not isinstance(value, (bytes, bytearray)):
            value = value.encode()
        cipher_value = pskc.encryption.encrypt_value(cast(bytes, value))
        mac_value = None
        if pskc.mac.algorithm:
            mac_value = pskc.mac.generate_mac(cipher_value)
        assert pskc.encryption.algorithm
        return cls(cipher_value, mac_value, pskc.encryption.algorithm)

    def get_value(self, pskc: PSKC) -> bytes:
        """Provide the decrypted value."""
        from pskc.exceptions import DecryptionError
        plaintext = pskc.encryption.decrypt_value(self.cipher_value, self.algorithm)
        # allow MAC over plaintext or ciphertext
        # (RFC 6030 implies MAC over ciphertext but older draft used
        # MAC over plaintext)
        if self.mac_value and self.mac_value not in (
                pskc.mac.generate_mac(self.cipher_value),
                pskc.mac.generate_mac(plaintext)):
            raise DecryptionError('MAC value does not match')
        return plaintext


class EncryptedIntegerValue(EncryptedValue):
    """Class representing an encrypted integer value."""

    @classmethod
    def create(cls, pskc: PSKC, value: int) -> EncryptedValue:  # type: ignore[override]
        """Construct an encrypted value from a plaintext value."""
        str_value = '%x' % value
        n = len(str_value)
        bytes_value = binascii.unhexlify(str_value.zfill(n + (n & 1)))
        return super(EncryptedIntegerValue, cls).create(pskc, bytes_value)

    def get_value(self, pskc: PSKC) -> int:  # type: ignore[override]
        """Provide the decrypted integer value."""
        value = super(EncryptedIntegerValue, self).get_value(pskc)
        # try to handle value as ASCII representation
        if value.isdigit():
            return int(value)
        # fall back to do big-endian decoding
        result = 0
        for x in array.array('B', value):
            result = (result << 8) + x
        return result


class DataTypeProperty:
    """A data descriptor that delegates actions to DataType instances."""

    def __init__(self, name: str, doc: str) -> None:
        self.name = name
        self.__doc__ = doc

    def __get__(self, obj: Key, objtype: type | None) -> Any:
        value = getattr(obj, '_' + self.name, None)
        if isinstance(value, EncryptedValue):
            return value.get_value(obj.device.pskc)
        else:
            return value

    def __set__(self, obj: Key, val: Any) -> None:
        setattr(obj, '_' + self.name, val)


class DeviceProperty:
    """A data descriptor that delegates actions to the Device instance."""

    def __init__(self, name: str) -> None:
        self.name = name

    def __get__(self, obj: Key, objtype: type | None) -> Any:
        return getattr(obj.device, self.name)

    def __set__(self, obj: Key, val: Any) -> None:
        setattr(obj.device, self.name, val)


class Key:
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

    def __init__(self, device: Device) -> None:

        self.device = device

        self.id: str | None = None
        self.algorithm: str | None = None

        self.issuer: str | None = None
        self.key_profile: str | None = None
        self.key_reference: str | None = None
        self.friendly_name: str | None = None
        self.key_userid: str | None = None

        self.algorithm_suite: str | None = None

        self.challenge_encoding: str | None = None
        self.challenge_min_length: int | None = None
        self.challenge_max_length: int | None = None
        self.challenge_check: bool | None = None

        self.response_encoding: str | None = None
        self.response_length: int | None = None
        self.response_check: bool | None = None

        self.policy = Policy(self)

    secret: bytes | None = DataTypeProperty(  # type: ignore[assignment]
        'secret', 'The secret key itself.')
    counter: int | None = DataTypeProperty(  # type: ignore[assignment]
        'counter', 'An event counter for event-based OTP.')
    time_offset: int | None = DataTypeProperty(  # type: ignore[assignment]
        'time_offset',
        'A time offset for time-based OTP (number of intervals).')
    time_interval: int | None = DataTypeProperty(  # type: ignore[assignment]
        'time_interval', 'A time interval in seconds.')
    time_drift: int | None = DataTypeProperty(  # type: ignore[assignment]
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

    def check(self) -> bool:
        """Check if all MACs in the message are valid.

        This will return `None` if there is no MAC to be checked. It will return
        True if all the MACs match. If any MAC fails a
        `DecryptionError` exception is raised.
        """
        if all(x is not False for x in (
                self.secret, self.counter, self.time_offset,
                self.time_interval, self.time_drift)):
            return True
        assert False  # pragma: no cover (only for mypy)  # noqa: B011

    @property
    def userid(self) -> str:
        """User identifier (either the key or device userid)."""
        return self.key_userid or self.device_userid
