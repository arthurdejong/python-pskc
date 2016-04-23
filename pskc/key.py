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

    def parse(self, element):
        """Read information from the provided element.

        The element is expected to contain <PlainValue>, <EncryptedValue>
        and/or <ValueMAC> elements that contain information on the actual
        value."""
        from pskc.xml import find, findtext, findbin
        if element is None:
            return
        # read plaintext value from <PlainValue>
        plain_value = findtext(element, 'PlainValue')
        if plain_value is not None:
            self.value = self._from_text(plain_value)
        # read encrypted data from <EncryptedValue>
        encrypted_value = find(element, 'EncryptedValue')
        if encrypted_value is not None:
            self.cipher_value = findbin(
                encrypted_value, 'CipherData/CipherValue')
            encryption_method = find(encrypted_value, 'EncryptionMethod')
            if encryption_method is not None:
                self.algorithm = encryption_method.attrib.get('Algorithm')
                # store the found algorithm in the pskc.encryption property
                if not self.pskc.encryption.algorithm and self.algorithm:
                    self.pskc.encryption.algorithm = self.algorithm
        # read MAC information from <ValueMAC>
        value_mac = findbin(element, 'ValueMAC')
        if value_mac is not None:
            self.value_mac = value_mac

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

    def make_xml(self, key, tag, field):
        from pskc.xml import find, mk_elem
        # skip empty values
        if self.value in (None, '') and not self.cipher_value:
            return
        # find the data tag and create our tag under it
        data = find(key, 'pskc:Data')
        if data is None:
            data = mk_elem(key, 'pskc:Data', empty=True)
        element = mk_elem(data, tag, empty=True)
        # see if we should encrypt
        if field in self.pskc.encryption.fields and not self.cipher_value:
            self.cipher_value = self.pskc.encryption.encrypt_value(
                self._to_bin(self.value))
            self.algorithm = self.pskc.encryption.algorithm
            self.value = None
        # write out value
        if self.cipher_value:
            encrypted_value = mk_elem(
                element, 'pskc:EncryptedValue', empty=True)
            mk_elem(
                encrypted_value, 'xenc:EncryptionMethod',
                Algorithm=self.algorithm)
            cipher_data = mk_elem(
                encrypted_value, 'xenc:CipherData', empty=True)
            mk_elem(
                cipher_data, 'xenc:CipherValue',
                base64.b64encode(self.cipher_value).decode())
            if self.value_mac:
                mk_elem(element, 'pskc:ValueMAC', base64.b64encode(
                    self.value_mac).decode())
            elif self.pskc.mac.algorithm:
                mk_elem(element, 'pskc:ValueMAC', base64.b64encode(
                    self.pskc.mac.generate_mac(self.cipher_value)
                ).decode())
        else:
            mk_elem(element, 'pskc:PlainValue', self._to_text(self.value))

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

    def parse(self, key_package):
        """Read key information from the provided <KeyPackage> tree."""
        from pskc.xml import find, findtext, findtime, getint, getbool

        key = find(key_package, 'Key')
        if key is not None:
            self.id = key.get('Id')
            self.algorithm = key.get('Algorithm')

        data = find(key_package, 'Key/Data')
        if data is not None:
            self._secret.parse(find(data, 'Secret'))
            self._counter.parse(find(data, 'Counter'))
            self._time_offset.parse(find(data, 'Time'))
            self._time_interval.parse(find(data, 'TimeInterval'))
            self._time_drift.parse(find(data, 'TimeDrift'))

        self.issuer = findtext(key_package, 'Key/Issuer')
        self.key_profile = findtext(key_package, 'Key/KeyProfileId')
        self.key_reference = findtext(key_package, 'Key/KeyReference')
        self.friendly_name = findtext(key_package, 'Key/FriendlyName')
        # TODO: support multi-language values of <FriendlyName>
        self.key_userid = findtext(key_package, 'Key/UserId')

        self.manufacturer = findtext(key_package, 'DeviceInfo/Manufacturer')
        self.serial = findtext(key_package, 'DeviceInfo/SerialNo')
        self.model = findtext(key_package, 'DeviceInfo/Model')
        self.issue_no = findtext(key_package, 'DeviceInfo/IssueNo')
        self.device_binding = findtext(
            key_package, 'DeviceInfo/DeviceBinding')
        self.start_date = findtime(key_package, 'DeviceInfo/StartDate')
        self.expiry_date = findtime(key_package, 'DeviceInfo/ExpiryDate')
        self.device_userid = findtext(key_package, 'DeviceInfo/UserId')

        self.crypto_module = findtext(key_package, 'CryptoModuleInfo/Id')

        self.algorithm_suite = findtext(
            key_package, 'Key/AlgorithmParameters/Suite')

        challenge_format = find(
            key_package, 'Key/AlgorithmParameters/ChallengeFormat')
        if challenge_format is not None:
            self.challenge_encoding = challenge_format.get('Encoding')
            self.challenge_min_length = getint(challenge_format, 'Min')
            self.challenge_max_length = getint(challenge_format, 'Max')
            self.challenge_check = getbool(
                challenge_format, 'CheckDigits', getbool(
                    challenge_format, 'CheckDigit'))

        response_format = find(
            key_package,
            'Key/AlgorithmParameters/ResponseFormat')
        if response_format is not None:
            self.response_encoding = response_format.get('Encoding')
            self.response_length = getint(response_format, 'Length')
            self.response_check = getbool(
                response_format, 'CheckDigits', getbool(
                    response_format, 'CheckDigit'))

        self.policy.parse(find(key_package, 'Key/Policy'))

    def make_xml(self, container):
        from pskc.xml import mk_elem

        key_package = mk_elem(container, 'pskc:KeyPackage', empty=True)

        if any(x is not None
               for x in (self.manufacturer, self.serial, self.model,
                         self.issue_no, self.device_binding, self.start_date,
                         self.expiry_date, self.device_userid)):
            device_info = mk_elem(key_package, 'pskc:DeviceInfo', empty=True)
            mk_elem(device_info, 'pskc:Manufacturer', self.manufacturer)
            mk_elem(device_info, 'pskc:SerialNo', self.serial)
            mk_elem(device_info, 'pskc:Model', self.model)
            mk_elem(device_info, 'pskc:IssueNo', self.issue_no)
            mk_elem(device_info, 'pskc:DeviceBinding', self.device_binding)
            mk_elem(device_info, 'pskc:StartDate', self.start_date)
            mk_elem(device_info, 'pskc:ExpiryDate', self.expiry_date)
            mk_elem(device_info, 'pskc:UserId', self.device_userid)

        if self.crypto_module is not None:
            crypto_module = mk_elem(key_package, 'pskc:CryptoModuleInfo',
                                    empty=True)
            mk_elem(crypto_module, 'pskc:Id', self.crypto_module)

        key = mk_elem(key_package, 'pskc:Key', empty=True, Id=self.id,
                      Algorithm=self.algorithm, )
        mk_elem(key, 'pskc:Issuer', self.issuer)

        if any((self.algorithm_suite, self.challenge_encoding,
                self.response_encoding, self.response_length)):
            parameters = mk_elem(key, 'pskc:AlgorithmParameters', empty=True)
            mk_elem(parameters, 'pskc:Suite', self.algorithm_suite)
            mk_elem(parameters, 'pskc:ChallengeFormat',
                    Encoding=self.challenge_encoding,
                    Min=self.challenge_min_length,
                    Max=self.challenge_max_length,
                    CheckDigits=self.challenge_check)
            mk_elem(parameters, 'pskc:ResponseFormat',
                    Encoding=self.response_encoding,
                    Length=self.response_length,
                    CheckDigits=self.response_check)

        mk_elem(key, 'pskc:KeyProfileId', self.key_profile)
        mk_elem(key, 'pskc:KeyReference', self.key_reference)
        mk_elem(key, 'pskc:FriendlyName', self.friendly_name)
        self._secret.make_xml(key, 'pskc:Secret', 'secret')
        self._counter.make_xml(key, 'pskc:Counter', 'counter')
        self._time_offset.make_xml(key, 'pskc:Time', 'time_offset')
        self._time_interval.make_xml(key, 'pskc:TimeInterval', 'time_interval')
        self._time_drift.make_xml(key, 'pskc:TimeDrift', 'time_drif')
        mk_elem(key, 'pskc:UserId', self.key_userid)

        self.policy.make_xml(key)

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
