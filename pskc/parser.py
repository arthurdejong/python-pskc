# parser.py - PSKC file parsing functions
# coding: utf-8
#
# Copyright (C) 2016 Arthur de Jong
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

"""Module for parsing PSKC files."""


from pskc.algorithms import normalise_algorithm
from pskc.exceptions import ParseError
from pskc.xml import (
    find, findall, findbin, findint, findtext, findtime, getbool, getint,
    parse, remove_namespaces)


class PSKCParser(object):

    @classmethod
    def parse_file(cls, pskc, filename):
        try:
            tree = parse(filename)
        except Exception:
            raise ParseError('Error parsing XML')
        remove_namespaces(tree)
        cls.parse_document(pskc, tree.getroot())

    @classmethod
    def parse_document(cls, pskc, container):
        """Read information from the provided <KeyContainer> tree."""
        if container.tag != 'KeyContainer':
            raise ParseError('Missing KeyContainer')
        # the version of the PSKC schema
        pskc.version = container.get('Version')
        if pskc.version != '1.0':
            raise ParseError('Unsupported version %r' % pskc.version)
        # unique identifier for the container
        pskc.id = container.get('Id')
        # handle EncryptionKey entries
        cls.parse_encryption(pskc.encryption, find(container, 'EncryptionKey'))
        # handle MACMethod entries
        cls.parse_mac_method(pskc.mac, find(container, 'MACMethod'))
        # handle KeyPackage entries
        for key_package in findall(container, 'KeyPackage'):
            cls.parse_key_package(pskc.add_device(), key_package)

    @classmethod
    def parse_encryption(cls, encryption, key_info):
        """Read encryption information from the <EncryptionKey> XML tree."""
        if key_info is None:
            return
        encryption.id = key_info.get('Id')
        for name in findall(key_info, 'KeyName'):
            encryption.key_names.append(findtext(name, '.'))
        for name in findall(key_info, 'DerivedKey/MasterKeyName'):
            encryption.key_names.append(findtext(name, '.'))
        cls.parse_key_derivation(encryption.derivation, find(
            key_info, 'DerivedKey/KeyDerivationMethod'))

    @classmethod
    def parse_key_derivation(cls, derivation, key_derivation):
        """Read derivation parameters from a <KeyDerivationMethod> element."""
        if key_derivation is None:
            return
        derivation.algorithm = key_derivation.get('Algorithm')
        # PBKDF2 properties
        pbkdf2 = find(key_derivation, 'PBKDF2-params')
        if pbkdf2 is not None:
            # get used salt
            derivation.pbkdf2_salt = findbin(pbkdf2, 'Salt/Specified')
            # required number of iterations
            derivation.pbkdf2_iterations = findint(pbkdf2, 'IterationCount')
            # key length
            derivation.pbkdf2_key_length = findint(pbkdf2, 'KeyLength')
            # pseudorandom function used
            prf = find(pbkdf2, 'PRF')
            if prf is not None:
                derivation.pbkdf2_prf = normalise_algorithm(
                    prf.get('Algorithm'))

    @classmethod
    def parse_mac_method(cls, mac, mac_method):
        """Read MAC information from the <MACMethod> XML tree."""
        if mac_method is None:
            return
        mac.algorithm = mac_method.get('Algorithm')
        mac_key = find(mac_method, 'MACKey')
        if mac_key is not None:
            mac.key_cipher_value = findbin(mac_key, 'CipherData/CipherValue')
            encryption_method = find(mac_key, 'EncryptionMethod')
            if encryption_method is not None:
                mac.key_algorithm = encryption_method.attrib.get('Algorithm')
        mac_key_reference = findtext(mac_method, 'MACKeyReference')

    @classmethod
    def parse_key_package(cls, device, key_package):
        """Read key information from the provided <KeyPackage> tree."""

        device.manufacturer = findtext(key_package, 'DeviceInfo/Manufacturer')
        device.serial = findtext(key_package, 'DeviceInfo/SerialNo')
        device.model = findtext(key_package, 'DeviceInfo/Model')
        device.issue_no = findtext(key_package, 'DeviceInfo/IssueNo')
        device.device_binding = findtext(
            key_package, 'DeviceInfo/DeviceBinding')
        device.start_date = findtime(key_package, 'DeviceInfo/StartDate')
        device.expiry_date = findtime(key_package, 'DeviceInfo/ExpiryDate')
        device.device_userid = findtext(key_package, 'DeviceInfo/UserId')

        device.crypto_module = findtext(key_package, 'CryptoModuleInfo/Id')

        for key_elm in findall(key_package, 'Key'):
            cls.parse_key(device.add_key(), key_elm)

    @classmethod
    def parse_key(cls, key, key_elm):
        """Read key information from the provided <KeyPackage> tree."""

        key.id = key_elm.get('Id')
        key.algorithm = key_elm.get('Algorithm')

        data = find(key_elm, 'Data')
        if data is not None:
            cls.parse_datatype(key._secret, find(data, 'Secret'))
            cls.parse_datatype(key._counter, find(data, 'Counter'))
            cls.parse_datatype(key._time_offset, find(data, 'Time'))
            cls.parse_datatype(key._time_interval, find(data, 'TimeInterval'))
            cls.parse_datatype(key._time_drift, find(data, 'TimeDrift'))

        key.issuer = findtext(key_elm, 'Issuer')
        key.key_profile = findtext(key_elm, 'KeyProfileId')
        key.key_reference = findtext(key_elm, 'KeyReference')
        key.friendly_name = findtext(key_elm, 'FriendlyName')
        # TODO: support multi-language values of <FriendlyName>
        key.key_userid = findtext(key_elm, 'UserId')

        key.algorithm_suite = findtext(
            key_elm, 'AlgorithmParameters/Suite')

        challenge_format = find(
            key_elm, 'AlgorithmParameters/ChallengeFormat')
        if challenge_format is not None:
            key.challenge_encoding = challenge_format.get('Encoding')
            key.challenge_min_length = getint(challenge_format, 'Min')
            key.challenge_max_length = getint(challenge_format, 'Max')
            key.challenge_check = getbool(
                challenge_format, 'CheckDigits', getbool(
                    challenge_format, 'CheckDigit'))

        response_format = find(
            key_elm, 'AlgorithmParameters/ResponseFormat')
        if response_format is not None:
            key.response_encoding = response_format.get('Encoding')
            key.response_length = getint(response_format, 'Length')
            key.response_check = getbool(
                response_format, 'CheckDigits', getbool(
                    response_format, 'CheckDigit'))

        cls.parse_policy(key.policy, find(key_elm, 'Policy'))

    @classmethod
    def parse_datatype(cls, dt, element):
        """Read information from the provided element.

        The element is expected to contain <PlainValue>, <EncryptedValue>
        and/or <ValueMAC> elements that contain information on the actual
        value."""
        if element is None:
            return
        # read plaintext value from <PlainValue>
        plain_value = findtext(element, 'PlainValue')
        if plain_value is not None:
            dt.value = dt._from_text(plain_value)
        # read encrypted data from <EncryptedValue>
        encrypted_value = find(element, 'EncryptedValue')
        if encrypted_value is not None:
            dt.cipher_value = findbin(
                encrypted_value, 'CipherData/CipherValue')
            encryption_method = find(encrypted_value, 'EncryptionMethod')
            if encryption_method is not None:
                dt.algorithm = encryption_method.attrib.get('Algorithm')
                # store the found algorithm in the pskc.encryption property
                if not dt.pskc.encryption.algorithm and dt.algorithm:
                    dt.pskc.encryption.algorithm = dt.algorithm
        # read MAC information from <ValueMAC>
        value_mac = findbin(element, 'ValueMAC')
        if value_mac is not None:
            dt.value_mac = value_mac

    @classmethod
    def parse_policy(cls, policy, policy_elm):
        """Read key policy information from the provided <Policy> tree."""
        if policy_elm is None:
            return

        policy.start_date = findtime(policy_elm, 'StartDate')
        policy.expiry_date = findtime(policy_elm, 'ExpiryDate')
        policy.number_of_transactions = findint(
            policy_elm, 'NumberOfTransactions')
        for key_usage in findall(policy_elm, 'KeyUsage'):
            policy.key_usage.append(findtext(key_usage, '.'))

        pin_policy_elm = find(policy_elm, 'PINPolicy')
        if pin_policy_elm is not None:
            policy.pin_key_id = pin_policy_elm.get('PINKeyId')
            policy.pin_usage = pin_policy_elm.get('PINUsageMode')
            policy.pin_max_failed_attemtps = getint(
                pin_policy_elm, 'MaxFailedAttempts')
            policy.pin_min_length = getint(pin_policy_elm, 'MinLength')
            policy.pin_max_length = getint(pin_policy_elm, 'MaxLength')
            policy.pin_encoding = pin_policy_elm.get('PINEncoding')
            # check for child elements
            if list(pin_policy_elm):
                policy.unknown_policy_elements = True
            # check for unknown attributes
            known_attributes = set([
                'PINKeyId', 'PINUsageMode', 'MaxFailedAttempts', 'MinLength',
                'MaxLength', 'PINEncoding'])
            if set(pin_policy_elm.keys()) - known_attributes:
                policy.unknown_policy_elements = True

        # check for other child elements
        known_children = set([
            'StartDate', 'ExpiryDate', 'NumberOfTransactions', 'KeyUsage',
            'PINPolicy'])
        for child in policy_elm:
            if child.tag not in known_children:
                policy.unknown_policy_elements = True
