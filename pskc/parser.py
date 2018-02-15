# parser.py - PSKC file parsing functions
# coding: utf-8
#
# Copyright (C) 2016-2018 Arthur de Jong
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


import array
import base64
import copy

from pskc.exceptions import ParseError
from pskc.key import EncryptedIntegerValue, EncryptedValue
from pskc.xml import (
    find, findall, findbin, findint, findtext, findtime, getbool, getint,
    parse, remove_namespaces)


def plain2int(value):
    """Convert a plain text value to an int."""
    # try normal integer string parsing
    try:
        return int(value)
    except ValueError:
        pass
    # fall back to base64 decoding
    value = base64.b64decode(value)
    # try to handle value as ASCII representation
    if value.isdigit():
        return int(value)
    # fall back to do big-endian decoding
    result = 0
    for x in array.array('B', value):
        result = (result << 8) + x
    return result


class PSKCParser(object):
    """Class to read various PSKC XML files into a PSKC structure."""

    @classmethod
    def parse_file(cls, pskc, filename):
        """Parse the provided file and store data in the PSKC instance."""
        try:
            tree = parse(filename)
        except Exception:
            raise ParseError('Error parsing XML')
        # save a clean copy of the tree for signature checking
        pskc.signature.tree = copy.deepcopy(tree)
        cls.parse_document(pskc, tree.getroot())

    @classmethod
    def parse_document(cls, pskc, container):
        """Read information from the provided <KeyContainer> tree."""
        remove_namespaces(container)
        if container.tag not in ('KeyContainer', 'SecretContainer'):
            raise ParseError('Missing KeyContainer')
        # the version of the PSKC schema
        pskc.version = container.get('Version') or container.get('version')
        if (container.tag == 'KeyContainer' and
                pskc.version and
                pskc.version not in ('1', '1.0')):
            raise ParseError('Unsupported version %r' % pskc.version)
        # unique identifier for the container
        pskc.id = (
            container.get('Id') or container.get('ID') or container.get('id'))
        # handle EncryptionKey entries
        cls.parse_encryption(pskc.encryption, find(
            container, 'EncryptionKey', 'EncryptionMethod'))
        # handle MACMethod entries
        cls.parse_mac_method(pskc.mac, find(
            container, 'MACMethod', 'DigestMethod'))
        # fall back to MACAlgorithm
        mac_algorithm = findtext(container, 'MACAlgorithm')
        if mac_algorithm:
            pskc.mac.algorithm = mac_algorithm
        # handle KeyPackage entries
        for key_package in findall(container, 'KeyPackage', 'Device'):
            cls.parse_key_package(pskc.add_device(), key_package)
        # handle Signature entries
        cls.parse_signature(pskc.signature, find(container, 'Signature'))

    @classmethod
    def parse_encryption(cls, encryption, key_info):
        """Read encryption information from the <EncryptionKey> XML tree."""
        if key_info is None:
            return
        encryption.id = key_info.get('Id')
        encryption.algorithm = (
            key_info.get('Algorithm') or
            key_info.get('algorithm') or
            encryption.algorithm)
        for name in findall(key_info,
                            'KeyName', 'DerivedKey/MasterKeyName',
                            'DerivedKey/CarriedKeyName'):
            encryption.key_names.append(findtext(name, '.'))
        encryption.iv = findbin(key_info, 'IV') or encryption.iv
        cls.parse_key_derivation(encryption.derivation, find(
            key_info, 'DerivedKey/KeyDerivationMethod'))
        encryption.derivation.pbkdf2_salt = (
            findbin(key_info, 'PBESalt') or encryption.derivation.pbkdf2_salt)
        encryption.derivation.pbkdf2_iterations = (
            findint(key_info, 'PBEIterationCount') or
            encryption.derivation.pbkdf2_iterations)
        algorithm = (
            key_info.get('Algorithm') or key_info.get('algorithm') or '')
        if (algorithm.lower().startswith('pbe') and
                not encryption.derivation.algorithm):
            encryption.derivation.algorithm = 'pbkdf2'
            encryption.derivation.pbkdf2_key_length = (
                encryption.derivation.pbkdf2_key_length or
                encryption.algorithm_key_lengths[0])

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
                derivation.pbkdf2_prf = prf.get('Algorithm')

    @classmethod
    def parse_mac_method(cls, mac, mac_method):
        """Read MAC information from the <MACMethod> XML tree."""
        if mac_method is None:
            return
        mac.algorithm = (
            mac_method.get('Algorithm') or
            mac_method.get('algorithm'))
        mac_key = find(mac_method, 'MACKey')
        if mac_key is not None:
            algorithm, cipher_value = cls.parse_encrypted_value(mac_key)
            mac.key = EncryptedValue(cipher_value, None, algorithm)

    @classmethod
    def parse_key_package(cls, device, key_package):
        """Read key information from the provided <KeyPackage> tree."""
        # find basic device information
        info = find(key_package, 'DeviceInfo', 'DeviceId')
        if info is not None:
            device.manufacturer = findtext(info, 'Manufacturer')
            device.serial = findtext(info, 'SerialNo')
            device.model = findtext(info, 'Model')
            device.issue_no = findtext(info, 'IssueNo')
            device.device_binding = findtext(info, 'DeviceBinding')
            device.start_date = findtime(info, 'StartDate')
            device.expiry_date = findtime(info, 'ExpiryDate', 'Expiry')
            device.device_userid = findtext(info, 'UserId')
        # find crypto module info
        device.crypto_module = findtext(key_package, 'CryptoModuleInfo/Id')
        # find keys for device
        for key_elm in findall(key_package, 'Key', 'Secret'):
            cls.parse_key(device.add_key(), key_elm)

    @classmethod
    def parse_key(cls, key, key_elm):
        """Read key information from the provided <KeyPackage> tree."""
        # get key basic information
        key.id = (
            key_elm.get('Id') or key_elm.get('KeyId') or
            key_elm.get('SecretId'))
        key.algorithm = (
            key_elm.get('Algorithm') or key_elm.get('KeyAlgorithm') or
            key_elm.get('SecretAlgorithm'))
        # parse data section with possibly encrypted data
        data = find(key_elm, 'Data')
        if data is not None:
            cls.parse_data(key, 'secret', find(data, 'Secret'))
            cls.parse_data(key, 'counter', find(data, 'Counter'))
            cls.parse_data(key, 'time_offset', find(data, 'Time'))
            cls.parse_data(key, 'time_interval', find(data, 'TimeInterval'))
            cls.parse_data(key, 'time_drift', find(data, 'TimeDrift'))
        # parse legacy data elements with name attribute
        for data in findall(key_elm, 'Data'):
            name = data.get('Name')
            if name:
                cls.parse_data(key, dict(
                    secret='secret',
                    counter='counter',
                    time='time_offset',
                    time_interval='time_interval',
                ).get(name.lower()), data)
        # parse more basic key properties
        key.issuer = findtext(key_elm, 'Issuer')
        key.key_profile = findtext(key_elm, 'KeyProfileId')
        key.key_reference = findtext(key_elm, 'KeyReference')
        key.friendly_name = findtext(key_elm, 'FriendlyName')
        # TODO: support multi-language values of <FriendlyName>
        key.key_userid = findtext(key_elm, 'UserId')
        key.algorithm_suite = findtext(
            key_elm, 'AlgorithmParameters/Suite')
        # parse challenge format
        challenge_format = find(
            key_elm,
            'AlgorithmParameters/ChallengeFormat', 'Usage/ChallengeFormat')
        if challenge_format is not None:
            key.challenge_encoding = (
                challenge_format.get('Encoding') or
                challenge_format.get('Format') or
                challenge_format.get('format'))
            key.challenge_min_length = (
                getint(challenge_format, 'Min') or
                getint(challenge_format, 'min'))
            key.challenge_max_length = (
                getint(challenge_format, 'Max') or
                getint(challenge_format, 'max'))
            key.challenge_check = getbool(
                challenge_format, 'CheckDigits', getbool(
                    challenge_format, 'CheckDigit'))
        # parse response format
        response_format = find(
            key_elm,
            'AlgorithmParameters/ResponseFormat', 'Usage/ResponseFormat')
        if response_format is not None:
            key.response_encoding = (
                response_format.get('Encoding') or
                response_format.get('Format') or
                response_format.get('format'))
            key.response_length = (
                getint(response_format, 'Length') or
                getint(response_format, 'length'))
            key.response_check = getbool(
                response_format, 'CheckDigits', getbool(
                    response_format, 'CheckDigit'))
        # parse key policy information
        cls.parse_policy(key.policy, find(key_elm, 'Policy'))
        # parse key usage information
        usage = find(key_elm, 'Usage')
        if usage is not None:
            for att in ('OTP', 'CR', 'Integrity', 'Encrypt', 'Unlock'):
                if getbool(usage, att):
                    key.policy.key_usage.append(att)
        key.policy.start_date = (
            findtime(key_elm, 'StartDate') or key.policy.start_date)
        key.policy.expiry_date = (
            findtime(key_elm, 'ExpiryDate') or key.policy.expiry_date)

    @classmethod
    def parse_encrypted_value(cls, encrypted_value):
        """Read encryption value from <EncryptedValue> element."""
        algorithm = None
        cipher_value = findbin(encrypted_value, 'CipherData/CipherValue')
        encryption_method = find(encrypted_value, 'EncryptionMethod')
        if encryption_method is not None:
            algorithm = encryption_method.attrib.get('Algorithm')
        encryption_scheme = find(
            encrypted_value, 'EncryptionMethod/EncryptionScheme')
        if encryption_scheme is not None:
            algorithm = encryption_scheme.attrib.get('Algorithm') or algorithm
        return (algorithm, cipher_value)

    @classmethod
    def parse_data(cls, key, field, element):
        """Read information from the provided element.

        The element is expected to contain <PlainValue>, <EncryptedValue>
        and/or <ValueMAC> elements that contain information on the actual
        value.
        """
        if element is None:
            return
        pskc = key.device.pskc
        plain_value = None
        cipher_value = None
        algorithm = None
        # get the plain2value function and encryption storage
        if field == 'secret':
            plain2value = base64.b64decode
            encrypted_value_cls = EncryptedValue
        else:
            plain2value = plain2int
            encrypted_value_cls = EncryptedIntegerValue
        # read plaintext value from <PlainValue>
        plain_value = findtext(element, 'PlainValue')
        if plain_value is not None:
            plain_value = plain2value(plain_value)
        # read encrypted data from <EncryptedValue>
        encrypted_value = find(element, 'EncryptedValue')
        if encrypted_value is not None:
            algorithm, cipher_value = cls.parse_encrypted_value(
                encrypted_value)
            # store the found algorithm in the pskc.encryption property
            if not pskc.encryption.algorithm and algorithm:
                pskc.encryption.algorithm = algorithm
        # read MAC information from <ValueMAC>
        mac_value = findbin(element, 'ValueMAC', 'ValueDigest')
        # read legacy <Value> elements (can be plain or encrypted)
        value = findtext(element, 'Value')
        if value is not None:
            if pskc.encryption.algorithm and mac_value:
                cipher_value = findbin(element, 'Value')
            else:
                plain_value = plain2value(value)
        # store the found information
        if plain_value is not None:
            setattr(key, field, plain_value)
        elif cipher_value:
            setattr(key, field,
                    encrypted_value_cls(cipher_value, mac_value, algorithm))

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
            policy.pin_max_failed_attempts = getint(
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

    @classmethod
    def parse_signature(cls, signature, signature_elm):
        """Read signature information from the <Signature> element."""
        if signature_elm is None:
            return
        cm_elm = find(signature_elm, 'SignedInfo/CanonicalizationMethod')
        if cm_elm is not None:
            signature.canonicalization_method = cm_elm.attrib.get('Algorithm')
        sm_elm = find(signature_elm, 'SignedInfo/SignatureMethod')
        if sm_elm is not None:
            signature.algorithm = sm_elm.attrib.get('Algorithm')
        dm_elm = find(signature_elm, 'SignedInfo/Reference/DigestMethod')
        if dm_elm is not None:
            signature.digest_algorithm = dm_elm.attrib.get('Algorithm')
        issuer = find(signature_elm, 'KeyInfo/X509Data/X509IssuerSerial')
        if issuer is not None:
            signature.issuer = findtext(issuer, 'X509IssuerName')
            signature.serial = findtext(issuer, 'X509SerialNumber')
        certificate = findbin(
            signature_elm, 'KeyInfo/X509Data/X509Certificate')
        if certificate:
            certificate = base64.b64encode(certificate)
            signature.certificate = b'\n'.join(
                [b'-----BEGIN CERTIFICATE-----'] +
                [certificate[i:i + 64]
                 for i in range(0, len(certificate), 64)] +
                [b'-----END CERTIFICATE-----'])
