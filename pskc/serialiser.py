# serialiser.py - PSKC file parsing functions
# coding: utf-8
#
# Copyright (C) 2016-2017 Arthur de Jong
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

"""Module for serialising PSKC files to XML."""


import base64

from pskc.xml import find, mk_elem, tostring


class PSKCSerialiser(object):

    @classmethod
    def serialise_file(cls, pskc, output):
        xml = tostring(cls.serialise_document(pskc)) + '\n'.encode('UTF-8')
        try:
            output.write(xml)
        except TypeError:  # pragma: no cover (Python 3 specific)
            # fall back to writing as string for Python 3
            output.write(xml.decode('utf-8'))

    @classmethod
    def serialise_document(cls, pskc):
        container = mk_elem('pskc:KeyContainer', Version=pskc.version,
                            Id=pskc.id)
        cls.serialise_encryption(pskc.encryption, container)
        cls.serialise_mac(pskc.mac, container)
        for device in pskc.devices:
            cls.serialise_key_package(device, container)
        return container

    @classmethod
    def serialise_encryption(cls, encryption, container):
        if all(x is None
               for x in (encryption.id, encryption.key_name, encryption.key,
                         encryption.derivation.algorithm)):
            return
        encryption_key = mk_elem(container, 'pskc:EncryptionKey',
                                 Id=encryption.id, empty=True)
        if encryption.derivation.algorithm:
            cls.serialise_key_derivation(
                encryption.derivation, encryption_key, encryption.key_names)
        else:
            for name in encryption.key_names:
                mk_elem(encryption_key, 'ds:KeyName', name)

    @classmethod
    def serialise_key_derivation(cls, derivation, encryption_key, key_names):
        derived_key = mk_elem(encryption_key, 'xenc11:DerivedKey', empty=True)
        key_derivation = mk_elem(derived_key, 'xenc11:KeyDerivationMethod',
                                 Algorithm=derivation.algorithm)
        if derivation.algorithm.endswith('#pbkdf2'):
            pbkdf2 = mk_elem(key_derivation, 'xenc11:PBKDF2-params',
                             empty=True)
            if derivation.pbkdf2_salt:
                salt = mk_elem(pbkdf2, 'Salt', empty=True)
                mk_elem(salt, 'Specified',
                        base64.b64encode(derivation.pbkdf2_salt))
            mk_elem(pbkdf2, 'IterationCount', derivation.pbkdf2_iterations)
            mk_elem(pbkdf2, 'KeyLength', derivation.pbkdf2_key_length)
            mk_elem(pbkdf2, 'PRF', derivation.pbkdf2_prf)
        # TODO: serialise ReferenceList/DataReference
        for name in key_names:
            mk_elem(derived_key, 'xenc11:MasterKeyName', name)

    @classmethod
    def serialise_mac(cls, mac, container):
        if not mac.algorithm and not mac.key:
            return
        mac_method = mk_elem(
            container, 'pskc:MACMethod', Algorithm=mac.algorithm, empty=True)
        mac_key = mk_elem(mac_method, 'pskc:MACKey', empty=True)
        mk_elem(
            mac_key, 'xenc:EncryptionMethod',
            Algorithm=mac.pskc.encryption.algorithm)
        cipher_data = mk_elem(mac_key, 'xenc:CipherData', empty=True)
        if mac.key_cipher_value:
            mk_elem(cipher_data, 'xenc:CipherValue',
                    base64.b64encode(mac.key_cipher_value).decode())
        elif mac.key_plain_value:
            mk_elem(cipher_data, 'xenc:CipherValue',
                    base64.b64encode(mac.pskc.encryption.encrypt_value(
                        mac.key_plain_value)).decode())

    @classmethod
    def serialise_key_package(cls, device, container):
        key_package = mk_elem(container, 'pskc:KeyPackage', empty=True)
        if any(x is not None
               for x in (device.manufacturer, device.serial, device.model,
                         device.issue_no, device.device_binding,
                         device.start_date, device.expiry_date,
                         device.device_userid)):
            device_info = mk_elem(key_package, 'pskc:DeviceInfo', empty=True)
            mk_elem(device_info, 'pskc:Manufacturer', device.manufacturer)
            mk_elem(device_info, 'pskc:SerialNo', device.serial)
            mk_elem(device_info, 'pskc:Model', device.model)
            mk_elem(device_info, 'pskc:IssueNo', device.issue_no)
            mk_elem(device_info, 'pskc:DeviceBinding', device.device_binding)
            mk_elem(device_info, 'pskc:StartDate', device.start_date)
            mk_elem(device_info, 'pskc:ExpiryDate', device.expiry_date)
            mk_elem(device_info, 'pskc:UserId', device.device_userid)
        if device.crypto_module is not None:
            crypto_module = mk_elem(key_package, 'pskc:CryptoModuleInfo',
                                    empty=True)
            mk_elem(crypto_module, 'pskc:Id', device.crypto_module)
        for key in device.keys:
            cls.serialise_key(key, key_package)

    @classmethod
    def serialise_key(cls, key, key_package):
        key_elm = mk_elem(key_package, 'pskc:Key', empty=True, Id=key.id,
                          Algorithm=key.algorithm, )
        mk_elem(key_elm, 'pskc:Issuer', key.issuer)
        if any((key.algorithm_suite, key.challenge_encoding,
                key.response_encoding, key.response_length)):
            parameters = mk_elem(key_elm, 'pskc:AlgorithmParameters',
                                 empty=True)
            mk_elem(parameters, 'pskc:Suite', key.algorithm_suite)
            mk_elem(parameters, 'pskc:ChallengeFormat',
                    Encoding=key.challenge_encoding,
                    Min=key.challenge_min_length,
                    Max=key.challenge_max_length,
                    CheckDigits=key.challenge_check)
            mk_elem(parameters, 'pskc:ResponseFormat',
                    Encoding=key.response_encoding,
                    Length=key.response_length,
                    CheckDigits=key.response_check)
        mk_elem(key_elm, 'pskc:KeyProfileId', key.key_profile)
        mk_elem(key_elm, 'pskc:KeyReference', key.key_reference)
        mk_elem(key_elm, 'pskc:FriendlyName', key.friendly_name)
        cls.serialise_datatype(
            key._secret, key_elm, 'pskc:Secret', 'secret')
        cls.serialise_datatype(
            key._counter, key_elm, 'pskc:Counter', 'counter')
        cls.serialise_datatype(
            key._time_offset, key_elm, 'pskc:Time', 'time_offset')
        cls.serialise_datatype(
            key._time_interval, key_elm, 'pskc:TimeInterval', 'time_interval')
        cls.serialise_datatype(
            key._time_drift, key_elm, 'pskc:TimeDrift', 'time_drif')
        mk_elem(key_elm, 'pskc:UserId', key.key_userid)
        cls.serialise_policy(key.policy, key_elm)

    @classmethod
    def serialise_datatype(cls, dt, key_elm, tag, field):
        # skip empty values
        if dt.value in (None, '') and not dt.cipher_value:
            return
        # find the data tag and create our tag under it
        data = find(key_elm, 'pskc:Data')
        if data is None:
            data = mk_elem(key_elm, 'pskc:Data', empty=True)
        element = mk_elem(data, tag, empty=True)
        # see if we should encrypt
        if field in dt.pskc.encryption.fields and not dt.cipher_value:
            dt.cipher_value = dt.pskc.encryption.encrypt_value(
                dt._to_bin(dt.value))
            dt.algorithm = dt.pskc.encryption.algorithm
            dt.value = None
        # write out value
        if dt.cipher_value:
            encrypted_value = mk_elem(
                element, 'pskc:EncryptedValue', empty=True)
            mk_elem(
                encrypted_value, 'xenc:EncryptionMethod',
                Algorithm=dt.algorithm)
            cipher_data = mk_elem(
                encrypted_value, 'xenc:CipherData', empty=True)
            mk_elem(
                cipher_data, 'xenc:CipherValue',
                base64.b64encode(dt.cipher_value).decode())
            if dt.value_mac:
                mk_elem(element, 'pskc:ValueMAC', base64.b64encode(
                    dt.value_mac).decode())
            elif dt.pskc.mac.algorithm:
                mk_elem(element, 'pskc:ValueMAC', base64.b64encode(
                    dt.pskc.mac.generate_mac(dt.cipher_value)).decode())
        else:
            mk_elem(element, 'pskc:PlainValue', dt._to_text(dt.value))

    @classmethod
    def serialise_policy(cls, policy, key_elm):
        # check if any policy attribute is set
        if not policy.key_usage and all(x is None for x in (
                policy.start_date, policy.expiry_date,
                policy.number_of_transactions, policy.pin_key_id,
                policy.pin_usage, policy.pin_max_failed_attemtps,
                policy.pin_min_length, policy.pin_max_length,
                policy.pin_encoding)):
            return
        policy_elm = mk_elem(key_elm, 'pskc:Policy', empty=True)
        mk_elem(policy_elm, 'pskc:StartDate', policy.start_date)
        mk_elem(policy_elm, 'pskc:ExpiryDate', policy.expiry_date)
        mk_elem(policy_elm, 'pskc:PINPolicy',
                PINKeyId=policy.pin_key_id,
                PINUsageMode=policy.pin_usage,
                MaxFailedAttempts=policy.pin_max_failed_attemtps,
                MinLength=policy.pin_min_length,
                MaxLength=policy.pin_max_length,
                PINEncoding=policy.pin_encoding)
        for usage in policy.key_usage:
            mk_elem(policy_elm, 'pskc:KeyUsage', usage)
        mk_elem(policy_elm, 'pskc:NumberOfTransactions',
                policy.number_of_transactions)
