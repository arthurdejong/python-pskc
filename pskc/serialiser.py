# serialiser.py - PSKC file parsing functions
# coding: utf-8
#
# Copyright (C) 2016-2025 Arthur de Jong
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

from __future__ import annotations

import base64
from typing import Callable, IO, Sequence, TYPE_CHECKING

from pskc.key import EncryptedIntegerValue, EncryptedValue
from pskc.xml import find, mk_elem, move_namespaces, reformat, tostring

if TYPE_CHECKING:  # pragma: no cover (only for mypy)
    from lxml.etree import _Element

    from pskc import PSKC
    from pskc.device import Device
    from pskc.encryption import Encryption, KeyDerivation
    from pskc.key import Key
    from pskc.mac import MAC
    from pskc.policy import Policy
    from pskc.signature import Signature


def my_b64encode(value: bytes | str) -> str:
    """Wrap around b64encode to handle types correctly."""
    if not isinstance(value, bytes):
        value = value.encode()
    return base64.b64encode(value).decode()


class PSKCSerialiser:
    """Class for serialising a PSKC structure to PSKC 1.0 XML."""

    @classmethod
    def serialise_file(
        cls,
        pskc: PSKC,
        output: IO[str] | IO[bytes],
    ) -> None:
        """Write the PSKC structure to the specified output file."""
        xml = tostring(cls.serialise_document(pskc))
        try:
            output.write(xml)  # type: ignore[arg-type]
        except TypeError:
            # fall back to writing as string
            output.write(xml.decode('utf-8'))  # type: ignore[call-overload]

    @classmethod
    def serialise_document(cls, pskc: PSKC) -> _Element:
        """Convert the PSKC structure to an element tree structure."""
        container: _Element = mk_elem('pskc:KeyContainer', Version='1.0', Id=pskc.id)  # type: ignore[assignment]
        cls.serialise_encryption(pskc.encryption, container)
        cls.serialise_mac(pskc.mac, container)
        for device in pskc.devices:
            cls.serialise_key_package(device, container)
        return cls.serialise_signature(pskc.signature, container)

    @classmethod
    def serialise_encryption(cls, encryption: Encryption, container: _Element) -> None:
        """Provide an XML element tree for the encryption information."""
        if all(x is None
               for x in (encryption.id, encryption.key_name, encryption.key,
                         encryption.derivation.algorithm)):
            return
        encryption_key: _Element = mk_elem(  # type: ignore[assignment]
            container, 'pskc:EncryptionKey', Id=encryption.id, empty=True)
        if encryption.derivation.algorithm:
            cls.serialise_key_derivation(
                encryption.derivation, encryption_key, encryption.key_names)
        else:
            for name in encryption.key_names:
                mk_elem(encryption_key, 'ds:KeyName', name)

    @classmethod
    def serialise_key_derivation(
        cls,
        derivation: KeyDerivation,
        encryption_key: _Element,
        key_names: Sequence[str],
    ) -> None:
        """Provide an XML structure for the key derivation properties."""
        assert derivation.algorithm
        derived_key = mk_elem(encryption_key, 'xenc11:DerivedKey', empty=True)
        key_derivation = mk_elem(derived_key, 'xenc11:KeyDerivationMethod',
                                 Algorithm=derivation.algorithm)
        if derivation.algorithm.endswith('#pbkdf2'):
            pbkdf2 = mk_elem(key_derivation, 'xenc11:PBKDF2-params',
                             empty=True)
            if derivation.pbkdf2_salt:
                salt = mk_elem(pbkdf2, 'Salt', empty=True)
                mk_elem(salt, 'Specified',
                        base64.b64encode(derivation.pbkdf2_salt).decode())
            mk_elem(pbkdf2, 'IterationCount', derivation.pbkdf2_iterations)
            mk_elem(pbkdf2, 'KeyLength', derivation.pbkdf2_key_length)
            mk_elem(pbkdf2, 'PRF', derivation.pbkdf2_prf)
        # TODO: serialise ReferenceList/DataReference
        for name in key_names:
            mk_elem(derived_key, 'xenc11:MasterKeyName', name)

    @classmethod
    def serialise_mac(cls, mac: MAC, container: _Element) -> None:
        """Provide an XML structure for the encrypted MAC key."""
        key_value = getattr(mac, '_key', None) or mac.pskc.encryption.key
        if not mac.algorithm and not key_value:
            return
        mac_method = mk_elem(
            container, 'pskc:MACMethod', Algorithm=mac.algorithm, empty=True)
        if not key_value:
            return
        # encrypt the mac key if needed
        if not isinstance(key_value, EncryptedValue):
            key_value = EncryptedValue.create(mac.pskc, key_value)
        # construct encrypted MACKey
        algorithm = key_value.algorithm or mac.pskc.encryption.algorithm
        cipher_value = key_value.cipher_value
        assert cipher_value
        if mac.pskc.encryption.iv:
            cipher_value = mac.pskc.encryption.iv + cipher_value
        mac_key = mk_elem(mac_method, 'pskc:MACKey', empty=True)
        mk_elem(mac_key, 'xenc:EncryptionMethod', Algorithm=algorithm)
        cipher_data = mk_elem(mac_key, 'xenc:CipherData', empty=True)
        mk_elem(cipher_data, 'xenc:CipherValue',
                base64.b64encode(cipher_value).decode())

    @classmethod
    def serialise_key_package(cls, device: Device, container: _Element) -> None:
        """Provide an XML structure for key package."""
        key_package = mk_elem(container, 'pskc:KeyPackage', empty=True)
        assert key_package is not None
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
    def serialise_key(cls, key: Key, key_package: _Element) -> None:
        """Provide an XML structure for the key information."""
        key_elm: _Element = mk_elem(  # type: ignore[assignment]
            key_package, 'pskc:Key', empty=True, Id=key.id, Algorithm=key.algorithm)
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
        cls.serialise_data(
            key, 'secret', key_elm, 'pskc:Secret')
        cls.serialise_data(
            key, 'counter', key_elm, 'pskc:Counter')
        cls.serialise_data(
            key, 'time_offset', key_elm, 'pskc:Time')
        cls.serialise_data(
            key, 'time_interval', key_elm, 'pskc:TimeInterval')
        cls.serialise_data(
            key, 'time_drift', key_elm, 'pskc:TimeDrift')
        mk_elem(key_elm, 'pskc:UserId', key.key_userid)
        cls.serialise_policy(key.policy, key_elm)

    @classmethod
    def serialise_data(cls, key: Key, field: str, key_elm: _Element, tag: str) -> None:
        """Provide an XML structure for the key material."""
        value: bytes | str | EncryptedValue | None = getattr(key, '_%s' % field, None)
        pskc = key.device.pskc
        # skip empty values
        if value in (None, ''):
            return
        assert value is not None
        # get the value2text and encryption storage
        if field == 'secret':
            value2text: Callable[[bytes | str], str] = my_b64encode
            encrypted_value_cls = EncryptedValue
        else:
            value2text = str
            encrypted_value_cls = EncryptedIntegerValue
        # find the data tag and create our tag under it
        data = find(key_elm, 'pskc:Data')
        if data is None:
            data = mk_elem(key_elm, 'pskc:Data', empty=True)
        element = mk_elem(data, tag, empty=True)
        # see if we should encrypt the value
        if field in pskc.encryption.fields and not isinstance(value, EncryptedValue):
            value = encrypted_value_cls.create(pskc, value)
        # write out value
        if not isinstance(value, EncryptedValue):
            # unencrypted value
            mk_elem(element, 'pskc:PlainValue', value2text(value))
        else:
            # encrypted value
            algorithm = value.algorithm or pskc.encryption.algorithm
            cipher_value = value.cipher_value
            if pskc.encryption.iv:
                cipher_value = pskc.encryption.iv + cipher_value
            encrypted_value = mk_elem(
                element, 'pskc:EncryptedValue', empty=True)
            mk_elem(encrypted_value, 'xenc:EncryptionMethod',
                    Algorithm=algorithm)
            cipher_data = mk_elem(
                encrypted_value, 'xenc:CipherData', empty=True)
            mk_elem(cipher_data, 'xenc:CipherValue',
                    base64.b64encode(cipher_value).decode())
            if value.mac_value:
                mk_elem(element, 'pskc:ValueMAC',
                        base64.b64encode(value.mac_value).decode())

    @classmethod
    def serialise_policy(cls, policy: Policy, key_elm: _Element) -> None:
        """Provide an XML structure with the key policy information."""
        # check if any policy attribute is set
        if not policy.key_usage and all(x is None for x in (
                policy.start_date, policy.expiry_date,
                policy.number_of_transactions, policy.pin_key_id,
                policy.pin_usage, policy.pin_max_failed_attempts,
                policy.pin_min_length, policy.pin_max_length,
                policy.pin_encoding)):
            return
        policy_elm = mk_elem(key_elm, 'pskc:Policy', empty=True)
        mk_elem(policy_elm, 'pskc:StartDate', policy.start_date)
        mk_elem(policy_elm, 'pskc:ExpiryDate', policy.expiry_date)
        mk_elem(policy_elm, 'pskc:PINPolicy',
                PINKeyId=policy.pin_key_id,
                PINUsageMode=policy.pin_usage,
                MaxFailedAttempts=policy.pin_max_failed_attempts,
                MinLength=policy.pin_min_length,
                MaxLength=policy.pin_max_length,
                PINEncoding=policy.pin_encoding)
        for usage in policy.key_usage:
            mk_elem(policy_elm, 'pskc:KeyUsage', usage)
        mk_elem(policy_elm, 'pskc:NumberOfTransactions',
                policy.number_of_transactions)

    @classmethod
    def serialise_signature(cls, signature: Signature, container: _Element) -> _Element:
        """Provide an XML structure for embedded XML signature."""
        if not signature.key:
            return container
        # move the namespace to the root element and reformat before signing
        mk_elem(container, 'ds:Signature', Id='placeholder')
        container = move_namespaces(container)
        reformat(container)
        # sign the document
        return signature.sign_xml(container)
