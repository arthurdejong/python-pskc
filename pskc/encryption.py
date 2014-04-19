# encryption.py - module for handling encrypted values
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

"""Module that handles encrypted PSKC values.

This module defines an Encryption class that handles the encryption key
and an EncryptedValue wrapper class that can decrypt values using the
encryption key.

The encryption key can be derived using the KeyDerivation class.
"""


import base64

from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2


AES128_CBC = 'http://www.w3.org/2001/04/xmlenc#aes128-cbc'


class EncryptedValue(object):
    """Wrapper class to handle encrypted values.

    Instances of this class provide the following attributes:

      algorithm: name of the encryption algorithm used
      cipher_value: binary encrypted data
    """

    def __init__(self, encryption, encrypted_value=None):
        """Initialise an encrypted value for the provided Key."""
        self.encryption = encryption
        self.algorithm = None
        self.cipher_value = None
        self.parse(encrypted_value)

    def parse(self, encrypted_value):
        """Read encrypted data from the <EncryptedValue> XML tree."""
        from pskc.parse import g_e_v, namespaces
        if encrypted_value is None:
            return
        encryption_method = encrypted_value.find(
            'xenc:EncryptionMethod', namespaces=namespaces)
        self.algorithm = encryption_method.attrib.get('Algorithm')
        value = g_e_v(encrypted_value, 'xenc:CipherData/xenc:CipherValue')
        if value is not None:
            self.cipher_value = base64.b64decode(value)

    def decrypt(self):
        """Decrypt the linked value and return the plaintext value."""
        key = self.encryption.key
        ciphertext = self.cipher_value
        if key is None or ciphertext is None:
            return
        if self.algorithm == AES128_CBC:
            iv = ciphertext[:AES.block_size]
            cipher = AES.new(key, AES.MODE_CBC, iv)
            plaintext = cipher.decrypt(ciphertext[AES.block_size:])
            return plaintext[0:-ord(plaintext[-1])]


PBKDF2_URIS = [
    'http://www.rsasecurity.com/rsalabs/pkcs/schemas/pkcs-5#pbkdf2',
    'http://www.rsasecurity.com/rsalabs/pkcs/schemas/pkcs-5v2-0#pbkdf2',
    'http://www.w3.org/2009/xmlenc11#pbkdf2',
]


class KeyDerivation(object):
    """Handle key derivation.

    The algorithm property contains the key derivation algorithm to use. For
    PBDKF2 the following parameters are set:

      pbkdf2_salt: salt value
      pbkdf2_iterations: number of iterations to use
      pbkdf2_key_length: required key lengt
      pbkdf2_prf: name of pseudorandom function used (HMAC-SHA1 is assumed)
    """

    def __init__(self, key_deriviation=None):
        self.algorithm = None
        # PBKDF2 properties
        self.pbkdf2_salt = None
        self.pbkdf2_iterations = None
        self.pbkdf2_key_length = None
        self.pbkdf2_prf = None
        self.parse(key_deriviation)

    def parse(self, key_deriviation):
        """Read derivation parameters from a <KeyDerivationMethod> element."""
        from pskc.parse import g_e_v, g_e_i, namespaces
        if key_deriviation is None:
            return
        self.algorithm = key_deriviation.attrib.get('Algorithm')
        # PBKDF2 properties
        pbkdf2 = key_deriviation.find(
            'xenc11:PBKDF2-params', namespaces=namespaces)
        if pbkdf2 is None:
            pbkdf2 = key_deriviation.find(
                'pkcs5:PBKDF2-params', namespaces=namespaces)
        if pbkdf2 is not None:
            # get used salt
            value = g_e_v(pbkdf2, 'Salt/Specified')
            if value is not None:
                self.pbkdf2_salt = base64.b64decode(value)
            # required number of iterations
            self.pbkdf2_iterations = g_e_i(pbkdf2, 'IterationCount')
            # key length
            self.pbkdf2_key_length = g_e_i(pbkdf2, 'KeyLength')
            # pseudorandom function used
            prf = pbkdf2.find('PRF', namespaces=namespaces)
            if prf is not None:
                self.pbkdf2_prf = prf.attrib.get('Algorithm')

    def generate(self, password):
        """Derive a key from the password."""
        if self.algorithm in PBKDF2_URIS:
            # TODO: support pseudorandom function (prf)
            return PBKDF2(
                password, self.pbkdf2_salt, dkLen=self.pbkdf2_key_length,
                count=self.pbkdf2_iterations, prf=None)


class Encryption(object):
    """Class for handling encryption keys that are used in the PSKC file.

    Encryption generally uses a symmetric key that is used to encrypt some
    of the information stored in PSKC files (typically the seed). This
    class provides the following values:

      id: identifier of the key
      key_names: list of names for the key
      key_name: (first) name of the key (usually there is only one)
      key: the key value itself (binary form)

    The key can either be included in the PSKC file (in that case it
    automatically picked up) or derived using the derive_key() method.
    """

    def __init__(self, key_info=None):
        self.id = None
        self.key_names = []
        self.key = None
        self.derivation = KeyDerivation()
        self.parse(key_info)

    def parse(self, key_info):
        """Read encryption information from the <EncryptionKey> XML tree."""
        from pskc.parse import g_e_v, namespaces
        if key_info is None:
            return
        self.id = key_info.attrib.get('Id')
        for name in key_info.findall('ds:KeyName', namespaces=namespaces):
            self.key_names.append(g_e_v(name, '.'))
        for name in key_info.findall(
                'xenc11:DerivedKey/xenc11:MasterKeyName',
                namespaces=namespaces):
            self.key_names.append(g_e_v(name, '.'))
        self.derivation.parse(key_info.find(
            'xenc11:DerivedKey/xenc11:KeyDerivationMethod',
            namespaces=namespaces))

    @property
    def key_name(self):
        """Provide the name of the (first) key."""
        if self.key_names:
            return self.key_names[0]

    def derive_key(self, password):
        """Derive a key from the password."""
        self.key = self.derivation.generate(password)
