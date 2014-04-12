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

import base64

from Crypto.Cipher import AES


AES128_CBC = 'http://www.w3.org/2001/04/xmlenc#aes128-cbc'


class EncryptedValue(object):
    """Wrapper class to handle encrypted values.

    Instances of this class provide the following attributes:

      algorithm: name of the encryption algorithm used
      cipher_value: binary encrypted data
    """

    def __init__(self, encryption, encrypted_value=None):
        """Initialise an encrypted value for the provided Key."""
        self.algorithm = None
        self.cipher_value = None
        self.encryption = encryption
        self.parse(encrypted_value)

    def parse(self, encrypted_value):
        """Read encrypted data from the EncryptedValue XML tree."""
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


class Encryption(object):
    """Class for handling encryption keys that are used in the PSKC file."""

    def __init__(self, key_info=None):
        self.key_names = []
        self.key = None
        if key_info is not None:
            self.parse(key_info)

    def parse(self, key_info):
        """Read encryption information from the EncryptionKey XML tree."""
        from pskc.parse import g_e_v, namespaces
        for name in key_info.findall('ds:KeyName', namespaces=namespaces):
            self.key_names.append(g_e_v(name, '.'))

    @property
    def key_name(self):
        if self.key_names:
            return self.key_names[0]
