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


def unpad(value):
    """Remove padding from the plaintext."""
    return value[0:-ord(value[-1])]


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
        from pskc.parse import find, findbin
        if encrypted_value is None:
            return
        encryption_method = find(encrypted_value, 'xenc:EncryptionMethod')
        if encryption_method is not None:
            self.algorithm = encryption_method.attrib.get('Algorithm')
        self.cipher_value = findbin(
            encrypted_value, 'xenc:CipherData/xenc:CipherValue')

    def decrypt(self):
        """Decrypt the linked value and return the plaintext value."""
        from pskc.exceptions import DecryptionError
        if self.cipher_value is None:
            return
        key = self.encryption.key
        if key is None:
            raise DecryptionError('No key available')
        if self.algorithm is None:
            raise DecryptionError('No algorithm specified')
        if self.algorithm.endswith('#aes128-cbc') or \
           self.algorithm.endswith('#aes192-cbc') or \
           self.algorithm.endswith('#aes256-cbc'):
            from Crypto.Cipher import AES
            if len(key) * 8 != int(self.algorithm[-7:-4]) or \
               len(key) not in AES.key_size:
                raise DecryptionError('Invalid key length')
            iv = self.cipher_value[:AES.block_size]
            ciphertext = self.cipher_value[AES.block_size:]
            cipher = AES.new(key, AES.MODE_CBC, iv)
            return unpad(cipher.decrypt(ciphertext))
        elif self.algorithm.endswith('#tripledes-cbc'):
            from Crypto.Cipher import DES3
            if len(key) not in DES3.key_size:
                raise DecryptionError('Invalid key length')
            iv = self.cipher_value[:DES3.block_size]
            ciphertext = self.cipher_value[DES3.block_size:]
            cipher = DES3.new(key, DES3.MODE_CBC, iv)
            return unpad(cipher.decrypt(ciphertext))
        elif self.algorithm.endswith('#kw-aes128') or \
                self.algorithm.endswith('#kw-aes192') or \
                self.algorithm.endswith('#kw-aes256'):
            from pskc.aeskw import unwrap
            from Crypto.Cipher import AES
            if len(key) * 8 != int(self.algorithm[-3:]) or \
               len(key) not in AES.key_size:
                raise DecryptionError('Invalid key length')
            return unwrap(self.cipher_value, key)
        elif self.algorithm.endswith('#kw-tripledes'):
            from pskc.tripledeskw import unwrap
            from Crypto.Cipher import DES3
            if len(key) not in DES3.key_size:
                raise DecryptionError('Invalid key length')
            return unwrap(self.cipher_value, key)
        else:
            raise DecryptionError('Unsupported algorithm: %r' % self.algorithm)


class KeyDerivation(object):
    """Handle key derivation.

    The algorithm property contains the key derivation algorithm to use. For
    PBDKF2 the following parameters are set:

      pbkdf2_salt: salt value
      pbkdf2_iterations: number of iterations to use
      pbkdf2_key_length: required key lengt
      pbkdf2_prf: name of pseudorandom function used
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
        from pskc.parse import find, findint, findbin
        if key_deriviation is None:
            return
        self.algorithm = key_deriviation.get('Algorithm')
        # PBKDF2 properties
        pbkdf2 = find(key_deriviation, 'xenc11:PBKDF2-params')
        if pbkdf2 is None:
            pbkdf2 = find(key_deriviation, 'pkcs5:PBKDF2-params')
        if pbkdf2 is not None:
            # get used salt
            self.pbkdf2_salt = findbin(pbkdf2, 'Salt/Specified')
            # required number of iterations
            self.pbkdf2_iterations = findint(pbkdf2, 'IterationCount')
            # key length
            self.pbkdf2_key_length = findint(pbkdf2, 'KeyLength')
            # pseudorandom function used
            prf = find(pbkdf2, 'PRF')
            if prf is not None:
                self.pbkdf2_prf = prf.get('Algorithm')

    def derive(self, password):
        """Derive a key from the password."""
        from pskc.exceptions import KeyDerivationError
        if self.algorithm is None:
            raise KeyDerivationError('No algorithm specified')
        if self.algorithm.endswith('#pbkdf2'):
            from Crypto.Protocol.KDF import PBKDF2
            from pskc.mac import get_hmac
            prf = None
            if self.pbkdf2_prf:
                prf = get_hmac(self.pbkdf2_prf)
                if prf is None:
                    raise KeyDerivationError(
                        'Pseudorandom function unsupported: %r' %
                        self.pbkdf2_prf)
            return PBKDF2(
                password, self.pbkdf2_salt, dkLen=self.pbkdf2_key_length,
                count=self.pbkdf2_iterations, prf=prf)
        else:
            raise KeyDerivationError(
                'Unsupported algorithm: %r' % self.algorithm)


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
        from pskc.parse import find, findall, findtext
        if key_info is None:
            return
        self.id = key_info.get('Id')
        for name in findall(key_info, 'ds:KeyName'):
            self.key_names.append(findtext(name, '.'))
        for name in findall(
                key_info, 'xenc11:DerivedKey/xenc11:MasterKeyName'):
            self.key_names.append(findtext(name, '.'))
        self.derivation.parse(find(
            key_info, 'xenc11:DerivedKey/xenc11:KeyDerivationMethod'))

    @property
    def key_name(self):
        """Provide the name of the (first) key."""
        if self.key_names:
            return self.key_names[0]

    def derive_key(self, password):
        """Derive a key from the password."""
        self.key = self.derivation.derive(password)
