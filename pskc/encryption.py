# encryption.py - module for handling encrypted values
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

"""Module that handles encrypted PSKC values.

This module defines an Encryption class that handles the encryption key,
algorithms and decryption.

The encryption key can be derived using the KeyDerivation class.
"""


# cannonical URIs of known encryption algorithms
_algorithms = {
    'tripledes-cbc': 'http://www.w3.org/2001/04/xmlenc#tripledes-cbc',
    'kw-tripledes': 'http://www.w3.org/2001/04/xmlenc#kw-tripledes',
    'aes128-cbc': 'http://www.w3.org/2001/04/xmlenc#aes128-cbc',
    'aes192-cbc': 'http://www.w3.org/2001/04/xmlenc#aes192-cbc',
    'aes256-cbc': 'http://www.w3.org/2001/04/xmlenc#aes256-cbc',
    'kw-aes128': 'http://www.w3.org/2001/04/xmlenc#kw-aes128',
    'kw-aes192': 'http://www.w3.org/2001/04/xmlenc#kw-aes192',
    'kw-aes256': 'http://www.w3.org/2001/04/xmlenc#kw-aes256',
    'camellia128': 'http://www.w3.org/2001/04/xmldsig-more#camellia128',
    'camellia192': 'http://www.w3.org/2001/04/xmldsig-more#camellia192',
    'camellia256': 'http://www.w3.org/2001/04/xmldsig-more#camellia256',
    'kw-camellia128': 'http://www.w3.org/2001/04/xmldsig-more#kw-camellia128',
    'kw-camellia192': 'http://www.w3.org/2001/04/xmldsig-more#kw-camellia192',
    'kw-camellia256': 'http://www.w3.org/2001/04/xmldsig-more#kw-camellia256',
}

# translation table to change old encryption names to new names
_algorithm_aliases = {
    '3des-cbc': 'tripledes-cbc',
    '3des112-cbc': 'tripledes-cbc',
    '3des168-cbc': 'tripledes-cbc',
    'kw-3des': 'kw-tripledes',
    'pbe-3des112-cbc': 'tripledes-cbc',
    'pbe-3des168-cbc': 'tripledes-cbc',
    'pbe-aes128-cbc': 'aes128-cbc',
    'pbe-aes192-cbc': 'aes192-cbc',
    'pbe-aes256-cbc': 'aes256-cbc',
    'rsa-1_5': 'rsa-1_5',
    'rsa-oaep-mgf1p': 'rsa-oaep-mgf1p',
}


def normalise_algorithm(algorithm):
    """Return the canonical URI for the provided algorithm."""
    if not algorithm or algorithm.lower() == 'none':
        return None
    algorithm = _algorithm_aliases.get(algorithm.lower(), algorithm)
    return _algorithms.get(algorithm.rsplit('#', 1)[-1].lower(), algorithm)


def unpad(value):
    """Remove padding from the plaintext."""
    return value[0:-ord(value[-1:])]


class KeyDerivation(object):
    """Handle key derivation.

    The algorithm property contains the key derivation algorithm to use. For
    PBDKF2 the following parameters are set:

      pbkdf2_salt: salt value
      pbkdf2_iterations: number of iterations to use
      pbkdf2_key_length: required key lengt
      pbkdf2_prf: name of pseudorandom function used
    """

    def __init__(self, key_derivation=None):
        self.algorithm = None
        # PBKDF2 properties
        self.pbkdf2_salt = None
        self.pbkdf2_iterations = None
        self.pbkdf2_key_length = None
        self.pbkdf2_prf = None
        self.parse(key_derivation)

    def parse(self, key_derivation):
        """Read derivation parameters from a <KeyDerivationMethod> element."""
        from pskc.xml import find, findint, findbin
        if key_derivation is None:
            return
        self.algorithm = key_derivation.get('Algorithm')
        # PBKDF2 properties
        pbkdf2 = find(key_derivation, 'PBKDF2-params')
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
      algorithm: the encryption algorithm used
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
        self._algorithm = None
        self._encrypted_values = []
        self.derivation = KeyDerivation()
        self.parse(key_info)

    def parse(self, key_info):
        """Read encryption information from the <EncryptionKey> XML tree."""
        from pskc.xml import find, findall, findtext
        if key_info is None:
            return
        self.id = key_info.get('Id')
        for name in findall(key_info, 'KeyName'):
            self.key_names.append(findtext(name, '.'))
        for name in findall(key_info, 'DerivedKey/MasterKeyName'):
            self.key_names.append(findtext(name, '.'))
        self.derivation.parse(find(
            key_info, 'DerivedKey/KeyDerivationMethod'))

    @property
    def key_name(self):
        """Provide the name of the (first) key."""
        if self.key_names:
            return self.key_names[0]

    @key_name.setter
    def key_name(self, value):
        self.key_names = [value]

    @property
    def algorithm(self):
        """Provide the encryption algorithm used."""
        if self._algorithm:
            return self._algorithm

    @algorithm.setter
    def algorithm(self, value):
        self._algorithm = normalise_algorithm(value)

    def derive_key(self, password):
        """Derive a key from the password."""
        self.key = self.derivation.derive(password)

    @property
    def algorithm_key_lengths(self):
        """Provide the possible key lengths for the configured algorithm."""
        from pskc.exceptions import DecryptionError
        algorithm = self.algorithm
        if algorithm is None:
            raise DecryptionError('No algorithm specified')
        elif algorithm.endswith('#aes128-cbc') or \
                algorithm.endswith('#aes192-cbc') or \
                algorithm.endswith('#aes256-cbc'):
            return [int(algorithm[-7:-4]) // 8]
        elif algorithm.endswith('#tripledes-cbc') or \
                algorithm.endswith('#kw-tripledes'):
            from Crypto.Cipher import DES3
            return list(DES3.key_size)
        elif algorithm.endswith('#kw-aes128') or \
                algorithm.endswith('#kw-aes192') or \
                algorithm.endswith('#kw-aes256'):
            return [int(algorithm[-3:]) // 8]
        else:
            raise DecryptionError('Unsupported algorithm: %r' % algorithm)

    def decrypt_value(self, cipher_value, algorithm=None):
        """Decrypt the cipher_value and return the plaintext value."""
        from pskc.exceptions import DecryptionError
        key = self.key
        if key is None:
            raise DecryptionError('No key available')
        algorithm = algorithm or self.algorithm
        if algorithm is None:
            raise DecryptionError('No algorithm specified')
        if len(key) not in self.algorithm_key_lengths:
            raise DecryptionError('Invalid key length')
        if algorithm.endswith('#aes128-cbc') or \
                algorithm.endswith('#aes192-cbc') or \
                algorithm.endswith('#aes256-cbc'):
            from Crypto.Cipher import AES
            iv = cipher_value[:AES.block_size]
            ciphertext = cipher_value[AES.block_size:]
            cipher = AES.new(key, AES.MODE_CBC, iv)
            return unpad(cipher.decrypt(ciphertext))
        elif algorithm.endswith('#tripledes-cbc'):
            from Crypto.Cipher import DES3
            iv = cipher_value[:DES3.block_size]
            ciphertext = cipher_value[DES3.block_size:]
            cipher = DES3.new(key, DES3.MODE_CBC, iv)
            return unpad(cipher.decrypt(ciphertext))
        elif algorithm.endswith('#kw-aes128') or \
                algorithm.endswith('#kw-aes192') or \
                algorithm.endswith('#kw-aes256'):
            from pskc.crypto.aeskw import unwrap
            return unwrap(cipher_value, key)
        elif algorithm.endswith('#kw-tripledes'):
            from pskc.crypto.tripledeskw import unwrap
            return unwrap(cipher_value, key)
