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

import base64

# cannonical URIs of known algorithms
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
    'hmac-md5': 'http://www.w3.org/2001/04/xmldsig-more#hmac-md5',
    'hmac-sha1': 'http://www.w3.org/2000/09/xmldsig#hmac-sha1',
    'hmac-sha224': 'http://www.w3.org/2001/04/xmldsig-more#hmac-sha224',
    'hmac-sha256': 'http://www.w3.org/2001/04/xmldsig-more#hmac-sha256',
    'hmac-sha384': 'http://www.w3.org/2001/04/xmldsig-more#hmac-sha384',
    'hmac-sha512': 'http://www.w3.org/2001/04/xmldsig-more#hmac-sha512',
    'hmac-ripemd160': 'http://www.w3.org/2001/04/xmldsig-more#hmac-ripemd160',
    'pbkdf2': 'http://www.rsasecurity.com/rsalabs/pkcs/schemas/' +
              'pkcs-5v2-0#pbkdf2',
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


class KeyDerivation(object):
    """Handle key derivation.

    The algorithm property contains the key derivation algorithm to use. For
    PBDKF2 the following parameters are set:

      pbkdf2_salt: salt value
      pbkdf2_iterations: number of iterations to use
      pbkdf2_key_length: required key length in bytes
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

    def make_xml(self, encryption_key, key_names):
        from pskc.xml import mk_elem
        derived_key = mk_elem(encryption_key, 'xenc11:DerivedKey', empty=True)
        key_derivation = mk_elem(derived_key, 'xenc11:KeyDerivationMethod',
                                 Algorithm=self.algorithm)
        if self.algorithm.endswith('#pbkdf2'):
            pbkdf2 = mk_elem(key_derivation, 'xenc11:PBKDF2-params',
                             empty=True)
            if self.pbkdf2_salt:
                salt = mk_elem(pbkdf2, 'Salt', empty=True)
                mk_elem(salt, 'Specified', base64.b64encode(self.pbkdf2_salt))
            mk_elem(pbkdf2, 'IterationCount', self.pbkdf2_iterations)
            mk_elem(pbkdf2, 'KeyLength', self.pbkdf2_key_length)
            mk_elem(pbkdf2, 'PRF', self.pbkdf2_prf)
        # TODO: serialise ReferenceList/DataReference
        for name in key_names:
            mk_elem(derived_key, 'xenc11:MasterKeyName', name)

    def derive_pbkdf2(self, password):
        from Crypto.Protocol.KDF import PBKDF2
        from pskc.mac import get_hmac
        from pskc.exceptions import KeyDerivationError
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

    def derive(self, password):
        """Derive a key from the password."""
        from pskc.exceptions import KeyDerivationError
        if self.algorithm is None:
            raise KeyDerivationError('No algorithm specified')
        if self.algorithm.endswith('#pbkdf2'):
            return self.derive_pbkdf2(password)
        else:
            raise KeyDerivationError(
                'Unsupported algorithm: %r' % self.algorithm)

    def setup_pbkdf2(self, password, salt=None, salt_length=16,
                     key_length=None, iterations=None, prf=None):
        from Crypto import Random
        self.algorithm = normalise_algorithm('pbkdf2')
        if salt is None:
            salt = Random.get_random_bytes(salt_length)
        self.pbkdf2_salt = salt
        if iterations:
            self.pbkdf2_iterations = iterations
        elif self.pbkdf2_iterations is None:
            self.pbkdf2_iterations = 12 * 1000
        if key_length:
            self.pbkdf2_key_length = key_length
        return self.derive_pbkdf2(password)


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
      fields: a list of Key fields that will be encrypted on writing

    The key can either be assigned to the key property or derived using the
    derive_key() method.
    """

    def __init__(self, pskc):
        self.pskc = pskc
        self.id = None
        self.key_names = []
        self.key = None
        self._algorithm = None
        self.derivation = KeyDerivation()
        self.fields = []

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

    def make_xml(self, container):
        from pskc.xml import mk_elem
        if all(x is None
               for x in (self.id, self.key_name, self.key,
                         self.derivation.algorithm)):
            return
        encryption_key = mk_elem(container, 'pskc:EncryptionKey',
                                 Id=self.id, empty=True)
        if self.derivation.algorithm:
            self.derivation.make_xml(encryption_key, self.key_names)
        else:
            for name in self.key_names:
                mk_elem(encryption_key, 'ds:KeyName', name)

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

    def _setup_encryption(self, kwargs):
        for k in ('id', 'algorithm', 'key_name', 'key_names', 'fields'):
            v = kwargs.pop(k, None)
            if v is not None:
                setattr(self, k, v)
        # default encryption to AES128-CBC
        if not self.algorithm:
            self.algorithm = 'aes128-cbc'
        # default to encrypting the secret only
        if not self.fields:
            self.fields = ['secret', ]
        # if we're using a CBC mode of encryption, add a MAC
        if self.algorithm.endswith('-cbc'):
            self.pskc.mac.setup()

    def setup_preshared_key(self, **kwargs):
        """Configure pre-shared key encryption.

        The following arguments may be supplied:
          key: the encryption key to use
          id: encryption key identifier
          algorithm: encryption algorithm
          key_length: encryption key length in bytes
          key_name: a name for the key
          key_names: a number of names for the key
          fields: a list of fields to encrypt

        None of the arguments are required, reasonable defaults will be
        chosen for missing arguments.
        """
        self._setup_encryption(kwargs)
        key = kwargs.pop('key', self.key)
        if not key:
            from Crypto import Random
            self.key = Random.get_random_bytes(kwargs.pop(
                'key_length', self.algorithm_key_lengths[-1]))

    def setup_pbkdf2(self, password, **kwargs):
        """Configure password-based PSKC encryption.

        The following arguments may be supplied:
          password: the password to use (required)
          id: encryption key identifier
          algorithm: encryption algorithm
          key_length: encryption key length in bytes
          key_name: a name for the key
          key_names: a number of names for the key
          fields: a list of fields to encrypt
          salt: PBKDF2 salt
          salt_length: used when generating random salt
          iterations: number of PBKDF2 iterations
          prf: PBKDF2 pseudorandom function

        Only password is required, for the other arguments reasonable
        defaults will be chosen.
        """
        self._setup_encryption(kwargs)
        # pass a key length to PBKDF2
        kwargs.setdefault('key_length', self.algorithm_key_lengths[-1])
        self.key = self.derivation.setup_pbkdf2(password, **kwargs)

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
            from pskc.crypto import unpad
            iv = cipher_value[:AES.block_size]
            ciphertext = cipher_value[AES.block_size:]
            cipher = AES.new(key, AES.MODE_CBC, iv)
            return unpad(cipher.decrypt(ciphertext))
        elif algorithm.endswith('#tripledes-cbc'):
            from Crypto.Cipher import DES3
            from pskc.crypto import unpad
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

    def encrypt_value(self, plaintext):
        """Encrypt the provided value and return the cipher_value."""
        from pskc.exceptions import EncryptionError
        key = self.key
        if key is None:
            raise EncryptionError('No key available')
        algorithm = self.algorithm
        if algorithm is None:
            raise EncryptionError('No algorithm specified')
        if len(key) not in self.algorithm_key_lengths:
            raise EncryptionError('Invalid key length')
        if algorithm.endswith('#aes128-cbc') or \
                algorithm.endswith('#aes192-cbc') or \
                algorithm.endswith('#aes256-cbc'):
            from Crypto import Random
            from Crypto.Cipher import AES
            from pskc.crypto import pad
            iv = Random.get_random_bytes(AES.block_size)
            cipher = AES.new(key, AES.MODE_CBC, iv)
            return iv + cipher.encrypt(pad(plaintext, AES.block_size))
        elif algorithm.endswith('#tripledes-cbc'):
            from Crypto import Random
            from Crypto.Cipher import DES3
            from pskc.crypto import pad
            iv = Random.get_random_bytes(DES3.block_size)
            cipher = DES3.new(key, DES3.MODE_CBC, iv)
            return iv + cipher.encrypt(pad(plaintext, DES3.block_size))
        elif algorithm.endswith('#kw-aes128') or \
                algorithm.endswith('#kw-aes192') or \
                algorithm.endswith('#kw-aes256'):
            from pskc.crypto.aeskw import wrap
            return wrap(plaintext, key)
        elif algorithm.endswith('#kw-tripledes'):
            from pskc.crypto.tripledeskw import wrap
            return wrap(plaintext, key)
