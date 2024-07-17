# encryption.py - module for handling encrypted values
# coding: utf-8
#
# Copyright (C) 2014-2024 Arthur de Jong
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


import os
import re


def algorithm_key_lengths(algorithm):
    """Return the possible key lengths for the configured algorithm."""
    from pskc.exceptions import DecryptionError
    if algorithm is None:
        raise DecryptionError('No algorithm specified')
    elif algorithm.endswith('#aes128-cbc') or \
            algorithm.endswith('#aes192-cbc') or \
            algorithm.endswith('#aes256-cbc'):
        return [int(algorithm[-7:-4]) // 8]
    elif algorithm.endswith('#tripledes-cbc') or \
            algorithm.endswith('#kw-tripledes'):
        return [16, 24]
    elif algorithm.endswith('#kw-aes128') or \
            algorithm.endswith('#kw-aes192') or \
            algorithm.endswith('#kw-aes256'):
        return [int(algorithm[-3:]) // 8]
    elif (algorithm.endswith('#camellia128-cbc') or
            algorithm.endswith('#camellia192-cbc') or
            algorithm.endswith('#camellia256-cbc')):
        return [int(algorithm[-7:-4]) // 8]
    elif (algorithm.endswith('#kw-camellia128') or
            algorithm.endswith('#kw-camellia192') or
            algorithm.endswith('#kw-camellia256')):
        return [int(algorithm[-3:]) // 8]
    else:
        raise DecryptionError('Unsupported algorithm: %r' % algorithm)


def _decrypt_cbc(algorithm, key, ciphertext, iv=None):
    """Decrypt the ciphertext and return the plaintext value."""
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import padding
    from cryptography.hazmat.primitives.ciphers import Cipher, modes
    from pskc.exceptions import DecryptionError
    if not iv:
        iv = ciphertext[:algorithm.block_size // 8]
        ciphertext = ciphertext[algorithm.block_size // 8:]
    cipher = Cipher(
        algorithm(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    unpadder = padding.PKCS7(algorithm.block_size).unpadder()
    try:
        return unpadder.update(
            decryptor.update(ciphertext) +
            decryptor.finalize()) + unpadder.finalize()
    except ValueError:
        raise DecryptionError('Invalid padding')


def decrypt(algorithm, key, ciphertext, iv=None):
    """Decrypt the ciphertext and return the plaintext value."""
    from cryptography.hazmat.primitives.ciphers import algorithms
    from pskc.exceptions import DecryptionError
    if key is None:
        raise DecryptionError('No key available')
    if algorithm is None:
        raise DecryptionError('No algorithm specified')
    if len(key) not in algorithm_key_lengths(algorithm):
        raise DecryptionError('Invalid key length')
    if algorithm.endswith('#aes128-cbc') or \
            algorithm.endswith('#aes192-cbc') or \
            algorithm.endswith('#aes256-cbc'):
        return _decrypt_cbc(algorithms.AES, key, ciphertext, iv)
    elif algorithm.endswith('#tripledes-cbc'):
        return _decrypt_cbc(algorithms.TripleDES, key, ciphertext, iv)
    elif algorithm.endswith('#kw-aes128') or \
            algorithm.endswith('#kw-aes192') or \
            algorithm.endswith('#kw-aes256'):
        from pskc.crypto.aeskw import unwrap
        return unwrap(ciphertext, key)
    elif algorithm.endswith('#kw-tripledes'):
        from pskc.crypto.tripledeskw import unwrap
        return unwrap(ciphertext, key)
    elif (algorithm.endswith('#camellia128-cbc') or
            algorithm.endswith('#camellia192-cbc') or
            algorithm.endswith('#camellia256-cbc')):
        return _decrypt_cbc(algorithms.Camellia, key, ciphertext, iv)
    elif (algorithm.endswith('#kw-camellia128') or  # pragma: no branch
            algorithm.endswith('#kw-camellia192') or
            algorithm.endswith('#kw-camellia256')):
        from pskc.crypto.aeskw import unwrap
        return unwrap(ciphertext, key, algorithm=algorithms.Camellia)
    # no fallthrough because algorithm_key_lengths() fails with unknown algo


def _encrypt_cbc(algorithm, key, plaintext, iv=None):
    """Encrypt the provided value with the key using the algorithm."""
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import padding
    from cryptography.hazmat.primitives.ciphers import Cipher, modes
    iv = iv or os.urandom(algorithm.block_size // 8)
    cipher = Cipher(
        algorithm(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(algorithm.block_size).padder()
    return (
        iv + encryptor.update(
            padder.update(plaintext) + padder.finalize()) +
        encryptor.finalize())


def encrypt(algorithm, key, plaintext, iv=None):
    """Encrypt the provided value with the key using the algorithm."""
    from cryptography.hazmat.primitives.ciphers import algorithms
    from pskc.exceptions import EncryptionError
    if key is None:
        raise EncryptionError('No key available')
    if algorithm is None:
        raise EncryptionError('No algorithm specified')
    if len(key) not in algorithm_key_lengths(algorithm):
        raise EncryptionError('Invalid key length')
    if algorithm.endswith('#aes128-cbc') or \
            algorithm.endswith('#aes192-cbc') or \
            algorithm.endswith('#aes256-cbc'):
        return _encrypt_cbc(algorithms.AES, key, plaintext, iv)
    elif algorithm.endswith('#tripledes-cbc'):
        return _encrypt_cbc(algorithms.TripleDES, key, plaintext, iv)
    elif algorithm.endswith('#kw-aes128') or \
            algorithm.endswith('#kw-aes192') or \
            algorithm.endswith('#kw-aes256'):
        from pskc.crypto.aeskw import wrap
        return wrap(plaintext, key)
    elif algorithm.endswith('#kw-tripledes'):
        from pskc.crypto.tripledeskw import wrap
        return wrap(plaintext, key)
    elif (algorithm.endswith('#camellia128-cbc') or
            algorithm.endswith('#camellia192-cbc') or
            algorithm.endswith('#camellia256-cbc')):
        return _encrypt_cbc(algorithms.Camellia, key, plaintext, iv)
    elif (algorithm.endswith('#kw-camellia128') or  # pragma: no branch
            algorithm.endswith('#kw-camellia192') or
            algorithm.endswith('#kw-camellia256')):
        from pskc.crypto.aeskw import wrap
        return wrap(plaintext, key, algorithm=algorithms.Camellia)
    # no fallthrough because algorithm_key_lengths() fails with unknown algo


class KeyDerivation(object):
    """Handle key derivation.

    The algorithm property contains the key derivation algorithm to use. For
    PBDKF2 the following parameters are set:

      pbkdf2_salt: salt value
      pbkdf2_iterations: number of iterations to use
      pbkdf2_key_length: required key length in bytes
      pbkdf2_prf: name of pseudorandom function used
    """

    def __init__(self):
        self._algorithm = None
        # PBKDF2 properties
        self.pbkdf2_salt = None
        self.pbkdf2_iterations = None
        self.pbkdf2_key_length = None
        self._pbkdf2_prf = None

    @property
    def algorithm(self):
        """Provide the key derivation algorithm used."""
        if self._algorithm:
            return self._algorithm

    @algorithm.setter
    def algorithm(self, value):
        from pskc.algorithms import normalise_algorithm
        self._algorithm = normalise_algorithm(value)

    @property
    def pbkdf2_prf(self):
        """Provide the PBKDF2 pseudorandom function used."""
        if self._pbkdf2_prf:
            return self._pbkdf2_prf

    @pbkdf2_prf.setter
    def pbkdf2_prf(self, value):
        from pskc.algorithms import normalise_algorithm
        self._pbkdf2_prf = normalise_algorithm(value)

    def derive_pbkdf2(self, password):
        """Derive an encryption key from the provided password."""
        from hashlib import pbkdf2_hmac
        from pskc.exceptions import KeyDerivationError
        prf = 'sha1'
        if self.pbkdf2_prf:
            match = re.search(
                r'^(.*#)?hmac-(?P<hash>[a-z0-9-]+)$', self.pbkdf2_prf)
            if match:
                prf = match.group('hash')
            else:
                raise KeyDerivationError(
                    'Unsupported PRF: %r' % self.pbkdf2_prf)
        if not all((password, self.pbkdf2_salt, self.pbkdf2_key_length,
                    self.pbkdf2_iterations)):
            raise KeyDerivationError('Incomplete PBKDF2 configuration')
        # force conversion to bytestring
        if not isinstance(password, type(b'')):
            password = password.encode()
        try:
            return pbkdf2_hmac(
                prf, password, self.pbkdf2_salt, self.pbkdf2_iterations,
                self.pbkdf2_key_length)
        except ValueError:
            raise KeyDerivationError(
                'Pseudorandom function unsupported: %r' % self.pbkdf2_prf)

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
        """Configure PBKDF2 key derivation properties."""
        self.algorithm = 'pbkdf2'
        if salt is None:
            salt = os.urandom(salt_length)
        self.pbkdf2_salt = salt
        if iterations:
            self.pbkdf2_iterations = iterations
        elif self.pbkdf2_iterations is None:
            self.pbkdf2_iterations = 100000
        if key_length:  # pragma: no branch (always specified)
            self.pbkdf2_key_length = key_length
        if prf:
            self.pbkdf2_prf = prf
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
      iv: optional initialization vector for CBC based encryption
      fields: a list of Key fields that will be encrypted on writing

    The key can either be assigned to the key property or derived using the
    derive_key() method.
    """

    def __init__(self, pskc):
        self.pskc = pskc
        self.id = None
        self._algorithm = None
        self.key_names = []
        self.key = None
        self.iv = None
        self.derivation = KeyDerivation()
        self.fields = []

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
        from pskc.algorithms import normalise_algorithm
        self._algorithm = normalise_algorithm(value)

    @property
    def is_encrypted(self):
        """Test whether the PSKC file requires a decryption key."""
        from pskc.exceptions import DecryptionError
        try:
            for key in self.pskc.keys:
                key.secret, key.counter, key.time_offset
                key.time_interval, key.time_drift
        except DecryptionError:
            return True
        return False

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
            self.fields = ['secret']
        # if we're using a CBC mode of encryption, add a MAC
        if self.algorithm.endswith('-cbc'):
            self.pskc.mac.setup()

    def setup_preshared_key(self, **kwargs):
        """Configure pre-shared key encryption when writing the file.

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
        self.key = kwargs.pop('key', self.key)
        if not self.key:
            self.key = os.urandom(
                kwargs.pop('key_length', self.algorithm_key_lengths[-1]))

    def setup_pbkdf2(self, password, **kwargs):
        """Configure password-based PSKC encryption when writing the file.

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
        return algorithm_key_lengths(self.algorithm)

    def decrypt_value(self, cipher_value, algorithm=None):
        """Decrypt the cipher_value and return the plaintext value."""
        return decrypt(
            algorithm or self.algorithm, self.key, cipher_value, self.iv)

    def encrypt_value(self, plaintext):
        """Encrypt the provided value and return the cipher_value."""
        cipher_value = encrypt(self.algorithm, self.key, plaintext, self.iv)
        if self.iv:
            cipher_value = cipher_value[len(self.iv):]
        return cipher_value

    def remove_encryption(self):
        """Decrypt all values and remove the encryption from the PSKC file."""
        # decrypt all values and store decrypted values
        for key in self.pskc.keys:
            key.secret = key.secret
            key.counter = key.counter
            key.time_offset = key.time_offset
            key.time_interval = key.time_interval
            key.time_drift = key.time_drift
        # remove MAC configuration
        self.pskc.mac.algorithm = None
        self.pskc.mac.key = None
        # remove encryption configuration
        self.id = None
        self.algorithm = None
        self.key_names = []
        self.key = None
        self.iv = None
        self.fields = []
        # remove key derivation configuration
        self.derivation.algorithm = None
        self.derivation.pbkdf2_salt = None
        self.derivation.pbkdf2_iterations = None
        self.derivation.pbkdf2_key_length = None
        self.derivation.pbkdf2_prf = None
