# encryption.py - module for handling encrypted values
# coding: utf-8
#
# Copyright (C) 2014-2025 Arthur de Jong
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

from __future__ import annotations

import os
import re
from collections.abc import Sequence
from typing import TYPE_CHECKING, Type

if TYPE_CHECKING:  # pragma: no cover (only for mypy)
    from cryptography.hazmat.primitives.ciphers import BlockCipherAlgorithm

    from pskc import PSKC


def algorithm_key_lengths(algorithm: str | None) -> Sequence[int]:
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


def _decrypt_cbc(
    algorithm: Type[BlockCipherAlgorithm],
    key: bytes,
    ciphertext: bytes,
    iv: bytes | None = None,
) -> bytes:
    """Decrypt the ciphertext and return the plaintext value."""
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import padding
    from cryptography.hazmat.primitives.ciphers import Cipher, modes
    from pskc.exceptions import DecryptionError
    if not iv:
        iv = ciphertext[:algorithm.block_size // 8]  # type: ignore[operator]
        ciphertext = ciphertext[algorithm.block_size // 8:]  # type: ignore[operator]
    cipher = Cipher(
        algorithm(key), modes.CBC(iv), backend=default_backend())  # type: ignore[call-arg]
    decryptor = cipher.decryptor()
    unpadder = padding.PKCS7(algorithm.block_size).unpadder()  # type: ignore[arg-type]
    try:
        return unpadder.update(
            decryptor.update(ciphertext) +
            decryptor.finalize()) + unpadder.finalize()
    except ValueError:
        raise DecryptionError('Invalid padding')


def decrypt(algorithm: str | None, key: bytes | None, ciphertext: bytes, iv: bytes | None = None) -> bytes:
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
        from pskc.crypto.aeskw import unwrap as easkw_unwrap
        return easkw_unwrap(ciphertext, key)
    elif algorithm.endswith('#kw-tripledes'):
        from pskc.crypto.tripledeskw import unwrap as tripledeskw_unwrap
        return tripledeskw_unwrap(ciphertext, key)
    elif (algorithm.endswith('#camellia128-cbc') or
            algorithm.endswith('#camellia192-cbc') or
            algorithm.endswith('#camellia256-cbc')):
        return _decrypt_cbc(algorithms.Camellia, key, ciphertext, iv)
    elif (algorithm.endswith('#kw-camellia128') or  # pragma: no branch
            algorithm.endswith('#kw-camellia192') or
            algorithm.endswith('#kw-camellia256')):
        from pskc.crypto.aeskw import unwrap as easkw_unwrap
        return easkw_unwrap(ciphertext, key, algorithm=algorithms.Camellia)
    # no fallthrough because algorithm_key_lengths() fails with unknown algo
    assert False  # pragma: no cover (only for mypy)  # noqa: B011


def _encrypt_cbc(algorithm: Type[BlockCipherAlgorithm], key: bytes, plaintext: bytes, iv: bytes | None = None) -> bytes:
    """Encrypt the provided value with the key using the algorithm."""
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import padding
    from cryptography.hazmat.primitives.ciphers import Cipher, modes
    iv = iv or os.urandom(algorithm.block_size // 8)  # type: ignore[operator]
    cipher = Cipher(
        algorithm(key), modes.CBC(iv), backend=default_backend())  # type: ignore[call-arg]
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(algorithm.block_size).padder()  # type: ignore[arg-type]
    return (
        iv + encryptor.update(
            padder.update(plaintext) + padder.finalize()) +
        encryptor.finalize())


def encrypt(algorithm: str | None, key: bytes | None, plaintext: bytes, iv: bytes | None = None) -> bytes:
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
        from pskc.crypto.aeskw import wrap as aeskw_wrap
        return aeskw_wrap(plaintext, key)
    elif algorithm.endswith('#kw-tripledes'):
        from pskc.crypto.tripledeskw import wrap as tripledeskw_wrap
        return tripledeskw_wrap(plaintext, key)
    elif (algorithm.endswith('#camellia128-cbc') or
            algorithm.endswith('#camellia192-cbc') or
            algorithm.endswith('#camellia256-cbc')):
        return _encrypt_cbc(algorithms.Camellia, key, plaintext, iv)
    elif (algorithm.endswith('#kw-camellia128') or  # pragma: no branch
            algorithm.endswith('#kw-camellia192') or
            algorithm.endswith('#kw-camellia256')):
        from pskc.crypto.aeskw import wrap as aeskw_wrap
        return aeskw_wrap(plaintext, key, algorithm=algorithms.Camellia)
    # no fallthrough because algorithm_key_lengths() fails with unknown algo
    assert False  # pragma: no cover (only for mypy)  # noqa: B011


class KeyDerivation:
    """Handle key derivation.

    The algorithm property contains the key derivation algorithm to use. For
    PBDKF2 the following parameters are set:

      pbkdf2_salt: salt value
      pbkdf2_iterations: number of iterations to use
      pbkdf2_key_length: required key length in bytes
      pbkdf2_prf: name of pseudorandom function used
    """

    def __init__(self) -> None:
        self._algorithm: str | None = None
        # PBKDF2 properties
        self.pbkdf2_salt: bytes | None = None
        self.pbkdf2_iterations: int | None = None
        self.pbkdf2_key_length: int | None = None
        self._pbkdf2_prf: str | None = None

    @property
    def algorithm(self) -> str | None:
        """Provide the key derivation algorithm used."""
        if self._algorithm:
            return self._algorithm
        return None

    @algorithm.setter
    def algorithm(self, value: str | None) -> None:
        from pskc.algorithms import normalise_algorithm
        self._algorithm = normalise_algorithm(value)

    @property
    def pbkdf2_prf(self) -> str | None:
        """Provide the PBKDF2 pseudorandom function used."""
        if self._pbkdf2_prf:
            return self._pbkdf2_prf
        return None

    @pbkdf2_prf.setter
    def pbkdf2_prf(self, value: str | None) -> None:
        from pskc.algorithms import normalise_algorithm
        self._pbkdf2_prf = normalise_algorithm(value)

    def derive_pbkdf2(self, password: str | bytes | bytearray) -> bytes:
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
            password = password.encode()  # type: ignore[union-attr]
        try:
            return pbkdf2_hmac(
                prf, password, self.pbkdf2_salt, self.pbkdf2_iterations,  # type: ignore[arg-type]
                self.pbkdf2_key_length)
        except ValueError:
            raise KeyDerivationError(
                'Pseudorandom function unsupported: %r' % self.pbkdf2_prf)

    def derive(self, password: str | bytes | bytearray) -> bytes:
        """Derive a key from the password."""
        from pskc.exceptions import KeyDerivationError
        if self.algorithm is None:
            raise KeyDerivationError('No algorithm specified')
        if self.algorithm.endswith('#pbkdf2'):
            return self.derive_pbkdf2(password)
        else:
            raise KeyDerivationError(
                'Unsupported algorithm: %r' % self.algorithm)

    def setup_pbkdf2(
        self,
        password: str | bytes | bytearray,
        salt: bytes | None = None,
        salt_length: int = 16,
        key_length: int | None = None,
        iterations: int | None = None,
        prf: str | None = None,
    ) -> bytes:
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


class Encryption:
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
    `derive_key()` method.
    """

    def __init__(self, pskc: PSKC) -> None:
        self.pskc = pskc
        self.id: str | None = None
        self._algorithm: str | None = None
        self.key_names: list[str] = []
        self.key: bytes | None = None
        self.iv: bytes | None = None
        self.derivation = KeyDerivation()
        self.fields: list[str] = []

    @property
    def key_name(self) -> str | None:
        """Provide the name of the (first) key."""
        if self.key_names:
            return self.key_names[0]
        return None

    @key_name.setter
    def key_name(self, value: str | None) -> None:
        if value:
            self.key_names = [value]
        else:
            self.key_names = []

    @property
    def algorithm(self) -> str | None:
        """Provide the encryption algorithm used."""
        if self._algorithm:
            return self._algorithm
        return None

    @algorithm.setter
    def algorithm(self, value: str | None) -> None:
        from pskc.algorithms import normalise_algorithm
        self._algorithm = normalise_algorithm(value)

    @property
    def is_encrypted(self) -> bool:
        """Test whether the PSKC file requires a decryption key."""
        from pskc.exceptions import DecryptionError
        try:
            for key in self.pskc.keys:
                key.secret, key.counter, key.time_offset
                key.time_interval, key.time_drift
        except DecryptionError:
            return True
        return False

    def derive_key(self, password: str | bytes | bytearray) -> None:
        """Derive a key from the password.

        The supplied password, together with the information embedded in the PSKC
        file (generally algorithm, salt, etc.) is used to create a decryption key.

        This function may raise a :exc:`~pskc.exceptions.KeyDerivationError`
        exception if key derivation fails.
        """
        self.key = self.derivation.derive(password)

    def _setup_encryption(
        self,
        *,
        id: str | None = None,
        algorithm: str | None = None,
        key_name: str | None = None,
        key_names: list[str] | None = None,
        fields: list[str] | None = None,
    ) -> None:
        if id is not None:
            self.id = id
        if algorithm is not None:
            self.algorithm = algorithm
        if key_name is not None:
            self.key_name = key_name
        if key_names is not None:
            self.key_names = key_names
        if fields is not None:
            self.fields = fields
        # default encryption to AES128-CBC
        if not self.algorithm:
            self.algorithm = 'aes128-cbc'
        # default to encrypting the secret only
        if not self.fields:
            self.fields = ['secret']
        # if we're using a CBC mode of encryption, add a MAC
        if self.algorithm.endswith('-cbc'):
            self.pskc.mac.setup()

    def setup_preshared_key(
        self,
        *,
        key: bytes | None = None,
        id: str | None = None,
        algorithm: str | None = None,
        key_length: int | None = None,
        key_name: str | None = None,
        key_names: list[str] | None = None,
        fields: list[str] | None = None,
    ) -> None:
        """Configure pre-shared key encryption when writing the file.

        :param key: the encryption key to use
        :param id: encryption key identifier
        :param algorithm: encryption algorithm
        :param key_length: encryption key length in bytes
        :param key_name: a name for the key
        :param key_names: a number of names for the key
        :param fields: a list of fields to encrypt

        This is a utility function to easily set up encryption. Encryption can
        also be set up by manually by setting the correct
        :class:`~pskc.encryption.Encryption` properties.

        This method will generate a key if required and set the passed values.
        By default AES128-CBC encryption will be configured and unless a key is
        specified one of the correct length will be generated. If the algorithm
        does not provide integrity checks (e.g. CBC-mode algorithms) integrity
        checking in the PSKC file will be set up using
        :func:`~pskc.mac.MAC.setup()`.

        By default only the :attr:`~pskc.key.Key.secret` property will be
        encrypted when writing the file.
        """
        self._setup_encryption(
            id=id,
            algorithm=algorithm,
            key_name=key_name,
            key_names=key_names,
            fields=fields,
        )
        if not key:
            key_length = key_length or self.algorithm_key_lengths[-1]
            key = os.urandom(key_length)
        self.key = key

    def setup_pbkdf2(
        self,
        password: str | bytes | bytearray,
        *,
        id: str | None = None,
        algorithm: str | None = None,
        key_name: str | None = None,
        key_names: list[str] | None = None,
        key_length: int | None = None,
        fields: list[str] | None = None,
        salt: bytes | None = None,
        salt_length: int = 16,
        iterations: int | None = None,
        prf: str | None = None,
    ) -> None:
        """Configure password-based PSKC encryption when writing the file.

        :param password: the password to use (required)
        :param id: encryption key identifier
        :param algorithm: encryption algorithm
        :param key_length: encryption key length in bytes
        :param key_name: a name for the key
        :param key_names: a number of names for the key
        :param fields: a list of fields to encrypt
        :param salt: PBKDF2 salt
        :param salt_length: used when generating random salt
        :param iterations: number of PBKDF2 iterations
        :param prf: PBKDF2 pseudorandom function

        Defaults for the above parameters are similar to those for
        :func:`setup_preshared_key()` but the password parameter is required.

        By default 12000 iterations will be used and a random salt with the
        length of the to-be-generated encryption key will be used.
        """
        self._setup_encryption(
            id=id,
            algorithm=algorithm,
            key_name=key_name,
            key_names=key_names,
            fields=fields,
        )
        self.key = self.derivation.setup_pbkdf2(
            password,
            salt=salt,
            salt_length=salt_length,
            key_length=key_length or self.algorithm_key_lengths[-1],
            iterations=iterations,
            prf=prf,
        )

    @property
    def algorithm_key_lengths(self) -> Sequence[int]:
        """Provide the possible key lengths for the configured algorithm."""
        return algorithm_key_lengths(self.algorithm)

    def decrypt_value(self, cipher_value: bytes, algorithm: str | None = None) -> bytes:
        """Decrypt the cipher_value and return the plaintext value."""
        return decrypt(
            algorithm or self.algorithm, self.key, cipher_value, self.iv)

    def encrypt_value(self, plaintext: bytes) -> bytes:
        """Encrypt the provided value and return the cipher_value."""
        cipher_value = encrypt(self.algorithm, self.key, plaintext, self.iv)
        if self.iv:
            cipher_value = cipher_value[len(self.iv):]
        return cipher_value

    def remove_encryption(self) -> None:
        """Decrypt all values and remove the encryption from the PSKC file.

        This can be used to read and encrypted PSKC file, decrypt the file,
        remove the encryption and output an unencrypted PSKC file or to replace
        the encryption algorithm.
        """
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
