PSKC encryption
===============

.. module:: pskc.encryption

Some of the information in PSKC files (e.g. key material) can be encrypted
with either pre-shared keys, passphrase-based keys or asymmetric keys
(asymmetric keys are currently unimplemented).

Embedded PSKC encryption is handled inside the :class:`Encryption` class that
defines encryption key or means of deriving keys. It is accessed from the
:attr:`~pskc.PSKC.encryption` attribute of a :class:`~pskc.PSKC` instance::

   >>> from binascii import a2b_hex
   >>> from pskc import PSKC
   >>> pskc = PSKC('somefile.pskcxml')
   >>> pskc.encryption.key = a2b_hex('12345678901234567890123456789012')

or::

   >>> pskc.encryption.derive_key('qwerty')

Once the encryption key has been set up, any encrypted key values from the
PSKC file are available transparently.

If no key or an incorrect key has been configured, upon accessing encrypted
information (e.g. the :attr:`~pskc.key.Key.secret` attribute of a
:class:`~pskc.key.Key` instance) a :exc:`~pskc.exceptions.DecryptionError`
exception will be raised.

When writing out a PSKC file, encryption can be configured with the
:func:`~pskc.encryption.Encryption.setup_preshared_key()` or
:func:`~pskc.encryption.Encryption.setup_pbkdf2()` function::

   >>> from pskc import PSKC
   >>> pskc = PSKC()
   >>> pskc.encryption.setup_preshared_key(algorithm='AES256-CBC')

or::

   >>> pskc.encryption.setup_pbkdf2(password='verysecure')


The Encryption class
--------------------

.. class:: Encryption

   .. attribute:: id

      Optional identifier of the encryption key.

   .. attribute:: algorithm

      A URI of the encryption algorithm used. Setting a value for this
      attribute will result in an attempt to use the canonical URI for this
      algorithm. For instance setting a `3DES-CBC` value will automatically
      be converted to `http://www.w3.org/2001/04/xmlenc#aes128-cbc`.

   .. attribute:: key_names

      List of names provided for the encryption key.

   .. attribute:: key_name

      Since usually only one name is defined for a key but the schema allows
      for multiple names, this is a shortcut for accessing the first value of
      :attr:`key_names`. It will return ``None`` if no name is available.

   .. attribute:: key

      The binary value of the encryption key. In the case of pre-shared keys
      this value should be set before trying to access encrypted information
      in the PSKC file.

      When using key derivation the secret key is available in this attribute
      after calling :func:`derive_key`.

   .. function:: derive_key(password)

      Derive a key from the supplied password and information in the PSKC
      file (generally algorithm, salt, etc.).

      This function may raise a :exc:`~pskc.exceptions.KeyDerivationError`
      exception if key derivation fails for some reason.

   .. attribute:: fields

      A list of :class:`~pskc.key.Key` instance field names that will be
      encrypted when the PSKC file is written. List values can contain
      ``secret``, ``counter``, ``time_offset``, ``time_interval`` and
      ``time_drift``.

   .. function:: setup_preshared_key(...)

      Configure pre-shared key encryption.

      :param binary key: the encryption key to use
      :param str id: encryption key identifier
      :param str algorithm: encryption algorithm
      :param int key_length: encryption key length in bytes
      :param str key_name: a name for the key
      :param list key_names: a number of names for the key
      :param list fields: a list of fields to encrypt

      This is a utility function to easily set up encryption. Encryption can
      also be set up by manually by setting the
      :class:`~pskc.encryption.Encryption` properties.

      This method will generate a key if required and set the passed values.
      By default AES128-CBC encryption will be configured and unless a key is
      specified one of the correct length will be generated. If the algorithm
      does not provide integrity checks (e.g. CBC-mode algorithms) integrity
      checking in the PSKC file will be set up using
      :func:`~pskc.mac.MAC.setup()`.

      By default only the :attr:`~pskc.key.Key.secret` property will be
      encrypted when writing the file.

   .. function:: setup_pbkdf2(...)

      Configure password-based PSKC encryption.

      :param str password: the password to use (required)
      :param str id: encryption key identifier
      :param str algorithm: encryption algorithm
      :param int key_length: encryption key length in bytes
      :param str key_name: a name for the key
      :param list key_names: a number of names for the key
      :param list fields: a list of fields to encrypt
      :param binary salt: PBKDF2 salt
      :param int salt_length: used when generating random salt
      :param int iterations: number of PBKDF2 iterations
      :param function prf: PBKDF2 pseudorandom function

      Defaults for the above parameters are similar to those for
      :func:`setup_preshared_key()` but the password parameter is required.

      By default 12000 iterations will be used and a random salt with the
      length of the to-be-generated encryption key will be used.
