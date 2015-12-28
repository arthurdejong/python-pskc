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

If no key or an incorrect key has been set configured, upon accessing encrypted
information (e.g. the :attr:`~pskc.key.Key.secret` attribute of a
:class:`~pskc.key.Key` instance) a :exc:`~pskc.exceptions.DecryptionError`
exception will be raised.


The Encryption class
--------------------

.. class:: Encryption

   .. attribute:: id

      Optional identifier of the encryption key.

   .. attribute:: key_names

      List of names provided for the encryption key.

   .. attribute:: key_name

      Since usually only one name is defined for a key but the schema allows
      for multiple names, this is a shortcut for accessing the first value of
      :attr:`key_names`.

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
