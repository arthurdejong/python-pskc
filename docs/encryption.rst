PSKC encryption
===============

.. module:: pskc.encryption

The keys (and some other data) in PSKC files can be encrypted. Encryption of
embedded data is defined in a PSKC file with either pre-shared keys,
passphrase-based keys or asymmetric keys (asymmetric keys are currently
unimplemented).

Embedded PSKC encryption is handled inside the :class:`Encryption` class that
defines encryption key and means of deriving keys. It is accessed from
:attr:`pskc.PSKC.encryption`::

   from pskc import PSKC
   pskc = PSKC('somefile.pskcxml')
   pskc.encryption.key = '12345678901234567890123456789012'.decode('hex')

or::

   pskc.encryption.derive_key('qwerty')

Once the encryption key has been set up any encrypted key values from the
PSKC file are available transparently.

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
