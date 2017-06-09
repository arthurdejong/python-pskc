Exceptions
==========

The module and parser will try to interpret any provided PSKC files and will
only raise exceptions on wildly invalid PSKC files.

.. module:: pskc.exceptions

.. exception:: PSKCError

   The base class for all exceptions that the module will raise. In some
   cases third-party code may raise additional exceptions.

.. exception:: ParseError

   Raised when the PSKC file cannot be correctly read due to invalid XML or
   some required element or attribute is missing. This exception should only
   be raised when parsing the file (i.e. when the :class:`~pskc.PSKC` class is
   instantiated).

.. .. exception:: EncryptionError

   Raised when encrypting a value is not possible due to key length issues,
   missing or wrong length plain text, or other issues.

.. exception:: DecryptionError

   Raised when decrypting a value fails due to missing or incorrect key,
   unsupported decryption or MAC algorithm, failed message authentication
   check or other error.

   This exception is generally raised when accessing encrypted information
   (i.e. the :attr:`~pskc.key.Key.secret`, :attr:`~pskc.key.Key.counter`,
   :attr:`~pskc.key.Key.time_offset`, :attr:`~pskc.key.Key.time_interval` or
   :attr:`~pskc.key.Key.time_drift` attributes of the :class:`~pskc.key.Key`
   class).

.. exception:: KeyDerivationError

   Raised when key derivation fails due to an unsupported algorithm or
   missing information in the PSKC file.
