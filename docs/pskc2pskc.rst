:orphan:

pskc2pskc
=========

Synopsis
--------

**pskc2pskc** [*options*] <*FILE*>

Description
-----------

:program:`pskc2pskc` reads a PSKC file in any of the supported formats,
optionally decrypts any encrypted information and outputs a PSKC file in the
RFC 6030 format, optionally encrypting the file.

Options
-------

.. program:: pskc2pskc

.. option:: -h, --help

   Display usage summary.

.. option:: -V, --version

   Display version information.

.. option:: -o FILE, --output FILE

   By default :program:`pskc2pskc` writes a PSKC file to stdout. This option
   can be used to save to a file instead.

.. option:: -p PASS/FILE, --password PASS/FILE, --passwd PASS/FILE

   The password to use for decryption. If the argument refers to a file the
   password is read from the file instead.

.. option:: -s KEY/FILE, --secret KEY/FILE

   A hex encoded encryption key or a file containing the binary (raw data,
   not encoded) key used for decryption.

.. option:: --new-password PASS/FILE, --new-passwd PASS/FILE

   Output an encrypted PSKC file that is protected with the specified
   password (or read the password from the file if a file argument was
   specified).

.. option:: --new-secret KEY/FILE

   Ensure that the output PSKC file is encrypted with the specified key
   value. The key can be provided as a hex-encoded value or point to a file
   that contains the binary value of the key.
