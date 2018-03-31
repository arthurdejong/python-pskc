:orphan:

csv2pskc
========

Synopsis
--------

**csv2pskc** [*options*] [<*FILE*>]

Description
-----------

:program:`csv2pskc` reads a CSV file where the first line contains column
labels and following lines contain key information for one key per line.

Options
-------

.. program:: csv2pskc

.. option:: -h, --help

   Display usage summary.

.. option:: -V, --version

   Display version information.

.. option:: -o FILE, --output FILE

   By default :program:`csv2pskc` writes a PSKC file to stdout. This option
   can be used to save to a file instead.

.. option:: -p PASS/FILE, --password PASS/FILE, --passwd PASS/FILE

   Encrypt the PSKC file with the specified password. If the argument refers
   to a file the password is read from the file instead.

.. option:: -s KEY/FILE, --secret KEY/FILE

   A hex encoded encryption key or a file containing the binary key (raw
   data, not encoded).

.. option:: -e ENCODING, --secret-encoding ENCODING

   Specify the encoding to use for reading key material from the CSV file. By
   default HEX encoding is used. Valid encodings are: ``base32``, ``base64``
   or ``hex``.
