:orphan:

pskc2csv
========

Synopsis
--------

**pskc2csv** [*options*] <*FILE*>

Description
-----------

:program:`pskc2csv` reads a PSKC file, optionally decrypts any encrypted key
material and outputs a CSV file with information from the PSKC file.

Options
-------

.. program:: pskc2csv

.. option:: -h, --help

   Display usage summary.

.. option:: -V, --version

   Display version information.

.. option:: -o FILE, --output FILE

   By default :program:`pskc2csv` writes a CSV file to stdout. This option
   can be used to save the CSV to a file instead.

.. option:: -c COL:LABEL,COL,.., --columns COL:LABEL,COL,..

   Specify the columns that should be written to the CSV file. Any
   property of :class:`~pskc.key.Key` instances can be used as well
   as :class:`~pskc.policy.Policy` properties via ``policy``.

   For example: ``serial``, ``secret``, ``counter``, ``time_offset``,
   ``time_interval``, ``interval``, ``time_drift``, ``issuer``,
   ``manufacturer``, ``response_length``, ``policy.pin_min_length``.

   By default ``serial,secret,algorithm,response_length,time_interval`` is
   used.

   The column can be followed by an optional label to use in the CSV file in
   place of the column specification.

.. option:: -p PASS/FILE, --password PASS/FILE, --passwd PASS/FILE

   The password to use for decryption. If the argument refers to a file the
   password is read from the file instead.

.. option:: -s KEY/FILE, --secret KEY/FILE

   A hex encoded encryption key or a file containing the binary (raw data,
   not encoded) key.

.. option:: -e ENCODING, --secret-encoding ENCODING

   Specify the encoding to use for writing key material to the CSV file. By
   default HEX encoding is used. Valid encodings are: ``base32``, ``base64``
   or ``hex``.
