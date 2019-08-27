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

.. option:: -c COL,COL,.., --columns COL,COL,..

   Specify the meaning of the columns in the CSV file. By default the first
   row of the CSV file is expected to list the names of the columns.

   Any property of :class:`~pskc.key.Key` instances can be used as well as
   :class:`~pskc.policy.Policy` properties via ``policy``. For example:
   ``serial``, ``secret``, ``counter``, ``time_offset``, ``time_interval``,
   ``interval``, ``time_drift``, ``issuer``, ``manufacturer``,
   ``response_length``, ``policy.pin_min_length``.

   This option can either specify a list of columns or a COL:KEY mapping
   where COL refers to the value found in the first line of the CSV file and
   KEY refers to a property as described above.

   It is possible to map a single column in the CSV file to multiple PSKC
   properties (e.g. use of ``id+serial`` sets both the ID and device serial
   number to the value found in that column).

.. option:: --skip-rows N

   By default the first row is treated as a header which contains labels.
   This option can be used to either skip more row (the first row of the CSV file will
   still be treated as a header) or to indicate that there is no header row.

   In the latter case the :option:`--columns` option is required.

.. option:: -x COL=VALUE, --set COL=VALUE

   Specify properties that are added to all keys in the generated PSKC file.
   Accepted labels are the same as for the :option:`--columns` option.

   This can be useful for setting the ``issuer``, ``manufacturer`` or
   other common properties globally.

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
