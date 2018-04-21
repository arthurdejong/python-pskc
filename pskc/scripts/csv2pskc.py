# csv2pskc.py - script to convert a CSV file to PSKC
#
# Copyright (C) 2018 Arthur de Jong
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

"""Script to convert a CSV file to PSKC."""

import argparse
import base64
import csv
import sys
from binascii import a2b_hex

import dateutil.parser

import pskc
from pskc.scripts.util import (
    OutputFile, VersionAction, get_key, get_password)


epilog = '''
supported columns:
  id, serial, secret, counter, time_offset, time_interval, interval,
  time_drift, issuer, manufacturer, response_length, algorithm
And any other properties of pskc.key.Key instances.

Report bugs to <python-pskc-users@lists.arthurdejong.org>.
'''.strip()

# set up command line parser
parser = argparse.ArgumentParser(
    formatter_class=argparse.RawDescriptionHelpFormatter,
    description='Convert a CSV file to PSKC.', epilog=epilog)
parser.add_argument(
    'input', nargs='?', metavar='FILE', help='the CSV file to read')
parser.add_argument(
    '-V', '--version', action=VersionAction)
parser.add_argument(
    '-o', '--output', metavar='FILE',
    help='write PSKC to file instead of stdout')
parser.add_argument(
    '-c', '--columns', metavar='COL|COL:LABEL,..',
    help='list of columns or label to column mapping to import')
parser.add_argument(
    '--skip-rows', metavar='N', type=int, default=1,
    help='the number of rows before rows with key information start')
parser.add_argument(
    '-x', '--set', metavar='COL=VALUE', action='append',
    type=lambda x: x.split('=', 1), dest='extra_columns',
    help='add an extra value that is added to all key containers')
parser.add_argument(
    '-p', '--password', '--passwd', metavar='PASS/FILE',
    help='password to use for encrypting the PSKC file)')
parser.add_argument(
    '-s', '--secret', metavar='KEY/FILE',
    help='hex encoded encryption key or a file containing the binary key')
encodings = {
    'hex': a2b_hex,
    'base32': base64.b32decode,
    'base64': base64.b64decode,
}
parser.add_argument(
    '-e', '--secret-encoding', choices=sorted(encodings.keys()),
    help='encoding used for reading key material',
    default='hex')


def from_column(key, value, args):
    """Convert a key value read from a CSV file in a format for PSKC."""
    # decode encoded secret
    if key == 'secret':
        return encodings[args.secret_encoding](value)
    # convert dates to timestamps
    if key.endswith('_date'):
        return dateutil.parser.parse(value)
    return value


def open_csvfile(inputfile):
    """Open the CSV file, trying to detect the dialect."""
    # Guess dialect if possible and open the CSV file
    dialect = 'excel'
    try:
        # seek before read to skip sniffing on non-seekable files
        inputfile.seek(0)
        try:
            dialect = csv.Sniffer().sniff(inputfile.read(1024))
        except Exception:  # pragma: no cover (very hard to test in doctest)
            pass
        inputfile.seek(0)
    except IOError:  # pragma: no cover (very hard to test in doctest)
        pass
    return csv.reader(inputfile, dialect)


def main():
    """Convert a CSV file to PSKC."""
    # parse command-line arguments
    args = parser.parse_args()
    # open the CSV file
    csvfile = open_csvfile(open(args.input, 'r') if args.input else sys.stdin)
    # figure out the meaning of the columns
    columns = []
    if args.skip_rows > 0:
        columns = [x.lower().replace(' ', '_') for x in next(csvfile)]
        for i in range(args.skip_rows - 1):
            next(csvfile)
    if args.columns:
        if ':' in args.columns:
            # --columns is a list of mappings
            mapping = dict(
                (label.lower().replace(' ', '_'), key.lower())
                for label, key in (
                    column.split(':')
                    for column in args.columns.split(',')))
            columns = [mapping.get(column, column) for column in columns]
        else:
            # --columns is a list of columns
            columns = [x.lower() for x in args.columns.split(',')]
    # store rows in PSKC structure
    pskcfile = pskc.PSKC()
    for row in csvfile:
        data = dict(args.extra_columns or [])
        for column, value in zip(columns, row):
            for key in column.split('+'):
                if value and key not in ('', '-'):
                    data[key] = from_column(key, value, args)
        pskcfile.add_key(**data)
    # encrypt the file if needed
    if args.secret:
        pskcfile.encryption.setup_preshared_key(key=get_key(args.secret))
    elif args.password:
        pskcfile.encryption.setup_pbkdf2(get_password(args.password))
    # write output PSKC file
    with OutputFile(args.output) as output:
        pskcfile.write(output)
