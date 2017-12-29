#!/usr/bin/env python
# coding: utf-8

# pskc2csv.py - script to convert a PSKC file to CSV
#
# Copyright (C) 2014-2017 Arthur de Jong
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

from __future__ import print_function
import argparse
import base64
import csv
import getpass
import operator
import os.path
import sys
from binascii import a2b_hex, b2a_hex

import pskc
from pskc.exceptions import DecryptionError


version_string = '''
pskc2csv (python-pskc) %s
Written by Arthur de Jong.

Copyright (C) 2014-2017 Arthur de Jong
This is free software; see the source for copying conditions.  There is NO
warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
'''.strip() % pskc.__version__


class VersionAction(argparse.Action):

    def __init__(self, option_strings, dest,
                 help='output version information and exit'):
        super(VersionAction, self).__init__(
            option_strings=option_strings,
            dest=argparse.SUPPRESS,
            default=argparse.SUPPRESS,
            nargs=0,
            help=help)

    def __call__(self, parser, namespace, values, option_string=None):
        print(version_string)
        parser.exit()


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
    description='Convert a PSKC file to CSV.', epilog=epilog)
parser.add_argument(
    'input', metavar='FILE', help='the PSKC file to read')
parser.add_argument(
    '-V', '--version', action=VersionAction)
parser.add_argument(
    '-o', '--output', metavar='FILE',
    help='write CSV to file instead of stdout')
parser.add_argument(
    '-c', '--columns', metavar='COL:LABEL,COL,..',
    type=lambda x: [column.split(':', 1) for column in x.split(',')],
    help='list of columns with optional labels to export',
    default='serial,secret,algorithm,response_length,time_interval')
parser.add_argument(
    '-p', '--password', '--passwd', metavar='PASS/FILE',
    help='password to use for decryption (or read from a file)')
parser.add_argument(
    '-s', '--secret', metavar='KEY/FILE',
    help='hex encoded encryption key or file containing the binary key')
encodings = {
    'hex': b2a_hex,
    'base32': base64.b32encode,
    'base64': base64.b64encode,
}
parser.add_argument(
    '-e', '--secret-encoding', choices=sorted(encodings.keys()),
    help='encoding used for outputting key material',
    default='hex')


def get_column(key, column, encoding):
    """Return a string value for the given column."""
    value = operator.attrgetter(column)(key)
    if column == 'secret':
        # Python 3 compatible construct for outputting a string
        return str(encodings[encoding](value).decode())
    return value


def main():
    # parse command-line arguments
    args = parser.parse_args()
    # open and parse input PSKC file
    pskcfile = pskc.PSKC(args.input)
    if args.secret:
        if os.path.isfile(args.secret):
            with open(args.secret, 'rb') as keyfile:
                pskcfile.encryption.key = keyfile.read()
        else:
            pskcfile.encryption.key = a2b_hex(args.secret)
    elif args.password:
        if os.path.isfile(args.password):
            with open(args.password, 'r') as passfile:
                passwd = passfile.read().replace('\n', '')
            pskcfile.encryption.derive_key(passwd)
        else:
            pskcfile.encryption.derive_key(args.password)
    elif sys.stdin.isatty() and pskcfile.encryption.is_encrypted:
        # prompt for a password
        prompt = 'Password: '
        if pskcfile.encryption.key_name:
            prompt = '%s: ' % pskcfile.encryption.key_name
        passwd = getpass.getpass(prompt)
        pskcfile.encryption.derive_key(passwd)
    # open output CSV file, write header and keys
    output = open(args.output, 'w') if args.output else sys.stdout
    csvfile = csv.writer(output, quoting=csv.QUOTE_MINIMAL)
    csvfile.writerow([column[-1] for column in args.columns])
    for key in pskcfile.keys:
        csvfile.writerow([
            get_column(key, column[0], args.secret_encoding)
            for column in args.columns])
    if args.output:
        output.close()
    else:
        output.flush()


if __name__ == '__main__':  # pragma: no cover
    main()
