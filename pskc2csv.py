#!/usr/bin/env python
# coding: utf-8

# pskc2csv.py - script to convert a PSKC file to CSV
#
# Copyright (C) 2014 Arthur de Jong
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

import argparse
import csv
import operator
import sys
import getpass
from binascii import b2a_hex

import pskc
from pskc.exceptions import DecryptionError


version_string = '''
pskc2csv (python-pskc) %s
Written by Arthur de Jong.

Copyright (C) 2014 Arthur de Jong
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
        print version_string
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
    '-c', '--columns', metavar='COL,COL', type=lambda x: x.split(','),
    help='list of columns to export',
    default='serial,secret,algorithm,response_length,time_interval')


def password_prompt(pskcfile):
    """Prompt for a password and use the password to decrypt."""
    prompt = 'Password: '
    if pskcfile.encryption.key_name:
        prompt = '%s: ' % pskcfile.encryption.key_name
    passwd = getpass.getpass(prompt)
    pskcfile.encryption.derive_key(passwd)


def get_column(key, column):
    """Return a string value for the given column."""
    value = operator.attrgetter(column)(key)
    if column == 'secret':
        return b2a_hex(value)
    return value


def is_encrypted(pskcfile):
    """Check whether the PSKC file is encrypted."""
    try:
        pskcfile.keys[0].secret
    except DecryptionError:
        return True
    except IndexError:
        pass
    return False


if __name__ == '__main__':
    # parse command-line arguments
    args = parser.parse_args()
    # open and parse input PSKC file
    pskcfile = pskc.PSKC(args.input)
    # see if we should prompt for a password
    if sys.stdin.isatty() and is_encrypted(pskcfile):
        password_prompt(pskcfile)
    # open output CSV file, write header and keys
    with open(args.output, 'wb') if args.output else sys.stdout as output:
        csvfile = csv.writer(output, quoting=csv.QUOTE_MINIMAL)
        csvfile.writerow(args.columns)
        for key in pskcfile.keys:
            csvfile.writerow([
                get_column(key, column) for column in args.columns])
