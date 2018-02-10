#!/usr/bin/env python
# coding: utf-8

# pskc2pskc.py - script to convert a PSKC file to another PSKC file
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

from __future__ import print_function
import argparse
import getpass
import operator
import os.path
import sys
from binascii import a2b_hex, b2a_hex

import pskc


version_string = '''
pskc2pskc (python-pskc) %s
Written by Arthur de Jong.

Copyright (C) 2018 Arthur de Jong
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
    description='Convert a PSKC file to another PSKC file.', epilog=epilog)
parser.add_argument(
    'input', metavar='FILE', help='the PSKC file to read')
parser.add_argument(
    '-V', '--version', action=VersionAction)
parser.add_argument(
    '-o', '--output', metavar='FILE',
    help='write PSKC to file instead of stdout')
parser.add_argument(
    '-p', '--password', '--passwd', metavar='PASS/FILE',
    help='password to use for decryption (or read from a file)')
parser.add_argument(
    '-s', '--secret', metavar='KEY/FILE',
    help='hex encoded encryption key or a file containing the binary key')
parser.add_argument(
    '--new-password', '--new-passwd', metavar='PASS/FILE',
    help='password to use for encryption (or read from a file)')
parser.add_argument(
    '--new-secret', metavar='KEY/FILE',
    help='hex encoded encryption key or a file containing the binary key')


def get_key(argument):
    """Get the key from a file or a hex-encoded string."""
    if os.path.isfile(argument):
        with open(argument, 'rb') as keyfile:
            return keyfile.read()
    else:
        return a2b_hex(argument)


def get_password(argument):
    """Get the password from a file or as a string."""
    if os.path.isfile(argument):
        with open(argument, 'r') as passfile:
            return passfile.read().replace('\n', '')
    else:
        return argument


def main():
    # parse command-line arguments
    args = parser.parse_args()
    # open and parse input PSKC file
    pskcfile = pskc.PSKC(args.input)
    if args.secret:
        pskcfile.encryption.key = get_key(args.secret)
        pskcfile.encryption.remove_encryption()
    elif args.password:
        pskcfile.encryption.derive_key(get_password(args.password))
        pskcfile.encryption.remove_encryption()
    # encrypt the file if needed
    if args.new_secret:
        assert not pskcfile.encryption.is_encrypted
        pskcfile.encryption.setup_preshared_key(key=get_key(args.new_secret))
    elif args.new_password:
        assert not pskcfile.encryption.is_encrypted
        pskcfile.encryption.setup_pbkdf2(get_password(args.new_password))
    # write output PSKC file
    output = open(args.output, 'w') if args.output else sys.stdout
    pskcfile.write(output)
    if args.output:
        output.close()
    else:
        output.flush()


if __name__ == '__main__':  # pragma: no cover
    main()
