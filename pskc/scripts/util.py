# util.py - utility functions for command-line scripts
#
# Copyright (C) 2014-2018 Arthur de Jong
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

"""Utility functions for command-line scripts."""

import argparse
import os.path
import sys
from binascii import a2b_hex

import pskc


version_string = '''
%s (python-pskc) %s
Written by Arthur de Jong.

Copyright (C) 2014-2018 Arthur de Jong
This is free software; see the source for copying conditions.  There is NO
warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
'''.lstrip()


class VersionAction(argparse.Action):
    """Define --version argparse action."""

    def __init__(self, option_strings, dest,
                 help='output version information and exit'):
        super(VersionAction, self).__init__(
            option_strings=option_strings,
            dest=argparse.SUPPRESS,
            default=argparse.SUPPRESS,
            nargs=0,
            help=help)

    def __call__(self, parser, namespace, values, option_string=None):
        """Output version information and exit."""
        sys.stdout.write(version_string % (parser.prog, pskc.__version__))
        parser.exit()


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


class OutputFile(object):
    """Wrapper around output file to also fall back to stdout."""

    def __init__(self, output):
        self.output = output

    def __enter__(self):
        self.file = open(self.output, 'w') if self.output else sys.stdout
        return self.file

    def __exit__(self, *args):
        if self.output:
            self.file.close()
        else:  # we are using stdout
            self.file.flush()
