# __init__.py - main module
# coding: utf-8
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

"""Python module for handling PSKC files

This Python library handles Portable Symmetric Key Container (PSKC) files
as defined in RFC6030. PSKC files are used to transport and provision
symmetric keys (seed files) to different types of crypto modules, commonly
one-time password tokens or other authentication devices.

The main goal of this module is to be able to extract keys from PSKC files
for use in an OTP authentication system.

The following prints all keys, decrypting using a password:

>>> from pskc import PSKC
>>> pskc = PSKC('tests/rfc6030-figure7.pskcxml')
>>> pskc.encryption.derive_key('qwerty')
>>> for key in pskc.keys:
...     print key.serial, key.secret
987654321 12345678901234567890

The module should be able to handle most common PSKC files. Checking
embedded signatures, asymmetric keys and writing files are on the wishlist
(patches welcome).
"""


__all__ = ['PSKC', '__version__']


# the version number of the library
__version__ = '0.1'


class PSKC(object):
    """Wrapper module for parsing a PSKC file.

    Instances of this class provide the following attributes:

      version: the PSKC format version used (1.0)
      id: identifier
      encryption: information on used encryption (Encryption instance)
      mac: information on used MAC method (MAC instance)
      keys: list of keys (Key instances)
    """

    def __init__(self, filename):
        from xml.etree import ElementTree
        from pskc.encryption import Encryption
        from pskc.mac import MAC
        self.version = None
        self.id = None
        self.encryption = Encryption()
        self.mac = MAC(self)
        self.keys = []
        tree = ElementTree.parse(filename)
        self.parse(tree.getroot())

    def parse(self, container):
        """Read information from the provided <KeyContainer> tree."""
        from pskc.parse import namespaces
        from pskc.key import Key
        # the version of the PSKC schema
        self.version = container.attrib.get('Version')
        # unique identifier for the container
        self.id = container.attrib.get('Id')
        # handle EncryptionKey entries
        self.encryption.parse(container.find(
            'pskc:EncryptionKey', namespaces=namespaces))
        # handle MACMethod entries
        self.mac.parse(container.find(
            'pskc:MACMethod', namespaces=namespaces))
        # handle KeyPackage entries
        for package in container.findall(
                'pskc:KeyPackage', namespaces=namespaces):
            self.keys.append(Key(self, package))
