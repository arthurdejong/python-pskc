# __init__.py - main module
# coding: utf-8
#
# Copyright (C) 2014-2024 Arthur de Jong
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

"""Python module for handling PSKC files.

This Python library handles Portable Symmetric Key Container (PSKC) files as
defined in RFC 6030. PSKC files are used to transport and provision symmetric
keys (seed files) to different types of crypto modules, commonly one-time
password tokens or other authentication devices.

This module can be used to extract keys from PSKC files for use in an OTP
authentication system. The module can also be used for authoring PSKC files.

The following prints all keys, decrypting using a password:

>>> from pskc import PSKC
>>> pskc = PSKC('tests/rfc6030/figure7.pskcxml')
>>> pskc.encryption.derive_key('qwerty')
>>> for key in pskc.keys:
...     print('%s %s' % (key.serial, str(key.secret.decode())))
987654321 12345678901234567890

The following generates an encrypted PSKC file:

>>> pskc = PSKC()
>>> key = pskc.add_key(
...     id='456', secret='987654321', manufacturer='Manufacturer',
...     algorithm = 'urn:ietf:params:xml:ns:keyprov:pskc:hotp')
>>> pskc.encryption.setup_pbkdf2('passphrase')
>>> pskc.write('output.pskcxml')

The module should be able to handle most common PSKC files.
"""


__all__ = ['PSKC', '__version__']


# the version number of the library
__version__ = '1.3'


class PSKC(object):
    """Wrapper module for parsing a PSKC file.

    Instances of this class provide the following attributes:

      version: the PSKC format version used (1.0)
      id: identifier
      encryption: information on used encryption (Encryption instance)
      mac: information on used MAC method (MAC instance)
      devices: list of devices (Device instances)
      keys: list of keys (Key instances)
    """

    def __init__(self, filename=None):
        from pskc.encryption import Encryption
        from pskc.signature import Signature
        from pskc.mac import MAC
        self.version = None
        self.id = None
        self.encryption = Encryption(self)
        self.signature = Signature(self)
        self.mac = MAC(self)
        self.devices = []
        if filename is not None:
            from pskc.parser import PSKCParser
            PSKCParser.parse_file(self, filename)
        else:
            self.version = '1.0'

    @property
    def keys(self):
        """Provide a list of keys."""
        return tuple(key for device in self.devices for key in device.keys)

    def add_device(self, **kwargs):
        """Create a new device instance for the PSKC file.

        The device is initialised with properties from the provided keyword
        arguments if any.
        """
        from pskc.device import Device, update_attributes
        device = Device(self)
        self.devices.append(device)
        update_attributes(device, **kwargs)
        return device

    def add_key(self, **kwargs):
        """Create a new key instance for the PSKC file.

        The new key is initialised with properties from the provided keyword
        arguments if any.
        """
        from pskc.device import update_attributes
        device = self.add_device()
        key = device.add_key()
        update_attributes(key, **kwargs)
        return key

    def write(self, filename):
        """Write the PSKC file to the provided file."""
        from pskc.serialiser import PSKCSerialiser
        if hasattr(filename, 'write'):
            PSKCSerialiser.serialise_file(self, filename)
        else:
            with open(filename, 'wb') as output:
                self.write(output)
