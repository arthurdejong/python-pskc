# exceptions.py - collection of pskc exceptions
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

"""Collection of exceptions."""


class PSKCError(Exception):
    """General top-level exception."""

    pass


class ParseError(PSKCError):
    """Something went wrong with parsing the PSKC file.

    Either the file is invalid XML or required elements or attributes are
    missing.
    """

    pass


class EncryptionError(PSKCError):
    """There was a problem encrypting the value."""

    pass


class DecryptionError(PSKCError):
    """There was a problem decrypting the value.

    The encrypted value as available but something went wrong with decrypting
    it.
    """

    pass


class KeyDerivationError(PSKCError):
    """There was a problem performing the key derivation."""

    pass
