# exceptions.py - collection of pskc exceptions
# coding: utf-8
#
# Copyright (C) 2014-2025 Arthur de Jong
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

from __future__ import annotations


class PSKCError(Exception):
    """General top-level exception.

    The base class for all exceptions that the module will raise. In some
    cases third-party code may raise additional exceptions.
    """

    pass


class ParseError(PSKCError):
    """Something went wrong with parsing the PSKC file.

    Raised when the PSKC file cannot be correctly read due to invalid XML or
    some required element or attribute is missing. This exception should only
    be raised when parsing the file (i.e. when the :class:`~pskc.PSKC` class is
    instantiated).
    """

    pass


class EncryptionError(PSKCError):
    """There was a problem encrypting the value.

    Raised when encrypting a value is not possible due to key length issues,
    missing or wrong length plain text, or other issues.
    """

    pass


class DecryptionError(PSKCError):
    """There was a problem decrypting the value.

    Raised when decrypting a value fails due to missing or incorrect key,
    unsupported decryption or MAC algorithm, failed message authentication
    check or other error.

    This exception is generally raised when accessing encrypted information
    (i.e. the :attr:`~pskc.key.Key.secret`, :attr:`~pskc.key.Key.counter`,
    :attr:`~pskc.key.Key.time_offset`, :attr:`~pskc.key.Key.time_interval` or
    :attr:`~pskc.key.Key.time_drift` attributes of the :class:`~pskc.key.Key`
    class).
    """

    pass


class KeyDerivationError(PSKCError):
    """There was a problem performing the key derivation.

    Raised when key derivation fails due to an unsupported algorithm or
    missing information in the PSKC file.
    """

    pass
