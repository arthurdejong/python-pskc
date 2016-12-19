# __init__.py - general crypto utility functions
# coding: utf-8
#
# Copyright (C) 2016 Arthur de Jong
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

"""Implement crypto utility functions."""


def pad(value, block_size):
    """Pad the value to block_size length."""
    padding = block_size - (len(value) % block_size)
    return value + padding * chr(padding).encode('ascii')


def unpad(value, block_size):
    """Remove padding from the plaintext."""
    from pskc.exceptions import DecryptionError
    padding = ord(value[-1:])
    # only unpad if all padding bytes are the same
    if (padding > 0 and padding <= block_size and
            value[-padding:] == padding * chr(padding).encode('ascii')):
        return value[:-padding]
    raise DecryptionError('Invalid padding')
