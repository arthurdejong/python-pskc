# device.py - module for handling device info from pskc files
# coding: utf-8
#
# Copyright (C) 2016-2025 Arthur de Jong
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

"""Module that handles device information stored in PSKC files."""

from __future__ import annotations

import datetime
from typing import Any, TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover (only for mypy)
    from pskc import PSKC
    from pskc.key import Key


def update_attributes(obj: Key | Device, **kwargs: Any) -> None:
    """Update object with provided properties."""
    for k, v in kwargs.items():
        parts = k.split('.') if '.' in k else k.split('__')
        o = obj
        for name in parts[:-1]:
            o = getattr(o, name)
        getattr(o, parts[-1])  # raise exception for non-existing properties
        setattr(o, parts[-1], v)


class Device:
    """Representation of a single key from a PSKC file.

    Instances of this class provide the following properties:

      manufacturer: name of the organisation that made the device
      serial: serial number of the device
      model: device model description
      issue_no: issue number per serial number
      device_binding: device (class) identifier for the key to be loaded upon
      start_date: key should not be used before this date
      expiry_date: key or device may expire after this date
      device_userid: user distinguished name associated with the device
      crypto_module: id of module to which keys are provisioned within device
    """

    def __init__(self, pskc: PSKC) -> None:

        self.pskc = pskc

        self.manufacturer: str | None = None
        self.serial: str | None = None
        self.model: str | None = None
        self.issue_no: str | int | None = None
        self.device_binding: str | None = None
        self.start_date: datetime.datetime | None = None
        self.expiry_date: datetime.datetime | None = None
        self.device_userid: str | None = None
        self.crypto_module: str | None = None

        self.keys: list[Key] = []

    def add_key(self, **kwargs: str | bytes | int | datetime.datetime | None) -> Key:
        """Create a new key instance for the device.

        The new key is initialised with properties from the provided keyword
        arguments if any.

        The arguments may be any valid attribute of :class:`~pskc.key.Key` or
        be of the special form `policy.attribute` or `policy__attribute` to set
        any attribute of :class:`~pskc.policy.Policy`.
        """
        from pskc.key import Key
        key = Key(self)
        self.keys.append(key)
        update_attributes(key, **kwargs)
        return key
