# policy.py - module for handling PSKC policy information
# coding: utf-8
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

"""Module that provides PSKC key policy information."""

import warnings


def _make_aware(d):
    """Make tge specified datetime timezone aware."""
    import dateutil.tz
    if not d.tzinfo:
        return d.replace(tzinfo=dateutil.tz.tzlocal())
    return d


class Policy(object):
    """Representation of a policy that describes key and pin usage.

    Instances of this class provide attributes that describe limits that
    are placed on key usage and requirements for key PIN protection. The
    policy provides the following attributes:

      start_date: the key MUST not be used before this datetime
      expiry_date: the key MUST not be used after this datetime
      number_of_transactions: maximum number of times the key may be used
      key_usage: list of valid usage scenarios for the key (e.g. OTP)
      pin_key_id: id of to the key that holds the PIN
      pin_key: reference to the key that holds the PIN
      pin: value of the PIN to use
      pin_usage: define how the PIN is used in relation to the key
      pin_max_failed_attempts: max. number of times a wrong PIN may be entered
      pin_min_length: minimum length of a PIN that may be set
      pin_max_length: maximum length of a PIN that may be set
      pin_encoding: DECIMAL/HEXADECIMAL/ALPHANUMERIC/BASE64/BINARY
      unknown_policy_elements: True if the policy contains unsupported rules

    If unknown_policy_elements is True the recipient MUST assume that key
    usage is not permitted.
    """

    # Key is used for OTP generation.
    KEY_USE_OTP = 'OTP'

    # Key is used for Challenge/Response purposes.
    KEY_USE_CR = 'CR'

    # Key is used for data encryption purposes.
    KEY_USE_ENCRYPT = 'Encrypt'

    # For generating keyed message digests.
    KEY_USE_INTEGRITY = 'Integrity'

    # For checking keyed message digests.
    KEY_USE_VERIFY = 'Verify'

    # Unlocking device when wrong PIN has been entered too many times.
    KEY_USE_UNLOCK = 'Unlock'

    # Key is used for data decryption purposes.
    KEY_USE_DECRYPT = 'Decrypt'

    # The key is used for key wrap purposes.
    KEY_USE_KEYWRAP = 'KeyWrap'

    # The key is used for key unwrap purposes.
    KEY_USE_UNWRAP = 'Unwrap'

    # Use in a key derivation function to derive a new key.
    KEY_USE_DERIVE = 'Derive'

    # Generate a new key based on a random number and the previous value.
    KEY_USE_GENERATE = 'Generate'

    # The PIN is checked on the device before the key is used.
    PIN_USE_LOCAL = 'Local'

    # The response has the PIN prepanded and needs to be checked.
    PIN_USE_PREPEND = 'Prepend'

    # The response has the PIN appended and needs to be checked.
    PIN_USE_APPEND = 'Append'

    # The PIN is used in the algorithm computation.
    PIN_USE_ALGORITHMIC = 'Algorithmic'

    def __init__(self, key=None):
        """Create a new policy, optionally linked to the key and parsed."""
        self.key = key
        self.start_date = None
        self.expiry_date = None
        self.number_of_transactions = None
        self.key_usage = []
        self.pin_key_id = None
        self.pin_usage = None
        self.pin_max_failed_attempts = None
        self.pin_min_length = None
        self.pin_max_length = None
        self.pin_encoding = None
        self.unknown_policy_elements = False

    @property
    def pin_max_failed_attemtps(self):
        """Provide access to deprecated name."""
        warnings.warn(
            'The pin_max_failed_attemtps property has been renamed to '
            'pin_max_failed_attempts.', DeprecationWarning, stacklevel=2)
        return self.pin_max_failed_attempts

    @pin_max_failed_attemtps.setter
    def pin_max_failed_attemtps(self, value):
        warnings.warn(
            'The pin_max_failed_attemtps property has been renamed to '
            'pin_max_failed_attempts.', DeprecationWarning, stacklevel=2)
        self.pin_max_failed_attempts = value

    def may_use(self, usage=None, now=None):
        """Check whether the key may be used for the provided purpose."""
        import datetime
        import dateutil.tz
        if self.unknown_policy_elements:
            return False
        if usage is not None and self.key_usage:
            if usage not in self.key_usage:
                return False
        # check start_date and expiry_date
        if now is None:
            now = datetime.datetime.now(dateutil.tz.tzlocal())
        if self.start_date:
            if _make_aware(self.start_date) > _make_aware(now):
                return False  # not-yet usable key
        if self.expiry_date:
            if _make_aware(self.expiry_date) < _make_aware(now):
                return False  # not-yet usable key
        return True

    @property
    def pin_key(self):
        """Provide the PSKC Key that holds the PIN (if any)."""
        if self.pin_key_id and self.key and self.key.device.pskc:
            for key in self.key.device.pskc.keys:
                if key.id == self.pin_key_id:
                    return key

    @property
    def pin(self):
        """Provide the PIN value referenced by PINKeyId if any."""
        key = self.pin_key
        if key:
            return str(key.secret.decode())
