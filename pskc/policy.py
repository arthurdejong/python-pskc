# policy.py - module for handling PSKC policy information
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

"""Module that provides PSKC key policy information."""


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
      pin_max_failed_attemtps: max. number of times a wrong PIN may be entered
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

    def __init__(self, key=None, policy=None):
        """Create a new policy, optionally linked to the key and parsed."""
        self.key = key
        self.start_date = None
        self.expiry_date = None
        self.number_of_transactions = None
        self.key_usage = []
        self.pin_key_id = None
        self.pin_usage = None
        self.pin_max_failed_attemtps = None
        self.pin_min_length = None
        self.pin_max_length = None
        self.pin_encoding = None
        self.unknown_policy_elements = False
        self.parse(policy)

    def parse(self, policy):
        """Read key policy information from the provided <Policy> tree."""
        from pskc.parse import g_e_v, g_e_i, g_e_d, namespaces
        if policy is None:
            return

        self.start_date = g_e_d(policy, 'pskc:StartDate')
        self.expiry_date = g_e_d(policy, 'pskc:ExpiryDate')
        self.number_of_transactions = g_e_i(
            policy, 'pskc:NumberOfTransactions')
        for key_usage in policy.findall(
                'pskc:KeyUsage', namespaces=namespaces):
            self.key_usage.append(g_e_v(key_usage, '.'))

        pin_policy = policy.find(
            'pskc:PINPolicy', namespaces=namespaces)
        if pin_policy is not None:
            self.pin_key_id = pin_policy.attrib.get('PINKeyId')
            self.pin_usage = pin_policy.attrib.get('PINUsageMode')
            v = pin_policy.attrib.get('MaxFailedAttempts')
            if v:
                self.pin_max_failed_attemtps = int(v)
            v = pin_policy.attrib.get('MinLength')
            if v:
                self.pin_min_length = int(v)
            v = pin_policy.attrib.get('MaxLength')
            if v:
                self.pin_max_length = int(v)
            self.pin_encoding = pin_policy.attrib.get('PINEncoding')
            # TODO: check if there are any other attributes set for PINPolicy
            # of if there are any children and set unknown_policy_elementss

        # TODO: check if there are other children and make sure
        # policy rejects any key usage (set unknown_policy_elements)

    def may_use(self, usage):
        """Check whether the key may be used for the provided purpose."""
        if self.unknown_policy_elements:
            return False
        return not self.key_usage or usage in self.key_usage

    @property
    def pin_key(self):
        """Reference to the PSKC Key that holds the PIN (if any)."""
        if self.pin_key_id and self.key and self.key.pskc:
            for key in self.key.pskc.keys:
                if key.id == self.pin_key_id:
                    return key

    @property
    def pin(self):
        """PIN value referenced by PINKeyId if any."""
        key = self.pin_key
        if key:
            return key.secret
