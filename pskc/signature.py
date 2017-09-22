# signature.py - module for handling signed XML files
# coding: utf-8
#
# Copyright (C) 2017 Arthur de Jong
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

"""Module for handling signed PSKC files.

This module defines a Signature class that handles the signature checking,
keys and certificates.
"""


class Signature(object):
    """Class for handling signature checking of the PSKC file.

    Instances of this class provide the following properties:

      is_signed: boolean to indicate whether a signature is present
      algorithm: identifier of the signing algorithm used
      canonicalization_method: identifier of the XML canonicalization used
      digest_algorithm: algorithm used for creating the hash
      issuer: issuer of the certificate
      serial: serial number of the certificate
      certificate: the certificate that is embedded in the signature
    """

    def __init__(self, pskc):
        self.pskc = pskc
        self._algorithm = None
        self.canonicalization_method = None
        self.digest_algorithm = None
        self.issuer = None
        self.serial = None
        self.certificate = None

    @property
    def is_signed(self):
        """Test whether the PSKC file contains a signature (not whether the
        signature is valid)."""
        return bool(
            self.algorithm or self.canonicalization_method or
            self.digest_algorithm or self.issuer or self.certificate)

    @property
    def algorithm(self):
        """Provide the signing algorithm used."""
        if self._algorithm:
            return self._algorithm

    @algorithm.setter
    def algorithm(self, value):
        from pskc.algorithms import normalise_algorithm
        self._algorithm = normalise_algorithm(value)
