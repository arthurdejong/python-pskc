# signature.py - module for handling signed XML files
# coding: utf-8
#
# Copyright (C) 2017-2025 Arthur de Jong
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

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover (only for mypy)
    from lxml.etree import _Element, _ElementTree

    from pskc import PSKC


def sign_x509(
    xml: _Element,
    key: bytes,
    certificate: str,
    algorithm: str | None = None,
    digest_algorithm: str | None = None,
    canonicalization_method: str | None = None,
) -> _Element:
    """Sign PSKC data using X.509 certificate and private key.

    xml: an XML document
    key: the private key in binary format
    certificate: the X.509 certificate
    """
    from signxml import XMLSigner, XMLSignatureProcessor, methods  # type: ignore[attr-defined]
    algorithm = algorithm or 'rsa-sha256'
    digest_algorithm = digest_algorithm or 'sha256'
    canonicalization_method = (
        canonicalization_method or
        getattr(XMLSignatureProcessor, 'default_c14n_algorithm', None) or
        'http://www.w3.org/2006/12/xml-c14n11')
    return XMLSigner(
        method=methods.enveloped,
        signature_algorithm=algorithm.rsplit('#', 1)[-1].lower(),
        digest_algorithm=digest_algorithm.rsplit('#', 1)[-1].lower(),
        c14n_algorithm=canonicalization_method,
    ).sign(xml, key=key, cert=certificate)


def verify_x509(tree: _Element, certificate: str | None = None, ca_pem_file: str | None = None) -> _Element:
    """Verify signature in PSKC data against a trusted X.509 certificate.

    :param certificate: a PEM encoded certificate that is used for verification
    :param ca_pem_file: the name of a file that contains a CA certificate

    The signature can be verified in three ways:

    * The signature has an embedded certificate that is signed by a CA that is
      configured in the system CA store. In this case neither `certificate` or
      `ca_pem_file` need to be specified
    * The signature was made  and a certificate was transmitted out-of-band.
      In this case the `certificate` argument needs to be present.
    * The signature has a certificate that is signed by a specific CA who's
      certificate was transmitted out-of-band. In this case the `ca_pem_file`
      is used to point to a CA certificate file (but a certificate needs to be
      embedded inside the PSKC file).

    This function will raise an exception when the validation fails.

    After calling this function a verified version of the PSKC file will
    be present in the :attr:`signed_pskc` attribute.
    """
    from signxml import XMLVerifier  # type: ignore[attr-defined]
    return XMLVerifier().verify(  # type: ignore[union-attr,return-value]
        tree, x509_cert=certificate,
        ca_pem_file=ca_pem_file,
    ).signed_xml


class Signature:
    """Class for handling signature checking of the PSKC file.

    Instances of this class provide the following properties:

      is_signed: boolean to indicate whether a signature is present
      algorithm: identifier of the signing algorithm used
      canonicalization_method: identifier of the XML canonicalization used
      digest_algorithm: algorithm used for creating the hash
      issuer: issuer of the certificate
      serial: serial number of the certificate
      key: key that will be used when creating a signed PSKC file
      certificate: the certificate that is embedded in the signature
      signed_pskc: a PSKC instance with the signed information
    """

    def __init__(self, pskc: PSKC) -> None:
        self.pskc = pskc
        self._algorithm: str | None = None
        self.canonicalization_method: str | None = None
        self.digest_algorithm: str | None = None
        self.issuer: str | None = None
        self.serial: str | None = None
        self.key: bytes | None = None
        self.certificate: str | None = None

    @property
    def is_signed(self) -> bool:
        """Test whether the PSKC file contains a signature.

        This method does not check whether the signature is valid but only if
        one was present in the PSKC file.
        """
        return bool(
            self.algorithm or self.canonicalization_method or
            self.digest_algorithm or self.issuer or self.certificate)

    @property
    def algorithm(self) -> str | None:
        """Provide the signing algorithm used."""
        if self._algorithm:
            return self._algorithm
        return None

    @algorithm.setter
    def algorithm(self, value: str | None) -> None:
        from pskc.algorithms import normalise_algorithm
        self._algorithm = normalise_algorithm(value)

    @property
    def signed_pskc(self) -> PSKC:
        """Provide the signed PSKC information."""
        if not hasattr(self, '_signed_pskc'):
            self.verify()
        return self._signed_pskc

    def verify(self, certificate: str | None = None, ca_pem_file: str | None = None) -> bool:
        """Verify signature in PSKC data against a trusted X.509 certificate.

        The signature can be verified in three ways:

        * The signature has an embedded certificate that is signed by a CA that is
          configured in the system CA store. In this case neither `certificate` or
          `ca_pem_file` need to be specified
        * The signature was made  and a certificate was transmitted out-of-band.
          In this case the `certificate` argument needs to be present.
        * The signature has a certificate that is signed by a specific CA who's
          certificate was transmitted out-of-band. In this case the `ca_pem_file`
          is used to point to a CA certificate file (but a certificate needs to be
          embedded inside the PSKC file).

        This function will raise an exception when the validation fails. The `certificate`
        is expected to be passed as a PEM encoded string. The `ca_pem_file` should point to a CA
        certificate store (PEM encoded file).

        After calling this function a verified version of the PSKC file will
        be present in the :attr:`signed_pskc` attribute.
        """
        from pskc import PSKC
        from pskc.parser import PSKCParser
        self.tree: _Element | _ElementTree[_Element]
        signed_xml = verify_x509(self.tree, certificate, ca_pem_file)
        pskc = PSKC()
        PSKCParser.parse_document(pskc, signed_xml)
        self._signed_pskc = pskc
        return True

    def sign(self, key: bytes, certificate: str | None = None) -> None:
        """Add an XML signature to the file.

        Set up a key and optionally a certificate that will be used to create an
        embedded XML signature when writing the file.

        This is a utility function that is used to configure the properties
        needed to create a signed PSKC file.
        """
        self.key = key
        self.certificate = certificate

    def sign_xml(self, xml: _Element) -> _Element:
        """Sign an XML document with the configured key and certificate."""
        assert self.key
        assert self.certificate
        return sign_x509(
            xml, self.key, self.certificate, self.algorithm,
            self.digest_algorithm, self.canonicalization_method)
