# signature.py - module for handling signed XML files
# coding: utf-8
#
# Copyright (C) 2017-2018 Arthur de Jong
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


def sign_x509(xml, key, certificate, algorithm=None, digest_algorithm=None,
              canonicalization_method=None):
    """Sign PSKC data using X.509 certificate and private key.

    xml: an XML document
    key: the private key in binary format
    certificate: the X.509 certificate
    """
    import signxml
    algorithm = algorithm or 'rsa-sha256'
    digest_algorithm = digest_algorithm or 'sha256'
    canonicalization_method = (
        canonicalization_method or
        signxml.XMLSignatureProcessor.default_c14n_algorithm)
    return signxml.XMLSigner(
        method=signxml.methods.enveloped,
        signature_algorithm=algorithm.rsplit('#', 1)[-1].lower(),
        digest_algorithm=digest_algorithm.rsplit('#', 1)[-1].lower(),
        c14n_algorithm=canonicalization_method,
    ).sign(xml, key=key, cert=certificate)


def verify_x509(tree, certificate=None, ca_pem_file=None):
    """Verify signature in PSKC data against a trusted X.509 certificate.

    If a certificate is supplied it is used to validate the signature,
    otherwise any embedded certificate is used and validated against a
    certificate in ca_pem_file if it specified and otherwise the operating
    system CA certificates.
    """
    from signxml import XMLVerifier
    return XMLVerifier().verify(
        tree, x509_cert=certificate, ca_pem_file=ca_pem_file).signed_xml


class Signature(object):
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

    def __init__(self, pskc):
        self.pskc = pskc
        self._algorithm = None
        self.canonicalization_method = None
        self.digest_algorithm = None
        self.issuer = None
        self.serial = None
        self.key = None
        self.certificate = None

    @property
    def is_signed(self):
        """Test whether the PSKC file contains a signature.

        This method does not check whether the signature is valid but only if
        one was present in the PSKC file.
        """
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

    @property
    def signed_pskc(self):
        """Provide the signed PSKC information."""
        if not hasattr(self, '_signed_pskc'):
            self.verify()
        return self._signed_pskc

    def verify(self, certificate=None, ca_pem_file=None):
        """Check that the signature was made with the specified certificate.

        If no certificate is provided the signature is expected to contain a
        signature that is signed by the CA certificate (or the CA standard CA
        certificates when ca_pem_file is absent).
        """
        from pskc import PSKC
        from pskc.parser import PSKCParser
        signed_xml = verify_x509(self.tree, certificate, ca_pem_file)
        pskc = PSKC()
        PSKCParser.parse_document(pskc, signed_xml)
        self._signed_pskc = pskc
        return True

    def sign(self, key, certificate=None):
        """Add an XML signature to the file."""
        self.key = key
        self.certificate = certificate

    def sign_xml(self, xml):
        """Sign an XML document with the configured key and certificate."""
        return sign_x509(
            xml, self.key, self.certificate, self.algorithm,
            self.digest_algorithm, self.canonicalization_method)
