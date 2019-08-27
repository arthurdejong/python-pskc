XML Signature checking
======================

.. module:: pskc.signature

PSKC files can contain embedded XML signatures that allow integrity and
authenticity checks of the transmitted information. This signature typically
covers the whole PSKC file while MAC checking only covers the encrypted
parts.

   >>> pskc = PSKC('somefile.pskcxml')
   >>> pskc.signature.verify()
   >>> pskc = pskc.signature.signed_pskc

When using XML signatures it is important to use the
:attr:`~pskc.signature.Signature.signed_pskc` attribute after verification
because that :class:`~pskc.PSKC` instance will only contain the signed
information.


To create a signed PSKC file build up a :class:`~pskc.PSKC` instance as
usual, configure the signature and save it:

   >>> pskc.signature.sign(key, certificate)
   >>> pskc.write('output.pskcxml')


The Signature class
--------------------

.. class:: Signature

   .. attribute:: is_signed

      A boolan value that indicates whether an XML signature is present in
      the PSKC file. This property does not indicate whether the signature
      is validated.

   .. attribute:: algorithm

      A URI of the signing algorithm used.
      Assigned values to this attribute will be converted to the canonical
      URI for the algorithm if it is known.

   .. attribute:: canonicalization_method

      A URI that is used to identify the XML canonicalization method used.

   .. attribute:: digest_algorithm

      A URI that identifies that hashing algorithm that is used to construct
      the signature.

   .. attribute:: issuer

      A distinguished name of the issuer of the certificate that belongs to
      the key that is used for the signature.

   .. attribute:: serial

      A serial number of the certificate that belongs to the key that is used
      for the signature.

   .. attribute:: key

      A PEM encoded key that will be used to create the signed PSKC file.

   .. attribute:: certificate

      A PEM encoded certificate that is embedded inside the signature that
      can be used to validate the signature.

   .. attribute:: signed_pskc

      A :class:`~pskc.PSKC` instance that contains the signed contents of the
      PSKC file. It is usually required to call :func:`verify` before
      accessing this attribute without raising an exception.

   .. function:: verify(certificate=None, ca_pem_file=None)

      Verify the validity of the embedded XML signature. This function will
      raise an exception when the validation fails.

      :param bytes certificate: a PEM encoded certificate that is used for verification
      :param str ca_pem_file: the name of a file that contains a CA certificate

      The signature can be verified in three ways:

      * The signature was made with a key that has a certificate that is
        signed by a CA that is configured in the system CA store. In this
        case neither `certificate` or `ca_pem_file` need to be specified (but
        a certificate needs to be embedded inside the PSKC file).
      * The signature was made with a key and a certificate for the key was
        transmitted out-of-band. In this case the `certificate` argument
        needs to be present.
      * The signature was made with a key and has a certificate that is
        signed by a specific CA who's certificate was transmitted
        out-of-band. In this case the `ca_pem_file` is used to point to a CA
        certificate file (but a certificate needs to be embedded inside the
        PSKC file).

      After calling this function a verified version of the PSKC file will
      be present in the :attr:`signed_pskc` attribute.

   .. function:: sign(key, certificate=None)

      Set up a key and optionally a certificate that will be used to create an
      embedded XML signature when writing the file.

      :param bytes key: PEM encoded key used for signing
      :param bytes certificate: PEM encoded certificate that will be embedded

      This is a utility function that is used to configure the properties
      needed to create a signed PSKC file.
