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
      :type: bool

      A boolan value that indicates whether an XML signature is present in
      the PSKC file. This property does not indicate whether the signature
      is validated.

   .. attribute:: algorithm
      :type: str | None

      A URI of the signing algorithm used.
      Assigned values to this attribute will be converted to the canonical
      URI for the algorithm if it is known.

   .. autoattribute:: canonicalization_method

      A URI that is used to identify the XML canonicalization method used.

   .. autoattribute:: digest_algorithm

      A URI that identifies that hashing algorithm that is used to construct
      the signature.

   .. autoattribute:: issuer

      A distinguished name of the issuer of the certificate that belongs to
      the key that is used for the signature.

   .. autoattribute:: serial

      A serial number of the certificate that belongs to the key that is used
      for the signature.

   .. autoattribute:: key

      A PEM encoded key that will be used to create the signed PSKC file.

   .. autoattribute:: certificate

      A PEM encoded certificate that is embedded inside the signature that
      can be used to validate the signature.

   .. attribute:: signed_pskc
      :type: PSKC

      A :class:`~pskc.PSKC` instance that contains the signed contents of the
      PSKC file. It is usually required to call :func:`verify` before
      accessing this attribute without raising an exception.

   .. automethod:: verify

   .. automethod:: sign
