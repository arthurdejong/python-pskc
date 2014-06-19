Basic usage
===========

The :mod:`pskc` module implements a simple and efficient API for parsing PSKC
files. The :class:`~pskc.PSKC` class is used to access the file as a whole
which provides access to a list of :class:`~pskc.key.Key` instances which
contain most of the useful information from the PSKC file.


Opening a PSKC file
-------------------

.. module:: pskc

Importing data from a PSKC file can be done by instantiating a
:class:`~pskc.PSKC` class::

    >>> from pskc import PSKC
    >>> pskc = PSKC('somefile.pskcxml')
    >>> pskc.version
    '1.0'


.. class:: PSKC([filename])

   The :class:`PSKC` class is used as a wrapper to access information from a
   PSKC file.

   The whole file is parsed in one go. Instances of this class provide the
   following attributes: If parsing the PSKC file fails, a
   :exc:`~pskc.exceptions.ParseError` exception is raised.

   .. attribute:: version

      The PSKC format version used. Only version ``1.0`` is currently
      specified in
      `RFC 6030 <https://tools.ietf.org/html/rfc6030#section-1.2>`__
      and supported.

   .. attribute:: id

      A unique identifier for the container.

   .. attribute:: keys

      A list of :class:`~pskc.key.Key` instances that represent the keys
      within the PSKC file.

   .. attribute:: encryption

      :class:`~pskc.encryption.Encryption` instance that handles PSKC file
      encryption.

   .. attribute:: mac

      :class:`~pskc.mac.MAC` instance that handles integrity checking.


Examining keys
--------------

.. module:: pskc.key

The :attr:`~pskc.PSKC.keys` attribute of a :class:`~pskc.PSKC` instance
provides access to a list of keys contained in the PSKC file. :class:`Key`
instances provide access to a number of attributes that provide information
on the transmitted keys::

    >>> pskc = PSKC('somefile.pskcxml')
    >>> first_key = pskc.keys[0]
    >>> first_key.id
    'some-id'
    >>> first_key.algorithm
    'urn:ietf:params:xml:ns:keyprov:pskc:hotp'
    >>> first_key.secret
    'SOME_SECRET_VALUE'

Attribute values will be ``None`` if it the value is not present in the PSKC
file. If any of the :attr:`~pskc.key.Key.secret`,
:attr:`~pskc.key.Key.counter`, :attr:`~pskc.key.Key.time_offset`,
:attr:`~pskc.key.Key.time_interval` or :attr:`~pskc.key.Key.time_drift`
values are accessed while they are encrypted and decryption is unsuccessful a
:exc:`~pskc.exceptions.DecryptionError` exception is raised.


.. class:: Key()

   .. attribute:: id

      A unique identifier for the key. If there are multiple interactions
      with the same key in multiple instances of PSKC files the `id` is
      supposed to remain the same.

   .. attribute:: algorithm

      A URI that identifies the PSKC algorithm profile. The algorithm profile
      associates specific semantics to the key. Some `known profiles
      <https://www.iana.org/assignments/pskc/#alg-profiles>`__ are:

      * ``urn:ietf:params:xml:ns:keyprov:pskc:pin``:
        `Symmetric static credential comparison <https://tools.ietf.org/html/rfc6030#section-10.2>`_
      * ``urn:ietf:params:xml:ns:keyprov:pskc:hotp``:
        `OATH event-based OTP <https://tools.ietf.org/html/rfc6030#section-10.1>`_
      * ``urn:ietf:params:xml:ns:keyprov:pskc#totp`` or
        ``urn:ietf:params:xml:ns:keyprov:pskc:totp``:
        `OATH time-based OTP <http://tools.ietf.org/html/draft-hoyer-keyprov-pskc-algorithm-profiles-01#section-4>`_
      * ``urn:ietf:params:xml:ns:keyprov:pskc#OCRA-1``:
        `OATH challenge-response algorithm <https://tools.ietf.org/html/draft-hoyer-keyprov-pskc-algorithm-profiles-01#section-3>`_

   .. attribute:: secret

      The binary value of the transported secret key. If the key information
      is encrypted in the PSKC file it is transparently decrypted if
      possible. Accessing the value may raise
      :exc:`~pskc.exceptions.DecryptionError` if decryption fails.

   .. attribute:: counter

      The event counter for event-based OTP algorithms. Will also be
      transparently decrypted and may also raise
      :exc:`~pskc.exceptions.DecryptionError`.

   .. attribute:: time_offset

      The time offset offset for time-based OTP algorithms. If time intervals
      are used it carries the number of time intervals passed from an
      algorithm-dependent start point. Will also be transparently decrypted
      and may also raise :exc:`~pskc.exceptions.DecryptionError`.

   .. attribute:: time_interval

      The time interval in seconds for time-based OTP algorithms (usually
      ``30`` or ``60``). Will also be transparently decrypted and may also
      raise :exc:`~pskc.exceptions.DecryptionError`.

   .. attribute:: time_drift

      For time-based OTP algorithms this contains the device clock drift in
      number of intervals. Will also be transparently decrypted and may also
      raise :exc:`~pskc.exceptions.DecryptionError`.

   .. attribute:: issuer

      The name of the party that issued the key. This may be different from
      the :attr:`manufacturer` of the device.

   .. attribute:: key_profile

      A reference to a pre-shared key profile agreed upon between the sending
      and receiving parties. The profile information itself is not
      transmitted within the container.
      See `RFC 6030 <https://tools.ietf.org/html/rfc6030#section-4.4>`__.

   .. attribute:: key_reference

      A reference to an external key that is not contained within the PSKC
      file (e.g., a PKCS #11 key label). If this attribute is present, the
      :attr:`secret` attribute will generally be missing.

   .. attribute:: friendly_name

      A human-readable name for the secret key.

   .. attribute:: key_userid

      The distinguished name of the user associated with the key.
      Also see :attr:`device_userid`.

   .. attribute:: manufacturer

      The name of the manufacturer of the device to which the key is
      provisioned.
      `RFC 6030 <https://tools.ietf.org/html/rfc6030#section-4.3.1>`__
      prescribes that the value is of the form ``oath.prefix`` for `OATH
      Manufacturer Prefixes <http://www.openauthentication.org/oath-id/prefixes/>`_
      or ``iana.organisation`` for `IANA Private Enterprise Numbers
      <https://www.iana.org/assignments/enterprise-numbers/enterprise-numbers>`_
      however, it is generally just a string. The value may be different from
      the :attr:`issuer` of the key on the device.

   .. attribute:: serial

      The serial number of the device to which the key is provisioned.
      Together with :attr:`manufacturer` (and possibly :attr:`issue_no`) this
      should uniquely identify the device.

   .. attribute:: model

      A manufacturer specific description of the model of the device.

   .. attribute:: issue_no

      The issue number in case there are devices with the same :attr:`serial`
      number so that they can be distinguished by different issue numbers.

   .. attribute:: device_binding

      Reference to a device identifier (e.g. IMEI) that allows a provisioning
      server to ensure that the key is going to be loaded into a specific
      device.

   .. attribute:: start_date

      :class:`datetime.datetime` value that indicates that the device should
      only be used after this date.

   .. attribute:: expiry_date

      :class:`datetime.datetime` value that indicates that the device should
      only be used before this date. Systems should not rely upon the device
      to enforce key usage date restrictions, as some devices do not have an
      internal clock.

   .. attribute:: device_userid

      The distinguished name of the user associated with the device.
      Also see :attr:`key_userid`.

   .. attribute:: crypto_module

      Implementation specific unique identifier of the cryptographic module
      on the device to which the keys have been (or will be) provisioned.

   .. attribute:: algorithm_suite

      Additional algorithm specific characteristics. For example, in an
      HMAC-based algorithm it could designate the hash algorithm used (SHA1
      or SHA256).

   .. attribute:: challenge_encoding

      Encoding of the challenge accepted by the device for challenge-response
      authentication. One of:

      * ``DECIMAL``: only numerical digits
      * ``HEXADECIMAL``: hexadecimal
      * ``ALPHANUMERIC``: all letters and numbers (case sensitive)
      * ``BASE64``: base-64 encoded
      * ``BINARY``: binary data

   .. attribute:: challenge_min_length

      The minimum size of the challenge accepted by the device.

   .. attribute:: challenge_max_length

      The maximum size of the challenge accepted by the device.

   .. attribute:: challenge_check

      Boolean that indicates whether the device will check an embedded
      `Luhn check digit <http://arthurdejong.org/python-stdnum/doc/0.9/stdnum.luhn.html>`_
      contained in the challenge.

   .. attribute:: response_encoding

      Format of the response that is generated by the device. If must be one
      of the values as described under :attr:`challenge_encoding`.

   .. attribute:: response_length

      The length of the response generated by the device.

   .. attribute:: response_check

      Boolean that indicates whether the device will append a
      `Luhn check digit <http://arthurdejong.org/python-stdnum/doc/0.9/stdnum.luhn.html>`_
      to the response.

   .. attribute:: policy

      :class:`~pskc.policy.Policy` instance that provides key and PIN policy
      information. See :doc:`policy`.

   .. function:: check()

      Check if any MACs in the key data embedded in the PSKC file are valid.
      This will return None if there is no MAC to be checked. It will return
      True if all the MACs match. If any MAC fails a
      :exc:`~pskc.exceptions.DecryptionError` exception is raised.
