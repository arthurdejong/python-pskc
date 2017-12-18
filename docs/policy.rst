Key usage policy
================

.. module:: pskc.policy

The PSKC format allows for specifying `key and pin usage policy <https://tools.ietf.org/html/rfc6030#section-5>`__
per key.

Instances of the :class:`Policy` class provide attributes that describe
limits that are placed on key usage and requirements for key PIN protection::

   >>> key = pskc.keys[0]
   >>> key.policy.may_use(key.policy.KEY_USE_OTP)
   True


The Policy class
----------------

.. class:: Policy

   .. attribute:: start_date

      :class:`datetime.datetime` value that indicates that the key must not
      be used before this date.

   .. attribute:: expiry_date

      :class:`datetime.datetime` value that indicates that the key must not
      be used after this date. Systems should not rely upon the device to
      enforce key usage date restrictions, as some devices do not have an
      internal clock.

   .. attribute:: number_of_transactions

      The value indicates the maximum number of times a key carried within
      the PSKC document may be used by an application after having received
      it.

   .. attribute:: key_usage

      A list of `valid usage scenarios
      <https://www.iana.org/assignments/pskc/#key-usage>`__ for the
      key that the recipient should check against the intended usage of the
      key. Also see :func:`may_use` and :ref:`key-use-constants` below.

   .. attribute:: pin_key_id

      The unique `id` of the key within the PSKC file that contains the value
      of the PIN that protects this key.

   .. attribute:: pin_key

      Instance of the :class:`~pskc.key.Key` (if any) that contains the value
      of the PIN referenced by :attr:`pin_key_id`.

   .. attribute:: pin

      PIN value referenced by :attr:`pin_key_id` (if any). The value is
      transparently decrypted if possible.

   .. attribute:: pin_usage

      Describe how the PIN is used during the usage of the key. See
      :ref:`pin-use-constants` below.

   .. attribute:: pin_max_failed_attempts

      The maximum number of times the PIN may be entered wrongly before it
      MUST NOT be possible to use the key any more.

   .. attribute:: pin_min_length

      The minimum length of a PIN that can be set to protect the associated
      key.

   .. attribute:: pin_max_length

      The maximum length of a PIN that can be set to protect this key.

   .. attribute:: pin_encoding

      The encoding of the PIN which is one of ``DECIMAL``, ``HEXADECIMAL``,
      ``ALPHANUMERIC``, ``BASE64``, or ``BINARY`` (see
      :attr:`~pskc.key.Key.challenge_encoding`).

   .. attribute:: unknown_policy_elements

      Boolean that is set to ``True`` if the PSKC policy information contains
      unknown or unsupported definitions or values. A conforming
      implementation must assume that key usage is not permitted if this
      value is ``True`` to ensure that the lack of understanding of certain
      extensions does not lead to unintended key usage.

   .. function:: may_use(usage=None, now=None)

      Check whether the key may be used for the provided purpose. The key
      :attr:`start_date` and :attr:`expiry_date` are also checked. The `now`
      argument can be used to specify another point in time to check against.

.. _key-use-constants:

Key usage constants
-------------------

The :class:`Policy` class provides the following key use constants (see
:attr:`~Policy.key_usage` and :func:`~Policy.may_use`):

   .. autoattribute:: Policy.KEY_USE_OTP

      Key is used for OTP generation.

   .. autoattribute:: Policy.KEY_USE_CR

      The key is used for challenge-response purposes.

   .. autoattribute:: Policy.KEY_USE_ENCRYPT

      The key is used for data encryption purposes.

   .. autoattribute:: Policy.KEY_USE_INTEGRITY

      The key is used to generate a keyed message digest for data integrity or
      authentication purposes.

   .. autoattribute:: Policy.KEY_USE_VERIFY

      The key is used to verify a keyed message digest for data integrity or
      authentication purposes (this is the opposite of
      :attr:`KEY_USE_INTEGRITY`).

   .. autoattribute:: Policy.KEY_USE_UNLOCK

      The key is used for an inverse challenge-response in the case where a
      user has locked the device by entering a wrong PIN too many times (for
      devices with PIN-input capability).

   .. autoattribute:: Policy.KEY_USE_DECRYPT

      The key is used for data decryption purposes.

   .. autoattribute:: Policy.KEY_USE_KEYWRAP

      The key is used for key wrap purposes.

   .. autoattribute:: Policy.KEY_USE_UNWRAP

      The key is used for key unwrap purposes.

   .. autoattribute:: Policy.KEY_USE_DERIVE

      The key is used with a key derivation function to derive a new key.

   .. autoattribute:: Policy.KEY_USE_GENERATE

      The key is used to generate a new key based on a random number and the
      previous value of the key.


.. _pin-use-constants:

Pin usage constants
-------------------

The following constants for PIN use are defined  in the :class:`Policy`
class (see :attr:`~Policy.pin_usage`):

   .. autoattribute:: Policy.PIN_USE_LOCAL

      The PIN is checked locally on the device before allowing the key to be
      used in executing the algorithm.

   .. autoattribute:: Policy.PIN_USE_PREPEND

      The PIN is prepended to the algorithm response. It must be checked by
      the party validating the response.

   .. autoattribute:: Policy.PIN_USE_APPEND

      The PIN is appended to the algorithm response. It must be checked by
      the party validating the response.

   .. autoattribute:: Policy.PIN_USE_ALGORITHMIC

      The PIN is used as part of the algorithm computation.
