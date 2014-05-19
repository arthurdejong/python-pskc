Integrity checking
==================

.. module:: pskc.mac

The PSKC format allows for `message authentication and integrity checking
<https://tools.ietf.org/html/rfc6030#section-6.1.1>`_ for some of the values
stored within the PSKC file.

.. class:: MAC

   .. attribute:: algorithm

      The name of the MAC algorithm to use (currently only ``HMAC_SHA1`` is
      supported).

   .. attribute:: key

      For HMAC checking, this contains the binary value of the MAC key. The
      MAC key is generated specifically for each PSKC file and encrypted with
      the PSKC encryption key, so the PSKC file should be decrypted first
      (see :doc:`encryption`).

Once the PSKC encryption key has been set up key values can be checked using
the :func:`pskc.key.Key.check` method::

   pskc = PSKC('somefile.pskcxml')
   pskc.encryption.derive_key('qwerty')
   all(key.check() for key in pskc.keys)
