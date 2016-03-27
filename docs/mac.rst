Integrity checking
==================

.. module:: pskc.mac

The PSKC format allows for `message authentication and integrity checking
<https://tools.ietf.org/html/rfc6030#section-6.1.1>`_ for some of the values
stored within the PSKC file.

Integrity checking is done transparently when accessing attributes that
are encrypted and contain a ValueMAC.

Once the PSKC encryption key has been set up, key values can be explicitly
checked using the :func:`~pskc.key.Key.check` method::

   >>> pskc = PSKC('somefile.pskcxml')
   >>> pskc.encryption.derive_key('qwerty')
   >>> pskc.mac.algorithm
   'http://www.w3.org/2000/09/xmldsig#hmac-sha1'
   >>> all(key.check() for key in pskc.keys)
   True


The MAC class
-------------

.. class:: MAC

   .. attribute:: algorithm

      The name of the MAC algorithm to use (currently ``HMAC-MD5``,
      ``HMAC-SHA1``, ``HMAC-SHA224``, ``HMAC-SHA256``, ``HMAC-SHA384`` and
      ``HMAC-SHA512`` are supported).

   .. attribute:: key

      For HMAC checking, this contains the binary value of the MAC key. The
      MAC key is generated specifically for each PSKC file and encrypted with
      the PSKC encryption key, so the PSKC file should be decrypted first
      (see :doc:`encryption`).

   .. function:: setup(...)

      Configure an encrypted MAC key.

      :param str algorithm: encryption algorithm
      :param binary key: the encryption key to use

      None of the arguments are required. By default HMAC-SHA1 will be used
      as a MAC algorithm. If no key is configured a random key will be
      generated with the length of the output of the configured hash.
