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

      A URI of the MAC algorithm used for message authentication. See the
      section :ref:`mac-algorithms` below for a list of algorithm URIs.

      Assigned values to this attribute will be converted to the canonical
      URI for the algorithm if it is known. For instance, the value
      ``HMAC-SHA-256`` will automatically be converted into
      ``http://www.w3.org/2001/04/xmldsig-more#hmac-sha256``.

   .. attribute:: key

      For HMAC checking, this contains the binary value of the MAC key. The
      MAC key is generated specifically for each PSKC file and encrypted with
      the PSKC encryption key, so the PSKC file should be decrypted first
      (see :doc:`encryption`).

   .. function:: setup(...)

      Configure an encrypted MAC key for creating a new PSKC file.

      :param str algorithm: encryption algorithm
      :param bytes key: the encryption key to use

      None of the arguments are required. By default HMAC-SHA1 will be used
      as a MAC algorithm. If no key is configured a random key will be
      generated with the length of the output of the configured hash.

      This function will automatically be called when the configured
      encryption algorithm requires a message authentication code.


.. _mac-algorithms:

Supported MAC algorithms
------------------------

The module should support all HMAC algorithms that can be constructed from
hash algorithms that are available in the standard Python :mod:`hashlib`
module. At the least the following algorithms should be supported:

+-----------------------------------------------------------+--------------------------+
| URI                                                       | Description              |
+===========================================================+==========================+
| ``http://www.w3.org/2001/04/xmldsig-more#hmac-md5``       | MD5-based HMAC           |
+-----------------------------------------------------------+--------------------------+
| ``http://www.w3.org/2000/09/xmldsig#hmac-sha1``           | SHA-1 based HMAC         |
+-----------------------------------------------------------+--------------------------+
| ``http://www.w3.org/2001/04/xmldsig-more#hmac-sha224``    | SHA-2 family based HMACs |
| ``http://www.w3.org/2001/04/xmldsig-more#hmac-sha256``    |                          |
| ``http://www.w3.org/2001/04/xmldsig-more#hmac-sha384``    |                          |
| ``http://www.w3.org/2001/04/xmldsig-more#hmac-sha512``    |                          |
+-----------------------------------------------------------+--------------------------+
| ``http://www.w3.org/2001/04/xmldsig-more#hmac-ripemd160`` | RIPEMD-160 based HMAC    |
+-----------------------------------------------------------+--------------------------+
