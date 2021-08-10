# algorithms.py - module for handling algorithm URIs
# coding: utf-8
#
# Copyright (C) 2016-2017 Arthur de Jong
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

"""Utility module that handles algorithm URIs."""


# canonical URIs of known algorithms
# Note that even if a URI is listed here it does not mean that
# the algorithm is supported in python-pskc.
_algorithms = dict((x.rsplit('#', 1)[-1], x) for x in [
    'http://www.w3.org/2001/04/xmlenc#tripledes-cbc',
    'http://www.w3.org/2001/04/xmlenc#kw-tripledes',
    'http://www.w3.org/2001/04/xmlenc#arcfour',
    'http://www.w3.org/2001/04/xmlenc#aes128-cbc',
    'http://www.w3.org/2001/04/xmlenc#aes192-cbc',
    'http://www.w3.org/2001/04/xmlenc#aes256-cbc',
    'http://www.w3.org/2001/04/xmlenc#kw-aes128',
    'http://www.w3.org/2001/04/xmlenc#kw-aes192',
    'http://www.w3.org/2001/04/xmlenc#kw-aes256',
    'http://www.w3.org/2009/xmlenc11#aes128-gcm',
    'http://www.w3.org/2009/xmlenc11#aes192-gcm',
    'http://www.w3.org/2009/xmlenc11#aes256-gcm',
    'http://www.w3.org/2009/xmlenc11#kw-aes-128-pad',
    'http://www.w3.org/2009/xmlenc11#kw-aes-192-pad',
    'http://www.w3.org/2009/xmlenc11#kw-aes-256-pad',
    'http://www.w3.org/2001/04/xmldsig-more#camellia128-cbc',
    'http://www.w3.org/2001/04/xmldsig-more#camellia192-cbc',
    'http://www.w3.org/2001/04/xmldsig-more#camellia256-cbc',
    'http://www.w3.org/2001/04/xmldsig-more#kw-camellia128',
    'http://www.w3.org/2001/04/xmldsig-more#kw-camellia192',
    'http://www.w3.org/2001/04/xmldsig-more#kw-camellia256',
    'http://www.w3.org/2007/05/xmldsig-more#seed128-cbc'
    'http://www.w3.org/2007/05/xmldsig-more#kw-seed128',
    'http://www.w3.org/2001/04/xmldsig-more#hmac-md5',
    'http://www.w3.org/2000/09/xmldsig#hmac-sha1',
    'http://www.w3.org/2001/04/xmldsig-more#hmac-sha224',
    'http://www.w3.org/2001/04/xmldsig-more#hmac-sha256',
    'http://www.w3.org/2001/04/xmldsig-more#hmac-sha384',
    'http://www.w3.org/2001/04/xmldsig-more#hmac-sha512',
    'http://www.w3.org/2001/04/xmldsig-more#hmac-ripemd160',
    'http://www.rsasecurity.com/rsalabs/pkcs/schemas/pkcs-5v2-0#pbkdf2',
    # a newer URI seems to be http://www.w3.org/2009/xmlenc11#pbkdf2
])


# translation table to change old encryption names to new names
_algorithm_aliases = {
    '3des-cbc': 'tripledes-cbc',
    '3des112-cbc': 'tripledes-cbc',
    '3des168-cbc': 'tripledes-cbc',
    'rc4': 'arcfour',
    'kw-aes128-pad': 'kw-aes-128-pad',
    'kw-aes192-pad': 'kw-aes-192-pad',
    'kw-aes256-pad': 'kw-aes-256-pad',
    'camellia128': 'camellia128-cbc',
    'camellia192': 'camellia192-cbc',
    'camellia256': 'camellia256-cbc',
    'hmac-sha-1': 'hmac-sha1',
    'hmac-sha-224': 'hmac-sha224',
    'hmac-sha-256': 'hmac-sha256',
    'hmac-sha-384': 'hmac-sha384',
    'hmac-sha-512': 'hmac-sha512',
    'hmac-ripemd-160': 'hmac-ripemd160',
    'kw-3des': 'kw-tripledes',
    'pbe-3des112-cbc': 'tripledes-cbc',
    'pbe-3des168-cbc': 'tripledes-cbc',
    'pbe-aes128-cbc': 'aes128-cbc',
    'pbe-aes192-cbc': 'aes192-cbc',
    'pbe-aes256-cbc': 'aes256-cbc',
    'rsa-1_5': 'rsa-1_5',
    'rsa-oaep-mgf1p': 'rsa-oaep-mgf1p',
}


def normalise_algorithm(algorithm):
    """Return the canonical URI for the provided algorithm."""
    if not algorithm or algorithm.lower() == 'none':
        return None
    algorithm = _algorithm_aliases.get(algorithm.lower(), algorithm)
    return _algorithms.get(algorithm.rsplit('#', 1)[-1].lower(), algorithm)
