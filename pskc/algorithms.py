# algorithms.py - module for handling algorithm URIs
# coding: utf-8
#
# Copyright (C) 2016 Arthur de Jong
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

"""Utility module that handles algorthm URIs."""


# cannonical URIs of known algorithms
_algorithms = {
    'tripledes-cbc': 'http://www.w3.org/2001/04/xmlenc#tripledes-cbc',
    'kw-tripledes': 'http://www.w3.org/2001/04/xmlenc#kw-tripledes',
    'aes128-cbc': 'http://www.w3.org/2001/04/xmlenc#aes128-cbc',
    'aes192-cbc': 'http://www.w3.org/2001/04/xmlenc#aes192-cbc',
    'aes256-cbc': 'http://www.w3.org/2001/04/xmlenc#aes256-cbc',
    'kw-aes128': 'http://www.w3.org/2001/04/xmlenc#kw-aes128',
    'kw-aes192': 'http://www.w3.org/2001/04/xmlenc#kw-aes192',
    'kw-aes256': 'http://www.w3.org/2001/04/xmlenc#kw-aes256',
    'camellia128': 'http://www.w3.org/2001/04/xmldsig-more#camellia128',
    'camellia192': 'http://www.w3.org/2001/04/xmldsig-more#camellia192',
    'camellia256': 'http://www.w3.org/2001/04/xmldsig-more#camellia256',
    'kw-camellia128': 'http://www.w3.org/2001/04/xmldsig-more#kw-camellia128',
    'kw-camellia192': 'http://www.w3.org/2001/04/xmldsig-more#kw-camellia192',
    'kw-camellia256': 'http://www.w3.org/2001/04/xmldsig-more#kw-camellia256',
    'hmac-md5': 'http://www.w3.org/2001/04/xmldsig-more#hmac-md5',
    'hmac-sha1': 'http://www.w3.org/2000/09/xmldsig#hmac-sha1',
    'hmac-sha224': 'http://www.w3.org/2001/04/xmldsig-more#hmac-sha224',
    'hmac-sha256': 'http://www.w3.org/2001/04/xmldsig-more#hmac-sha256',
    'hmac-sha384': 'http://www.w3.org/2001/04/xmldsig-more#hmac-sha384',
    'hmac-sha512': 'http://www.w3.org/2001/04/xmldsig-more#hmac-sha512',
    'hmac-ripemd160': 'http://www.w3.org/2001/04/xmldsig-more#hmac-ripemd160',
    'pbkdf2': 'http://www.rsasecurity.com/rsalabs/pkcs/schemas/' +
              'pkcs-5v2-0#pbkdf2',
}

# translation table to change old encryption names to new names
_algorithm_aliases = {
    '3des-cbc': 'tripledes-cbc',
    '3des112-cbc': 'tripledes-cbc',
    '3des168-cbc': 'tripledes-cbc',
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
