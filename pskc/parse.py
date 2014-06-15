# parse.py - module for reading PSKC files
# coding: utf-8
#
# Copyright (C) 2014 Arthur de Jong
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

"""Module for parsing PSKC files.

This module provides some utility functions for parsing PSKC files.
"""

# try to find a usable ElementTree module
try:
    from lxml import etree
except ImportError:  # pragma: no cover (different implementations)
    import xml.etree.ElementTree as etree


# the relevant XML namespaces for PSKC
namespaces = dict(
    # the XML namespace URI for version 1.0 of PSKC
    pskc='urn:ietf:params:xml:ns:keyprov:pskc',
    # the XML Signature namespace
    ds='http://www.w3.org/2000/09/xmldsig#',
    # the XML Encryption namespace
    xenc='http://www.w3.org/2001/04/xmlenc#',
    # the XML Encryption version 1.1 namespace
    xenc11='http://www.w3.org/2009/xmlenc11#',
    # the PKCS #5 namespace
    pkcs5='http://www.rsasecurity.com/rsalabs/pkcs/schemas/pkcs-5v2-0#',
)


def findall(tree, match):
    """Find a child element (or None)."""
    return tree.findall(match, namespaces=namespaces)


def find(tree, match):
    """Find a child element (or None)."""
    try:
        return iter(findall(tree, match)).next()
    except StopIteration:
        return None


def findtext(tree, match):
    """Get the text value of an element (or None)."""
    element = find(tree, match)
    if element is not None:
        return element.text.strip()


def findint(tree, match):
    """Return an element value as an int (or None)."""
    value = findtext(tree, match)
    if value:
        return int(value)


def findtime(tree, match):
    """Return an element value as a datetime (or None)."""
    value = findtext(tree, match)
    if value:
        import dateutil.parser
        return dateutil.parser.parse(value)


def findbin(tree, match):
    """Return the binary element value base64 decoded."""
    value = findtext(tree, match)
    if value:
        import base64
        return base64.b64decode(value)


def getint(tree, attribute):
    """Return an attribute value as an integer (or None)."""
    value = tree.get(attribute)
    if value:
        return int(value)


def getbool(tree, attribute):
    """Return an attribute value as a boolean (or None)."""
    value = tree.get(attribute)
    if value:
        return value.lower() == 'true'
