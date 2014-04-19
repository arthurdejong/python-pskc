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

This module provides the PSKC class and some utility functions for parsing
PSKC files.
"""


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


def g_e_v(tree, match):
    """Get the text value of an element (or None)."""
    element = tree.find(match, namespaces=namespaces)
    if element is not None:
        return element.text.strip()


def g_e_i(tree, match):
    """Return an element value as an int (or None)."""
    element = tree.find(match, namespaces=namespaces)
    if element is not None:
        return int(element.text.strip())


def g_e_d(tree, match):
    """Return an element value as a datetime (or None)."""
    element = tree.find(match, namespaces=namespaces)
    if element is not None:
        import dateutil.parser
        return dateutil.parser.parse(element.text.strip())
