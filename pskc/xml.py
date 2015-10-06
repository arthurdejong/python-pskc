# xml.py - module for parsing and writing XML for PSKC files
# coding: utf-8
#
# Copyright (C) 2014-2015 Arthur de Jong
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

"""Module for parsing XML in PSKC files.

This module provides some utility functions for parsing XML files.
"""

from __future__ import absolute_import

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


# register the namespaces so the correct short names will be used
for ns, namespace in namespaces.items():
    etree.register_namespace(ns, namespace)


def parse(source):
    """Parse the provided file and return an element tree."""
    return etree.parse(source)


def findall(tree, match):
    """Find the child elements."""
    return tree.findall(match, namespaces=namespaces)


def find(tree, *matches):
    """Find a child element that matches any of the patterns (or None)."""
    for match in matches:
        try:
            return next(iter(findall(tree, match)))
        except StopIteration:
            pass


def findtext(tree, *matches):
    """Get the text value of an element (or None)."""
    element = find(tree, *matches)
    if element is not None:
        return element.text.strip()


def findint(tree, *matches):
    """Return an element value as an int (or None)."""
    value = findtext(tree, *matches)
    if value:
        return int(value)


def findtime(tree, *matches):
    """Return an element value as a datetime (or None)."""
    value = findtext(tree, *matches)
    if value:
        import dateutil.parser
        return dateutil.parser.parse(value)


def findbin(tree, *matches):
    """Return the binary element value base64 decoded."""
    value = findtext(tree, *matches)
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


def _format(value):
    import datetime
    if isinstance(value, datetime.datetime):
        value = value.isoformat()
        if value.endswith('+00:00'):
            value = value[:-6] + 'Z'
        return value
    elif value is True:
        return 'true'
    elif value is False:
        return 'false'
    return str(value)


def mk_elem(parent, tag=None, text=None, empty=False, **kwargs):
    """Add element as a child of parent."""
    # special-case the top-level element
    if tag is None:
        tag = parent
        parent = None
        empty = True
    # don't create empty elements
    if not empty and text is None and \
       all(x is None for x in kwargs.values()):
        return
    # replace namespace identifier with URL
    if ':' in tag:
        ns, name = tag.split(':', 1)
        tag = '{%s}%s' % (namespaces[ns], name)
    if parent is None:
        element = etree.Element(tag)
    else:
        element = etree.SubElement(parent, tag)
    # set text of element
    if text is not None:
        element.text = _format(text)
    # set kwargs as attributes
    for k, v in kwargs.items():
        if v is not None:
            element.set(k, _format(v))
    return element


def tostring(element):
    """Return a serialised XML document for the element tree."""
    from xml.dom import minidom
    xml = etree.tostring(element, encoding='UTF-8')
    return minidom.parseString(xml).toprettyxml(
        indent=' ', encoding='UTF-8').strip()
