# xml.py - module for parsing and writing XML for PSKC files
# coding: utf-8
#
# Copyright (C) 2014-2025 Arthur de Jong
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

from __future__ import absolute_import, annotations

import datetime
import sys
from collections import OrderedDict
from typing import IO, TYPE_CHECKING, cast

if TYPE_CHECKING:  # pragma: no cover (only for mypy)
    from collections.abc import Generator
    from os import PathLike

    from lxml.etree import _Element, _ElementTree


# try to find a usable ElementTree implementation
try:  # pragma: no cover (different implementations)
    from lxml.etree import parse as xml_parse, tostring as xml_tostring
    from lxml.etree import register_namespace, Element, SubElement
except ImportError:  # pragma: no cover (different implementations)
    from xml.etree.ElementTree import (  # type: ignore[no-redef]
        parse as xml_parse, tostring as xml_tostring)
    from xml.etree.ElementTree import register_namespace, Element, SubElement  # type: ignore[no-redef,assignment]
    try:
        from defusedxml.ElementTree import parse as xml_parse  # type: ignore[no-redef]  # noqa: F811
    except ImportError:
        pass


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


def register_namespaces() -> None:
    """Register the namespaces so the correct short names will be used."""
    for ns, namespace in namespaces.items():
        register_namespace(ns, namespace)


register_namespaces()


def parse(
    source: str | bytes | PathLike[str] | PathLike[bytes] | IO[str] | IO[bytes],
) -> _ElementTree[_Element]:
    """Parse the provided file and return an element tree."""
    return xml_parse(sys.stdin if source == '-' else source)


def remove_namespaces(tree: _Element | _ElementTree[_Element]) -> None:
    """Remove namespaces from all elements in the tree."""
    import re
    for elem in tree.iter():
        if isinstance(elem.tag, ''.__class__):  # pragma: no branch
            elem.tag = re.sub(r'^\{[^}]*\}', '', elem.tag)


def findall(tree: _Element | _ElementTree[_Element], *matches: str) -> Generator[_Element]:
    """Find the child elements."""
    for match in matches:
        for element in tree.findall(match, namespaces=namespaces):
            yield element


def find(tree: _Element | _ElementTree[_Element], *matches: str) -> _Element | None:
    """Find a child element that matches any of the patterns (or None)."""
    try:
        return next(findall(tree, *matches))
    except StopIteration:
        pass
    return None


def findtext(tree: _Element | _ElementTree[_Element], *matches: str) -> str | None:
    """Get the text value of an element (or None)."""
    element = find(tree, *matches)
    if element is not None and element.text:
        return element.text.strip()
    return None


def findint(tree: _Element | _ElementTree[_Element], *matches: str) -> int | None:
    """Return an element value as an int (or None)."""
    value = findtext(tree, *matches)
    if value:
        return int(value)
    return None


def findtime(tree: _Element | _ElementTree[_Element], *matches: str) -> datetime.datetime | None:
    """Return an element value as a datetime (or None)."""
    value = findtext(tree, *matches)
    if value:
        import dateutil.parser
        return dateutil.parser.parse(value)
    return None


def findbin(tree: _Element | _ElementTree[_Element], *matches: str) -> bytes | None:
    """Return the binary element value base64 decoded."""
    value = findtext(tree, *matches)
    if value:
        import base64
        return base64.b64decode(value)
    return None


def getint(tree: _Element, attribute: str) -> int | None:
    """Return an attribute value as an integer (or None)."""
    value = tree.get(attribute)
    if value:
        return int(value)
    return None


def getbool(tree: _Element, attribute: str, default: bool | None = None) -> bool | None:
    """Return an attribute value as a boolean (or None)."""
    value = tree.get(attribute)
    if value:
        value = value.lower()
        if value in ('1', 'true'):
            return True
        elif value in ('0', 'false'):
            return False
        else:
            raise ValueError('invalid boolean value: %r' % value)
    return default


def _format(value: datetime.datetime | bool | int | str) -> str:
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


def mk_elem(
    parent: _Element | str | None,
    tag: str | None = None,
    text: str | int | bool | datetime.datetime | None = None,
    empty: bool = False,
    **kwargs: str | int | bool | datetime.datetime | None,
) -> _Element | None:
    """Add element as a child of parent."""
    # special-case the top-level element
    if tag is None:
        tag = cast(str, parent)
        parent = None
        empty = True
    # don't create empty elements
    if not empty and text is None and all(x is None for x in kwargs.values()):
        return None
    # replace namespace identifier with URL
    if ':' in tag:
        ns, name = tag.split(':', 1)
        tag = '{%s}%s' % (namespaces[ns], name)
    if parent is None:
        element: _Element = Element(tag, OrderedDict())
    else:
        element = SubElement(parent, tag, OrderedDict())  # type: ignore[assignment,type-var]
    # set text of element
    if text is not None:
        element.text = _format(text)
    # set kwargs as attributes
    for k, v in kwargs.items():
        if v is not None:
            element.set(k, _format(v))
    return element


def move_namespaces(element: _Element) -> _Element:
    """Move the namespace declarations to the toplevel element."""
    if hasattr(element, 'nsmap'):  # pragma: no cover (only on lxml)
        # get all used namespaces
        nsmap = {}
        for e in element.iter():
            nsmap.update(e.nsmap)
        nsmap = OrderedDict(sorted(nsmap.items()))
        # replace toplevel element with all namespaces
        e = Element(element.tag, attrib=element.attrib, nsmap=nsmap)
        for a in element:
            e.append(a)
        element = e
    return element


def reformat(element: _Element, indent: str = '') -> None:
    """Reformat the XML tree to have nice wrapping and indenting."""
    tag = cast(str, element.tag).split('}')[-1]
    # re-order attributes by alphabet
    attrib = sorted(element.attrib.items())
    element.attrib.clear()
    element.attrib.update(attrib)
    if len(element) == 0:
        # clean up inner text
        if element.text:
            element.text = element.text.strip()
        if tag in ('X509Certificate', 'SignatureValue'):
            element.text = ''.join(x for x in element.text if not x.isspace())  # type: ignore[union-attr]
    elif tag != 'SignedInfo':
        # indent children
        element.text = '\n ' + indent
        childred = list(element)
        for child in childred:
            reformat(child, indent + ' ')
        childred[-1].tail = '\n' + indent
    element.tail = '\n' + indent


def tostring(element: _Element) -> bytes:
    """Return a serialised XML document for the element tree."""
    element = move_namespaces(element)
    reformat(element)
    xml = xml_tostring(element, encoding='UTF-8')
    xml_decl = b"<?xml version='1.0' encoding='UTF-8'?>\n"
    if xml.startswith(xml_decl):  # pragma: no cover (only a few cases)
        xml = xml[len(xml_decl):]
    return (
        b'<?xml version="1.0" encoding="UTF-8"?>\n' +
        xml.replace(b' />', b'/>').strip() + b'\n')
