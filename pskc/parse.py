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

from xml.etree import ElementTree
import base64


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


def g_e_v(element, match):
    value = element.find(match, namespaces=namespaces)
    if value is not None:
        return value.text.strip()


class Key(object):

    def __init__(self, key_package):

        self.manufacturer = g_e_v(key_package, 'pskc:DeviceInfo/pskc:Manufacturer')
        self.serial = g_e_v(key_package, 'pskc:DeviceInfo/pskc:SerialNo')
        self.model = g_e_v(key_package, 'pskc:DeviceInfo/pskc:Model')
        self.issue_no = g_e_v(key_package, 'pskc:DeviceInfo/pskc:IssueNo')
        self.device_binding = g_e_v(key_package, 'pskc:DeviceInfo/pskc:DeviceBinding')
        self.start_date = g_e_v(key_package, 'pskc:DeviceInfo/pskc:StartDate')
        # TODO: handle <StartDate> as datetime
        self.expiry_date = g_e_v(key_package, 'pskc:DeviceInfo/pskc:ExpiryDate')
        # TODO: handle <ExpiryDate> as datetime
        self.device_userid = g_e_v(key_package, 'pskc:DeviceInfo/pskc:UserId')

        self.id = None
        self.algorithm = None

        key = key_package.find('pskc:Key', namespaces=namespaces)
        if key is not None:
            self.id = key.attrib.get('Id')
            self.algorithm = key.attrib.get('Algorithm')

        self.issuer = g_e_v(key_package, 'pskc:Key/pskc:Issuer')


class PSKC(object):

    def __init__(self, filename):
        tree = ElementTree.parse(filename)
        container = tree.getroot()
        # the version of the PSKC schema
        self.version = container.attrib.get('Version')
        # unique identifier for the container
        self.id = container.attrib.get('Id')
        # handle KeyPackage entries
        self.keys = []
        for package in container.findall('pskc:KeyPackage', namespaces=namespaces):
            self.keys.append(Key(package))
