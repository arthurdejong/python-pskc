#!/usr/bin/env python

# setup.py - python-pskc installation script
#
# Copyright (C) 2014-2019 Arthur de Jong
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

"""python-pskc installation script."""

import os
import sys
from setuptools import setup, find_packages

import pskc

# fix permissions for sdist
if 'sdist' in sys.argv:
    os.system('chmod -R a+rX .')
    os.umask(int('022', 8))

base_dir = os.path.dirname(__file__)

with open(os.path.join(base_dir, 'README'), 'r') as fp:
    long_description = fp.read()

setup(
    name='python-pskc',
    version=pskc.__version__,
    description='Python module for handling PSKC files',
    long_description=long_description,
    author='Arthur de Jong',
    author_email='arthur@arthurdejong.org',
    keywords=['PSKC', 'RFC 6030', 'key container'],
    url='https://arthurdejong.org/python-pskc/',
    license='LGPL',
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'Intended Audience :: Information Technology',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: GNU Lesser General Public License v2 or later (LGPLv2+)',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: Implementation :: PyPy',
        'Topic :: Security :: Cryptography',
        'Topic :: Software Development :: Libraries :: Python Modules',
        'Topic :: System :: Systems Administration :: Authentication/Directory',
        'Topic :: Text Processing :: Markup :: XML',
    ],
    packages=find_packages(),
    install_requires=['cryptography', 'python-dateutil'],
    extras_require={
        'lxml': ['lxml'],
        'defuse': ['defusedxml'],
        'signature': ['signxml'],
    },
    entry_points={
        'console_scripts': [
            'csv2pskc = pskc.scripts.csv2pskc:main',
            'pskc2csv = pskc.scripts.pskc2csv:main',
            'pskc2pskc = pskc.scripts.pskc2pskc:main',
        ],
    },
)
