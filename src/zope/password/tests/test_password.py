##############################################################################
#
# Copyright (c) 2009 Zope Foundation and Contributors.
# All Rights Reserved.
#
# This software is subject to the provisions of the Zope Public License,
# Version 2.1 (ZPL).  A copy of the ZPL should accompany this distribution.
# THIS SOFTWARE IS PROVIDED "AS IS" AND ANY AND ALL EXPRESS OR IMPLIED
# WARRANTIES ARE DISCLAIMED, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF TITLE, MERCHANTABILITY, AGAINST INFRINGEMENT, AND FITNESS
# FOR A PARTICULAR PURPOSE.
#
##############################################################################
"""Password Managers Tests
"""
import doctest
import re
import unittest
from zope.testing import renormalizing

checker = renormalizing.RENormalizing([
    # Python 3 bytes add a "b".
    (re.compile("b('.*?')"),
     r"\1"),
    (re.compile('b(".*?")'),
     r"\1"),
    ])

def test_suite():
    return unittest.TestSuite((
        doctest.DocTestSuite('zope.password.password', checker=checker),
        doctest.DocTestSuite('zope.password.legacy', checker=checker),
        doctest.DocTestSuite(
            'zope.password.testing',
            optionflags=doctest.ELLIPSIS, checker=checker),
        ))
