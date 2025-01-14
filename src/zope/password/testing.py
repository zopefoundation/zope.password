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
"""Setup password managers as utilities
"""
__docformat__ = "reStructuredText"

from zope.configuration import xmlconfig

import zope.password


def setUpPasswordManagers():
    """Helper function for setting up password manager utilities for tests

    >>> from zope.component import getUtility
    >>> from zope.password.interfaces import IMatchingPasswordManager
    >>> from zope.schema.interfaces import IVocabularyFactory
    >>> setUpPasswordManagers()

    >>> getUtility(IMatchingPasswordManager, 'BCRYPT')
    <zope.password.password.BCRYPTPasswordManager object at 0x...>
    >>> getUtility(IMatchingPasswordManager, 'BCRYPTKDF')
    <zope.password.password.BCRYPTKDFPasswordManager object at 0x...>
    >>> getUtility(IMatchingPasswordManager, 'Plain Text')
    <zope.password.password.PlainTextPasswordManager object at 0x...>
    >>> getUtility(IMatchingPasswordManager, 'SSHA')
    <zope.password.password.SSHAPasswordManager object at 0x...>
    >>> getUtility(IMatchingPasswordManager, 'SMD5')
    <zope.password.password.SMD5PasswordManager object at 0x...>
    >>> getUtility(IMatchingPasswordManager, 'MD5')
    <zope.password.password.MD5PasswordManager object at 0x...>
    >>> getUtility(IMatchingPasswordManager, 'SHA1')
    <zope.password.password.SHA1PasswordManager object at 0x...>
    >>> getUtility(IMatchingPasswordManager, 'MySQL')
    <zope.password.legacy.MySQLPasswordManager object at 0x...>

    >>> voc = getUtility(IVocabularyFactory, 'Password Manager Names')
    >>> voc = voc(None)
    >>> voc
    <zope.schema.vocabulary.SimpleVocabulary object at 0x...>
    >>> 'SSHA' in voc
    True
    >>> 'Plain Text' in voc
    True
    >>> 'SHA1' in voc
    True
    >>> 'MD5' in voc
    True
    >>> 'SMD5' in voc
    True
    >>> 'MySQL' in voc
    True
    >>> 'BCRYPT' in voc
    True
    >>> 'BCRYPTKDF' in voc
    True

    """
    xmlconfig.file('configure.zcml', zope.password)
