##############################################################################
#
# Copyright (c) 2009 Zope Corporation and Contributors.
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

$Id$
"""
__docformat__ = "reStructuredText"
from zope.component import provideUtility
from zope.password.interfaces import IPasswordManager
from zope.password.password import PlainTextPasswordManager
from zope.password.password import MD5PasswordManager
from zope.password.password import SHA1PasswordManager
from zope.password.password import SSHAPasswordManager


def setUpPasswordManagers():
    """Helper function for setting up password manager utilities for tests
    
    >>> from zope.component import getUtility
    >>> setUpPasswordManagers()
    >>> getUtility(IPasswordManager, 'Plain Text')
    <zope.password.password.PlainTextPasswordManager object at 0x...>
    >>> getUtility(IPasswordManager, 'SSHA')
    <zope.password.password.SSHAPasswordManager object at 0x...>
    >>> getUtility(IPasswordManager, 'MD5')
    <zope.password.password.MD5PasswordManager object at 0x...>
    >>> getUtility(IPasswordManager, 'SHA1')
    <zope.password.password.SHA1PasswordManager object at 0x...>
    
    """
    provideUtility(PlainTextPasswordManager(), IPasswordManager, 'Plain Text')
    provideUtility(SSHAPasswordManager(), IPasswordManager, 'SSHA')
    provideUtility(MD5PasswordManager(), IPasswordManager, 'MD5')
    provideUtility(SHA1PasswordManager(), IPasswordManager, 'SHA1')
