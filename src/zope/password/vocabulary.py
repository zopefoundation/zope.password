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
"""Vocabulary of password manager utility names for use with zope.component and
zope.schema.

$Id$
"""
from zope.component import getUtilitiesFor
from zope.interface import directlyProvides
from zope.schema.interfaces import IVocabularyFactory
from zope.schema.vocabulary import SimpleVocabulary, SimpleTerm

from zope.password.interfaces import IPasswordManager

def PasswordManagerNamesVocabulary(context=None):
    terms = []
    for name, util in getUtilitiesFor(IPasswordManager, context):
        terms.append(SimpleTerm(name))
    return SimpleVocabulary(terms)

directlyProvides(PasswordManagerNamesVocabulary, IVocabularyFactory)
