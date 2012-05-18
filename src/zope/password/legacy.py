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
"""Legacy password managers, using now-outdated, insecure methods for hashing
"""
__docformat__ = 'restructuredtext'

from codecs import getencoder

try:
    from crypt import crypt
    from random import choice
except ImportError:
    # The crypt module is not universally available, apparently
    crypt = None

from zope.interface import implementer
from zope.password.interfaces import IMatchingPasswordManager

_encoder = getencoder("utf-8")


if crypt is not None:
    @implementer(IMatchingPasswordManager)
    class CryptPasswordManager(object):
        """Crypt password manager.
        
        Implements a UNIX crypt(3) hashing scheme. Note that crypt is 
        considered far inferior to more modern schemes such as SSHA hashing,
        and only uses the first 8 characters of a password.
        
        >>> from zope.interface.verify import verifyObject

        >>> manager = CryptPasswordManager()
        >>> verifyObject(IMatchingPasswordManager, manager)
        True

        >>> password = u"right \N{CYRILLIC CAPITAL LETTER A}"
        >>> encoded = manager.encodePassword(password, salt="..")
        >>> encoded
        '{CRYPT}..I1I8wps4Na2'
        >>> manager.match(encoded)
        True
        >>> manager.checkPassword(encoded, password)
        True

        Unfortunately, crypt only looks at the first 8 characters, so matching
        against an 8 character password plus suffix always matches. Our test
        password (including utf-8 encoding) is exactly 8 characters long, and
        thus affixing 'wrong' to it tests as a correct password::
        
        >>> manager.checkPassword(encoded, password + u"wrong")
        True

        Using a completely different password is rejected as expected::

        >>> manager.checkPassword(encoded, 'completely wrong')
        False

        Using the `openssl passwd` command-line utility to encode ``secret``, 
        we get ``erz50QD3gv4Dw`` as seeded hash.

        Our password manager generates the same value when seeded with the
        same salt, so we can be sure, our output is compatible with
        standard LDAP tools that also use crypt::

        >>> salt = 'er'
        >>> password = 'secret'
        >>> encoded = manager.encodePassword(password, salt)
        >>> encoded
        '{CRYPT}erz50QD3gv4Dw'

        >>> manager.checkPassword(encoded, password)
        True
        >>> manager.checkPassword(encoded, password + u"wrong")
        False

        >>> manager.encodePassword(password) != manager.encodePassword(password)
        True

        The manager only claims to implement CRYPT encodings, anything not 
        starting with the string {CRYPT} returns False::

        >>> manager.match('{MD5}someotherhash')
        False

        """


        def encodePassword(self, password, salt=None):
            if salt is None:
                choices = ("ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                           "abcdefghijklmnopqrstuvwxyz"
                           "0123456789./")
                salt = choice(choices) + choice(choices)
            return '{CRYPT}%s' % crypt(_encoder(password)[0], salt)

        def checkPassword(self, encoded_password, password):
            return encoded_password == self.encodePassword(password, 
                encoded_password[7:9])

        def match(self, encoded_password):
            return encoded_password.startswith('{CRYPT}')


@implementer(IMatchingPasswordManager)
class MySQLPasswordManager(object):
    """A MySQL digest manager.

    This Password Manager implements the digest scheme as implemented in the
    MySQL PASSWORD function in MySQL versions before 4.1. Note that this
    method results in a very weak 16-byte hash.

    >>> from zope.interface.verify import verifyObject

    >>> manager = MySQLPasswordManager()
    >>> verifyObject(IMatchingPasswordManager, manager)
    True

    >>> password = u"right \N{CYRILLIC CAPITAL LETTER A}"
    >>> encoded = manager.encodePassword(password)
    >>> encoded
    '{MYSQL}0ecd752c5097d395'
    >>> manager.match(encoded)
    True
    >>> manager.checkPassword(encoded, password)
    True
    >>> manager.checkPassword(encoded, password + u"wrong")
    False

    Using the password 'PHP & Information Security' should result in the
    hash ``379693e271cd3bd6``, according to 
    http://phpsec.org/articles/2005/password-hashing.html

    Our password manager generates the same value when seeded with the, so we 
    can be sure, our output is compatible with MySQL versions before 4.1::

    >>> password = 'PHP & Information Security'
    >>> encoded = manager.encodePassword(password)
    >>> encoded
    '{MYSQL}379693e271cd3bd6'

    >>> manager.checkPassword(encoded, password)
    True
    >>> manager.checkPassword(encoded, password + u"wrong")
    False

    The manager only claims to implement MYSQL encodings, anything not 
    starting with the string {MYSQL} returns False::

    >>> manager.match('{MD5}someotherhash')
    False

    """


    def encodePassword(self, password):
        nr = 1345345333L
        add = 7
        nr2 = 0x12345671L
        for i in _encoder(password)[0]:
            if i == ' ' or i == '\t':
                continue
            nr ^= (((nr & 63) + add) * ord(i)) + (nr << 8)
            nr2 += (nr2 << 8) ^ nr
            add += ord(i)
        r0 = nr & ((1L << 31) - 1L)
        r1 = nr2 & ((1L << 31) - 1L)
        return "{MYSQL}%08lx%08lx" % (r0, r1)

    def checkPassword(self, encoded_password, password):
        return encoded_password == self.encodePassword(password)

    def match(self, encoded_password):
        return encoded_password.startswith('{MYSQL}')
