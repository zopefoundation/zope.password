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
import sys
from codecs import getencoder

try:
    from crypt import crypt
    from random import choice
except ImportError: # pragma: no cover
    # The crypt module is not universally available, apparently
    crypt = None

from zope.interface import implementer
from zope.password.interfaces import IMatchingPasswordManager

_encoder = getencoder("utf-8")

PY2 = sys.version_info[0] == 2


@implementer(IMatchingPasswordManager)
class CryptPasswordManager(object):
    """Crypt password manager.

    Implements a UNIX crypt(3) hashing scheme. Note that crypt is
    considered far inferior to more modern schemes such as SSHA hashing,
    and only uses the first 8 characters of a password.

    >>> from zope.interface.verify import verifyObject
    >>> from zope.password.interfaces import IMatchingPasswordManager
    >>> from zope.password.legacy import CryptPasswordManager

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

    Note that this object fails to return bytes from the ``encodePassword``
    function on Python 3:

    >>> isinstance(encoded, str)
    True

    Unfortunately, crypt only looks at the first 8 characters, so matching
    against an 8 character password plus suffix always matches. Our test
    password (including utf-8 encoding) is exactly 8 characters long, and
    thus affixing 'wrong' to it tests as a correct password:

    >>> manager.checkPassword(encoded, password + u"wrong")
    True

    Using a completely different password is rejected as expected:

    >>> manager.checkPassword(encoded, 'completely wrong')
    False

    Using the `openssl passwd` command-line utility to encode ``secret``,
    we get ``erz50QD3gv4Dw`` as seeded hash.

    Our password manager generates the same value when seeded with the
    same salt, so we can be sure, our output is compatible with
    standard LDAP tools that also use crypt:

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
    starting with the string {CRYPT} returns False:

    >>> manager.match('{MD5}someotherhash')
    False

    """


    def encodePassword(self, password, salt=None):
        if salt is None:
            choices = ("ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                       "abcdefghijklmnopqrstuvwxyz"
                       "0123456789./")
            salt = choice(choices) + choice(choices)
        if PY2:
            # Py3: Python 2 can only handle ASCII for crypt.
            password = _encoder(password)[0]
        return '{CRYPT}%s' % crypt(password, salt)

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
    >>> from zope.password.interfaces import IMatchingPasswordManager
    >>> from zope.password.legacy import MySQLPasswordManager

    >>> manager = MySQLPasswordManager()
    >>> verifyObject(IMatchingPasswordManager, manager)
    True

    >>> password = u"right \N{CYRILLIC CAPITAL LETTER A}"
    >>> encoded = manager.encodePassword(password)
    >>> isinstance(encoded, bytes)
    True
    >>> print(encoded.decode())
    {MYSQL}0ecd752c5097d395
    >>> manager.match(encoded)
    True
    >>> manager.match(encoded.decode())
    True
    >>> manager.checkPassword(encoded.decode(), password)
    True
    >>> manager.checkPassword(encoded, password)
    True
    >>> manager.checkPassword(encoded, password + u"wrong")
    False

    Using the password 'PHP & Information Security' should result in the
    hash ``379693e271cd3bd6``, according to
    http://phpsec.org/articles/2005/password-hashing.html

    Our password manager generates the same value when seeded with the same seed, so we
    can be sure, our output is compatible with MySQL versions before 4.1:

    >>> password = 'PHP & Information Security'
    >>> encoded = manager.encodePassword(password)
    >>> isinstance(encoded, bytes)
    True
    >>> print(encoded.decode())
    {MYSQL}379693e271cd3bd6

    >>> manager.checkPassword(encoded, password)
    True
    >>> manager.checkPassword(encoded, password + u"wrong")
    False

    The manager only claims to implement MYSQL encodings, anything not
    starting with the string {MYSQL} returns False:

    >>> manager.match('{MD5}someotherhash')
    False

    Spaces and tabs are ignored:

    >>> encoded = manager.encodePassword('\tign or ed')
    >>> print(encoded.decode())
    {MYSQL}75818366052c6a78
    >>> encoded = manager.encodePassword('ignored')
    >>> print(encoded.decode())
    {MYSQL}75818366052c6a78
    """


    def encodePassword(self, password):
        nr = 1345345333
        add = 7
        nr2 = 0x12345671
        for i in _encoder(password)[0]:
            if PY2:
                # In Python 2 bytes iterate over single-char strings.
                i = ord(i)
            if i == ord(b' ') or i == ord(b'\t'):
                continue # pragma: no cover (this is actually hit, but coverage isn't reporting it)
            nr ^= (((nr & 63) + add) * i) + (nr << 8)
            nr2 += (nr2 << 8) ^ nr
            add += i
        r0 = nr & ((1 << 31) - 1)
        r1 = nr2 & ((1 << 31) - 1)
        return ("{MYSQL}%08lx%08lx" % (r0, r1)).encode()

    def checkPassword(self, encoded_password, password):
        if not isinstance(encoded_password, bytes):
            encoded_password = encoded_password.encode('ascii')
        return encoded_password == self.encodePassword(password)

    def match(self, encoded_password):
        if not isinstance(encoded_password, bytes):
            encoded_password = encoded_password.encode('ascii')
        return encoded_password.startswith(b'{MYSQL}')
