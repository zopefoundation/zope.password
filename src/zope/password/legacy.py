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
from codecs import getencoder

from zope.interface import implementer

from zope.password.interfaces import IMatchingPasswordManager


_encoder = getencoder("utf-8")


@implementer(IMatchingPasswordManager)
class MySQLPasswordManager:
    """A MySQL digest manager.

    This Password Manager implements the digest scheme as implemented in the
    MySQL PASSWORD function in MySQL versions before 4.1. Note that this method
    results in a very weak 16-byte hash.

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

    Using the password 'PHP & Information Security' should result in the hash
    ``379693e271cd3bd6``, according to
    http://phpsec.org/articles/2005/password-hashing.html

    Our password manager generates the same value when seeded with the same
    seed, so we can be sure, our output is compatible with MySQL versions
    before 4.1:

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

    The manager only claims to implement MYSQL encodings, anything not starting
    with the string {MYSQL} returns False:

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
            if i == ord(b' ') or i == ord(b'\t'):
                continue  # pragma: no cover (this is actually hit, but ...
                # coverage isn't reporting it)
            nr ^= (((nr & 63) + add) * i) + (nr << 8)
            nr2 += (nr2 << 8) ^ nr
            add += i
        r0 = nr & ((1 << 31) - 1)
        r1 = nr2 & ((1 << 31) - 1)
        return (f"{{MYSQL}}{r0:08x}{r1:08x}").encode()

    def checkPassword(self, encoded_password, password):
        if not isinstance(encoded_password, bytes):
            encoded_password = encoded_password.encode('ascii')
        return encoded_password == self.encodePassword(password)

    def match(self, encoded_password):
        if not isinstance(encoded_password, bytes):
            encoded_password = encoded_password.encode('ascii')
        return encoded_password.startswith(b'{MYSQL}')
