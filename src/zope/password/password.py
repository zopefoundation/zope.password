##############################################################################
#
# Copyright (c) 2009 Zope Foundation and Contributors.
# All Rights Reserved.
#
# This software is subject to the provisions of the Zope Public License,
# Version 2.0 (ZPL).  A copy of the ZPL should accompany this distribution.
# THIS SOFTWARE IS PROVIDED "AS IS" AND ANY AND ALL EXPRESS OR IMPLIED
# WARRANTIES ARE DISCLAIMED, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF TITLE, MERCHANTABILITY, AGAINST INFRINGEMENT, AND FITNESS
# FOR A PARTICULAR PURPOSE.
#
##############################################################################
"""Password managers

$Id$
"""
__docformat__ = 'restructuredtext'

from base64 import urlsafe_b64encode
from base64 import urlsafe_b64decode
from os import urandom
from random import randint
from codecs import getencoder
try:
    from hashlib import md5, sha1
except ImportError:
    # Python 2.4
    from md5 import new as md5
    from sha import new as sha1

from zope.interface import implements
from zope.password.interfaces import IPasswordManager

_encoder = getencoder("utf-8")


class PlainTextPasswordManager(object):
    """Plain text password manager.

    >>> from zope.interface.verify import verifyObject

    >>> manager = PlainTextPasswordManager()
    >>> verifyObject(IPasswordManager, manager)
    True

    >>> password = u"right \N{CYRILLIC CAPITAL LETTER A}"
    >>> encoded = manager.encodePassword(password)
    >>> encoded
    u'right \u0410'
    >>> manager.checkPassword(encoded, password)
    True
    >>> manager.checkPassword(encoded, password + u"wrong")
    False
    """

    implements(IPasswordManager)

    def encodePassword(self, password):
        return password

    def checkPassword(self, encoded_password, password):
        return encoded_password == self.encodePassword(password)


class SSHAPasswordManager(PlainTextPasswordManager):
    """SSHA password manager.

    SSHA is basically SHA1-encoding which also incorporates a salt
    into the encoded string. This way, stored passwords are more
    robust against dictionary attacks of attackers that could get
    access to lists of encoded passwords.

    SSHA is regularly used in LDAP databases and we should be
    compatible with passwords used there.

    >>> from zope.interface.verify import verifyObject

    >>> manager = SSHAPasswordManager()
    >>> verifyObject(IPasswordManager, manager)
    True

    >>> password = u"right \N{CYRILLIC CAPITAL LETTER A}"
    >>> encoded = manager.encodePassword(password, salt="")
    >>> encoded
    '{SSHA}BLTuxxVMXzouxtKVb7gLgNxzdAI='

    >>> manager.checkPassword(encoded, password)
    True
    >>> manager.checkPassword(encoded, password + u"wrong")
    False

    Using the `slappasswd` utility to encode ``secret``, we get
    ``{SSHA}J4mrr3NQHXzLVaT0h9TuEWoJOrxeQ5lv`` as seeded hash.

    Our password manager generates the same value when seeded with the
    same salt, so we can be sure, our output is compatible with
    standard LDAP tools that also use SSHA::

    >>> from base64 import urlsafe_b64decode
    >>> salt = urlsafe_b64decode('XkOZbw==')
    >>> encoded = manager.encodePassword('secret', salt)
    >>> encoded
    '{SSHA}J4mrr3NQHXzLVaT0h9TuEWoJOrxeQ5lv'

    >>> encoded = manager.encodePassword(password)
    >>> manager.checkPassword(encoded, password)
    True
    >>> manager.checkPassword(encoded, password + u"wrong")
    False

    >>> manager.encodePassword(password) != manager.encodePassword(password)
    True

    The password manager should be able to cope with unicode strings for input::

    >>> passwd = u'foobar\u2211' # sigma-sign.
    >>> manager.checkPassword(manager.encodePassword(passwd), passwd)
    True
    >>> manager.checkPassword(unicode(manager.encodePassword(passwd)), passwd)
    True

    """

    implements(IPasswordManager)

    def encodePassword(self, password, salt=None):
        if salt is None:
            salt = urandom(4)
        hash = sha1(_encoder(password)[0])
        hash.update(salt)
        return '{SSHA}' + urlsafe_b64encode(hash.digest() + salt)

    def checkPassword(self, encoded_password, password):
        # urlsafe_b64decode() cannot handle unicode input string. We
        # encode to ascii. This is safe as the encoded_password string
        # should not contain non-ascii characters anyway.
        encoded_password = encoded_password.encode('ascii')
        byte_string = urlsafe_b64decode(encoded_password[6:])
        salt = byte_string[20:]
        return encoded_password == self.encodePassword(password, salt)


class MD5PasswordManager(PlainTextPasswordManager):
    """MD5 password manager.

    Note: use of salt in this password manager is purely
    cosmetical. Use SSHA if you want increased security.

    >>> from zope.interface.verify import verifyObject

    >>> manager = MD5PasswordManager()
    >>> verifyObject(IPasswordManager, manager)
    True

    >>> password = u"right \N{CYRILLIC CAPITAL LETTER A}"
    >>> encoded = manager.encodePassword(password, salt="")
    >>> encoded
    '{MD5}86dddccec45db4599f1ac00018e54139'
    >>> manager.checkPassword(encoded, password)
    True
    >>> manager.checkPassword(encoded, password + u"wrong")
    False

    >>> encoded = manager.encodePassword(password)
    >>> encoded[-32:]
    '86dddccec45db4599f1ac00018e54139'
    >>> manager.checkPassword(encoded, password)
    True
    >>> manager.checkPassword(encoded, password + u"wrong")
    False

    >>> manager.encodePassword(password) != manager.encodePassword(password)
    True

    The old version of this password manager didn't add the {MD5} to
    passwords. Let's check if it can work with old stored passwords.

    >>> encoded = manager.encodePassword(password, salt="")
    >>> encoded = encoded[5:]
    >>> encoded
    '86dddccec45db4599f1ac00018e54139'

    >>> manager.checkPassword(encoded, password)
    True
    """

    implements(IPasswordManager)

    def encodePassword(self, password, salt=None):
        if salt is None:
            salt = "%08x" % randint(0, 0xffffffff)
        return '{MD5}%s%s' % (salt, md5(_encoder(password)[0]).hexdigest())

    def checkPassword(self, encoded_password, password):
        if encoded_password.startswith('{MD5}'):
            salt = encoded_password[5:-32]
            return encoded_password == self.encodePassword(password, salt)
        salt = encoded_password[:-32]
        return encoded_password == self.encodePassword(password, salt)[5:]


class SHA1PasswordManager(PlainTextPasswordManager):
    """SHA1 password manager.

    Note: use of salt in this password manager is purely
    cosmetical. Use SSHA if you want increased security.

    >>> from zope.interface.verify import verifyObject

    >>> manager = SHA1PasswordManager()
    >>> verifyObject(IPasswordManager, manager)
    True

    >>> password = u"right \N{CYRILLIC CAPITAL LETTER A}"
    >>> encoded = manager.encodePassword(password, salt="")
    >>> encoded
    '{SHA1}04b4eec7154c5f3a2ec6d2956fb80b80dc737402'
    >>> manager.checkPassword(encoded, password)
    True
    >>> manager.checkPassword(encoded, password + u"wrong")
    False

    >>> encoded = manager.encodePassword(password)
    >>> encoded[-40:]
    '04b4eec7154c5f3a2ec6d2956fb80b80dc737402'
    >>> manager.checkPassword(encoded, password)
    True
    >>> manager.checkPassword(encoded, password + u"wrong")
    False

    >>> manager.encodePassword(password) != manager.encodePassword(password)
    True

    The old version of this password manager didn't add the {SHA1} to
    passwords. Let's check if it can work with old stored passwords.

    >>> encoded = manager.encodePassword(password, salt="")
    >>> encoded = encoded[6:]
    >>> encoded
    '04b4eec7154c5f3a2ec6d2956fb80b80dc737402'

    >>> manager.checkPassword(encoded, password)
    True

    """

    implements(IPasswordManager)

    def encodePassword(self, password, salt=None):
        if salt is None:
            salt = "%08x" % randint(0, 0xffffffff)
        return '{SHA1}%s%s' % (salt, sha1(_encoder(password)[0]).hexdigest())

    def checkPassword(self, encoded_password, password):
        if encoded_password.startswith('{SHA1}'):
            salt = encoded_password[6:-40]
            return encoded_password == self.encodePassword(password, salt)
        salt = encoded_password[:-40]
        return encoded_password == self.encodePassword(password, salt)[6:]


# Simple registry
managers = [
    ('Plain Text', PlainTextPasswordManager()),
    ('MD5', MD5PasswordManager()),
    ('SHA1', SHA1PasswordManager()),
    ('SSHA', SSHAPasswordManager()),
]
