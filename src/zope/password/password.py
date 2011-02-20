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
"""Password managers
"""
__docformat__ = 'restructuredtext'

from base64 import standard_b64encode
from base64 import standard_b64decode
from base64 import urlsafe_b64decode
from os import urandom
from codecs import getencoder
try:
    from hashlib import md5, sha1
except ImportError:
    # Python 2.4
    from md5 import new as md5
    from sha import new as sha1

from zope.interface import implements
from zope.password.interfaces import IMatchingPasswordManager

_encoder = getencoder("utf-8")


class PlainTextPasswordManager(object):
    """Plain text password manager.

    >>> from zope.interface.verify import verifyObject

    >>> manager = PlainTextPasswordManager()
    >>> verifyObject(IMatchingPasswordManager, manager)
    True

    >>> password = u"right \N{CYRILLIC CAPITAL LETTER A}"
    >>> encoded = manager.encodePassword(password)
    >>> encoded
    u'right \u0410'
    >>> manager.checkPassword(encoded, password)
    True
    >>> manager.checkPassword(encoded, password + u"wrong")
    False

    The plain text password manager *never* claims to implement the scheme,
    because this would open a security hole, where a hash from a different
    scheme could be used as-is as a plain-text password. Authentication code
    that needs to support plain-text passwords need to explicitly check for
    plain-text password matches after all other options have been tested for::

    >>> manager.match(encoded)
    False
    """

    implements(IMatchingPasswordManager)

    def encodePassword(self, password):
        return password

    def checkPassword(self, encoded_password, password):
        return encoded_password == self.encodePassword(password)

    def match(self, encoded_password):
        # We always return False for PlainText because it was a) not encrypted
        # and b) matching against actual encryption methods would result in
        # the ability to authenticate with the un-encrypted hash as a password.
        # For example, you should not be able to authenticate with a literal
        # SSHA hash.
        return False


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
    >>> verifyObject(IMatchingPasswordManager, manager)
    True

    >>> password = u"right \N{CYRILLIC CAPITAL LETTER A}"
    >>> encoded = manager.encodePassword(password, salt="")
    >>> encoded
    '{SSHA}BLTuxxVMXzouxtKVb7gLgNxzdAI='

    >>> manager.match(encoded)
    True
    >>> manager.checkPassword(encoded, password)
    True
    >>> manager.checkPassword(encoded, password + u"wrong")
    False

    Using the `slappasswd` utility to encode ``secret``, we get
    ``{SSHA}J4mrr3NQHXzLVaT0h9TuEWoJOrxeQ5lv`` as seeded hash.

    Our password manager generates the same value when seeded with the
    same salt, so we can be sure, our output is compatible with
    standard LDAP tools that also use SSHA::

    >>> from base64 import standard_b64decode
    >>> salt = standard_b64decode('XkOZbw==')
    >>> password = 'secret'
    >>> encoded = manager.encodePassword(password, salt)
    >>> encoded
    '{SSHA}J4mrr3NQHXzLVaT0h9TuEWoJOrxeQ5lv'

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

    The manager only claims to implement SSHA encodings, anything not starting
    with the string {SSHA} returns False::

    >>> manager.match('{MD5}someotherhash')
    False

    """

    def encodePassword(self, password, salt=None):
        if salt is None:
            salt = urandom(4)
        hash = sha1(_encoder(password)[0])
        hash.update(salt)
        return '{SSHA}' + standard_b64encode(hash.digest() + salt)

    def checkPassword(self, encoded_password, password):
        # standard_b64decode() cannot handle unicode input string. We
        # encode to ascii. This is safe as the encoded_password string
        # should not contain non-ascii characters anyway.
        encoded_password = encoded_password.encode('ascii')[6:]
        if '_' in encoded_password or '-' in encoded_password:
            # Encoded using urlsafe_b64encode
            byte_string = urlsafe_b64decode(encoded_password)
        byte_string = standard_b64decode(encoded_password)
        salt = byte_string[20:]
        return encoded_password == self.encodePassword(password, salt)[6:]

    def match(self, encoded_password):
        return encoded_password.startswith('{SSHA}')


class MD5PasswordManager(PlainTextPasswordManager):
    """MD5 password manager.

    >>> from zope.interface.verify import verifyObject

    >>> manager = MD5PasswordManager()
    >>> verifyObject(IMatchingPasswordManager, manager)
    True

    >>> password = u"right \N{CYRILLIC CAPITAL LETTER A}"
    >>> encoded = manager.encodePassword(password)
    >>> encoded
    '{MD5}86dddccec45db4599f1ac00018e54139'
    >>> manager.match(encoded)
    True
    >>> manager.checkPassword(encoded, password)
    True
    >>> manager.checkPassword(encoded, password + u"wrong")
    False

    The old version of this password manager didn't add the {MD5} to
    passwords. Let's check if it can work with old stored passwords.

    >>> encoded = manager.encodePassword(password)
    >>> encoded = encoded[5:]
    >>> encoded
    '86dddccec45db4599f1ac00018e54139'

    >>> manager.checkPassword(encoded, password)
    True

    However, because the prefix is missing, the password manager cannot claim
    to implement the scheme:

    >>> manager.match(encoded)
    False

    A previous version of this manager also created a cosmetic salt, added
    to the start of the hash, but otherwise not used in creating the hash
    itself. To still support these 'hashed' passwords, only the last 32 bytes
    of the pre-existing hash are used:
    
    >>> manager.checkPassword('salt' + encoded, password)
    True

    """

    def encodePassword(self, password, salt=None):
        # The salt argument only exists for backwards compatibility and is
        # ignored on purpose.
        return '{MD5}%s' % (md5(_encoder(password)[0]).hexdigest())

    def checkPassword(self, encoded_password, password):
        return encoded_password[-32:] == self.encodePassword(password)[-32:]

    def match(self, encoded_password):
        return encoded_password.startswith('{MD5}')


class SHA1PasswordManager(PlainTextPasswordManager):
    """SHA1 password manager.

    >>> from zope.interface.verify import verifyObject

    >>> manager = SHA1PasswordManager()
    >>> verifyObject(IMatchingPasswordManager, manager)
    True

    >>> password = u"right \N{CYRILLIC CAPITAL LETTER A}"
    >>> encoded = manager.encodePassword(password)
    >>> encoded
    '{SHA}04b4eec7154c5f3a2ec6d2956fb80b80dc737402'
    >>> manager.match(encoded)
    True
    >>> manager.checkPassword(encoded, password)
    True
    >>> manager.checkPassword(encoded, password + u"wrong")
    False

    The old version of this password manager didn't add the {SHA} to
    passwords. Let's check if it can work with old stored passwords.

    >>> encoded = manager.encodePassword(password)
    >>> encoded = encoded[5:]
    >>> encoded
    '04b4eec7154c5f3a2ec6d2956fb80b80dc737402'

    >>> manager.checkPassword(encoded, password)
    True

    However, because the prefix is missing, the password manager cannot claim
    to implement the scheme:

    >>> manager.match(encoded)
    False

    A previous version of this manager also created a cosmetic salt, added
    to the start of the hash, but otherwise not used in creating the hash
    itself. To still support these 'hashed' passwords, only the last 40 bytes
    of the pre-existing hash are used:
    
    >>> manager.checkPassword('salt' + encoded, password)
    True

    Previously, this password manager used {SHA1} as a prefix, but this was
    changed to be compatible with LDAP (RFC 2307). The old prefix is still
    supported:

    >>> password = u"right \N{CYRILLIC CAPITAL LETTER A}"
    >>> encoded = '{SHA1}04b4eec7154c5f3a2ec6d2956fb80b80dc737402'
    >>> manager.match(encoded)
    True
    >>> manager.checkPassword(encoded, password)
    True
    >>> manager.checkPassword(encoded, password + u"wrong")
    False

    """

    def encodePassword(self, password, salt=None):
        # The salt argument only exists for backwards compatibility and is
        # ignored on purpose.
        return '{SHA}%s' % sha1(_encoder(password)[0]).hexdigest()

    def checkPassword(self, encoded_password, password):
        if self.match(encoded_password):
            encoded = encoded_password[encoded_password.find('}') + 1:]
            return encoded[-40:] == self.encodePassword(password)[5:]
        return encoded_password[-40:] == self.encodePassword(password)[5:]

    def match(self, encoded_password):
        return (
            encoded_password.startswith('{SHA}') or 
            encoded_password.startswith('{SHA1}'))


# Simple registry
managers = [
    ('Plain Text', PlainTextPasswordManager()),
    ('MD5', MD5PasswordManager()),
    ('SHA1', SHA1PasswordManager()),
    ('SSHA', SSHAPasswordManager()),
]
