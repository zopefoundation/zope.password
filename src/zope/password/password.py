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

from base64 import standard_b64decode
from base64 import standard_b64encode
from base64 import urlsafe_b64decode
from binascii import a2b_hex
from codecs import getencoder
from hashlib import md5, sha1
from os import urandom

try:
    import bcrypt
except ImportError:
    bcrypt = None

from zope.interface import implementer
from zope.password.compat import text_type
from zope.password.interfaces import IMatchingPasswordManager

_encoder = getencoder("utf-8")


@implementer(IMatchingPasswordManager)
class PlainTextPasswordManager(object):
    """Plain text password manager.

    >>> from zope.interface.verify import verifyObject
    >>> from zope.password.interfaces import IMatchingPasswordManager
    >>> from zope.password.password import PlainTextPasswordManager

    >>> manager = PlainTextPasswordManager()
    >>> verifyObject(IMatchingPasswordManager, manager)
    True

    >>> password = u"right \N{CYRILLIC CAPITAL LETTER A}"
    >>> encoded = manager.encodePassword(password)
    >>> encoded == password.encode('utf-8')
    True
    >>> manager.checkPassword(encoded, password)
    True
    >>> manager.checkPassword(encoded, password + u"wrong")
    False

    The plain text password manager *never* claims to implement the scheme,
    because this would open a security hole, where a hash from a different
    scheme could be used as-is as a plain-text password. Authentication code
    that needs to support plain-text passwords need to explicitly check for
    plain-text password matches after all other options have been tested for:

    >>> manager.match(encoded)
    False
    """


    def encodePassword(self, password):
        if isinstance(password, text_type):
            password = password.encode('utf-8')
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
    >>> from zope.password.interfaces import IMatchingPasswordManager
    >>> from zope.password.password import SSHAPasswordManager

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
    ``{SSHA}x3HIoiF9y6YRi/I4W1fkptbzTDiNr+9l`` as seeded hash.

    Our password manager generates the same value when seeded with the
    same salt, so we can be sure, our output is compatible with
    standard LDAP tools that also use SSHA:

    >>> from base64 import standard_b64decode
    >>> salt = standard_b64decode('ja/vZQ==')
    >>> password = 'secret'
    >>> encoded = manager.encodePassword(password, salt)
    >>> encoded
    '{SSHA}x3HIoiF9y6YRi/I4W1fkptbzTDiNr+9l'

    >>> manager.checkPassword(encoded, password)
    True
    >>> manager.checkPassword(encoded, password + u"wrong")
    False

    Because a random salt is generated, the output of encodePassword is
    different every time you call it.

    >>> manager.encodePassword(password) != manager.encodePassword(password)
    True

    The password manager should be able to cope with unicode strings for input:

    >>> passwd = u'foobar\u2211' # sigma-sign.
    >>> manager.checkPassword(manager.encodePassword(passwd), passwd)
    True
    >>> manager.checkPassword(manager.encodePassword(passwd).decode(), passwd)
    True

    The manager only claims to implement SSHA encodings, anything not starting
    with the string {SSHA} returns False:

    >>> manager.match('{MD5}someotherhash')
    False

    An older version of this manager used the urlsafe variant of the base64
    encoding (replacing / and + characters with _ and - respectively). Hashes
    encoded with the old manager are still supported:

    >>> encoded = '{SSHA}x3HIoiF9y6YRi_I4W1fkptbzTDiNr-9l'
    >>> manager.checkPassword(encoded, 'secret')
    True

    """

    def encodePassword(self, password, salt=None):
        if salt is None:
            salt = urandom(4)
        elif isinstance(salt, text_type):
            salt = salt.encode('utf-8')
        hash = sha1(_encoder(password)[0])
        hash.update(salt)
        return b'{SSHA}' + standard_b64encode(hash.digest() + salt)

    def checkPassword(self, encoded_password, password):
        # standard_b64decode() cannot handle unicode input string. We
        # encode to ascii. This is safe as the encoded_password string
        # should not contain non-ascii characters anyway.
        if isinstance(encoded_password, text_type):
            encoded_password = encoded_password.encode('ascii')
        encoded_password = encoded_password[6:]
        if b'_' in encoded_password or b'-' in encoded_password:
            # Encoded using old urlsafe_b64encode, re-encode
            byte_string = urlsafe_b64decode(encoded_password)
            encoded_password = standard_b64encode(byte_string)
        else:
            byte_string = standard_b64decode(encoded_password)
        salt = byte_string[20:]
        return encoded_password == self.encodePassword(password, salt)[6:]

    def match(self, encoded_password):
        if isinstance(encoded_password, text_type):
            encoded_password = encoded_password.encode('ascii')
        return encoded_password.startswith(b'{SSHA}')


class SMD5PasswordManager(PlainTextPasswordManager):
    """SMD5 password manager.

    SMD5 is basically SMD5-encoding which also incorporates a salt
    into the encoded string. This way, stored passwords are more
    robust against dictionary attacks of attackers that could get
    access to lists of encoded passwords:

    >>> from zope.interface.verify import verifyObject
    >>> from zope.password.interfaces import IMatchingPasswordManager
    >>> from zope.password.password import SMD5PasswordManager

    >>> manager = SMD5PasswordManager()
    >>> verifyObject(IMatchingPasswordManager, manager)
    True

    >>> password = u"right \N{CYRILLIC CAPITAL LETTER A}"
    >>> encoded = manager.encodePassword(password, salt="")
    >>> encoded
    '{SMD5}ht3czsRdtFmfGsAAGOVBOQ=='

    >>> manager.match(encoded)
    True
    >>> manager.checkPassword(encoded, password)
    True
    >>> manager.checkPassword(encoded, password + u"wrong")
    False

    Using the ``slappasswd`` utility to encode ``secret``, we get
    ``{SMD5}zChC6x0tl2zr9fjvjZzKePV5KWA=`` as seeded hash.

    Our password manager generates the same value when seeded with the
    same salt, so we can be sure, our output is compatible with
    standard LDAP tools that also use SMD5:

    >>> from base64 import standard_b64decode
    >>> salt = standard_b64decode('9XkpYA==')
    >>> password = 'secret'
    >>> encoded = manager.encodePassword(password, salt)
    >>> encoded
    '{SMD5}zChC6x0tl2zr9fjvjZzKePV5KWA='

    >>> manager.checkPassword(encoded, password)
    True
    >>> manager.checkPassword(encoded, password + u"wrong")
    False

    Because a random salt is generated, the output of encodePassword is
    different every time you call it.

    >>> manager.encodePassword(password) != manager.encodePassword(password)
    True

    The password manager should be able to cope with unicode strings for
    input:

    >>> passwd = u'foobar\u2211' # sigma-sign.
    >>> manager.checkPassword(manager.encodePassword(passwd), passwd)
    True
    >>> manager.checkPassword(manager.encodePassword(passwd).decode(), passwd)
    True

    The manager only claims to implement SMD5 encodings, anything not starting
    with the string {SMD5} returns False:

    >>> manager.match('{MD5}someotherhash')
    False
    """

    def encodePassword(self, password, salt=None):
        if salt is None:
            salt = urandom(4)
        elif isinstance(salt, text_type):
            salt = salt.encode('utf-8')
        hash = md5(_encoder(password)[0])
        hash.update(salt)
        return b'{SMD5}' + standard_b64encode(hash.digest() + salt)

    def checkPassword(self, encoded_password, password):
        if isinstance(encoded_password, text_type):
            encoded_password = encoded_password.encode('ascii')
        byte_string = standard_b64decode(encoded_password[6:])
        salt = byte_string[16:]
        return encoded_password == self.encodePassword(password, salt)

    def match(self, encoded_password):
        if isinstance(encoded_password, text_type):
            encoded_password = encoded_password.encode('ascii')
        return encoded_password.startswith(b'{SMD5}')


class MD5PasswordManager(PlainTextPasswordManager):
    """MD5 password manager.

    >>> from zope.interface.verify import verifyObject
    >>> from zope.password.interfaces import IMatchingPasswordManager
    >>> from zope.password.password import MD5PasswordManager

    >>> manager = MD5PasswordManager()
    >>> verifyObject(IMatchingPasswordManager, manager)
    True

    >>> password = u"right \N{CYRILLIC CAPITAL LETTER A}"
    >>> encoded = manager.encodePassword(password)
    >>> encoded
    '{MD5}ht3czsRdtFmfGsAAGOVBOQ=='
    >>> manager.match(encoded)
    True
    >>> manager.checkPassword(encoded, password)
    True
    >>> manager.checkPassword(encoded, password + u"wrong")
    False

    This password manager is compatible with other RFC 2307 MD5
    implementations. For example the output of the slappasswd command for
    a MD5 hashing of ``secret`` is ``{MD5}Xr4ilOzQ4PCOq3aQ0qbuaQ==``,
    and our implementation returns the same hash:

    >>> manager.encodePassword('secret')
    '{MD5}Xr4ilOzQ4PCOq3aQ0qbuaQ=='

    The password manager should be able to cope with unicode strings for input:

    >>> passwd = u'foobar\u2211' # sigma-sign.
    >>> manager.checkPassword(manager.encodePassword(passwd), passwd)
    True
    >>> manager.checkPassword(manager.encodePassword(passwd).decode(), passwd)
    True

    A previous version of this manager also created a cosmetic salt, added
    to the start of the hash, but otherwise not used in creating the hash
    itself. Moreover, it generated the MD5 hash as a hex digest, not a base64
    encoded value and did not include the {MD5} prefix. Such hashed values are
    still supported too:

    >>> encoded = 'salt86dddccec45db4599f1ac00018e54139'
    >>> manager.checkPassword(encoded, password)
    True

    However, because the prefix is missing, the password manager cannot claim
    to implement the scheme:

    >>> manager.match(encoded)
    False
    """

    def encodePassword(self, password, salt=None):
        # The salt argument only exists for backwards compatibility and is
        # ignored on purpose.
        return b'{MD5}' + standard_b64encode(
            md5(_encoder(password)[0]).digest())

    def checkPassword(self, encoded_password, password):
        if isinstance(encoded_password, text_type):
            encoded_password = encoded_password.encode('ascii')
        encoded = encoded_password[encoded_password.find(b'}') + 1:]
        if len(encoded) > 24:
            # Backwards compatible, hexencoded md5 and bogus salt
            encoded = standard_b64encode(a2b_hex(encoded[-32:]))
        return encoded == self.encodePassword(password)[5:]

    def match(self, encoded_password):
        if isinstance(encoded_password, text_type):
            encoded_password = encoded_password.encode('ascii')
        return encoded_password.startswith(b'{MD5}')


class SHA1PasswordManager(PlainTextPasswordManager):
    """SHA1 password manager.

    >>> from zope.interface.verify import verifyObject
    >>> from zope.password.interfaces import IMatchingPasswordManager
    >>> from zope.password.password import SHA1PasswordManager

    >>> manager = SHA1PasswordManager()
    >>> verifyObject(IMatchingPasswordManager, manager)
    True

    >>> password = u"right \N{CYRILLIC CAPITAL LETTER A}"
    >>> encoded = manager.encodePassword(password)
    >>> encoded
    '{SHA}BLTuxxVMXzouxtKVb7gLgNxzdAI='
    >>> manager.match(encoded)
    True
    >>> manager.checkPassword(encoded, password)
    True
    >>> manager.checkPassword(encoded, password + u"wrong")
    False

    This password manager is compatible with other RFC 2307 SHA
    implementations. For example the output of the slappasswd command for
    a SHA hashing of ``secret`` is ``{SHA}5en6G6MezRroT3XKqkdPOmY/BfQ=``,
    and our implementation returns the same hash:

    >>> manager.encodePassword('secret')
    '{SHA}5en6G6MezRroT3XKqkdPOmY/BfQ='

    The password manager should be able to cope with unicode strings for input:

    >>> passwd = u'foobar\u2211' # sigma-sign.
    >>> manager.checkPassword(manager.encodePassword(passwd), passwd)
    True
    >>> manager.checkPassword(manager.encodePassword(passwd).decode(), passwd)
    True

    A previous version of this manager also created a cosmetic salt, added
    to the start of the hash, but otherwise not used in creating the hash
    itself. Moreover, it generated the SHA hash as a hex digest, not a base64
    encoded value and did not include the {SHA} prefix. Such hashed values are
    still supported too:

    >>> encoded = 'salt04b4eec7154c5f3a2ec6d2956fb80b80dc737402'
    >>> manager.checkPassword(encoded, password)
    True

    However, because the prefix is missing, the password manager cannot claim
    to implement the scheme:

    >>> manager.match(encoded)
    False

    Previously, this password manager used {SHA1} as a prefix, but this was
    changed to be compatible with LDAP (RFC 2307). The old prefix is still
    supported (note the hexdigest encoding as well):

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
        return b'{SHA}' + standard_b64encode(
            sha1(_encoder(password)[0]).digest())

    def checkPassword(self, encoded_password, password):
        if isinstance(encoded_password, text_type):
            encoded_password = encoded_password.encode('ascii')
        if self.match(encoded_password):
            encoded = encoded_password[encoded_password.find(b'}') + 1:]
            if len(encoded) > 28:
                # Backwards compatible, hexencoded sha1 and bogus salt
                encoded = standard_b64encode(a2b_hex(encoded[-40:]))
            return encoded == self.encodePassword(password)[5:]
        # Backwards compatible, hexdigest and no prefix
        encoded_password = standard_b64encode(a2b_hex(encoded_password[-40:]))
        return encoded_password == self.encodePassword(password)[5:]

    def match(self, encoded_password):
        if isinstance(encoded_password, text_type):
            encoded_password = encoded_password.encode('ascii')
        return (
            encoded_password.startswith(b'{SHA}') or
            encoded_password.startswith(b'{SHA1}'))


class BCRYPTPasswordManager(PlainTextPasswordManager):
    """BCRYPT password manager."""

    _prefix = b'{BCRYPT}'

    def _to_bytes(self, password, encoding):
        if isinstance(password, text_type):
            return password.encode(encoding)
        return password

    def _clean_clear(self, password):
        return self._to_bytes(password, 'utf-8')

    def _clean_hashed(self, hashed_password):
        return self._to_bytes(hashed_password, 'ascii')

    def checkPassword(self, hashed_password, clear_password):
        """Check a `hashed_password` against a `clear password`.

        :param hashed_password: The encoded password.
        :type hashed_password: str
        :param clear_password: The password to check.
        :type clear_password: unicode
        :returns: True iif hashed passwords are equal.
        :rtype: bool
        """
        if not self.match(hashed_password):
            return False
        pw_bytes = self._clean_clear(clear_password)
        pw_hash = hashed_password[len(self._prefix):]
        try:
            ok = bcrypt.checkpw(pw_bytes, pw_hash)
        except ValueError:
            # invalid salt
            ok = False
        return ok

    def encodePassword(self, password, salt=None):
        """Encode a `password`, with an optional `salt`.

        If `salt` is not provided, a unique hash will be generated
        for each invokation.

        :param password: The clear-text password.
        :type password: unicode
        :param salt: The salt to be used to hash the password.
        :rtype: str
        :returns: The encoded password as a byte-siring.
        """
        if salt is None:
            salt = bcrypt.gensalt()
        salt = self._clean_hashed(salt)
        pw = self._clean_clear(password)
        return self._prefix + bcrypt.hashpw(pw, salt=salt)

    def match(self, hashed_password):
        """Was the password hashed with this password manager.

        :param hashed_password: The encoded password.
        :type hashed_password: str
        :rtype: bool
        :returns: True iif the password was hashed with this manager.
        """
        return hashed_password.startswith(self._prefix)


# Simple registry
managers = [
    ('Plain Text', PlainTextPasswordManager()),
    ('MD5', MD5PasswordManager()),
    ('SMD5', SMD5PasswordManager()),
    ('SHA1', SHA1PasswordManager()),
    ('SSHA', SSHAPasswordManager()),
]

if bcrypt is not None:
    managers.append(('BCRYPT', BCRYPTPasswordManager()))
