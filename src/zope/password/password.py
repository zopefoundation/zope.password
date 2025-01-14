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

import re
from base64 import standard_b64decode
from base64 import standard_b64encode
from base64 import urlsafe_b64decode
from base64 import urlsafe_b64encode
from binascii import a2b_hex
from codecs import getencoder
from hashlib import md5
from hashlib import sha1
from hmac import compare_digest as _timing_safe_compare
from os import urandom


try:
    import bcrypt
except ModuleNotFoundError:  # pragma: no cover
    bcrypt = None

from zope.interface import implementer

from zope.password.interfaces import IMatchingPasswordManager


_enc = getencoder("utf-8")


def _encoder(s):
    if isinstance(s, bytes):
        return s
    return _enc(s)[0]


@implementer(IMatchingPasswordManager)
class PlainTextPasswordManager:
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
        password = _encoder(password)
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


class _PrefixedPasswordManager(PlainTextPasswordManager):

    # The bytes prefix this object uses.
    _prefix = None

    def match(self, encoded_password):
        return _encoder(encoded_password).startswith(self._prefix)


class SSHAPasswordManager(_PrefixedPasswordManager):
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
    >>> isinstance(encoded, bytes)
    True
    >>> print(encoded.decode())
    {SSHA}BLTuxxVMXzouxtKVb7gLgNxzdAI=

    >>> manager.match(encoded)
    True
    >>> manager.match(encoded.decode())
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
    >>> isinstance(encoded, bytes)
    True
    >>> print(encoded.decode())
    {SSHA}x3HIoiF9y6YRi/I4W1fkptbzTDiNr+9l

    >>> manager.checkPassword(encoded, password)
    True
    >>> manager.checkPassword(encoded, password + u"wrong")
    False

    We can also pass a salt that is a text string:

    >>> salt = u'salt'
    >>> password = 'secret'
    >>> encoded = manager.encodePassword(password, salt)
    >>> isinstance(encoded, bytes)
    True
    >>> print(encoded.decode())
    {SSHA}gVK8WC9YyFT1gMsQHTGCgT3sSv5zYWx0

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

    _prefix = b'{SSHA}'

    def encodePassword(self, password, salt=None):
        if salt is None:
            salt = urandom(4)
        elif not isinstance(salt, bytes):
            salt = _encoder(salt)
        hash = sha1(_encoder(password))
        hash.update(salt)
        return self._prefix + standard_b64encode(hash.digest() + salt)

    def checkPassword(self, encoded_password, password):
        # standard_b64decode() cannot handle unicode input string.
        encoded_password = _encoder(encoded_password)
        encoded_password = encoded_password[6:]
        if b'_' in encoded_password or b'-' in encoded_password:
            # Encoded using old urlsafe_b64encode, re-encode
            byte_string = urlsafe_b64decode(encoded_password)
            encoded_password = standard_b64encode(byte_string)
        else:
            byte_string = standard_b64decode(encoded_password)
        salt = byte_string[20:]
        return _timing_safe_compare(encoded_password,
                                    self.encodePassword(password, salt)[6:])


class SMD5PasswordManager(_PrefixedPasswordManager):
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
    >>> isinstance(encoded, bytes)
    True
    >>> print(encoded.decode())
    {SMD5}ht3czsRdtFmfGsAAGOVBOQ==

    >>> manager.match(encoded)
    True
    >>> manager.match(encoded.decode())
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
    >>> isinstance(encoded, bytes)
    True
    >>> print(encoded.decode())
    {SMD5}zChC6x0tl2zr9fjvjZzKePV5KWA=

    >>> manager.checkPassword(encoded, password)
    True
    >>> manager.checkPassword(encoded, password + u"wrong")
    False

    We can also pass a salt that is a text string:

    >>> salt = u'salt'
    >>> password = 'secret'
    >>> encoded = manager.encodePassword(password, salt)
    >>> isinstance(encoded, bytes)
    True
    >>> print(encoded.decode())
    {SMD5}mc0uWpXVVe5747A4pKhGJXNhbHQ=

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

    _prefix = b'{SMD5}'

    def encodePassword(self, password, salt=None):
        if salt is None:
            salt = urandom(4)
        elif not isinstance(salt, bytes):
            salt = salt.encode('utf-8')
        hash = md5(_encoder(password))
        hash.update(salt)
        return self._prefix + standard_b64encode(hash.digest() + salt)

    def checkPassword(self, encoded_password, password):
        encoded_password = _encoder(encoded_password)
        byte_string = standard_b64decode(encoded_password[6:])
        salt = byte_string[16:]
        return _timing_safe_compare(encoded_password,
                                    self.encodePassword(password, salt))


class MD5PasswordManager(_PrefixedPasswordManager):
    """MD5 password manager.

    >>> from zope.interface.verify import verifyObject
    >>> from zope.password.interfaces import IMatchingPasswordManager
    >>> from zope.password.password import MD5PasswordManager

    >>> manager = MD5PasswordManager()
    >>> verifyObject(IMatchingPasswordManager, manager)
    True

    >>> password = u"right \N{CYRILLIC CAPITAL LETTER A}"
    >>> encoded = manager.encodePassword(password)
    >>> isinstance(encoded, bytes)
    True
    >>> print(encoded.decode())
    {MD5}ht3czsRdtFmfGsAAGOVBOQ==
    >>> manager.match(encoded)
    True
    >>> manager.match(encoded.decode())
    True
    >>> manager.checkPassword(encoded, password)
    True
    >>> manager.checkPassword(encoded, password + u"wrong")
    False

    This password manager is compatible with other RFC 2307 MD5
    implementations. For example the output of the slappasswd command for
    a MD5 hashing of ``secret`` is ``{MD5}Xr4ilOzQ4PCOq3aQ0qbuaQ==``,
    and our implementation returns the same hash:

    >>> print(manager.encodePassword('secret').decode())
    {MD5}Xr4ilOzQ4PCOq3aQ0qbuaQ==

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

    _prefix = b'{MD5}'

    def encodePassword(self, password, salt=None):
        # The salt argument only exists for backwards compatibility and is
        # ignored on purpose.
        return self._prefix + standard_b64encode(
            md5(_encoder(password)).digest())

    def checkPassword(self, encoded_password, password):
        encoded_password = _encoder(encoded_password)
        encoded = encoded_password[encoded_password.find(b'}') + 1:]
        if len(encoded) > 24:
            # Backwards compatible, hexencoded md5 and bogus salt
            encoded = standard_b64encode(a2b_hex(encoded[-32:]))
        return _timing_safe_compare(encoded, self.encodePassword(password)[5:])


class SHA1PasswordManager(_PrefixedPasswordManager):
    """SHA1 password manager.

    >>> from zope.interface.verify import verifyObject
    >>> from zope.password.interfaces import IMatchingPasswordManager
    >>> from zope.password.password import SHA1PasswordManager

    >>> manager = SHA1PasswordManager()
    >>> verifyObject(IMatchingPasswordManager, manager)
    True

    >>> password = u"right \N{CYRILLIC CAPITAL LETTER A}"
    >>> encoded = manager.encodePassword(password)
    >>> isinstance(encoded, bytes)
    True
    >>> print(encoded.decode())
    {SHA}BLTuxxVMXzouxtKVb7gLgNxzdAI=
    >>> manager.match(encoded)
    True
    >>> manager.match(encoded.decode())
    True
    >>> manager.checkPassword(encoded, password)
    True
    >>> manager.checkPassword(encoded, password + u"wrong")
    False

    This password manager is compatible with other RFC 2307 SHA
    implementations. For example the output of the slappasswd command for
    a SHA hashing of ``secret`` is ``{SHA}5en6G6MezRroT3XKqkdPOmY/BfQ=``,
    and our implementation returns the same hash:

    >>> print(manager.encodePassword('secret').decode())
    {SHA}5en6G6MezRroT3XKqkdPOmY/BfQ=

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

    _prefix = b'{SHA}'

    def encodePassword(self, password, salt=None):
        # The salt argument only exists for backwards compatibility and is
        # ignored on purpose.
        return self._prefix + standard_b64encode(
            sha1(_encoder(password)).digest())

    def checkPassword(self, encoded_password, password):
        encoded_password = _encoder(encoded_password)
        if self.match(encoded_password):
            encoded = encoded_password[encoded_password.find(b'}') + 1:]
            if len(encoded) > 28:
                # Backwards compatible, hexencoded sha1 and bogus salt
                encoded = standard_b64encode(a2b_hex(encoded[-40:]))
            return encoded == self.encodePassword(password)[5:]
        # Backwards compatible, hexdigest and no prefix
        encoded_password = standard_b64encode(a2b_hex(encoded_password[-40:]))
        return _timing_safe_compare(
            encoded_password, self.encodePassword(password)[5:])

    def match(self, encoded_password):
        encoded_password = _encoder(encoded_password)
        return encoded_password.startswith((self._prefix, b'{SHA1}'))


class BCRYPTPasswordManager(_PrefixedPasswordManager):
    """
    BCRYPT password manager.

    In addition to the passwords encoded by this class,
    this class can also recognize passwords encoded by :mod:`z3c.bcrypt`
    and properly match and check them.

    .. note:: This uses the :mod:`bcrypt` library in its
        implementation, which `only uses the first 72 characters
        <https://pypi.python.org/pypi/bcrypt/3.1.3#maximum-password-length>`_
        of the password when computing the hash.
    """

    _prefix = b'{BCRYPT}'
    # This is the same regex that z3c.bcrypt uses, via way of cryptacular
    # The $2a$ is a prefix.
    _z3c_bcrypt_syntax = re.compile(br'\$2a\$[0-9]{2}\$[./A-Za-z0-9]{53}')

    _clean_clear = staticmethod(_encoder)
    _clean_hashed = staticmethod(_encoder)

    def checkPassword(self, hashed_password, clear_password):
        """Check a *hashed_password* against a *clear_password*.

        >>> from zope.password.password import BCRYPTPasswordManager
        >>> manager = BCRYPTPasswordManager()
        >>> manager.checkPassword(b'not from here', None)
        False

        :param bytes hashed_password: The encoded password.
        :param unicode clear_password: The password to check.
        :returns: True iif hashed passwords are equal.
        :rtype: bool
        """
        if not self.match(hashed_password):
            return False
        pw_bytes = self._clean_clear(clear_password)
        pw_hash = hashed_password
        if hashed_password.startswith(self._prefix):
            pw_hash = hashed_password[len(self._prefix):]

        try:
            ok = bcrypt.checkpw(pw_bytes, pw_hash)
        except ValueError:  # pragma: no cover
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
        """Was the password hashed with this password manager?

        :param bytes hashed_password: The encoded password.
        :rtype: bool
        :returns: True iif the password was hashed with this manager.
        """
        hashed_password = _encoder(hashed_password)
        return (hashed_password.startswith(self._prefix)
                or self._z3c_bcrypt_syntax.match(hashed_password) is not None)


class BCRYPTKDFPasswordManager(_PrefixedPasswordManager):
    """
    BCRYPT KDF password manager.

    This manager converts a plain text password into a byte array.
    The password and salt values (randomly generated when the password
    is encoded) are combined and repeatedly hashed *rounds* times. The
    repeated hashing is designed to thwart discovery of the key via
    password guessing attacks. The higher the number of rounds, the
    slower each attempt will be.

    Compared to the :class:`BCRYPTPasswordManager`, this has the
    advantage of allowing tunable rounds, so as computing devices get
    more powerful making brute force attacks faster, the difficulty
    level can be raised (for newly encoded passwords).

    >>> from zope.password.password import BCRYPTKDFPasswordManager
    >>> manager = BCRYPTKDFPasswordManager()
    >>> manager.checkPassword(b'not from here', None)
    False

    Let's encode a password. We'll use the minimum acceptable number
    of rounds so that the tests run fast:

    >>> manager.rounds = 51
    >>> password = u"right \N{CYRILLIC CAPITAL LETTER A}"
    >>> encoded = manager.encodePassword(password)
    >>> print(encoded.decode())
    {BCRYPTKDF}33...

    It checks out:

    >>> manager.checkPassword(encoded, password)
    True

    We can change the number of rounds for future encodings:

    >>> manager.rounds = 100
    >>> encoded2 = manager.encodePassword(password)
    >>> print(encoded2.decode())
    {BCRYPTKDF}64...
    >>> manager.checkPassword(encoded2, password)
    True

    And the old password still checks out:

    >>> manager.checkPassword(encoded, password)
    True
    """

    #: The number of rounds of hashing that should be applied.
    #: The higher the number, the slower it is. It should be at least
    #: 50.
    rounds = 1024

    #: The number of bytes long the encoded password will be. It must be
    #: at least 1 and no more than 512.
    keylen = 32

    _prefix = b'{BCRYPTKDF}'

    def _encode(self, password, salt, rounds, keylen):
        password = _encoder(password)

        key = bcrypt.kdf(password, salt=salt,
                         desired_key_bytes=keylen,
                         rounds=rounds)
        rounds_bytes = _encoder('%x' % rounds)
        result = (self._prefix
                  + rounds_bytes
                  + b'$'
                  + urlsafe_b64encode(salt)
                  + b'$'
                  + urlsafe_b64encode(key))
        return result

    def encodePassword(self, password):
        salt = bcrypt.gensalt()
        return self._encode(password, salt, self.rounds, self.keylen)

    def checkPassword(self, hashed_password, clear_password):
        hashed_password = _encoder(hashed_password)
        if not self.match(hashed_password):
            return False
        rounds, salt, key = hashed_password[len(self._prefix):].split(b'$')
        rounds = int(rounds, 16)

        salt = urlsafe_b64decode(salt)
        keylen = len(urlsafe_b64decode(key))
        encoded_password = self._encode(clear_password, salt, rounds, keylen)
        return _timing_safe_compare(hashed_password, encoded_password)


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
    managers.append(('BCRYPTKDF', BCRYPTKDFPasswordManager()))
