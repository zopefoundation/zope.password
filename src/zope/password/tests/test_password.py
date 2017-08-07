##############################################################################
#
# Copyright (c) 2009 Zope Foundation and Contributors.
# All Rights Reserved.
#
#
# This software is subject to the provisions of the Zope Public License,
# Version 2.1 (ZPL).  A copy of the ZPL should accompany this distribution.
# THIS SOFTWARE IS PROVIDED "AS IS" AND ANY AND ALL EXPRESS OR IMPLIED
# WARRANTIES ARE DISCLAIMED, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF TITLE, MERCHANTABILITY, AGAINST INFRINGEMENT, AND FITNESS
# FOR A PARTICULAR PURPOSE.
#
##############################################################################
"""Password Managers Tests
"""
import contextlib
import doctest
import re
import unittest

try:
    import bcrypt
except ImportError:
    bcrypt = None

from zope.interface.verify import verifyObject
from zope.testing import renormalizing

from zope.password.interfaces import IMatchingPasswordManager
from zope.password.compat import bytes_type, text_type

checker = renormalizing.RENormalizing([
])


skip_if_bcrypt_not_installed = unittest.skipIf(
    bcrypt is None,
    'bcrypt is not installed')


class TestBCRYPTPasswordManager(unittest.TestCase):
    """Tests for custom zope.password password manager."""

    password = (
        u'Close \N{GREEK SMALL LETTER PHI}ncounterS 0f '
        u'tHe Erd K1nd'
    )

    def _make_one(self):
        from zope.password.password import BCRYPTPasswordManager
        return BCRYPTPasswordManager()

    @contextlib.contextmanager
    def _encode_twice(self, pw_mgr, salt1=None, salt2=None):
        enc_pw1 = pw_mgr.encodePassword(self.password, salt=salt1)
        enc_pw2 = pw_mgr.encodePassword(self.password, salt=salt2)
        yield (enc_pw1, enc_pw2)
        for enc_pw in (enc_pw1, enc_pw2):
            self.assertTrue(enc_pw.startswith(b'{BCRYPT}'))
            self.assertTrue(isinstance(enc_pw, bytes_type))

    @skip_if_bcrypt_not_installed
    def test_interface_compliance(self):
        pw_mgr = self._make_one()
        verifyObject(IMatchingPasswordManager, pw_mgr)

    @skip_if_bcrypt_not_installed
    def test_encodePassword_with_no_salt(self):
        pw_mgr = self._make_one()
        with self._encode_twice(pw_mgr,
                                salt1=None,
                                salt2=None) as encoded_passwords:
            self.assertNotEqual(*encoded_passwords)

    @skip_if_bcrypt_not_installed
    def test_encodePassword_with_same_salt(self):
        pw_mgr = self._make_one()
        salt = bcrypt.gensalt()
        with self._encode_twice(pw_mgr,
                                salt1=salt,
                                salt2=salt) as encoded_passwords:
            self.assertEqual(*encoded_passwords)

    @skip_if_bcrypt_not_installed
    def test_encodePassword_with_different_salts(self):
        pw_mgr = self._make_one()
        salt = bcrypt.gensalt()
        with self._encode_twice(pw_mgr,
                                salt1=salt,
                                salt2=None) as encoded_passwords:
            self.assertNotEqual(*encoded_passwords)
        with self._encode_twice(pw_mgr,
                                salt1=None,
                                salt2=salt) as encoded_passwords:
            self.assertNotEqual(*encoded_passwords)

    @skip_if_bcrypt_not_installed
    def test_encodePassword_with_unicode_salts(self):
        pw_mgr = self._make_one()
        salt = bcrypt.gensalt()
        # *handle* unicode salts (since all other encoding is handled)
        with self._encode_twice(pw_mgr,
                                salt1=text_type(salt, 'utf-8'),
                                salt2=salt) as encoded_passwords:
            self.assertEqual(*encoded_passwords)

    @skip_if_bcrypt_not_installed
    def test_checkPassword(self):
        encoded = (
            b'{BCRYPT}'
            b'$2b$12$ez4eHl6W1PfAWix5bPIbe.drdnyqjpuT1Cp0N.xcdxkAEbA7K6AHK'
        )
        pw_mgr = self._make_one()
        self.assertTrue(pw_mgr.checkPassword(encoded, self.password))
        # Mess with the hashed password, should not match
        encoded = encoded[:-1]
        self.assertFalse(pw_mgr.checkPassword(encoded, self.password))

        password = u"right \N{CYRILLIC CAPITAL LETTER A}"
        encoded = pw_mgr.encodePassword(password)
        self.assertTrue(pw_mgr.checkPassword(encoded, password))
        self.assertFalse(pw_mgr.checkPassword(encoded, password + u"wrong"))

        # Subsequently hashing the same password will produce a
        # different encoding
        encoded2 = pw_mgr.encodePassword(password)
        self.assertNotEqual(encoded2, encoded)
        self.assertFalse(pw_mgr.checkPassword(encoded2, password + u"wrong"))
        self.assertTrue(pw_mgr.checkPassword(encoded, password))
        self.assertTrue(pw_mgr.checkPassword(encoded2, password))

    @skip_if_bcrypt_not_installed
    def test_match(self):
        pw_mgr = self._make_one()
        self.assertFalse(pw_mgr.match(b'{SHA1}1lksd;kf;slkf;slkf'))
        self.assertTrue(pw_mgr.match(b'{BCRYPT}'))


def test_suite():
    suite = unittest.TestSuite((
        doctest.DocTestSuite('zope.password.password', checker=checker),
        doctest.DocTestSuite('zope.password.legacy', checker=checker),
        doctest.DocTestSuite(
            'zope.password.testing',
            optionflags=doctest.ELLIPSIS, checker=checker),
        ))
    suite.addTests(unittest.defaultTestLoader.loadTestsFromName(__name__))
    return suite
