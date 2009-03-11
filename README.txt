================
Password Manager
================

This package provides a password manager mechanism. Password manager is an
utility object that can encode and check encoded passwords. Beyond the generic
interface, this package also provides four implementations:

 * PlainTextPasswordManager - the most simple and the less secure one. It does
   not do any password encoding and simply checks password by string equality.
   It's useful in tests or as a base class for more secure implementations.

 * MD5PasswordManager - a password manager that uses MD5 algorithm to encode
   passwords. It adds salt to the encoded password, but the salt is not used
   for encoding the password itself, so the use of salt in it is purely
   cosmetical. It's generally weak against dictionary attacks.
 
 * SHA1PasswordManager - a password manager that uses SHA1 algorithm to encode
   passwords. It has the same salt weakness as the MD5PasswordManager.
 
 * SSHAPasswordManager - the most secure password manager that is strong against
   dictionary attacks. It's basically SHA1-encoding password manager which also
   incorporates a salt into the password when encoding it. This password manager
   is compatible with passwords used in LDAP databases.

It is strongly recommended to use SSHAPasswordManager, as it's the most secure.


Usage
-----

It's very easy to use password managers. The ``zope.password.interfaces.IPasswordManager``
interface defines only two methods::

  def encodePassword(password):
      """Return encoded data for the given password"""

  def checkPassword(encoded_password, password):
      """Return whether the given encoded data coincide with the given password"""

The implementations mentioned above are in the ``zope.password.password`` module.


Password Manager Names Vocabulary
---------------------------------

The ``zope.password.vocabulary`` module provides a vocabulary of registered
password manager utility names. It is typically registered as an
`IVocabularyFactory` utility named "Password Manager Names".

It's intended to be used with ``zope.component`` and ``zope.schema``, so
you need to have them installed and the utility registrations needs to
be done properly. The `configure.zcml` file, contained in ``zope.password``
does the registrations, as well as in `setUpPasswordManagers` function in
``zope.password.testing`` module.
