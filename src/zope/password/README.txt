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

It is strongly recommended to use SSHAPasswordManager, as it's the most secure
one.

Usage
-----

It's very easy to use password managers. The ``zope.password.interfaces.IPasswordManager``
interface defines only two methods:

 * encodePassword(password) - return encoded data for the given `password`
 * checkPassword(storedPassword, password) - return whether the given `password`
   coincide with the storedPassword, which is 
 