================
Password Manager
================

This package provides a password manager mechanism. Password manager
is an utility object that can encode and check encoded
passwords. Beyond the generic interface, this package also provides
four implementations:

* PlainTextPasswordManager - the most simple and the less secure
  one. It does not do any password encoding and simply checks password
  by string equality.  It's useful in tests or as a base class for
  more secure implementations.

* MD5PasswordManager - a password manager that uses MD5 algorithm to
  encode passwords. It adds salt to the encoded password, but the salt
  is not used for encoding the password itself, so the use of salt in
  it is purely cosmetical. It's generally weak against dictionary
  attacks.
 
* SHA1PasswordManager - a password manager that uses SHA1 algorithm to
  encode passwords. It has the same salt weakness as the
  MD5PasswordManager.
 
* SSHAPasswordManager - the most secure password manager that is
  strong against dictionary attacks. It's basically SHA1-encoding
  password manager which also incorporates a salt into the password
  when encoding it. This password manager is compatible with passwords
  used in LDAP databases.

It is strongly recommended to use SSHAPasswordManager, as it's the
most secure.

The package also provides a script `zpasswd` to generate principal
entries in typical ``site.zcml`` files.

Usage
-----

It's very easy to use password managers. The
``zope.password.interfaces.IPasswordManager`` interface defines only
two methods::

  def encodePassword(password):
      """Return encoded data for the given password"""

  def checkPassword(encoded_password, password):
      """Return whether the given encoded data coincide with the given password"""

The implementations mentioned above are in the
``zope.password.password`` module.


Password Manager Names Vocabulary
---------------------------------

The ``zope.password.vocabulary`` module provides a vocabulary of
registered password manager utility names. It is typically registered
as an `IVocabularyFactory` utility named "Password Manager Names".

It's intended to be used with ``zope.component`` and ``zope.schema``,
so you need to have them installed and the utility registrations needs
to be done properly. The `configure.zcml` file, contained in
``zope.password`` does the registrations, as well as in
`setUpPasswordManagers` function in ``zope.password.testing`` module.

zpasswd script
--------------

``zpasswd`` is a script to generate principal entries in typical
``site.zcml`` files.

You can create a ``zpasswd`` script in your package by adding a
section like this to your ``buildout.cfg``::

  [zpasswd]
  recipe = z3c.recipe.dev:script
  eggs = zope.password
  module = zope.password.zpasswd
  method = main

This will generate a script ``zpasswd`` next time you run
``buildout``.

When run, the script will ask you for all parameters needed to create
a typical principal entry, including the encrypted password.

Use::

  $ bin/zpasswd --help

to get a list of options.

Using

  $ bin/zpasswd -c some/site.zcml

the script will try to lookup any password manager you defined and
registered in your environment. This is lookup is not necessary if you
go with the standard password managers defined in `zope.password`.

A typical ``zpasswd`` session::

  $ ./bin/zpasswd 

  Please choose an id for the principal.

  Id: foo


  Please choose a title for the principal.

  Title: The Foo


  Please choose a login for the principal.

  Login: foo

  Password manager:

   1. Plain Text
   2. MD5
   3. SHA1
   4. SSHA

  Password Manager Number [4]: 
  SSHA password manager selected


  Please provide a password for the principal.

  Password: 
  Verify password: 

  Please provide an optional description for the principal.

  Description: The main foo 

  ============================================
  Principal information for inclusion in ZCML:

    <principal
      id="foo"
      title="The Foo"
      login="foo"
      password="{SSHA}Zi_Lsz7Na3bS5rz4Aer-9TbqomXD2f3T"
      description="The main foo"
      password_manager="SSHA"
      />


