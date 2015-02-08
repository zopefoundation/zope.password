Using :mod:`zope.password`
==========================

This package provides a password manager mechanism. Password manager
is an utility object that can encode and check encoded
passwords. Beyond the generic interface, this package also provides
seven implementations:

:class:`zope.password.password.PlainTextPasswordManager`

   The most simple and the less secure one. It does not do any password
   encoding and simply checks password by string equality.  It's useful in
   tests or as a base class for more secure implementations.

:class:`zope.password.password.MD5PasswordManager`

   A password manager that uses MD5 algorithm to encode passwords. It's
   generally weak against dictionary attacks due to a lack of a salt.

:class:`zope.password.password.SMD5PasswordManager`

   A password manager that uses MD5 algorithm, together with a salt to
   encode passwords. It's better protected against against dictionary
   attacks, but the MD5 hashing algorithm is not as strong as the SHA1
   algorithm.

:class:`zope.password.password.SHA1PasswordManager`

   A password manager that uses SHA1 algorithm to encode passwords. It has
   the same weakness as the MD5PasswordManager.

:class:`zope.password.password.SSHAPasswordManager`

   the most secure password manager that is strong against dictionary
   attacks. It's basically SHA1-encoding password manager which also
   incorporates a salt into the password when encoding it.

:class:`zope.password.password.CryptPasswordManager`

   A manager implementing the crypt(3) hashing scheme.  Only available if
   the python crypt module is installed. This is a legacy manager, only
   present to ensure that zope.password can be used for all schemes defined
   in RFC 2307 (LDAP).

:class:`zope.password.password.MySQLPasswordManager`

   A manager implementing the digest scheme as implemented in the MySQL
   PASSWORD function in MySQL versions before 4.1.  Note that this method
   results in a very weak 16-byte hash.

The ``Crypt``, ``MD5``, ``SMD5``, ``SHA`` and ``SSHA`` password managers
are all compatible with RFC 2307 LDAP implementations of the same password
encoding schemes.

.. note:: 
   It is strongly recommended to use SSHAPasswordManager, as it's the
   most secure.

The package also provides a script, :command:`zpasswd`,to generate principal
entries in typical ``site.zcml`` files.

Password Manager Interfaces
---------------------------

The :class:`zope.password.interfaces.IPasswordManager` interface defines only
two methods:

.. literalinclude:: ../src/zope/password/interfaces.py
   :pyobject: IPasswordManager.encodePassword

.. literalinclude:: ../src/zope/password/interfaces.py
   :pyobject: IPasswordManager.checkPassword

An extended interface,
:class:`zope.password.interfaces.IMatchingPasswordManager`,
adds one additional method:

.. literalinclude:: ../src/zope/password/interfaces.py
   :pyobject: IMatchingPasswordManager.match


Looking Up Password Managers via a Vocabulary
---------------------------------------------

The :mod:`zope.password.vocabulary` module provides a vocabulary of
registered password manager utility names. It is typically registered
as an :class:`zope.schema.interfaces.IVocabularyFactory` utility named
"Password Manager Names".

It's intended to be used with :mod:`zope.component` and :mod:`zope.schema`,
so you need to have them installed and the utility registrations needs
to be done properly. The ``configure.zcml`` file contained in
:mod:`zope.password` does the registrations, as well as in
:func:`zope.password.testing.setUpPasswordManagers`.

Encrypting Passwords with :command:`zpasswd`
--------------------------------------------

:command:`zpasswd` is a script to generate principal entries in typical
``site.zcml`` files.

You can create a :command:`zpasswd` script in your buildout by adding a
section like this to your ``buildout.cfg``:

.. code-block:: ini

   [zpasswd]
   recipe = z3c.recipe.dev:script
   eggs = zope.password
   module = zope.password.zpasswd
   method = main

This will generate a script :command:`zpasswd` next time you run
:command:`buildout`.

When run, the script will ask you for all parameters needed to create
a typical principal entry, including the encrypted password.

Use:

.. code-block:: sh

   $ bin/zpasswd --help

to get a list of options.

Using

.. code-block:: sh

   $ bin/zpasswd -c some/site.zcml

the script will try to lookup any password manager you defined and
registered in your environment. This is lookup is not necessary if you
go with the standard password managers defined in :mod:`zope.password`.

A typical :command:`zpasswd` session might look like:

.. code-block:: sh

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
