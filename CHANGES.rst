Changes
=======

4.2.0 (2016-07-07)
------------------

- Drop support for Python 2.6.

- Converted documentation to Sphinx, including testing doctest snippets
  under ``tox``.

- Add support for Python 3.5.


4.1.0 (2014-12-27)
------------------

- Add support for PyPy.  (PyPy3 is pending release of a fix for:
  https://bitbucket.org/pypy/pypy/issue/1946)

- Add supprt for Python 3.4.

- Add support for testing on Travis.


4.0.2 (2013-03-11)
------------------

- Fix some final resource warnings.


4.0.1 (2013-03-10)
------------------

- Fix test failures under Python 3.3 when warnings are enabled.


4.0.0 (2013-02-21)
------------------

- Make ``zpasswd`` a proper console script entry point.

- Add ``tox.ini`` and ``MANIFEST.in``.

- Add support for Python 3.3

- Replace deprecated ``zope.interface.implements`` usage with equivalent
  ``zope.interface.implementer`` decorator.

- Drop support for Python 2.4 and 2.5.

- Add a new ``IMatchingPasswordManager`` interface with a 'match' method,
  which returns True if a given password hash was encdoded with the scheme
  implemented by the specific manager. All managers in this package implement
  this interface.

- Use "{SHA}" as the prefix for SHA1-encoded passwords to be compatible with
  RFC 2307, but support matching against "{SHA1}" for backwards compatibility.

- Add a crypt password manager to fully support all methods named in RFC 2307.
  It is contained in the ``legacy`` module however, to flag crypt's status.

- Add a SMD5 (salted MD5) password manager to fully support all encoding
  schemes implemented by OpenLDAP.

- Add a MySQL ``PASSWORD()`` (versions before 4.1) password manager, as also
  found in Zope2's ``AccessControl.AuthEncoding`` module.

- Remove the useless, cosmetic salt from the MD5 and SHA1 password managers,
  and use base64 encoding instead of hexdigests. This makes the output of
  these managers compatible with other MD5 and SHA1 hash implementations such
  as RFC 2307 but doesn't lower it's security in any way. Checking passwords
  against old, still 'salted' password hashes with hexdigests is still
  supported.

- Use the ``standard_base64encode`` method instead of ``url_base64encode``
  to maintain compatibility with LDAP.

3.6.1 (2010-05-27)
------------------

- The SSHAPasswordManager.checkPassword() would not handle unicode input
  (even if the string would only contain ascii characters). Now, the
  ``encoded_password`` input will be encoded to ascii, which is deemed safe
  as it should not contain non-ascii characters anyway.

3.6.0 (2010-05-07)
------------------

- Remove ``zope.testing`` dependency for tests.

- Update some copyright headers to comply to repository policy.

- Add ``zpasswd`` script formerly hold in zope.app.server. Contrary to
  former zpasswd script, which used "Plain Text" as default password
  manager, now SSHA is used as default.

3.5.1 (2009-03-14)
------------------

- Make security protection directives in ``configure.zcml`` execute only
  if ``zope.security`` is installed. This will allow reuse of the
  ``configure.zcml`` file in environments without ``zope.security``,
  for example with ``repoze.zcml``.

- Add "Password Manager Names" vocabulary for use with ``zope.schema``
  and ``zope.component``, like it was in ``zope.app.authentication``.
  It's an optional feature so it doesn't add hard dependency. We use
  "vocabulary" extra to list dependencies needed for vocabulary functionality.

3.5.0 (2009-03-06)
------------------

First release. This package was splitted off from ``zope.app.authentication``
to separate password manager functionality that is greatly re-usable without
any bit of ``zope.app.authentication`` and to reduce its dependencies.
