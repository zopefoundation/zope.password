##############################################################################
#
# Copyright (c) 2004 Zope Foundation and Contributors.
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
"""Implementation of the zpasswd script.
"""

import argparse
import os
import sys
from importlib.metadata import version
from xml.sax.saxutils import quoteattr


VERSION = version('zope.password')


def main(argv=None, app_factory=None):
    """Top-level script function to create a new principals."""
    argv = sys.argv if argv is None else argv

    try:
        options = parse_args(argv)
    except SystemExit as e:
        if e.code:
            return 2
        return 0

    return run_app_with_options(options, app_factory)


def run_app_with_options(options, app_factory=None):
    app = Application if app_factory is None else app_factory
    app = app(options)
    try:
        return app.process()
    except KeyboardInterrupt:
        return 1
    except SystemExit as e:
        return e.code


class Principal:
    """Principal.

    >>> principal = Principal("id", u"title", u"login", b"password")
    >>> print(principal)
      <principal
        id="id"
        title="title"
        login="login"
        password="password"
        />

    >>> principal = Principal("id", u"title", u"login", b"password",
    ...     u"description", "SHA1")
    >>> print(principal)
      <principal
        id="id"
        title="title"
        login="login"
        password="password"
        description="description"
        password_manager="SHA1"
        />
    """

    def __init__(self, id, title, login, password,
                 description="", password_manager_name="Plain Text"):
        self.id = id
        self.login = login
        self.password = password
        self.title = title
        self.description = description
        self.password_manager_name = password_manager_name

    def getLines(self):
        lines = [
            '  <principal',
            '    id=%s' % quoteattr(self.id),
            '    title=%s' % quoteattr(self.title),
            '    login=%s' % quoteattr(self.login),
            '    password=%s' % quoteattr(self.password.decode())
        ]
        if self.description:
            lines.append('    description=%s' % quoteattr(self.description))
        if self.password_manager_name != "Plain Text":
            lines.append('    password_manager=%s'
                         % quoteattr(self.password_manager_name))
        lines.append('    />')
        return lines

    def __str__(self):
        return "\n".join(self.getLines())


TITLE = """
============================================
Principal information for inclusion in ZCML:
"""

ID_TITLE = """
Please choose an id for the principal.
"""

TITLE_TITLE = """
Please choose a title for the principal.
"""

LOGIN_TITLE = """
Please choose a login for the principal.
"""

PASSWORD_TITLE = """
Please provide a password for the principal.
"""

DESCRIPTION_TITLE = """
Please provide an optional description for the principal.
"""


class Application:

    title = TITLE
    id_title = ID_TITLE
    title_title = TITLE_TITLE
    login_title = LOGIN_TITLE
    password_title = PASSWORD_TITLE
    description_title = DESCRIPTION_TITLE

    def __init__(self, options):
        self.options = options
        self.need_blank_line = False

    def read_input_line(self, prompt):
        # The tests replace this to make sure the right things happen.
        return input(prompt)

    def read_password(self, prompt):
        # The tests replace this to make sure the right things happen.
        import getpass
        try:
            return getpass.getpass(prompt)
        except KeyboardInterrupt:
            # The cursor was left on the same line as the prompt,
            # which we don't like.  Print a blank line.
            print()
            raise

    def process(self):
        options = self.options

        destination = options.destination
        try:
            principal = self.get_principal()

            if destination is sys.stdout:
                print(self.title)
            print(principal, file=destination)
            print()
        finally:
            if destination is not sys.stdout:
                destination.close()

        return 0

    def get_principal(self):
        id = self.get_value(self.id_title, "Id: ", "Id may not be empty")
        title = self.get_value(self.title_title, "Title: ",
                               "Title may not be empty")
        login = self.get_value(self.login_title, "Login: ",
                               "Login may not be empty")
        password_manager_name, password_manager = self.get_password_manager()
        password = self.get_password()
        description = self.get_value(self.description_title, "Description: ",)

        password = password_manager.encodePassword(password)
        return Principal(id, title, login, password, description,
                         password_manager_name)

    def get_value(self, title, prompt, error=""):
        self.print_message(title)
        self.need_blank_line = True
        while True:
            value = self.read_input_line(prompt).strip()
            if not value and error:
                print(error, file=sys.stderr)
                continue
            return value

    def get_password_manager(self):
        default = 0
        self.print_message("Password manager:")
        print()
        managers = self.options.managers

        for i, (name, manager) in enumerate(managers):
            print("% i. %s" % (i + 1, name))
            if name == 'BCRYPT':
                default = i
            elif name == 'SSHA' and not default:
                default = i
        print()
        self.need_blank_line = True
        while True:
            password_manager = self.read_input_line(
                "Password Manager Number [%s]: " % (default + 1))
            if not password_manager:
                index = default
                break
            elif password_manager.isdigit():
                index = int(password_manager)
                if index > 0 and index <= len(managers):
                    index -= 1
                    break
            print("You must select a password manager", file=sys.stderr)
        print("%s password manager selected" % managers[index][0])
        return managers[index]

    def get_password(self):
        self.print_message(self.password_title)
        while True:
            password = self.read_password("Password: ")
            if not password:
                print("Password may not be empty", file=sys.stderr)
                continue
            if password != password.strip() or password.split() != [password]:
                print("Password may not contain spaces", file=sys.stderr)
                continue
            break
        again = self.read_password("Verify password: ")
        if again != password:
            print("Password not verified!", file=sys.stderr)
            sys.exit(1)
        return password

    def print_message(self, message):
        if self.need_blank_line:
            print()
            self.need_blank_line = False
        print(message)


def get_password_managers(config_path=None):
    from zope.password.password import managers as default_managers

    managers = default_managers

    if config_path:
        from zope.component import getUtilitiesFor
        from zope.configuration import xmlconfig

        from zope.password.interfaces import IPasswordManager

        print("Loading configuration...")
        xmlconfig.file(config_path)
        managers = []
        for name, manager in getUtilitiesFor(IPasswordManager):
            if name == "Plain Text":
                managers.insert(0, (name, manager))
            else:
                managers.append((name, manager))

    return managers or default_managers


def parse_args(argv):
    """Parse the command line, returning an object representing the input."""
    prog = os.path.split(os.path.realpath(argv[0]))[1]
    p = argparse.ArgumentParser(prog=prog)
    p.add_argument(
        "-c",
        "--config",
        dest="config",
        metavar="FILE",
        help=("path to the site.zcml configuration file"
              " (more accurate but slow password managers registry creation)"))
    p.add_argument("-o", "--output", dest="destination", metavar="FILE",
                   help=("the file in which the output will be saved"
                         " (STDOUT by default)"),
                   default=sys.stdout,
                   type=argparse.FileType('w'))
    p.add_argument("--version", action="version", version=VERSION)
    options = p.parse_args(argv[1:])
    options.managers = get_password_managers(options.config)
    options.program = prog
    return options
