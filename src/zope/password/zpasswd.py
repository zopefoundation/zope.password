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

$Id$
"""
import optparse
import os
import pkg_resources
import sys
from xml.sax.saxutils import quoteattr

VERSION = pkg_resources.get_distribution('zope.password').version

def main(argv=None):
    """Top-level script function to create a new principals."""
    if argv is None:
        argv = sys.argv
    try:
        options = parse_args(argv)
    except SystemExit, e:
        if e.code:
            return 2
        else:
            return 0
    app = Application(options)
    try:
        return app.process()
    except KeyboardInterrupt:
        return 1
    except SystemExit, e:
        return e.code

class Principal(object):
    """Principal.

    >>> principal = Principal("id", "title", "login", "password")
    >>> print principal
      <principal
        id="id"
        title="title"
        login="login"
        password="password"
        />

    >>> principal = Principal("id", "title", "login", "password",
    ...     "description", "SHA1")
    >>> print principal
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
            '    password=%s' % quoteattr(self.password)
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

class Application(object):

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
        return raw_input(prompt)

    def read_password(self, prompt):
        # The tests replace this to make sure the right things happen.
        import getpass
        try:
            return getpass.getpass(prompt)
        except KeyboardInterrupt:
            # The cursor was left on the same line as the prompt,
            # which we don't like.  Print a blank line.
            print
            raise

    def process(self):
        options = self.options

        if not options.destination:
            destination = sys.stdout
        else:
            destination = open(options.destination, "wb")

        principal = self.get_principal()

        if destination is sys.stdout:
            print self.title
        print >>destination, principal
        print

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
                print >>sys.stderr, error
                continue
            return value

    def get_password_manager(self):
        default = 0
        self.print_message("Password manager:")
        print
        managers = self.options.managers

        for i, (name, manager) in enumerate(managers):
            print "% i. %s" % (i + 1, name)
            if name == 'SSHA':
                default = i
        print
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
            print >>sys.stderr, "You must select a password manager"
        print "%s password manager selected" % managers[index][0]
        return managers[index]

    def get_password(self):
        self.print_message(self.password_title)
        while True:
            password = self.read_password("Password: ")
            if not password:
                print >>sys.stderr, "Password may not be empty"
                continue
            if password != password.strip() or password.split() != [password]:
                print >>sys.stderr, "Password may not contain spaces"
                continue
            break
        again = self.read_password("Verify password: ")
        if again != password:
            print >>sys.stderr, "Password not verified!"
            sys.exit(1)
        return password

    def print_message(self, message):
        if self.need_blank_line:
            print
            self.need_blank_line = False
        print message

def get_password_managers(config_path=None):
    if not config_path:
        from zope.password.password import managers
    else:
        from zope.configuration import xmlconfig
        from zope.component import getUtilitiesFor
        from zope.password.interfaces import IPasswordManager

        print "Loading configuration..."
        config = xmlconfig.file(config_path)
        managers = []
        for name, manager in getUtilitiesFor(IPasswordManager):
            if name == "Plain Text":
                managers.insert(0, (name, manager))
            else:
                managers.append((name, manager))
        if not managers:
            from zope.password.password import managers
    return managers

def parse_args(argv):
    """Parse the command line, returning an object representing the input."""
    path, prog = os.path.split(os.path.realpath(argv[0]))
    p = optparse.OptionParser(prog=prog,
                              usage="%prog [options]",
                              version=VERSION)
    p.add_option("-c", "--config", dest="config", metavar="FILE",
        help=("path to the site.zcml configuration file"
        " (more accurate but slow password managers registry creation)"))
    p.add_option("-o", "--output", dest="destination", metavar="FILE",
        help=("the file in which the output will be saved"
        " (STDOUT by default)"))
    options, args = p.parse_args(argv[1:])
    options.managers = get_password_managers(options.config)
    options.program = prog
    options.version = VERSION
    if args:
        p.error("too many arguments")
    return options
