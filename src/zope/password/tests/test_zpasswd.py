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
"""Tests for the zpasswd script.
"""
import contextlib
import doctest
import io
import os
import sys
import tempfile
import unittest

from zope.password import password
from zope.password import zpasswd


class TestBase(unittest.TestCase):

    stdin = None
    stdout = None
    stderr = None

    old_stderr = None
    old_stdout = None
    old_stdin = None

    def setUp(self):
        # Create a minimal site.zcml file
        with tempfile.NamedTemporaryFile(prefix="testsite",
                                         suffix=".zcml",
                                         delete=False) as f:
            f.write(
                b"""<configure xmlns="http://namespaces.zope.org/zope">
                  <include file="configure.zcml" package="zope.password" />
                </configure>
                """)
            self.config = f.name
            self.addCleanup(os.remove, f.name)

    @contextlib.contextmanager
    def patched_stdio(self, input_data=None):
        self.stdout = io.StringIO()
        self.stderr = io.StringIO()

        self.old_stdout = sys.stdout
        self.old_stderr = sys.stderr
        self.old_stdin = sys.stdin
        sys.stdout = self.stdout
        sys.stderr = self.stderr

        if input_data is not None:
            self.stdin = io.StringIO(input_data)
            sys.stdin = self.stdin

        try:
            yield
        finally:
            sys.stdout = self.old_stdout
            sys.stderr = self.old_stderr
            sys.stdin = self.old_stdin

    @contextlib.contextmanager
    def patched_getpass(self, func):
        import getpass
        orig_gp = getpass.getpass
        getpass.getpass = func

        try:
            yield
        finally:
            getpass.getpass = orig_gp


class ArgumentParsingTestCase(TestBase):

    def parse_args(self, args):
        argv = ["foo/bar.py"] + args
        with self.patched_stdio():
            options = zpasswd.parse_args(argv)

        self.assertEqual(options.program, "bar.py")
        return options

    def check_stdout_content(self, args, stderr=False):
        with self.assertRaises(SystemExit) as e:
            self.parse_args(args)

        e = e.exception
        self.assertEqual(e.code, 0)
        full = self.stdout
        empty = self.stderr
        if stderr:
            full = self.stderr
            empty = self.stdout
        self.assertTrue(full.getvalue())
        self.assertFalse(empty.getvalue())

    def test_no_arguments(self):
        options = self.parse_args([])
        self.assertTrue(options.managers)
        self.assertIs(options.destination, self.stdout)

    def test_version_long(self):
        self.check_stdout_content(["--version"], stderr=False)

    def test_help_long(self):
        self.check_stdout_content(["--help"])

    def test_help_short(self):
        self.check_stdout_content(["-h"])

    def test_destination_short(self, option="-o"):
        handle, path = tempfile.mkstemp()
        os.close(handle)
        self.addCleanup(os.remove, path)
        options = self.parse_args([option, path])
        try:
            self.assertEqual(options.destination.name, path)
        finally:
            options.destination.close()

    def test_destination_long(self):
        self.test_destination_short("--output")

    def test_config_short(self):
        options = self.parse_args(["-c", self.config])
        self.assertTrue(options.managers)

    def test_config_long(self):
        options = self.parse_args(["--config", self.config])
        self.assertTrue(options.managers)

    def test_too_many_arguments(self):
        with self.assertRaises(SystemExit):
            self.parse_args(["--config", self.config, "extra stuff"])

        self.assertIn("unrecognized arguments",
                      self.stderr.getvalue())

    def test_main(self):
        with self.patched_stdio():
            x = zpasswd.main(['foo/bar.py', '--help'])
        self.assertEqual(x, 0)

        with self.patched_stdio():
            x = zpasswd.main(['foo/bar.py', '--no-such-argument'])
        self.assertEqual(x, 2)


class ControlledInputApplication(zpasswd.Application):

    def __init__(self, options, input_lines):
        super().__init__(options)
        self.__input = input_lines

    def read_input_line(self, prompt):
        return self.__input.pop(0)

    read_password = read_input_line

    def all_input_consumed(self):
        return not self.__input


class Options:

    config = None
    program = "[test-program]"
    managers = password.managers

    def __init__(self):
        self.destination = sys.stdout


class InputCollectionTestCase(TestBase):

    def createOptions(self):
        return Options()

    def _get_output(self):
        return self.stdout.getvalue()

    def _check_principal(self, expected, output=None):
        output = self._get_output()
        self.assertTrue(output)

        principal_lines = output.splitlines()[-(len(expected) + 1):-1]
        for line, expline in zip(principal_lines, expected):
            self.assertEqual(line.strip(), expline)

    def test_principal_information(self):
        apps = []

        def factory(options):
            app = ControlledInputApplication(
                options,
                ["id", "title", "login", "1",
                 "passwd", "passwd", "description"])
            apps.append(app)
            return app
        with self.patched_stdio():
            options = self.createOptions()
            zpasswd.run_app_with_options(options, factory)
        self.assertFalse(self.stderr.getvalue())
        self.assertTrue(apps[0].all_input_consumed())
        self._check_principal([
            '<principal',
            'id="id"',
            'title="title"',
            'login="login"',
            'password="passwd"',
            'description="description"',
            '/>'
        ])


class TestDestination(InputCollectionTestCase):

    destination = None

    def createOptions(self):
        opts = Options()
        destination = tempfile.NamedTemporaryFile(mode='w',
                                                  suffix=".test_zpasswd",
                                                  delete=False)
        self.addCleanup(os.remove, destination.name)
        self.destination = opts.destination = destination
        return opts

    def _get_output(self):
        with open(self.destination.name) as f:
            return f.read()


class TestRunAndApplication(TestBase):

    def test_keyboard_interrupt(self):
        class App:
            def __init__(self, options):
                self.options = options

            def process(self):
                raise KeyboardInterrupt()
        with self.patched_stdio():
            x = zpasswd.run_app_with_options(None, App)

        self.assertEqual(x, 1)

    def test_exit(self):
        class App:
            def __init__(self, options):
                self.options = options

            def process(self):
                raise SystemExit(42)
        with self.patched_stdio():
            x = zpasswd.run_app_with_options(None, App)

        self.assertEqual(x, 42)

        # Now via main
        parse_args = zpasswd.parse_args
        zpasswd.parse_args = lambda x: x
        try:
            x = zpasswd.main(argv=[], app_factory=App)
        finally:
            zpasswd.parse_args = parse_args

        self.assertEqual(x, 42)

    def test_read_input(self):
        with self.patched_stdio(input_data="hi there"):
            x = zpasswd.Application(None).read_input_line("")
        self.assertEqual(x, "hi there")

    def test_get_value(self):
        # No error message
        with self.patched_stdio(input_data="\n"):
            x = zpasswd.Application(None).get_value("", "")
        self.assertEqual(x, "")

        # With error message we retry
        with self.patched_stdio(input_data="\nYup"):
            x = zpasswd.Application(None).get_value("", "", error="Error")
        self.assertEqual(x, "Yup")

    def test_read_password(self):
        with self.patched_getpass(lambda _prompt: sys.stdin.read()):
            with self.patched_stdio(input_data="hi there"):
                x = zpasswd.Application(None).read_password("")
            self.assertEqual(x, "hi there")

    def test_read_password_cancel(self):
        def gp(_prompt):
            raise KeyboardInterrupt()

        with self.patched_getpass(gp):
            with self.patched_stdio(input_data="hi there"):
                with self.assertRaises(KeyboardInterrupt):
                    zpasswd.Application(None).read_password("")

        self.assertEqual(self.stdout.getvalue(), '\n')

    def test_get_passwd_empty(self):
        passwords = ['', 'abc', 'abc']
        passwords.reverse()

        def gp(_prompt):
            return passwords.pop()

        with self.patched_getpass(gp):
            with self.patched_stdio():
                x = zpasswd.Application(None).get_password()
        self.assertEqual(x, 'abc')
        self.assertEqual(self.stderr.getvalue(),
                         "Password may not be empty\n")

    def test_get_passwd_spaces(self):
        passwords = [' with spaces ', 'abc', 'abc']
        passwords.reverse()

        def gp(_prompt):
            return passwords.pop()

        with self.patched_getpass(gp):
            with self.patched_stdio():
                x = zpasswd.Application(None).get_password()
        self.assertEqual(x, 'abc')
        self.assertEqual(self.stderr.getvalue(),
                         "Password may not contain spaces\n")

    def test_get_passwd_verify_fail(self):
        passwords = ['abc', 'def']
        passwords.reverse()

        def gp(_prompt):
            return passwords.pop()

        with self.patched_getpass(gp):
            with self.patched_stdio():
                with self.assertRaises(SystemExit):
                    zpasswd.Application(None).get_password()
        self.assertEqual(self.stderr.getvalue(),
                         "Password not verified!\n")

    def test_get_password_manager_default(self):
        with self.patched_stdio(input_data='\n'):
            manager = zpasswd.Application(Options()).get_password_manager()
        self.assertEqual(manager[0], 'BCRYPT')

    def test_get_password_manager_bad(self):
        with self.patched_stdio(input_data='HI\n1'):
            manager = zpasswd.Application(Options()).get_password_manager()
        self.assertEqual(manager[0], 'Plain Text')
        self.assertEqual(self.stderr.getvalue(),
                         'You must select a password manager\n')


def test_suite():
    suite = doctest.DocTestSuite('zope.password.zpasswd')
    suite.addTest(unittest.defaultTestLoader.loadTestsFromName(__name__))
    return suite
