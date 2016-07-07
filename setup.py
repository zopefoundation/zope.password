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
"""Setup for zope.password package
"""
import os
from setuptools import setup, find_packages

def read(*rnames):
    with open(os.path.join(os.path.dirname(__file__), *rnames)) as file:
        return file.read()

def alltests():
    import os
    import sys
    import unittest
    # use the zope.testrunner machinery to find all the
    # test suites we've put under ourselves
    import zope.testrunner.find
    import zope.testrunner.options
    here = os.path.abspath(os.path.join(os.path.dirname(__file__), 'src'))
    args = sys.argv[:]
    defaults = ["--test-path", here]
    options = zope.testrunner.options.get_options(args, defaults)
    suites = list(zope.testrunner.find.find_suites(options))
    return unittest.TestSuite(suites)

setup(name='zope.password',
      version='4.2.0',
      author='Zope Foundation and Contributors',
      author_email='zope-dev@zope.org',
      description='Password encoding and checking utilities',
      long_description=(
        read('README.rst')
        + '\n\n' +
        read('CHANGES.rst')
        ),
      url='http://pypi.python.org/pypi/zope.password',
      license='ZPL 2.1',
      classifiers = [
          'Development Status :: 5 - Production/Stable',
          'Environment :: Web Environment',
          'Intended Audience :: Developers',
          'License :: OSI Approved :: Zope Public License',
          'Programming Language :: Python',
          'Programming Language :: Python :: 2',
          'Programming Language :: Python :: 2.7',
          'Programming Language :: Python :: 3',
          'Programming Language :: Python :: 3.3',
          'Programming Language :: Python :: 3.4',
          'Programming Language :: Python :: 3.5',
          'Programming Language :: Python :: Implementation :: CPython',
          'Programming Language :: Python :: Implementation :: PyPy',
          'Natural Language :: English',
          'Operating System :: OS Independent',
          'Topic :: Internet :: WWW/HTTP',
          'Framework :: Zope3'],
      keywords='zope authentication password zpasswd',
      packages=find_packages('src'),
      package_dir = {'': 'src'},
      extras_require=dict(vocabulary=['zope.schema'],
                          test=['zope.schema', 'zope.testing'],
                          ),
      namespace_packages=['zope'],
      install_requires=['setuptools',
                        'zope.component',
                        'zope.configuration',
                        'zope.interface',
                        ],
      tests_require = [
          'zope.schema',
          'zope.testing',
          'zope.testrunner',
          ],
      test_suite = '__main__.alltests',
      include_package_data = True,
      zip_safe = False,
      entry_points="""
      [console_scripts]
      zpasswd = zope.password.zpasswd:main
      """,
      )
