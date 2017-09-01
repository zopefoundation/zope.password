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

VOCABULARY_REQUIRES = [
    'zope.schema',
]

BCRYPT_REQUIRES = [
    'bcrypt',
]

TESTS_REQUIRE = VOCABULARY_REQUIRES + BCRYPT_REQUIRES + [
    'zope.security',
    'zope.testing',
    'zope.testrunner',
]

setup(name='zope.password',
      version='4.3.1',
      author='Zope Foundation and Contributors',
      author_email='zope-dev@zope.org',
      description='Password encoding and checking utilities',
      long_description=(
          read('README.rst')
          + '\n\n' +
          read('CHANGES.rst')
      ),
      url='http://github.com/zopefoundation/zope.password',
      license='ZPL 2.1',
      classifiers=[
          'Development Status :: 5 - Production/Stable',
          'Environment :: Web Environment',
          'Intended Audience :: Developers',
          'License :: OSI Approved :: Zope Public License',
          'Programming Language :: Python',
          'Programming Language :: Python :: 2',
          'Programming Language :: Python :: 2.7',
          'Programming Language :: Python :: 3',
          'Programming Language :: Python :: 3.4',
          'Programming Language :: Python :: 3.5',
          'Programming Language :: Python :: 3.6',
          'Programming Language :: Python :: Implementation :: CPython',
          'Programming Language :: Python :: Implementation :: PyPy',
          'Natural Language :: English',
          'Operating System :: OS Independent',
          'Topic :: Internet :: WWW/HTTP',
          'Framework :: Zope3',
      ],
      keywords='zope authentication password zpasswd',
      packages=find_packages('src'),
      package_dir={'': 'src'},
      extras_require={
          'vocabulary': VOCABULARY_REQUIRES,
          'test': TESTS_REQUIRE,
          'bcrypt': BCRYPT_REQUIRES,
          'docs': [
              'Sphinx',
              'repoze.sphinx.autointerface',
          ]
      },
      namespace_packages=['zope'],
      install_requires=[
          'setuptools',
          'zope.component',
          'zope.configuration',
          'zope.interface',
      ],
      tests_require=TESTS_REQUIRE,
      include_package_data=True,
      zip_safe=False,
      entry_points="""
      [console_scripts]
      zpasswd = zope.password.zpasswd:main
      """,
      python_requires='>=2.7.7,!=3.0.*,!=3.1.*,!=3.2.*,!=3.3.*',
)
