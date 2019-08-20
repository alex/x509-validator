#!/usr/bin/env python

from setuptools import setup

setup(
    name='x509-validator',
    version='0.1.0',
    description='X509 certificate validator',
    url='https://github.com/alex/x509-validator',
    author='Alex Gaynor',
    author_email='alex.gaynor@gmail.com',
    py_modules=['validator'],
    setup_requires=['pytest-runner'],
    install_requires=['cryptography >= 2.0, < 3.0', 'requests >= 2.0'],
    tests_require=['pytest'])
