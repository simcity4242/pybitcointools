#!/usr/bin/env python
try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup

setup(name='bitcoin',
      version='2.6.11',
      description='Python Bitcoin Tools',
      author='simcity fork of Vitalik Buterin',
      author_email='vbuterin@gmail.com',
      url='http://github.com/simcity4242/pybitcointools',
      packages=['bitcoin'],
      scripts=['pybtctool'],
      include_package_data=True,
      data_files=[("", ["LICENSE"])],
      )
