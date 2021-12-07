#!/usr/bin/env python3

from setuptools import setup, find_packages
from setuptools.command.install import install
from setuptools.command.develop import develop

setup(name='pandare_pyplugins',
      version='0.0.1',
      description='A collection of reusable PyPlugins for PANDA.re',
      author='Andrew Fasano',
      author_email='fasano@mit.edu',
      url='https://github.com/panda-re/pypanda-plugins',
      packages=find_packages(),
      #install_requires=[ 'pandare>=0.1.1.3' ],
      cmdclass={'install': install, 'develop': develop},
     )
