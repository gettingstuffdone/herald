#!/usr/bin/env python
# -*- coding: utf-8 -*-

from setuptools import setup

setup(name='haproxy-herald',
      version='0.1.1',
      description='Haproxy load feedback and check agent',
      url='https://github.com/helpshift/herald',
      download_url='https://github.com/helpshift/herald/tarball/0.1.0',
      author='Raghu Udiyar',
      author_email='raghusiddarth@gmail.com',
      license='MIT',
      packages=['herald', 'herald.plugins'],
      install_requires=['gevent>=1.3.3',
                        'pyyaml>=3.11',
                        'psutil>=5.4.6',
                        'future>=0.16.0',
                        ],
      package_data={'herald.plugins': ['*.py']},
      entry_points={
          'console_scripts': [
              'herald = herald.herald:main'
          ]
      },
      keywords=['Haproxy']
      )
