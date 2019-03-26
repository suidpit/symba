from setuptools import setup

setup(
  name='symba',
  version='0.1dev',
  packages=['symba'],
  long_description=open('README.md').read(),
  install_requires=[
    'angr',
  ]
)
