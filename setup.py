# -*- coding: utf-8 -*-
from setuptools import setup, find_packages

with open("README.md", "r") as fh:
    long_description = fh.read()


requirements = ["smda"]


setup(
    name='picblocks',
    version='1.1.1',
    description='A library for code similarity estimation using PIC hashing over basic blocks.',
    long_description_content_type="text/markdown",
    long_description=long_description,
    author='Daniel Plohmann',
    author_email='daniel.plohmann@mailbox.org',
    url='https://github.com/danielplohmann/picblocks',
    license="BSD 2-Clause",
    packages=find_packages(exclude=('tests')),
    data_files=[
        ('', ['LICENSE']),
    ],
    install_requires=requirements,
    classifiers=[
        "Development Status :: 4 - Beta",
        "License :: OSI Approved :: BSD License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3",
        "Topic :: Security",
        "Topic :: Software Development :: Disassemblers",
    ],
    python_requires=">=3.6",
)