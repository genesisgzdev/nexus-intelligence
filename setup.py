#!/usr/bin/env python3
from setuptools import setup, find_packages

setup(
    name='osint-intelligence',
    version='4.0.0',
    author='Genesis GZ',
    author_email='genzt.dev@pm.me',
    description='OSINT Intelligence Framework',
    packages=find_packages(),
    python_requires='>=3.8',
    install_requires=[
        'requests>=2.28.0',
        'dnspython>=2.3.0',
        'python-whois>=0.7.3',
        'jinja2>=3.0.0',
        'beautifulsoup4>=4.11.0',
        'rich>=13.0.0',
        'python-dotenv>=1.0.0',
        'lxml>=4.9.0',
        'aiohttp>=3.8.0',
    ],
    entry_points={
        'console_scripts': [
            'osint=src.osinth:main',
        ],
    },
)
