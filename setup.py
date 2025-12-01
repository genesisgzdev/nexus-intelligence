#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from setuptools import setup, find_packages
from pathlib import Path

# Read long description from README
readme_file = Path(__file__).parent / "README.md"
long_description = readme_file.read_text(encoding="utf-8") if readme_file.exists() else ""

setup(
    name="nexus-intelligence",
    version="1.0.0",
    author="Genesis",
    author_email="genzt.dev@pm.me",
    description="Enterprise-grade OSINT intelligence gathering framework for security researchers",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/genesisgzdev/nexus-intelligence",
    project_urls={
        "Bug Reports": "mailto:genesis.issues@pm.me",
        "Source": "https://github.com/genesisgzdev/nexus-intelligence",
        "Documentation": "https://github.com/genesisgzdev/nexus-intelligence/wiki",
    },
    packages=find_packages(exclude=["tests*", "docs*", "examples*"]),
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Information Technology",
        "Intended Audience :: Science/Research",
        "Topic :: Security",
        "Topic :: Internet :: WWW/HTTP :: Indexing/Search",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Operating System :: OS Independent",
        "Natural Language :: English",
    ],
    python_requires=">=3.8",
    install_requires=[
        "requests>=2.31.0",
        "urllib3>=2.2.1",
        "dnspython>=2.6.0",
        "python-whois>=0.8.0",
        "beautifulsoup4>=4.12.3",
        "lxml>=5.1.0",
        "jinja2>=3.1.3",
        "rich>=13.7.0",
        "python-dotenv>=1.0.1",
        "certifi>=2024.2.2",
        "chardet>=5.2.0",
        "aiohttp>=3.9.0",
    ],
    extras_require={
        "dev": [
            "pytest>=8.0.0",
            "pytest-cov>=4.1.0",
            "black>=24.0.0",
            "flake8>=7.0.0",
            "mypy>=1.8.0",
            "pylint>=3.0.0",
            "isort>=5.13.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "nexus-intel=src.osinth:main",
        ],
    },
    keywords=[
        "osint",
        "intelligence",
        "reconnaissance",
        "security",
        "penetration-testing",
        "information-gathering",
        "github-osint",
        "dns-reconnaissance",
        "social-media-osint",
        "breach-intelligence",
    ],
    license="MIT",
    zip_safe=False,
)
