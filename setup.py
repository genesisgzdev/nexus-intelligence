from setuptools import setup, find_packages

setup(
    name="nexus-intelligence",
    version="2.0.0",
    packages=find_packages(),
    install_requires=[
        "requests>=2.31.0",
        "dnspython>=2.6.0",
        "cryptography>=42.0.0",
        "rich>=13.7.0",
        "jinja2>=3.1.3",
    ],
    entry_points={
        "console_scripts": [
            "nexus-intel=nexus_intelligence.__main__:main",
        ],
    },
    author="Genesis",
    description="Professional Zero-API OSINT Framework",
    python_requires=">=3.8",
)
