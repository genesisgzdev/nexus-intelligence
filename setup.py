from setuptools import setup, find_packages
setup(
    name="nexus-intelligence",
    version="3.1.0",
    packages=find_packages(),
    install_requires=["requests", "dnspython", "cryptography", "rich", "jinja2"],
    entry_points={"console_scripts": ["nexus-intel=nexus_intelligence.__main__:main"]}
)
