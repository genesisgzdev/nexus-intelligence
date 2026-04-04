# Contributing to Nexus Intelligence

First off, thank you for considering contributing to the **Nexus Intelligence Framework**. It's people like you who make this a great security tool.

## Code of Conduct

By participating in this project, you agree to abide by our Code of Conduct.

## How Can I Contribute?

### Reporting Bugs
- Use the GitHub issue tracker.
- Provide a clear summary and steps to reproduce.

### Suggesting Enhancements
- Open an issue with the [Enhancement] tag.
- Describe the feature and why it would be useful.

### Pull Requests
1. Fork the repo and create your branch from `main`.
2. If you've added code that should be tested, add tests.
3. Ensure the test suite passes.
4. Format your code using `black`.
5. Write clear commit messages.

## Style Guide
- Follow PEP 8.
- Use type hints for all function signatures.
- Document classes and methods using Google-style docstrings.

## Zero-API Mandate
All new modules MUST follow the **Zero-API** mandate: no third-party APIs for intelligence gathering. Use direct protocols (DNS, TCP/IP, HTTP) whenever possible.
