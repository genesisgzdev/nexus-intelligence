# Contributing to Nexus Intelligence

## Standards
- **Asynchronous Patterns**: All new modules MUST inherit from \BaseModule\ and implement the \sync run()\ method. 
- **Zero-API Mandate**: Do not introduce dependencies on external REST APIs for intelligence gathering. Use direct protocols (DNS, TCP, SMTP, etc.) whenever possible.
- **Type Safety**: Utilize Pydantic for configuration validation and explicit type hinting across the codebase.

## Local Environment
1. **Requirements**: Python 3.11+, Docker.
2. **Setup**: \pip install -r requirements.txt\.
3. **Linting**: We adhere to strict PEP8 formatting with professional, technical English documentation.
