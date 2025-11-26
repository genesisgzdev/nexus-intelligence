Contributing to the OSINT Intelligence Framework

1. Development Philosophy

We build tools that matter. Every contribution must significantly enhance the framework's intelligence gathering capabilities, improve operational security, or expand platform coverage.

We have a Zero-Tolerance policy for non-functional complexity. We do not accept cosmetic changes or "refactoring for refactoring's sake"—every line of code must serve a critical, verifiable purpose in the reconnaissance pipeline.

2. Getting Started

Prerequisites

Before contributing, ensure your development environment meets the following rigorous standards:

Development Environment

Python 3.8+ with pip.

Git 2.30+ with GPG signing configured (Mandatory for all commits).

Isolated environment (venv, virtualenv, or conda).

Required Toolchain for Quality Assurance (QA)

Tool

Minimum Version

Purpose

pytest

>= 7.0.0

Execution of unit and integration tests.

pytest-cov

>= 4.0.0

Code coverage measurement.

black

>= 23.0.0

Automatic code formatter.

flake8

>= 6.0.0

Static linter.

mypy

>= 1.0.0

Static type checker.

bandit

>= 1.7.0

Security linter.

Vulnerability Scanning Tools

safety >= 2.3.0

pip-audit >= 2.5.0

semgrep >= 1.0.0

Environment Setup

Follow this sequence exactly to set up your isolated development workspace:

# 1. Clone your fork and enter the directory
git clone [https://github.com/yourusername/nexus-intelligence.git](https://github.com/yourusername/nexus-intelligence.git)
cd nexus-intelligence

# 2. Create isolated environment
python -m venv venv
source venv/bin/activate    # Linux/macOS
venv\Scripts\activate       # Windows

# 3. Install development dependencies
pip install -r requirements-dev.txt

# 4. Configure pre-commit hooks for automated linting/formatting
pre-commit install

# 5. Verify setup by running a core test
pytest tests/unit/test_core.py


3. Contribution Guidelines

Accepted Contribution Types

Contributions are prioritized based on verifiable impact:

High-Priority (Tier 1 - Immediate Review)

New platform modules with 95%+ detection accuracy (must be benchmarked).

Credential pattern detection for emerging or specialized services.

Anti-detection and evasion techniques that demonstrably bypass platform security measures.

Performance optimizations with benchmarks proving >20% throughput/latency improvement.

Security vulnerabilities reported with Proof of Concept (PoC) and a complete fix.

Exhaustive documentation for undocumented complex functions.

Medium-Priority (Tier 2 - Scheduled Review)

Bug fixes accompanied by regression tests that guarantee the issue will not return.

Additional export formats (.csv, .xml, custom) with real-world use cases.

Cache optimization strategies (e.g., LRU eviction, dynamic TTL).

Robust error handling and rate limiting retry logic improvements.

Unacceptable Contribution Types (Rejection Policy)

Cosmetic code changes without verifiable functional or security improvement.

Dependencies that add <5% value but increase the attack surface or deployment complexity.

"Clean code" refactoring that does not tangibly improve performance or maintainability.

Generic features that do not directly align with the framework's advanced OSINT objectives.

AI-generated code without full, line-by-line human verification and GPG signature.

4. Code Standards

Python Style Guide (Mandatory)

All submitted code must strictly adhere to the following template and requirements.

# Module structure template
"""
Module description with specific technical details.

Technical Details:
    - Implementation approach (e.g., utilizes requests session pooling, custom regex).
    - Performance considerations (e.g., time complexity, memory footprint).
    - Security implications (e.g., proxy handling, input validation).
    - Known limitations (e.g., only detects public profiles, rate limits).

Author: Your Actual Name (not "contributor")
Created: 2025-11-26
Modified: 2025-11-26
"""

import standard_library_modules
import third_party_modules

from local_modules import specific_imports

# Constants (module level, MUST use all caps with underscores)
API_TIMEOUT = 30  # seconds, based on p95 response times
MAX_RETRIES = 5   # exponential backoff: 2, 4, 8, 16, 32 seconds
CACHE_TTL = 3600  # 1 hour, balances freshness vs API limits

# Type hints are mandatory for all functions and public attributes
from typing import Dict, List, Optional, Tuple, Set, Union


class IntelModule:
    """
    Intelligence module for platform X.

    Explain exactly what this does, how it bypasses rate limits, what
    patterns it detects, and why it's structured this way.

    Attributes:
        http: HTTPEngine instance with connection pooling.
        cache: LRU cache for response deduplication.
        patterns: Compiled regex patterns for credential detection.

    Performance Metrics (Required):
        - Average response time: 2.3s
        - Memory footprint: 15MB
        - API calls per investigation: 5-10
    """

    def __init__(self, http_engine: HTTPEngine, cache: Optional[CacheManager] = None):
        """
        Initialize with explicit dependency injection.

        Args:
            http_engine: Shared HTTP client with retry logic and connection pooling.
            cache: Optional cache manager for response storage.

        Raises:
            ConfigurationError: If required API keys or configuration settings are missing.
        """
        self.http = http_engine
        self.cache = cache or CacheManager(ttl=self.CACHE_TTL)
        self._validate_configuration()

    def investigate(self, target: str) -> Dict[str, Union[str, List, Dict]]:
        """
        Investigate target on platform.

        Implementation notes:
            1. Check cache to avoid redundant API calls.
            2. Validate target format before making any request.
            3. Parse response with defensive programming.
            4. Extract intelligence with pattern matching.
            5. Calculate dynamic risk score based on findings.

        Args:
            target: Username, email, or domain to investigate.

        Returns:
            Dictionary containing 'found', 'profile' metadata, 'risk_indicators', and 'raw_data' (sanitized).

        Raises:
            RateLimitError: If platform rate limit is consistently exceeded.
            InvalidTargetError: If target format is invalid.
        """
        # Implementation with robust error handling
        pass


5. Testing Requirements

Every module requires comprehensive, high-quality tests to ensure stability and performance.

Test Directory Structure

All tests must be placed in the tests/ directory and adhere to this strict structure:

tests/
├── unit/             # Fast, isolated tests for core logic (http, cache, patterns)
│   ├── test_http_engine.py
│   ├── test_cache.py
│   └── test_patterns.py
├── integration/      # Module interaction tests (may require network/API keys)
│   ├── test_github_intel.py
│   ├── test_breach_intel.py
│   └── test_correlation.py
├── performance/      # Benchmark tests for performance regression detection
│   ├── test_cache_perf.py
│   └── test_http_perf.py
├── security/         # Security-specific tests (SSRF, Injection, Auth)
│   ├── test_ssrf.py
│   ├── test_injection.py
│   └── test_auth.py
└── fixtures/         # Static test data
    ├── responses/
    ├── patterns/
    └── profiles/


Test Quality Requirements

# Minimum coverage thresholds (Mandatory)
COVERAGE_REQUIREMENTS = {
    'unit': 90,       # Core logic
    'integration': 75,    # Module interactions
    'overall': 85     # Total coverage
}

# Performance baselines (Regression detection)
PERFORMANCE_BASELINES = {
    'http_request': 2.0,    # seconds
    'cache_lookup': 0.001,  # seconds
    'pattern_match': 0.01,  # seconds
    'full_investigation': 60.0  # seconds
}


6. Commit Standards

Commit Message Format (Conventional Commits)

# Format:
<type>(<scope>): <subject> [<issue>]

<body>

<footer>


Accepted Commit Types

Type

Description

feat

New intelligence module or major feature.

fix

Bug fix with security or functional impact.

perf

Performance improvement with proven metrics.

security

Security vulnerability patch.

refactor

Code restructure that improves maintainability.

test

Test additions or fixes to the existing suite.

docs

Documentation for complex functionality or architecture.

chore

Build, CI, dependency updates, or toolchain configuration.

Commit Examples

# Feature commit
feat(github): Add credential detection for JWT tokens [#142]

Implemented regex pattern matching for JWT tokens in GitHub repositories.
Scans repository descriptions, README files, and recent commit messages.

Detection rate: 94% based on test corpus of 1000 known exposures.
False positive rate: <2% verified against legitimate base64 strings.

Performance impact: +0.3s average scan time per repository.

Closes #142


# Security fix
security(http): Prevent SSRF via proxy configuration [#256]

Validates proxy URLs against private IP ranges before connection.
Blocks requests to:
- 127.0.0.0/8 (loopback)
- 10.0.0.0/8 (private)
- 172.16.0.0/12 (private)
- 192.168.0.0/16 (private)
- 169.254.0.0/16 (link-local)

CVE-2025-XXXX: High severity SSRF in proxy handling

Fixes #256


7. Code Review Process

Local Execution Pre-PR

You must run and pass all quality checks locally before opening a Pull Request:

# Run all quality checks locally
make lint          # flake8, black, isort
make type-check    # mypy type validation
make security      # bandit, safety, pip-audit
make test          # pytest with coverage
make test-integration # Full integration tests

# Verification of specific standards (Mandatory detailed check)
pytest tests/unit/ --cov=src --cov-report=term-missing
black --check src/ tests/
flake8 src/ tests/ --max-line-length=100
mypy src/ --strict
bandit -r src/ -ll
safety check


Pull Request (PR) Requirements

Clear Purpose: Links to the issue it resolves and justifies the change's necessity.

Tests Included: Unit tests with >90% coverage for new code and performance benchmarks (if applicable).

Complete Documentation: Docstrings for all public functions/classes, and necessary updates to the README/CHANGELOG.

Checks Passed: CI/CD pipeline green, no merge conflicts, and GPG-signed commits.

Demonstrable Impact: Performance metrics or documented security improvement analysis.

PR Template (Mandatory Use)

## Description
[Describe what this PR does and why it's needed, focusing on technical impact.]

## Type of Change
- [ ] Bug fix (non-breaking change fixing an issue)
- [ ] New feature (non-breaking change adding functionality)
- [ ] Breaking change (fix or feature that would cause existing functionality to not work as expected)
- [ ] Security fix (vulnerability patch)

## Testing
- [ ] Unit tests pass locally with >90% coverage
- [ ] Integration tests pass (requires API/Network)
- [ ] Security scan clean (bandit, safety)

## Performance Impact
[Include benchmarks showing before/after metrics, or state N/A.]

## Security Considerations
[Explain any security implications or mitigations applied.]

## Checklist
- [ ] My code follows the project's style guidelines and documentation requirements.
- [ ] I have performed a self-review and verified the security impact.
- [ ] I have commented complex code sections.
- [ ] I have made corresponding documentation and CHANGELOG changes.
- [ ] New and existing unit tests pass locally.
- [ ] Dependent changes have been merged.

## Evidence
[Screenshots, logs, or benchmarks proving the fix works or feature is complete.]

Fixes #[issue number]


8. Security Vulnerability Reporting

DO NOT open a public issue for security vulnerabilities.

Email genzt.dev@pm.me with the subject line "Vulnerability Report: [Module Name]". The report must include:

Vulnerability description.

Proof of Concept (PoC) script or steps to reproduce.

Impact assessment (High, Medium, Low severity).

Suggested fix if available.

Mandatory Protocol:

Use PGP encryption for sensitive details.

Allow 90 days for patching before any public disclosure.

Credit will be received in the official security advisory.

9. Release Process

Version Numbering

We use semantic versioning with security patch priority:

MAJOR.MINOR.PATCH-SECURITY

4.1.0        - New features
4.1.1        - Bug fixes
4.1.1-sec1   - Security patch


Release Checklist (Maintainer)

# 1. Update version number
bump2version minor  # or major, patch, depending on changes

# 2. Update the CHANGELOG entry
echo "## [4.1.0] - $(date +%Y-%m-%d)" >> CHANGELOG.md

# 3. Run full test suite and security audit
make test-all
make security-scan

# 4. Build and test distribution packages
python setup.py sdist bdist_wheel
twine check dist/*

# 5. Tag and sign the release in Git
git tag -s v4.1.0 -m "Release v4.1.0"
git push origin v4.1.0

# 6. Create GitHub release with complete documentation of changes


10. Development Resources

Module Development Guide

When creating a new intelligence module, follow these mandatory steps:

Research Platform API: Authentication methods, rate limits, response formats, and error codes.

Implement Detection Logic: Profile existence validation, critical metadata extraction, robust error handling, and rate limit compliance.

Add Credential Patterns: Platform-specific tokens and API key formats.

Create Tests: Mocked API responses, edge cases, error conditions, and performance benchmarks.

Document Thoroughly: API limitations, detection accuracy, false positive rate, and evasion techniques used (in Docstrings).

Architecture Decisions

Significant architectural changes must be documented as an Architecture Decision Record (ADR) in docs/architecture/.

# ADR-001: HTTP Connection Pooling

## Status
Accepted

## Context
Need to optimize HTTP performance across 200+ platform checks to reduce investigation time per target.

## Decision
Implement request session-based connection pooling with a maximum of 30 concurrent connections.

## Consequences
- 40% reduction in connection overhead (TCP handshake).
- 2.5x faster batch processing speed.
- ~100MB memory overhead for connection pool management.


Contact

Category

Email Address

Notes

Project Maintainer (General Queries, Feature Discussion)

genzt.dev@pm.me



Security Issues (Vulnerability Disclosure ONLY)

genzt.dev@pm.me

PGP encryption is Mandatory for sensitive details.

General Discussion

GitHub Discussion

For open discussion on new features and design.
