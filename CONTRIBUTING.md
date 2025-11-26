Contributing
Development Philosophy
We build tools that matter. Every contribution should enhance the framework's intelligence gathering capabilities, improve operational security, or expand platform coverage. We don't accept cosmetic changes or "refactoring for refactoring's sake" - every line of code must serve a purpose in the reconnaissance pipeline.
Getting Started
Prerequisites
Before contributing, ensure you have:
bash# Development environment
Python 3.8+ with pip
Git 2.30+ with GPG signing configured
Virtual environment (venv/virtualenv/conda)

# Testing tools
pytest >= 7.0.0
pytest-cov >= 4.0.0
pytest-asyncio >= 0.21.0
black >= 23.0.0
flake8 >= 6.0.0
mypy >= 1.0.0
bandit >= 1.7.0

# Security tools
safety >= 2.3.0
pip-audit >= 2.5.0
semgrep >= 1.0.0
Environment Setup
bash# Clone your fork
git clone https://github.com/yourusername/nexus-intelligence.git
cd nexus-intelligence

# Create isolated environment
python -m venv venv
source venv/bin/activate  # Linux/macOS
venv\Scripts\activate     # Windows

# Install development dependencies
pip install -r requirements-dev.txt

# Configure pre-commit hooks
pre-commit install

# Verify setup
pytest tests/unit/test_core.py
Contribution Guidelines
What We Accept
High-Priority Contributions:

New platform modules with 95%+ detection accuracy
Credential pattern detection for emerging services
Anti-detection evasion techniques that actually work
Performance optimizations with benchmarks proving >20% improvement
Security vulnerabilities with POC and fix
Documentation for undocumented complex functions

Medium-Priority Contributions:

Bug fixes with regression tests
Additional export formats with real use cases
Cache optimization strategies
Rate limiting improvements
Error handling enhancements

We Don't Accept:

Cosmetic code changes without functional improvement
Dependencies that add <5% value but increase attack surface
"Clean code" refactoring that doesn't improve performance
Generic features that don't align with OSINT objectives
AI-generated code without human verification

Code Standards
Python Style Guide
python# Module structure
"""
Module description with actual technical details.

Technical Details:
    - Implementation approach
    - Performance considerations
    - Security implications
    - Known limitations

Author: Your actual name (not "contributor")
Created: 2025-11-26
Modified: 2025-11-26
"""

import standard_library_modules
import third_party_modules

from local_modules import specific_imports

# Constants (module level)
API_TIMEOUT = 30  # seconds, based on p95 response times
MAX_RETRIES = 5   # exponential backoff: 2, 4, 8, 16, 32
CACHE_TTL = 3600  # 1 hour, balances freshness vs API limits

# Type hints are mandatory
from typing import Dict, List, Optional, Tuple, Set, Union


class IntelModule:
    """
    Intelligence module for platform X.
    
    This isn't generic documentation - explain exactly what this does,
    how it bypasses rate limits, what patterns it detects, and why
    it's structured this way.
    
    Attributes:
        http: HTTPEngine instance with connection pooling
        cache: LRU cache for response deduplication
        patterns: Compiled regex patterns for credential detection
    
    Performance:
        - Average response time: 2.3s
        - Memory footprint: 15MB
        - API calls per investigation: 5-10
    """
    
    def __init__(self, http_engine: HTTPEngine, cache: Optional[CacheManager] = None):
        """
        Initialize with dependency injection.
        
        Args:
            http_engine: Shared HTTP client with retry logic
            cache: Optional cache manager for response storage
        
        Raises:
            ConfigurationError: If required API keys missing
        """
        self.http = http_engine
        self.cache = cache or CacheManager(ttl=self.CACHE_TTL)
        self._validate_configuration()
    
    def investigate(self, target: str) -> Dict[str, Union[str, List, Dict]]:
        """
        Investigate target on platform.
        
        Implementation notes:
            1. Check cache to avoid redundant API calls
            2. Validate target format before request
            3. Parse response with defensive programming
            4. Extract intelligence with pattern matching
            5. Calculate risk score based on findings
        
        Args:
            target: Username, email, or domain to investigate
        
        Returns:
            Dictionary containing:
                - found: Boolean indicating if target exists
                - profile: Profile metadata if available
                - risk_indicators: List of security concerns
                - raw_data: Sanitized API response
        
        Raises:
            RateLimitError: If platform rate limit exceeded
            InvalidTargetError: If target format invalid
        """
        # Implementation with actual error handling
        pass
Testing Requirements
Every module needs comprehensive tests:
python# tests/test_module_name.py

import pytest
from unittest.mock import Mock, patch
from freezegun import freeze_time

class TestIntelModule:
    """Test intelligence module functionality."""
    
    @pytest.fixture
    def module(self):
        """Initialize module with mocked dependencies."""
        http_mock = Mock(spec=HTTPEngine)
        return IntelModule(http_mock)
    
    def test_successful_investigation(self, module):
        """Test successful target investigation."""
        # Arrange: Set up mocks with realistic responses
        module.http.get.return_value = Mock(
            status_code=200,
            json=lambda: {"user": "found", "id": 12345}
        )
        
        # Act: Execute investigation
        result = module.investigate("testuser")
        
        # Assert: Verify behavior, not just output
        assert result['found'] is True
        assert module.http.get.call_count == 1
        assert 'profile' in result
        
    def test_rate_limit_handling(self, module):
        """Test exponential backoff on rate limits."""
        module.http.get.side_effect = [
            Mock(status_code=429, headers={'Retry-After': '2'}),
            Mock(status_code=429, headers={'Retry-After': '4'}),
            Mock(status_code=200, json=lambda: {"found": True})
        ]
        
        with patch('time.sleep') as mock_sleep:
            result = module.investigate("testuser")
            
        # Verify exponential backoff was applied
        assert mock_sleep.call_args_list == [call(2), call(4)]
        assert result['found'] is True
        
    @freeze_time("2025-11-26 10:00:00")
    def test_cache_expiration(self, module):
        """Test cache TTL expiration."""
        # Test implementation
        pass
    
    def test_credential_pattern_detection(self, module):
        """Test all credential patterns with real examples."""
        test_cases = [
            ("AKIAIOSFODNN7EXAMPLE", "AWS_ACCESS_KEY"),
            ("ghp_x" * 9, "GITHUB_TOKEN"),
            ("sk_live_" + "x" * 24, "STRIPE_KEY"),
        ]
        
        for credential, pattern_type in test_cases:
            detected = module._scan_credentials(credential)
            assert pattern_type in detected
Commit Standards
Commit Message Format
bash# Format
<type>(<scope>): <subject> [<issue>]

<body>

<footer>

# Types (use exactly these)
feat     - New intelligence module or major feature
fix      - Bug fix with security or functional impact
perf     - Performance improvement with benchmarks
security - Security vulnerability patch
refactor - Code restructure that improves maintainability
test     - Test additions or fixes
docs     - Documentation for complex functionality
chore    - Build, CI, dependency updates
Commit Examples
bash# Feature commit
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

# Performance improvement
perf(cache): Implement LRU eviction for memory efficiency [#189]

Replaced dict-based cache with OrderedDict LRU implementation.
Limits cache to 10,000 entries with automatic eviction.

Benchmarks (Intel i7-12700K, 32GB RAM):
- Memory usage: 450MB -> 100MB (78% reduction)
- Cache hit rate: 68% -> 71% (3% improvement)
- Lookup time: 0.003ms -> 0.001ms (66% faster)

No API changes, backwards compatible.

Resolves #189
Code Review Process
Before Submitting PR
bash# Run all quality checks locally
make lint          # flake8, black, isort
make type-check    # mypy type validation
make security      # bandit, safety, pip-audit
make test          # pytest with coverage
make test-integration  # Full integration tests

# Verify specific standards
pytest tests/unit/ --cov=src --cov-report=term-missing
black --check src/ tests/
flake8 src/ tests/ --max-line-length=100
mypy src/ --strict
bandit -r src/ -ll
safety check
PR Requirements
Your pull request must:

Have a Clear Purpose

Links to issue it resolves
Explains why this change is necessary
Shows evidence of the problem it solves


Include Tests

Unit tests with >90% coverage for new code
Integration tests for new modules
Performance benchmarks for optimizations


Provide Documentation

Docstrings for all public functions
README updates for new features
CHANGELOG entry for user-visible changes


Pass All Checks

CI/CD pipeline green
No merge conflicts
Signed commits (GPG)


Show Real Impact

Performance metrics
Detection accuracy rates
Security improvement analysis



PR Template
markdown## Description
[Describe what this PR does and why it's needed]

## Type of Change
- [ ] Bug fix (non-breaking change fixing an issue)
- [ ] New feature (non-breaking change adding functionality)
- [ ] Breaking change (fix or feature that would cause existing functionality to not work as expected)
- [ ] Security fix (vulnerability patch)

## Testing
- [ ] Unit tests pass locally with >90% coverage
- [ ] Integration tests pass
- [ ] Tested on Linux, macOS, Windows
- [ ] Security scan clean (bandit, safety)

## Performance Impact
[Include benchmarks showing before/after metrics]

## Security Considerations
[Explain any security implications]

## Checklist
- [ ] My code follows the project's style guidelines
- [ ] I have performed a self-review
- [ ] I have commented complex code sections
- [ ] I have made corresponding documentation changes
- [ ] My changes generate no new warnings
- [ ] New and existing unit tests pass locally
- [ ] Dependent changes have been merged

## Evidence
[Screenshots, logs, or benchmarks proving the fix works]

Fixes #[issue number]
Security Vulnerability Reporting
For security vulnerabilities, DO NOT open a public issue:

Email genzt.dev@pm.me with:

Vulnerability description
Proof of concept (PoC)
Impact assessment
Suggested fix if available


Use PGP encryption for sensitive details
Allow 90 days for patching before disclosure
Receive credit in security advisory

Testing Standards
Test Structure
pythontests/
├── unit/                 # Fast, isolated tests
│   ├── test_http_engine.py
│   ├── test_cache.py
│   └── test_patterns.py
├── integration/          # Module interaction tests
│   ├── test_github_intel.py
│   ├── test_breach_intel.py
│   └── test_correlation.py
├── performance/          # Benchmark tests
│   ├── test_cache_perf.py
│   └── test_http_perf.py
├── security/            # Security-specific tests
│   ├── test_ssrf.py
│   ├── test_injection.py
│   └── test_auth.py
└── fixtures/           # Test data
    ├── responses/      # Mock API responses
    ├── patterns/       # Credential patterns
    └── profiles/       # Test profiles
Test Quality Requirements
python# Minimum coverage thresholds
COVERAGE_REQUIREMENTS = {
    'unit': 90,      # Core logic
    'integration': 75,  # Module interactions
    'overall': 85    # Total coverage
}

# Performance baselines (regression detection)
PERFORMANCE_BASELINES = {
    'http_request': 2.0,    # seconds
    'cache_lookup': 0.001,  # seconds
    'pattern_match': 0.01,  # seconds
    'full_investigation': 60.0  # seconds
}
```

### Release Process

#### Version Numbering

We use semantic versioning with security patch priority:
```
MAJOR.MINOR.PATCH-SECURITY

4.1.0      - New features
4.1.1      - Bug fixes
4.1.1-sec1 - Security patch
Release Checklist
bash# 1. Update version
bump2version minor  # or major, patch

# 2. Update CHANGELOG
echo "## [4.1.0] - $(date +%Y-%m-%d)" >> CHANGELOG.md

# 3. Run full test suite
make test-all

# 4. Security audit
make security-scan

# 5. Build and test distribution
python setup.py sdist bdist_wheel
twine check dist/*

# 6. Tag and sign
git tag -s v4.1.0 -m "Release v4.1.0"
git push origin v4.1.0

# 7. Create GitHub release with:
# - Changelog excerpt
# - Security advisories
# - Breaking changes
# - Upgrade instructions
Development Resources
Module Development Guide
When creating a new intelligence module:

Research Platform API

Authentication methods
Rate limits
Response formats
Error codes


Implement Detection Logic

Profile existence validation
Metadata extraction
Error handling
Rate limit compliance


Add Credential Patterns

Platform-specific tokens
API key formats
Authentication headers


Create Tests

Mock API responses
Edge cases
Error conditions
Performance benchmarks


Document Thoroughly

API limitations
Detection accuracy
False positive rate
Evasion detection



Architecture Decisions
Document significant decisions in docs/architecture/:
markdown# ADR-001: HTTP Connection Pooling

## Status
Accepted

## Context
Need to optimize HTTP performance across 200+ platform checks.

## Decision
Implement connection pooling with 30 concurrent connections.

## Consequences
- 40% reduction in connection overhead
- 2.5x faster batch processing
- 100MB memory overhead for pool
Contact
Project Maintainer: genzt.dev@pm.me
Security Issues: genesis.Issues@pm.me (PGP required)
General Discussion: GitHub Discussion
