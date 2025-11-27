# Contributing to Nexus Intelligence Framework

## Overview

Nexus Intelligence Framework is an enterprise-grade OSINT platform built for security researchers, penetration testers, and intelligence analysts. This document outlines the technical standards, architectural principles, and contribution workflow required to maintain the framework's production-quality codebase.

**Project Maintainer:** Genesis ([@genesisgzdev](https://github.com/genesisgzdev))  
**Issue Reports:** genesis.issues@pm.me  
**Technical Support:** genzt.dev@pm.me  

---

## Table of Contents

- [Prerequisites & Technical Requirements](#prerequisites--technical-requirements)
- [Development Environment Setup](#development-environment-setup)
- [Architecture & Design Principles](#architecture--design-principles)
- [Contribution Workflow](#contribution-workflow)
- [Code Quality Standards](#code-quality-standards)
- [Module Development Guidelines](#module-development-guidelines)
- [Testing Strategy](#testing-strategy)
- [Security & OPSEC Considerations](#security--opsec-considerations)
- [Performance Optimization](#performance-optimization)
- [Documentation Requirements](#documentation-requirements)
- [Pull Request Process](#pull-request-process)
- [Issue Reporting](#issue-reporting)
- [Legal & Ethical Guidelines](#legal--ethical-guidelines)

---

## Prerequisites & Technical Requirements

### Required Competencies

Contributors should possess:

- **Advanced Python Proficiency**: Deep understanding of async/await, decorators, context managers, metaclasses, and descriptor protocol
- **Network Programming**: Experience with TCP/IP stack, HTTP/2 protocol, TLS handshakes, and socket programming
- **Web Technologies**: Expertise in HTML/CSS parsing, JavaScript execution contexts, DOM manipulation, and browser fingerprinting
- **Security Engineering**: Knowledge of OWASP Top 10, common vulnerabilities (SQLi, XSS, SSRF), rate limiting bypass techniques, and evasion strategies
- **OSINT Methodologies**: Practical experience with reconnaissance frameworks (Maltego, Recon-ng, theHarvester), OSINT intelligence cycle, and correlation analysis

### Technical Stack

```
Python 3.8+
├── Core Dependencies
│   ├── requests (HTTP client with connection pooling)
│   ├── dnspython (DNS resolution and record parsing)
│   ├── beautifulsoup4 (HTML/XML parsing)
│   └── urllib3 (Low-level HTTP operations)
├── Optional Modules
│   ├── rich (Terminal UI rendering)
│   ├── lxml (High-performance XML processing)
│   ├── whois (Domain registration lookup)
│   └── jinja2 (Template engine for reports)
└── Development Tools
    ├── pytest (Testing framework)
    ├── black (Code formatter)
    ├── mypy (Static type checker)
    ├── pylint (Linter & code analyzer)
    └── pytest-cov (Coverage reporting)
```

---

## Development Environment Setup

### Repository Configuration

```bash
# Fork and clone repository
git clone git@github.com:YOUR_USERNAME/nexus-intelligence.git
cd nexus-intelligence

# Configure remotes
git remote add upstream git@github.com:genesisgzdev/nexus-intelligence.git
git fetch upstream

# Create isolated Python environment
python3 -m venv venv
source venv/bin/activate  # Linux/macOS
venv\Scripts\activate.bat  # Windows (cmd)
venv\Scripts\Activate.ps1  # Windows (PowerShell)

# Install dependencies with locked versions
pip install --upgrade pip setuptools wheel
pip install -r requirements.txt
pip install -r requirements-dev.txt  # Development dependencies
```

### Pre-commit Hooks

Configure automated code quality checks:

```bash
# Install pre-commit framework
pip install pre-commit

# Initialize hooks
pre-commit install
pre-commit install --hook-type commit-msg

# Run manually (optional)
pre-commit run --all-files
```

### IDE Configuration

**VS Code** (`settings.json`):
```json
{
  "python.linting.enabled": true,
  "python.linting.pylintEnabled": true,
  "python.linting.flake8Enabled": true,
  "python.formatting.provider": "black",
  "python.formatting.blackArgs": ["--line-length", "100"],
  "editor.formatOnSave": true,
  "editor.codeActionsOnSave": {
    "source.organizeImports": true
  },
  "python.testing.pytestEnabled": true,
  "python.testing.unittestEnabled": false
}
```

**PyCharm**:
- Enable `black` as external tool: Preferences → Tools → External Tools
- Configure `mypy` plugin: Preferences → Plugins → Browse Repositories → Mypy
- Set line length to 100: Preferences → Editor → Code Style → Python

---

## Architecture & Design Principles

### System Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     OSINT Framework Core                     │
├─────────────────────────────────────────────────────────────┤
│                                                               │
│  ┌─────────────┐  ┌──────────────┐  ┌─────────────────┐    │
│  │   HTTPEngine│  │ CacheManager │  │  DataProcessor  │    │
│  │             │  │              │  │                 │    │
│  │ • Retry     │  │ • TTL Cache  │  │ • Correlation   │    │
│  │ • Proxy     │  │ • LRU Evict  │  │ • Risk Scoring  │    │
│  │ • User-Agent│  │ • Persistence│  │ • Normalization │    │
│  └──────┬──────┘  └──────┬───────┘  └────────┬────────┘    │
│         │                │                    │              │
│         └────────────────┼────────────────────┘              │
│                          │                                   │
├──────────────────────────┼───────────────────────────────────┤
│                     Module Layer                              │
├──────────────────────────┼───────────────────────────────────┤
│                          │                                   │
│  ┌──────────┐  ┌─────────┴────┐  ┌──────────┐  ┌─────────┐ │
│  │  GitHub  │  │    Social    │  │   DNS    │  │  Email  │ │
│  │  Module  │  │    Module    │  │  Module  │  │ Module  │ │
│  └────┬─────┘  └─────┬────────┘  └────┬─────┘  └────┬────┘ │
│       │              │                 │             │      │
│       └──────────────┼─────────────────┼─────────────┘      │
│                      │                 │                    │
├──────────────────────┼─────────────────┼────────────────────┤
│                  Export Layer          │                    │
├──────────────────────┼─────────────────┼────────────────────┤
│                      │                 │                    │
│  ┌──────────┐  ┌─────┴────┐  ┌────────┴───┐  ┌──────────┐  │
│  │   JSON   │  │   CSV    │  │    HTML    │  │   XML    │  │
│  │ Exporter │  │ Exporter │  │  Exporter  │  │ Exporter │  │
│  └──────────┘  └──────────┘  └────────────┘  └──────────┘  │
└─────────────────────────────────────────────────────────────┘
```

### Design Principles

#### 1. Modularity & Separation of Concerns
Each component has a single, well-defined responsibility. Modules communicate through standardized interfaces (`BaseModule` abstract class) and do not directly depend on each other's implementation details.

#### 2. Defensive Programming
- **Input Validation**: All external data is validated, sanitized, and type-checked
- **Error Handling**: Specific exception types, never bare `except` clauses
- **Resource Management**: Context managers for file handles, network connections, and locks
- **Rate Limiting**: Platform-specific delays, exponential backoff, circuit breakers

#### 3. Performance by Default
- **Connection Pooling**: Reuse TCP connections via `requests.Session`
- **Lazy Evaluation**: Load modules only when invoked
- **Streaming Parsers**: Process large datasets without loading entire content into memory
- **Concurrent Execution**: Thread pool for I/O-bound operations, process pool for CPU-bound tasks

#### 4. Security-First Approach
- **No Credential Storage**: API tokens passed via environment variables or CLI flags
- **TLS Verification**: Certificate pinning for critical endpoints
- **Request Sanitization**: Strip identifying headers, randomize fingerprints
- **Proxy Support**: SOCKS4/5 and HTTP(S) proxy chains

---

## Contribution Workflow

### Branch Strategy

```bash
# Feature branches
git checkout -b feature/linkedin-profile-module
git checkout -b feature/telegram-osint-integration

# Bug fixes
git checkout -b fix/dns-timeout-regression
git checkout -b fix/github-api-rate-limit-handling

# Performance improvements
git checkout -b perf/optimize-social-module-concurrency
git checkout -b perf/implement-redis-cache-backend

# Documentation
git checkout -b docs/module-development-guide
git checkout -b docs/api-reference-update

# Security patches
git checkout -b security/fix-ssrf-vulnerability
git checkout -b security/implement-request-signing
```

### Commit Convention

We enforce **Conventional Commits** specification:

```
<type>(<scope>): <subject>

<body>

<footer>
```

#### Types
- `feat`: New feature, module, or capability
- `fix`: Bug fix, regression patch
- `perf`: Performance optimization
- `refactor`: Code restructuring without behavioral changes
- `style`: Formatting, whitespace, missing semicolons
- `test`: Adding/updating test suites
- `docs`: Documentation updates
- `chore`: Dependency updates, build configuration
- `security`: Security vulnerabilities, OPSEC improvements
- `ci`: CI/CD pipeline modifications

#### Examples

```bash
# Feature addition
feat(modules): implement Instagram profile reconnaissance module

Adds comprehensive Instagram OSINT capabilities including:
- Profile metadata extraction (followers, following, bio)
- Post analysis with engagement metrics
- Story archival through third-party APIs
- Location geolocation from EXIF data

Implements rate limiting to avoid detection (3 req/min).
Uses residential proxy rotation to bypass IP-based blocks.

Closes #127

# Bug fix with technical detail
fix(http): resolve connection pool exhaustion under high concurrency

The HTTPAdapter pool_maxsize parameter was insufficient for >50
concurrent requests, causing ConnectionPool timeout exceptions.

Changes:
- Increase pool_maxsize from 10 to 30
- Implement connection pool monitoring
- Add exponential backoff for pool acquisition failures

This resolves intermittent failures observed during batch processing
of 100+ targets simultaneously.

Fixes #89

# Performance optimization with benchmarks
perf(cache): implement LRU eviction policy for memory efficiency

Previous FIFO cache strategy caused unbounded memory growth during
long-running investigations with diverse targets.

Benchmarks (10,000 unique requests):
- Memory usage: 450MB → 120MB (73% reduction)
- Cache hit rate: 42% → 61%
- Eviction overhead: <2ms per operation

Uses OrderedDict for O(1) access and eviction.

# Security patch
security(http): add certificate pinning for GitHub API endpoints

Implements certificate pinning to prevent MITM attacks against
GitHub API requests. Uses SHA-256 fingerprints of GitHub's
certificate chain.

Fallback mechanism: If pinning fails, log warning and continue
with standard TLS verification to avoid breaking existing workflows.

CVSS Score: 5.3 (Medium) - Network-based MITM without auth bypass
```

### Code Review Checklist

Before submitting PR, verify:

- [ ] **Functionality**: Code accomplishes stated objective
- [ ] **Tests**: Unit tests with >70% coverage, integration tests for modules
- [ ] **Documentation**: Docstrings, inline comments, README updates
- [ ] **Performance**: No obvious bottlenecks, efficient algorithms
- [ ] **Security**: No hardcoded credentials, input validation, error handling
- [ ] **Style**: Passes `black`, `flake8`, `mypy`, `pylint`
- [ ] **Dependencies**: No unnecessary libraries, licenses compatible with MIT
- [ ] **Backwards Compatibility**: No breaking changes without major version bump

---

## Code Quality Standards

### Type Hints

**Required** for all function signatures and class attributes:

```python
from typing import Dict, List, Optional, Tuple, Union, Any
from pathlib import Path

class GitHubModule:
    """GitHub intelligence gathering module."""
    
    def __init__(
        self, 
        api_token: Optional[str] = None,
        timeout: int = 30,
        max_retries: int = 3
    ) -> None:
        self.api_token: Optional[str] = api_token
        self.timeout: int = timeout
        self.max_retries: int = max_retries
        self._session: Optional[requests.Session] = None
    
    def fetch_user_profile(
        self, 
        username: str,
        include_repos: bool = True
    ) -> Dict[str, Any]:
        """
        Retrieve comprehensive GitHub user profile.
        
        Args:
            username: Target GitHub username
            include_repos: Whether to fetch repository data
            
        Returns:
            Dictionary containing user profile with structure:
            {
                'login': str,
                'id': int,
                'created_at': str,
                'public_repos': int,
                'followers': int,
                'following': int,
                'repos': List[Dict] (if include_repos=True)
            }
            
        Raises:
            ValueError: If username contains invalid characters
            requests.HTTPError: If API request fails
            TimeoutError: If request exceeds configured timeout
        """
        self._validate_username(username)
        # Implementation
        pass
    
    def _validate_username(self, username: str) -> None:
        """Validate GitHub username format."""
        if not username or not username.isalnum():
            raise ValueError(f"Invalid GitHub username: {username}")
```

### Error Handling

Implement **specific exception handling** with context:

```python
# Bad: Generic exception catching
try:
    response = requests.get(url)
    data = response.json()
except Exception as e:
    print(f"Error: {e}")
    return None

# Good: Specific exceptions with context
from requests.exceptions import ConnectionError, Timeout, HTTPError

try:
    response = self.session.get(
        url, 
        timeout=self.timeout,
        headers=self._get_headers()
    )
    response.raise_for_status()
    data = response.json()
    
except ConnectionError as e:
    logger.error(
        f"Network connectivity failure for {url}: {e}",
        extra={'target': username, 'module': 'github'}
    )
    raise OSINTNetworkError(f"Cannot reach GitHub API: {e}") from e
    
except Timeout as e:
    logger.warning(
        f"Request timeout after {self.timeout}s for {url}",
        extra={'target': username, 'retry_count': self.retry_count}
    )
    raise OSINTTimeoutError(f"GitHub API timeout: {e}") from e
    
except HTTPError as e:
    if response.status_code == 429:
        retry_after = response.headers.get('Retry-After', 60)
        logger.warning(
            f"Rate limit exceeded, retry after {retry_after}s",
            extra={'endpoint': url, 'remaining': response.headers.get('X-RateLimit-Remaining')}
        )
        raise OSINTRateLimitError(f"GitHub rate limit exceeded") from e
    else:
        logger.error(f"HTTP {response.status_code} for {url}: {e}")
        raise OSINTHTTPError(f"GitHub API error: {e}") from e
        
except json.JSONDecodeError as e:
    logger.error(f"Invalid JSON response from {url}: {e}")
    raise OSINTParseError(f"Cannot parse GitHub API response") from e
```

### Logging Strategy

Use **structured logging** with appropriate levels:

```python
import logging
from typing import Dict, Any

logger = logging.getLogger(__name__)

class InvestigationModule:
    """Base module for intelligence gathering."""
    
    def execute(self, target: str) -> Dict[str, Any]:
        """Execute investigation against target."""
        
        # DEBUG: Detailed execution flow
        logger.debug(
            "Starting investigation",
            extra={
                'target': target,
                'module': self.name,
                'config': self.config
            }
        )
        
        # INFO: Significant milestones
        logger.info(
            f"Fetching data from {self.platform}",
            extra={'target': target, 'endpoint': endpoint}
        )
        
        # WARNING: Recoverable issues
        if response.status_code == 429:
            logger.warning(
                "Rate limit encountered, implementing backoff",
                extra={
                    'target': target,
                    'retry_after': retry_after,
                    'attempt': attempt_number
                }
            )
        
        # ERROR: Failures requiring attention
        if not data:
            logger.error(
                "No data retrieved from API",
                extra={
                    'target': target,
                    'status_code': response.status_code,
                    'response_body': response.text[:500]
                }
            )
        
        # CRITICAL: System-level failures
        except MemoryError as e:
            logger.critical(
                "Memory exhaustion during processing",
                extra={
                    'target': target,
                    'data_size': len(raw_data),
                    'available_memory': psutil.virtual_memory().available
                }
            )
```

### Code Formatting

**Black** configuration (`.black.toml` or `pyproject.toml`):
```toml
[tool.black]
line-length = 100
target-version = ['py38', 'py39', 'py310', 'py311']
include = '\.pyi?$'
exclude = '''
/(
    \.git
  | \.venv
  | venv
  | build
  | dist
  | __pycache__
)/
'''
```

**isort** configuration:
```toml
[tool.isort]
profile = "black"
line_length = 100
multi_line_output = 3
include_trailing_comma = true
force_grid_wrap = 0
use_parentheses = true
ensure_newline_before_comments = true
```

---

## Module Development Guidelines

### Module Structure

Every intelligence module must inherit from `BaseModule`:

```python
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional
import logging

logger = logging.getLogger(__name__)

class BaseModule(ABC):
    """Abstract base class for OSINT modules."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None) -> None:
        """
        Initialize module with configuration.
        
        Args:
            config: Module-specific configuration dictionary
        """
        self.config = config or {}
        self.name: str = self.__class__.__name__
        self.description: str = ""
        self.version: str = "1.0.0"
        self.supported_targets: List[str] = []
        self.rate_limit: Optional[int] = None  # requests per minute
        
    @abstractmethod
    def validate_target(self, target: str) -> bool:
        """
        Validate if target is compatible with this module.
        
        Args:
            target: Target identifier (username, email, domain, etc.)
            
        Returns:
            True if target is valid for this module, False otherwise
        """
        pass
    
    @abstractmethod
    def execute(self, target: str) -> Dict[str, Any]:
        """
        Execute intelligence gathering for target.
        
        Args:
            target: Validated target identifier
            
        Returns:
            Dictionary containing investigation results:
            {
                'found': bool,
                'data': Dict[str, Any],
                'metadata': Dict[str, Any],
                'errors': List[str],
                'confidence': float  # 0.0 to 1.0
            }
        """
        pass
    
    def get_info(self) -> Dict[str, Any]:
        """Return module metadata."""
        return {
            'name': self.name,
            'description': self.description,
            'version': self.version,
            'supported_targets': self.supported_targets,
            'rate_limit': self.rate_limit
        }
```

### Example: Twitter/X Module Implementation

```python
import re
from typing import Dict, Any, List, Optional
import requests
from src.core.base_module import BaseModule
from src.core.exceptions import OSINTValidationError, OSINTRateLimitError

logger = logging.getLogger(__name__)

class TwitterModule(BaseModule):
    """
    Twitter/X intelligence gathering module.
    
    Capabilities:
    - Profile metadata extraction (username, display name, bio, location)
    - Tweet analysis (frequency, engagement metrics, sentiment)
    - Follower/following relationship mapping
    - Timeline reconstruction with date range filters
    - Media extraction (images, videos from tweets)
    
    Rate Limits:
    - Guest API: 15 requests/15 minutes per IP
    - Authenticated: 900 requests/15 minutes per token
    
    OPSEC Considerations:
    - Use residential proxies to avoid datacenter IP blocks
    - Randomize user-agent strings for each request
    - Implement request jitter (random delays between calls)
    - Clear cookies between investigations
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(config)
        self.name = "Twitter"
        self.description = "Twitter/X profile and activity reconnaissance"
        self.version = "2.1.0"
        self.supported_targets = ['username']
        self.rate_limit = 15  # requests per 15-minute window
        
        self.api_base = "https://api.twitter.com/2"
        self.bearer_token: Optional[str] = config.get('bearer_token')
        self.use_guest_mode: bool = not self.bearer_token
        
    def validate_target(self, target: str) -> bool:
        """
        Validate Twitter username format.
        
        Twitter usernames must:
        - Be 1-15 characters
        - Contain only alphanumeric characters and underscores
        - Not start with a number
        
        Args:
            target: Potential Twitter username
            
        Returns:
            True if valid Twitter username format
        """
        pattern = r'^[a-zA-Z_][a-zA-Z0-9_]{0,14}$'
        return bool(re.match(pattern, target))
    
    def execute(self, target: str) -> Dict[str, Any]:
        """
        Execute Twitter intelligence gathering.
        
        Args:
            target: Valid Twitter username
            
        Returns:
            Comprehensive Twitter profile data
            
        Raises:
            OSINTValidationError: If username format is invalid
            OSINTRateLimitError: If API rate limit is exceeded
        """
        if not self.validate_target(target):
            raise OSINTValidationError(
                f"Invalid Twitter username format: {target}"
            )
        
        logger.info(f"Investigating Twitter profile: @{target}")
        
        results = {
            'found': False,
            'data': {},
            'metadata': {
                'module': self.name,
                'version': self.version,
                'timestamp': datetime.now(timezone.utc).isoformat()
            },
            'errors': [],
            'confidence': 0.0
        }
        
        try:
            # Fetch user profile
            profile = self._fetch_profile(target)
            if not profile:
                return results
            
            results['found'] = True
            results['data']['profile'] = profile
            results['confidence'] = 0.9
            
            # Fetch recent tweets
            tweets = self._fetch_tweets(profile['id'], limit=100)
            results['data']['tweets'] = tweets
            results['data']['tweet_analysis'] = self._analyze_tweets(tweets)
            
            # Extract followers/following counts
            results['data']['social_graph'] = {
                'followers_count': profile['public_metrics']['followers_count'],
                'following_count': profile['public_metrics']['following_count'],
                'ratio': self._calculate_follower_ratio(profile)
            }
            
            logger.info(f"Successfully retrieved data for @{target}")
            
        except OSINTRateLimitError as e:
            logger.error(f"Rate limit exceeded for @{target}: {e}")
            results['errors'].append(str(e))
            
        except Exception as e:
            logger.exception(f"Unexpected error during investigation of @{target}")
            results['errors'].append(f"Internal error: {str(e)}")
        
        return results
    
    def _fetch_profile(self, username: str) -> Optional[Dict[str, Any]]:
        """Fetch user profile via Twitter API v2."""
        endpoint = f"{self.api_base}/users/by/username/{username}"
        params = {
            'user.fields': 'id,name,username,created_at,description,'
                          'location,public_metrics,verified,profile_image_url'
        }
        headers = self._get_auth_headers()
        
        try:
            response = requests.get(
                endpoint,
                params=params,
                headers=headers,
                timeout=20
            )
            
            if response.status_code == 429:
                raise OSINTRateLimitError("Twitter API rate limit exceeded")
            
            response.raise_for_status()
            data = response.json()
            
            return data.get('data')
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to fetch Twitter profile: {e}")
            return None
    
    def _fetch_tweets(self, user_id: str, limit: int = 100) -> List[Dict[str, Any]]:
        """Fetch recent tweets for user."""
        # Implementation details
        pass
    
    def _analyze_tweets(self, tweets: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Perform statistical analysis on tweet corpus."""
        # Implementation details
        pass
    
    def _calculate_follower_ratio(self, profile: Dict[str, Any]) -> float:
        """Calculate follower/following ratio as influence metric."""
        followers = profile['public_metrics']['followers_count']
        following = profile['public_metrics']['following_count']
        
        if following == 0:
            return float('inf')
        
        return round(followers / following, 2)
    
    def _get_auth_headers(self) -> Dict[str, str]:
        """Generate authentication headers."""
        if self.bearer_token:
            return {'Authorization': f'Bearer {self.bearer_token}'}
        else:
            # Implement guest token acquisition
            return {}
```

### Module Registration

Add new modules to `src/modules/__init__.py`:

```python
from .github import GitHubModule
from .twitter import TwitterModule
from .linkedin import LinkedInModule  # Your new module

AVAILABLE_MODULES = {
    'github': GitHubModule,
    'twitter': TwitterModule,
    'linkedin': LinkedInModule,  # Register here
}

__all__ = ['AVAILABLE_MODULES', 'GitHubModule', 'TwitterModule', 'LinkedInModule']
```

---

## Testing Strategy

### Test Hierarchy

```
tests/
├── unit/                      # Fast, isolated tests
│   ├── core/
│   │   ├── test_http_engine.py
│   │   ├── test_cache_manager.py
│   │   └── test_data_processor.py
│   └── modules/
│       ├── test_github_module.py
│       ├── test_twitter_module.py
│       └── test_dns_module.py
├── integration/               # Multi-component tests
│   ├── test_full_investigation.py
│   ├── test_batch_processing.py
│   └── test_export_pipeline.py
├── performance/               # Load and stress tests
│   ├── test_concurrent_requests.py
│   ├── test_memory_usage.py
│   └── test_cache_efficiency.py
├── security/                  # Security-focused tests
│   ├── test_input_validation.py
│   ├── test_ssl_verification.py
│   └── test_credential_handling.py
├── fixtures/                  # Test data and mocks
│   ├── github_responses.json
│   ├── twitter_api_mock.json
│   └── dns_records.yaml
└── conftest.py               # Pytest configuration
```

### Unit Test Example

```python
import pytest
from unittest.mock import Mock, patch, MagicMock
from src.modules.github import GitHubModule
from src.core.exceptions import OSINTValidationError, OSINTRateLimitError

class TestGitHubModule:
    """Test suite for GitHub intelligence module."""
    
    @pytest.fixture
    def github_module(self):
        """Create GitHubModule instance with test configuration."""
        config = {
            'api_token': 'ghp_test_token_1234567890',
            'timeout': 10,
            'max_retries': 2
        }
        return GitHubModule(config)
    
    @pytest.fixture
    def mock_user_response(self):
        """Mock GitHub API user response."""
        return {
            'login': 'testuser',
            'id': 123456,
            'name': 'Test User',
            'company': 'ACME Corp',
            'blog': 'https://testuser.dev',
            'location': 'San Francisco, CA',
            'email': 'test@example.com',
            'bio': 'Security researcher and Python developer',
            'public_repos': 42,
            'public_gists': 15,
            'followers': 350,
            'following': 120,
            'created_at': '2015-03-15T10:30:00Z',
            'updated_at': '2024-11-27T14:20:00Z'
        }
    
    # Validation Tests
    
    def test_validate_target_valid_username(self, github_module):
        """Test username validation with valid input."""
        valid_usernames = [
            'testuser',
            'test-user',
            'test_user',
            'Test123',
            'a',  # Single character
            'a' * 39  # Maximum length
        ]
        
        for username in valid_usernames:
            assert github_module.validate_target(username) is True
    
    def test_validate_target_invalid_username(self, github_module):
        """Test username validation with invalid input."""
        invalid_usernames = [
            '',  # Empty string
            'test user',  # Space
            'test@user',  # Special character
            'a' * 40,  # Too long
            '-startdash',  # Starts with hyphen
            'enddash-'  # Ends with hyphen
        ]
        
        for username in invalid_usernames:
            assert github_module.validate_target(username) is False
    
    # Execution Tests
    
    @patch('src.modules.github.requests.get')
    def test_execute_successful_investigation(
        self, 
        mock_get, 
        github_module, 
        mock_user_response
    ):
        """Test successful profile retrieval and data processing."""
        # Configure mock response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = mock_user_response
        mock_response.headers = {
            'X-RateLimit-Remaining': '4999',
            'X-RateLimit-Reset': '1703779200'
        }
        mock_get.return_value = mock_response
        
        # Execute investigation
        result = github_module.execute('testuser')
        
        # Assertions
        assert result['found'] is True
        assert result['data']['profile']['login'] == 'testuser'
        assert result['data']['profile']['id'] == 123456
        assert result['confidence'] >= 0.9
        assert len(result['errors']) == 0
        
        # Verify API call
        mock_get.assert_called_once()
        call_args = mock_get.call_args
        assert 'testuser' in call_args[0][0]
        assert 'Authorization' in call_args[1]['headers']
    
    @patch('src.modules.github.requests.get')
    def test_execute_rate_limit_handling(self, mock_get, github_module):
        """Test handling of GitHub API rate limiting."""
        # Configure mock to return 429 Too Many Requests
        mock_response = Mock()
        mock_response.status_code = 429
        mock_response.headers = {
            'X-RateLimit-Remaining': '0',
            'X-RateLimit-Reset': '1703779500',
            'Retry-After': '60'
        }
        mock_get.return_value = mock_response
        
        # Expect OSINTRateLimitError
        with pytest.raises(OSINTRateLimitError) as exc_info:
            github_module.execute('testuser')
        
        assert 'rate limit' in str(exc_info.value).lower()
    
    @patch('src.modules.github.requests.get')
    def test_execute_network_failure_handling(self, mock_get, github_module):
        """Test handling of network connectivity issues."""
        # Simulate connection error
        from requests.exceptions import ConnectionError
        mock_get.side_effect = ConnectionError("Network unreachable")
        
        result = github_module.execute('testuser')
        
        assert result['found'] is False
        assert len(result['errors']) > 0
        assert 'network' in result['errors'][0].lower()
    
    def test_execute_invalid_username(self, github_module):
        """Test execution with invalid username format."""
        with pytest.raises(OSINTValidationError):
            github_module.execute('invalid username!')
```

### Integration Test Example

```python
import pytest
from src.osint_framework import OSINTFramework

@pytest.mark.integration
class TestFullInvestigation:
    """Integration tests for complete investigation workflow."""
    
    @pytest.fixture(scope='class')
    def framework(self):
        """Initialize framework for integration tests."""
        config = {
            'github_token': os.getenv('GITHUB_TEST_TOKEN'),
            'timeout': 30,
            'cache_enabled': True
        }
        return OSINTFramework(config)
    
    def test_full_investigation_workflow(self, framework):
        """Test complete investigation from input to export."""
        target = 'genesisgzdev'  # Use project author as test subject
        
        # Execute investigation
        results = framework.investigate(
            target=target,
            modules=['github', 'social'],
            output_format='json'
        )
        
        # Verify results structure
        assert 'target' in results
        assert 'timestamp' in results
        assert 'results' in results
        assert 'statistics' in results
        
        # Verify GitHub module executed
        assert 'github' in results['results']
        github_data = results['results']['github']
        assert github_data['found'] is True
        assert 'profile' in github_data['data']
        
        # Verify social module executed
        assert 'social' in results['results']
        
        # Verify statistics
        stats = results['statistics']
        assert stats['total_requests'] > 0
        assert stats['successful_requests'] > 0
```

### Running Tests

```bash
# Run all tests
pytest tests/ -v

# Run specific test file
pytest tests/unit/modules/test_github_module.py -v

# Run with coverage
pytest tests/ --cov=src --cov-report=html --cov-report=term-missing

# Run only unit tests
pytest tests/unit/ -v

# Run only integration tests
pytest tests/integration/ -m integration

# Run performance tests
pytest tests/performance/ -m performance --durations=10

# Run with parallel execution (requires pytest-xdist)
pytest tests/ -n auto

# Generate XML report for CI/CD
pytest tests/ --junitxml=test-results.xml
```

---

## Security & OPSEC Considerations

### Critical Security Principles

1. **Never Commit Credentials**
   ```bash
   # Add to .gitignore
   .env
   *.key
   *.pem
   config/secrets.yaml
   ```

2. **API Token Management**
   ```python
   # Bad: Hardcoded token
   GITHUB_TOKEN = "ghp_1234567890abcdef"
   
   # Good: Environment variable
   import os
   GITHUB_TOKEN = os.getenv('GITHUB_TOKEN')
   if not GITHUB_TOKEN:
       raise EnvironmentError("GITHUB_TOKEN not set")
   ```

3. **Input Sanitization**
   ```python
   import re
   from html import escape
   
   def sanitize_username(username: str) -> str:
       """
       Sanitize username to prevent injection attacks.
       
       Removes:
       - SQL injection patterns
       - Command injection characters
       - Path traversal sequences
       - XSS payloads
       """
       # Remove dangerous characters
       username = re.sub(r'[;&|`$(){}[\]<>]', '', username)
       
       # Remove path traversal
       username = username.replace('../', '').replace('..\\', '')
       
       # HTML escape
       username = escape(username)
       
       # Limit length
       return username[:100]
   ```

4. **TLS Certificate Verification**
   ```python
   # Never disable verification in production
   # response = requests.get(url, verify=False)  # INSECURE!
   
   # Correct approach with custom CA bundle
   response = requests.get(
       url,
       verify='/path/to/custom-ca-bundle.crt',
       timeout=20
   )
   ```

5. **Rate Limit Respect**
   ```python
   import time
   from functools import wraps
   
   def rate_limit(calls_per_minute: int):
       """Decorator to enforce rate limiting."""
       min_interval = 60.0 / calls_per_minute
       last_called = [0.0]
       
       def decorator(func):
           @wraps(func)
           def wrapper(*args, **kwargs):
               elapsed = time.time() - last_called[0]
               remaining = min_interval - elapsed
               
               if remaining > 0:
                   time.sleep(remaining)
               
               result = func(*args, **kwargs)
               last_called[0] = time.time()
               return result
           return wrapper
       return decorator
   
   @rate_limit(calls_per_minute=30)
   def fetch_api_data(url: str) -> Dict:
       """Fetch data with rate limiting."""
       return requests.get(url).json()
   ```

### OPSEC Best Practices

1. **User-Agent Rotation**
   ```python
   USER_AGENTS = [
       'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
       'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
       'Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/118.0'
   ]
   
   import random
   
   headers = {
       'User-Agent': random.choice(USER_AGENTS),
       'Accept-Language': 'en-US,en;q=0.9',
       'Accept-Encoding': 'gzip, deflate, br',
       'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
   }
   ```

2. **Proxy Rotation**
   ```python
   class ProxyRotator:
       """Rotate through proxy list with health checking."""
       
       def __init__(self, proxies: List[str]):
           self.proxies = proxies
           self.current_index = 0
           self.failed_proxies: Set[str] = set()
       
       def get_next_proxy(self) -> Dict[str, str]:
           """Get next available proxy."""
           attempts = 0
           
           while attempts < len(self.proxies):
               proxy = self.proxies[self.current_index]
               self.current_index = (self.current_index + 1) % len(self.proxies)
               
               if proxy not in self.failed_proxies:
                   return {
                       'http': proxy,
                       'https': proxy
                   }
               
               attempts += 1
           
           raise Exception("All proxies failed")
   ```

3. **Request Fingerprint Randomization**
   ```python
   def generate_realistic_headers() -> Dict[str, str]:
       """Generate realistic browser headers."""
       return {
           'User-Agent': random.choice(USER_AGENTS),
           'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
           'Accept-Language': random.choice(['en-US,en;q=0.9', 'en-GB,en;q=0.9']),
           'Accept-Encoding': 'gzip, deflate, br',
           'DNT': random.choice(['1', None]),  # Do Not Track
           'Connection': 'keep-alive',
           'Upgrade-Insecure-Requests': '1',
           'Sec-Fetch-Dest': 'document',
           'Sec-Fetch-Mode': 'navigate',
           'Sec-Fetch-Site': 'none',
           'Cache-Control': 'max-age=0'
       }
   ```

---

## Performance Optimization

### Profiling Tools

```bash
# CPU profiling with cProfile
python -m cProfile -o profile.stats src/osint_framework.py testuser

# Analyze profile
python -m pstats profile.stats
>>> sort cumtime
>>> stats 20

# Memory profiling with memory_profiler
python -m memory_profiler src/osint_framework.py testuser

# Line-by-line profiling
kernprof -l -v src/modules/github.py
```

### Optimization Techniques

#### 1. Concurrent Requests

```python
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Callable, Dict, Any

def execute_concurrent_requests(
    targets: List[str],
    fetch_function: Callable[[str], Dict[str, Any]],
    max_workers: int = 10
) -> List[Dict[str, Any]]:
    """
    Execute requests concurrently using thread pool.
    
    Args:
        targets: List of targets to investigate
        fetch_function: Function to execute for each target
        max_workers: Maximum concurrent threads
        
    Returns:
        List of results from all targets
    """
    results = []
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Submit all tasks
        future_to_target = {
            executor.submit(fetch_function, target): target
            for target in targets
        }
        
        # Collect results as they complete
        for future in as_completed(future_to_target):
            target = future_to_target[future]
            try:
                result = future.result(timeout=30)
                results.append(result)
            except Exception as e:
                logger.error(f"Failed to process {target}: {e}")
                results.append({'target': target, 'error': str(e)})
    
    return results
```

#### 2. Connection Pooling

```python
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

def create_optimized_session(
    pool_connections: int = 30,
    pool_maxsize: int = 30,
    max_retries: int = 3
) -> requests.Session:
    """
    Create HTTP session with connection pooling.
    
    Connection pooling reduces:
    - TCP handshake overhead
    - TLS negotiation time
    - DNS lookup latency
    
    Args:
        pool_connections: Number of connection pools
        pool_maxsize: Maximum connections per pool
        max_retries: Retry attempts for failed requests
        
    Returns:
        Configured requests.Session instance
    """
    session = requests.Session()
    
    # Configure retry strategy
    retry_strategy = Retry(
        total=max_retries,
        backoff_factor=1,  # 1, 2, 4, 8 seconds
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET", "POST", "PUT", "DELETE"]
    )
    
    # Create adapter with pooling
    adapter = HTTPAdapter(
        pool_connections=pool_connections,
        pool_maxsize=pool_maxsize,
        max_retries=retry_strategy,
        pool_block=False
    )
    
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    
    return session
```

#### 3. Lazy Loading

```python
class ModuleLoader:
    """Lazy-load modules to reduce startup time and memory footprint."""
    
    def __init__(self):
        self._modules: Dict[str, Any] = {}
        self._module_classes = {
            'github': 'src.modules.github.GitHubModule',
            'twitter': 'src.modules.twitter.TwitterModule',
            'linkedin': 'src.modules.linkedin.LinkedInModule'
        }
    
    def get_module(self, module_name: str) -> Any:
        """
        Load module on first access.
        
        Modules are only imported when actually needed, reducing:
        - Initial import time
        - Memory usage for unused modules
        - Dependency conflicts
        """
        if module_name not in self._modules:
            module_path = self._module_classes.get(module_name)
            if not module_path:
                raise ValueError(f"Unknown module: {module_name}")
            
            # Dynamic import
            module_pkg, class_name = module_path.rsplit('.', 1)
            module = __import__(module_pkg, fromlist=[class_name])
            module_class = getattr(module, class_name)
            
            # Instantiate and cache
            self._modules[module_name] = module_class()
        
        return self._modules[module_name]
```

#### 4. Streaming Parsers

```python
import ijson  # Iterative JSON parser

def stream_large_json(file_path: str) -> Generator[Dict, None, None]:
    """
    Stream large JSON files without loading entire content into memory.
    
    Useful for processing:
    - Large API responses (>100MB)
    - Batch export files
    - Historical data archives
    """
    with open(file_path, 'rb') as f:
        parser = ijson.items(f, 'item')
        for item in parser:
            yield item
```

---

## Documentation Requirements

### Docstring Standards

Every public function, class, and module must include comprehensive docstrings:

```python
def calculate_risk_score(
    social_presence: int,
    repo_count: int,
    followers: int,
    email_leaks: int,
    has_2fa: bool
) -> Tuple[float, str]:
    """
    Calculate composite risk score for target based on multiple factors.
    
    Risk assessment methodology:
    1. Social Presence (0-25 points): Higher presence increases exposure
    2. Repository Count (0-20 points): More repos may contain sensitive data
    3. Followers (0-15 points): Larger audience increases attack surface
    4. Email Leaks (0-30 points): Leaked credentials pose immediate risk
    5. 2FA Status (0-10 points): Lack of 2FA significantly increases risk
    
    Risk Levels:
    - CRITICAL (80-100): Immediate action required
    - HIGH (60-79): Significant vulnerabilities identified
    - MEDIUM (40-59): Moderate risk, monitoring recommended
    - LOW (0-39): Minimal risk with good security posture
    
    Args:
        social_presence: Number of active social media accounts
        repo_count: Total public repositories across platforms
        followers: Combined follower count across platforms
        email_leaks: Number of confirmed email addresses in breach databases
        has_2fa: Whether target has two-factor authentication enabled
        
    Returns:
        Tuple containing:
        - float: Normalized risk score (0.0 to 100.0)
        - str: Risk level classification (CRITICAL/HIGH/MEDIUM/LOW)
        
    Example:
        >>> score, level = calculate_risk_score(
        ...     social_presence=12,
        ...     repo_count=45,
        ...     followers=3500,
        ...     email_leaks=2,
        ...     has_2fa=False
        ... )
        >>> print(f"Risk: {level} ({score:.1f}/100)")
        Risk: HIGH (68.5/100)
        
    Note:
        This is a heuristic model and should be combined with human analysis
        for critical security decisions. Adjust weights based on threat model.
        
    References:
        - NIST Cybersecurity Framework: https://www.nist.gov/cyberframework
        - OWASP Risk Rating Methodology: https://owasp.org/www-community/OWASP_Risk_Rating_Methodology
    """
    # Implementation
    pass
```

### README Updates

When adding new features or modules, update:

1. **Installation instructions** (if new dependencies)
2. **Usage examples** (command-line and programmatic)
3. **Module documentation** (capabilities, limitations, rate limits)
4. **Configuration options** (new environment variables or config fields)

### Changelog Maintenance

Follow [Keep a Changelog](https://keepachangelog.com/) format:

```markdown
# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- LinkedIn profile intelligence module with connection graph analysis
- Redis backend support for distributed caching
- Certificate pinning for GitHub API endpoints
- Prometheus metrics exporter for monitoring

### Changed
- Improved DNS module performance with parallel queries (3x faster)
- Updated user-agent rotation pool with 2024 browser versions
- Refactored HTTPEngine to use aiohttp for async requests

### Fixed
- Fixed race condition in cache manager under high concurrency
- Resolved memory leak in batch processing for >1000 targets
- Corrected Twitter API v2 pagination handling

### Security
- Implemented request signing for API authentication
- Added SSRF protection in URL validation
- Patched command injection vulnerability in subdomain enumeration

## [2.1.0] - 2024-11-15

### Added
- Instagram reconnaissance module with story archival
- Export templates for HTML reports with customizable branding
- Automatic proxy health checking with failover

### Changed
- Migrated from Twitter API v1.1 to v2
- Increased default connection pool size from 10 to 30
```

---

## Pull Request Process

### Before Opening PR

1. **Sync with upstream**
   ```bash
   git fetch upstream
   git rebase upstream/main
   ```

2. **Run full test suite**
   ```bash
   pytest tests/ -v --cov=src --cov-report=term-missing
   ```

3. **Code quality checks**
   ```bash
   black src/ tests/
   isort src/ tests/
   flake8 src/ tests/
   mypy src/
   pylint src/
   ```

4. **Update documentation**
   - Add docstrings to new functions/classes
   - Update README if adding features
   - Add entry to CHANGELOG.md

### PR Title Format

```
<type>(<scope>): <description>

Examples:
feat(modules): add Telegram profile reconnaissance module
fix(http): resolve connection pool exhaustion under load
perf(cache): implement LRU eviction policy
docs(contributing): add module development guidelines
security(validation): add input sanitization for usernames
```

### PR Description Template

```markdown
## Description

Brief summary of changes and motivation.

## Type of Change

- [ ] Bug fix (non-breaking change fixing an issue)
- [ ] New feature (non-breaking change adding functionality)
- [ ] Breaking change (fix or feature causing existing functionality to change)
- [ ] Performance improvement
- [ ] Code refactoring
- [ ] Documentation update
- [ ] Security patch

## Changes Made

Detailed list of modifications:

- Added `LinkedInModule` with profile extraction capabilities
- Implemented rate limiting (30 requests/minute) to avoid detection
- Added proxy rotation with residential IP pool
- Integrated with existing export manager for JSON/HTML output

## Testing

Describe testing performed:

- [ ] Unit tests added/updated (coverage: XX%)
- [ ] Integration tests passing
- [ ] Manual testing completed
- [ ] Tested with proxies: ✅ SOCKS5, ✅ HTTP
- [ ] Tested rate limiting behavior

Test cases:
```bash
pytest tests/unit/modules/test_linkedin.py -v
pytest tests/integration/test_linkedin_integration.py -v
```

## Performance Impact

Benchmarks (if applicable):

| Metric | Before | After | Change |
|--------|--------|-------|--------|
| Response time | 2.3s | 1.8s | -22% |
| Memory usage | 120MB | 95MB | -21% |
| Requests/sec | 15 | 23 | +53% |

## Security Considerations

Security implications of changes:

- Added input validation for LinkedIn URLs (prevents SSRF)
- Implemented certificate pinning for LinkedIn API
- No credentials stored in code or logs

## Breaking Changes

List any breaking changes:

- Changed `fetch_profile()` return type from `dict` to `LinkedInProfile` dataclass
- Removed deprecated `--linkedin-legacy` flag
- Updated config schema: `linkedin_api_key` → `linkedin.api_key`

## Migration Guide

Steps for users to migrate:

```python
# Old API
profile = module.fetch_profile(username)
name = profile['name']

# New API
profile = module.fetch_profile(username)
name = profile.name  # Now a dataclass attribute
```

## Checklist

- [ ] Code follows project style guidelines
- [ ] Self-review of code completed
- [ ] Comments added for complex logic
- [ ] Documentation updated
- [ ] Tests added and passing
- [ ] No new warnings generated
- [ ] Changelog updated
- [ ] Commit messages follow convention

## Screenshots/Logs

Include relevant output (if applicable):

```
[*] Investigating LinkedIn profile: john-doe
[+] Profile found: John Doe (Software Engineer at ACME Corp)
[+] Extracted 127 connections
[+] Identified 5 shared connections
[✓] Investigation complete (3.2s)
```

## Related Issues

Closes #XXX
Relates to #YYY

## Additional Context

Any other relevant information.
```

### Code Review Expectations

Reviewers will assess:

- **Functionality**: Does it work as intended?
- **Code Quality**: Is it readable, maintainable, well-structured?
- **Performance**: Any bottlenecks or inefficiencies?
- **Security**: Input validation, error handling, credential management?
- **Testing**: Adequate coverage, edge cases handled?
- **Documentation**: Clear docstrings, comments where needed?
- **Style**: Adherence to project conventions?

### Addressing Review Comments

```bash
# Make requested changes
git add .
git commit -m "refactor: address PR review comments"

# Update PR
git push origin feature/linkedin-module

# If rebase requested
git fetch upstream
git rebase upstream/main
git push origin feature/linkedin-module --force-with-lease
```

---

## Issue Reporting

### Bug Reports

**Submit to:** genesis.issues@pm.me

Include the following information:

```markdown
## Bug Description

Clear, concise description of the bug.

## Environment

- OS: Ubuntu 22.04 LTS
- Python version: 3.10.12
- Framework version: 2.1.0
- Installed via: pip / git clone / docker

## Reproduction Steps

1. Initialize framework with config: `config.json`
2. Execute command: `python -m src.osint_framework -t testuser -m github`
3. Observe error at stage: API rate limit check
4. Error message: `OSINTRateLimitError: GitHub rate limit exceeded`

## Expected Behavior

Framework should implement exponential backoff and retry after rate limit reset.

## Actual Behavior

Framework crashes immediately without retry attempt.

## Logs

```
[2024-11-27 14:32:15] INFO - Investigating target: testuser
[2024-11-27 14:32:16] DEBUG - Fetching GitHub profile: GET https://api.github.com/users/testuser
[2024-11-27 14:32:17] ERROR - HTTP 429: {'message': 'API rate limit exceeded'}
[2024-11-27 14:32:17] CRITICAL - Unhandled exception: OSINTRateLimitError
Traceback (most recent call last):
  File "src/modules/github.py", line 156, in fetch_profile
    response.raise_for_status()
  ...
```

## Additional Context

- Occurs only when no GitHub API token is provided
- Does not occur with authenticated requests
- Frequency: Every time (100% reproducible)

## Possible Solution

Implement retry logic with `Retry-After` header respect:

```python
if response.status_code == 429:
    retry_after = int(response.headers.get('Retry-After', 60))
    logger.warning(f"Rate limited, retrying after {retry_after}s")
    time.sleep(retry_after)
    return self._fetch_with_retry(url, attempt + 1)
```
```

### Feature Requests

**Submit to:** genesis.issues@pm.me

Include:

```markdown
## Feature Description

Add support for Reddit user profile reconnaissance.

## Use Case

OSINT investigators need to analyze Reddit activity including:
- Post history across subreddits
- Comment patterns and engagement metrics
- Account age and karma analysis
- Identified alternate accounts through writing style

## Proposed Implementation

### Module Structure
```python
class RedditModule(BaseModule):
    """Reddit user intelligence gathering."""
    
    def execute(self, target: str) -> Dict[str, Any]:
        # Fetch user profile
        # Analyze post history
        # Calculate karma distribution
        # Identify active subreddits
        pass
```

### API Endpoints
- Profile: `GET /user/{username}/about`
- Posts: `GET /user/{username}/submitted`
- Comments: `GET /user/{username}/comments`

### Rate Limits
- Unauthenticated: 60 requests/minute
- Authenticated (OAuth): 600 requests/minute

## Alternatives Considered

1. **PRAW Library**: Higher-level API wrapper, but adds dependency
2. **Pushshift API**: Historical data, but service deprecated
3. **Manual Scraping**: Fragile, high maintenance

Recommendation: Use official Reddit API with OAuth authentication.

## Additional Context

Similar to existing Twitter/GitHub modules in structure and capability.
```

### Security Vulnerabilities

**CRITICAL: Submit privately to:** genzt.dev@pm.me

**DO NOT create public GitHub issues for security vulnerabilities.**

Include:

```markdown
## Vulnerability Type

Server-Side Request Forgery (SSRF) in domain validation

## Severity

CVSS v3.1 Score: 7.5 (High)
Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N

## Affected Versions

- 2.0.0 through 2.1.0
- Introduced in commit: abc123def456

## Vulnerability Description

The `validate_domain()` function in `src/modules/dns.py` does not properly
sanitize user input, allowing attackers to specify internal network resources.

## Proof of Concept

```python
# Attacker can probe internal network
framework.investigate_domain('http://169.254.169.254/latest/meta-data/')

# Framework makes request to AWS metadata service
# Exposes EC2 instance credentials
```

## Impact

- Information Disclosure: Access to internal services
- Credential Theft: Cloud provider metadata endpoints
- Port Scanning: Map internal network topology

## Recommended Fix

```python
def validate_domain(domain: str) -> bool:
    """Validate domain and block private IP ranges."""
    
    # Parse domain
    parsed = urllib.parse.urlparse(domain)
    hostname = parsed.netloc or parsed.path
    
    # Resolve to IP
    try:
        ip = socket.gethostbyname(hostname)
    except socket.gaierror:
        return False
    
    # Block private ranges
    ip_obj = ipaddress.ip_address(ip)
    if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local:
        raise ValueError(f"Private IP address not allowed: {ip}")
    
    return True
```

## Disclosure Timeline

- [2024-11-20] Vulnerability discovered during internal audit
- [2024-11-27] Reported to maintainers
- [Target: 2024-12-05] Patch release scheduled
- [Target: 2024-12-12] Public disclosure (14 days after patch)
```

---

## Legal & Ethical Guidelines

### Authorized Use Only

This framework must only be used for:

- **Authorized penetration testing** with signed engagement letters
- **Bug bounty programs** within defined scope
- **Academic research** with IRB approval
- **Personal information verification** for one's own accounts
- **Corporate security assessments** with proper authorization

### Prohibited Activities

Contributors must NOT:

- **Unauthorized Access**: Investigate targets without explicit permission
- **Terms of Service Violations**: Bypass rate limits, use unauthorized APIs
- **Data Scraping**: Harvest data at scale for commercial purposes
- **Harassment**: Use framework for stalking, doxxing, or intimidation
- **Malicious Intent**: Facilitate illegal activities or harm individuals

### Responsible Disclosure

If discovering vulnerabilities during development:

1. **Do not exploit** beyond proof-of-concept verification
2. **Report privately** to affected parties
3. **Allow time** for patching (typically 90 days)
4. **Coordinate disclosure** with maintainers and affected vendors

### Data Handling

When working with investigation results:

- **Minimize collection**: Only gather necessary information
- **Secure storage**: Encrypt sensitive data at rest
- **Limited retention**: Delete data when no longer needed
- **Access control**: Restrict access to authorized personnel
- **Compliance**: Adhere to GDPR, CCPA, and regional privacy laws

### Code of Ethics

Contributors agree to:

- Prioritize user privacy and security
- Act with integrity and transparency
- Respect intellectual property rights
- Contribute to defensive security, not offensive exploitation
- Report security issues responsibly

---

## Community & Support

### Getting Help

- **Technical Support:** genzt.dev@pm.me
- **Bug Reports:** genesis.issues@pm.me
- **GitHub Discussions:** https://github.com/genesisgzdev/nexus-intelligence/discussions

### Contributing Beyond Code

Non-code contributions are equally valuable:

- **Documentation**: Improve guides, tutorials, examples
- **Issue Triage**: Help categorize and prioritize bug reports
- **Testing**: Report bugs, verify fixes, provide feedback
- **Community Support**: Answer questions in discussions
- **Blog Posts**: Write about OSINT techniques and tool usage
- **Translations**: Localize documentation to other languages

---

## Acknowledgments

Thank you for contributing to the Nexus Intelligence Framework. Your efforts help build a more secure and transparent digital ecosystem for security professionals worldwide.

**Project Maintainer:** Genesis GZ ([@genesisgzdev](https://github.com/genesisgzdev))  
**License:** MIT License  
**Last Updated:** 2024-11-27

---

*This document is a living guide and will evolve with the project. Suggestions for improvements are welcome via pull requests.*
