4#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Usage:
    python osint_framework_v3.py <username>
    python osint_framework_v3.py --email user@example.com
    python osint_framework_v3.py --domain example.com
    python osint_framework_v3.py --batch users.txt -o results.json
    python osint_framework_v3.py target --format html --output report.html
    python osint_framework_v3.py target --proxy https://proxy:8080 -v

Requirements:
    - requests>=2.28.0
    - dnspython>=2.3.0
    - beautifulsoup4>=4.11.0 (optional)
    - rich>=13.0.0 (optional)
    - lxml>=4.9.0 (optional, for advanced HTML parsing)
"""

import sys
import json
import csv
import time
import logging
import argparse
import hashlib
import re
import socket
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Tuple, Set
from collections import Counter, defaultdict
from pathlib import Path
import xml.etree.ElementTree as ET

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn
    RICH_AVAILABLE = True
    console = Console()
except ImportError:
    RICH_AVAILABLE = False
    console = None

try:
    from bs4 import BeautifulSoup
    BS4_AVAILABLE = True
except ImportError:
    BS4_AVAILABLE = False

try:
    import dns.resolver
    import dns.reversename
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False

try:
    from jinja2 import Template, Environment, FileSystemLoader
    JINJA2_AVAILABLE = True
except ImportError:
    JINJA2_AVAILABLE = False

try:
    import whois
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False


class LoggerSetup:
    """Enhanced logging configuration."""

    @staticmethod
    def setup(verbose: bool = False, log_file: Optional[str] = None) -> logging.Logger:
        """Configure logging with optional file output."""
        level = logging.DEBUG if verbose else logging.INFO

        logger = logging.getLogger('OSINT')
        logger.setLevel(level)

        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')

        console_handler = logging.StreamHandler()
        console_handler.setLevel(level)
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)

        if log_file:
            file_handler = logging.FileHandler(log_file)
            file_handler.setLevel(level)
            file_handler.setFormatter(formatter)
            logger.addHandler(file_handler)

        return logger


logger = LoggerSetup.setup()

INDICATORS = {
    'success': '[✓]',
    'error': '[✗]',
    'warning': '[!]',
    'processing': '[*]',
    'input': '[>]',
    'found': '[+]',
    'not_found': '[-]'
}


class CachedResponse:
    """Lightweight response wrapper for cached data."""

    def __init__(self, text: str, status_code: int = 200):
        """Initialize with text content and status code."""
        self.text = text
        self.status_code = status_code

    def json(self):
        """Parse cached text as JSON."""
        return json.loads(self.text)


class CacheManager:
    """Response cache with TTL support for text and JSON data."""

    def __init__(self, ttl: int = 3600):
        """Initialize cache with TTL in seconds."""
        self.cache = {}
        self.ttl = ttl
        self.timestamps = {}

    def get(self, key: str):
        """Retrieve cached value if not expired."""
        if key not in self.cache:
            return None

        if time.time() - self.timestamps[key] > self.ttl:
            del self.cache[key]
            del self.timestamps[key]
            return None

        return self.cache[key]

    def set(self, key: str, value):
        """Store any value in cache (text, JSON, dict)."""
        self.cache[key] = value
        self.timestamps[key] = time.time()

    def clear(self):
        """Clear all cached data."""
        self.cache.clear()
        self.timestamps.clear()


class HTTPEngine:
    """
    Enterprise-grade HTTP client with proxy rotation, retry logic, and custom headers.

    Features:
    - Automatic retry with exponential backoff
    - User-agent rotation
    - Proxy rotation with health checks
    - Custom header support
    - Connection pooling
    - Request caching
    """

    USER_AGENTS = [
        'Mozilla/5.0 (X11; Linux x86_64; rv:115.0) Gecko/20100101 Firefox/115.0',
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:115.0) Gecko/20100101 Firefox/115.0',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 13_5) AppleWebKit/537.36'
    ]

    def __init__(self, timeout: int = 20, proxies: Optional[List[str]] = None, api_tokens: Optional[List[str]] = None, cache_enabled: bool = True):
        """Initialize HTTP engine with proxy/user-agent rotation, rate limiting, and token rotation."""
        self.session = requests.Session()
        self.ua_index = 0
        self.timeout = timeout
        self.proxies = proxies or []
        self.proxy_index = 0
        self.api_tokens = api_tokens or []
        self.token_index = 0
        self.cache = CacheManager() if cache_enabled else None
        self.request_count = 0
        self.failed_requests = 0
        self.rate_limit_remaining = None
        self.rate_limit_reset = None

        retry = Retry(
            total=5,
            backoff_factor=2,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET", "POST"]
        )

        adapter = HTTPAdapter(
            max_retries=retry,
            pool_connections=30,
            pool_maxsize=30,
            pool_block=False
        )

        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

        logger.debug(f"HTTPEngine initialized with {len(self.proxies)} proxies and cache {'enabled' if cache_enabled else 'disabled'}")

    def _get_next_proxy(self) -> Optional[Dict]:
        """Get next proxy from rotation list."""
        if not self.proxies:
            return None

        proxy_url = self.proxies[self.proxy_index]
        self.proxy_index = (self.proxy_index + 1) % len(self.proxies)

        return {
            'http': proxy_url,
            'https': proxy_url
        }

    def _get_next_token(self) -> Optional[str]:
        """Get next API token from rotation list."""
        if not self.api_tokens:
            return None

        token = self.api_tokens[self.token_index]
        self.token_index = (self.token_index + 1) % len(self.api_tokens)

        return token

    def get(self, url: str, params: Optional[Dict] = None, headers: Optional[Dict] = None,
            use_cache: bool = True) -> Optional[requests.Response]:
        """
        Perform HTTP GET request with retry, proxy rotation, caching, and rate limiting.

        Args:
            url: Target URL
            params: Query parameters
            headers: Custom headers to include
            use_cache: Whether to use cache (if enabled)

        Returns:
            Response object or None if all retries fail
        """
        cache_key = f"{url}_{json.dumps(params or {}, sort_keys=True)}"

        if use_cache and self.cache:
            cached_text = self.cache.get(cache_key)
            if cached_text:
                logger.debug(f"Cache hit for {url}")
                return CachedResponse(cached_text, 200)

        try:
            req_headers = headers or {}
            req_headers.setdefault('User-Agent', self.USER_AGENTS[self.ua_index])
            self.ua_index = (self.ua_index + 1) % len(self.USER_AGENTS)
            req_headers.setdefault('Accept', 'application/json,text/html,*/*;q=0.9')
            req_headers.setdefault('Accept-Language', 'en-US,en;q=0.9')
            req_headers.setdefault('Connection', 'keep-alive')

            proxy = self._get_next_proxy()

            response = self.session.get(
                url,
                params=params,
                headers=req_headers,
                timeout=self.timeout,
                verify=False,
                allow_redirects=True,
                proxies=proxy
            )

            self.request_count += 1

            # Handle rate limiting (HTTP 429)
            if response.status_code == 429:
                reset_time = response.headers.get('X-RateLimit-Reset')
                if reset_time:
                    wait_seconds = int(reset_time) - int(time.time())
                    if wait_seconds > 0:
                        logger.warning(f"Rate limit reached. Waiting {wait_seconds} seconds")
                        time.sleep(min(wait_seconds, 60))

            # Track API rate limit from response headers
            if 'X-RateLimit-Remaining' in response.headers:
                self.rate_limit_remaining = int(response.headers.get('X-RateLimit-Remaining', 0))
                self.rate_limit_reset = int(response.headers.get('X-RateLimit-Reset', 0))

                if self.rate_limit_remaining == 0:
                    reset_time = self.rate_limit_reset - int(time.time())
                    if reset_time > 0:
                        logger.warning(f"API rate limit exhausted. Reset in {reset_time} seconds")

            if response.status_code == 200 and self.cache and use_cache:
                try:
                    self.cache.set(cache_key, response.text)
                except Exception as e:
                    logger.debug(f"Cache storage failed for {url}: {type(e).__name__}")

            return response

        except requests.exceptions.RequestException as e:
            self.failed_requests += 1
            logger.debug(f"Request failed ({url}): {type(e).__name__}")
            return None

    def get_stats(self) -> Dict:
        """Get HTTP engine statistics including rate limit info."""
        stats = {
            'total_requests': self.request_count,
            'failed_requests': self.failed_requests,
            'success_rate': round((self.request_count - self.failed_requests) / max(self.request_count, 1) * 100, 2),
            'proxies_available': len(self.proxies)
        }

        if self.rate_limit_remaining is not None:
            stats['rate_limit_remaining'] = self.rate_limit_remaining
        if self.rate_limit_reset is not None:
            stats['rate_limit_reset'] = self.rate_limit_reset

        return stats


class GitHubIntel:
    """Advanced GitHub intelligence collector with detailed analysis."""

    API_BASE = 'https://api.github.com'

    def __init__(self, http: HTTPEngine, api_token: Optional[str] = None):
        self.http = http
        self.api_token = api_token
        self.headers = {}
        if api_token:
            self.headers['Authorization'] = f'token {api_token}'

    def collect(self, username: str) -> Dict:
        """Comprehensive GitHub user investigation."""
        intel = {
            'found': False,
            'user': {},
            'repos': [],
            'events': [],
            'gists': [],
            'followers': [],
            'following': [],
            'organizations': [],
            'contributed_to': [],
            'stats': {
                'total_stars': 0,
                'total_forks': 0,
                'total_watchers': 0,
                'languages': {},
                'commit_times': [],
                'most_active_hours': [],
                'repositories_contributed': [],
                'total_repositories': 0,
                'average_stars_per_repo': 0
            },
            'discovered_emails': set(),
            'discovered_names': set(),
            'risk_indicators': []
        }

        response = self.http.get(f'{self.API_BASE}/users/{username}', headers=self.headers)
        if not response or response.status_code != 200:
            logger.warning(f"GitHub user not found: {username}")
            return intel

        try:
            user_data = response.json()
        except (ValueError, json.JSONDecodeError) as e:
            logger.error(f"Failed to parse GitHub response: {e}")
            return intel

        intel['found'] = True
        intel['user'] = {
            'login': user_data.get('login'),
            'name': user_data.get('name'),
            'company': user_data.get('company'),
            'blog': user_data.get('blog'),
            'location': user_data.get('location'),
            'email': user_data.get('email'),
            'bio': user_data.get('bio'),
            'twitter': user_data.get('twitter_username'),
            'repos': user_data.get('public_repos', 0),
            'gists': user_data.get('public_gists', 0),
            'followers': user_data.get('followers', 0),
            'following': user_data.get('following', 0),
            'created': user_data.get('created_at'),
            'updated': user_data.get('updated_at'),
            'profile_url': user_data.get('html_url'),
            'avatar_url': user_data.get('avatar_url'),
            'public_repos': user_data.get('public_repos', 0)
        }

        if user_data.get('name'):
            intel['discovered_names'].add(user_data['name'])
        if user_data.get('email'):
            intel['discovered_emails'].add(user_data['email'])

        # Collect risk indicators
        if user_data.get('bio') and any(x in user_data['bio'].lower() for x in ['admin', 'root', 'security']):
            intel['risk_indicators'].append('Mentions privileged roles in bio')

        self._collect_repos(username, intel)
        self._collect_events(username, intel)
        self._collect_gists(username, intel)
        self._collect_network(username, intel)
        self._collect_organizations(username, intel)
        self._scan_credentials(username, intel)

        if intel['repos']:
            intel['stats']['total_repositories'] = len(intel['repos'])
            intel['stats']['average_stars_per_repo'] = intel['stats']['total_stars'] / len(intel['repos']) if intel['repos'] else 0

        intel['discovered_emails'] = list(intel['discovered_emails'])
        intel['discovered_names'] = list(intel['discovered_names'])

        return intel

    def _paginate_api(self, url: str) -> List[Dict]:
        """Paginate through API endpoint following Link header until all results obtained."""
        all_results = []
        current_url = url
        params = {'per_page': 100}

        while current_url:
            try:
                response = self.http.get(current_url, params=params, headers=self.headers)

                if not response or response.status_code != 200:
                    break

                data = response.json()
                if not data:
                    break

                all_results.extend(data)

                # Follow the Link header to get next page
                current_url = self._get_next_page_url(response)
                params = {}  # URL already has params after first request

            except (ValueError, json.JSONDecodeError):
                logger.debug(f"Pagination stopped at {current_url}")
                break

        return all_results

    def _get_next_page_url(self, response) -> Optional[str]:
        """Extract next page URL from Link header."""
        link_header = response.headers.get('Link', '')
        if not link_header:
            return None

        # Parse Link header: Link: <url1>; rel="next", <url2>; rel="last"
        links = link_header.split(',')
        for link in links:
            if 'rel="next"' in link:
                # Extract URL from <url>
                url_part = link.split(';')[0].strip()
                if url_part.startswith('<') and url_part.endswith('>'):
                    return url_part[1:-1]

        return None

    def _collect_repos(self, username: str, intel: Dict):
        """Extract repository metadata and statistics with pagination."""
        try:
            repos = self._paginate_api(f'{self.API_BASE}/users/{username}/repos')

            if not repos:
                return
        except Exception as e:
            logger.error(f"Failed to collect repos for {username}: {str(e)[:100]}")
            return

        for repo in repos:
            repo_intel = {
                'name': repo.get('name'),
                'full_name': repo.get('full_name'),
                'description': repo.get('description'),
                'language': repo.get('language'),
                'stars': repo.get('stargazers_count', 0),
                'forks': repo.get('forks_count', 0),
                'watchers': repo.get('watchers_count', 0),
                'size': repo.get('size', 0),
                'created': repo.get('created_at'),
                'updated': repo.get('updated_at'),
                'url': repo.get('html_url'),
                'topics': repo.get('topics', []),
                'is_fork': repo.get('fork', False),
                'is_archived': repo.get('archived', False),
                'open_issues': repo.get('open_issues_count', 0),
                'visibility': 'private' if repo.get('private') else 'public'
            }

            intel['repos'].append(repo_intel)
            intel['stats']['total_stars'] += repo_intel['stars']
            intel['stats']['total_forks'] += repo_intel['forks']
            intel['stats']['total_watchers'] += repo_intel['watchers']

            if repo_intel['language']:
                lang = repo_intel['language']
                intel['stats']['languages'][lang] = intel['stats']['languages'].get(lang, 0) + 1

    def _collect_events(self, username: str, intel: Dict):
        """Extract activity patterns and commit history with pagination."""
        try:
            events = self._paginate_api(f'{self.API_BASE}/users/{username}/events/public')

            if not events:
                return
        except Exception as e:
            logger.debug(f"Failed to collect events for {username}: {str(e)[:100]}")
            return

        commit_times = []

        for event in events:
            event_type = event.get('type')
            created_at = event.get('created_at')
            repo_name = event.get('repo', {}).get('name')

            event_intel = {
                'type': event_type,
                'created': created_at,
                'repo': repo_name,
                'action': event.get('payload', {}).get('action')
            }

            if event_type == 'PushEvent':
                commits = event.get('payload', {}).get('commits', [])
                for commit in commits:
                    author = commit.get('author', {})
                    if author.get('email'):
                        intel['discovered_emails'].add(author['email'])
                    if author.get('name'):
                        intel['discovered_names'].add(author['name'])

                if created_at:
                    commit_times.append(created_at)

            if repo_name and repo_name not in intel['stats']['repositories_contributed']:
                intel['stats']['repositories_contributed'].append(repo_name)

            intel['events'].append(event_intel)

        if commit_times:
            hours = []
            for t in commit_times:
                try:
                    hour = int(t.split('T')[1].split(':')[0])
                    hours.append(hour)
                except (IndexError, ValueError):
                    pass

            if hours:
                hour_counts = Counter(hours)
                intel['stats']['most_active_hours'] = [
                    {'hour': h, 'count': c} for h, c in hour_counts.most_common(5)
                ]

    def _collect_gists(self, username: str, intel: Dict):
        """Extract gist information."""
        try:
            response = self.http.get(
                f'{self.API_BASE}/users/{username}/gists',
                params={'per_page': 30},
                headers=self.headers
            )

            if not response or response.status_code != 200:
                return

            gists = response.json()
        except (ValueError, json.JSONDecodeError):
            return

        for gist in gists:
            intel['gists'].append({
                'id': gist.get('id'),
                'url': gist.get('html_url'),
                'created': gist.get('created_at'),
                'updated': gist.get('updated_at'),
                'public': gist.get('public'),
                'files': list(gist.get('files', {}).keys())
            })

    def _collect_network(self, username: str, intel: Dict):
        """Extract follower/following information."""
        for endpoint, field in [('followers', 'followers'), ('following', 'following')]:
            try:
                response = self.http.get(
                    f'{self.API_BASE}/users/{username}/{endpoint}',
                    params={'per_page': 100},
                    headers=self.headers
                )

                if not response or response.status_code != 200:
                    continue

                users = response.json()
            except (ValueError, json.JSONDecodeError):
                continue

            intel[field] = [{'login': u.get('login'), 'url': u.get('html_url')} for u in users[:100]]

    def _collect_organizations(self, username: str, intel: Dict):
        """Extract organization memberships."""
        try:
            response = self.http.get(
                f'{self.API_BASE}/users/{username}/orgs',
                headers=self.headers
            )

            if not response or response.status_code != 200:
                return

            orgs = response.json()
        except (ValueError, json.JSONDecodeError):
            return

        intel['organizations'] = [
            {'login': o.get('login'), 'url': o.get('html_url'), 'avatar': o.get('avatar_url')}
            for o in orgs
        ]

    def _scan_credentials(self, username: str, intel: Dict):
        """Scan repositories and descriptions for exposed credentials."""
        credential_patterns = {
            'AWS_KEY': r'AKIA[0-9A-Z]{16}',
            'PRIVATE_KEY': r'-----BEGIN (?:RSA |DSA |EC )?PRIVATE KEY',
            'API_KEY': r'[\'"]?(?:api_key|apikey|API_KEY|api-key)[\'"]?\s*[:=]\s*[\'"]?[a-zA-Z0-9_\-]{20,}',
            'SECRET': r'[\'"]?(?:secret|password|passwd|pwd)[\'"]?\s*[:=]\s*[\'"]?[a-zA-Z0-9_\-]{10,}',
            'TOKEN': r'[\'"]?(?:token|auth_token)[\'"]?\s*[:=]\s*(?:ghp_|github_|sk_|pk_)[a-zA-Z0-9_\-]{20,}',
            'DATABASE_URL': r'(?:postgres|mysql|mongodb)://[a-zA-Z0-9:@\.\-_/]+',
            'AWS_REGION': r'us-(?:east|west)-[12]'
        }

        credential_findings = {}

        try:
            for repo in intel.get('repos', [])[:10]:
                repo_name = repo.get('name', '')
                description = repo.get('description') or ''

                if not isinstance(description, str):
                    description = str(description) if description else ''

                for pattern_name, pattern in credential_patterns.items():
                    if re.search(pattern, description, re.IGNORECASE):
                        if pattern_name not in credential_findings:
                            credential_findings[pattern_name] = []
                        credential_findings[pattern_name].append(f"{repo_name}: {description[:50]}")

            if credential_findings:
                intel['risk_indicators'].append('Potential credentials found in repo descriptions')
                intel['credential_exposure'] = credential_findings
                logger.warning(f"Credential patterns detected in {username} repos")

        except Exception as e:
            logger.debug(f"Credential scan failed for {username}: {str(e)[:100]}")


class DomainIntel:
    """Domain intelligence with DNS analysis."""

    def __init__(self, http: HTTPEngine):
        self.http = http

    def analyze(self, domain: str) -> Dict:
        """Domain analysis: DNS, email security, and registrant data."""
        intel = {
            'domain': domain,
            'valid': False,
            'dns_records': {},
            'email_security': {},
            'registrant_info': {},
            'vulnerabilities': [],
            'ip_addresses': []
        }

        domain_regex = r'^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$'
        if not re.match(domain_regex, domain.lower()):
            logger.warning(f"Invalid domain format: {domain}")
            return intel

        intel['valid'] = True

        if DNS_AVAILABLE:
            self._analyze_dns(domain, intel)

        self._analyze_email_security(domain, intel)

        if WHOIS_AVAILABLE:
            self._analyze_whois(domain, intel)

        return intel

    def _analyze_dns(self, domain: str, intel: Dict):
        """Resolve domain names to IP addresses and DNS records."""
        record_types = ['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME', 'SOA']

        for record_type in record_types:
            try:
                answers = dns.resolver.resolve(domain, record_type)
                intel['dns_records'][record_type] = [str(rdata) for rdata in answers]

                if record_type == 'A':
                    intel['ip_addresses'].extend([str(rdata) for rdata in answers])
            except Exception as e:
                error_name = type(e).__name__
                logger.debug(f"DNS {record_type} lookup for {domain}: {error_name}")

    def _analyze_email_security(self, domain: str, intel: Dict):
        """Check domain email security policies."""
        has_sender_policy = False
        has_auth_policy = False

        try:
            answers = dns.resolver.resolve(domain, 'TXT')
            txt_records = [str(rdata) for rdata in answers]
            has_sender_policy = any('v=spf1' in record for record in txt_records)
        except Exception as e:
            logger.debug(f"Email security policy check failed for {domain}")

        try:
            auth_answers = dns.resolver.resolve(f'_dmarc.{domain}', 'TXT')
            has_auth_policy = any('v=DMARC1' in str(rdata) for rdata in auth_answers)
        except Exception as e:
            logger.debug(f"Auth policy check failed for {domain}")

        intel['email_security'] = {
            'sender_policy': has_sender_policy,
            'auth_policy': has_auth_policy
        }

        if not has_sender_policy:
            intel['vulnerabilities'].append('Missing sender policy (email can be spoofed)')
        if not has_auth_policy:
            intel['vulnerabilities'].append('Missing auth policy (no email validation)')

    def _analyze_whois(self, domain: str, intel: Dict):
        """Query registrant information and domain metadata."""
        try:
            whois_data = whois.whois(domain)

            intel['registrant_info'] = {
                'registrant': whois_data.get('registrant_name') or whois_data.get('name'),
                'registrar': whois_data.get('registrar'),
                'creation_date': str(whois_data.get('creation_date')),
                'expiration_date': str(whois_data.get('expiration_date')),
                'updated_date': str(whois_data.get('updated_date')),
                'nameservers': whois_data.get('name_servers', [])
            }

            if intel['registrant_info']['registrant']:
                logger.debug(f"WHOIS data retrieved for {domain}")
            else:
                logger.debug(f"WHOIS data incomplete for {domain}")

        except Exception as e:
            logger.debug(f"WHOIS lookup failed for {domain}: {str(e)[:100]}")


class SocialIntel:
    """Search for user presence across multiple platforms and websites."""

    PLATFORMS = {
        'GitHub': 'https://github.com/{username}',
        'GitLab': 'https://gitlab.com/{username}',
        'Twitter': 'https://twitter.com/{username}',
        'LinkedIn': 'https://linkedin.com/in/{username}',
        'Reddit': 'https://reddit.com/user/{username}',
        'Instagram': 'https://instagram.com/{username}',
        'TikTok': 'https://tiktok.com/@{username}',
        'Twitch': 'https://twitch.tv/{username}',
        'YouTube': 'https://youtube.com/@{username}',
        'Mastodon': 'https://mastodon.social/@{username}',
        'StackOverflow': 'https://stackoverflow.com/users/?tab=newest&search={username}',
        'HackerOne': 'https://hackerone.com/{username}',
        'Bugcrowd': 'https://bugcrowd.com/researchers/{username}',
        'Dev.to': 'https://dev.to/{username}',
        'Medium': 'https://medium.com/@{username}',
        'CodePen': 'https://codepen.io/{username}',
        'Patreon': 'https://patreon.com/{username}',
        'Behance': 'https://behance.net/{username}',
        'Dribbble': 'https://dribbble.com/{username}',
        'Discord': 'https://discord.com/users/{username}'
    }

    def __init__(self, http: HTTPEngine):
        self.http = http

    def search(self, username: str) -> Dict[str, bool]:
        """Check if username exists across multiple platforms."""
        results = {}

        for platform, url_template in self.PLATFORMS.items():
            url = url_template.format(username=username)
            exists = self._check_url(url, platform)
            results[platform] = exists

        return results

    def _check_url(self, url: str, platform: str) -> bool:
        """Check if URL returns valid response."""
        try:
            response = self.http.get(url, use_cache=False)

            if not response:
                return False

            status = response.status_code
            if status == 200:
                return True
            elif status == 404:
                return False
            elif status in [301, 302, 307, 308]:
                return True
            else:
                logger.debug(f"{platform} check returned {status}")
                return status != 404

        except Exception as e:
            logger.debug(f"Platform check failed for {platform}: {type(e).__name__}")
            return False


class BreachIntel:
    """Intelligence module for checking emails in data breaches."""

    def __init__(self, http: HTTPEngine):
        self.http = http
        self.api_url = 'https://haveibeenpwned.com/api/v3'
        self.breach_cache = {}

    def check_emails(self, emails: List[str]) -> Dict[str, List[str]]:
        """Check if emails appear in known data breaches."""
        results = {}

        if not emails:
            return results

        for email in emails:
            results[email] = self._check_single_email(email)

        return results

    def _check_single_email(self, email: str) -> List[str]:
        """Check single email for breach presence."""
        if email in self.breach_cache:
            return self.breach_cache[email]

        breaches = []

        try:
            headers = {
                'User-Agent': 'OSINT-Framework',
                'Add-Padding': 'true'
            }

            response = self.http.get(
                f'{self.api_url}/breachedaccount/{email}',
                headers=headers
            )

            if response and response.status_code == 200:
                data = response.json()
                breaches = [breach.get('Name') for breach in data if isinstance(data, list)]
            elif response and response.status_code == 404:
                breaches = []
            else:
                logger.debug(f"Breach check failed for {email}: HTTP {response.status_code if response else 'N/A'}")

        except Exception as e:
            logger.debug(f"Error checking breaches for {email}: {str(e)[:100]}")

        self.breach_cache[email] = breaches
        return breaches


class RiskScorer:
    """Advanced risk scoring system."""

    RISK_WEIGHTS = {
        'exposed_emails': 0.2,
        'email_breaches': 0.25,
        'public_repos': 0.15,
        'activity_patterns': 0.1,
        'network_size': 0.1,
        'vulnerabilities': 0.1,
        'domain_vulnerabilities': 0.1
    }

    def __init__(self):
        self.scores = {}

    def calculate_user_risk(self, intel: Dict) -> Dict:
        """Calculate overall risk score for user based on multiple factors."""
        score_breakdown = {}

        # Email exposure score
        emails = intel.get('github', {}).get('discovered_emails', [])
        email_score = min(len(emails) * 15, 100)
        score_breakdown['exposed_emails'] = (email_score, self.RISK_WEIGHTS['exposed_emails'])

        # Email breach score (checking if emails are in known data breaches)
        breach_score = 0
        breach_data = intel.get('breach_intel', {})
        if breach_data:
            emails_in_breaches = sum(1 for breaches in breach_data.values() if breaches)
            breach_score = min(emails_in_breaches * 30, 100)
        score_breakdown['email_breaches'] = (breach_score, self.RISK_WEIGHTS['email_breaches'])

        # Repository public exposure
        repos = intel.get('github', {}).get('repos', [])
        public_repos = len([r for r in repos if r.get('visibility') == 'public'])
        repo_score = min(public_repos * 5, 100)
        score_breakdown['public_repos'] = (repo_score, self.RISK_WEIGHTS['public_repos'])

        # Activity consistency
        activity_score = 50
        temporal = intel.get('temporal_analysis', {})
        if temporal.get('most_active_hours'):
            activity_score = 30
        score_breakdown['activity_patterns'] = (activity_score, self.RISK_WEIGHTS['activity_patterns'])

        # Network risk
        followers = intel.get('github', {}).get('user', {}).get('followers', 0)
        network_score = min(followers / 10, 100)
        score_breakdown['network_size'] = (network_score, self.RISK_WEIGHTS['network_size'])

        # Vulnerability indicators
        vuln_score = len(intel.get('github', {}).get('risk_indicators', [])) * 10
        score_breakdown['vulnerabilities'] = (min(vuln_score, 100), self.RISK_WEIGHTS['vulnerabilities'])

        # Domain vulnerabilities
        domain_vuln_score = 0
        domain_intel = intel.get('domain', {})
        if domain_intel.get('vulnerabilities'):
            domain_vuln_score = min(len(domain_intel['vulnerabilities']) * 20, 100)
        score_breakdown['domain_vulnerabilities'] = (domain_vuln_score, self.RISK_WEIGHTS['domain_vulnerabilities'])

        # Calculate composite score
        total_score = sum(score * weight for score, weight in score_breakdown.values())

        if total_score >= 80:
            risk_level = 'CRITICAL'
        elif total_score >= 60:
            risk_level = 'HIGH'
        elif total_score >= 40:
            risk_level = 'MEDIUM'
        else:
            risk_level = 'LOW'

        return {
            'overall_score': round(total_score, 2),
            'risk_level': risk_level,
            'breakdown': score_breakdown
        }


class ExportManager:
    """Handle multiple export formats."""

    @staticmethod
    def to_json(data: Dict, filepath: str) -> bool:
        """Export to JSON format."""
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False, default=str)
            logger.info(f"JSON export saved: {filepath}")
            return True
        except (OSError, IOError) as e:
            logger.error(f"JSON export failed - file operation error: {e}")
            return False
        except (TypeError, ValueError) as e:
            logger.error(f"JSON export failed - serialization error: {e}")
            return False
        except Exception as e:
            logger.error(f"JSON export failed - unexpected error: {e}")
            return False

    @staticmethod
    def to_csv(data: Dict, filepath: str) -> bool:
        """Export to CSV format."""
        try:
            with open(filepath, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)

                # Flatten data structure for CSV
                github = data.get('github', {})
                rows = []

                if github.get('found'):
                    user = github.get('user', {})
                    rows.append(['GitHub Profile Found', 'Yes'])
                    rows.append(['Name', user.get('name', 'N/A')])
                    rows.append(['Login', user.get('login', 'N/A')])
                    rows.append(['Location', user.get('location', 'N/A')])
                    rows.append(['Company', user.get('company', 'N/A')])
                    rows.append(['Followers', user.get('followers', 0)])
                    rows.append(['Repositories', user.get('repos', 0)])
                    rows.append(['Emails Discovered', '; '.join(github.get('discovered_emails', []))])
                    rows.append(['Names Discovered', '; '.join(github.get('discovered_names', []))])

                writer.writerows(rows)

            logger.info(f"CSV export saved: {filepath}")
            return True
        except (OSError, IOError) as e:
            logger.error(f"CSV export failed - file operation error: {e}")
            return False
        except Exception as e:
            logger.error(f"CSV export failed - unexpected error: {e}")
            return False

    @staticmethod
    def to_html(data: Dict, filepath: str) -> bool:
        """Export to HTML format with Jinja2 template if available."""
        try:
            if JINJA2_AVAILABLE:
                template_str = '''<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>OSINT Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        h1 { color: #333; border-bottom: 3px solid #007bff; padding-bottom: 10px; margin-bottom: 30px; }
        h2 { color: #555; margin-top: 25px; border-left: 4px solid #007bff; padding-left: 10px; }
        .section { background: #f9f9f9; padding: 20px; margin: 15px 0; border-left: 4px solid #007bff; border-radius: 4px; }
        .stat { display: inline-block; margin: 10px; padding: 15px; background: #e7f3ff; border-radius: 5px; border-left: 4px solid #007bff; }
        table { width: 100%; border-collapse: collapse; margin: 10px 0; }
        th, td { border: 1px solid #ddd; padding: 12px; text-align: left; }
        th { background: #007bff; color: white; font-weight: bold; }
        tr:nth-child(even) { background: #f5f5f5; }
        .risk-critical { color: #dc3545; font-weight: bold; }
        .risk-high { color: #fd7e14; font-weight: bold; }
        .risk-medium { color: #ffc107; font-weight: bold; }
        .risk-low { color: #28a745; font-weight: bold; }
        .score-box { padding: 20px; background: #f0f0f0; border-radius: 8px; text-align: center; margin: 15px 0; }
        .risk-score { font-size: 32px; font-weight: bold; margin: 10px 0; }
        .vulnerability { color: #dc3545; margin: 8px 0; padding: 8px; background: #fff0f0; border-left: 3px solid #dc3545; }
        .credential { color: #ff6b6b; font-weight: bold; padding: 5px 10px; background: #ffe0e0; border-radius: 3px; margin: 5px 0; }
        .email-breach { background: #fff3cd; padding: 10px; margin: 8px 0; border-left: 3px solid #ffc107; }
    </style>
</head>
<body>
    <div class="container">
        <h1>OSINT Intelligence Report</h1>
        <p>Report Generated: {{ timestamp }}</p>

        <div class="section">
            <h2>Target Information</h2>
            <table>
                <tr><th>Property</th><th>Value</th></tr>
                <tr><td>Target</td><td>{{ target }}</td></tr>
                <tr><td>Investigation Time</td><td>{{ timestamp }}</td></tr>
            </table>
        </div>

        {% if github.found %}
        <div class="section">
            <h2>Profile Data</h2>
            <table>
                <tr><th>Property</th><th>Value</th></tr>
                <tr><td>Name</td><td>{{ github.user.name or 'N/A' }}</td></tr>
                <tr><td>Login</td><td>{{ github.user.login or 'N/A' }}</td></tr>
                <tr><td>Location</td><td>{{ github.user.location or 'N/A' }}</td></tr>
                <tr><td>Company</td><td>{{ github.user.company or 'N/A' }}</td></tr>
                <tr><td>Followers</td><td>{{ github.user.followers or 0 }}</td></tr>
                <tr><td>Repositories</td><td>{{ github.user.repos or 0 }}</td></tr>
                <tr><td>Gists</td><td>{{ github.user.gists or 0 }}</td></tr>
            </table>
        </div>

        {% if risk_assessment %}
        <div class="section">
            <h2>Risk Assessment</h2>
            <div class="score-box">
                <div>Overall Risk Score</div>
                <div class="risk-score risk-{{ risk_assessment.risk_level.lower() }}">{{ risk_assessment.overall_score }}</div>
                <div class="risk-{{ risk_assessment.risk_level.lower() }}">{{ risk_assessment.risk_level }}</div>
            </div>
            {% if risk_assessment.score_breakdown %}
            <h3>Risk Score Breakdown</h3>
            <table>
                <tr><th>Factor</th><th>Score</th><th>Weight</th><th>Impact</th></tr>
                {% for factor, values in risk_assessment.score_breakdown.items() %}
                <tr>
                    <td>{{ factor|replace('_', ' ')|title }}</td>
                    <td>{{ values[0]|round(1) }}</td>
                    <td>{{ values[1]|round(2) }}</td>
                    <td>{{ (values[0] * values[1])|round(2) }}</td>
                </tr>
                {% endfor %}
            </table>
            {% endif %}
        </div>
        {% endif %}

        {% if github.repos %}
        <div class="section">
            <h2>Repositories ({{ github.repos|length }})</h2>
            <table>
                <tr><th>Name</th><th>Language</th><th>Stars</th><th>Updated</th><th>Visibility</th></tr>
                {% for repo in github.repos[:20] %}
                <tr>
                    <td><a href="{{ repo.url }}" target="_blank">{{ repo.name }}</a></td>
                    <td>{{ repo.language or 'N/A' }}</td>
                    <td>{{ repo.stars }}</td>
                    <td>{{ repo.updated[:10] if repo.updated else 'N/A' }}</td>
                    <td>{{ repo.visibility }}</td>
                </tr>
                {% endfor %}
            </table>
            {% if github.repos|length > 20 %}
            <p><em>Showing 20 of {{ github.repos|length }} repositories</em></p>
            {% endif %}
        </div>
        {% endif %}

        {% if social_intel %}
        <div class="section">
            <h2>Social Media Presence</h2>
            {% set found_platforms = [] %}
            {% for platform, found in social_intel.items() %}
                {% if found %}
                    {% set _ = found_platforms.append(platform) %}
                {% endif %}
            {% endfor %}
            <p>Profile found on <strong>{{ found_platforms|length }}/20</strong> platforms:</p>
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 10px; margin-top: 10px;">
                {% for platform in found_platforms %}
                <div style="padding: 10px; background: #e7f3ff; border-radius: 5px; border-left: 4px solid #28a745;">{{ platform }}</div>
                {% endfor %}
            </div>
        </div>
        {% endif %}

        {% if github.discovered_emails %}
        <div class="section">
            <h2>Discovered Emails</h2>
            <table>
                <tr><th>Email</th></tr>
                {% for email in github.discovered_emails %}
                <tr><td>{{ email }}</td></tr>
                {% endfor %}
            </table>
        </div>
        {% endif %}

        {% if github.risk_indicators %}
        <div class="section">
            <h2>Risk Indicators</h2>
            {% for indicator in github.risk_indicators %}
            <div class="vulnerability">{{ indicator }}</div>
            {% endfor %}
        </div>
        {% endif %}

        {% if github.credential_exposure %}
        <div class="section">
            <h2>Credential Exposure Detection</h2>
            {% for pattern, findings in github.credential_exposure.items() %}
            <h3>{{ pattern }}</h3>
            {% for finding in findings %}
            <div class="credential">{{ finding }}</div>
            {% endfor %}
            {% endfor %}
        </div>
        {% endif %}

        {% if breach_intel %}
        <div class="section">
            <h2>Data Breach Analysis</h2>
            {% for email, breaches in breach_intel.items() %}
            {% if breaches %}
            <div class="email-breach">
                <strong>{{ email }}</strong> found in {{ breaches|length }} breach(es):
                <ul>
                {% for breach in breaches %}
                    <li>{{ breach }}</li>
                {% endfor %}
                </ul>
            </div>
            {% endif %}
            {% endfor %}
        </div>
        {% endif %}

        {% endif %}

        {% if domain %}
        <div class="section">
            <h2>Domain Analysis</h2>
            {% if domain.vulnerabilities %}
            <h3>Vulnerabilities</h3>
            {% for vuln in domain.vulnerabilities %}
            <div class="vulnerability">{{ vuln }}</div>
            {% endfor %}
            {% endif %}
        </div>
        {% endif %}

        <div class="section" style="margin-top: 40px; padding-top: 20px; border-top: 2px solid #ddd; font-size: 12px; color: #666;">
            <p>Report generated by OSINT Framework v4.0</p>
            <p>This intelligence is for authorized security testing and research only.</p>
        </div>
    </div>
</body>
</html>'''

                template = Template(template_str)
                html_content = template.render(
                    target=data.get('target', 'N/A'),
                    timestamp=data.get('timestamp', 'N/A'),
                    github=data.get('github', {}),
                    risk_assessment=data.get('risk_assessment', {}),
                    breach_intel=data.get('breach_intel', {}),
                    social_intel=data.get('social_intel', {}),
                    domain=data.get('domain', {})
                )
            else:
                github = data.get('github', {})
                user = github.get('user', {})
                risk = data.get('risk_assessment', {})
                repos = github.get('repos', [])
                social = data.get('social_intel', {})
                breach = data.get('breach_intel', {})

                repos_html = ''
                if repos:
                    repos_html = '<h3>Repositories</h3><table><tr><th>Name</th><th>Language</th><th>Stars</th><th>Visibility</th></tr>'
                    for repo in repos[:15]:
                        lang = repo.get('language') or 'N/A'
                        repos_html += f"<tr><td>{repo.get('name')}</td><td>{lang}</td><td>{repo.get('stars', 0)}</td><td>{repo.get('visibility')}</td></tr>"
                    repos_html += '</table>'

                social_html = ''
                if social:
                    found = [p for p, f in social.items() if f]
                    if found:
                        social_html = f'<h3>Social Media Presence ({len(found)}/20)</h3><p>{", ".join(found)}</p>'

                risk_html = ''
                if risk:
                    risk_color = {'CRITICAL': '#dc3545', 'HIGH': '#fd7e14', 'MEDIUM': '#ffc107', 'LOW': '#28a745'}.get(risk.get('risk_level'), '#007bff')
                    risk_html = f'<div class="section"><h2>Risk Assessment</h2><h3 style="color: {risk_color};">{risk.get("risk_level")} - Score: {risk.get("overall_score")}</h3></div>'

                html_content = f'''<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>OSINT Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        h1 {{ color: #333; border-bottom: 3px solid #007bff; padding-bottom: 10px; margin-bottom: 30px; }}
        h2 {{ color: #555; margin-top: 25px; border-left: 4px solid #007bff; padding-left: 10px; }}
        h3 {{ color: #666; margin-top: 15px; }}
        .section {{ background: #f9f9f9; padding: 20px; margin: 15px 0; border-left: 4px solid #007bff; border-radius: 4px; }}
        table {{ width: 100%; border-collapse: collapse; margin: 15px 0; }}
        th, td {{ border: 1px solid #ddd; padding: 12px; text-align: left; }}
        th {{ background: #007bff; color: white; font-weight: bold; }}
        tr:nth-child(even) {{ background: #f5f5f5; }}
        .stat {{ display: inline-block; margin: 10px; padding: 15px; background: #e7f3ff; border-radius: 5px; border-left: 4px solid #007bff; }}
        .footer {{ margin-top: 40px; padding-top: 20px; border-top: 2px solid #ddd; font-size: 12px; color: #666; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>OSINT Intelligence Report (Fallback HTML)</h1>

        <div class="section">
            <h2>Target Information</h2>
            <table>
                <tr><th>Property</th><th>Value</th></tr>
                <tr><td>Target</td><td>{data.get('target', 'N/A')}</td></tr>
                <tr><td>Generated</td><td>{data.get('timestamp', 'N/A')}</td></tr>
            </table>
        </div>

        {risk_html}

        <div class="section">
            <h2>GitHub Profile</h2>
            <table>
                <tr><th>Property</th><th>Value</th></tr>
                <tr><td>Name</td><td>{user.get('name', 'N/A')}</td></tr>
                <tr><td>Login</td><td>{user.get('login', 'N/A')}</td></tr>
                <tr><td>Location</td><td>{user.get('location', 'N/A')}</td></tr>
                <tr><td>Company</td><td>{user.get('company', 'N/A')}</td></tr>
                <tr><td>Followers</td><td>{user.get('followers', 0)}</td></tr>
                <tr><td>Repositories</td><td>{user.get('repos', 0)}</td></tr>
            </table>
        </div>

        {repos_html}
        {social_html}

        <div class="footer">
            <p>Report generated by OSINT Framework v4.0</p>
            <p>This intelligence is for authorized security testing and research only.</p>
        </div>
    </div>
</body>
</html>'''

            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(html_content)

            logger.info(f"HTML export saved: {filepath}")
            return True
        except (OSError, IOError) as e:
            logger.error(f"HTML export failed - file operation error: {e}")
            return False
        except Exception as e:
            logger.error(f"HTML export failed - unexpected error: {e}")
            return False

    @staticmethod
    def to_xml(data: Dict, filepath: str) -> bool:
        """Export to XML format."""
        try:
            root = ET.Element('osint_report')
            root.set('timestamp', data.get('timestamp', ''))

            target_elem = ET.SubElement(root, 'target')
            target_elem.text = data.get('target', 'N/A')

            github_elem = ET.SubElement(root, 'github')
            github_data = data.get('github', {})

            if github_data.get('found'):
                github_elem.set('found', 'true')
                user = github_data.get('user', {})

                for key, value in user.items():
                    elem = ET.SubElement(github_elem, key)
                    elem.text = str(value)

                emails_elem = ET.SubElement(github_elem, 'discovered_emails')
                for email in github_data.get('discovered_emails', []):
                    email_elem = ET.SubElement(emails_elem, 'email')
                    email_elem.text = email
            else:
                github_elem.set('found', 'false')

            tree = ET.ElementTree(root)
            tree.write(filepath, encoding='utf-8', xml_declaration=True)

            logger.info(f"XML export saved: {filepath}")
            return True
        except (OSError, IOError) as e:
            logger.error(f"XML export failed - file operation error: {e}")
            return False
        except Exception as e:
            logger.error(f"XML export failed - unexpected error: {e}")
            return False


class OSINTSystem:
    """Main OSINT orchestration system."""

    def __init__(self, proxies: Optional[List[str]] = None, api_token: Optional[str] = None,
                 cache_enabled: bool = True):
        """Initialize OSINT system with all intelligence modules."""
        self.http = HTTPEngine(proxies=proxies, api_tokens=[api_token] if api_token else None, cache_enabled=cache_enabled)
        self.github = GitHubIntel(self.http, api_token=api_token)
        self.domain = DomainIntel(self.http)
        self.breach_intel = BreachIntel(self.http)
        self.social_intel = SocialIntel(self.http)
        self.risk_scorer = RiskScorer()
        self.export_manager = ExportManager()

    def investigate(self, username: str) -> Dict:
        """Perform comprehensive user investigation."""
        logger.info(f"Starting investigation for: {username}")

        github_data = self.github.collect(username)

        report = {
            'target': username,
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'github': github_data,
            'http_stats': self.http.get_stats()
        }

        # Check discovered emails for breaches
        discovered_emails = github_data.get('discovered_emails', [])
        if discovered_emails:
            logger.info(f"Checking {len(discovered_emails)} emails for breaches")
            report['breach_intel'] = self.breach_intel.check_emails(discovered_emails)

        # Search for social media presence
        logger.info(f"Searching for {username} across social platforms")
        report['social_intel'] = self.social_intel.search(username)

        # Calculate risk score (now includes breach data)
        report['risk_assessment'] = self.risk_scorer.calculate_user_risk(report)

        return report

    def investigate_batch(self, usernames: List[str]) -> List[Dict]:
        """Investigate multiple users."""
        logger.info(f"Starting batch investigation for {len(usernames)} users")

        results = []
        for username in usernames:
            report = self.investigate(username)
            results.append(report)
            time.sleep(1)  # Rate limiting

        return results

    def investigate_domain(self, domain: str) -> Dict:
        """Investigate domain."""
        logger.info(f"Starting domain investigation for: {domain}")

        return {
            'target': domain,
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'domain': self.domain.analyze(domain)
        }


class AdvancedInterface:
    """Enhanced CLI with advanced features."""

    def __init__(self):
        self.use_rich = RICH_AVAILABLE

    def display_report(self, report: Dict):
        """Display investigation report."""
        if not self.use_rich or not console:
            self._display_report_plain(report)
            return

        console.print(f"\n[bold cyan]OSINT Investigation Report[/bold cyan]")
        console.print(f"Target: [yellow]{report.get('target')}[/yellow]")
        console.print(f"Timestamp: [dim]{report.get('timestamp')}[/dim]\n")

        # Risk assessment
        risk = report.get('risk_assessment', {})
        risk_level = risk.get('risk_level', 'UNKNOWN')
        score = risk.get('overall_score', 0)

        if risk_level == 'CRITICAL':
            risk_color = 'red'
        elif risk_level == 'HIGH':
            risk_color = 'orange1'
        elif risk_level == 'MEDIUM':
            risk_color = 'yellow'
        else:
            risk_color = 'green'

        console.print(f"Risk Assessment: [{risk_color}]{risk_level}[/{risk_color}] (Score: {score})")

        # Risk score breakdown table
        breakdown = risk.get('score_breakdown', {})
        if breakdown:
            console.print(f"\n[bold]Risk Score Breakdown[/bold]")
            breakdown_table = Table(title="Risk Factors Analysis")
            breakdown_table.add_column("Factor", style="cyan")
            breakdown_table.add_column("Score", style="yellow")
            breakdown_table.add_column("Weight", style="magenta")
            breakdown_table.add_column("Impact", style="green")

            for factor, (factor_score, weight) in breakdown.items():
                impact = factor_score * weight
                breakdown_table.add_row(
                    factor.replace('_', ' ').title(),
                    f"{factor_score:.1f}",
                    f"{weight:.2f}",
                    f"{impact:.2f}"
                )

            console.print(breakdown_table)

        # GitHub section
        github = report.get('github', {})
        if github.get('found'):
            console.print(f"\n[bold]GitHub Profile Found[/bold]")
            user = github.get('user', {})

            table = Table(title="GitHub User Info")
            table.add_column("Property", style="cyan")
            table.add_column("Value", style="magenta")

            for key, value in user.items():
                if key not in ['profile_url', 'avatar_url']:
                    table.add_row(key, str(value))

            console.print(table)

            # Repositories summary
            repos = github.get('repos', [])
            if repos:
                console.print(f"\n[bold]Repositories ({len(repos)})[/bold]")
                repos_table = Table(title="Recent Repositories")
                repos_table.add_column("Name", style="cyan")
                repos_table.add_column("Language", style="yellow")
                repos_table.add_column("Stars", style="magenta")
                repos_table.add_column("Visibility", style="green")

                for repo in repos[:10]:
                    repos_table.add_row(
                        repo.get('name', 'N/A'),
                        repo.get('language', 'N/A'),
                        str(repo.get('stars', 0)),
                        repo.get('visibility', 'N/A')
                    )

                console.print(repos_table)

            # Social profiles
            console.print(f"\n[bold]Social Media Presence[/bold]")
            social = report.get('social_intel', {})
            if social:
                found_platforms = [p for p, found in social.items() if found]
                console.print(f"  Found on {len(found_platforms)}/20 platforms")
                platforms_per_line = 5
                for i in range(0, len(found_platforms), platforms_per_line):
                    console.print(f"  {', '.join(found_platforms[i:i+platforms_per_line])}")

            if github.get('discovered_emails'):
                console.print(f"\n[bold yellow]Discovered Emails:[/bold yellow]")
                for email in github.get('discovered_emails', []):
                    console.print(f"  [red]{email}[/red]")

    def _display_report_plain(self, report: Dict):
        """Display report in plain text."""
        print(f"\n{'='*60}")
        print(f"OSINT Investigation Report")
        print(f"Target: {report.get('target')}")
        print(f"Timestamp: {report.get('timestamp')}")
        print(f"{'='*60}\n")

        risk = report.get('risk_assessment', {})
        print(f"Risk Level: {risk.get('risk_level')} (Score: {risk.get('overall_score')})")

        github = report.get('github', {})
        if github.get('found'):
            print(f"\n[+] GitHub Profile Found")
            user = github.get('user', {})
            for key, value in user.items():
                if key not in ['profile_url', 'avatar_url']:
                    print(f"  {key}: {value}")

            if github.get('discovered_emails'):
                print(f"\n[+] Discovered Emails:")
                for email in github.get('discovered_emails', []):
                    print(f"  - {email}")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='Advanced OSINT Intelligence System v3',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  %(prog)s john_doe
  %(prog)s john_doe -o report.json
  %(prog)s --batch users.txt -o results.json
  %(prog)s john_doe --proxy https://proxy:8080
  %(prog)s --domain example.com
  %(prog)s john_doe --format html --output report.html
        '''
    )

    parser.add_argument('target', nargs='?', help='Username to investigate')
    parser.add_argument('--batch', help='File with list of usernames (one per line)')
    parser.add_argument('--domain', help='Domain to investigate')
    parser.add_argument('-o', '--output', help='Output file path')
    parser.add_argument('--format', choices=['json', 'csv', 'html', 'xml'], default='json',
                       help='Output format (default: json)')
    parser.add_argument('--proxy', action='append', help='Proxy URL (can be used multiple times)')
    parser.add_argument('--api-token', help='GitHub API token for higher rate limits')
    parser.add_argument('--no-cache', action='store_true', help='Disable response caching')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose logging')
    parser.add_argument('--log-file', help='Save logs to file')

    args = parser.parse_args()

    # Setup logging
    global logger
    logger = LoggerSetup.setup(verbose=args.verbose, log_file=args.log_file)

    logger.info("OSINT System v3 initialized")

    # Initialize system
    proxies = args.proxy if args.proxy else None
    system = OSINTSystem(proxies=proxies, api_token=args.api_token, cache_enabled=not args.no_cache)
    interface = AdvancedInterface()

    # Batch processing
    if args.batch:
        try:
            with open(args.batch, 'r', encoding='utf-8') as f:
                usernames = [line.strip() for line in f if line.strip()]

            logger.info(f"Processing {len(usernames)} users from batch file")
            reports = system.investigate_batch(usernames)

            if args.output:
                combined = {
                    'timestamp': datetime.now(timezone.utc).isoformat(),
                    'target_count': len(usernames),
                    'reports': reports
                }
                system.export_manager.to_json(combined, args.output)
                logger.info(f"Batch results saved to {args.output}")

        except Exception as e:
            logger.error(f"Batch processing failed: {e}")
            sys.exit(1)

    # Domain investigation
    elif args.domain:
        logger.info(f"Investigating domain: {args.domain}")
        report = system.investigate_domain(args.domain)
        interface.display_report(report)

        if args.output:
            system.export_manager.to_json(report, args.output)

    # Single target investigation
    elif args.target:
        logger.info(f"Investigating target: {args.target}")
        report = system.investigate(args.target)
        interface.display_report(report)

        if args.output:
            file_format = args.format.lower()
            output_path = args.output if args.output.endswith(f'.{file_format}') else f"{args.output}.{file_format}"

            if file_format == 'json':
                system.export_manager.to_json(report, output_path)
            elif file_format == 'csv':
                system.export_manager.to_csv(report, output_path)
            elif file_format == 'html':
                system.export_manager.to_html(report, output_path)
            elif file_format == 'xml':
                system.export_manager.to_xml(report, output_path)

    else:
        parser.print_help()


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n{INDICATORS['warning']} Interrupted by user")
        sys.exit(0)
    except Exception as e:
        logger.error(f"{INDICATORS['error']} Fatal error: {str(e)}")
        if logging.getLogger().level == logging.DEBUG:
            import traceback
            traceback.print_exc()
        sys.exit(1)