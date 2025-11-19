#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
OSINT Intelligence System
Multi-platform threat intelligence and data extraction tool.
"""

# ============================================================================
# IMPORTS & DEPENDENCIES
# ============================================================================

import sys
import json
import time
import logging
import argparse
import hashlib
import re
import socket
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple
from collections import Counter

# Core HTTP dependencies
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Optional rich library for enhanced terminal UI
try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.style import Style
    from rich.text import Text
    from rich import box
    from rich.progress import track, Progress, SpinnerColumn, TextColumn
    RICH_AVAILABLE = True
    console = Console()
except ImportError:
    RICH_AVAILABLE = False
    console = None

# Optional BeautifulSoup for web scraping
try:
    from bs4 import BeautifulSoup
    BS4_AVAILABLE = True
except ImportError:
    BS4_AVAILABLE = False

# ============================================================================
# CONFIGURATION & CONSTANTS
# ============================================================================

# Color theme configuration - Dark background with green accents
THEME = {
    'background': 'black',          # Main background
    'primary': 'green',             # Primary color for success/highlights
    'accent': 'cyan',               # Titles and section headers
    'success': 'bright_green',      # Success messages
    'warning': 'yellow',            # Warning messages
    'error': 'red',                 # Error messages
    'info': 'white',                # General information
    'dim': 'bright_black'           # Dimmed/secondary text
}

# Visual indicators for different message types
INDICATORS = {
    'success': '[OK]',
    'error': '[ERROR]',
    'warning': '[!]',
    'processing': '[*]',
    'input': '[>]',
    'found': '[+]',
    'not_found': '[-]'
}

# Logging configuration
logging.basicConfig(
    level=logging.INFO,
    format='%(message)s'
)
logger = logging.getLogger('OSINT')


# ============================================================================
# HTTP ENGINE
# ============================================================================

class HTTPEngine:
    """
    Enhanced HTTP client with automatic retry logic and user-agent rotation.

    Provides robust HTTP request handling with:
    - Automatic retries for failed requests
    - User-agent rotation to avoid detection
    - Connection pooling for performance
    - Configurable timeouts and error handling
    """

    USER_AGENTS = [
        'Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0',
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
    ]

    def __init__(self):
        """
        Initialize HTTP engine with session and retry strategy.

        Sets up:
        - Persistent HTTP session for connection reuse
        - Retry strategy for handling transient failures
        - Connection pooling for better performance
        """
        self.session = requests.Session()
        self.ua_index = 0

        # Configure retry strategy for resilient requests
        retry = Retry(
            total=5,
            backoff_factor=2,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET", "POST"]
        )

        adapter = HTTPAdapter(
            max_retries=retry,
            pool_connections=20,
            pool_maxsize=20,
            pool_block=False
        )

        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

    def get_user_agent(self) -> str:
        """
        Rotate through available user agents to avoid detection.

        Returns:
            str: A user-agent string from the rotation pool
        """
        ua = self.USER_AGENTS[self.ua_index]
        self.ua_index = (self.ua_index + 1) % len(self.USER_AGENTS)
        return ua

    def get(self, url: str, **kwargs) -> Optional[requests.Response]:
        """
        Perform HTTP GET request with enhanced error handling.

        Args:
            url: Target URL to request
            **kwargs: Additional parameters passed to requests.get()

        Returns:
            Response object if successful, None if request fails

        Raises:
            No exceptions raised - errors are logged and None is returned
        """
        try:
            headers = kwargs.pop('headers', {})
            headers.setdefault('User-Agent', self.get_user_agent())
            headers.setdefault('Accept', 'application/json,text/html,*/*')
            headers.setdefault('Accept-Language', 'en-US,en;q=0.9')

            response = self.session.get(
                url,
                headers=headers,
                timeout=kwargs.pop('timeout', 20),
                verify=False,
                allow_redirects=True,
                **kwargs
            )
            return response
        except requests.exceptions.RequestException as e:
            logger.debug(f"Request failed: {url} - {e}")
            return None


# ============================================================================
# GITHUB INTELLIGENCE MODULE
# ============================================================================

class GitHubIntel:
    """
    GitHub intelligence collector with data extraction.

    Collects and analyzes:
    - User profile information
    - Repository details and statistics
    - Public events and activity patterns
    - Gists and code snippets
    - Network connections (followers/following)
    - Organization memberships
    - Email addresses and names from commits
    """

    API_BASE = 'https://api.github.com'

    def __init__(self, http: HTTPEngine):
        """
        Initialize GitHub intelligence collector.

        Args:
            http: HTTPEngine instance for making requests
        """
        self.http = http

    def collect(self, username: str) -> Dict:
        """
        Collect GitHub intelligence for a user.

        Args:
            username: GitHub username to investigate

        Returns:
            Dictionary containing all collected intelligence including:
            - found: Boolean indicating if user exists
            - user: Profile information
            - repos: List of repositories
            - events: Public activity events
            - gists: Public gists
            - followers/following: Network connections
            - organizations: Org memberships
            - stats: Aggregated statistics
            - discovered_emails: Email addresses found
            - discovered_names: Real names found
        """
        intel = {
            'found': False,
            'user': {},
            'repos': [],
            'events': [],
            'gists': [],
            'followers': [],
            'following': [],
            'organizations': [],
            'stats': {
                'total_stars': 0,
                'total_forks': 0,
                'total_watchers': 0,
                'languages': {},
                'commit_times': [],
                'most_active_hours': [],
                'repositories_contributed': []
            },
            'discovered_emails': set(),
            'discovered_names': set()
        }

        # Fetch user profile data
        response = self.http.get(f'{self.API_BASE}/users/{username}')
        if not response or response.status_code != 200:
            return intel

        user_data = response.json()
        intel['found'] = True
        intel['user'] = {
            'login': user_data.get('login'),
            'name': user_data.get('name'),
            'company': user_data.get('company'),
            'blog': user_data.get('blog'),
            'location': user_data.get('location'),
            'email': user_data.get('email'),
            'hireable': user_data.get('hireable'),
            'bio': user_data.get('bio'),
            'twitter': user_data.get('twitter_username'),
            'repos': user_data.get('public_repos', 0),
            'gists': user_data.get('public_gists', 0),
            'followers': user_data.get('followers', 0),
            'following': user_data.get('following', 0),
            'created': user_data.get('created_at'),
            'updated': user_data.get('updated_at')
        }

        # Collect discovered information
        if user_data.get('name'):
            intel['discovered_names'].add(user_data.get('name'))
        if user_data.get('email'):
            intel['discovered_emails'].add(user_data.get('email'))

        # Collect additional intelligence from various endpoints
        self._collect_repos(username, intel)
        self._collect_events(username, intel)
        self._collect_gists(username, intel)
        self._collect_network(username, intel)
        self._collect_organizations(username, intel)

        # Convert sets to lists for JSON serialization
        intel['discovered_emails'] = list(intel['discovered_emails'])
        intel['discovered_names'] = list(intel['discovered_names'])

        return intel

    def _collect_repos(self, username: str, intel: Dict):
        """
        Collect all repositories with detailed statistics.

        Args:
            username: GitHub username
            intel: Intelligence dictionary to populate
        """
        response = self.http.get(
            f'{self.API_BASE}/users/{username}/repos',
            params={'per_page': 100, 'sort': 'updated'}
        )

        if response and response.status_code == 200:
            for repo in response.json():
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
                    'pushed': repo.get('pushed_at'),
                    'url': repo.get('html_url'),
                    'topics': repo.get('topics', []),
                    'license': repo.get('license', {}).get('name') if repo.get('license') else None,
                    'is_fork': repo.get('fork', False),
                    'is_archived': repo.get('archived', False),
                    'open_issues': repo.get('open_issues_count', 0)
                }

                intel['repos'].append(repo_intel)
                intel['stats']['total_stars'] += repo_intel['stars']
                intel['stats']['total_forks'] += repo_intel['forks']
                intel['stats']['total_watchers'] += repo_intel['watchers']

                if repo_intel['language']:
                    lang = repo_intel['language']
                    intel['stats']['languages'][lang] = intel['stats']['languages'].get(lang, 0) + 1

    def _collect_events(self, username: str, intel: Dict):
        """
        Collect public events to analyze activity patterns.

        Extracts commit information including author emails and names,
        and analyzes temporal patterns to infer timezone and active hours.

        Args:
            username: GitHub username
            intel: Intelligence dictionary to populate
        """
        response = self.http.get(
            f'{self.API_BASE}/users/{username}/events/public',
            params={'per_page': 100}
        )

        if response and response.status_code == 200:
            events = response.json()
            commit_times = []

            for event in events[:100]:
                event_type = event.get('type')
                created_at = event.get('created_at')
                repo_name = event.get('repo', {}).get('name')

                event_intel = {
                    'type': event_type,
                    'created': created_at,
                    'repo': repo_name
                }

                # Extract commit information for email/name discovery
                if event_type == 'PushEvent':
                    commits = event.get('payload', {}).get('commits', [])
                    for commit in commits:
                        author = commit.get('author', {})
                        if author.get('email'):
                            intel['discovered_emails'].add(author.get('email'))
                        if author.get('name'):
                            intel['discovered_names'].add(author.get('name'))

                    # Track commit times for timezone inference
                    if created_at:
                        commit_times.append(created_at)

                # Track repositories contributed to
                if repo_name and repo_name not in intel['stats']['repositories_contributed']:
                    intel['stats']['repositories_contributed'].append(repo_name)

                intel['events'].append(event_intel)

            # Analyze commit times to infer timezone and active hours
            if commit_times:
                hours = [int(t.split('T')[1].split(':')[0]) for t in commit_times]
                hour_counts = Counter(hours)
                intel['stats']['most_active_hours'] = [
                    {'hour': h, 'count': c} for h, c in hour_counts.most_common(5)
                ]

    def _collect_gists(self, username: str, intel: Dict):
        """
        Collect public gists (code snippets).

        Args:
            username: GitHub username
            intel: Intelligence dictionary to populate
        """
        response = self.http.get(
            f'{self.API_BASE}/users/{username}/gists',
            params={'per_page': 50}
        )

        if response and response.status_code == 200:
            for gist in response.json()[:30]:
                gist_intel = {
                    'id': gist.get('id'),
                    'description': gist.get('description'),
                    'public': gist.get('public'),
                    'files': list(gist.get('files', {}).keys()),
                    'created': gist.get('created_at'),
                    'updated': gist.get('updated_at'),
                    'url': gist.get('html_url')
                }
                intel['gists'].append(gist_intel)

    def _collect_network(self, username: str, intel: Dict):
        """
        Collect network connections (followers and following).

        Limited to top 30 connections for performance.

        Args:
            username: GitHub username
            intel: Intelligence dictionary to populate
        """
        # Collect followers (top 30)
        followers_resp = self.http.get(
            f'{self.API_BASE}/users/{username}/followers',
            params={'per_page': 30}
        )
        if followers_resp and followers_resp.status_code == 200:
            for follower in followers_resp.json()[:30]:
                intel['followers'].append({
                    'login': follower.get('login'),
                    'name': follower.get('name'),
                    'company': follower.get('company'),
                    'location': follower.get('location')
                })

        time.sleep(0.5)

        # Collect following (top 30)
        following_resp = self.http.get(
            f'{self.API_BASE}/users/{username}/following',
            params={'per_page': 30}
        )
        if following_resp and following_resp.status_code == 200:
            for followed in following_resp.json()[:30]:
                intel['following'].append({
                    'login': followed.get('login'),
                    'name': followed.get('name'),
                    'company': followed.get('company'),
                    'location': followed.get('location')
                })

    def _collect_organizations(self, username: str, intel: Dict):
        """
        Collect organization memberships.

        Args:
            username: GitHub username
            intel: Intelligence dictionary to populate
        """
        response = self.http.get(f'{self.API_BASE}/users/{username}/orgs')
        if response and response.status_code == 200:
            for org in response.json():
                intel['organizations'].append({
                    'login': org.get('login'),
                    'description': org.get('description'),
                    'url': f"https://github.com/{org.get('login')}"
                })


# ============================================================================
# REDDIT INTELLIGENCE MODULE
# ============================================================================

class RedditIntel:
    """
    Reddit intelligence collector with behavioral analysis.

    Collects and analyzes:
    - User profile and karma statistics
    - Posts and submissions
    - Comments and discussions
    - Subreddit activity patterns
    - Posting hours and behavior
    - Controversial content ratio
    """

    BASE_URL = 'https://www.reddit.com'

    def __init__(self, http: HTTPEngine):
        """
        Initialize Reddit intelligence collector.

        Args:
            http: HTTPEngine instance for making requests
        """
        self.http = http

    def collect(self, username: str) -> Dict:
        """
        Collect Reddit intelligence for a user.

        Args:
            username: Reddit username to investigate

        Returns:
            Dictionary containing all collected intelligence including:
            - found: Boolean indicating if user exists
            - user: Profile information and karma
            - posts: List of submissions
            - comments: List of comments
            - stats: Behavioral statistics and patterns
        """
        intel = {
            'found': False,
            'user': {},
            'posts': [],
            'comments': [],
            'stats': {
                'top_subreddits': [],
                'posting_hours': [],
                'avg_score': 0,
                'controversial_ratio': 0
            }
        }

        # Fetch user profile
        response = self.http.get(f'{self.BASE_URL}/user/{username}/about.json')
        if not response or response.status_code != 200:
            return intel

        try:
            data = response.json().get('data', {})
            intel['found'] = True
            intel['user'] = {
                'name': data.get('name'),
                'created': data.get('created_utc'),
                'link_karma': data.get('link_karma', 0),
                'comment_karma': data.get('comment_karma', 0),
                'total_karma': data.get('total_karma', 0),
                'is_gold': data.get('is_gold', False),
                'is_mod': data.get('is_mod', False),
                'is_employee': data.get('is_employee', False),
                'verified': data.get('verified', False),
                'has_verified_email': data.get('has_verified_email', False),
                'icon_img': data.get('icon_img')
            }
        except (KeyError, ValueError, Exception):
            return intel

        # Collect posts and comments
        self._collect_posts(username, intel)
        time.sleep(0.5)
        self._collect_comments(username, intel)

        # Analyze behavioral patterns
        self._analyze_patterns(intel)

        return intel

    def _collect_posts(self, username: str, intel: Dict):
        """
        Collect user posts and submissions.

        Args:
            username: Reddit username
            intel: Intelligence dictionary to populate
        """
        response = self.http.get(
            f'{self.BASE_URL}/user/{username}/submitted.json',
            params={'limit': 100}
        )

        if response and response.status_code == 200:
            try:
                posts_data = response.json().get('data', {}).get('children', [])
                for post in posts_data:
                    p = post.get('data', {})
                    intel['posts'].append({
                        'title': p.get('title'),
                        'subreddit': p.get('subreddit'),
                        'score': p.get('score', 0),
                        'upvote_ratio': p.get('upvote_ratio', 0),
                        'num_comments': p.get('num_comments', 0),
                        'created': p.get('created_utc'),
                        'url': p.get('url'),
                        'selftext': p.get('selftext', '')[:500],
                        'is_video': p.get('is_video', False),
                        'over_18': p.get('over_18', False),
                        'gilded': p.get('gilded', 0)
                    })
            except (KeyError, ValueError, Exception):
                pass

    def _collect_comments(self, username: str, intel: Dict):
        """
        Collect user comments.

        Args:
            username: Reddit username
            intel: Intelligence dictionary to populate
        """
        response = self.http.get(
            f'{self.BASE_URL}/user/{username}/comments.json',
            params={'limit': 100}
        )

        if response and response.status_code == 200:
            try:
                comments_data = response.json().get('data', {}).get('children', [])
                for comment in comments_data:
                    c = comment.get('data', {})
                    intel['comments'].append({
                        'subreddit': c.get('subreddit'),
                        'score': c.get('score', 0),
                        'created': c.get('created_utc'),
                        'body': c.get('body', '')[:500],
                        'gilded': c.get('gilded', 0),
                        'controversiality': c.get('controversiality', 0)
                    })
            except (KeyError, ValueError, Exception):
                pass

    def _analyze_patterns(self, intel: Dict):
        """
        Analyze user behavioral patterns.

        Calculates:
        - Top subreddits by activity
        - Average post/comment scores
        - Controversial content ratio

        Args:
            intel: Intelligence dictionary to populate
        """
        # Count subreddit activity
        subreddit_counts = Counter()
        all_scores = []

        for post in intel['posts']:
            subreddit_counts[post['subreddit']] += 1
            all_scores.append(post['score'])

        for comment in intel['comments']:
            subreddit_counts[comment['subreddit']] += 1
            all_scores.append(comment['score'])

        intel['stats']['top_subreddits'] = [
            {'name': sub, 'count': count}
            for sub, count in subreddit_counts.most_common(10)
        ]

        # Calculate average score
        if all_scores:
            intel['stats']['avg_score'] = sum(all_scores) / len(all_scores)

        # Calculate controversial ratio
        controversial_count = sum(1 for c in intel['comments'] if c['controversiality'] > 0)
        if intel['comments']:
            intel['stats']['controversial_ratio'] = controversial_count / len(intel['comments'])


# ============================================================================
# STACKOVERFLOW INTELLIGENCE MODULE
# ============================================================================

class StackOverflowIntel:
    """
    StackOverflow intelligence collector with expertise analysis.

    Collects and analyzes:
    - User profile and reputation
    - Questions asked
    - Answers provided
    - Tag expertise
    - Accept rates
    - Badge achievements
    """

    API_BASE = 'https://api.stackexchange.com/2.3'

    def __init__(self, http: HTTPEngine):
        """
        Initialize StackOverflow intelligence collector.

        Args:
            http: HTTPEngine instance for making requests
        """
        self.http = http

    def collect(self, username: str) -> Dict:
        """
        Collect StackOverflow intelligence for a user.

        Args:
            username: StackOverflow username to investigate

        Returns:
            Dictionary containing all collected intelligence including:
            - found: Boolean indicating if user exists
            - user: Profile and reputation information
            - questions: List of questions asked
            - answers: List of answers provided
            - tags: Technology expertise tags
            - stats: Performance statistics
        """
        intel = {
            'found': False,
            'user': {},
            'questions': [],
            'answers': [],
            'tags': [],
            'stats': {
                'accept_rate': 0,
                'top_tags': [],
                'avg_question_score': 0,
                'avg_answer_score': 0
            }
        }

        # Find user by username
        response = self.http.get(
            f'{self.API_BASE}/users',
            params={'inname': username, 'site': 'stackoverflow'}
        )

        if not response or response.status_code != 200:
            return intel

        try:
            users = response.json().get('items', [])
            if not users:
                return intel

            user = users[0]
            user_id = user.get('user_id')

            intel['found'] = True
            intel['user'] = {
                'id': user_id,
                'name': user.get('display_name'),
                'reputation': user.get('reputation', 0),
                'location': user.get('location'),
                'website': user.get('website_url'),
                'profile_url': user.get('link'),
                'badges': user.get('badge_counts', {}),
                'accept_rate': user.get('accept_rate', 0),
                'question_count': user.get('question_count', 0),
                'answer_count': user.get('answer_count', 0),
                'created': user.get('creation_date'),
                'last_access': user.get('last_access_date')
            }

            # Collect questions, answers, and tags
            self._collect_questions(user_id, intel)
            time.sleep(0.5)
            self._collect_answers(user_id, intel)
            time.sleep(0.5)
            self._collect_tags(user_id, intel)

            # Calculate statistics
            self._calculate_stats(intel)

        except (KeyError, ValueError, Exception) as e:
            logger.debug(f"StackOverflow error: {e}")

        return intel

    def _collect_questions(self, user_id: int, intel: Dict):
        """
        Collect user questions.

        Args:
            user_id: StackOverflow user ID
            intel: Intelligence dictionary to populate
        """
        response = self.http.get(
            f'{self.API_BASE}/users/{user_id}/questions',
            params={'site': 'stackoverflow', 'pagesize': 100, 'sort': 'votes', 'filter': 'withbody'}
        )

        if response and response.status_code == 200:
            for q in response.json().get('items', []):
                intel['questions'].append({
                    'id': q.get('question_id'),
                    'title': q.get('title'),
                    'score': q.get('score', 0),
                    'views': q.get('view_count', 0),
                    'answers': q.get('answer_count', 0),
                    'tags': q.get('tags', []),
                    'answered': q.get('is_answered', False),
                    'accepted': q.get('accepted_answer_id') is not None,
                    'created': q.get('creation_date'),
                    'url': q.get('link')
                })

    def _collect_answers(self, user_id: int, intel: Dict):
        """
        Collect user answers.

        Args:
            user_id: StackOverflow user ID
            intel: Intelligence dictionary to populate
        """
        response = self.http.get(
            f'{self.API_BASE}/users/{user_id}/answers',
            params={'site': 'stackoverflow', 'pagesize': 100, 'sort': 'votes'}
        )

        if response and response.status_code == 200:
            for a in response.json().get('items', []):
                intel['answers'].append({
                    'id': a.get('answer_id'),
                    'question_id': a.get('question_id'),
                    'score': a.get('score', 0),
                    'accepted': a.get('is_accepted', False),
                    'created': a.get('creation_date')
                })

    def _collect_tags(self, user_id: int, intel: Dict):
        """
        Collect user tags (technology expertise).

        Args:
            user_id: StackOverflow user ID
            intel: Intelligence dictionary to populate
        """
        response = self.http.get(
            f'{self.API_BASE}/users/{user_id}/tags',
            params={'site': 'stackoverflow', 'pagesize': 100}
        )

        if response and response.status_code == 200:
            for t in response.json().get('items', []):
                intel['tags'].append({
                    'name': t.get('name'),
                    'count': t.get('count', 0)
                })

    def _calculate_stats(self, intel: Dict):
        """
        Calculate performance statistics.

        Computes average scores and acceptance rates.

        Args:
            intel: Intelligence dictionary to populate
        """
        if intel['questions']:
            scores = [q['score'] for q in intel['questions']]
            intel['stats']['avg_question_score'] = sum(scores) / len(scores)

        if intel['answers']:
            scores = [a['score'] for a in intel['answers']]
            intel['stats']['avg_answer_score'] = sum(scores) / len(scores)
            accepted_count = sum(1 for a in intel['answers'] if a['accepted'])
            intel['stats']['accept_rate'] = (accepted_count / len(intel['answers'])) * 100

        intel['stats']['top_tags'] = intel['tags'][:10]


# ============================================================================
# HAVEIBEENPWNED INTELLIGENCE MODULE
# ============================================================================

class HaveIBeenPwnedIntel:
    """
    HaveIBeenPwned data breach checker.

    Checks email addresses against known data breaches and paste sites.
    Requires API key for full access to breach data.

    Features:
    - Breach history lookup
    - Paste site monitoring
    - Detailed breach information
    - Data class exposure details
    """

    API_BASE = 'https://haveibeenpwned.com/api/v3'

    def __init__(self, http: HTTPEngine, api_key: Optional[str] = None):
        """
        Initialize HaveIBeenPwned checker.

        Args:
            http: HTTPEngine instance for making requests
            api_key: HIBP API key (required for breach checking)
        """
        self.http = http
        self.api_key = api_key

    def check(self, email: str) -> Dict:
        """
        Check email address in data breaches.

        Args:
            email: Email address to check

        Returns:
            Dictionary containing:
            - email: The checked email address
            - breached: Boolean indicating if found in breaches
            - breaches: List of breach details
            - pastes: List of paste exposures
            - note: Information message if API key missing
        """
        intel = {
            'email': email,
            'breached': False,
            'breaches': [],
            'pastes': [],
            'note': None
        }

        if not self.api_key:
            intel['note'] = 'HIBP API key required for breach checking. Set via --hibp-key parameter.'
            logger.info(f"HIBP check skipped for {email}: No API key provided")
            return intel

        # Check breaches
        headers = {'hibp-api-key': self.api_key}
        breach_resp = self.http.get(
            f'{self.API_BASE}/breachedaccount/{email}',
            headers=headers
        )

        if breach_resp and breach_resp.status_code == 200:
            intel['breached'] = True
            try:
                breaches = breach_resp.json()
                for breach in breaches:
                    intel['breaches'].append({
                        'name': breach.get('Name'),
                        'title': breach.get('Title'),
                        'domain': breach.get('Domain'),
                        'breach_date': breach.get('BreachDate'),
                        'added_date': breach.get('AddedDate'),
                        'pwn_count': breach.get('PwnCount'),
                        'description': breach.get('Description'),
                        'data_classes': breach.get('DataClasses', []),
                        'is_verified': breach.get('IsVerified'),
                        'is_sensitive': breach.get('IsSensitive')
                    })
            except (KeyError, ValueError, Exception):
                pass

        time.sleep(1.5)

        # Check pastes
        paste_resp = self.http.get(
            f'{self.API_BASE}/pasteaccount/{email}',
            headers=headers
        )

        if paste_resp and paste_resp.status_code == 200:
            try:
                pastes = paste_resp.json()
                for paste in pastes[:20]:
                    intel['pastes'].append({
                        'source': paste.get('Source'),
                        'id': paste.get('Id'),
                        'title': paste.get('Title'),
                        'date': paste.get('Date'),
                        'email_count': paste.get('EmailCount')
                    })
            except (KeyError, ValueError, Exception):
                pass

        return intel


# ============================================================================
# TWITTER/X INTELLIGENCE MODULE
# ============================================================================

class TwitterIntel:
    """
    Twitter/X intelligence collector via Nitter proxy.

    Uses Nitter instances (privacy-friendly Twitter frontend) to collect:
    - Profile information
    - Recent tweets
    - Hashtag usage patterns
    - User mentions
    - Posting behavior

    Note: Requires BeautifulSoup for HTML parsing
    """

    NITTER_INSTANCES = [
        'https://nitter.net',
        'https://nitter.poast.org',
        'https://nitter.privacydev.net'
    ]

    def __init__(self, http: HTTPEngine):
        """
        Initialize Twitter intelligence collector.

        Args:
            http: HTTPEngine instance for making requests
        """
        self.http = http

    def collect(self, username: str) -> Dict:
        """
        Collect Twitter intelligence via Nitter proxy.

        Args:
            username: Twitter/X username to investigate

        Returns:
            Dictionary containing:
            - found: Boolean indicating if user exists
            - user: Profile information
            - tweets: List of recent tweets
            - stats: Usage statistics (hashtags, mentions)
        """
        intel = {
            'found': False,
            'user': {},
            'tweets': [],
            'stats': {
                'hashtags': [],
                'mentions': [],
                'posting_hours': []
            }
        }

        if not BS4_AVAILABLE:
            logger.debug("BeautifulSoup not available, skipping Twitter scraping")
            return intel

        # Try different Nitter instances until one works
        for instance in self.NITTER_INSTANCES:
            try:
                response = self.http.get(f'{instance}/{username}', timeout=10)
                if response and response.status_code == 200:
                    intel = self._parse_profile(response.text, intel)
                    intel['found'] = True
                    break
            except Exception as e:
                logger.debug(f"Nitter instance {instance} failed: {e}")
                continue

        return intel

    def _parse_profile(self, html: str, intel: Dict) -> Dict:
        """
        Parse Nitter profile page HTML.

        Args:
            html: HTML content from Nitter
            intel: Intelligence dictionary to populate

        Returns:
            Updated intel dictionary
        """
        try:
            soup = BeautifulSoup(html, 'html.parser')

            # Extract profile information
            profile_card = soup.find('div', class_='profile-card')
            if profile_card:
                bio_elem = profile_card.find('div', class_='profile-bio')
                loc_elem = profile_card.find('div', class_='profile-location')
                intel['user']['bio'] = bio_elem.get_text(strip=True) if bio_elem else None
                intel['user']['location'] = loc_elem.get_text(strip=True) if loc_elem else None

            # Extract tweets (limited to 30)
            tweets = soup.find_all('div', class_='timeline-item')[:30]
            for tweet in tweets:
                tweet_text = tweet.find('div', class_='tweet-content')
                if tweet_text:
                    text = tweet_text.get_text(strip=True)
                    intel['tweets'].append({
                        'text': text[:500],
                        'hashtags': re.findall(r'#\w+', text),
                        'mentions': re.findall(r'@\w+', text)
                    })

            # Aggregate hashtags and mentions
            all_hashtags = []
            all_mentions = []
            for tweet in intel['tweets']:
                all_hashtags.extend(tweet['hashtags'])
                all_mentions.extend(tweet['mentions'])

            intel['stats']['hashtags'] = [
                {'tag': tag, 'count': count}
                for tag, count in Counter(all_hashtags).most_common(15)
            ]
            intel['stats']['mentions'] = [
                {'user': user, 'count': count}
                for user, count in Counter(all_mentions).most_common(15)
            ]

        except Exception as e:
            logger.debug(f"Twitter parsing error: {e}")

        return intel


# ============================================================================
# CRYPTOCURRENCY INTELLIGENCE MODULE
# ============================================================================

class CryptoIntel:
    """
    Multi-chain cryptocurrency analyzer.

    Supports:
    - Bitcoin (BTC) via blockchain.info API
    - Ethereum (ETH) via Etherscan API

    Provides:
    - Address balance information
    - Transaction counts
    - First and last transaction timestamps
    - Total received and sent amounts
    """

    def __init__(self, http: HTTPEngine):
        """
        Initialize cryptocurrency analyzer.

        Args:
            http: HTTPEngine instance for making requests
        """
        self.http = http

    def analyze_bitcoin(self, address: str) -> Dict:
        """
        Analyze Bitcoin address using blockchain.info API.

        Args:
            address: Bitcoin address to analyze

        Returns:
            Dictionary containing:
            - chain: 'bitcoin'
            - address: The analyzed address
            - valid: Boolean indicating if address is valid
            - balance: Current balance in BTC
            - total_received: Total BTC received
            - total_sent: Total BTC sent
            - tx_count: Number of transactions
            - first_tx: Timestamp of first transaction
            - last_tx: Timestamp of last transaction
        """
        intel = {
            'chain': 'bitcoin',
            'address': address,
            'valid': False,
            'balance': 0,
            'total_received': 0,
            'total_sent': 0,
            'tx_count': 0,
            'first_tx': None,
            'last_tx': None
        }

        response = self.http.get(
            f'https://blockchain.info/rawaddr/{address}',
            params={'limit': 100}
        )

        if not response or response.status_code != 200:
            return intel

        try:
            data = response.json()
            intel['valid'] = True
            intel['balance'] = data.get('final_balance', 0) / 100000000
            intel['total_received'] = data.get('total_received', 0) / 100000000
            intel['total_sent'] = data.get('total_sent', 0) / 100000000
            intel['tx_count'] = data.get('n_tx', 0)

            # Extract transaction timestamps
            txs = data.get('txs', [])
            if txs:
                intel['first_tx'] = txs[-1].get('time')
                intel['last_tx'] = txs[0].get('time')

        except (KeyError, ValueError, Exception):
            pass

        return intel

    def analyze_ethereum(self, address: str) -> Dict:
        """
        Analyze Ethereum address using public Etherscan API.

        Args:
            address: Ethereum address to analyze

        Returns:
            Dictionary containing:
            - chain: 'ethereum'
            - address: The analyzed address
            - valid: Boolean indicating if address is valid
            - balance: Current balance in ETH
            - tx_count: Number of transactions
        """
        intel = {
            'chain': 'ethereum',
            'address': address,
            'valid': False,
            'balance': 0,
            'tx_count': 0
        }

        # Get balance using public Etherscan API
        response = self.http.get(
            'https://api.etherscan.io/api',
            params={
                'module': 'account',
                'action': 'balance',
                'address': address,
                'tag': 'latest'
            }
        )

        if response and response.status_code == 200:
            try:
                data = response.json()
                if data.get('status') == '1':
                    intel['valid'] = True
                    intel['balance'] = int(data.get('result', 0)) / 1e18
            except (KeyError, ValueError, Exception):
                pass

        time.sleep(0.5)

        # Get transaction count
        tx_resp = self.http.get(
            'https://api.etherscan.io/api',
            params={
                'module': 'proxy',
                'action': 'eth_getTransactionCount',
                'address': address,
                'tag': 'latest'
            }
        )

        if tx_resp and tx_resp.status_code == 200:
            try:
                data = tx_resp.json()
                intel['tx_count'] = int(data.get('result', '0x0'), 16)
            except (KeyError, ValueError, Exception):
                pass

        return intel


# ============================================================================
# EMAIL INTELLIGENCE MODULE
# ============================================================================

class EmailIntel:
    """
    Email validation and intelligence gathering.

    Features:
    - Email format validation
    - Domain extraction
    - MX record verification
    - Gravatar profile detection
    - Disposable email detection
    """

    def __init__(self, http: HTTPEngine):
        """
        Initialize email intelligence collector.

        Args:
            http: HTTPEngine instance for making requests
        """
        self.http = http

    def analyze(self, email: str) -> Dict:
        """
        Analyze email address.

        Args:
            email: Email address to analyze

        Returns:
            Dictionary containing:
            - email: The analyzed email
            - valid_format: Boolean for format validation
            - domain: Email domain
            - mx_records: List of MX records
            - gravatar: Gravatar profile information
            - disposable: Boolean if disposable email provider
        """
        intel = {
            'email': email,
            'valid_format': False,
            'domain': None,
            'mx_records': [],
            'gravatar': {
                'exists': False,
                'hash': None,
                'profile_url': None
            },
            'disposable': False
        }

        # Validate email format
        email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if re.match(email_regex, email):
            intel['valid_format'] = True
            intel['domain'] = email.split('@')[1]

            # Perform additional checks
            self._check_gravatar(email, intel)
            self._check_mx_records(intel['domain'], intel)
            self._check_disposable(intel['domain'], intel)

        return intel

    def _check_gravatar(self, email: str, intel: Dict):
        """
        Check if email has Gravatar profile.

        Args:
            email: Email address to check
            intel: Intelligence dictionary to populate
        """
        email_hash = hashlib.md5(email.lower().encode()).hexdigest()
        gravatar_url = f'https://www.gravatar.com/avatar/{email_hash}?d=404'

        response = self.http.get(gravatar_url)
        if response and response.status_code == 200:
            intel['gravatar']['exists'] = True
            intel['gravatar']['hash'] = email_hash
            intel['gravatar']['profile_url'] = f'https://gravatar.com/{email_hash}'

    def _check_mx_records(self, domain: str, intel: Dict):
        """
        Check MX records for domain.

        Args:
            domain: Domain to check
            intel: Intelligence dictionary to populate
        """
        try:
            import dns.resolver
            try:
                mx_records = dns.resolver.resolve(domain, 'MX')
                intel['mx_records'] = [str(r.exchange).rstrip('.') for r in mx_records]
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
                # Domain not found or no MX records
                intel['mx_records'] = []
        except ImportError:
            logger.debug("dnspython not available, using fallback DNS resolution")
            # Fallback to socket if dnspython not available
            try:
                import socket as sock
                result = sock.gethostbyname(domain)
                if result:
                    intel['mx_records'] = [f'A record: {result}']
                else:
                    intel['mx_records'] = []
            except (socket.gaierror, OSError):
                intel['mx_records'] = []
        except Exception as e:
            logger.debug(f"MX record lookup failed for {domain}: {e}")
            intel['mx_records'] = []

    def _check_disposable(self, domain: str, intel: Dict):
        """
        Check if domain is disposable email provider.

        Args:
            domain: Domain to check
            intel: Intelligence dictionary to populate
        """
        disposable_domains = [
            'tempmail.com', 'guerrillamail.com', '10minutemail.com',
            'mailinator.com', 'throwaway.email', 'temp-mail.org',
            'trashmail.com', 'maildrop.cc', 'getnada.com'
        ]
        intel['disposable'] = domain.lower() in disposable_domains


# ============================================================================
# TEMPORAL ANALYSIS MODULE
# ============================================================================

class TemporalAnalyzer:
    """
    Temporal pattern analyzer across all platforms.

    Analyzes:
    - Activity timestamps from all platforms
    - Timezone inference based on activity patterns
    - Most active hours (UTC)
    - Activity distribution
    - Timeline of events

    Uses machine learning-style heuristics to infer user timezone
    based on when they are most active.
    """

    def analyze(self, report: Dict) -> Dict:
        """
        Perform temporal analysis.

        Args:
            report: Complete investigation report

        Returns:
            Dictionary containing:
            - timezone_inference: Estimated timezone
            - most_active_hours: Peak activity hours
            - activity_patterns: Behavioral patterns
            - timeline_events: Chronological event list
        """
        analysis = {
            'timezone_inference': None,
            'most_active_hours': [],
            'activity_patterns': {},
            'timeline_events': []
        }

        all_timestamps = []

        # Collect timestamps from all platforms
        intel = report.get('intelligence', {})

        # GitHub events
        if 'github' in intel and intel['github'].get('events'):
            for event in intel['github']['events']:
                if event.get('created'):
                    all_timestamps.append({
                        'time': event['created'],
                        'platform': 'github',
                        'type': event.get('type')
                    })

        # Reddit posts and comments
        if 'reddit' in intel:
            for post in intel['reddit'].get('posts', []):
                if post.get('created'):
                    all_timestamps.append({
                        'time': post['created'],
                        'platform': 'reddit',
                        'type': 'post'
                    })

        # StackOverflow questions
        if 'stackoverflow' in intel:
            for q in intel['stackoverflow'].get('questions', []):
                if q.get('created'):
                    all_timestamps.append({
                        'time': q['created'],
                        'platform': 'stackoverflow',
                        'type': 'question'
                    })

        # Analyze collected timestamps
        if all_timestamps:
            analysis = self._analyze_timestamps(all_timestamps, analysis)

        return analysis

    def _analyze_timestamps(self, timestamps: List[Dict], analysis: Dict) -> Dict:
        """
        Analyze timestamp patterns to infer timezone and activity hours.

        Args:
            timestamps: List of timestamp dictionaries
            analysis: Analysis dictionary to populate

        Returns:
            Updated analysis dictionary
        """
        hours = []

        for ts in timestamps:
            time_str = ts['time']
            try:
                # Parse different timestamp formats
                if isinstance(time_str, (int, float)):
                    dt = datetime.fromtimestamp(time_str, tz=timezone.utc)
                else:
                    dt = datetime.fromisoformat(time_str.replace('Z', '+00:00'))

                hours.append(dt.hour)
            except Exception:
                continue

        if hours:
            # Count hour frequencies
            hour_counts = Counter(hours)
            analysis['most_active_hours'] = [
                {'hour': h, 'count': c}
                for h, c in hour_counts.most_common(10)
            ]

            # Infer timezone based on activity patterns
            # Assumption: Most people are active during typical hours (14:00-22:00 local time)
            # Peak activity around 18:00 local time is common
            most_common_hour = hour_counts.most_common(1)[0][0]
            assumed_local_peak = 18
            utc_offset = most_common_hour - assumed_local_peak

            if -12 <= utc_offset <= 14:
                analysis['timezone_inference'] = f"UTC{utc_offset:+d} (estimated based on activity peak at {most_common_hour:02d}:00 UTC)"

        return analysis


# ============================================================================
# MAIN OSINT SYSTEM
# ============================================================================

class OSINTSystem:
    """
    Main OSINT threat intelligence system.

    Orchestrates all intelligence modules and provides unified interface
    for investigations across multiple platforms.

    Features:
    - Username investigation across all platforms
    - Cryptocurrency address analysis
    - Email intelligence gathering
    - Data breach checking
    - Temporal pattern analysis
    - Comprehensive reporting
    """

    def __init__(self, hibp_api_key: Optional[str] = None):
        """
        Initialize OSINT system with all intelligence modules.

        Args:
            hibp_api_key: Optional HaveIBeenPwned API key
        """
        self.http = HTTPEngine()
        self.github = GitHubIntel(self.http)
        self.reddit = RedditIntel(self.http)
        self.stackoverflow = StackOverflowIntel(self.http)
        self.haveibeenpwned = HaveIBeenPwnedIntel(self.http, api_key=hibp_api_key)
        self.twitter = TwitterIntel(self.http)
        self.crypto = CryptoIntel(self.http)
        self.email = EmailIntel(self.http)
        self.temporal = TemporalAnalyzer()

    def investigate(self, username: str) -> Dict:
        """
        Run complete OSINT investigation for username.

        Collects intelligence from all available platforms and performs
        analysis including temporal patterns and email discovery.

        Args:
            username: Target username to investigate

        Returns:
            Complete investigation report dictionary containing:
            - target: Username investigated
            - timestamp: Investigation timestamp
            - intelligence: Data from all platforms
            - discovered_emails: List of found email addresses
            - temporal_analysis: Activity pattern analysis
        """
        logger.info(f"{INDICATORS['processing']} Starting deep investigation: {username}")

        report = {
            'target': username,
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'intelligence': {},
            'discovered_emails': [],
            'temporal_analysis': {}
        }

        # GitHub intelligence collection
        logger.info(f"{INDICATORS['processing']} Collecting GitHub intelligence...")
        github_intel = self.github.collect(username)
        if github_intel['found']:
            report['intelligence']['github'] = github_intel
            report['discovered_emails'].extend(github_intel.get('discovered_emails', []))
            logger.info(f"  {INDICATORS['success']} GitHub: {len(github_intel['repos'])} repos, {len(github_intel['events'])} events")

        # Reddit intelligence collection
        logger.info(f"{INDICATORS['processing']} Collecting Reddit intelligence...")
        reddit_intel = self.reddit.collect(username)
        if reddit_intel['found']:
            report['intelligence']['reddit'] = reddit_intel
            logger.info(f"  {INDICATORS['success']} Reddit: {len(reddit_intel['posts'])} posts, {len(reddit_intel['comments'])} comments")

        # StackOverflow intelligence collection
        logger.info(f"{INDICATORS['processing']} Collecting StackOverflow intelligence...")
        so_intel = self.stackoverflow.collect(username)
        if so_intel['found']:
            report['intelligence']['stackoverflow'] = so_intel
            logger.info(f"  {INDICATORS['success']} StackOverflow: {so_intel['user'].get('reputation', 0):,} reputation")

        # Twitter intelligence collection
        logger.info(f"{INDICATORS['processing']} Collecting Twitter intelligence...")
        twitter_intel = self.twitter.collect(username)
        if twitter_intel['found']:
            report['intelligence']['twitter'] = twitter_intel
            logger.info(f"  {INDICATORS['success']} Twitter: {len(twitter_intel['tweets'])} tweets")

        # HaveIBeenPwned check for discovered emails
        discovered_emails = list(set(report['discovered_emails']))
        if discovered_emails:
            logger.info(f"{INDICATORS['processing']} Checking {len(discovered_emails)} discovered emails in breaches...")
            report['intelligence']['breaches'] = {}
            for email in discovered_emails[:5]:
                breach_intel = self.haveibeenpwned.check(email)
                if breach_intel['breached']:
                    report['intelligence']['breaches'][email] = breach_intel
                    logger.info(f"  {INDICATORS['warning']} {email}: {len(breach_intel['breaches'])} breaches")

        # Email analysis for discovered emails
        if discovered_emails:
            logger.info(f"{INDICATORS['processing']} Analyzing discovered emails...")
            report['intelligence']['emails'] = {}
            for email in discovered_emails[:5]:
                email_intel = self.email.analyze(email)
                report['intelligence']['emails'][email] = email_intel

        # Temporal pattern analysis
        logger.info(f"{INDICATORS['processing']} Performing temporal analysis...")
        temporal_analysis = self.temporal.analyze(report)
        report['temporal_analysis'] = temporal_analysis
        if temporal_analysis.get('timezone_inference'):
            logger.info(f"  {INDICATORS['success']} {temporal_analysis['timezone_inference']}")

        return report

    def analyze_crypto_multi(self, address: str) -> Dict:
        """
        Analyze cryptocurrency address across multiple chains.

        Attempts to identify the blockchain and analyze the address.

        Args:
            address: Cryptocurrency address to analyze

        Returns:
            Intelligence dictionary with blockchain and balance information
        """
        logger.info(f"{INDICATORS['processing']} Analyzing crypto address: {address}")

        # Try Bitcoin first
        btc_intel = self.crypto.analyze_bitcoin(address)
        if btc_intel['valid']:
            logger.info(f"  {INDICATORS['success']} Bitcoin: {btc_intel['balance']:.8f} BTC")
            return btc_intel

        # Try Ethereum
        eth_intel = self.crypto.analyze_ethereum(address)
        if eth_intel['valid']:
            logger.info(f"  {INDICATORS['success']} Ethereum: {eth_intel['balance']:.8f} ETH")
            return eth_intel

        logger.info(f"  {INDICATORS['not_found']} Address not found on supported chains")
        return {'valid': False, 'address': address}


# ============================================================================
# ENHANCED USER INTERFACE
# ============================================================================

class Interface:
    """
    Terminal interface with dark theme and green styling.

    Features:
    - Rich library integration for enhanced visuals
    - Dark background with green accents
    - Professional tables and panels
    - Color-coded status indicators
    - Progress indicators
    - Formatted JSON output
    - Fallback to plain text when rich unavailable
    """

    def __init__(self):
        """
        Initialize interface with rich library if available.
        """
        self.use_rich = RICH_AVAILABLE

    def banner(self):
        """
        Display banner with styling.

        Shows application title and tagline with visual separators.
        """
        if self.use_rich:
            banner_panel = Panel(
                "[bold cyan]OSINT THREAT INTELLIGENCE TOOL[/bold cyan]\n"
                "[green]Professional Edition[/green]\n"
                "[dim]Deep Intelligence Extraction[/dim]",
                box=box.DOUBLE,
                style="green",
                padding=(1, 2)
            )
            console.print("\n")
            console.print(banner_panel)
            console.print()
        else:
            print("\n" + "="*60)
            print("     OSINT THREAT INTELLIGENCE TOOL")
            print("          Professional Edition")
            print("     Deep Intelligence Extraction")
            print("="*60 + "\n")

    def menu(self):
        """
        Display interactive menu with formatting.

        Shows all available options with visual indicators and
        organized sections for different functionality.
        """
        if self.use_rich:
            # Create menu table with dark theme and green accents
            menu_table = Table(
                show_header=False,
                box=box.ROUNDED,
                border_style="green",
                padding=(0, 2)
            )
            menu_table.add_column("Option", style="green bold", width=8)
            menu_table.add_column("Description", style="white")

            menu_table.add_row("", "[bold cyan]=== INVESTIGATION OPTIONS ===[/bold cyan]")
            menu_table.add_row("[1]", "[green]Deep Username Investigation[/green] (All Platforms)")
            menu_table.add_row("[2]", "[green]Cryptocurrency Analysis[/green] (Bitcoin & Ethereum)")
            menu_table.add_row("[3]", "[green]Email Intelligence & HIBP Breach Check[/green]")
            menu_table.add_row("[4]", "[green]Interactive Temporal Analysis[/green]")
            menu_table.add_row("", "")
            menu_table.add_row("", "[bold cyan]=== SYSTEM OPTIONS ===[/bold cyan]")
            menu_table.add_row("[5]", "[green]Help & Documentation[/green]")
            menu_table.add_row("[0]", "[red]Exit[/red]")

            console.print(menu_table)
            console.print()
        else:
            print("\n+========================================================+")
            print("|        OSINT THREAT INTELLIGENCE TOOL                 |")    
            print("+========================================================+")
            print()
            print("  [1] Deep Username Investigation (All Platforms)")
            print("  [2] Cryptocurrency Analysis (Bitcoin & Ethereum)")
            print("  [3] Email Intelligence & HIBP Breach Check")
            print("  [4] Interactive Temporal Analysis")
            print("  [5] Help & Documentation")
            print("  [0] Exit")
            print()

    def help(self):
        """
        Display help documentation.

        Includes usage examples, supported platforms, requirements,
        and important notes about data sources.
        """
        if self.use_rich:
            help_panel = Panel(
                "[bold cyan]USAGE EXAMPLES:[/bold cyan]\n\n"
                "[green]  python osint-tool.py torvalds[/green]\n"
                "    -> Investigate username across all platforms\n\n"
                "[green]  python osint-tool.py --crypto 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa[/green]\n"
                "    -> Analyze cryptocurrency address\n\n"
                "[green]  python osint-tool.py --email user@example.com[/green]\n"
                "    -> Analyze email address\n\n"
                "[green]  python osint-tool.py --hibp-key <key> username[/green]\n"
                "    -> Investigate with HIBP breach checking\n\n"
                "[green]  python osint-tool.py -i[/green]\n"
                "    -> Interactive mode\n\n"
                "[bold cyan]PLATFORMS SUPPORTED:[/bold cyan]\n\n"
                "  [green][OK][/green] GitHub: Profile, repos, events, gists, network, organizations\n"
                "  [green][OK][/green] Reddit: Posts, comments, karma, subreddit analysis\n"
                "  [green][OK][/green] StackOverflow: Questions, answers, tags, reputation\n"
                "  [green][OK][/green] Twitter/X: Tweets, hashtags, mentions (via nitter proxy)\n"
                "  [green][OK][/green] HaveIBeenPwned: Data breaches, pastes (requires API key)\n"
                "  [green][OK][/green] Crypto: Bitcoin, Ethereum analysis\n"
                "  [green][OK][/green] Email: Validation, Gravatar, MX records\n"
                "  [green][OK][/green] Temporal: Timezone inference, activity patterns\n\n"
                "[bold cyan]REQUIREMENTS:[/bold cyan]\n"
                "  * requests, urllib3 (required)\n"
                "  * rich (optional, for enhanced display)\n"
                "  * beautifulsoup4 (optional, for Twitter scraping)\n"
                "  * dnspython (optional, for MX record checks)",
                title="[bold green]OSINT Tool Documentation[/bold green]",
                box=box.ROUNDED,
                border_style="cyan",
                padding=(1, 2)
            )
            console.print("\n")
            console.print(help_panel)
            console.print()
        else:
            print("\n" + "="*70)
            print("USAGE EXAMPLES:")
            print("="*70)
            print("\n  python osint-tool.py torvalds")
            print("    -> Investigate username across all platforms\n")
            print("  python osint-tool.py --crypto 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa")
            print("    -> Analyze cryptocurrency address\n")
            print("  python osint-tool.py --email user@example.com")
            print("    -> Analyze email address\n")
            print("  python osint-tool.py --hibp-key <key> username")
            print("    -> Investigate with HIBP breach checking\n")
            print("  python osint-tool.py -i")
            print("    -> Interactive mode\n")
            print("\n" + "="*70)
            print("PLATFORMS SUPPORTED:")
            print("="*70)
            print("  [OK] GitHub: Profile, repos, events, gists, network")
            print("  [OK] Reddit: Posts, comments, karma, subreddit analysis")
            print("  [OK] StackOverflow: Questions, answers, tags, reputation")
            print("  [OK] Twitter/X: Tweets, hashtags, mentions (via nitter)")
            print("  [OK] HaveIBeenPwned: Data breaches (requires API key)")
            print("  [OK] Crypto: Bitcoin, Ethereum analysis")
            print("  [OK] Email: Validation, Gravatar, MX records")
            print("  [OK] Temporal: Timezone inference, activity patterns")

    def show_results(self, report: Dict):
        """
        Display investigation results with formatting.

        Args:
            report: Complete investigation report to display
        """
        if self.use_rich:
            self._show_rich(report)
        else:
            self._show_plain(report)

    def _show_rich(self, report: Dict):
        """
        Display results using rich library with colors and tables.

        Args:
            report: Investigation report to display
        """
        console.print("\n")
        console.print(Panel(
            "[bold green]DEEP INVESTIGATION COMPLETE[/bold green]",
            box=box.DOUBLE,
            style="green",
            padding=(0, 2)
        ))
        console.print()

        intel = report.get('intelligence', {})

        # Create summary table with styling
        table = Table(
            title="[bold cyan]Intelligence Summary[/bold cyan]",
            box=box.ROUNDED,
            border_style="green",
            show_header=True,
            header_style="bold cyan"
        )
        table.add_column("Platform", style="cyan bold", width=18)
        table.add_column("Status", style="green", width=12)
        table.add_column("Key Intelligence", style="white", width=50)

        # GitHub intelligence
        if 'github' in intel and intel['github']['found']:
            gh = intel['github']
            info = f"{len(gh['repos'])} repos, {len(gh['events'])} events, {len(gh['gists'])} gists"
            if gh.get('discovered_emails'):
                info += f", {len(gh['discovered_emails'])} emails"
            table.add_row("GitHub", f"[green]{INDICATORS['success']}[/green]", info)

        # Reddit intelligence
        if 'reddit' in intel and intel['reddit']['found']:
            rd = intel['reddit']
            info = f"{len(rd['posts'])} posts, {len(rd['comments'])} comments, {rd['user']['total_karma']:,} karma"
            table.add_row("Reddit", f"[green]{INDICATORS['success']}[/green]", info)

        # StackOverflow intelligence
        if 'stackoverflow' in intel and intel['stackoverflow']['found']:
            so = intel['stackoverflow']
            info = f"{so['user']['reputation']:,} rep, {len(so['questions'])} Q, {len(so['answers'])} A"
            table.add_row("StackOverflow", f"[green]{INDICATORS['success']}[/green]", info)

        # Twitter intelligence
        if 'twitter' in intel and intel['twitter']['found']:
            tw = intel['twitter']
            info = f"{len(tw['tweets'])} tweets"
            table.add_row("Twitter/X", f"[green]{INDICATORS['success']}[/green]", info)

        # Breach information
        if 'breaches' in intel and intel['breaches']:
            breach_count = sum(len(b['breaches']) for b in intel['breaches'].values() if 'breaches' in b)
            info = f"{breach_count} breaches found"
            table.add_row("HaveIBeenPwned", f"[yellow]{INDICATORS['warning']} Breached[/yellow]", info)

        console.print(table)

        # Display discovered emails
        if report.get('discovered_emails'):
            console.print("\n[bold yellow]Discovered Emails:[/bold yellow]")
            for email in report['discovered_emails'][:10]:
                console.print(f"  [green]{INDICATORS['found']}[/green] {email}")

        # Display temporal analysis
        temporal = report.get('temporal_analysis', {})
        if temporal.get('timezone_inference'):
            console.print(f"\n[bold cyan]Timezone Analysis:[/bold cyan] {temporal['timezone_inference']}")

        if temporal.get('most_active_hours'):
            console.print("\n[bold cyan]Most Active Hours (UTC):[/bold cyan]")
            for hour_data in temporal['most_active_hours'][:5]:
                console.print(f"  [green]{hour_data['hour']:02d}:00[/green] - {hour_data['count']} activities")

        console.print()

    def _show_plain(self, report: Dict):
        """
        Display results in plain text format (fallback).

        Args:
            report: Investigation report to display
        """
        print("\n" + "="*70)
        print("DEEP INVESTIGATION COMPLETE")
        print("="*70 + "\n")

        intel = report.get('intelligence', {})

        # GitHub summary
        if 'github' in intel and intel['github']['found']:
            print("\n" + INDICATORS['success'] + " GITHUB:")
            print("-" * 50)
            gh = intel['github']
            print(f"  Repos: {len(gh['repos'])}")
            print(f"  Events: {len(gh['events'])}")
            print(f"  Gists: {len(gh['gists'])}")
            print(f"  Followers: {len(gh['followers'])}")
            print(f"  Organizations: {len(gh['organizations'])}")
            if gh.get('discovered_emails'):
                print(f"  Discovered Emails: {len(gh['discovered_emails'])}")

        # Reddit summary
        if 'reddit' in intel and intel['reddit']['found']:
            print("\n" + INDICATORS['success'] + " REDDIT:")
            print("-" * 50)
            rd = intel['reddit']
            print(f"  Karma: {rd['user']['total_karma']:,}")
            print(f"  Posts: {len(rd['posts'])}")
            print(f"  Comments: {len(rd['comments'])}")
            if rd['stats']['top_subreddits']:
                top_subs = ', '.join([s['name'] for s in rd['stats']['top_subreddits'][:5]])
                print(f"  Top Subreddits: {top_subs}")

        # StackOverflow summary
        if 'stackoverflow' in intel and intel['stackoverflow']['found']:
            print("\n" + INDICATORS['success'] + " STACKOVERFLOW:")
            print("-" * 50)
            so = intel['stackoverflow']
            print(f"  Reputation: {so['user']['reputation']:,}")
            print(f"  Questions: {len(so['questions'])}")
            print(f"  Answers: {len(so['answers'])}")
            if so['tags']:
                top_tags = ', '.join([t['name'] for t in so['tags'][:5]])
                print(f"  Top Tags: {top_tags}")

        # Twitter summary
        if 'twitter' in intel and intel['twitter']['found']:
            print("\n" + INDICATORS['success'] + " TWITTER/X:")
            print("-" * 50)
            tw = intel['twitter']
            print(f"  Tweets Collected: {len(tw['tweets'])}")

        # Breach information
        if 'breaches' in intel and intel['breaches']:
            print("\n" + INDICATORS['warning'] + " DATA BREACHES:")
            print("-" * 50)
            for email, breach_data in intel['breaches'].items():
                if 'breaches' in breach_data:
                    print(f"  {email}: {len(breach_data['breaches'])} breaches")

        # Discovered emails
        if report.get('discovered_emails'):
            print("\nDISCOVERED EMAILS:")
            print("-" * 50)
            for email in report['discovered_emails'][:10]:
                print(f"  {INDICATORS['found']} {email}")

        # Temporal analysis
        temporal = report.get('temporal_analysis', {})
        if temporal.get('timezone_inference'):
            print("\nTEMPORAL ANALYSIS:")
            print("-" * 50)
            print(f"  {temporal['timezone_inference']}")

        if temporal.get('most_active_hours'):
            print("  Most Active Hours (UTC):")
            for hour_data in temporal['most_active_hours'][:5]:
                print(f"    {hour_data['hour']:02d}:00 - {hour_data['count']} activities")

        print()

    def prompt(self, message: str) -> str:
        """
        Display prompt and get user input.

        Args:
            message: Prompt message to display

        Returns:
            User input string
        """
        if self.use_rich:
            return console.input(f"[green]{INDICATORS['input']}[/green] {message}: ").strip()
        else:
            return input(f"{INDICATORS['input']} {message}: ").strip()

    def success(self, message: str):
        """
        Display success message.

        Args:
            message: Success message to display
        """
        if self.use_rich:
            console.print(f"[green]{INDICATORS['success']}[/green] {message}")
        else:
            print(f"{INDICATORS['success']} {message}")

    def error(self, message: str):
        """
        Display error message.

        Args:
            message: Error message to display
        """
        if self.use_rich:
            console.print(f"[red]{INDICATORS['error']}[/red] {message}")
        else:
            print(f"{INDICATORS['error']} {message}")

    def warning(self, message: str):
        """
        Display warning message.

        Args:
            message: Warning message to display
        """
        if self.use_rich:
            console.print(f"[yellow]{INDICATORS['warning']}[/yellow] {message}")
        else:
            print(f"{INDICATORS['warning']} {message}")

    def info(self, message: str):
        """
        Display informational message.

        Args:
            message: Info message to display
        """
        if self.use_rich:
            console.print(f"[cyan]{INDICATORS['processing']}[/cyan] {message}")
        else:
            print(f"{INDICATORS['processing']} {message}")


# ============================================================================
# MAIN ENTRY POINT
# ============================================================================

def main():
    """
    Main entry point for OSINT Threat Intelligence Tool.

    Handles:
    - Command-line argument parsing
    - Interactive mode
    - Username investigation
    - Cryptocurrency analysis
    - Email intelligence
    - Report generation and export
    """
    parser = argparse.ArgumentParser(
        description='OSINT Threat Intelligence Tool - Professional Edition',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s torvalds                           # Investigate username
  %(prog)s --crypto 1A1zP1eP...              # Analyze crypto address
  %(prog)s --email user@example.com          # Analyze email
  %(prog)s --hibp-key <key> username         # With breach checking
  %(prog)s -i                                 # Interactive mode
        """
    )
    parser.add_argument('username', nargs='?', help='Target username to investigate')
    parser.add_argument('-i', '--interactive', action='store_true', help='Interactive mode')
    parser.add_argument('--crypto', metavar='ADDRESS', help='Analyze cryptocurrency address')
    parser.add_argument('--email', metavar='EMAIL', help='Analyze email address')
    parser.add_argument('--hibp-key', metavar='KEY', help='HaveIBeenPwned API key')
    parser.add_argument('-o', '--output', metavar='FILE', help='Save report to JSON file')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose logging')

    args = parser.parse_args()

    # Configure logging level
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # Initialize interface and OSINT system
    ui = Interface()
    osint = OSINTSystem(hibp_api_key=args.hibp_key)

    # Interactive mode
    if args.interactive:
        ui.banner()
        while True:
            ui.menu()
            choice = ui.prompt("Enter your choice (0-5)")

            if choice == '0':
                ui.info("Exiting...")
                break

            elif choice == '1':
                username = ui.prompt("Enter username")
                if username:
                    ui.info(f"Starting investigation for: {username}")
                    report = osint.investigate(username)
                    ui.show_results(report)

                    # Save report if output specified
                    if args.output:
                        with open(args.output, 'w', encoding='utf-8') as f:
                            json.dump(report, f, indent=2, ensure_ascii=False)
                        ui.success(f"Report saved: {args.output}")

            elif choice == '2':
                address = ui.prompt("Enter cryptocurrency address")
                if address:
                    intel = osint.analyze_crypto_multi(address)
                    if intel.get('valid'):
                        ui.success(f"{intel['chain'].upper()} Address Analysis:")
                        print(f"  Address: {address}")
                        print(f"  Balance: {intel.get('balance', 0)} {intel['chain'].upper()}")
                        if 'tx_count' in intel:
                            print(f"  Transactions: {intel['tx_count']:,}")
                    else:
                        ui.error("Invalid or unknown cryptocurrency address")

            elif choice == '3':
                email = ui.prompt("Enter email address")
                if email:
                    ui.info(f"Analyzing email: {email}")
                    email_intel = osint.email.analyze(email)

                    print(f"\n  Valid Format: {email_intel['valid_format']}")
                    print(f"  Domain: {email_intel['domain']}")
                    print(f"  Gravatar: {'Yes' if email_intel['gravatar']['exists'] else 'No'}")
                    print(f"  MX Records: {len(email_intel['mx_records'])}")

                    # Check breaches
                    breach_intel = osint.haveibeenpwned.check(email)
                    if breach_intel['breached']:
                        ui.warning(f"{len(breach_intel['breaches'])} data breaches found!")
                        for breach in breach_intel['breaches'][:5]:
                            print(f"    - {breach['name']} ({breach['breach_date']})")
                    elif breach_intel.get('note'):
                        ui.info(breach_intel['note'])
                    else:
                        ui.success("No breaches found")

            elif choice == '4':
                username = ui.prompt("Enter username for temporal analysis")
                if username:
                    ui.info(f"Performing temporal analysis for: {username}")
                    report = osint.investigate(username)
                    temporal = report.get('temporal_analysis', {})

                    if temporal.get('timezone_inference'):
                        ui.success(f"Timezone: {temporal['timezone_inference']}")

                    if temporal.get('most_active_hours'):
                        print("\n  Most Active Hours (UTC):")
                        for hour_data in temporal['most_active_hours'][:5]:
                            print(f"    {hour_data['hour']:02d}:00 - {hour_data['count']} activities")

            elif choice == '5':
                ui.help()

            else:
                ui.error("Invalid option. Please select 0-5.")

    # Cryptocurrency analysis mode
    elif args.crypto:
        ui.banner()
        intel = osint.analyze_crypto_multi(args.crypto)
        if intel.get('valid'):
            ui.success(f"{intel['chain'].upper()} Address Analysis")
            print(f"  Address: {args.crypto}")
            print(f"  Balance: {intel.get('balance', 0)} {intel['chain'].upper()}")
            if 'total_received' in intel:
                print(f"  Total Received: {intel['total_received']} {intel['chain'].upper()}")
                print(f"  Total Sent: {intel['total_sent']} {intel['chain'].upper()}")
            if 'tx_count' in intel:
                print(f"  Transactions: {intel['tx_count']:,}")
        else:
            ui.error("Invalid or unknown cryptocurrency address")

    # Email analysis mode
    elif args.email:
        ui.banner()
        ui.info(f"Analyzing email: {args.email}")
        email_intel = osint.email.analyze(args.email)

        print(f"\n  Valid Format: {email_intel['valid_format']}")
        print(f"  Domain: {email_intel['domain']}")
        print(f"  Gravatar: {'Exists' if email_intel['gravatar']['exists'] else 'Not found'}")
        print(f"  MX Records: {', '.join(email_intel['mx_records'][:3])}")

        # Check breaches
        breach_intel = osint.haveibeenpwned.check(args.email)
        if breach_intel['breached']:
            ui.warning(f"{len(breach_intel['breaches'])} data breaches found!")
            for breach in breach_intel['breaches'][:5]:
                print(f"    - {breach['name']} ({breach['breach_date']})")
        elif breach_intel.get('note'):
            ui.info(breach_intel['note'])
        else:
            ui.success("No breaches found")

    # Username investigation mode
    elif args.username:
        ui.banner()
        ui.info(f"Starting investigation for: {args.username}")
        report = osint.investigate(args.username)
        ui.show_results(report)

        # Save report if output specified
        if args.output:
            with open(args.output, 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=2, ensure_ascii=False)
            ui.success(f"Report saved: {args.output}")

    # No arguments - show help
    else:
        ui.banner()
        ui.help()


# ============================================================================
# SCRIPT EXECUTION
# ============================================================================

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n{INDICATORS['warning']} Interrupted by user")
        sys.exit(0)
    except Exception as e:
        logger.error(f"{INDICATORS['error']} Fatal error: {e}")
        if logging.getLogger().level == logging.DEBUG:
            import traceback
            traceback.print_exc()
        sys.exit(1)
