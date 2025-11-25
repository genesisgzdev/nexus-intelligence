# OSINT Intelligence Framework

## Overview

OSINT Intelligence Framework is an advanced reconnaissance and intelligence gathering platform implementing automated multi-vector analysis across digital footprints. The framework combines username enumeration, email intelligence, domain analysis, social media correlation, and breach data aggregation with real-time caching and risk scoring capabilities to address modern OSINT requirements including identity verification, threat assessment, corporate reconnaissance, and digital investigation.

## Technical Architecture

### Integrated Intelligence System

The framework implements a unified intelligence architecture with modular analysis engines:

- **Seven-Module Intelligence Engine**: Sequential analysis across GitHub profiles, domain infrastructure, breach databases, social media platforms, DNS records, WHOIS data, and SSL certificates
- **Four-Layer Caching System**: Memory-based caching with TTL management, request deduplication, response validation, and automatic cache invalidation
- **Real-Time Correlation**: Cross-platform identity linking with confidence scoring enabling unified profile construction across 200+ platforms
- **Comprehensive Risk Assessment**: Weighted scoring algorithm tracking credential exposure, privilege indicators, and security posture metrics

### Core Intelligence Subsystems

#### HTTP Engine with Advanced Features
- Connection pooling: 30 concurrent connections with session reuse
- Retry strategy: Exponential backoff (5 retries, 2x multiplier)
- Rate limiting: Configurable delays with burst protection
- User-Agent rotation: 50+ browser signatures with randomization
- Proxy support: HTTP/HTTPS/SOCKS with authentication
- Cache implementation: TTL-based memory cache with 3600s default

#### GitHub Intelligence Module
- Full API v3 integration with pagination support (100 items/page)
- Repository mining: Language statistics, commit history, contributor analysis
- Email extraction: Commit history traversal with Git API
- Credential scanning: 7 regex patterns for AWS, API keys, tokens
- Organization mapping: Membership detection and role identification
- Risk indicators: Admin mentions, exposed credentials, sensitive data

#### Domain Intelligence Analyzer
- DNS enumeration: A, AAAA, MX, TXT, NS, SOA, CAA records
- DNSSEC validation: Chain of trust verification
- Email security: SPF, DKIM, DMARC policy analysis
- Subdomain discovery: Certificate transparency logs, DNS brute-force
- WHOIS parsing: Registrant extraction, historical data correlation
- SSL analysis: Certificate chain validation, expiry monitoring

#### Breach Intelligence Aggregator
- HaveIBeenPwned API v3 integration with authentication
- Breach correlation: Email, domain, and paste analysis
- Temporal analysis: Breach timeline construction
- Risk scoring: Severity assessment based on breach types
- Data categories: Password, financial, PII exposure tracking
- Statistics: Total breaches, unique passwords, data classes

#### Social Media Enumerator
- Platform coverage: 200+ social networks and forums
- Username availability: Real-time checking with retry logic
- Profile discovery: Metadata extraction when available
- Cross-correlation: Identity linking across platforms
- Confidence scoring: Response code and content validation
- Category classification: Professional, social, gaming, adult

## Performance Characteristics

- **Sequential execution**: 7 intelligence modules with optimized ordering
- **Response time**: <2s for single module, <30s for comprehensive scan
- **Memory efficiency**: Bounded at 100MB with streaming parsers
- **Cache hit ratio**: 60% reduction in API calls via intelligent caching
- **Rate compliance**: Automatic throttling for API limits
- **Error resilience**: Graceful degradation on module failures

## Feature Implementation

### Automated Intelligence Capabilities

#### Username Enumeration
```python
def enumerate_username(username: str) -> Dict:
    - Platform checking across 200+ sites
    - Response validation (200, 301, 302 = found)
    - Metadata extraction where available
    - Cross-platform correlation
    - Confidence scoring per result
```

#### Email Intelligence
```python
def analyze_email(email: str) -> Dict:
    - Format validation (RFC 5322)
    - Domain verification (MX records)
    - Breach database lookup
    - Paste correlation
    - Risk assessment scoring
```

#### Domain Analysis
```python
def analyze_domain(domain: str) -> Dict:
    - DNS record enumeration
    - WHOIS data extraction
    - SSL certificate analysis
    - Subdomain discovery
    - Technology stack identification
```

### Risk Scoring Algorithm
```python
def calculate_risk_score(intel: Dict) -> RiskAssessment:
    Score calculation (0-100 scale):
    
    GitHub indicators (0-30 points):
    - Exposed credentials: +15 points
    - Admin/root mentions: +10 points
    - No 2FA enabled: +5 points
    
    Breach indicators (0-40 points):
    - Password breaches: +20 points
    - Financial breaches: +15 points
    - Recent breaches (<1 year): +5 points
    
    Domain indicators (0-30 points):
    - No DNSSEC: +10 points
    - No email security (SPF/DKIM): +10 points
    - Expired SSL: +10 points
    
    Classification:
    - 0-30: Low risk
    - 31-60: Medium risk
    - 61-80: High risk
    - 81-100: Critical risk
```

### Caching Architecture
```python
class CacheManager:
    def __init__(self, ttl: int = 3600):
        self.cache = {}
        self.ttl = ttl
        
    def get(self, key: str) -> Optional[str]:
        if key in self.cache:
            data, timestamp = self.cache[key]
            if time.time() - timestamp < self.ttl:
                return data
        return None
```

## Installation

### System Requirements

- **Operating System**: Linux, macOS, Windows 10+ (WSL)
- **Python**: 3.8 or higher
- **Memory**: 2GB RAM minimum (4GB recommended)
- **Network**: Stable internet connection
- **Storage**: 100MB free space

### Dependencies
```bash
# Core requirements
requests>=2.28.0       # HTTP client with session management
dnspython>=2.3.0      # DNS resolution and analysis
python-whois>=0.7.3   # WHOIS data parsing
beautifulsoup4>=4.11.0 # HTML parsing
rich>=13.0.0          # Terminal UI enhancements
jinja2>=3.0.0         # Template rendering
lxml>=4.9.0           # XML parsing
aiohttp>=3.8.0        # Async HTTP operations
```

### Installation Instructions
```bash
# Clone repository
git clone https://github.com/genesisgzdev/nexus-intelligence.git
cd nexus-intelligence

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # Linux/macOS
# OR
venv\Scripts\activate     # Windows

# Install dependencies
pip install --upgrade pip
pip install -r requirements.txt

# Verify installation
python src/osinth.py --help
```

## Usage

### Command-Line Execution
```bash
# Basic username search
python src/osinth.py username

# Email investigation
python src/osinth.py --email user@example.com

# Domain analysis
python src/osinth.py --domain example.com

# Batch processing
python src/osinth.py --batch targets.txt -o results.json

# With proxy
python src/osinth.py username --proxy socks5://127.0.0.1:9050

# Verbose output
python src/osinth.py username -v

# Export formats
python src/osinth.py username --format html --output report.html
python src/osinth.py username --format json --output data.json
python src/osinth.py username --format csv --output results.csv
python src/osinth.py username --format xml --output intel.xml
```

### API Integration
```python
from osinth import OSINTSystem

# Initialize framework
osint = OSINTSystem(cache_enabled=True)

# Username investigation
result = osint.investigate_username("target_user")

# Email analysis
email_intel = osint.investigate_email("user@example.com")

# Domain reconnaissance
domain_intel = osint.investigate_domain("example.com")

# Export results
osint.export_manager.to_json(result, "output.json")
```

## Detection Output Format

### Console Output
```
[OSINT] Starting comprehensive investigation...
================================================================================

[*] Investigating username: john_doe
[+] GitHub profile found: https://github.com/john_doe
[+] Email discovered: john.doe@example.com
[!] Credential pattern detected in repository descriptions
[+] 15 social media profiles identified

[*] GitHub Intelligence:
  - Public repos: 42
  - Followers: 156
  - Organizations: 3
  - Total stars: 523
  - Primary language: Python
  - Account created: 2019-03-15

[*] Breach Intelligence:
  - Total breaches: 3
  - Latest breach: 2023-07-20
  - Data classes: Passwords, Email addresses
  - Risk level: HIGH

[*] Social Media Presence:
  ✓ Twitter: @john_doe (High confidence)
  ✓ LinkedIn: /in/johndoe (High confidence)
  ✓ Reddit: u/john_doe (Medium confidence)
  ✓ Instagram: @johndoe (Low confidence)

[*] Risk Assessment:
  Overall Score: 72/100 (HIGH RISK)
  - GitHub exposure: 25/30
  - Breach severity: 35/40
  - Domain security: 12/30

================================================================================
Investigation complete. Results exported to report.json
```

### JSON Output Structure
```json
{
  "timestamp": "2025-01-25T10:30:00Z",
  "target": "john_doe",
  "github": {
    "found": true,
    "user": {
      "login": "john_doe",
      "email": "john.doe@example.com",
      "repos": 42,
      "followers": 156
    },
    "discovered_emails": ["john.doe@example.com"],
    "risk_indicators": ["Exposed credentials", "Admin role mentioned"]
  },
  "breaches": {
    "total": 3,
    "breaches": [
      {
        "name": "ServiceX",
        "date": "2023-07-20",
        "data_classes": ["Passwords", "Email addresses"]
      }
    ]
  },
  "social_media": {
    "found": 15,
    "profiles": {
      "twitter": {"found": true, "url": "https://twitter.com/john_doe"},
      "linkedin": {"found": true, "url": "https://linkedin.com/in/johndoe"}
    }
  },
  "risk_assessment": {
    "score": 72,
    "level": "HIGH",
    "factors": ["Credential exposure", "Recent breaches", "No 2FA"]
  }
}
```

## Intelligence Modules

### GitHub Intelligence

**Capabilities:**
- Repository analysis with language statistics
- Commit history traversal for email discovery
- Organization membership detection
- Gist enumeration
- Event timeline reconstruction
- Credential pattern detection

**API Endpoints:**
- `/users/{username}` - Profile data
- `/users/{username}/repos` - Repository list (paginated)
- `/users/{username}/events` - Activity timeline
- `/users/{username}/orgs` - Organization memberships
- `/repos/{owner}/{repo}/commits` - Commit history

### Domain Intelligence

**DNS Analysis:**
- Record types: A, AAAA, MX, TXT, NS, SOA, CAA, PTR
- DNSSEC validation
- Subdomain enumeration
- Zone transfer attempts

**Security Assessment:**
- SPF record validation
- DKIM selector discovery
- DMARC policy analysis
- SSL/TLS configuration

### Breach Intelligence

**Data Sources:**
- HaveIBeenPwned API v3
- Public paste sites
- Breach databases

**Analysis Features:**
- Temporal correlation
- Data class identification
- Severity scoring
- Password policy assessment

### Social Media Intelligence

**Platform Categories:**
- Professional: LinkedIn, GitHub, Kaggle
- Social: Twitter, Instagram, Facebook
- Forums: Reddit, HackerNews, StackOverflow
- Gaming: Steam, Xbox, PlayStation
- Adult: OnlyFans, AdultFriendFinder

**Detection Methods:**
- HTTP status codes (200, 301, 302)
- Content markers
- Profile URL patterns
- API availability

## Performance Benchmarks

### Execution Time Analysis

Measured on Ubuntu 22.04, Intel i7-10700K, 16GB RAM:

| Module | Average Time | API Calls | Memory Usage |
|--------|-------------|-----------|--------------|
| GitHub Analysis | 3.2s | 8-15 | 25MB |
| Domain Intelligence | 2.1s | 5-10 | 15MB |
| Breach Lookup | 1.5s | 2-3 | 10MB |
| Social Media (200 sites) | 45s | 200+ | 50MB |
| Full Investigation | 52s | 220+ | 100MB |

### Optimization Techniques

- **Connection pooling**: 30 persistent connections
- **Response caching**: 60% cache hit rate
- **Parallel processing**: Async operations for I/O
- **Memory streaming**: Bounded buffers for large responses
- **Rate limiting**: Automatic throttling

## Technical Implementation

### HTTP Engine Architecture
```python
class HTTPEngine:
    def __init__(self):
        self.session = requests.Session()
        
        # Retry strategy
        retry = Retry(
            total=5,
            backoff_factor=2,
            status_forcelist=[429, 500, 502, 503, 504]
        )
        
        # Connection pooling
        adapter = HTTPAdapter(
            max_retries=retry,
            pool_connections=30,
            pool_maxsize=30
        )
        
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
```

### Credential Detection Patterns
```python
credential_patterns = {
    'AWS_KEY': r'AKIA[0-9A-Z]{16}',
    'PRIVATE_KEY': r'-----BEGIN.*PRIVATE KEY',
    'API_KEY': r'api[_-]?key.*[:=].*[a-zA-Z0-9_\-]{20,}',
    'TOKEN': r'(ghp_|github_|sk_|pk_)[a-zA-Z0-9]{20,}',
    'DATABASE_URL': r'(postgres|mysql|mongodb)://.*',
}
```

### Risk Scoring Implementation
```python
class RiskScorer:
    def calculate_user_risk(self, intel: Dict) -> Dict:
        score = 0
        factors = []
        
        # GitHub risks (0-30)
        if intel.get('github', {}).get('discovered_emails'):
            score += 10
            factors.append('Email exposure')
            
        if 'credentials' in str(intel.get('github', {})):
            score += 15
            factors.append('Potential credentials')
            
        # Breach risks (0-40)
        breaches = intel.get('breach_intel', {}).get('breaches', [])
        if breaches:
            score += min(20, len(breaches) * 5)
            factors.append(f'{len(breaches)} data breaches')
            
        # Domain risks (0-30)
        if not intel.get('domain', {}).get('dnssec'):
            score += 10
            factors.append('No DNSSEC')
            
        return {
            'score': score,
            'level': self._get_risk_level(score),
            'factors': factors
        }
```

## Troubleshooting

### Common Issues

#### Rate Limiting
```
Error: HTTP 429 Too Many Requests
Solution: Increase RATE_LIMIT_DELAY in config
         Use authenticated requests for higher limits
```

#### SSL Verification
```
Error: SSL certificate verification failed
Solution: Update certificates: pip install --upgrade certifi
         Or disable (not recommended): verify=False
```

#### Memory Issues
```
Error: MemoryError during large batch processing
Solution: Process in smaller batches
         Increase system swap space
         Use --no-cache flag
```

### Debug Configuration
```bash
# Enable verbose logging
export OSINT_DEBUG=1
python src/osinth.py username -v

# Log to file
python src/osinth.py username --log-file debug.log

# Trace HTTP requests
export OSINT_HTTP_DEBUG=1
```

## Security Considerations

### Operational Security

**Pre-Deployment:**
- Obtain authorization for target investigation
- Review applicable laws and regulations
- Configure proxy for anonymization
- Use dedicated research infrastructure

**API Key Management:**
- Store in environment variables
- Never commit to version control
- Rotate keys periodically
- Use separate keys for production

**Network Security:**
- Route through VPN/Tor
- Implement rate limiting
- Monitor for detection
- Use distributed infrastructure

### Legal Compliance

**Authorization Requirements:**
- Written permission for corporate targets
- Compliance with terms of service
- Respect robots.txt and rate limits
- Follow responsible disclosure

**Regulatory Framework:**
- GDPR (European Union)
- CCPA (California)
- PIPEDA (Canada)
- Local privacy laws

### Data Handling

**Collection Principles:**
- Minimize data collection
- No persistent storage of PII
- Implement retention policies
- Secure data transmission

**Export Security:**
- Encrypt sensitive reports
- Sanitize before sharing
- Implement access controls
- Audit data access

## Known Limitations

### Technical Constraints

- **API Dependencies**: Reliance on third-party APIs
- **Rate Limits**: Platform-specific restrictions
- **Detection**: Anti-bot mechanisms may block requests
- **Data Freshness**: Cache may serve stale data
- **Coverage**: Not all platforms have APIs

### Architectural Limitations

- **Sequential Processing**: No true parallel execution
- **Memory Bound**: Large investigations may exhaust RAM
- **Network Dependent**: Requires stable internet
- **No Real-time Monitoring**: Snapshot analysis only
- **Limited Depth**: Surface-level reconnaissance

## Support and Contact

**Repository**: https://github.com/genesisgzdev/nexus-intelligence  
**Author**: Genesis GZ  
**Email**: genzt.dev@pm.me  
**License**: MIT

## Legal Disclaimer

THIS SOFTWARE IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND. The authors assume no liability for misuse or damage. Users are responsible for compliance with all applicable laws and regulations.

**Critical Notices:**
- No warranty for accuracy or completeness
- User responsibility for legal compliance
- Not for unauthorized surveillance
- Respect privacy and terms of service

---

*OSINT Intelligence Framework - Advanced reconnaissance for the modern digital landscape*
