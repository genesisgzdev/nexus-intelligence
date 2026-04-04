import re
import random
import logging
from typing import Dict, Any, List
from curl_cffi import requests
from bs4 import BeautifulSoup
from nexus_intelligence.analysis.base import BaseModule
from nexus_intelligence.analysis.intelligence.entropy import EntropyAnalyzer

# Pre-compiled signatures for optimal performance during scale scans
SIGNATURES = {
    "frameworks": {
        "WordPress": [re.compile(r"wp-content", re.I), re.compile(r"wp-includes", re.I), re.compile(r"xmlrpc\.php", re.I)],
        "Laravel": [re.compile(r"XSRF-TOKEN", re.I), re.compile(r"laravel_session", re.I)],
        "Django": [re.compile(r"csrftoken", re.I), re.compile(r"__admin__", re.I)],
        "React": [re.compile(r"react-root", re.I), re.compile(r"_reactRootContainer", re.I)],
        "Vue.js": [re.compile(r"vue-app", re.I), re.compile(r"v-attr", re.I)],
    },
    "security_controls": {
        "Cloudflare": [re.compile(r"__cfduid", re.I), re.compile(r"cf-ray", re.I), re.compile(r"cloudflare", re.I)],
        "Akamai": [re.compile(r"akamai-", re.I), re.compile(r"akamai_", re.I)],
        "Incapsula": [re.compile(r"visid_incap", re.I), re.compile(r"incap_ses", re.I)],
    }
}

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0"
]

class WebIntelligence(BaseModule):
    """
    Advanced Web Intelligence Engine.
    Implements JA3 TLS impersonation and robust DOM tree parsing.
    """
    def run(self) -> Dict[str, Any]:
        self.logger.info(f"Analyzing application stack: {self.target}")
        res: Dict[str, Any] = {
            "frameworks": [], 
            "controls": [], 
            "security_headers": {},
            "opsec": "TLS_Impersonation_Chrome120"
        }
        
        try:
            # TLS Impersonation (JA3 Evasion) & Browser Profile Injection
            # Bypasses Cloudflare/Akamai bot-management at the cryptographic handshake layer
            headers = {"User-Agent": random.choice(USER_AGENTS)}
            proxies = {"http": self.config.proxy_url, "https": self.config.proxy_url} if self.config.proxy_url else None

            r = requests.get(
                f"https://{self.target}",
                timeout=self.config.timeout,
                impersonate="chrome120",
                proxies=proxies,
                headers=headers,
                allow_redirects=True,
                verify=False # SSL forensics usually requires analyzing invalid/self-signed certs
            )
            
            res['status_code'] = r.status_code
            res['response_time'] = round(r.elapsed.total_seconds(), 4)
            
            # Robust DOM Parsing (Tree-based, not string slicing)
            soup = BeautifulSoup(r.text, "lxml")
            
            # Signature Forensic Analysis
            body_content = r.text
            headers_str = str(r.headers)
            
            for category, sigs in SIGNATURES.items():
                for name, patterns in sigs.items():
                    if any(p.search(body_content) or p.search(headers_str) for p in patterns):
                        res[category].append(name)
            
            # Structured Header Analysis
            standard_sec_headers = [
                'Content-Security-Policy', 
                'Strict-Transport-Security', 
                'X-Frame-Options', 
                'X-Content-Type-Options',
                'Server',
                'X-Powered-By'
            ]
            for h in standard_sec_headers:
                val = r.headers.get(h)
                if val: res['security_headers'][h] = val
            
            # Structural metadata extraction
            if soup.title:
                title_text = soup.title.get_text().strip()
                res['title'] = title_text
                res['title_analysis'] = EntropyAnalyzer.analyze(title_text)
            
            # Extract meta tags for deeper OSINT
            res['meta_tags'] = {
                m.get('name', m.get('property')): m.get('content') 
                for m in soup.find_all('meta') if (m.get('name') or m.get('property'))
            }

        except Exception as e:
            self.logger.error(f"Web module failure for {self.target}: {str(e)}")
            res['error'] = str(e)
            
        return res
