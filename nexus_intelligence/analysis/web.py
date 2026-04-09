import re
import random
import asyncio
from typing import Dict, Any, List
from curl_cffi.requests import AsyncSession
from bs4 import BeautifulSoup
from nexus_intelligence.analysis.base import BaseModule

SIGNATURES = {
    "frameworks": {
        "WordPress": [re.compile(r"wp-content", re.I), re.compile(r"wp-includes", re.I)],
        "Laravel": [re.compile(r"XSRF-TOKEN", re.I), re.compile(r"laravel_session", re.I)],
        "React": [re.compile(r"react-root", re.I), re.compile(r"_reactRootContainer", re.I)],
        "Vue.js": [re.compile(r"vue-app", re.I), re.compile(r"v-attr", re.I)],
    },
    "security_controls": {
        "Cloudflare": [re.compile(r"cf-ray", re.I), re.compile(r"__cfduid", re.I)],
        "Akamai": [re.compile(r"akamai-", re.I), re.compile(r"akamai_", re.I)],
        "AWS_WAF": [re.compile(r"AWSALB", re.I), re.compile(r"AWSALBCORS", re.I)],
        "ModSecurity": [re.compile(r"Mod_Security", re.I), re.compile(r"NO_CACHE", re.I)],
        "FortiWeb": [re.compile(r"FORTIWAFSID", re.I)],
    }
}

class WebIntelligence(BaseModule):
    """
    Advanced Web Intelligence Engine.
    Performs application stack fingerprinting and security header audit.
    """
    async def run(self) -> Dict[str, Any]:
        self.logger.info(f"Analyzing application stack (Async): {self.target}")
        res: Dict[str, Any] = {
            "frameworks": [],
            "security_controls": [],
            "security_headers": {},
            "misconfigurations": []
        }
        
        try:
            async with AsyncSession(impersonate="chrome120") as s:
                r = await s.get(
                    f"https://{self.target}",
                    timeout=self.config.timeout,
                    verify=False
                )

                res['status_code'] = r.status_code
                
                # 1. Signature-based fingerprinting
                body_content = r.text
                headers_str = str(r.headers)
                for category, sigs in SIGNATURES.items():
                    for name, patterns in sigs.items():
                        if any(p.search(body_content) or p.search(headers_str) for p in patterns):
                            res[category].append(name)

                # 2. Security Header Audit
                critical_headers = {
                    "Content-Security-Policy": "Missing CSP",
                    "Strict-Transport-Security": "Missing HSTS",
                    "X-Content-Type-Options": "Missing No-Sniff",
                    "X-Frame-Options": "Missing Clickjacking protection"
                }
                for h, alert in critical_headers.items():
                    val = r.headers.get(h)
                    if val:
                        res['security_headers'][h] = val
                    else:
                        res['misconfigurations'].append(alert)

                # 3. Detect potentially dangerous headers
                dangerous = ["Server", "X-Powered-By", "X-AspNet-Version"]
                for h in dangerous:
                    val = r.headers.get(h)
                    if val:
                        res['security_headers'][f"Information_Leak_{h}"] = val

                soup = BeautifulSoup(r.text, "lxml")
                if soup.title:
                    res['title'] = soup.title.get_text().strip()

        except Exception as e:
            self.logger.error(f"Web module failure for {self.target}: {str(e)}")
            res['error'] = str(e)

        return res
