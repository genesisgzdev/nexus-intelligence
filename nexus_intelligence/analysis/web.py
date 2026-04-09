import re
import random
import asyncio
from typing import Dict, Any, List
from curl_cffi.requests import AsyncSession
from bs4 import BeautifulSoup
from nexus_intelligence.analysis.base import BaseModule
from nexus_intelligence.analysis.intelligence.entropy import EntropyAnalyzer

SIGNATURES = {
    "frameworks": {
        "WordPress": [re.compile(r"wp-content", re.I)],
        "Laravel": [re.compile(r"XSRF-TOKEN", re.I)],
        "React": [re.compile(r"react-root", re.I)],
    },
    "security_controls": {
        "Cloudflare": [re.compile(r"cf-ray", re.I)],
        "Akamai": [re.compile(r"akamai-", re.I)],
    }
}

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
]

class WebIntelligence(BaseModule):
    async def run(self) -> Dict[str, Any]:
        self.logger.info(f"Analyzing application stack (Async): {self.target}")
        res: Dict[str, Any] = {"frameworks": [], "security_controls": [], "security_headers": {}}
        
        try:
            async with AsyncSession(impersonate="chrome120") as s:
                r = await s.get(
                    f"https://{self.target}",
                    timeout=self.config.timeout,
                    verify=False
                )

                res['status_code'] = r.status_code
                soup = BeautifulSoup(r.text, "lxml")

                # Signature Forensic Analysis
                body_content = r.text
                headers_str = str(r.headers)

                for category, sigs in SIGNATURES.items():
                    for name, patterns in sigs.items():
                        if any(p.search(body_content) or p.search(headers_str) for p in patterns):
                            res[category].append(name)

                if soup.title:
                    res['title'] = soup.title.get_text().strip()

        except Exception as e:
            self.logger.error(f"Web module failure for {self.target}: {str(e)}")
            res['error'] = str(e)

        return res
