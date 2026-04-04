"""
Passive Web Intelligence & Fingerprinting Module.
Analyzes HTTP layer forensics and technology stack signatures.
"""
import requests
import re
from typing import Dict, Any, List
from nexus_intelligence.analysis.base import BaseModule

class WebAnalyzer(BaseModule):
    """Fingerprints web technologies and security configurations."""

    SIGNATURES = {
        "WordPress": [r"wp-content", r"wp-includes", r"xmlrpc.php"],
        "Laravel": [r"XSRF-TOKEN", r"laravel_session", r"Laravel"],
        "React": [r"react-root", r"_reactRootContainer", r"data-reactid"],
        "Vue.js": [r"vue-app", r"v-attr", r"data-v-"],
        "Cloudflare": [r"__cfduid", r"cf-ray", r"cloudflare"]
    }

    def run(self) -> Dict[str, Any]:
        self.logger.info(f"Performing passive web fingerprinting on [bold]{self.target}[/]")
        results = {}
        url = f"https://{self.target}"
        
        try:
            # Disable verification for forensics; we want the response regardless of SSL state
            response = requests.get(
                url, 
                headers=self.config.get_http_headers(),
                timeout=self.config.timeout,
                verify=False,
                allow_redirects=True
            )
            
            results['status_code'] = response.status_code
            results['final_url'] = response.url
            results['headers'] = dict(response.headers)
            
            # Security header audit
            sec_headers = [
                'Content-Security-Policy', 'Strict-Transport-Security', 
                'X-Frame-Options', 'X-Content-Type-Options', 
                'X-XSS-Protection', 'Referrer-Policy'
            ]
            results['security_headers'] = {
                h: response.headers.get(h, "MISSING") for h in sec_headers
            }
            
            # Technology fingerprinting via signatures
            detected = []
            html = response.text
            for tech, patterns in self.SIGNATURES.items():
                for pattern in patterns:
                    if re.search(pattern, html, re.I) or re.search(pattern, str(response.headers), re.I):
                        detected.append(tech)
                        break
            results['detected_technologies'] = detected
            
            # Extract common meta tags
            meta_tags = {}
            if '<title>' in html.lower():
                title = html.split('<title>')[1].split('</title>')[0]
                meta_tags['title'] = title.strip()
            results['meta_info'] = meta_tags

        except Exception as e:
            self.logger.error(f"Web analysis failed: {e}")
            results['error'] = str(e)
            
        return results
