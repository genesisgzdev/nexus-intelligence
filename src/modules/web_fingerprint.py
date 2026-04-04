import requests
import re
from modules.base import BaseModule
from typing import Dict, Any

class WebFingerprint(BaseModule):
    def run(self) -> Dict[str, Any]:
        self.logger.info(f"Running Web Fingerprinting for {self.target} (passive headers, no external API)")
        results = {}
        url = f"https://{self.target}"
        try:
            resp = requests.get(url, headers=self.config.get_headers(), timeout=self.config.timeout, verify=False)
            results['status_code'] = resp.status_code
            results['headers'] = dict(resp.headers)
            
            # Identify specific security headers
            sec_headers = ['Strict-Transport-Security', 'Content-Security-Policy', 'X-Frame-Options', 'X-Content-Type-Options', 'X-XSS-Protection']
            results['security_headers'] = {h: resp.headers.get(h) for h in sec_headers if h in resp.headers}
            
            # Fingerprint technologies
            techs = []
            server = resp.headers.get('Server', '')
            if server: techs.append(f"Server: {server}")
            x_powered = resp.headers.get('X-Powered-By', '')
            if x_powered: techs.append(f"X-Powered-By: {x_powered}")
            
            # Basic HTML checks
            html = resp.text
            if re.search(r'wp-content', html, re.I): techs.append("WordPress")
            if re.search(r'Laravel', html, re.I): techs.append("Laravel")
            
            results['detected_technologies'] = techs
            self.logger.debug("Successfully performed Web Fingerprinting")
        except requests.RequestException as e:
            self.logger.error(f"Web Fingerprint failed: {e}")
            results['error'] = str(e)
            
        self.results = results
        return results
