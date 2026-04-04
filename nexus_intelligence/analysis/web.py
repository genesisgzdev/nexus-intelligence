import requests
import re
from nexus_intelligence.analysis.base import BaseModule
from nexus_intelligence.analysis.intelligence.entropy import EntropyAnalyzer

class WebIntelligence(BaseModule):
    # Professional fingerprinting signatures (Passive)
    SIGNATURES = {
        "frameworks": {
            "WordPress": [r"wp-content", r"wp-includes", r"xmlrpc.php"],
            "Laravel": [r"XSRF-TOKEN", r"laravel_session"],
            "Django": [r"csrftoken", r"__admin__"],
            "React": [r"react-root", r"_reactRootContainer"],
            "Vue.js": [r"vue-app", r"v-attr"],
        },
        "security_controls": {
            "Cloudflare": [r"__cfduid", r"cf-ray", r"cloudflare"],
            "Akamai": [r"akamai-", r"akamai_"],
            "Incapsula": [r"visid_incap", r"incap_ses"],
        }
    }

    def run(self):
        self.logger.info(f"Analyzing application stack: {self.target}")
        res = {"frameworks": [], "controls": [], "security_headers": {}}
        try:
            # Passive audit via HTTP/S stream
            r = requests.get(f"https://{self.target}", timeout=10, verify=False, allow_redirects=True)
            res['status_code'] = r.status_code
            res['response_time'] = r.elapsed.total_seconds()
            
            body = r.text
            headers_str = str(r.headers)
            
            # Signature matching
            for category, sigs in self.SIGNATURES.items():
                for name, patterns in sigs.items():
                    if any(re.search(p, body, re.I) or re.search(p, headers_str, re.I) for p in patterns):
                        res[category].append(name)
            
            # Header forensics
            for h in ['Content-Security-Policy', 'Strict-Transport-Security', 'X-Frame-Options', 'X-Content-Type-Options']:
                if h in r.headers:
                    res['security_headers'][h] = r.headers[h]
            
            # Content entropy (Detect obfuscation/DGA titles)
            if '<title>' in body.lower():
                title = body.split('<title>')[1].split('</title>')[0]
                res['title_analysis'] = EntropyAnalyzer.analyze(title.strip())
                
        except Exception as e:
            res['error'] = str(e)
        return res
