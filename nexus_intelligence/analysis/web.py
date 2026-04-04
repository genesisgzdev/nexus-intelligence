import requests
from nexus_intelligence.analysis.base import BaseModule
from nexus_intelligence.analysis.intelligence.entropy import EntropyAnalyzer

class WebIntelligence(BaseModule):
    def run(self):
        self.logger.info(f"Analyzing web stack: {self.target}")
        res = {}
        try:
            r = requests.get(f"https://{self.target}", timeout=10, verify=False)
            res['status'] = r.status_code
            res['server'] = r.headers.get('Server')
            res['security_headers'] = {h: r.headers.get(h) for h in ['Content-Security-Policy', 'Strict-Transport-Security'] if h in r.headers}
            res['title_entropy'] = EntropyAnalyzer.analyze(r.text[:500]) # Sample entropy
        except Exception as e: res['error'] = str(e)
        return res
