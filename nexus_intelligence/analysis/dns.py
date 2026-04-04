import dns.resolver
from nexus_intelligence.analysis.base import BaseModule
from nexus_intelligence.analysis.intelligence.entropy import EntropyAnalyzer

class DNSIntelligence(BaseModule):
    def run(self):
        self.logger.info(f"Querying DNS infrastructure for {self.target}")
        results = {"target_entropy": EntropyAnalyzer.analyze(self.target)}
        resolver = dns.resolver.Resolver()
        resolver.timeout = self.config.timeout
        
        for rtype in ['A', 'MX', 'NS', 'TXT']:
            try:
                ans = resolver.resolve(self.target, rtype)
                results[rtype] = [str(r) for r in ans]
            except: continue
        return results
