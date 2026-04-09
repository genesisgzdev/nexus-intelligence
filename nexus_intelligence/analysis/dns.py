import asyncio
import dns.asyncresolver
import dns.message
import dns.query
from typing import Dict, Any, List
from nexus_intelligence.analysis.base import BaseModule
from nexus_intelligence.analysis.intelligence.entropy import EntropyAnalyzer

class DNSIntelligence(BaseModule):
    """
    Asynchronous DNS forensic analysis module.
    
    Directly interacts with name servers to extract resource records
    without third-party API middle-men.
    """
    async def run(self) -> Dict[str, Any]:
        self.logger.info(f"Initiating DNS recursive audit: {self.target}")
        results: Dict[str, Any] = {
            "entropy_score": EntropyAnalyzer.analyze(self.target)
        }

        rtypes = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CAA']
        resolver = dns.asyncresolver.Resolver()
        resolver.nameservers = self.config.dns_resolvers
        resolver.timeout = self.config.timeout
        resolver.lifetime = self.config.timeout

        for rtype in rtypes:
            try:
                answers = await resolver.resolve(self.target, rtype)
                results[rtype] = [str(r) for r in answers]
            except Exception as e:
                self.logger.debug(f"Resolver fault for {rtype}: {str(e)}")
                continue

        return results
