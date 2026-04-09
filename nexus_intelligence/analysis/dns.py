import asyncio
import dns.asyncresolver
import dns.message
import dns.query
from typing import Dict, Any, List
from nexus_intelligence.analysis.base import BaseModule
from nexus_intelligence.analysis.intelligence.entropy import EntropyAnalyzer

class DNSIntelligence(BaseModule):
    """
    Asynchronous DNS Forensic Module.
    Direct protocol implementation using standard resolvers and raw queries.
    """
    async def run(self) -> Dict[str, Any]:
        self.logger.info(f"Performing DNS forensic analysis: {self.target}")
        results: Dict[str, Any] = {
            "target_entropy": EntropyAnalyzer.analyze(self.target)
        }

        rtypes = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CAA']
        resolver = dns.asyncresolver.Resolver()
        resolver.nameservers = self.config.dns_resolvers
        resolver.timeout = self.config.timeout
        resolver.lifetime = self.config.timeout

        for rtype in rtypes:
            try:
                # Direct UDP/TCP query, no web APIs involved.
                answers = await resolver.resolve(self.target, rtype)
                results[rtype] = [str(r) for r in answers]
            except Exception as e:
                self.logger.debug(f"DNS lookup failed for {rtype}: {str(e)}")
                continue

        return results
