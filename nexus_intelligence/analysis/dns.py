import dns.resolver
import dns.query
import dns.message
import httpx
import asyncio
from typing import Dict, Any, List
from tenacity import retry, stop_after_attempt, wait_exponential
from nexus_intelligence.analysis.base import BaseModule
from nexus_intelligence.analysis.intelligence.entropy import EntropyAnalyzer

class DNSIntelligence(BaseModule):
    """
    Async DNS Intelligence Module.
    """

    async def query_doh(self, qname: str, rtype: str) -> List[str]:
        query = dns.message.make_query(qname, rtype)
        query_data = query.to_wire()
        
        headers = {
            "Accept": "application/dns-message",
            "Content-Type": "application/dns-message"
        }

        proxies = {"all://": self.config.proxy_url} if self.config.proxy_url else None

        async with httpx.AsyncClient(proxies=proxies, timeout=self.config.timeout) as client:
            resp = await client.post(
                self.config.doh_endpoint,
                content=query_data,
                headers=headers
            )
            resp.raise_for_status()

            msg = dns.message.from_wire(resp.content)
            return [str(rr) for rset in msg.answer for rr in rset]

    async def run(self) -> Dict[str, Any]:
        self.logger.info(f"Querying DNS infrastructure (Async): {self.target}")
        results: Dict[str, Any] = {
            "target_entropy": EntropyAnalyzer.analyze(self.target)
        }

        tasks = []
        rtypes = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CAA']
        
        for rtype in rtypes:
            tasks.append(self.query_doh(self.target, rtype))

        resolved = await asyncio.gather(*tasks, return_exceptions=True)

        for rtype, ans in zip(rtypes, resolved):
            if isinstance(ans, list) and ans:
                results[rtype] = ans
            elif isinstance(ans, Exception):
                self.logger.debug(f"DoH query failed for {rtype}: {str(ans)}")

        return results
