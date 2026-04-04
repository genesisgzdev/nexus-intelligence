import dns.resolver
import dns.query
import dns.message
import httpx
from typing import Dict, Any, List
from tenacity import retry, stop_after_attempt, wait_exponential
from nexus_intelligence.analysis.base import BaseModule
from nexus_intelligence.analysis.intelligence.entropy import EntropyAnalyzer

class DNSIntelligence(BaseModule):
    """
    DNS Intelligence Module with Privacy-first design.
    Implements DNS-over-HTTPS (DoH) to prevent ISP-level traffic analysis.
    """
    
    @retry(
        wait=wait_exponential(multiplier=1, min=2, max=10),
        stop=stop_after_attempt(3),
        reraise=True
    )
    def query_doh(self, qname: str, rtype: str) -> List[str]:
        """
        Execute a DoH query via HTTPX.
        Provides protection against DNS leaks and cleartext interception.
        """
        query = dns.message.make_query(qname, rtype)
        query_data = query.to_wire()
        
        headers = {
            "Accept": "application/dns-message",
            "Content-Type": "application/dns-message"
        }
        
        proxies = {"all://": self.config.proxy_url} if self.config.proxy_url else None
        
        with httpx.Client(proxies=proxies, timeout=self.config.timeout) as client:
            resp = client.post(
                self.config.doh_endpoint,
                content=query_data,
                headers=headers
            )
            resp.raise_for_status()
            
            msg = dns.message.from_wire(resp.content)
            return [str(rr) for rset in msg.answer for rr in rset]

    def run(self) -> Dict[str, Any]:
        self.logger.info(f"Querying DNS infrastructure (via DoH): {self.target}")
        results: Dict[str, Any] = {
            "target_entropy": EntropyAnalyzer.analyze(self.target),
            "resolver_config": "DoH_Privacy_Active"
        }
        
        # Standard Record Analysis
        for rtype in ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CAA']:
            try:
                # DoH primary path
                ans = self.query_doh(self.target, rtype)
                if ans:
                    results[rtype] = ans
                    
            except Exception as e:
                self.logger.debug(f"DoH query failed for {rtype}: {str(e)}")
                # Falling back to explicit privacy resolvers as secondary (non-DoH)
                try:
                    resolver = dns.resolver.Resolver(configure=False)
                    resolver.nameservers = self.config.dns_resolvers
                    resolver.timeout = self.config.timeout
                    ans = resolver.resolve(self.target, rtype)
                    results[f"{rtype}_legacy"] = [str(r) for r in ans]
                except:
                    continue
                    
        return results
