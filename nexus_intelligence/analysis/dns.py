"""
Advanced DNS Intelligence Module.
Performs RFC-compliant DNS lookups without using 3rd-party APIs.
"""
import dns.resolver
import dns.reversename
from typing import Dict, Any, List
from nexus_intelligence.analysis.base import BaseModule

class DNSAnalyzer(BaseModule):
    """Analyzes DNS infrastructure for the target domain."""

    def run(self) -> Dict[str, Any]:
        self.logger.info(f"Analyzing DNS infrastructure for [bold]{self.target}[/]")
        results = {}
        
        # Standard records to query
        records = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME']
        
        resolver = dns.resolver.Resolver()
        resolver.timeout = self.config.timeout
        resolver.lifetime = self.config.timeout

        for rtype in records:
            try:
                answers = resolver.resolve(self.target, rtype)
                results[rtype] = [str(rdata) for rdata in answers]
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                continue
            except Exception as e:
                self.logger.debug(f"DNS query for {rtype} failed: {e}")
        
        # Try to find the mail servers' IPs
        if 'MX' in results:
            mx_ips = []
            for mx in results['MX']:
                # MX format: "priority host"
                host = mx.split()[-1].rstrip('.')
                try:
                    ips = resolver.resolve(host, 'A')
                    mx_ips.extend([str(ip) for ip in ips])
                except Exception:
                    continue
            results['MX_IP_ADDRESSES'] = list(set(mx_ips))

        return results
