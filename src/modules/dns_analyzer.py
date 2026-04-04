import dns.resolver
import dns.exception
from modules.base import BaseModule
from typing import Dict, Any

class DNSAnalyzer(BaseModule):
    def run(self) -> Dict[str, Any]:
        self.logger.info(f"Running DNS Analysis for {self.target} (No external APIs)")
        record_types = ['A', 'AAAA', 'MX', 'TXT', 'NS', 'SOA']
        results = {}
        resolver = dns.resolver.Resolver()
        resolver.timeout = self.config.timeout
        resolver.lifetime = self.config.timeout

        for rtype in record_types:
            try:
                answers = resolver.resolve(self.target, rtype)
                results[rtype] = [rdata.to_text() for rdata in answers]
                self.logger.debug(f"Found {rtype} records: {results[rtype]}")
            except dns.resolver.NoAnswer:
                self.logger.debug(f"No {rtype} record found")
            except dns.resolver.NXDOMAIN:
                self.logger.error("Domain does not exist")
                break
            except Exception as e:
                self.logger.debug(f"Error querying {rtype}: {e}")
        
        self.results = results
        return results
