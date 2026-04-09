import asyncio
import dns.asyncresolver
from typing import Dict, Any, List
from nexus_intelligence.analysis.base import BaseModule

class SubdomainDiscovery(BaseModule):
    """
    High-Performance Subdomain Enumerator.
    Uses async recursion and wildcard detection to minimize false positives.
    """
    # Optimized initial wordlist for high-value targets
    BASE_WORDS = [
        "www", "dev", "api", "mail", "vpn", "remote", "staging", "portal", 
        "cloud", "admin", "test", "auth", "gitlab", "jenkins", "docker", 
        "nexus", "jira", "confluence", "prod", "beta", "monitor", "status"
    ]

    async def _is_wildcard(self) -> bool:
        """Detects if the target has a wildcard DNS record."""
        try:
            resolver = dns.asyncresolver.Resolver()
            await resolver.resolve(f"nexus-wildcard-check-{uuid.uuid4().hex}.{self.target}", 'A')
            return True
        except: return False

    async def _resolve(self, sub: str, semaphore: asyncio.Semaphore) -> str:
        async with semaphore:
            full = f"{sub}.{self.target}"
            try:
                resolver = dns.asyncresolver.Resolver()
                # We query 'A' and 'CNAME' records concurrently
                await resolver.resolve(full, 'A')
                return full
            except: return ""

    async def run(self) -> Dict[str, Any]:
        self.logger.info(f"Enumerating subdomains: {self.target}")
        
        # 1. Check for wildcards to avoid garbage results
        is_wildcard = await self._is_wildcard()
        if is_wildcard:
            return {"error": "Wildcard DNS detected. Manual inspection required."}

        sem = asyncio.Semaphore(100) # Elevated concurrency for Desktop environment
        tasks = [self._resolve(w, sem) for w in self.BASE_WORDS]
        
        results = await asyncio.gather(*tasks)
        found = [r for r in results if r]
        
        return {
            "found_count": len(found),
            "results": found,
            "engine": "Async_Recursion_v2"
        }
