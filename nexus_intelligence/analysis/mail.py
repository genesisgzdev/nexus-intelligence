import asyncio
import dns.asyncresolver
import socket
from typing import Dict, Any, List
from nexus_intelligence.analysis.base import BaseModule

class MailIntelligence(BaseModule):
    """
    Forensic Mail Infrastructure Analysis.
    Inspects SPF, DMARC, and performs SMTP banner grabbing.
    """
    async def get_mx_records(self) -> List[str]:
        try:
            resolver = dns.asyncresolver.Resolver()
            answers = await resolver.resolve(self.target, 'MX')
            return [str(r.exchange).rstrip('.') for r in answers]
        except: return []

    async def check_policy(self, rtype: str) -> str:
        try:
            resolver = dns.asyncresolver.Resolver()
            # Prefix for DMARC is _dmarc.
            target = f"_dmarc.{self.target}" if rtype == 'TXT' and "DMARC" in rtype else self.target
            answers = await resolver.resolve(target, 'TXT')
            for r in answers:
                txt = str(r).lower()
                if "v=spf1" in txt or "v=dmarc1" in txt: return str(r)
            return "No Policy Detected"
        except: return "Lookup Failed"

    async def grab_smtp_banner(self, host: str) -> str:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, 25), timeout=5
            )
            banner = await reader.read(1024)
            writer.close()
            await writer.wait_closed()
            return banner.decode().strip()
        except: return "Timeout/Refused"

    async def run(self) -> Dict[str, Any]:
        self.logger.info(f"Analyzing mail infrastructure: {self.target}")
        mx_servers = await this.get_mx_records()
        
        res = {
            "mx_records": mx_servers,
            "spf_record": await self.check_policy('SPF'),
            "banners": {}
        }

        # Concurrently grab banners for all MX nodes
        tasks = [self.grab_smtp_banner(srv) for srv in mx_servers]
        banners = await asyncio.gather(*tasks)
        for srv, b in zip(mx_servers, banners):
            res["banners"][srv] = b

        return res
