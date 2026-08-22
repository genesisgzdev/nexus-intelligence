import asyncio
import dns.asyncresolver
from typing import Dict, Any, List
from nexus_intelligence.analysis.base import BaseModule
from nexus_intelligence.core.security import SecurityValidator

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
        except Exception as exc:
            self.logger.debug("MX lookup failed for %s: %s", self.target, exc)
            return []

    async def check_policy(self, rtype: str) -> str:
        try:
            resolver = dns.asyncresolver.Resolver()
            # Prefix for DMARC is _dmarc.
            target = f"_dmarc.{self.target}" if rtype.upper() == "DMARC" else self.target
            answers = await resolver.resolve(target, 'TXT')
            for r in answers:
                txt = str(r).lower()
                if "v=spf1" in txt or "v=dmarc1" in txt: return str(r)
            return "No Policy Detected"
        except Exception as exc:
            self.logger.debug("%s policy lookup failed for %s: %s", rtype, self.target, exc)
            return "Lookup Failed"

    async def grab_smtp_banner(self, host: str) -> str:
        writer = None
        try:
            destination = SecurityValidator.resolve_public_addresses(host)[0]
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(destination, 25), timeout=5
            )
            banner = await asyncio.wait_for(reader.read(1024), timeout=5)
            return banner.decode().strip()
        except Exception as exc:
            self.logger.debug("SMTP banner lookup failed for %s: %s", host, exc)
            return "Timeout/Refused"
        finally:
            if writer is not None:
                writer.close()
                try:
                    await asyncio.wait_for(writer.wait_closed(), timeout=5)
                except Exception:
                    self.logger.debug("SMTP writer close did not complete for %s", host)

    async def run(self) -> Dict[str, Any]:
        self.logger.info(f"Analyzing mail infrastructure: {self.target}")
        mx_servers = await self.get_mx_records()
        
        res = {
            "mx_records": mx_servers,
            "spf_record": await self.check_policy("SPF"),
            "dmarc_record": await self.check_policy("DMARC"),
            "banners": {}
        }

        # Concurrently grab banners for all MX nodes
        tasks = [self.grab_smtp_banner(srv) for srv in mx_servers]
        banners = await asyncio.gather(*tasks)
        for srv, b in zip(mx_servers, banners):
            res["banners"][srv] = b

        return res
