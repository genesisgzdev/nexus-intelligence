import ssl
import socket
import httpx
import hashlib
import asyncio
from typing import Dict, Any, List, Optional
from cryptography import x509
from nexus_intelligence.analysis.base import BaseModule

class SSLForensics(BaseModule):
    async def check_ct_logs(self, cert_hash: str) -> Dict[str, Any]:
        try:
            async with httpx.AsyncClient(timeout=15) as client:
                r = await client.get(f"https://crt.sh/?q={cert_hash}&output=json")
                if r.status_code == 200:
                    return {"ct_entries": len(r.json()), "source": "crt.sh", "status": "Found"}
        except: pass
        return {"status": "CT_Lookup_Failed"}

    async def run(self) -> Dict[str, Any]:
        self.logger.info(f"Forensic TLS handshake (Async): {self.target}")
        res: Dict[str, Any] = {}

        try:
            # Low-level async handshake
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            reader, writer = await asyncio.open_connection(self.target, 443, ssl=ctx, server_hostname=self.target)
            ss = writer.get_extra_info('ssl_object')
            der_cert = ss.getpeercert(True)
            writer.close()
            await writer.wait_closed()

            cert = x509.load_der_x509_certificate(der_cert)
            res['issuer'] = {a.oid._name: str(a.value) for a in cert.issuer}
            res['subject'] = {a.oid._name: str(a.value) for a in cert.subject}
            res['protocol'] = ss.version()

            if self.config.allow_external_ct:
                cert_hash = hashlib.sha256(der_cert).hexdigest()
                res['transparency'] = await self.check_ct_logs(cert_hash)

        except Exception as e:
            self.logger.error(f"TLS forensics failed: {str(e)}")
            res['error'] = str(e)

        return res
