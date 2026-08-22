import ssl
import socket
import asyncio
import hashlib
from typing import Dict, Any, List
from cryptography import x509
from cryptography.x509.extensions import ExtensionNotFound
from nexus_intelligence.analysis.base import BaseModule
from nexus_intelligence.core.security import SecurityValidator

class SSLForensics(BaseModule):
    """
    Low-level TLS Handshake and X.509 Forensic Engine.
    Performs local certificate validation and attribute extraction.
    """
    async def run(self) -> Dict[str, Any]:
        self.logger.info(f"Starting local TLS handshake: {self.target}")
        res: Dict[str, Any] = {}

        try:
            # Custom SSL context for unverified inspection
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE 

            # Pin the socket destination to the address that passed the SSRF
            # policy. Keep the hostname as SNI for the requested virtual host.
            destination = (await SecurityValidator.resolve_public_addresses_async(self.target, self.config.timeout))[0]
            _reader, writer = await asyncio.open_connection(
                destination, 443, ssl=ctx, server_hostname=self.target
            )
            try:
                ssl_obj = writer.get_extra_info('ssl_object')
                if ssl_obj is None:
                    raise RuntimeError("TLS connection did not expose an SSL object")
                der_cert = ssl_obj.getpeercert(True)
            finally:
                writer.close()
                await writer.wait_closed()

            # Local X.509 Parsing (cryptography library)
            cert = x509.load_der_x509_certificate(der_cert)
            
            res['issuer'] = {a.oid._name: str(a.value) for a in cert.issuer}
            res['subject'] = {a.oid._name: str(a.value) for a in cert.subject}
            res['serial'] = hex(cert.serial_number)
            res['not_valid_before'] = cert.not_valid_before_utc.isoformat()
            res['not_valid_after'] = cert.not_valid_after_utc.isoformat()
            res['fingerprint_sha256'] = hashlib.sha256(der_cert).hexdigest()
            res['version'] = cert.version.name
            res['signature_hash_algorithm'] = cert.signature_hash_algorithm.name

            # Extract Subject Alternative Names (SAN) locally
            try:
                ext = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                res['sans'] = ext.value.get_values_for_type(x509.DNSName)
            except ExtensionNotFound:
                pass

        except Exception as e:
            self.logger.error(f"Local TLS analysis failed: {str(e)}")
            res['error'] = str(e)

        return res
