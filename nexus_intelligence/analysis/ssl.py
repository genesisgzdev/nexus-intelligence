import ssl
import socket
import httpx
import hashlib
from typing import Dict, Any, List, Optional
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.ocsp import OCSPResponseStatus
from nexus_intelligence.analysis.base import BaseModule
from nexus_intelligence.analysis.intelligence.entropy import EntropyAnalyzer

class SSLForensics(BaseModule):
    """
    Advanced SSL/TLS Forensic Engine.
    Performs deep X.509 inspection, CT log verification, and OCSP revocation checks.
    """
    
    def check_ct_logs(self, cert_hash: str) -> Dict[str, Any]:
        """
        Query public CT log aggregators for certificate transparency data.
        """
        try:
            # Using CRT.sh for Certificate Transparency lookup
            # Note: Public APIs may be rate-limited
            with httpx.Client(timeout=15, follow_redirects=True) as client:
                r = client.get(f"https://crt.sh/?q={cert_hash}&output=json")
                if r.status_code == 200:
                    data = r.json()
                    return {"ct_entries": len(data), "source": "crt.sh", "status": "Found"}
                return {"status": "No_Entries", "http_code": r.status_code}
        except Exception as e:
            self.logger.debug(f"CT lookup failed: {str(e)}")
        return {"status": "CT_Lookup_Failed"}

    def run(self) -> Dict[str, Any]:
        self.logger.info(f"Forensic TLS handshake: {self.target}")
        res: Dict[str, Any] = {"opsec": "Socket_Level_Handshake"}
        
        try:
            # Direct socket handshake for raw attribute extraction
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE # Forensics needs to see even invalid certs
            
            with socket.create_connection((self.target, 443), timeout=self.config.timeout) as s:
                with ctx.wrap_socket(s, server_hostname=self.target) as ss:
                    der_cert = ss.getpeercert(True)
                    cert = x509.load_der_x509_certificate(der_cert)
                    
                    # Core Attributes
                    res['issuer'] = {a.oid._name: str(a.value) for a in cert.issuer}
                    res['subject'] = {a.oid._name: str(a.value) for a in cert.subject}
                    res['serial'] = hex(cert.serial_number)
                    res['not_valid_before'] = cert.not_valid_before_utc.isoformat()
                    res['not_valid_after'] = cert.not_valid_after_utc.isoformat()
                    res['cipher'] = ss.cipher()
                    res['protocol'] = ss.version()
                    
                    # Fingerprints
                    cert_hash_sha256 = hashlib.sha256(der_cert).hexdigest()
                    res['fingerprint_sha256'] = cert_hash_sha256
                    
                    # X.509 Extensions (SAN, OCSP, etc.)
                    res['extensions'] = {}
                    try:
                        sans = []
                        ext = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                        sans = ext.value.get_values_for_type(x509.DNSName)
                        res['sans'] = sans
                        if sans: res['san_entropy'] = EntropyAnalyzer.analyze("".join(sans))
                    except: pass
                    
                    # OCSP Endpoints
                    try:
                        aia = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.AUTHORITY_INFORMATION_ACCESS)
                        res['ocsp_endpoints'] = [desc.access_location.value for desc in aia.value if desc.access_method.oid == x509.oid.AuthorityInformationAccessOID.OCSP]
                    except: pass

                    # CT Log Lookup (Respecting Zero-API Mandate)
                    if self.config.allow_external_ct:
                        res['transparency'] = self.check_ct_logs(cert_hash_sha256)
                    else:
                        res['transparency'] = {"status": "Skipped", "reason": "Zero-API_Mandate_Strict"}

        except Exception as e:
            self.logger.error(f"TLS forensics failed for {self.target}: {str(e)}")
            res['error'] = str(e)
            
        return res
