"""
Forensic SSL/TLS Analysis Module.
Directly communicates with the target over TLS to extract certificate data.
Zero-API architecture.
"""
import ssl
import socket
from typing import Dict, Any
from datetime import datetime, timezone
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from nexus_intelligence.analysis.base import BaseModule

class SSLAnalyzer(BaseModule):
    """Performs deep analysis of SSL/TLS certificates and handshake."""

    def run(self) -> Dict[str, Any]:
        self.logger.info(f"Extracting SSL/TLS forensics for [bold]{self.target}[/]")
        results = {}
        
        try:
            # Create a default context that doesn't verify (for forensics we want the cert even if invalid)
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((self.target, 443), timeout=self.config.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=self.target) as ssock:
                    cert_bin = ssock.getpeercert(binary_form=True)
                    cert = x509.load_der_x509_certificate(cert_bin, default_backend())
                    
                    results['subject'] = {attr.oid._name: attr.value for attr in cert.subject}
                    results['issuer'] = {attr.oid._name: attr.value for attr in cert.issuer}
                    results['version'] = cert.version.name
                    results['serial_number'] = str(cert.serial_number)
                    results['not_valid_before'] = cert.not_valid_before_utc.isoformat()
                    results['not_valid_after'] = cert.not_valid_after_utc.isoformat()
                    
                    # Extension forensic analysis
                    extensions = {}
                    for ext in cert.extensions:
                        try:
                            extensions[ext.oid._name] = str(ext.value)
                        except Exception:
                            continue
                    results['extensions'] = extensions
                    
                    # Protocol & Cipher metrics
                    results['handshake'] = {
                        'protocol': ssock.version(),
                        'cipher': ssock.cipher()[0],
                        'cipher_bits': ssock.cipher()[1]
                    }
                    
                    # Validity check
                    now = datetime.now(timezone.utc)
                    results['is_expired'] = now > cert.not_valid_after_utc
                    results['days_until_expiration'] = (cert.not_valid_after_utc - now).days

        except Exception as e:
            self.logger.error(f"SSL analysis failed for {self.target}: {e}")
            results['error'] = str(e)
            
        return results
