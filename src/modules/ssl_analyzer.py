import ssl
import socket
from datetime import datetime
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from modules.base import BaseModule
from typing import Dict, Any

class SSLAnalyzer(BaseModule):
    def run(self) -> Dict[str, Any]:
        self.logger.info(f"Running SSL/TLS Analysis for {self.target} via raw sockets (0 APIs)")
        results = {}
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((self.target, 443), timeout=self.config.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=self.target) as ssock:
                    cert_bin = ssock.getpeercert(binary_form=True)
                    cert = x509.load_der_x509_certificate(cert_bin, default_backend())
                    
                    results['subject'] = {attr.oid._name: attr.value for attr in cert.subject}
                    results['issuer'] = {attr.oid._name: attr.value for attr in cert.issuer}
                    results['serial_number'] = str(cert.serial_number)
                    results['not_valid_before'] = cert.not_valid_before_utc.isoformat()
                    results['not_valid_after'] = cert.not_valid_after_utc.isoformat()
                    
                    # Basic extensions
                    exts = {}
                    for ext in cert.extensions:
                        exts[ext.oid._name] = str(ext.value)
                    results['extensions'] = exts
                    results['protocol'] = ssock.version()
                    results['cipher'] = ssock.cipher()
                    self.logger.debug(f"Successfully extracted SSL data for {self.target}")
        except Exception as e:
            self.logger.error(f"SSL Analysis failed: {e}")
            results['error'] = str(e)
            
        self.results = results
        return results
