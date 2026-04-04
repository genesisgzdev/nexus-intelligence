import ssl, socket
from cryptography import x509
from nexus_intelligence.analysis.base import BaseModule
from nexus_intelligence.analysis.intelligence.entropy import EntropyAnalyzer

class SSLForensics(BaseModule):
    def run(self):
        self.logger.info(f"Forensic TLS handshake: {self.target}")
        res = {}
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((self.target, 443), 10) as s:
                with ctx.wrap_socket(s, server_hostname=self.target) as ss:
                    cert = x509.load_der_x509_certificate(ss.getpeercert(True))
                    res['issuer'] = {a.oid._name: a.value for a in cert.issuer}
                    res['subject'] = {a.oid._name: a.value for a in cert.subject}
                    res['cipher'] = ss.cipher()
                    sans = []
                    try:
                        ext = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                        sans = ext.value.get_values_for_type(x509.DNSName)
                    except: pass
                    res['sans'] = sans
                    if sans: res['san_entropy'] = EntropyAnalyzer.analyze("".join(sans))
        except Exception as e: res['error'] = str(e)
        return res
