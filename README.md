# Nexus Intelligence Framework

## Overview

Nexus Intelligence is an advanced, parallelized protocol-level Open Source Intelligence (OSINT) and network forensic framework. Engineered for absolute Operational Security (OPSEC), cryptographic evasion, and statistical infrastructure validation, the suite bypasses traditional reliance on third-party SaaS aggregators (such as Shodan, Censys, or VirusTotal). 

The framework implements direct protocol interactions coupled with modular mathematical models to identify synthetic entities, Domain Generation Algorithms (DGA), and infrastructure anomalies in real-time. The core engine operates strictly under the **Zero-API Mandate**, ensuring target identifiers are never leaked to public databases.

## Technical Architecture

### Integrated Protocol and Statistical Engine

The framework implements a unified, thread-safe execution architecture divided into three primary layers:

- **Cryptographic Evasion Layer (OPSEC)**: Implements JA3/JA4 TLS impersonation and DNS-over-HTTPS (DoH) routing to completely mask forensic network footprints from WAFs and ISP-level interception.
- **Direct Protocol Forensics**: Raw socket and HTTP/S stream analysis across the network (DNS), transport (SSL/TLS), and application (Web) layers.
- **Mathematical Validation Core**: Real-time statistical analysis utilizing Shannon Entropy, Benford's Law (First-Digit Law), and Markovian Determinism to classify infrastructure authenticity.

### Core Intelligence Subsystems

**Application Layer Analyzer (Web Intelligence)**
- Cryptographic Handshake Impersonation utilizing `curl_cffi` to perform TLS handshakes that mathematically match Google Chrome 120, preventing identification by Layer 7 bot-management systems.
- Robust DOM Parsing for tree-based structural metadata extraction via `BeautifulSoup` (`lxml`).
- Passive Stack Fingerprinting using pre-compiled regex signatures for modern frameworks and security controls.

**Transport Layer Analyzer (SSL Forensics)**
- Direct Socket Forensics bypassing standard HTTPS libraries to extract the raw X.509 certificate chain via native Python sockets.
- Deep parsing of Subject Alternative Names (SAN), Authority Information Access (AIA/OCSP), and exact validity periods.
- Zero-API Certificate Transparency with strict local-only parsing by default (optional explicit override via `--allow-external-ct`).

**Network Layer Analyzer (DNS Intelligence)**
- DNS Leaks Prevention enforcing DNS-over-HTTPS (DoH) via Cloudflare (`https://cloudflare-dns.com/dns-query`) using `httpx` to prevent cleartext port 53 interception.
- RFC-Compliant parallel enumeration of A, AAAA, MX, NS, TXT, SOA, and CAA records.

## Mathematical Forensics & Detection Algorithms

Unlike traditional scanners that rely on static signatures, Nexus identifies synthetic infrastructure through mathematical proofs.

### Benford's Law Auditor

Calculates Pearson's Chi-squared test against the expected logarithmic distribution of first digits to detect artificially generated datasets (e.g., DNS record lengths).

```python
class BenfordAnalyzer:
    EXPECTED = {d: math.log10(1 + 1/d) for d in range(1, 10)}
    
    @classmethod
    def get_first_digit(cls, v: float) -> int:
        """Pure mathematical extraction of the first non-zero digit."""
        if v == 0: return 0
        v = abs(v)
        return int(v / (10 ** int(math.log10(v))))

    @classmethod
    def compute(cls, values: List[float]) -> Dict[str, Any]:
        digits = [cls.get_first_digit(v) for v in values]
        digits = [d for d in digits if 1 <= d <= 9]
        
        # Pearson's Chi-squared test
        counts = Counter(digits)
        n = len(digits)
        chi_sq = sum(
            ((counts.get(d, 0) - (cls.EXPECTED[d] * n))**2) / (cls.EXPECTED[d] * n) 
            for d in range(1, 10)
        )
        
        # Critical value: 15.507 for 8 DoF at alpha=0.05
        return {
            "chi_squared": round(chi_sq, 4), 
            "is_anomalous": chi_sq > 15.507
        }
Shannon Entropy & Markovian DeterminismCombines Information Density with sequence predictability to accurately identify Domain Generation Algorithms (DGA) and encrypted payloads.Pythonclass EntropyAnalyzer:
    @staticmethod
    def analyze(data: str) -> Dict[str, Any]:
        n = len(data)
        freqs = Counter(data)
        probs = [c/n for c in freqs.values()]
        
        # Shannon Entropy (Bits per character)
        shannon = -sum(p * math.log(p, 2) for p in probs)
        
        # Efficiency (Normalized entropy H / H_max)
        max_h = math.log(len(freqs), 2) if len(freqs) > 1 else 1.0
        efficiency = shannon / max_h
        
        # Markovian Structural Analysis
        markov = MarkovChain.analyze(data)
        det_idx = markov.get("determinism_index", 0.0)
        
        # DGA Heuristic Detection
        is_synthetic = (efficiency > 0.85 and det_idx < 0.45) or (efficiency > 0.94)
        
        return {
            "shannon": round(shannon, 4),
            "efficiency": round(efficiency, 4),
            "determinism": round(det_idx, 4),
            "is_synthetic": is_synthetic
        }
Reliability Engineering (SRE)Tarpit Tolerance (Anti-Zombie Threads): Orchestration via ThreadPoolExecutor wrapped in strict concurrent.futures.wait controls. If a malicious server (Honeypot/Tarpit) holds the socket open to exhaust scanner resources, Nexus severs the blocked thread upon reaching the global NEXUS_TIMEOUT, guaranteeing audit completion.Exponential Backoff: Integration of the tenacity library to handle rate-limits and HTTP 429 blocks with intelligent retry logic and random jitter.Strict Environment Validation: Pydantic (BaseSettings) integration ensures that the execution matrix instantiation fails fast if the environment configuration is corrupted.InstallationSystem RequirementsOperating System: Linux (Debian/Ubuntu/Alpine) or Windows (WSL2 recommended)Runtime: Python 3.11+Privileges: Standard user (No root required for containerized execution)Docker Deployment (Recommended)Nexus utilizes a multi-stage Docker build to optimize image size and enforce OPSEC via a non-privileged system user (nexus).Bash# Build the secure container image
docker build -t nexus-intelligence .

# Execute an isolated forensic scan with volume mapping for JSONL logs
docker run --rm -v $(pwd)/reports:/home/nexus/app/reports nexus-intelligence target.com
Local Development CompilationBash# Clone repository
git clone [https://github.com/genesisgzdev/nexus-intelligence.git](https://github.com/genesisgzdev/nexus-intelligence.git)
cd nexus-intelligence

# Install dependencies and local package
pip install -r requirements.txt
pip install -e .
Configuration (Pydantic Schema)The framework adapts its behavior through strictly typed environment variables defined in .env:VariableTypeDefaultDescriptionNEXUS_TIMEOUTint15Global request timeout in seconds per operationNEXUS_THREADSint8Maximum parallel module execution limitNEXUS_PROXY_URLstrNoneSOCKS5/HTTP proxy (e.g. socks5://127.0.0.1:9050)NEXUS_DOH_ENDPOINTstrCloudflareDNS-over-HTTPS endpoint for leak preventionNEXUS_ALLOW_EXTERNAL_CTboolFalseDanger: Breaks Zero-API mandate via crt.shUsage & Output ForensicsCommand-Line ExecutionBash# Standard strict-OPSEC execution (Zero-API compliant)
nexus-intel target.com

# Verbose execution with external CT log queries (Breaks Zero-API Mandate)
nexus-intel target.com --verbose --allow-external-ct
Immutable Forensic TrailNexus utilizes a dual-channel logging system. Real-time visualization is handled via the Rich console, while immutable .jsonl forensic logs are securely written to the /reports/ directory for SIEM ingestion.Serialized JSON Evidence Output:JSON─── DNSIntelligence ───
{
  "target_entropy": {
    "shannon": 3.452,
    "efficiency": 0.941,
    "determinism": 0.210,
    "is_synthetic": true,
    "forensic_summary": "High_Entropy_Synthetic"
  },
  "resolver_config": "DoH_Privacy_Active",
  "A": ["104.21.XX.XX"],
  "_meta": {"runtime": 0.812, "module": "DNSIntelligence"}
}

─── StatisticalAudit ───
{
  "chi_squared": 18.204,
  "is_anomalous": true,
  "sample_size": 45,
  "distribution": { "1": 0.12, "2": 0.08, "3": 0.40 }
}
Known LimitationsCorporate SSL Inspection: If the framework is executed behind a deep packet inspection firewall (DPI/SSL Decryption), the SSLForensics module will audit the certificate injected by the local proxy, not the target's actual certificate.Dynamic JA3 Evasion: Although the signature emulates Chrome 120, highly paranoid WAFs that cross-reference the JA3 hash with passive OS-level TCP fingerprinting (p0f) may detect discrepancies if executed on legacy Linux distributions.Legal Disclaimer & LicenseGNU AGPLv3 (Affero General Public License)This software is licensed under the GNU AGPLv3. This strong copyleft license stipulates that:You are free to use, modify, and distribute this software.Any modifications must be distributed under the exact same license.Network Clause: If you run this modified software on a server and allow others to interact with it over a network (such as a cloud service or web interface), YOU ARE REQUIRED to make the complete source code of your version publicly available to the network users.Authorized Use Clause (Legal Liability)THIS SOFTWARE IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND.This framework is forensic intelligence weaponry. Using Nexus Intelligence for unauthorized reconnaissance of government, corporate, or civilian infrastructure is a federal crime in most jurisdictions (including the Computer Fraud and Abuse Act - CFAA in the U.S. and international cybercrime conventions).By executing nexus-intel, you declare under penalty of perjury that you possess explicit, written authorization from the target infrastructure's owner. The developer assumes NO liability for damage, data loss, service interruption, or criminal prosecution resulting from the misuse of this tool.Support & ContactContact: genzt.dev@pm.meNexus Intelligence Cryptography. Mathematics. Stealth.Developed by Genesis
