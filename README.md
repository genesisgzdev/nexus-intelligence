# Nexus Intelligence Framework

Professional Zero-API OSINT and Network Forensics Framework for advanced security research. Engineered for total OPSEC, cryptographic evasion, and statistical analysis of infrastructure.

## Core Philosophy: The Zero-API Mandate

Nexus is built on the principle of absolute isolation. Unlike traditional reconnaissance tools that rely on third-party aggregators (Shodan, VirusTotal, Censys), Nexus performs raw, local-first forensic analysis. 

*   **Zero Leakage:** Target identifiers (domains, IPs) are never transmitted to third-party APIs by default.
*   **Cryptographic Evasion:** Implements JA3/JA4 TLS impersonation to bypass modern Layer 7 bot-management systems (Cloudflare, Akamai).
*   **Privacy-First DNS:** All infrastructure queries are routed via DNS-over-HTTPS (DoH) to prevent ISP-level metadata interception.

## Technical Architecture

### 1. Network Fingerprinting & Evasion
*   **TLS Impersonation:** Utilizes `curl_cffi` to perform cryptographic handshakes that perfectly mimic Google Chrome 120, preventing WAF-level fingerprinting.
*   **Browser Profile Injection:** Randomizes User-Agents and header structures to match real-world browser traffic.
*   **Proxy Support:** Native SOCKS5 and Tor routing for all outbound forensic traffic.

### 2. Forensic Intelligence Modules
*   **WebIntelligence:** Structural DOM analysis using `BeautifulSoup` (lxml) for meta-tag extraction and technology stack fingerprinting.
*   **SSLForensics:** Deep X.509 inspection, extracting Subject Alternative Names (SAN), Serial Numbers, and OCSP endpoints.
*   **DNSIntelligence:** Multi-record infrastructure analysis (A, AAAA, MX, NS, TXT, SOA, CAA) via secure DoH resolvers.

### 3. Mathematical & Statistical Engine
*   **Benford's Law Audit:** Statistical validation of numerical data (latencies, record lengths) using Pearson's Chi-squared test to detect synthetic or manipulated data.
*   **Markovian Determinism:** N-gram transition probability analysis to distinguish between Natural Language and Domain Generation Algorithms (DGA).
*   **Shannon Entropy:** Information density calculation to identify obfuscated payloads and encrypted strings.

### 4. Reliability Engineering
*   **Exponential Backoff:** Intelligent retry logic with random jitter using the `tenacity` engine.
*   **Zombie Process Prevention:** Strict global timeout enforcement to prevent thread stalling on network tarpits.
*   **Immutable Auditing:** Dual-channel logging (Structured Rich console + Forensic JSONL files).

## Installation

### Via Docker (Recommended)
Isolate the framework and its dependencies within a non-privileged container.

```bash
docker build -t nexus-intelligence .
docker run --rm -v $(pwd)/reports:/home/nexus/app/reports nexus-intelligence <target>
```

### Local Development
Requires Python 3.11+.

```bash
pip install -r requirements.txt
python -m nexus_intelligence <target>
```

## Configuration

Nexus uses Pydantic-based configuration. You can override defaults via environment variables:

*   `NEXUS_TIMEOUT`: Global timeout in seconds (Default: 15).
*   `NEXUS_THREADS`: Maximum parallel execution threads (Default: 8).
*   `NEXUS_PROXY_URL`: SOCKS5/HTTP proxy URL.
*   `NEXUS_DOH_ENDPOINT`: DNS-over-HTTPS provider.

## Usage

Standard forensic scan:
```bash
nexus-intel cloudflare.com
```

Verbose scan with external CT log lookup (Breaks Zero-API Mandate):
```bash
nexus-intel google.com --verbose --allow-external-ct
```

## Forensic Logs
All results are persisted in the `reports/` directory in JSONL format, providing an immutable audit trail for forensic investigations.

## License
MIT License.
