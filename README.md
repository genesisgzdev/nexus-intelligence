# Nexus Intelligence Framework (v3.1.0)

**Nexus Intelligence** is a high-performance, Zero-API OSINT reconnaissance and forensic framework designed for deep infrastructure analysis and digital investigation. Unlike traditional OSINT tools that rely on fragile 3rd-party APIs, Nexus implements direct protocol forensics and advanced mathematical models to extract intelligence from the network, transport, and application layers.

The framework is built on a decoupled, multi-threaded orchestration engine that correlates statistical anomalies—such as Information Entropy and Benford's Law violations—to identify synthetic entities, DGA domains, and infrastructure inconsistencies.

---

## Core Philosophy: Zero-API Forensics

In modern digital investigations, reliance on external APIs (GitHub, Shodan, HIBP) introduces three critical failure points: **detectability** (via API logging), **unreliability** (rate limits/downtime), and **privacy leakage**. 

Nexus Intelligence operates on an absolute **Zero-API Mandate**:
- **Direct Protocol Interaction**: Intelligence is pulled directly from RFC-compliant DNS, TCP/IP handshakes, and HTTP/S streams.
- **Local Mathematical Inference**: Anomalies are detected using local statistical engines rather than remote databases.
- **Operational Security (OPSEC)**: Minimal footprint, no centralized tracking of queries.

---

## Technical Architecture

### 1. Intelligence Orchestration Engine
The `IntelligenceEngine` manages the concurrent execution of decoupled forensic modules. Using a high-performance thread pool, it aggregates intelligence from multiple layers of the OSI model simultaneously.

- **Parallel Execution**: DNS, SSL, and Web modules run in non-blocking threads.
- **State Aggregation**: Centralized result processing with runtime metadata and fault isolation.
- **Extensible Plugin System**: Base-class architecture allows for seamless integration of new forensic modules.

### 2. Mathematical Forensic Core
Nexus integrates advanced statistical engines to validate the integrity of gathered intelligence:

*   **Information Entropy (Shannon & Rényi)**: Analyzes the density of information in domain names and certificates. High efficiency scores (>0.92) in targets are flagged as potential DGA (Domain Generation Algorithms) or synthetic certificates.
*   **Benford's Law Auditor**: Performs chi-squared tests on the distribution of numerical metadata (e.g., DNS record lengths, certificate validity periods). Identifies datasets that have been manually manipulated or synthetically generated.
*   **Markov Transition Model**: Measures the determinism of sequential data. Used to distinguish between automated system behavior and human-like interactions at the protocol level.

### 3. Forensic Modules

#### **Network Intelligence (DNS)**
- **RFC-Compliant Enumeration**: Direct resolution of A, AAAA, MX, NS, TXT, and SOA records.
- **DGA Detection**: Real-time entropy analysis of the target identifier to detect algorithmic domain generation.
- **Infrastructure Mapping**: Automatic extraction of mail server priorities and authoritative nameservers.

#### **Transport Intelligence (SSL/TLS Forensics)**
- **Handshake Analysis**: Direct extraction of the TLS certificate chain via native sockets.
- **X.509 Intelligence**: Deep parsing of Subject, Issuer, Serial Numbers, and Validity periods.
- **SAN Forensic Audit**: Entropy analysis of Subject Alternative Names to detect hidden infrastructure or shared hosting anomalies.
- **Cipher Suite Fingerprinting**: Identification of the server's cryptographic stack and protocol versions.

#### **Application Intelligence (Web Fingerprinting)**
- **Passive Stack Audit**: Signature-based detection of frameworks (WordPress, Laravel, React) via headers and response body analysis.
- **Security Policy Evaluation**: Validation of Content-Security-Policy (CSP) and Strict-Transport-Security (HSTS).
- **Metadata Forensics**: Statistical analysis of HTML titles and structural components.

---

## Performance Benchmarks

*Tested on Python 3.11, 8-core CPU, 1Gbps Uplink.*

| Operation | Strategy | Avg. Time | Complexity |
| :--- | :--- | :--- | :--- |
| **DNS Intelligence** | Parallel RFC Query | 0.8s | O(records) |
| **TLS Forensics** | Direct Handshake | 0.4s | O(1) |
| **Web Audit** | Passive Fingerprint | 1.1s | O(signatures) |
| **Statistical Audit** | Chi-Squared / Entropy | <0.1s | O(n) |
| **Full Investigation** | Parallel Orchestration | **~1.5s** | **Optimized** |

---

## Installation & Deployment

### Docker Deployment (Recommended)
Nexus is optimized for containerized environments to ensure consistent forensic snapshots.

```bash
# Build the intelligence image
docker build -t nexus-intel .

# Execute a non-persistent scan
docker run --rm nexus-intel target.com
```

### Standard Installation
```bash
# Clone the repository
git clone https://github.com/genesisgzdev/nexus-intelligence.git
cd nexus-intelligence

# Install local package
pip install -e .

# Run CLI
nexus-intel target.com --verbose
```

---

## Operational Security & Legal Notice

This framework is a professional tool for security researchers and authorized investigators. 

1.  **Authorization**: Explicit written consent from the target infrastructure owner is mandatory before execution.
2.  **Compliance**: Users must comply with the Computer Fraud and Abuse Act (CFAA) and GDPR regulations regarding data processing.
3.  **Disclaimer**: The developers provide this tool "as-is" for educational and forensic purposes. Misuse of this tool for unauthorized activities is strictly prohibited.

---

**Nexus Intelligence**  
**Forensics Mathematical Rigor.**
