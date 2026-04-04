Nexus Intelligence Framework
Advanced Protocol-Level OSINT & Forensics Suite

Overview
Nexus Intelligence is a next-generation signal intelligence (SIGINT) and network infrastructure forensics framework. Engineered for threat researchers and Red Team operators, Nexus abandons the traditional reliance on third-party SaaS aggregators (such as Shodan, Censys, or VirusTotal).

Instead, it executes direct protocol reconnaissance and implements real-time mathematical validation engines to detect synthetic entities, Domain Generation Algorithms (DGA), and obfuscated infrastructure. The core engine operates strictly under the Zero-API Mandate, ensuring target identifiers are never leaked to public databases, while utilizing Layer 7 cryptographic evasion to remain undetectable by modern bot-management systems.

Technical Architecture: Integrated Detection System
The framework implements a unified, thread-safe execution architecture divided into three simultaneous execution subsystems.

1. Cryptographic Evasion Layer (OPSEC)
TLS Handshake Impersonation (JA3/JA4): Through the integration of the curl_cffi library, Nexus spoofs ClientHello packets at the socket level to cryptographically match the exact signature of Google Chrome 120. This silently bypasses WAFs and DDoS mitigation systems (Cloudflare, Akamai, Imperva) that block forensic tools based on standard Python SSL fingerprints.

DNS Leak Prevention (DoH): Infrastructure resolution no longer travels in plaintext over port 53. All queries are routed via DNS-over-HTTPS (DoH) using the httpx library, preventing metadata interception by the local ISP or the target's network.

Anonymous Routing: Native, environment-validated support for SOCKS5 tunnels and Tor network routing, fully isolating the analyst's origin IP address from the target infrastructure.

2. Protocol Intelligence Modules
WebIntelligence (Application Layer): Structural DOM tree analysis via BeautifulSoup (lxml). Identifies frameworks (React, Vue, Laravel), security policies (HSTS, CSP), and calculates the entropy of meta-structural content to identify algorithmically generated landing pages.

SSLForensics (Transport Layer): Raw socket connections bypass high-level HTTP validators. Extracts the complete X.509 chain, identifying Subject Alternative Names (SAN), Authority Information Access (OCSP) endpoints, and Certificate Transparency history directly from the handshake.

DNSIntelligence (Network Layer): Parallel, RFC-compliant infrastructure mapping (A, AAAA, MX, NS, TXT, SOA, CAA) strictly shielded by DoH upstream resolvers.

3. Mathematical Forensics Core
The heart of the framework does not rely on static threat signatures, but rather on statistical anomalies within the response data.

Benford's Law Auditor (First-Digit Law) Extracts the distribution of numerical datasets (e.g., DNS record lengths, SSL latencies) using pure mathematics. It applies Pearson's Chi-squared goodness-of-fit test. If the value exceeds the critical threshold of 15.507 (at α = 0.05 with 8 degrees of freedom), the dataset is flagged as manually manipulated or synthetically generated.

Shannon Entropy & Markovian Determinism Calculates information density and normalizes it against the maximum possible entropy of the alphabet (Efficiency). It computes a transition probability matrix for N-grams (Determinism). By cross-referencing Shannon efficiency (>0.85) with the Markov determinism index (<0.45), the engine mathematically distinguishes between natural language and encrypted strings or DGA.

Reliability Engineering (SRE)
To operate seamlessly in hostile network environments, Nexus implements severe reliability controls:

Tarpit Tolerance (Anti-Zombie Threads): Orchestration is handled via ThreadPoolExecutor wrapped in strict concurrent.futures.wait controls. If a malicious server (Honeypot/Tarpit) holds the socket open to exhaust scanner resources, Nexus severs the blocked thread upon reaching the global NEXUS_TIMEOUT, guaranteeing audit completion.

Exponential Backoff: Integration of the Tenacity library to handle rate-limits and HTTP 429 blocks with intelligent retry logic and random jitter.

Strict Environment Validation: Pydantic (BaseSettings) integration ensures that the execution matrix instantiation fails fast if the environment configuration is corrupted, preventing silent runtime errors during an active analysis.

Installation & Deployment
System Requirements
Environment: Linux (Debian/Ubuntu/Alpine) or WSL2.

Language: Python 3.11+

Core Dependencies: Underlying C libraries required for lxml and cryptographic certificate compression algorithms.

Secure Deployment (Docker - Recommended)
An optimized Dockerfile utilizing a Multi-stage build is provided. It strips compilers from the final image and executes the tool under a non-privileged nexus user, ensuring strict containment.

Local Compilation
Environment Configuration
The framework adapts its behavior through strictly typed environment variables. These can be defined in a .env file or passed at runtime.

Immutable Auditing & Logs
Nexus utilizes a dual-channel logging system:

Console (Rich): Structured, real-time visualization for the analyst during active operations.

Forensic Log (JSONL): Immutable .jsonl files generated in the /reports/ directory. Ideal for direct ingestion into SIEM platforms (Splunk, Elastic) or secure storage as chain-of-custody digital evidence.

Output Example (Serialized JSON)
Known Limitations
Corporate SSL Inspection: If the framework is executed behind a deep packet inspection firewall (DPI/SSL Decryption), the SSLForensics module will audit the certificate injected by the local proxy, not the target's actual certificate.

Dynamic JA3 Evasion Anomaly: Although the signature emulates Chrome 120, highly paranoid WAFs that cross-reference the JA3 hash with passive OS-level TCP fingerprinting (p0f) may detect discrepancies if the framework is executed on legacy Linux distributions.

License and Legal Use (IMPORTANT)
GNU AGPLv3 (Affero General Public License)
This software is licensed under the GNU AGPLv3. This strong copyleft license stipulates that:

You are free to use, modify, and distribute this software.

Any modifications must be distributed under the exact same license.

Network Clause: If you run this modified software on a server and allow others to interact with it over a network (such as a cloud service or web interface), YOU ARE REQUIRED to make the complete source code of your version publicly available to the network users.

Authorized Use Clause (Legal Liability)
This framework is forensic intelligence weaponry. Using Nexus Intelligence for unauthorized reconnaissance of government, corporate, or civilian infrastructure is a federal crime in most jurisdictions (including the Computer Fraud and Abuse Act - CFAA in the U.S. and international cybercrime conventions).

By executing nexus-intel, you declare under penalty of perjury that you possess explicit, written authorization from the target infrastructure's owner. The developer assumes NO liability for damage, data loss, service interruption, or criminal prosecution resulting from the misuse of this tool.

Nexus Intelligence Cryptography. Mathematics. Stealth.

Developed by Genesis | genzt.dev@pm.me
