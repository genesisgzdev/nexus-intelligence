# Nexus Intelligence

## System Overview
Nexus Intelligence is an asynchronous, protocol-driven Open Source Intelligence (OSINT) orchestration platform. It is engineered for high-concurrency forensic data collection across DNS, TLS/SSL, Web Application Stacks, and Mail Infrastructure without reliance on third-party APIs.

## Architecture

`mermaid
graph TD;
    CLI[__main__.py] -->|argparse| ORCH[IntelligenceOrchestrator];
    ORCH -->|asyncio.Queue| ENG[IntelligenceEngine];
    ENG -->|Parallel Execution| MODS[Analysis Modules];
    
    subgraph Modules [Forensic Engines]
        DNS[DNSIntelligence: raw UDP/TCP 53]
        SSL[SSLForensics: Local X.509 Handshake]
        WEB[WebIntelligence: JA3 Impersonation]
        MAIL[MailIntelligence: SMTP Banner/SPF/DMARC]
        SUB[SubdomainDiscovery: Async Brute-force]
    end
    
    MODS -->|JSON Results| DB[(Local SQLite Persistence)];
    MODS -->|Event Stream| REP[ReportingEngine];
    REP -->|Markdown/JSON| FS[Forensic Reports];
`

## Core Capabilities

### 1. Protocol-Driven Intelligence (Zero-API)
Unlike standard OSINT tools that proxy queries through web services, Nexus interacts directly with target infrastructure:
- **DNS Forensics**: Utilizes \dns.asyncresolver\ for direct recursion over UDP/TCP port 53.
- **TLS Handshake**: Performs local X.509 attribute extraction (Issuer, SANs, Signature Algorithms) via raw async socket handshakes.
- **SMTP Auditing**: Executes non-intrusive SMTP banner grabbing and validates SPF/DMARC policies to map mail infrastructure trust levels.

### 2. High-Concurrency Orchestration
The system utilizes a non-blocking \syncio\ event loop to manage massive target lists:
- **Semaphores**: Rate-limiting is enforced via \syncio.Semaphore\ to prevent local network stack exhaustion.
- **Worker/Master Pattern**: The \IntelligenceOrchestrator\ enables parallel processing of multiple domains with automated job queuing and recovery.

### 3. Forensic Persistence & Reporting
- **SQLite Storage**: Every session is indexed in \
exus_forensics.db\ for historical correlation and time-series analysis.
- **Automated Artifacts**: The \ReportingEngine\ generates structured Markdown forensics upon task completion, detailing infrastructure anomalies and cryptographic fingerprints.

## Security Controls
- **SSRF Mitigation**: Every target is validated against a comprehensive list of restricted private subnets and metadata endpoints prior to resolution.
- **OPSEC Hardware Impersonation**: Web modules utilize JA3 fingerprint impersonation to bypass traffic-shaping devices and WAFs at the cryptographic layer.

## Build and Deployment
Nexus is fully containerized using multi-stage Alpine builds with non-privileged user contexts. Refer to \CONTRIBUTING.md\ for setup details.
