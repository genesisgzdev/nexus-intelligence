# Nexus Intelligence Framework (v1.6.0)

## Technical Specification
Nexus Intelligence is a distributed, asynchronous forensic orchestration platform designed for autonomous Open Source Intelligence (OSINT) and cross-project threat correlation. It operates under a **Zero-API Mandate**, utilizing native network protocols to interact directly with target infrastructure.

## System Architecture

`mermaid
graph TB
    subgraph Input_Layer [Orchestration]
        M[__main__.py] -->|argparse| ORCH[IntelligenceOrchestrator]
        ORCH -->|asyncio.Queue| Q[Task Queue]
    end

    subgraph Analysis_Layer [Forensic Engines]
        Q --> W1[Worker 1]
        Q --> W2[Worker 2]
        W1 & W2 --> DNS[DNS: raw UDP/53]
        W1 & W2 --> SSL[SSL: Local X.509 Parser]
        W1 & W2 --> WEB[Web: JA3 Impersonation]
        W1 & W2 --> MAIL[Mail: SMTP Banner Grabbing]
    end

    subgraph Intelligence_Layer [AI Correlation]
        DNS & SSL & WEB & MAIL -->|JSONL| DB[(SQLite Persistence)]
        DB -->|Text Context| VEC[TF-IDF VectorCorrelator]
        VEC -->|Cosine Similarity| REL[Related Threats Mapping]
    end

    subgraph Output_Layer [Forensics]
        REL -->|Markdown| REP[Automated ReportingEngine]
    end
`

## Core Modules & Protocol Implementation

### 1. Advanced DNS Forensics
- **Mechanism**: Utilizes \dns.asyncresolver\ for non-blocking recursion.
- **Protocol Integrity**: Bypasses HTTPS-based resolvers (DoH) to interact directly with nameservers, capturing raw record sets (A, AAAA, MX, TXT, SOA, CAA).
- **Security**: Implements SSRF gating, preventing queries to internal RFC 1918 addresses or cloud metadata endpoints.

### 2. TLS/SSL Forensic Engine
- **Local Handshake**: Performs a full async TLS handshake without verifying chains (Forensic Mode) to extract raw DER-encoded certificates.
- **X.509 Analysis**: Parses Issuer, Subject, Validity, Serial, and Subject Alternative Names (SAN) locally using the \cryptography\ library.
- **Fingerprinting**: Calculates SHA-256 fingerprints and analyzes signature hash algorithms to detect compromised or spoofed certificates.

### 3. Application Stack Fingerprinting
- **JA3 Impersonation**: Uses \curl_cffi\ to mimic specific browser cryptographic signatures (Chrome 120), bypassing perimeter Bot-Management (Cloudflare/Akamai).
- **Security Header Audit**: Passively analyzes CSP, HSTS, X-Frame-Options, and X-Content-Type-Options to identify misconfigurations.

### 4. Semantic Correlation (TF-IDF)
- **Local features**: Builds a reproducible TF-IDF matrix from persisted findings and optional EDR JSONL telemetry.
- **Similarity search**: Uses cosine similarity over the actual scikit-learn matrix; no FAISS or unavailable embedding service is required.
- **Cross-Project Linking**: Correlates EDR kernel events (\	hreat-detection-suite\) with OSINT findings to identify multi-stage attack chains.

## Data Governance & Persistence
- **SQLite Schema**: All findings are stored in a relational schema with JSON blobs for modular extensibility.
- **Integrity Auditing**: The `VectorIntegrityAuditor` validates matrix size and unit normalization of the active TF-IDF vectors.

## Deployment
- **Docker**: Hardened Alpine-based containers with unprivileged user contexts (\USER nexususer\).
- **CI/CD**: Workflows are configured for \workflow_dispatch\ to ensure successful, manually-gated deployments.

### 5. Automated Correlation
Nexus triggers local semantic search after report generation.
- **Contextual ingestion**: Reads optional EDR JSONL and historical OSINT findings from SQLite.
- **Live search**: Performs cosine similarity over the TF-IDF matrix.
- **Integrity gating**: Audits the active matrix before treating its vectors as healthy.
