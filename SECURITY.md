# Security Policy

## Core Security Mandate: Zero-API Intelligence

Nexus Intelligence is architected to prioritize **Operational Security (OPSEC)** and **Data Sovereignty**. By operating under a **Zero-API** mandate, the framework ensures that:
1.  **No Third-Party Exposure**: Intelligence gathering does not trigger logs in 3rd-party SaaS databases (e.g., Shodan, Censys, HIBP).
2.  **Privacy of Investigation**: Target identifiers are never transmitted to external APIs, preventing investigation leakage.
3.  **Local Forensic Integrity**: All mathematical audits (Entropy, Benford's Law) occur locally on the investigator's infrastructure.

---

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 3.1.x   | :white_check_mark: |
| 3.0.x   | :x:                |
| < 2.0.0 | :x:                |

---

## Reporting a Vulnerability

We prioritize the security of the Nexus framework and the data it processes. If you discover a security vulnerability within the framework's orchestration engine or forensic modules, please report it following these steps:

1.  **Private Disclosure**: Do not open a public GitHub issue for security vulnerabilities.
2.  **Email**: Send a detailed report to `genesis.issues@pm.me`.
3.  **Required Information**:
    -   A clear description of the vulnerability.
    -   Steps to reproduce (PoC).
    -   Potential impact on investigators or targets.
    -   (Optional) Suggestions for remediation.

### Response Timeline
-   **Acknowledgment**: Within 24 hours.
-   **Initial Analysis**: Within 72 hours.
-   **Remediation Plan**: Provided within 7 days.

---

## Secure Deployment Recommendations

To maintain the forensic integrity of your investigations, we recommend the following:

*   **Isolated Infrastructure**: Execute Nexus from a dedicated, non-production environment or an ephemeral container.
*   **Encrypted Egress**: Always route Nexus traffic through an encrypted VPN or Tor bridge to prevent ISP-level metadata collection.
*   **Root Authority**: When performing deep SSL forensics, ensure your certificate bundle (`certifi`) is updated to prevent MITM during the handshake extraction.
*   **Docker Isolation**: Use the provided `Dockerfile` to ensure that dependencies do not pollute the host system and that the environment remains immutable.

---

## Legal & Ethical Usage

Use of Nexus Intelligence for unauthorized reconnaissance is a violation of international cyber-laws. The framework is designed for:
-   **Security Auditing**: Validating the infrastructure of systems you own.
-   **Digital Forensics**: Investigating security incidents under proper legal authorization.
-   **Threat Intelligence**: Identifying DGA and synthetic infrastructure in a research capacity.

Misuse of this tool can lead to severe legal consequences under the **Computer Fraud and Abuse Act (CFAA)** or your local jurisdiction's equivalent.
