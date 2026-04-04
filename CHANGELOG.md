# Changelog

All notable changes to this project will be documented in this file.

## [3.3.0] - 2026-04-04

### Nexus Intelligence v3.3.0: Protocol Forensics and Cryptographic Evasion

### 🛡️ Network Fingerprinting and OPSEC
- **TLS Impersonation (JA3/JA4):** Integration of `curl_cffi` for cryptographic handshake spoofing. Handshake profiles match **Google Chrome 120**, bypassing Layer 7 bot-management and DDoS mitigation systems (Cloudflare, Akamai) at the socket layer.
- **DNS-over-HTTPS (DoH):** Native implementation of DoH via `httpx`. Infrastructure resolution is strictly routed through encrypted tunnels, preventing ISP-level metadata leakage and plaintext interception.
- **Zero-API Mandate Enforcement:** The framework operates under a strict local-first philosophy. Target identifiers are never transmitted to third-party APIs. External Certificate Transparency (CT) lookups are disabled by default and require explicit user authorization via `--allow-external-ct`.

### 🧬 Mathematical Forensics Engine
- **Statistical Data Auditing:** Implements **Benford’s Law** using Pearson's Chi-squared goodness-of-fit test. Detects synthetic or manipulated numerical distributions in DNS and SSL datasets.
- **Markovian Determinism:** Analyzes N-gram transition probabilities to distinguish between natural language structures and Domain Generation Algorithms (DGA).
- **Information Density:** Shannon Entropy calculations to identify encrypted payloads and obfuscated strings within application and transport layers.

### 🏗️ Systems Engineering and Reliability (SRE)
- **Tarpit Resilience:** Orchestration via `ThreadPoolExecutor` with strict global timeout enforcement. Prevents resource exhaustion (Zombie Threads) when interacting with malicious honeypots or tarpits.
- **Intelligent Backoff:** Integration of the `tenacity` engine for exponential backoff with random jitter, optimizing success rates against rate-limited endpoints.
- **Typed Configuration:** Migration to `Pydantic` (BaseSettings) for strict environment validation and fail-fast initialization.

### 📊 Forensic Auditing
- **Immutable Logging:** Dual-channel logging system providing structured Rich console output and forensic-grade **JSONL** persistent storage for SIEM ingestion and chain-of-custody preservation.

## [3.2.0] - 2026-04-04
- Refactored core engine for Pydantic v2.
- Added advanced entropy analysis for subdomains.
- Initial Docker support for non-root execution.
