# Nexus Intelligence Framework

> Advanced Protocol-Level OSINT & Network Forensics Suite

![Version](https://img.shields.io/badge/version-3.3.0-blue.svg?style=flat-square)
![License](https://img.shields.io/badge/license-AGPLv3-red.svg?style=flat-square)
![Python](https://img.shields.io/badge/python-3.11+-green.svg?style=flat-square)
![Docker](https://img.shields.io/badge/docker-ready-cyan.svg?style=flat-square)

---

## Overview

**Nexus Intelligence** is a signal intelligence (SIGINT) and network infrastructure forensics framework built for threat researchers and Red Team operators.

The core design principle is the **Zero-API Mandate**: all analysis is executed via direct socket interactions against the target. No external SaaS aggregators (Shodan, Censys, VirusTotal) are contacted at any point. Target identifiers never leave the local execution environment unless explicitly overridden by the operator.

On top of passive silence, the framework implements Layer 7 cryptographic evasion to avoid fingerprinting by modern bot-management systems, and a local statistical inference engine to validate the authenticity of the target infrastructure without relying on threat signature databases.

---

## Architecture

The framework is composed of three concurrent execution subsystems, all coordinated through a single thread-safe orchestration layer.

```
nexus_intelligence/
├── core/
│   ├── orchestrator.py       # ThreadPoolExecutor + futures.wait coordination
│   ├── config.py             # Pydantic BaseSettings — environment validation
│   └── logging.py            # Dual-channel output (Rich console + JSONL)
├── modules/
│   ├── web_intelligence.py   # Application layer — DOM, headers, entropy
│   ├── ssl_forensics.py      # Transport layer — raw X.509 chain extraction
│   └── dns_intelligence.py   # Network layer — DoH-shielded parallel mapping
├── forensics/
│   ├── benford.py            # Chi-squared first-digit distribution auditor
│   ├── entropy.py            # Shannon entropy + Markov N-gram analysis
│   └── fingerprint.py        # JA3/JA4 spoof layer via curl_cffi
└── __main__.py               # CLI entry point: nexus-intel <target>
```

---

## Subsystem 1 — Cryptographic OPSEC Layer

### TLS Handshake Impersonation (JA3/JA4)

Standard Python SSL clients produce a distinctive `ClientHello` fingerprint that is trivially blocked by enterprise WAFs and bot-management systems. Nexus replaces the Python SSL stack with `curl_cffi`, spoofing the handshake at the socket level to cryptographically match **Google Chrome 120**.

This bypasses passive JA3/JA4 fingerprinting employed by Cloudflare Bot Management, Akamai, and Imperva without any active evasion behavior that could trigger anomaly detection.

Known limitation: paranoid WAFs that cross-reference JA3 against passive OS-level TCP fingerprinting (p0f) may detect a mismatch on older Linux kernels where the TCP stack differs from a native Windows Chrome client.

### DNS-over-HTTPS Enforcement

All infrastructure resolution is routed through encrypted DoH upstream resolvers (Cloudflare 1.1.1.1 or Quad9) via `httpx`. Plaintext port 53 queries are never issued. This eliminates ISP-level metadata collection, DNS poisoning vectors, and passive DNS monitoring by the target network.

### Anonymous Routing

The framework validates and routes traffic through SOCKS5 proxies or Tor (`stem`) when `NEXUS_PROXY_URL` is set. The proxy URL is type-checked at startup by Pydantic — an invalid URI causes an immediate abort rather than a silent fallback to the real IP.

### Zero-API Mandate

External Certificate Transparency log queries via `crt.sh` are disabled by default. This is the only operation that would leak the target domain to a third party. Pass `--allow-external-ct` explicitly to enable it. The flag is intentionally verbose to make the OPSEC tradeoff visible.

---

## Subsystem 2 — Protocol Intelligence Modules

### WebIntelligence (Application Layer)

Performs structural DOM analysis via `BeautifulSoup` with `lxml` as the parser backend. Extracts and classifies:

- Frontend framework fingerprints (React, Vue, Angular, Laravel) via meta-tag and script source analysis
- Security policy headers: HSTS, CSP, X-Frame-Options, Referrer-Policy
- Shannon entropy of page title, meta descriptions, and canonical URLs — high entropy is a primary indicator of algorithmically generated landing pages

### SSLForensics (Transport Layer)

Connects via raw socket, bypassing high-level HTTP clients that strip or normalize certificate data. Extracts the complete X.509 chain and surfaces:

- Full Subject Alternative Name (SAN) list
- Authority Information Access (AIA) — OCSP responder and CA issuer endpoints
- Certificate Transparency SCT records from the handshake extension
- Validity window and issuer chain depth

Note: if the framework executes behind a corporate DPI/SSL-inspection firewall, this module will audit the proxy-injected certificate rather than the target's actual chain.

### DNSIntelligence (Network Layer)

Parallel, RFC-compliant infrastructure mapping shielded entirely by DoH resolvers. Queries all record types concurrently: `A`, `AAAA`, `MX`, `NS`, `TXT`, `SOA`, `CAA`. Results are fed directly into the mathematical forensics core for entropy and Benford analysis.

---

## Subsystem 3 — Mathematical Forensics Core

Static threat signatures can be spoofed. Statistical distributions extracted from protocol responses cannot be fabricated without introducing detectable anomalies.

### Benford's Law Auditor

Benford's Law (First-Digit Law) states that in naturally occurring numerical datasets, the leading digit `d` appears with probability `log10(1 + 1/d)`. Infrastructure that has been synthetically generated or manually manipulated will produce a leading-digit distribution that deviates significantly from this logarithmic curve.

The auditor extracts numerical datasets from DNS record lengths, SSL latency measurements, and TLS field values. It applies **Pearson's Chi-squared goodness-of-fit test** against the expected Benford distribution. A chi-squared value exceeding **15.507** (a = 0.05, 8 degrees of freedom) flags the dataset as anomalous.

```python
class BenfordAnalyzer:
    EXPECTED = {d: math.log10(1 + 1/d) for d in range(1, 10)}

    @classmethod
    def get_first_digit(cls, v: float) -> int:
        # Extracts leading digit without scientific notation edge cases
        if v == 0:
            return 0
        v = abs(v)
        return int(v / (10 ** int(math.log10(v))))

    @classmethod
    def compute(cls, values: List[float]) -> Dict[str, Any]:
        digits = [cls.get_first_digit(v) for v in values if v != 0]
        digits = [d for d in digits if 1 <= d <= 9]
        counts = Counter(digits)
        n = len(digits)
        chi_sq = sum(
            ((counts.get(d, 0) - (cls.EXPECTED[d] * n)) ** 2) / (cls.EXPECTED[d] * n)
            for d in range(1, 10)
        )
        return {
            "chi_squared": round(chi_sq, 4),
            "is_anomalous": chi_sq > 15.507,
            "sample_size": n,
        }
```

### Shannon Entropy & Markovian Determinism

Shannon entropy `H(X) = -sum(p(x) * log2(p(x)))` measures the information density of a string. Normalized against the maximum possible entropy of the character alphabet, it produces an **efficiency score** between 0 and 1.

A Markov transition probability matrix computed over N-grams of the same string produces a **determinism index**: how predictable the character sequence is relative to natural language baseline structures.

The two metrics are cross-referenced:

| Efficiency | Determinism | Classification |
|:---|:---|:---|
| < 0.75 | any | Natural language / human-readable |
| > 0.85 | > 0.45 | Encrypted or hashed payload |
| > 0.85 | < 0.45 | Domain Generation Algorithm (DGA) |
| 0.75 – 0.85 | < 0.45 | Obfuscated identifier — manual review |

This allows the engine to mathematically distinguish DGA-generated hostnames from legitimate high-entropy domains (e.g., CDN subdomains) without any external threat feed.

---

## Reliability Engineering

Hostile networks actively exploit scanner behavior. Three controls are implemented to guarantee audit completion under adversarial conditions.

**Tarpit Tolerance.** Thread orchestration uses `ThreadPoolExecutor` wrapped in `concurrent.futures.wait` with a hard `NEXUS_TIMEOUT` ceiling. If a honeypot holds a TCP connection open indefinitely to exhaust file descriptors and thread pool slots, the blocked thread is severed at timeout and the remaining audit proceeds unaffected.

**Exponential Backoff.** All DNS and HTTP operations are wrapped in `tenacity` retry logic with exponential backoff and randomized jitter. Rate-limited endpoints (HTTP 429, DNS SERVFAIL) are retried transparently without triggering secondary detection thresholds on the target side.

**Fail-Fast Environment Validation.** `pydantic` `BaseSettings` performs strict type-checking on the entire configuration matrix at process startup. A missing required variable or a malformed proxy URI causes an immediate abort with a structured error. There are no silent fallbacks that could compromise OPSEC mid-analysis.

---

## Installation

### Requirements

- Linux (Debian, Ubuntu, Alpine) or WSL2
- Python 3.11+
- C build tools (`build-essential` or equivalent) required for `lxml` and `cryptography` compilation

### Docker — Recommended

The provided `Dockerfile` uses a multi-stage build. The final image strips all compilers and build tooling, and runs the process under a non-privileged `nexus` user. This is the recommended deployment method for operational use.

```bash
# Build the isolated image
docker build -t nexus-intelligence .

# Run an audit — forensic output mapped to host via volume
docker run --rm \
  -v $(pwd)/reports:/home/nexus/app/reports \
  nexus-intelligence target.com
```

To pass environment overrides at runtime:

```bash
docker run --rm \
  -e NEXUS_PROXY_URL=socks5://127.0.0.1:9050 \
  -e NEXUS_THREADS=16 \
  -v $(pwd)/reports:/home/nexus/app/reports \
  nexus-intelligence target.com
```

### Local

```bash
git clone https://github.com/genesisgzdev/nexus-intelligence.git
cd nexus-intelligence

# Install with hash verification (recommended)
pip install -r requirements.txt

# Install the CLI entry point
pip install -e .

# Run
nexus-intel target.com
```

---

## Configuration

All parameters are read from environment variables or a `.env` file in the working directory. Pydantic validates types and constraints at startup — invalid values abort immediately.

| Variable | Type | Default | Description |
|:---|:---|:---|:---|
| `NEXUS_TIMEOUT` | `int` | `15` | Maximum wait time in seconds per socket or HTTP operation. |
| `NEXUS_THREADS` | `int` | `8` | Thread pool size for concurrent module execution. |
| `NEXUS_PROXY_URL` | `str` | `None` | SOCKS5 or HTTP proxy URI. Example: `socks5://127.0.0.1:9050`. |
| `NEXUS_DOH_ENDPOINT` | `str` | `cloudflare` | DoH upstream resolver. Accepts `cloudflare` or `quad9`. |
| `NEXUS_ALLOW_EXTERNAL_CT` | `bool` | `False` | Enables `crt.sh` CT log queries. Breaks the Zero-API Mandate. |
| `NEXUS_OUTPUT_DIR` | `str` | `./reports` | Directory for JSONL forensic output files. |

---

## Output & Forensic Logging

Every analysis run writes to two simultaneous channels.

**Rich console** provides structured, real-time output for the active operator with color-coded severity levels and per-module timing.

**JSONL forensic log** writes one JSON object per line to `reports/<target>_<timestamp>.jsonl`. Each record includes an ISO-8601 timestamp, the originating module, and raw result metadata. The format is directly ingestible by Splunk, Elastic, and any SIEM that accepts JSONL. Files are append-only and never overwritten — each run produces a new timestamped file.

```jsonc
// DNSIntelligence record
{
  "timestamp": "2024-11-19T05:09:42.381Z",
  "module": "DNSIntelligence",
  "target": "target.com",
  "resolver_config": "DoH_Privacy_Active",
  "A": ["104.21.XX.XX"],
  "target_entropy": {
    "shannon": 3.452,
    "efficiency": 0.941,
    "determinism": 0.210,
    "is_synthetic": true,
    "forensic_summary": "High_Entropy_Synthetic"
  },
  "_meta": {
    "runtime_ms": 812,
    "thread_id": 3
  }
}

// StatisticalAudit record
{
  "timestamp": "2024-11-19T05:09:42.594Z",
  "module": "BenfordAuditor",
  "chi_squared": 18.204,
  "critical_threshold": 15.507,
  "is_anomalous": true,
  "sample_size": 45,
  "distribution": {
    "1": 0.12, "2": 0.08, "3": 0.40,
    "4": 0.18, "5": 0.09, "6": 0.04,
    "7": 0.03, "8": 0.03, "9": 0.03
  }
}
```

---

## Known Limitations

**Corporate SSL inspection.** If the host executing the framework sits behind a DPI/SSL-decryption firewall, `SSLForensics` will audit the certificate injected by the corporate proxy rather than the target's actual X.509 chain. There is no programmatic way to detect this condition from inside the process.

**JA3 vs. passive OS fingerprinting.** The Chrome 120 JA3/JA4 signature is accurate. However, WAFs that cross-reference the TLS fingerprint against passive TCP stack fingerprints (p0f, SYN packet analysis) may flag a discrepancy on older Linux kernels or non-standard TCP configurations. This is a fundamental limitation of software-level handshake spoofing.

**Benford's Law sample size.** The Chi-squared test requires a minimum sample size of approximately 30 data points to produce statistically meaningful results. On targets with sparse DNS records or very fast SSL responses, the auditor will report `insufficient_sample` rather than a false positive.

**Tor latency.** When `NEXUS_PROXY_URL` routes through Tor, module timeouts (`NEXUS_TIMEOUT`) may need to be increased significantly. Tor circuit establishment and hidden service routing add latency well beyond the default 15-second ceiling.

---

## Dependencies

| Package | Version | Purpose |
|:---|:---|:---|
| `curl_cffi` | >= 0.7.0 | JA3/JA4 TLS fingerprint spoofing |
| `httpx[socks]` | >= 0.27.0 | Async HTTP client + DoH resolver |
| `dnspython` | >= 2.6.1 | RFC-compliant DNS query engine |
| `cryptography` | >= 42.0.5 | X.509 chain parsing and validation |
| `beautifulsoup4` + `lxml` | >= 4.12.3 / 5.1.0 | DOM tree analysis |
| `tenacity` | >= 8.2.3 | Retry logic with exponential backoff |
| `pydantic` + `pydantic-settings` | >= 2.6.4 | Environment validation |
| `rich` | >= 13.7.1 | Structured console output |
| `stem` | >= 1.8.2 | Tor control protocol integration |

---

## License

Licensed under the **GNU AGPLv3**.

You are free to use, modify, and distribute this software under the same license. The Network Clause applies: if you run a modified version of this framework as a network-accessible service, you are required to make the complete source code of your version available to the users of that service.

---

## Legal

This framework is a forensic intelligence tool. Executing it against infrastructure you do not own or do not have explicit written authorization to test is illegal in most jurisdictions, including under the Computer Fraud and Abuse Act (CFAA) in the United States and equivalent statutes internationally.

By running `nexus-intel`, you confirm that you hold written authorization from the owner of the target infrastructure. The developer assumes no liability for misuse.

---

*Nexus Intelligence — Cryptography. Mathematics. Stealth.*
Developed by Genesis &nbsp;|&nbsp; [genzt.dev@pm.me](mailto:genzt.dev@pm.me)
