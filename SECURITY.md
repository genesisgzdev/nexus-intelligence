# Security Policy and Threat Model

## Threat Model
Nexus Intelligence is an active reconnaissance tool. It is designed to be resilient against defensive countermeasures and to prevent its own infrastructure from being used as an attack pivot.

### Defensive Mitigations
- **SSRF Prevention**: The \SecurityValidator\ blocks queries to loopback (127.0.0.1), private CIDR blocks (RFC 1918), and Cloud Provider metadata endpoints (169.254.169.254).
- **Handshake Safety**: TLS handshakes are executed in isolated async tasks with strict timeouts to prevent socket exhaustion (Tarpit attacks).
- **Non-Privileged Execution**: The Docker runtime enforces a \USER nexususer\ context, preventing local privilege escalation within the container.

## Vulnerability Reporting
Please report logic flaws, SSRF bypasses, or parser vulnerabilities via GitHub Issues. 
