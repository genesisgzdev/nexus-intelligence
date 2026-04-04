"""
Network utilities for domain and IP validation.
"""
import socket
import re

def is_valid_domain(domain: str) -> bool:
    """Validates domain format using regex."""
    pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}$'
    return bool(re.match(pattern, domain))

def resolve_ip(domain: str) -> str:
    """Resolves a domain to an IP address."""
    try:
        return socket.gethostbyname(domain)
    except socket.gaierror:
        return ""
