import socket
import ipaddress
from typing import Optional

class SecurityValidator:
    """
    Industrial-grade security validation for network targets.
    Prevents SSRF and local subnet scanning.
    """
    PRIVATE_SUBNETS = [
        ipaddress.ip_network('127.0.0.0/8'),
        ipaddress.ip_network('10.0.0.0/8'),
        ipaddress.ip_network('172.16.0.0/12'),
        ipaddress.ip_network('192.168.0.0/16'),
        ipaddress.ip_network('169.254.169.254/32'), # Cloud Metadata
        ipaddress.ip_network('::1/128'),
        ipaddress.ip_network('fe80::/10'),
    ]

    @staticmethod
    def is_safe_target(target: str) -> bool:
        """
        Validates that the target is not a private or restricted IP address.
        """
        try:
            # Resolve target to IP
            ip_addr = socket.gethostbyname(target)
            ip = ipaddress.ip_address(ip_addr)
            
            for subnet in SecurityValidator.PRIVATE_SUBNETS:
                if ip in subnet:
                    return False
            return True
        except Exception:
            # If resolution fails, we assume it's unsafe or invalid
            return False
