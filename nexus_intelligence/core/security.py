import socket
import ipaddress
from typing import List

class SecurityValidator:
    """
    Network target validation logic.
    Restricts scanning to public infrastructure by blocking private subnets.
    """
    PRIVATE_SUBNETS = [
        ipaddress.ip_network('127.0.0.0/8'),
        ipaddress.ip_network('10.0.0.0/8'),
        ipaddress.ip_network('172.16.0.0/12'),
        ipaddress.ip_network('192.168.0.0/16'),
        ipaddress.ip_network('169.254.169.254/32'),
        ipaddress.ip_network('::1/128'),
        ipaddress.ip_network('fe80::/10'),
    ]

    @staticmethod
    def resolve_public_addresses(target: str) -> List[str]:
        addresses = {
            ipaddress.ip_address(info[4][0])
            for info in socket.getaddrinfo(target, None, type=socket.SOCK_STREAM)
        }
        if not addresses:
            raise ValueError("target has no address")
        for ip in addresses:
            if (
                any(ip in subnet for subnet in SecurityValidator.PRIVATE_SUBNETS)
                or ip.is_private
                or ip.is_loopback
                or ip.is_link_local
                or ip.is_multicast
                or ip.is_reserved
                or ip.is_unspecified
            ):
                raise ValueError("target resolves to a restricted address")
        return sorted(str(ip) for ip in addresses)

    @staticmethod
    def is_safe_target(target: str) -> bool:
        try:
            SecurityValidator.resolve_public_addresses(target)
            return True
        except (OSError, ValueError):
            return False
