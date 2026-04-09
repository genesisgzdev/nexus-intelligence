import socket
import ipaddress

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
    def is_safe_target(target: str) -> bool:
        try:
            ip_addr = socket.gethostbyname(target)
            ip = ipaddress.ip_address(ip_addr)
            for subnet in SecurityValidator.PRIVATE_SUBNETS:
                if ip in subnet: return False
            return True
        except: return False
