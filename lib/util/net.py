from ipaddress import ip_network, ip_address

__all__ = ['is_ip', 'is_network']


def is_ip(ip_str: str) -> bool:
    """
    Checks if string is IP address
    """
    try:
        ip_address(ip_str)
        return True
    except ValueError:
        return False


def is_network(net_str: str) -> bool:
    """
    Checks if string is network address
    """
    try:
        ip_network(net_str)
        return True
    except ValueError:
        return False
