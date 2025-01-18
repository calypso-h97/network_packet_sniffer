import socket

def mac_address(address):
    """Converting MAC-address to readable format"""
    return ':'.join(f'{b:02x}' for b in address)

def ip_to_str(ip):
    """Converting IP-address to string"""
    return socket.inet_ntoa(ip)