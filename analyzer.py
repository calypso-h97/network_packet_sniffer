import os
import dpkt
from scapy.all import sniff, IP, TCP, UDP, DNS, Raw, wrpcap
from logger import logger
from converter import mac_address
from converter import ip_to_str
from datetime import datetime

# Logs folder
LOG_DIR = "logs"
os.makedirs(LOG_DIR, exist_ok=True)

# pcap-file saving path
PCAP_FILE = os.path.join(LOG_DIR, f"capture_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pcap")

def analyze_pcap(file_path):
    """pcap-file analysis"""
    try:
        with open(file_path, 'rb') as f:
            pcap = dpkt.pcap.Reader(f)

            for timestamp, buf in pcap:
                try:
                    #Ethernet frame analysis
                    eth = dpkt.ethernet.Ethernet(buf)
                    logger.debug(f"[Ethernet] Source MAC: {mac_address(eth.src)}, Destination MAC: {mac_address(eth.dst)}")

                    #IP-level check
                    if isinstance(eth.data, dpkt.ip.IP):
                        ip = eth.data
                        logger.info(f"[IP] {ip_to_str(ip.src)} -> {ip_to_str(ip.dst)}")

                        #TCP analysis
                        if isinstance(ip.data, dpkt.tcp.TCP):
                            tcp = ip.data
                            logger.info(f"[TCP] Source Port: {tcp.sport}, Destination Port: {tcp.dport}")
                            if tcp.data:
                                logger.debug(f"[TCP Payload] {tcp.data[:50]}...")

                        #UDP analysis
                        elif isinstance(ip.data, dpkt.udp.UDP):
                            udp = ip.data
                            logger.info(f"[UDP] Source port: {udp.sport}, Destination Port: {udp.dport}")
                            if udp.data:
                                logger.debug(f"[UDP Payload] {udp.data[:50]}...")

                        #DNS analysis
                        elif isinstance(ip.data, dpkt.dns.DNS):
                            dns = ip.data
                            logger.info(f"[DNS] Query: {dns.qd[0].name}")
                except Exception as e:
                    logger.error(f"Error packege analysis: {e}")
    except FileNotFoundError:
        logger.critical(f"File {file_path} not found")
    except Exception as e:
        logger(f"[ERROR] : {e}")

def analyze_http(packet):
    """HTTP-requests analysis"""
    if packet.haslayer(Raw):
        payload = packet[Raw].load.decode(errors="ignore")
        if payload.startswith("GET") or payload.startswith("POST"):
            logger.info("[HTTP] Http-request is found")
            logger.debug(f"Payload: {payload}")

def analyze_dns(packet):
    """DNS-requests analysis"""
    if packet.haslayer(DNS):
        dns_layer = packet[DNS]
        if dns_layer.qr ==  0: # case it is an DNS request
            logger.info(f"[DNS] Request: {dns_layer.qd.qname.decode()}")
        else: # case it is an DNS response
            for i in range(dns_layer.ancount):
                try:
                    answer = dns_layer.an[i]
                    logger.info(f"[DNS] Response: {dns_layer.rrname.decode()} -> {answer.rdata}")
                except Exception as e:
                    logger.debug(f"[DNS] Error handling response: {e}")

def extract_sensitive_data(packet):
    """Search for unencrypted data"""
    if packet.haslayer(Raw):
        payload = packet[Raw].load.decode(errors="ignore")
        if "password" in payload or "passwd" in payload or "pass" in payload:
            logger.warning(f"[SENSITIVE] Potentially sensitive data found | password: {payload}")
        if "login" in payload :
            logger.warning(f"[SENSITIVE] Potentially sensitive data found | login: {payload}")

def packet_callback(packet):
    """Packets analysis"""
    try:
        # General packet info
        src_ip = packet[IP].src if packet.haslayer(IP) else "Unknown"
        dst_ip = packet[IP].dst if packet.haslayer(IP) else "Unknown"
        protocol = "TCP" if packet.haslayer(TCP) else "UDP" if packet.haslayer(UDP) else "Other one"

        logger.info(f"[+] Packet: {src_ip} -> {dst_ip} [{protocol}]")

        # http traffic analysis | DNS traffic | sensitive data
        if packet.haslayer(TCP) or packet.haslayer(IP) or packet.haslayer(DNS):
            analyze_http(packet)
            analyze_dns(packet)
            extract_sensitive_data(packet)

        # Packet saving to pcap-file
        wrpcap(PCAP_FILE, packet, append = True)
    except Exception as e:
        logger.error(f"Error in packet analysis: {e}")