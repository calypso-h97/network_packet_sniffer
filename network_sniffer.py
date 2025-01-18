from logger import logger
from scapy.all import sniff, IP, TCP, UDP, DNS, Raw, wrpcap
from analyzer import analyze_pcap, packet_callback, PCAP_FILE

if __name__ == "__main__":
    logger.info("Choose working mode")
    print("1. Realtime traffic sniffing")
    print("2. Analysis of saved pcap-file")
    choice = input("Please enter 1 or 2 : Enter: ")

    if choice == "1":
        logger.info("SNIFFER START...use Ctrl+C for stop")
        try:
            sniff(iface="en0", filter="tcp or udp", prn=packet_callback, store=False)
        except KeyboardInterrupt:
            logger.info("Sniffer is stopped")
            logger.info(f"logs saved in {PCAP_FILE}")
    elif choice == "2":
        file_path = input("Fill the path to pcap-file: ")
        analyze_pcap(file_path)
    else:
        logger.warning("Uncorrect choice. SHUTDOWN")

        