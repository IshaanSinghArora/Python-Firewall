import socket
import time
import threading
import datetime
import logging
from netaddr import IPNetwork

# Custom imports
from imports.protocols import ethernet_frame, ipv4_packet, icmp_packet, udp_packet, tcp_packet
from imports.helper import get_interfaces, compare_rules, PROTOCOLS
from imports.validator import validate_with_route_table

logging.basicConfig(level=logging.INFO, filename="firewall.log", format="%(asctime)s - %(levelname)s - %(message)s")

SEND_SOCKET = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
SEND_SOCKET.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
SEND_SOCKET.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

def send_packet(payload, dst_ip):
    """Send a packet to the specified destination IP."""
    try:
        SEND_SOCKET.sendto(payload, (dst_ip, 0))
    except (PermissionError, OSError) as error:
        logging.error(f"Failed to send packet: {error}")

def bind_socket(interface):
    """Bind a socket to a specific network interface and listen for incoming packets."""
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0800))
    conn.bind((interface[0], 0))
    try:
        while True:
            raw_data, _ = conn.recvfrom(65536)
            dest_mac, src_mac, eth_protocol, eth_data = ethernet_frame(raw_data)
            src_port, dst_port = 0, 0
            if eth_protocol == 8:
                s_addr, d_addr, protocol, ip_header = ipv4_packet(eth_data[14:34])
                logging.info(f"[{datetime.datetime.now()}] {interface[0]} ({d_addr}) > {PROTOCOLS.get(protocol, 'Unknown Protocol')}")
                if protocol == 6:
                    src_port, dst_port = tcp_packet(eth_data[34:54])
                elif protocol == 17:
                    src_port, dst_port, size, data = udp_packet(eth_data[34:42])
                if validate_with_route_table(s_addr, d_addr, src_port, dst_port):
                    send_packet(eth_data[14:], d_addr)
                else:
                    logging.error(f"<FAILED ROUTE> [{datetime.datetime.now()}] {interface[0]} ({s_addr}, {d_addr}) > {PROTOCOLS.get(protocol, 'Unknown Protocol')}")
    except KeyboardInterrupt:
        logging.info("\n[END] Firewall stopped")

if __name__ == "__main__":
    interfaces = get_interfaces()
    if len(interfaces.items()) < 4:
        logging.error("Not enough interfaces")
        exit()

    for key, val in interfaces.items():
        thread = threading.Thread(target=bind_socket, args=([key, val],), name=key)
        thread.setDaemon(True)
        thread.start()

    logging.info("Firewall is running")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logging.info("\nExiting firewall")
        exit(1)
