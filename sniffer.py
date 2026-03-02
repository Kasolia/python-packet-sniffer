# sniffer.py
"""
Python Packet Sniffer - Phase 1
Author: Phillip Kasolia
Purpose: Capture live TCP/UDP packets on Windows and log source/destination IPs, ports, and timestamps.
"""

from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP
from datetime import datetime

def packet_callback(packet):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Only process TCP or UDP packets
    if packet.haslayer(TCP):
        proto = "TCP"
        sport = packet[TCP].sport
        dport = packet[TCP].dport
    elif packet.haslayer(UDP):
        proto = "UDP"
        sport = packet[UDP].sport
        dport = packet[UDP].dport
    else:
        return  # skip non-TCP/UDP packets

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst

    print(f"[{timestamp}] Packet Captured")
    print(f"Source IP: {src_ip}")
    print(f"Destination IP: {dst_ip}")
    print(f"Protocol: {proto}")
    print(f"Source Port: {sport}")
    print(f"Destination Port: {dport}")
    print("-" * 50)

def main():
    print("Starting packet sniffer... Press CTRL+C to stop.")
    # sniff on all interfaces, store=0 to avoid memory usage, prn=callback
    sniff(prn=packet_callback, store=0)

if __name__ == "__main__":
    main()