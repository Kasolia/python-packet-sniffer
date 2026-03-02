# sniffer.py
"""
Python Packet Sniffer - Phase 2
Author: Phillip Kasolia
Description:
Enhanced packet sniffer with interface selection, filtering,
basic protocol detection, and optional logging.
"""

import argparse
from scapy.all import AsyncSniffer, get_if_list
from scapy.layers.inet import IP, TCP, UDP
from datetime import datetime


def detect_application_protocol(port):
    common_ports = {
        80: "HTTP",
        443: "HTTPS",
        53: "DNS",
        21: "FTP",
        22: "SSH",
        25: "SMTP"
    }
    return common_ports.get(port, "Unknown")


def packet_callback(packet, args):
    if not packet.haslayer(IP):
        return

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    if packet.haslayer(TCP):
        proto = "TCP"
        sport = packet[TCP].sport
        dport = packet[TCP].dport
    elif packet.haslayer(UDP):
        proto = "UDP"
        sport = packet[UDP].sport
        dport = packet[UDP].dport
    else:
        return

    # Protocol filter
    if args.protocol and proto.lower() != args.protocol.lower():
        return

    # Port filter
    if args.port and args.port not in (sport, dport):
        return

    app_proto = detect_application_protocol(sport) \
        if detect_application_protocol(sport) != "Unknown" \
        else detect_application_protocol(dport)

    output = (
        f"[{timestamp}] {proto} | {app_proto}\n"
        f"  {packet[IP].src}:{sport}  -->  {packet[IP].dst}:{dport}\n"
        + "-" * 60
    )

    print(output)

    if args.log:
        with open(args.log, "a") as f:
            f.write(output + "\n")



def main():
    parser = argparse.ArgumentParser(description="Enhanced Packet Sniffer")
    parser.add_argument("--interface", type=int, help="Interface number to sniff on")
    parser.add_argument("--protocol", help="Filter by protocol (tcp/udp)")
    parser.add_argument("--port", type=int, help="Filter by port number")
    parser.add_argument("--log", help="Log output to file")

    args = parser.parse_args()
    interfaces = get_if_list()

    if args.interface is None:
        print("Available Interfaces:")
        for idx, iface in enumerate(interfaces):
            print(f"{idx}: {iface}")
        return

    try:
        selected_iface = interfaces[args.interface]
    except IndexError:
        print("Invalid interface number.")
        return

    print(f"Sniffing on {selected_iface}... Press CTRL+C to stop.\n")

    sniffer = AsyncSniffer(
        iface=selected_iface,
        prn=lambda packet: packet_callback(packet, args),
        store=False
    )

    sniffer.start()

    try:
        while True:
            pass
    except KeyboardInterrupt:
        sniffer.stop()
        print("\nSniffer stopped gracefully.")

if __name__ == "__main__":
    main()