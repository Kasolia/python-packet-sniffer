"""
Python Packet Sniffer - Phase 2 (Professional Edition)
Author: Phillip Kasolia
Description:
Asynchronous packet sniffer with interface selection,
kernel-level filtering (BPF), protocol detection,
and optional persistent logging.
"""

import argparse
import time
from datetime import datetime
from scapy.all import AsyncSniffer, get_if_list
from scapy.layers.inet import IP, TCP, UDP


# --------------------------------------------------
# Phase 3 Imports (Traffic Statistics)
# --------------------------------------------------

from collections import defaultdict


# --------------------------------------------------
# Phase 3 Traffic Statistics
# --------------------------------------------------

packet_count = 0
protocol_stats = defaultdict(int)
src_ip_stats = defaultdict(int)
dst_ip_stats = defaultdict(int)

start_time = time.time()


# --------------------------------------------------
# Application Protocol Detection
# --------------------------------------------------

def detect_application_protocol(port: int) -> str:
    common_ports = {
        80: "HTTP",
        443: "HTTPS",
        53: "DNS",
        21: "FTP",
        22: "SSH",
        25: "SMTP",
        5228: "Google Services"
    }
    return common_ports.get(port, "Unknown")


# --------------------------------------------------
# BPF Filter Builder (Kernel-Level Filtering)
# --------------------------------------------------

def build_bpf_filter(args) -> str | None:
    filters = []

    if args.protocol:
        filters.append(args.protocol.lower())

    if args.port:
        filters.append(f"port {args.port}")

    return " and ".join(filters) if filters else None


# --------------------------------------------------
# Packet Processing
# --------------------------------------------------

def packet_callback(packet, args, log_file):
    global packet_count

    if not packet.haslayer(IP):
        return

    packet_count += 1

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    if packet.haslayer(TCP):
        proto = "TCP"
        protocol_stats["TCP"] += 1
        sport = packet[TCP].sport
        dport = packet[TCP].dport

    elif packet.haslayer(UDP):
        proto = "UDP"
        protocol_stats["UDP"] += 1
        sport = packet[UDP].sport
        dport = packet[UDP].dport

    else:
        protocol_stats["OTHER"] += 1
        return

    # Phase 3 IP Statistics
    src_ip_stats[packet[IP].src] += 1
    dst_ip_stats[packet[IP].dst] += 1

    # Application protocol detection
    app_proto = detect_application_protocol(sport)
    if app_proto == "Unknown":
        app_proto = detect_application_protocol(dport)

    output = (

        f"[{timestamp}] {proto} | {app_proto}\n"
        f"  {packet[IP].src}:{sport}  -->  {packet[IP].dst}:{dport}\n"
        + "-" * 60
    )

    print(output)

    if log_file:
        log_file.write(output + "\n")
        log_file.flush()


# --------------------------------------------------
# Phase 3 Statistics Display
# --------------------------------------------------

def show_statistics():
    elapsed = time.time() - start_time
    pps = packet_count / elapsed if elapsed > 0 else 0

    print("\n===== Traffic Statistics =====")

    print(f"\nTotal Packets: {packet_count}")
    print(f"Packets/sec: {pps:.2f}")

    print("\nProtocol Distribution")
    for proto, count in protocol_stats.items():
        print(f"{proto}: {count}")

    print("\nTop Source IPs")
    top_src = sorted(src_ip_stats.items(), key=lambda x: x[1], reverse=True)[:5]
    for ip, count in top_src:
        print(f"{ip} → {count}")

    print("\nTop Destination IPs")
    top_dst = sorted(dst_ip_stats.items(), key=lambda x: x[1], reverse=True)[:5]
    for ip, count in top_dst:
        print(f"{ip} → {count}")


# --------------------------------------------------
# Main Execution
# --------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Asynchronous Packet Sniffer")
    parser.add_argument("--interface", type=int, help="Interface number to sniff on")
    parser.add_argument("--protocol", choices=["tcp", "udp"], help="Filter by protocol")
    parser.add_argument("--port", type=int, help="Filter by port number")
    parser.add_argument("--log", help="Log output to file")

    args = parser.parse_args()
    interfaces = get_if_list()

    # Show interfaces if none selected
    if args.interface is None:
        print("Available Interfaces:")
        for idx, iface in enumerate(interfaces):
            print(f"{idx}: {iface}")
        return

    # Validate interface
    try:
        selected_iface = interfaces[args.interface]
    except IndexError:
        print("Invalid interface number.")
        return

    # Setup logging
    log_file = open(args.log, "a") if args.log else None

    # Build kernel-level filter
    bpf_filter = build_bpf_filter(args)

    sniffer = AsyncSniffer(
        iface=selected_iface,
        prn=lambda pkt: packet_callback(pkt, args, log_file),
        filter=bpf_filter,
        store=False
    )

    print(f"Sniffing on {selected_iface}")
    if bpf_filter:
        print(f"Using BPF filter: {bpf_filter}")
    print("Press CTRL+C to stop.\n")

    try:
        sniffer.start()

        # Idle loop (low CPU)
        while True:
            time.sleep(1)

    except KeyboardInterrupt:
        print("\nStopping sniffer...")
        sniffer.stop()

        show_statistics()

        if log_file:
            log_file.close()

        print("Sniffer stopped gracefully.")


if __name__ == "__main__":
    main()