"""
Python Packet Sniffer - Phase 5 (Network Monitoring & IDS)
Author: Phillip Kasolia
Description:
A modular, asynchronous packet sniffer with traffic analytics, 
intrusion detection, and JSON-based security logging.
"""

import argparse
import time
import threading
from scapy.all import AsyncSniffer, get_if_list

from core.capture import packet_callback
from core.filters import build_bpf_filter
from analytics.monitor import monitor_traffic_rate
from analytics.stats import show_statistics

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
        prn=lambda pkt: packet_callback(pkt, log_file),
        filter=bpf_filter,
        store=False
    )

    print(f"Sniffing on {selected_iface}")
    if bpf_filter:
        print(f"Using BPF filter: {bpf_filter}")
    print("Press CTRL+C to stop.\n")

    try:
        sniffer.start()
        # Start traffic monitoring thread
        monitor_thread = threading.Thread(target=monitor_traffic_rate, daemon=True)
        monitor_thread.start()

        # Idle loop (low CPU)
        while True:
            time.sleep(1)

    except KeyboardInterrupt:
        print("\nStopping sniffer...")
        if sniffer.running:
            sniffer.stop()

        show_statistics()

        if log_file:
            log_file.close()

        print("Sniffer stopped gracefully.")


if __name__ == "__main__":
    main()