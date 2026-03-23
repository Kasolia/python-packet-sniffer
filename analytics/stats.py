import time
from collections import defaultdict

# -------------------------------
# Global Traffic Counters
# -------------------------------
packet_count = 0
packet_rate_counter = 0

protocol_stats = defaultdict(int)
src_ip_stats = defaultdict(int)
dst_ip_stats = defaultdict(int)

start_time = time.time()

# -------------------------------
# Update stats for each packet
# -------------------------------
def update_stats(proto, src_ip, dst_ip):
    global packet_count, packet_rate_counter
    packet_count += 1
    packet_rate_counter += 1
    protocol_stats[proto] += 1
    src_ip_stats[src_ip] += 1
    dst_ip_stats[dst_ip] += 1

# -------------------------------
# Display statistics
# -------------------------------
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
    for ip, count in sorted(src_ip_stats.items(), key=lambda x: x[1], reverse=True)[:5]:
        print(f"{ip} → {count}")

    print("\nTop Destination IPs")
    for ip, count in sorted(dst_ip_stats.items(), key=lambda x: x[1], reverse=True)[:5]:
        print(f"{ip} → {count}")