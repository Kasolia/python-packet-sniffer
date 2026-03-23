from scapy.layers.inet import IP, TCP, UDP
from datetime import datetime
from analytics import stats
from detection.threats import detect_threats
from utils.protocols import detect_application_protocol

# --------------------------------------------------
# Packet Processing
# --------------------------------------------------

def packet_callback(packet, log_file):
    if not packet.haslayer(IP):
        return

    # Increment global stats
    stats.packet_count += 1
    stats.packet_rate_counter += 1

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
        proto = "OTHER"
        return

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst

    stats.update_stats(proto, src_ip, dst_ip)


    # Application protocol detection
    app_proto = detect_application_protocol(sport)
    if app_proto == "Unknown":
        app_proto = detect_application_protocol(dport)

    # Phase 4 threat detection
    detect_threats(packet, sport, dport)

    output = f"[{timestamp}] {proto} | {app_proto}\n  {src_ip}:{sport}  -->  {dst_ip}:{dport}\n" + "-"*60
    print(output)

    if log_file:
        log_file.write(output + "\n")
        log_file.flush()