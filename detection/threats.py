import time
from collections import defaultdict, deque
from scapy.layers.inet import IP
from utils.logger import log_security_event

# --------------------------------------------------
# Phase 4 Security Detection Structures
# --------------------------------------------------

# Track destination ports accessed by source IP in a rolling window
port_scan_tracker = defaultdict(lambda: deque(maxlen=20))
# Track connection attempts in a rolling time window
connection_attempts = defaultdict(lambda: deque(maxlen=50))
# Track global packet timestamps for traffic spikes
packet_timestamps = deque()

# Detection thresholds
PORT_SCAN_THRESHOLD = 10      # Number of unique ports in the window
BRUTE_FORCE_THRESHOLD = 20    # Attempts in the window
TIME_WINDOW = 10              # Seconds
TRAFFIC_SPIKE_COUNT = 100     # Packets in 5 seconds

# --------------------------------------------------
# Phase 4 Threat Detection
# --------------------------------------------------

def detect_threats(packet, sport, dport):
    src_ip = packet[IP].src
    current_time = time.time()

    # ---- Port Scan Detection ----
    ports_deque = port_scan_tracker[src_ip]
    if dport not in ports_deque:
        ports_deque.append(dport)

    if len(set(ports_deque)) >= PORT_SCAN_THRESHOLD:
        log_security_event(
            "Port Scan Detected",
            {"source_ip": src_ip, "ports": list(set(ports_deque))}
        )
        print(f"\n[SECURITY ALERT] Possible Port Scan Detected\nSource IP: {src_ip}\nPorts scanned: {sorted(set(ports_deque))}\n")

    # ---- Brute Force Detection ----
    key = f"{src_ip}:{dport}"
    attempts_deque = connection_attempts[key]
    attempts_deque.append(current_time)

    # Remove attempts older than TIME_WINDOW seconds
    while attempts_deque and current_time - attempts_deque[0] > TIME_WINDOW:
        attempts_deque.popleft()

    if len(attempts_deque) >= BRUTE_FORCE_THRESHOLD:
        log_security_event(
            "Brute Force Attempt",
            {"source_ip": src_ip, "target_port": dport, "attempts": len(attempts_deque)}
        )
        print(f"\n[ALERT] Possible Brute Force Attempt\nSource IP: {src_ip}\nTarget Port: {dport}\n")

    # ---- Traffic Spike Detection ----
    packet_timestamps.append(current_time)
    # Remove packets older than 5 seconds
    while packet_timestamps and current_time - packet_timestamps[0] > 5:
        packet_timestamps.popleft()

    if len(packet_timestamps) > TRAFFIC_SPIKE_COUNT:
        log_security_event(
            "Traffic Spike",
            {"packet_rate_window": len(packet_timestamps), "window_seconds": 5}
        )
        print("\n[ALERT] Unusual Traffic Spike Detected\n")