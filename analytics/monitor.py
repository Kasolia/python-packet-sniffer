import time
from analytics import stats

def monitor_traffic_rate():
    while True:
        time.sleep(1)
        rate = stats.packet_rate_counter
        stats.packet_rate_counter = 0  # Reset for next interval
        if rate > 0:
            print(f"[Traffic Rate] {rate} packets/sec")