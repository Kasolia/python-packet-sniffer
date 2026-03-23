![Python](https://img.shields.io/badge/python-3.10+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Status](https://img.shields.io/badge/status-active-success.svg)

# Python Packet Sniffer – Phase 5 (Network Monitoring & IDS)

## Overview

This project is a Python-based **network packet sniffer and monitoring tool** built using the Scapy library.  
It captures live network traffic, analyzes packets in real time, and performs basic **intrusion detection** based on network behavior.

The project was developed in multiple phases to demonstrate progressive improvements in architecture, monitoring capabilities, and security analysis.

Phase 5 expands the tool into a **lightweight Network Intrusion Detection System (NIDS)** capable of identifying suspicious traffic patterns such as port scans, brute-force attempts, and abnormal traffic spikes.

This project demonstrates practical knowledge of:

- Network packet capture
- Protocol inspection
- Kernel-level packet filtering (BPF)
- Asynchronous packet processing
- Traffic analytics
- Intrusion detection techniques
- Structured security event logging

---

## Phase 4 Improvements

Phase 4 introduces **security detection capabilities** that transform the packet sniffer into a basic intrusion detection system.

### Port Scan Detection

The tool tracks destination ports accessed by each source IP address.

If a host attempts connections to **multiple different ports in a short period**, the tool raises an alert.

Example alert:

```
[SECURITY ALERT] Possible Port Scan Detected

Source IP: 192.168.1.5
Ports scanned: [22, 80, 443, 8080]

```

---

### Brute Force Detection

Repeated connection attempts to the same service can indicate a brute-force attack.

The sniffer monitors repeated attempts to the same port from a single IP address.

Example alert:

```
[ALERT] Possible Brute Force Attempt

Source IP: 192.168.1.5
Target Port: 22
```

---

### Traffic Spike Detection

In addition to intrusion detection, the tool provides real-time traffic analytics.

Tracked metrics include:

- Total packets captured
- Packets per second
- Protocol distribution
- Top source IP addresses
- Top destination IP addresses

Example alert:

```
[ALERT] Unusual Traffic Spike Detected
```

---

# Phase 5 Improvements

Phase 5 adds **real-time monitoring and structured security logging**.

### Real-Time Traffic Rate Monitoring

The sniffer now displays **live packet rates while running**.

Example:

```
[Traffic Rate] 12 packets/sec
```
This allows users to detect sudden traffic increases in real time.

---

### Structured JSON Security Event Logging

Security alerts are now written to a structured log file:

alerts.json

Example event:

```
{
  "timestamp": "2026-03-16 14:10:22",
  "event": "Port Scan Detected",
  "details": {
    "source_ip": "192.168.1.5",
    "ports": [22, 80, 443]
  }
}

```
Structured logging makes it possible to integrate this tool with SIEM systems such as:

- Splunk
- Elastic Stack
- Graylog

---

## Traffic Analytics

In addition to intrusion detection, the tool provides real-time traffic analytics.

Tracked metrics include:

- Total packets captured
- Packets per second
- Protocol distribution
- Top source IP addresses
- Top destination IP addresses

When the sniffer stops (`CTRL+C`), a summary report is displayed.

Example:

```
===== Traffic Statistics =====

Total Packets: 387
Packets/sec: 19.7

Protocol Distribution
TCP: 240
UDP: 120
OTHER: 27

Top Source IPs
192.168.1.4 → 110
192.168.1.7 → 75

Top Destination IPs
142.250.190.78 → 95
104.18.39.21 → 60

```

---

## Features

- Live packet capture using Scapy
- Asynchronous packet sniffing (`AsyncSniffer`)
- Network interface selection
- Kernel-level packet filtering using BPF
- Protocol filtering (TCP / UDP)
- Port-based filtering
- Application protocol detection (common ports)
- Persistent logging to file
- Graceful shutdown handling
- Traffic statistics and monitoring
- Protocol distribution analysis
- Top source and destination host tracking
- Port scan detection
- Brute force attempt detection
- Traffic spike detection
- JSON security event logging

---

## Project Structure

```
python-packet-sniffer/
│
├── core/
│ ├── capture.py # Packet processing & callback logic
│ └── filters.py # BPF filter builder (kernel-level)
│
├── analytics/
│ ├── stats.py # Packet counters & traffic statistics
│ └── monitor.py # Real-time traffic rate monitoring
│
├── detection/
│ └── threats.py # Intrusion detection logic (port scan, brute force, traffic spike)
│
├── utils/
│ └── logger.py # JSON security logging
│
├── sniffer.py # Main executable
├── requirements.txt # Dependencies
├── README.md
└── screenshots/ # Optional: add screenshots of sniffer in action
└── sniffer-output.png
```

---

## Requirements

- Python 3.10 or higher
- Scapy
- Npcap (Windows)

### Install Scapy:

```bash
pip install scapy
```

### Install Npcap

Npcap is required for packet capture on Windows.

Download from:

https://npcap.com/

When installing, enable:
```
 WinPcap API-compatible mode.

```

---

## Usage

### List Available Network Interfaces

```bash
python sniffer.py
```

Example output:

```
Available Interfaces:
0: \Device\NPF_{...}
1: \Device\NPF_{...}
2: \Device\NPF_{...}
3: \Device\NPF_{...}
4: \Device\NPF_Loopback
```

---

### Start Packet Capture

```bash
python sniffer.py --interface 3
```

---

### Filter by Protocol

```bash
python sniffer.py --interface 3 --protocol tcp
```

or

```bash
python sniffer.py --interface 3 --protocol udp
```

---

### Filter by Port

```bash
python sniffer.py --interface 3 --port 443
```

---

### Combine Filters

```bash
python sniffer.py --interface 3 --protocol tcp --port 443
```

---

### Enable Logging

```bash
python sniffer.py --interface 3 --log traffic.log
```

Captured traffic will be written to: 

```
traffic.log.
```

---

## Example Output

### Live Packet Capture

![Packet Sniffer Output](screenshots/sniffer-output.png)

---

## Protocol Detection

The sniffer performs basic application protocol identification based on commonly used ports.

| Port | Protocol |
|-----|----------|
| 80 | HTTP |
| 443 | HTTPS |
| 53 | DNS |
| 21 | FTP |
| 22 | SSH |
| 25 | SMTP |
| 5228 | Google Services |

Unknown ports are labeled as **Unknown**.

---

## Current Limitations

This project currently focuses on packet capture, analytics, and basic intrusion detection.

Future improvements may include:

-IPv6 packet support
-Network flow/session tracking
-Deep packet inspection
-PCAP export functionality
-Advanced anomaly detection
-Real-time monitoring dashboard

These features are planned for future phases.

---

## Development Phases

### Phase 1 - Basic Packet Sniffer

-Synchronous packet capture
-Basic packet inspection

### Phase 2 - Architecture Improvements

- Asynchronous packet capture
- Kernel-level filtering
- CLI argument support
- Persistent logging

### Phase 3 - Traffic Analytics
Traffic analytics and monitoring:

- Packet rate monitoring
- Protocol distribution statistics
- Top network hosts analysis

### Phase 4 – Intrusion Detection

- Port scan detection
- Brute force detection
- Traffic spike detection
- Security alert system

### Phase 5 – Monitoring & Security Logging

- Real-time traffic rate monitoring
- JSON security event logging
- Structured alert generation

---

## Disclaimer

This tool is intended for educational purposes and authorized network monitoring only.

Do not capture or inspect network traffic on systems or networks without proper authorization.

---

## Author

**Phillip Kasolia**  
Cybersecurity Analyst