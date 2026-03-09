# Python Packet Sniffer – Phase 2

## Overview

Phase 2 enhances the original packet sniffer by introducing a more efficient and scalable architecture. The sniffer now uses asynchronous packet capture, kernel-level filtering, and improved logging to provide a more reliable and professional monitoring tool.

The goal of this phase was to transform the Phase 1 prototype into a structured and efficient packet analysis utility suitable for security research and network troubleshooting.

---

## Key Improvements from Phase 1

Phase 2 focuses on performance, stability, and usability.

### Asynchronous Packet Capture

The sniffer now uses Scapy's `AsyncSniffer` instead of the blocking `sniff()` function.  
This allows the program to run packet capture in a background thread and respond instantly to shutdown signals.

### Kernel-Level Packet Filtering

Protocol and port filters are now applied using **Berkeley Packet Filter (BPF)** syntax at the capture level.

Example filter:

```bash
tcp and port 443
```

This significantly reduces unnecessary packet processing in user space.

### Persistent Logging

Instead of opening and closing a file for each captured packet, the program now keeps a persistent file handle during execution and writes log entries efficiently.

### Clean Shutdown Handling

The application now properly handles `CTRL+C`, ensuring:

- Packet capture stops gracefully
- File handles close correctly
- The program exits without freezing

### Reduced CPU Usage

An idle loop with controlled sleep intervals prevents the sniffer from consuming unnecessary CPU resources while running.

---

## Features

- Live packet capture
- TCP and UDP traffic detection
- Interface selection via CLI
- Protocol filtering (`tcp`, `udp`)
- Port-based filtering
- Application protocol identification (common ports)
- Asynchronous packet capture
- Optional traffic logging
- Graceful shutdown support

---

## Project Structure

```
python-packet-sniffer/
│
├── sniffer.py
├── README.md
├── README_phase1.md
└── requirements.txt
```

---

## Requirements

- Python 3.10 or higher
- Scapy
- Npcap (Windows)

Install Scapy:

```bash
pip install scapy
```

Install Npcap (required for packet capture on Windows):

https://npcap.com/

When installing, enable **WinPcap API-compatible mode**.

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

Captured traffic will be written to **traffic.log**.

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

This project currently focuses on packet capture and basic inspection. The following features are not yet implemented:

- IPv6 support
- Flow/session tracking
- Packet rate monitoring
- Deep packet inspection
- PCAP file export
- Intrusion detection capabilities

These features are planned for future phases.

---

## Phase 3 Roadmap

The next phase of the project will focus on expanding the sniffer into a lightweight monitoring tool with advanced analysis capabilities.

Planned improvements include:

- Network flow tracking
- Packet rate monitoring
- Basic anomaly detection
- JSON-based structured logging
- Traffic statistics
- Modular architecture

---

## Disclaimer

This tool is intended for educational purposes and authorized network monitoring only.

Do not capture or inspect network traffic on systems or networks without proper authorization.

---

## Author

**Phillip Kasolia**  
Cybersecurity Analyst