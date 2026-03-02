# Python Packet Sniffer

## Overview

Phase 1 of the project: a Python-based packet sniffer that captures live TCP/UDP network traffic, logs source/destination IPs, ports, and timestamps.  

This tool is intended for **educational purposes** and **authorized security testing only**.

---

## Features

- Capture live packets on Windows using Scapy and Npcap

- TCP & UDP detection

- Logs source/destination IPs and ports

- Timestamps for each packet

- Easy to extend for protocol detection and filtering

---

## Installation

1. Install **Python 3** (if not already installed).  

2. Install **Npcap** (Windows packet capture driver): https://npcap.com  

3. Install **Scapy**:



```bash

python -m pip install scapy

```
---

##Usage

Run the sniffer:

```bash

python sniffer.py

```

Open a browser or run ping 8.8.8.8 to generate packets

Press CTRL+C to stop the sniffer

---

##Ethical Disclaimer

- This tool is intended strictly for:

- Educational purposes

- Personal lab environments

- Authorized penetration testing

- Unauthorized scanning of networks or systems is illegal and unethical.

---

##Author

Phillip Kasolia

Cybersecurity | Python | Network Security

