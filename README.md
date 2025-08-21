# Python SIEM-like Firewall CLI

A lightweight, cross-platform **firewall/IDS (Intrusion Detection System)** built in Python.  
This tool can **monitor network traffic, apply user-defined rules, detect anomalies**, and log suspicious activity.  
Designed as a **learning project** to understand networking, packet capture, and SIEM-like concepts.

---

## ✨ Features

- 📡 **Packet capture** (using [Scapy](https://scapy.net/))
- 📜 **Rules engine** (define alerts/logging via `rules.json`)
- 🚨 **Anomaly detection** (detects high packet rates per IP)
- 📂 **Logging & reporting** (review suspicious activity later)
- 💻 **Cross-platform CLI** (Windows, Linux, macOS)

---

## 📦 Installation

### Requirements
- Python **3.9+**
- [Scapy](https://scapy.net/)  
- (Windows only) [Npcap](https://nmap.org/npcap/) must be installed

### Install dependencies
```bash
pip install -r requirements.txt
