Got it ✅ — here’s a **single Markdown file** you can drop into your repo so readers see everything (rules, commands, input/output, reports) in one place.
You could name it **`EXAMPLES.md`** or even append this to your `README.md`.

---

## 🔹 `EXAMPLES.md`


# 🔍 Example Input and Output for Python SIEM-like Firewall

This document shows **how the firewall/IDS tool works** with sample rules, commands, and outputs.  
It’s meant as a quick reference for users who want to see what to expect.

---

## 📥 Example Input

### 1. Rules File (`rules.json`)

Below is a sample rules file. It defines **alerts and logging** for SSH, DNS, and HTTP traffic:

```json
[
  {
    "name": "SSH Alert",
    "match": { "protocol": "tcp", "dst_port": 22 },
    "action": "alert"
  },
  {
    "name": "DNS Logging",
    "match": { "protocol": "udp", "dst_port": 53 },
    "action": "log"
  },
  {
    "name": "HTTP Alert",
    "match": { "protocol": "tcp", "dst_port": 80 },
    "action": "alert"
  }
]
````

### 2. Command to Start Monitoring

Run the tool with the rules file and log output:

```bash
python firewall.py start --rules rules.json --log traffic.log --iface Wi-Fi --threshold 50
```

* `--rules rules.json` → Use custom rules
* `--log traffic.log` → Save events to a log file
* `--iface Wi-Fi` → Capture packets on the Wi-Fi interface
* `--threshold 50` → Detect anomalies if an IP sends >50 packets/min

---

## 📤 Example Output

### Console Output

What you’d see while running:

```bash
[INFO] Starting capture on Wi-Fi
[ALERT] SSH Alert - TCP 192.168.1.10:55678 > 192.168.1.20:22
[LOG]   DNS Logging - UDP 192.168.1.15:5353 > 8.8.8.8:53
[ALERT] HTTP Alert - TCP 192.168.1.30:44567 > 93.184.216.34:80
[ANOMALY] High traffic from 192.168.1.25: 55 packets/min
```

### Log File (`traffic.log`)

Saved entries will look like this:

```
SSH Alert - TCP 192.168.1.10:55678 > 192.168.1.20:22
DNS Logging - UDP 192.168.1.15:5353 > 8.8.8.8:53
HTTP Alert - TCP 192.168.1.30:44567 > 93.184.216.34:80
[ANOMALY] High traffic from 192.168.1.25: 55 packets/min
```

---

## 📊 Example Report

You can generate a summary report from the log file:

```bash
python firewall.py report --log traffic.log
```

Example report output:

```
[INFO] Generating report from traffic.log
Total log entries: 4
Top talkers:
192.168.1.25: 1 events
192.168.1.30: 1 events
192.168.1.15: 1 events
192.168.1.10: 1 events
```

---

## What's finally done :

* Define traffic rules in `rules.json`
* Start monitoring with `firewall.py start ...`
* Logs are written to `traffic.log`
* Reports can be generated anytime with `firewall.py report ...`

This gives you a **mini-SIEM-like view** of your network traffic in real-time.

```
