# ------------------------------
# Imports
# ------------------------------
import argparse        # For creating the CLI (command-line interface)
import json            # For reading/writing the rules.json file
import time            # For timing (used in anomaly detection resets)
from collections import defaultdict   # For counting packets per IP easily
from scapy.all import sniff, IP, TCP, UDP   # Scapy for packet capture and protocol parsing


# ------------------------------
# Global variables for anomaly detection
# ------------------------------
traffic_stats = defaultdict(int)   # Stores packet counts per source IP
last_reset = time.time()           # Keeps track of when we last cleared stats


# ------------------------------
# Function: load_rules
# Purpose:  Load rules.json from disk
# ------------------------------
def load_rules(path):
    try:
        # Open the JSON rules file in read mode
        with open(path, "r") as f:
            return json.load(f)  # Parse JSON into Python list of dicts
    except FileNotFoundError:
        # If rules file is missing, show error and return empty rules list
        print(f"[ERROR] Rules file {path} not found.")
        return []


# ------------------------------
# Function: apply_rules
# Purpose:  Check if a packet matches any rules and take action (alert/log)
# ------------------------------
def apply_rules(packet, rules, logfile):
    for rule in rules:   # Loop over every rule in rules.json
        match = rule.get("match", {})   # Extract "match" part of rule
        action = rule.get("action", "log")  # Default action is "log"

        # ---- Protocol filter ----
        if "protocol" in match:    # If rule specifies a protocol (TCP/UDP)
            if match["protocol"].lower() == "tcp" and not packet.haslayer(TCP):
                continue  # Rule wants TCP, but this packet is not TCP → skip
            if match["protocol"].lower() == "udp" and not packet.haslayer(UDP):
                continue  # Rule wants UDP, but this packet is not UDP → skip

        # ---- Destination port filter ----
        if "dst_port" in match:   # If rule specifies a destination port
            # Find correct layer: TCP or UDP
            layer = TCP if packet.haslayer(TCP) else UDP if packet.haslayer(UDP) else None
            if layer and packet[layer].dport != match["dst_port"]:
                continue  # Port does not match rule → skip

        # ---- If we got here, packet matches the rule ----
        summary = f"{rule['name']} - {packet.summary()}"   # Create a summary string

        # ---- Take action ----
        if action == "alert":
            print(f"[ALERT] {summary}")   # Print to console
        elif action == "log":
            # Append summary to the log file
            with open(logfile, "a") as log:
                log.write(summary + "\n")


# ------------------------------
# Function: detect_anomalies
# Purpose:  Detect when a source IP sends too many packets per minute
# ------------------------------
def detect_anomalies(packet, threshold, logfile):
    global last_reset

    if IP in packet:    # Only analyze IP packets
        src = packet[IP].src   # Extract source IP address
        traffic_stats[src] += 1   # Increment packet counter for this IP

        # ---- Reset counters every 60 seconds ----
        if time.time() - last_reset > 60:  # If more than 60s passed
            traffic_stats.clear()   # Clear all stats
            last_reset = time.time()   # Reset timer

        # ---- Check if IP exceeded threshold ----
        if traffic_stats[src] > threshold:
            alert_msg = f"[ANOMALY] High traffic from {src}: {traffic_stats[src]} packets/min"
            print(alert_msg)   # Print anomaly alert
            with open(logfile, "a") as log:   # Save to log file
                log.write(alert_msg + "\n")


# ------------------------------
# Function: packet_callback
# Purpose:  Called for each captured packet
# ------------------------------
def packet_callback(packet, rules, threshold, logfile):
    if IP in packet:   # Only process IP packets
        apply_rules(packet, rules, logfile)          # Apply rule checks
        detect_anomalies(packet, threshold, logfile) # Apply anomaly detection


# ------------------------------
# Function: main
# Purpose:  CLI entry point
# ------------------------------
def main():
    # ---- CLI Argument Parser ----
    parser = argparse.ArgumentParser(description="Python SIEM-like Firewall CLI")
    parser.add_argument("mode", choices=["start", "report"], help="Mode: start sniffing or generate report")
    parser.add_argument("--rules", default="rules.json", help="Path to rules.json")
    parser.add_argument("--log", default="traffic.log", help="Log file path")
    parser.add_argument("--iface", default=None, help="Network interface to sniff (optional)")
    parser.add_argument("--threshold", type=int, default=100, help="Packets/min threshold for anomaly detection")
    args = parser.parse_args()

    # ---- Start Mode → begin live capture ----
    if args.mode == "start":
        rules = load_rules(args.rules)   # Load rules from file
        print(f"[INFO] Starting capture on {args.iface or 'default interface'}")
        sniff(
            prn=lambda pkt: packet_callback(pkt, rules, args.threshold, args.log),  # Callback for each packet
            store=0,     # Don't store packets in memory (saves RAM)
            iface=args.iface  # Capture on chosen interface
        )

    # ---- Report Mode → analyze logs ----
    elif args.mode == "report":
        print(f"[INFO] Generating report from {args.log}")
        with open(args.log, "r") as log:
            lines = log.readlines()   # Read all log lines
            print(f"Total log entries: {len(lines)}")

            # Count number of events per IP
            top_ips = defaultdict(int)
            for line in lines:
                if "from" in line:   # Find "from <IP>" in log entries
                    ip = line.split("from")[-1].split(":")[0].strip()
                    top_ips[ip] += 1

            # Display top 5 talkers
            print("\nTop talkers (most events):")
            for ip, count in sorted(top_ips.items(), key=lambda x: x[1], reverse=True)[:5]:
                print(f"{ip}: {count} events")


# ------------------------------
# Run the program
# ------------------------------
if __name__ == "__main__":
    main()
