"""
malicious_ip.py — Malicious IP Detector
NetWatchman | MITRE T1071

Logic:
  - Fetches a live blocklist from Emerging Threats on first run
  - Checks both src_ip and dst_ip of every packet against the blocklist
  - Fires a CRITICAL alert if either IP is known malicious
  - Falls back to empty set if the feed is unavailable
"""

import requests

# Config 

BLOCKLIST_URL = "https://rules.emergingthreats.net/blockrules/compromised-ips.txt"

# State 

_malicious_ips: set = None  # Loaded once on first detect() call


# Loader 

def _load_blocklist() -> set:
    print("[*] Fetching malicious IP blocklist from Emerging Threats...")
    try:
        response = requests.get(BLOCKLIST_URL, timeout=10)
        ips = set()
        for line in response.text.splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                ips.add(line)
        print(f"[*] Loaded {len(ips)} malicious IPs.")
        return ips
    except Exception as e:
        print(f"[!] Failed to fetch blocklist: {e}. Continuing with empty set.")
        return set()


# Main detector 

def detect(packets: list[dict]) -> list[dict]:
    global _malicious_ips

    # Load blocklist once
    if _malicious_ips is None:
        _malicious_ips = _load_blocklist()

    alerts = []

    for pkt in packets:
        src_ip = pkt.get("src_ip")
        dst_ip = pkt.get("dst_ip")
        ts     = pkt.get("timestamp", "unknown")

        # Check source IP
        if src_ip and src_ip in _malicious_ips:
            alerts.append({
                "alert":     "Malicious IP Detected",
                "severity":  "CRITICAL",
                "mitre":     "T1071",
                "direction": "inbound",
                "src_ip":    src_ip,
                "dst_ip":    dst_ip,
                "timestamp": ts,
                "detail": (
                    f"Inbound traffic from known malicious IP {src_ip} → {dst_ip}. "
                    f"Source is listed on Emerging Threats blocklist. MITRE T1071."
                )
            })

        # Check destination IP
        if dst_ip and dst_ip in _malicious_ips:
            alerts.append({
                "alert":     "Malicious IP Detected",
                "severity":  "CRITICAL",
                "mitre":     "T1071",
                "direction": "outbound",
                "src_ip":    src_ip,
                "dst_ip":    dst_ip,
                "timestamp": ts,
                "detail": (
                    f"Outbound traffic to known malicious IP {dst_ip} from {src_ip}. "
                    f"Possible malware phoning home or C2 communication. MITRE T1071."
                )
            })

    return alerts