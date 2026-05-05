"""
cleartext_creds.py — Cleartext Credentials Detector
NetWatchman | MITRE T1040

Logic:
  - Inspects the payload of every packet
  - Searches for known plaintext credential patterns (FTP, Telnet, HTTP Basic Auth, SMTP)
  - Fires a HIGH alert immediately when a match is found
"""

import re

# Patterns

# Each entry: (pattern, protocol_label)
CREDENTIAL_PATTERNS = [
    (re.compile(r"USER\s+\S+",         re.IGNORECASE), "FTP/Telnet USER command"),
    (re.compile(r"PASS\s+\S+",         re.IGNORECASE), "FTP/Telnet PASS command"),
    (re.compile(r"username=\S+",       re.IGNORECASE), "HTTP form username"),
    (re.compile(r"password=\S+",       re.IGNORECASE), "HTTP form password"),
    (re.compile(r"pwd=\S+",   re.IGNORECASE), "HTTP form password"),
    (re.compile(r"passwd=\S+",re.IGNORECASE), "HTTP form password"),
    (re.compile(r"login=\S+", re.IGNORECASE), "HTTP form username"),
    (re.compile(r"Authorization:\s*Basic\s+\S+", re.IGNORECASE), "HTTP Basic Auth header"),
    (re.compile(r"AUTH\s+LOGIN",       re.IGNORECASE), "SMTP AUTH LOGIN"),
    (re.compile(r"AUTH\s+PLAIN\s+\S+", re.IGNORECASE), "SMTP AUTH PLAIN"),
]


# Main detector 

def detect(packets: list[dict]) -> list[dict]:
    alerts = []

    for pkt in packets:
        payload = pkt.get("payload")
        if not payload:
            continue

        for pattern, label in CREDENTIAL_PATTERNS:
            match = pattern.search(payload)
            if match:
                alerts.append({
                    "alert":     "Cleartext Credentials Detected",
                    "severity":  "HIGH",
                    "mitre":     "T1040",
                    "src_ip":    pkt.get("src_ip", "unknown"),
                    "dst_ip":    pkt.get("dst_ip", "unknown"),
                    "src_port":  pkt.get("src_port"),
                    "dst_port":  pkt.get("dst_port"),
                    "protocol":  label,
                    "matched":   match.group(0),
                    "timestamp": pkt.get("timestamp", "unknown"),
                    "detail": (
                        f"Plaintext credentials found in traffic from "
                        f"{pkt.get('src_ip')} → {pkt.get('dst_ip')}. "
                        f"Pattern: '{label}'. "
                        f"Credentials should never travel unencrypted. MITRE T1040."
                    )
                })
                break  # One alert per packet, don't double-fire on same payload

    return alerts