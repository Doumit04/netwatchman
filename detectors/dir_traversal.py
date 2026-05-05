"""
dir_traversal.py — Directory Traversal Detector
NetWatchman | MITRE T1083

Logic:
  - Inspects the payload of every packet
  - Searches for known directory traversal patterns
  - Fires a HIGH alert immediately when a match is found
"""

import re

# ── Patterns ──────────────────────────────────────────────────────────────────

# Each entry: (pattern, label)
TRAVERSAL_PATTERNS = [
    (re.compile(r"\.\./",              re.IGNORECASE), "Unix path traversal ../"),
    (re.compile(r"\.\.[/\\]",         re.IGNORECASE), "Windows path traversal ..\\"),
    (re.compile(r"%2e%2e%2f",         re.IGNORECASE), "URL encoded ../"),
    (re.compile(r"%2e%2e%5c",         re.IGNORECASE), "URL encoded ..\\"),
    (re.compile(r"\.\.//",            re.IGNORECASE), "Double slash bypass ..//"),
    (re.compile(r"\.\.\\\\",          re.IGNORECASE), "Double backslash bypass ..\\\\"),
    (re.compile(r"/etc/passwd",       re.IGNORECASE), "Sensitive file: /etc/passwd"),
    (re.compile(r"/etc/shadow",       re.IGNORECASE), "Sensitive file: /etc/shadow"),
    (re.compile(r"/proc/self",        re.IGNORECASE), "Sensitive path: /proc/self"),
    (re.compile(r"boot\.ini",         re.IGNORECASE), "Sensitive file: boot.ini"),
    (re.compile(r"win\.ini",          re.IGNORECASE), "Sensitive file: win.ini"),
    (re.compile(r"\\windows\\system32", re.IGNORECASE), "Sensitive path: \\windows\\system32"),
]


# ── Main detector ─────────────────────────────────────────────────────────────

def detect(packets: list[dict]) -> list[dict]:
    alerts = []

    for pkt in packets:
        payload = pkt.get("payload")
        if not payload:
            continue

        for pattern, label in TRAVERSAL_PATTERNS:
            match = pattern.search(payload)
            if match:
                alerts.append({
                    "alert":     "Directory Traversal Detected",
                    "severity":  "HIGH",
                    "mitre":     "T1083",
                    "src_ip":    pkt.get("src_ip", "unknown"),
                    "dst_ip":    pkt.get("dst_ip", "unknown"),
                    "src_port":  pkt.get("src_port"),
                    "dst_port":  pkt.get("dst_port"),
                    "pattern":   label,
                    "matched":   match.group(0),
                    "timestamp": pkt.get("timestamp", "unknown"),
                    "detail": (
                        f"Directory traversal attempt from "
                        f"{pkt.get('src_ip')} → {pkt.get('dst_ip')}. "
                        f"Pattern: '{label}'. "
                        f"Attacker may be attempting to access sensitive files. MITRE T1083."
                    )
                })
                break  # One alert per packet

    return alerts