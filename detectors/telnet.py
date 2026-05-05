"""
telnet.py — Telnet Usage Detector
NetWatchman | MITRE T1040

Logic:
  - Checks every TCP packet for src_port or dst_port == 23
  - Fires a HIGH alert immediately — Telnet has no legitimate modern use
  - Both directions flagged: connections to and responses from Telnet servers
"""


# ── Main detector ─────────────────────────────────────────────────────────────

def detect(packets: list[dict]) -> list[dict]:
    alerts = []

    for pkt in packets:
        if pkt.get("protocol") != "TCP":
            continue

        src_port = pkt.get("src_port")
        dst_port = pkt.get("dst_port")
        src_ip   = pkt.get("src_ip", "unknown")
        dst_ip   = pkt.get("dst_ip", "unknown")
        ts       = pkt.get("timestamp", "unknown")

        if dst_port == 23:
            alerts.append({
                "alert":     "Telnet Connection Detected",
                "severity":  "HIGH",
                "mitre":     "T1040",
                "direction": "outbound",
                "src_ip":    src_ip,
                "dst_ip":    dst_ip,
                "src_port":  src_port,
                "dst_port":  dst_port,
                "timestamp": ts,
                "detail": (
                    f"{src_ip} is connecting to Telnet server at {dst_ip}:23. "
                    f"Telnet transmits credentials and commands in plain text. "
                    f"Replace with SSH immediately. MITRE T1040."
                )
            })

        elif src_port == 23:
            alerts.append({
                "alert":     "Telnet Session Detected",
                "severity":  "HIGH",
                "mitre":     "T1040",
                "direction": "inbound",
                "src_ip":    src_ip,
                "dst_ip":    dst_ip,
                "src_port":  src_port,
                "dst_port":  dst_port,
                "timestamp": ts,
                "detail": (
                    f"Telnet server at {src_ip}:23 is responding to {dst_ip}. "
                    f"Active Telnet session in progress — data is flowing in plain text. "
                    f"Replace with SSH immediately. MITRE T1040."
                )
            })

    return alerts