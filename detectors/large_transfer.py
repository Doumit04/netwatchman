"""
large_transfer.py — Large Data Transfer / Exfiltration Detector
NetWatchman | MITRE T1048

Logic:
  - Tracks total bytes transferred per (src_ip, dst_ip) pair
  - Uses a 60-second sliding window
  - Fires HIGH at 50MB/min, CRITICAL at 100MB/min
  - Alert cooldown of 30 seconds per pair to suppress duplicates
"""

from collections import defaultdict


# Thresholds 

WINDOW_SECONDS     = 60
HIGH_THRESHOLD     = 50  * 1024 * 1024   # 50 MB
CRITICAL_THRESHOLD = 100 * 1024 * 1024   # 100 MB
ALERT_COOLDOWN     = 30


# State 

# { (src_ip, dst_ip): { bucket_ts: total_bytes } }
_transfer_bytes = defaultdict(lambda: defaultdict(int))

# { (src_ip, dst_ip): last_alert_timestamp }
_last_alert = {}


# Helpers 

def _bucket(ts: float) -> float:
    """Floor timestamp to 60-second bucket."""
    return float(int(ts // WINDOW_SECONDS) * WINDOW_SECONDS)


def _packet_size(pkt: dict) -> int:
    return pkt.get("pkt_len", 0)

# Main detector 

def detect(packets: list[dict]) -> list[dict]:
    alerts = []

    for pkt in packets:
        src_ip = pkt.get("src_ip")
        dst_ip = pkt.get("dst_ip")
        ts     = float(pkt.get("timestamp_raw", 0))

        if not src_ip or not dst_ip:
            continue

        size = _packet_size(pkt)
        if size == 0:
            continue

        bkt      = _bucket(ts)
        pair_key = (src_ip, dst_ip)

        _transfer_bytes[pair_key][bkt] += size
        total = _transfer_bytes[pair_key][bkt]

        if total >= CRITICAL_THRESHOLD:
            severity = "CRITICAL"
        elif total >= HIGH_THRESHOLD:
            severity = "HIGH"
        else:
            severity = None

        if severity:
            last = _last_alert.get(pair_key, 0)
            if ts - last >= ALERT_COOLDOWN:
                _last_alert[pair_key] = ts
                alerts.append({
                    "alert":        "Large Data Transfer Detected",
                    "severity":     severity,
                    "mitre":        "T1048",
                    "src_ip":       src_ip,
                    "dst_ip":       dst_ip,
                    "bytes":        total,
                    "mb":           round(total / (1024 * 1024), 2),
                    "window_sec":   WINDOW_SECONDS,
                    "timestamp":    pkt.get("timestamp", "unknown"),
                    "detail": (
                        f"{src_ip} transferred {round(total / (1024*1024), 2)}MB "
                        f"to {dst_ip} within {WINDOW_SECONDS} seconds. "
                        f"Possible data exfiltration. MITRE T1048."
                    )
                })

    return alerts