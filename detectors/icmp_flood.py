"""
icmp_flood.py — ICMP Flood (Ping Flood) DDoS Detector
NetWatchman | MITRE T1498.001

Logic:
  - Filters packets to ICMP Echo Requests only (icmp_type == 8)
  - Uses 1-second time buckets per (src_ip, dst_ip) pair
  - Also tracks global ICMP rate per dst_ip to catch distributed floods
  - Fires HIGH at 100 pings/sec, CRITICAL at 500 pings/sec
  - Alert cooldown of 5 seconds to suppress duplicates
"""

from collections import defaultdict


WINDOW_SECONDS     = 1
HIGH_THRESHOLD     = 100
CRITICAL_THRESHOLD = 500
ALERT_COOLDOWN     = 5


# { (src_ip, dst_ip): { bucket_ts: count } }
_icmp_counts = defaultdict(lambda: defaultdict(int))

# { (src_ip, dst_ip): last_alert_timestamp }
_last_alert = {}

# { dst_ip: { bucket_ts: count } }
_dst_icmp_counts = defaultdict(lambda: defaultdict(int))

# { dst_ip: last_alert_timestamp }
_dst_last_alert = {}



def _is_echo_request(pkt: dict) -> bool:
    """Return True only for ICMP Echo Request packets (type 8)."""
    return pkt.get("protocol") == "ICMP" and pkt.get("icmp_type") == 8


def _bucket(ts: float) -> float:
    """Floor a timestamp to the nearest 1-second bucket."""
    return float(int(ts // WINDOW_SECONDS) * WINDOW_SECONDS)


def _build_alert(severity: str, src_ip: str, dst_ip: str,
                 count: int, bucket: float, distributed: bool) -> dict:
    return {
        "alert":      "ICMP Flood Detected" if not distributed else "Distributed ICMP Flood Detected",
        "severity":   severity,
        "mitre":      "T1498.001",
        "src_ip":     src_ip if not distributed else "multiple (spoofed)",
        "dst_ip":     dst_ip,
        "icmp_count": count,
        "window_sec": WINDOW_SECONDS,
        "timestamp":  bucket,
        "detail": (
            f"{'Distributed: m' if distributed else 'M'}ultiple ICMP Echo Requests to {dst_ip} "
            f"({count}/sec) — ping flood detected. "
            f"Possible DoS attack. MITRE T1498.001."
        ),
    }



def detect(packets: list[dict]) -> list[dict]:
    alerts = []

    for pkt in packets:
        if not _is_echo_request(pkt):
            continue

        src = pkt.get("src_ip", "unknown")
        dst = pkt.get("dst_ip", "unknown")
        ts  = float(pkt.get("timestamp_raw", 0))
        bkt = _bucket(ts)

        pair_key = (src, dst)
        _icmp_counts[pair_key][bkt] += 1
        count = _icmp_counts[pair_key][bkt]

        if count >= CRITICAL_THRESHOLD:
            severity = "CRITICAL"
        elif count >= HIGH_THRESHOLD:
            severity = "HIGH"
        else:
            severity = None

        if severity:
            last = _last_alert.get(pair_key, 0)
            if ts - last >= ALERT_COOLDOWN:
                _last_alert[pair_key] = ts
                alerts.append(_build_alert(severity, src, dst, count, bkt,
                                           distributed=False))

        _dst_icmp_counts[dst][bkt] += 1
        dst_count = _dst_icmp_counts[dst][bkt]

        if dst_count >= CRITICAL_THRESHOLD:
            dst_severity = "CRITICAL"
        elif dst_count >= HIGH_THRESHOLD:
            dst_severity = "HIGH"
        else:
            dst_severity = None

        if dst_severity:
            last_dst = _dst_last_alert.get(dst, 0)
            if ts - last_dst >= ALERT_COOLDOWN:
                _dst_last_alert[dst] = ts
                alerts.append(_build_alert(dst_severity, "multiple (spoofed)",
                                           dst, dst_count, bkt,
                                           distributed=True))

    return alerts