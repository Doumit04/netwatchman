"""
syn_flood.py — SYN Flood DDoS Detector
NetWatchman | MITRE T1498.001

Logic:
  - Filters packets to SYN-only (TCP flags == 0x02, no ACK)
  - Uses 1-second time buckets per (src_ip, dst_ip) pair
  - Also tracks global SYN rate per dst_ip to catch distributed floods
  - Fires HIGH at 100 SYNs/sec, CRITICAL at 500 SYNs/sec
  - Alert cooldown of 5 seconds per (src_ip, dst_ip) to suppress duplicates
"""

from collections import defaultdict


# ── Thresholds ──────────────────────────────────────────────────────────────

WINDOW_SECONDS    = 1     # Size of each time bucket
HIGH_THRESHOLD    = 100   # SYNs/sec → HIGH alert
CRITICAL_THRESHOLD = 500  # SYNs/sec → CRITICAL alert
ALERT_COOLDOWN    = 5     # Seconds before re-alerting same (src, dst) pair


# ── State ────────────────────────────────────────────────────────────────────

# { (src_ip, dst_ip): { bucket_ts: count } }
_syn_counts = defaultdict(lambda: defaultdict(int))

# { (src_ip, dst_ip): last_alert_timestamp }
_last_alert = {}

# { dst_ip: { bucket_ts: count } }  — for distributed flood detection
_dst_syn_counts = defaultdict(lambda: defaultdict(int))

# { dst_ip: last_alert_timestamp }
_dst_last_alert = {}


# ── Helpers ──────────────────────────────────────────────────────────────────
def _is_syn_only(pkt: dict) -> bool:
    """Return True only for TCP SYN packets with ACK not set."""
    if pkt.get("protocol") != "TCP":
        return False
    flags = pkt.get("tcp_flags")
    if flags is None:
        return False
    return (int(flags) & 0x3F) == 0x02  # SYN=1, ACK=0


def _bucket(ts: float) -> float:
    """Floor a timestamp to the nearest 1-second bucket."""
    return float(int(ts // WINDOW_SECONDS) * WINDOW_SECONDS)


def _build_alert(severity: str, src_ip: str, dst_ip: str,
                 syn_count: int, bucket: float, distributed: bool) -> dict:
    return {
        "alert":      "SYN Flood Detected" if not distributed else "Distributed SYN Flood Detected",
        "severity":   severity,
        "mitre":      "T1498.001",
        "src_ip":     src_ip if not distributed else "multiple (spoofed)",
        "dst_ip":     dst_ip,
        "syn_count":  syn_count,
        "window_sec": WINDOW_SECONDS,
        "timestamp":  bucket,
        "detail": (
            f"{'Distributed: m' if distributed else 'M'}ultiple SYN packets to {dst_ip} "
            f"({syn_count}/sec) — TCP handshakes never completed. "
            f"Possible DoS attack. MITRE T1498.001."
        ),
    }


# ── Main detector ─────────────────────────────────────────────────────────────

def detect(packets: list[dict]) -> list[dict]:
    """
    Analyse a list of parsed packets and return SYN flood alerts.

    Each packet dict is expected to follow the parser.py schema:
      timestamp_raw (float), src_ip, dst_ip, protocol, payload (bytes)
    """
    alerts = []

    for pkt in packets:
        if not _is_syn_only(pkt):
            continue

        src  = pkt.get("src_ip", "unknown")
        dst  = pkt.get("dst_ip", "unknown")
        ts   = float(pkt.get("timestamp_raw", 0))
        bkt  = _bucket(ts)

        # ── Per-(src, dst) counting ──────────────────────────────────────────
        pair_key = (src, dst)
        _syn_counts[pair_key][bkt] += 1
        count = _syn_counts[pair_key][bkt]

        # Determine severity
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

        # ── Per-dst counting (distributed flood detection) ───────────────────
        _dst_syn_counts[dst][bkt] += 1
        dst_count = _dst_syn_counts[dst][bkt]

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