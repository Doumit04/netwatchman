"""
dns_spoof.py — DNS Spoofing Detector
NetWatchman | MITRE T1557.002

Logic:
  - Only looks at DNS response packets (dns_qr == 1)
  - Tracks all IPs seen per (transaction_id, domain) pair
  - If the same query (same domain name, same transaction id) receives responses with different IPs → spoofing alert
"""

from collections import defaultdict


# ── State ─────────────────────────────────────────────────────────────────────

# { (dns_id, domain): set of IPs seen in responses }
_dns_responses = defaultdict(set)


# ── Main detector ─────────────────────────────────────────────────────────────

def detect(packets: list[dict]) -> list[dict]:
    alerts = []

    for pkt in packets:

        # Only care about DNS responses
        if pkt.get("dns_qr") != 1:
            continue

        dns_id  = pkt.get("dns_id")
        domain  = pkt.get("dns_domain")
        ips     = pkt.get("dns_response_ips", [])
        src_ip  = pkt.get("src_ip", "unknown")
        ts      = pkt.get("timestamp", "unknown")

        if not dns_id or not domain or not ips:
            continue

        key = (dns_id, domain)

        # Check each IP in this response against what we've seen before
        for ip in ips:
            if _dns_responses[key] and ip not in _dns_responses[key]:
                # We've seen a different IP for this exact query → spoofing
                alerts.append({
                    "alert":        "DNS Spoofing Detected",
                    "severity":     "CRITICAL",
                    "mitre":        "T1557.002",
                    "src_ip":       src_ip,
                    "domain":       domain,
                    "dns_id":       dns_id,
                    "legit_ips":    list(_dns_responses[key]),
                    "spoofed_ip":   ip,
                    "timestamp":    ts,
                    "detail": (
                        f"DNS response conflict for '{domain}' "
                        f"(transaction ID {dns_id}): "
                        f"previously saw {list(_dns_responses[key])}, "
                        f"now seeing {ip} from {src_ip}. "
                        f"Possible DNS spoofing. MITRE T1557.002."
                    )
                })

            _dns_responses[key].add(ip)

    return alerts