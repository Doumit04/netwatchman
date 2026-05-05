"""
service_version.py — Service Version/Banner Detection
NetWatchman | MITRE T1046

Logic:
  - Inspects the payload of every packet
  - Searches for service banners that reveal software names and versions
  - Fires a MEDIUM alert when version information is exposed
"""

import re

# Patterns 

# Each entry: (pattern, service_label)
BANNER_PATTERNS = [
    (re.compile(r"SSH-\d+\.\d+-\S+",            re.IGNORECASE), "SSH banner"),
    (re.compile(r"Apache/[\d.]+",               re.IGNORECASE), "Apache HTTP Server"),
    (re.compile(r"nginx/[\d.]+",                re.IGNORECASE), "Nginx"),
    (re.compile(r"Microsoft-IIS/[\d.]+",        re.IGNORECASE), "Microsoft IIS"),
    (re.compile(r"ProFTPD[\s/][\d.]+",          re.IGNORECASE), "ProFTPD"),
    (re.compile(r"vsftpd[\s/][\d.]+",           re.IGNORECASE), "vsftpd"),
    (re.compile(r"FileZilla Server[\s/][\d.]+", re.IGNORECASE), "FileZilla FTP"),
    (re.compile(r"OpenSSL/[\d.]+",              re.IGNORECASE), "OpenSSL"),
    (re.compile(r"PHP/[\d.]+",                  re.IGNORECASE), "PHP"),
    (re.compile(r"Exim[\s/][\d.]+",             re.IGNORECASE), "Exim Mail"),
    (re.compile(r"Postfix[\s/][\d.]+",          re.IGNORECASE), "Postfix Mail"),
    (re.compile(r"Sendmail[\s/][\d.]+",         re.IGNORECASE), "Sendmail"),
    (re.compile(r"MySQL[\s/][\d.]+",            re.IGNORECASE), "MySQL"),
    (re.compile(r"PostgreSQL[\s/][\d.]+",       re.IGNORECASE), "PostgreSQL"),
    (re.compile(r"Samba[\s/][\d.]+",            re.IGNORECASE), "Samba"),
]


# Main detector 

def detect(packets: list[dict]) -> list[dict]:
    alerts = []

    for pkt in packets:
        payload = pkt.get("payload")
        if not payload:
            continue

        for pattern, label in BANNER_PATTERNS:
            match = pattern.search(payload)
            if match:
                alerts.append({
                    "alert":     "Service Version Exposed",
                    "severity":  "MEDIUM",
                    "mitre":     "T1046",
                    "src_ip":    pkt.get("src_ip", "unknown"),
                    "dst_ip":    pkt.get("dst_ip", "unknown"),
                    "src_port":  pkt.get("src_port"),
                    "dst_port":  pkt.get("dst_port"),
                    "service":   label,
                    "banner":    match.group(0),
                    "timestamp": pkt.get("timestamp", "unknown"),
                    "detail": (
                        f"Service banner from {pkt.get('src_ip')} exposes "
                        f"{label} version info: '{match.group(0)}'. "
                        f"Attackers can use this to find known vulnerabilities. MITRE T1046."
                    )
                })
                break  # One alert per packet

    return alerts