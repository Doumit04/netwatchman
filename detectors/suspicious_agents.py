"""
suspicious_agents.py — Suspicious User-Agent Detector
NetWatchman | MITRE T1595

Logic:
  - Inspects the payload of every packet for HTTP User-Agent headers
  - Compares against a list of known attack tool signatures
  - Fires a HIGH alert when a known malicious tool is identified
"""

import re

# Patterns 

# Each entry: (pattern, tool_label)
SUSPICIOUS_AGENTS = [
    # SQL injection tools
    (re.compile(r"sqlmap", re.IGNORECASE), "sqlmap — SQL injection scanner"),
    (re.compile(r"Havij", re.IGNORECASE), "Havij — automated SQL injection tool"),
    (re.compile(r"pangolin", re.IGNORECASE), "Pangolin — SQL injection tool"),

    # Web vulnerability scanners
    (re.compile(r"Nikto", re.IGNORECASE), "Nikto — web vulnerability scanner"),
    (re.compile(r"Nessus", re.IGNORECASE), "Nessus — vulnerability scanner"),
    (re.compile(r"OpenVAS", re.IGNORECASE), "OpenVAS — vulnerability scanner"),
    (re.compile(r"Acunetix", re.IGNORECASE), "Acunetix — web app scanner"),
    (re.compile(r"w3af", re.IGNORECASE), "w3af — web attack framework"),
    (re.compile(r"Netsparker", re.IGNORECASE), "Netsparker — web vulnerability scanner"),
    (re.compile(r"AppScan", re.IGNORECASE), "IBM AppScan — web app scanner"),
    (re.compile(r"Burp\s*Suite", re.IGNORECASE), "Burp Suite — web security testing"),
    (re.compile(r"ZAP", re.IGNORECASE), "OWASP ZAP — web app scanner"),

    # Network scanners
    (re.compile(r"Nmap\s*Scripting\s*Engine", re.IGNORECASE), "Nmap NSE — network scanner"),
    (re.compile(r"masscan", re.IGNORECASE), "masscan — fast port scanner"),
    (re.compile(r"ZMap", re.IGNORECASE), "ZMap — internet scanner"),

    # Exploitation frameworks
    (re.compile(r"Metasploit", re.IGNORECASE), "Metasploit — exploitation framework"),
    (re.compile(r"msfcrawler", re.IGNORECASE), "Metasploit crawler"),
    (re.compile(r"msfpayload", re.IGNORECASE), "Metasploit payload"),

    # Directory/file brute forcers
    (re.compile(r"DirBuster", re.IGNORECASE), "DirBuster — directory brute forcer"),
    (re.compile(r"gobuster", re.IGNORECASE), "gobuster — directory brute forcer"),
    (re.compile(r"dirsearch", re.IGNORECASE), "dirsearch — directory scanner"),
    (re.compile(r"wfuzz", re.IGNORECASE), "wfuzz — web fuzzer"),
    (re.compile(r"ffuf", re.IGNORECASE), "ffuf — web fuzzer"),
    (re.compile(r"feroxbuster", re.IGNORECASE), "feroxbuster — content discovery"),

    # Brute force tools
    (re.compile(r"Hydra", re.IGNORECASE), "Hydra — password brute forcer"),
    (re.compile(r"Medusa", re.IGNORECASE), "Medusa — parallel brute forcer"),

    # Generic automation/scripting
    (re.compile(r"python-requests", re.IGNORECASE), "python-requests — scripted attack"),
    (re.compile(r"Go-http-client", re.IGNORECASE), "Go HTTP client — automated tool"),
    (re.compile(r"curl/", re.IGNORECASE), "curl — command line tool"),
    (re.compile(r"Wget/", re.IGNORECASE), "wget — command line downloader"),

    # Scanners and recon tools
    (re.compile(r"WhatWeb", re.IGNORECASE), "WhatWeb — web fingerprinter"),
    (re.compile(r"whatweb", re.IGNORECASE), "WhatWeb — web fingerprinter"),
    (re.compile(r"zgrab", re.IGNORECASE), "zgrab — banner grabber"),
    (re.compile(r"nuclei", re.IGNORECASE), "Nuclei — vulnerability scanner"),
    (re.compile(r"subfinder", re.IGNORECASE), "subfinder — subdomain discovery"),
]


# Helpers 

def _extract_user_agent(payload: str) -> str | None:
    """Extract the User-Agent value from an HTTP payload."""
    match = re.search(r"User-Agent:\s*(.+)", payload, re.IGNORECASE)
    return match.group(1).strip() if match else None


# Main detector 

def detect(packets: list[dict]) -> list[dict]:
    alerts = []

    for pkt in packets:
        payload = pkt.get("payload")
        if not payload:
            continue

        # Only check HTTP traffic
        if "User-Agent" not in payload:
            continue

        user_agent = _extract_user_agent(payload)
        if not user_agent:
            continue

        for pattern, label in SUSPICIOUS_AGENTS:
            match = pattern.search(user_agent)
            if match:
                alerts.append({
                    "alert":      "Suspicious User-Agent Detected",
                    "severity":   "HIGH",
                    "mitre":      "T1595",
                    "src_ip":     pkt.get("src_ip", "unknown"),
                    "dst_ip":     pkt.get("dst_ip", "unknown"),
                    "src_port":   pkt.get("src_port"),
                    "dst_port":   pkt.get("dst_port"),
                    "tool":       label,
                    "user_agent": user_agent,
                    "timestamp":  pkt.get("timestamp", "unknown"),
                    "detail": (
                        f"Known attack tool detected from {pkt.get('src_ip')} → {pkt.get('dst_ip')}. "
                        f"Tool: '{label}'. "
                        f"User-Agent: '{user_agent}'. MITRE T1595."
                    )
                })
                break  # One alert per packet

    return alerts