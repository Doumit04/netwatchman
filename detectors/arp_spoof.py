from collections import defaultdict

def detect(parsed_packets):
    """
    Detects ARP spoofing / cache poisoning.
    Same IP appearing with more than one MAC address = alert.
    MITRE ATT&CK: T1557.002 - ARP Cache Poisoning
    """

    ip_to_macs = defaultdict(set)
    alerts = []

    for packet in parsed_packets:
        if packet.get("protocol") != "ARP":
            continue

        src_ip = packet.get("src_ip")
        src_mac = packet.get("src_mac")

        if src_ip and src_mac:
            ip_to_macs[src_ip].add(src_mac) #Sets automatically deduplicate — if the router sends 500 legitimate ARP replies all with the same MAC, the set stays at size 1. We only care when a second different MAC appears.
    
    for ip, macs in ip_to_macs.items():
        if len(macs) > 1: #one ip, with 2 mac addresses => suspicious
            alerts.append({
                "type" : "ARP Spoofing",
                "severity": "CRITICAL",
                "src_ip": ip,
                "mac_addresses": list(macs),
                "description": f"ARP Spoofing detected: IP {ip} claimed by {len(macs)} different MAC addresses: {', '.join(macs)}",
                "mitre_id": "T1557.002",
                "mitre_name": "ARP Cache Poisoning"
            })
    return alerts