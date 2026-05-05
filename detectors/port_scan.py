from collections import defaultdict

THRESHOLD = 15

def detect(parsed_packets):
    """
    Detects port scanning behavior.
    One IP probing more than THRESHOLD unique ports = alert.
    """

    port_tracker = defaultdict(set)
    alerts = []

    for packet in parsed_packets:
        src_ip = packet.get("src_ip")
        dst_port = packet.get("dst_port")
        #get is sued because some packets won't have the whole fields, so get() protects us from crashing on those packets

        if src_ip and dst_port:
            port_tracker[src_ip].add(dst_port)
        
    for ip, ports in port_tracker.items():
        if len(ports) >= THRESHOLD:
            alerts.append({
                "type": "Port Scan",
                "severity": "HIGH",
                "src_ip": ip,
                "ports_scanned": len(ports),
                "description": f"Port scan detected: {ip} probed {len(ports)} unique ports",
                "mitre_id": "T1046",
                "mitre_name": "Network Service Discovery"
            })
    
    return alerts