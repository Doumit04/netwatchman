from scapy.all import IP, TCP, UDP, Raw, ARP, ICMP, DNS, DNSRR
from datetime import datetime

def parse_packet(packet):
    """
    Takes a raw Scapy packet and returns a clean dictionary.
    """
    parsed = {
        "timestamp": datetime.fromtimestamp(float(packet.time)).strftime("%Y-%m-%d %H:%M:%S"),
        "timestamp_raw": float(packet.time),
        "src_ip": None,
        "dst_ip": None,
        "protocol": None,
        "src_port": None,
        "dst_port": None,
        "payload": None,
        "src_mac": None,
        "dst_mac": None
    }

    #Extract IP Layer
    if packet.haslayer(IP):
        parsed["src_ip"] = packet[IP].src
        parsed["dst_ip"] = packet[IP].dst
        parsed["pkt_len"] = len(packet)
    
    #Extract protocol and ports
    if packet.haslayer(TCP):
        parsed["protocol"] = "TCP"
        parsed["src_port"] = packet[TCP].sport
        parsed["dst_port"] = packet[TCP].dport
        parsed["tcp_flags"] = packet[TCP].flags
    
    elif packet.haslayer(UDP):
        parsed["protocol"] = "UDP"
        parsed["src_port"] = packet[UDP].sport
        parsed["dst_port"] = packet[UDP].dport

    elif packet.haslayer(ICMP):
        parsed["protocol"] = "ICMP"
        parsed["icmp_type"] = packet[ICMP].type

    elif packet.haslayer(ARP):
        parsed["protocol"] = "ARP"
        parsed["src_ip"] = packet[ARP].psrc #sender ip (claimed)
        parsed["dst_ip"] = packet[ARP].pdst #target ip
        parsed["src_mac"] = packet[ARP].hwsrc #sender mac (real)
        parsed["dst_mac"] = packet[ARP].hwdst #target mac

    #Extract Payload
    if packet.haslayer(Raw):
        try:
            parsed["payload"] = packet[Raw].load.decode("utf-8", errors="ignore")
        except Exception:
            parsed["payload"] = None


    if packet.haslayer(DNS):
        dns = packet[DNS]
        parsed["dns_id"] = dns.id
        parsed["dns_qr"] = dns.qr
        if dns.qr == 1 and dns.qd:
            parsed["dns_domain"] = dns.qd.qname.decode(errors="ignore")
            ips = []
            rr = dns.an
            while rr and rr.name:
                try:
                    if rr.type == 1:
                        ips.append(str(rr.rdata))
                    rr = rr.payload
                except Exception:
                    break
            parsed["dns_response_ips"] = ips
    
    return parsed