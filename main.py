import sys
from sniffer import read_pcap
from parser import parse_packet
from detectors import port_scan, arp_spoof, ssh_brute, ftp_brute, syn_flood, icmp_flood, dns_spoof, cleartext_creds, dir_traversal, malicious_ip, service_version,sql_injection, telnet, xss, suspicious_agents, large_transfer
import json

def main():
    if len(sys.argv) < 2:
        print("[ERROR] Please provide a PCAP file path.")
        print("Usage: python main.py pcap_samples/http.pcap")
        return
    
    filepath = sys.argv[1]
    packets = read_pcap(filepath)

    if not packets:
        return
    
    # Parse all packets into a list
    print("\n[*] Parsing packets...")
    parsed_packets = []
    for packet in packets:
        parsed = parse_packet(packet)
        parsed_packets.append(parsed)
    print(f"[*] Parsed {len(parsed_packets)} packets successfully")


    # Run Port Scan detector
    print("\n[*] Running Port Scan Detector...")
    alerts = port_scan.detect(parsed_packets)
    if alerts:
        print(f"\n[!] {len(alerts)} alert(s) found:\n")
        for alert in alerts:
            print(json.dumps(alert, indent=2))
            print("-" * 40)
    else:
        print("\n[✓] No port scan detected.")

    # Run ARP Spoofing detector
    print("\n[*] Running ARP Spoofing detector...")
    alerts = arp_spoof.detect(parsed_packets)
    if alerts:
        print(f"\n[!] {len(alerts)} alert(s) found:\n")
        for alert in alerts:
            print(json.dumps(alert, indent=2))
            print("-" * 40)
    else:
        print("\n[✓] No ARP spoofing detected.")

    # Run SSH Brute Force detector
    print("\n[*] Running SSH Brute Force Detector...")
    alerts = ssh_brute.detect(parsed_packets)
    if alerts:
        print(f"\n[!] {len(alerts)} alert(s) found:\n")
        for alert in alerts:
            print(json.dumps(alert, indent=2))
            print("-" * 40)
    else:
        print("\n[✓] No SSH brute force detected.")

    # Run FTP Brute Force detector
    print("\n[*] Running FTP Brute Force Detector...")
    alerts = ftp_brute.detect(parsed_packets)
    if alerts:
        print(f"\n[!] {len(alerts)} alert(s) found:\n")
        for alert in alerts:
            print(json.dumps(alert, indent=2))
            print("-" * 40)
    else:
        print("\n[✓] No FTP brute force detected.")

    # Run SYN Flood detector
    print("\n[*] Running SYN Flood Detector...")
    alerts = syn_flood.detect(parsed_packets)
    if alerts:
        print(f"\n[!] {len(alerts)} alert(s) found:\n")
        for alert in alerts:
            print(json.dumps(alert, indent=2))
            print("-" * 40)
    else:
        print("\n[✓] No SYN flood detected.")

    # Run ICMP Flood detector
    print("\n[*] Running ICMP Flood Detector...")
    alerts = icmp_flood.detect(parsed_packets)
    if alerts:
        print(f"\n[!] {len(alerts)} alert(s) found:\n")
        for alert in alerts:
            print(json.dumps(alert, indent=2))
            print("-" * 40)
    else:
        print("\n[✓] No ICMP flood detected.")

    # Run DNS Spoofing detector
    print("\n[*] Running DNS Spoofing Detector...")
    alerts = dns_spoof.detect(parsed_packets)
    if alerts:
        print(f"\n[!] {len(alerts)} alert(s) found:\n")
        for alert in alerts:
            print(json.dumps(alert, indent=2))
            print("-" * 40)
    else:
        print("\n[✓] No DNS spoofing detected.")


    # Run Cleartext Credentials detector
    print("\n[*] Running Cleartext Credentials Detector...")
    alerts = cleartext_creds.detect(parsed_packets)
    if alerts:
        print(f"\n[!] {len(alerts)} alert(s) found:\n")
        for alert in alerts:
            print(json.dumps(alert, indent=2))
            print("-" * 40)
    else:
        print("\n[✓] No cleartext credentials detected.")


    # Run Directory Traversal detector
    print("\n[*] Running Directory Traversal Detector...")
    alerts = dir_traversal.detect(parsed_packets)
    if alerts:
        print(f"\n[!] {len(alerts)} alert(s) found:\n")
        for alert in alerts:
            print(json.dumps(alert, indent=2))
            print("-" * 40)
    else:
        print("\n[✓] No directory traversal detected.")


    # Run Malicious IP detector
    print("\n[*] Running Malicious IP Detector...")
    alerts = malicious_ip.detect(parsed_packets)
    if alerts:
        print(f"\n[!] {len(alerts)} alert(s) found:\n")
        for alert in alerts:
            print(json.dumps(alert, indent=2))
            print("-" * 40)
    else:
        print("\n[✓] No malicious IPs detected.")


    # Run Service Version detector
    print("\n[*] Running Service Version Detector...")
    alerts = service_version.detect(parsed_packets)
    if alerts:
        print(f"\n[!] {len(alerts)} alert(s) found:\n")
        for alert in alerts:
            print(json.dumps(alert, indent=2))
            print("-" * 40)
    else:
        print("\n[✓] No service version exposure detected.")


    # Run SQL Injection detector
    print("\n[*] Running SQL Injection Detector...")
    alerts = sql_injection.detect(parsed_packets)
    if alerts:
        print(f"\n[!] {len(alerts)} alert(s) found:\n")
        for alert in alerts:
            print(json.dumps(alert, indent=2))
            print("-" * 40)
    else:
        print("\n[✓] No SQL injection detected.")


    # Run Telnet detector
    print("\n[*] Running Telnet Detector...")
    alerts = telnet.detect(parsed_packets)
    if alerts:
        print(f"\n[!] {len(alerts)} alert(s) found:\n")
        for alert in alerts:
            print(json.dumps(alert, indent=2))
            print("-" * 40)
    else:
        print("\n[✓] No Telnet usage detected.")


    # Run XSS detector
    print("\n[*] Running XSS Detector...")
    alerts = xss.detect(parsed_packets)
    if alerts:
        print(f"\n[!] {len(alerts)} alert(s) found:\n")
        for alert in alerts:
            print(json.dumps(alert, indent=2))
            print("-" * 40)
    else:
        print("\n[✓] No XSS attacks detected.")


    # Run Suspicious User-Agent detector
    print("\n[*] Running Suspicious User-Agent Detector...")
    alerts = suspicious_agents.detect(parsed_packets)
    if alerts:
        print(f"\n[!] {len(alerts)} alert(s) found:\n")
        for alert in alerts:
            print(json.dumps(alert, indent=2))
            print("-" * 40)
    else:
        print("\n[✓] No suspicious user agents detected.")


    # Run Large Transfer detector
    print("\n[*] Running Large Transfer Detector...")
    alerts = large_transfer.detect(parsed_packets)
    if alerts:
        print(f"\n[!] {len(alerts)} alert(s) found:\n")
        for alert in alerts:
            print(json.dumps(alert, indent=2))
            print("-" * 40)
    else:
        print("\n[✓] No large transfers detected.")

if __name__ == "__main__":
    main()