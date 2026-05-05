from collections import defaultdict

SSH_PORT = 22
TIME_WINDOW = 60 # seconds
HIGH_THRESHOLD = 20
CRITICAL_THRESHOLD = 100

def detect(parsed_packets):
    """
    Detects SSH brute force attacks.
    Same IP making too many connection attempts to port 22
    within a 60 second sliding window = alert.
    MITRE ATT&CK: T1110.001 - Brute Force: Password Guessing
    """

    attempts = defaultdict(list)
    alerts = []

    #step 1 - collect all SSH connection attempts per source IP
    for packet in parsed_packets:
        if packet.get("protocol") != "TCP":
            continue
        if packet.get("dst_port") !=SSH_PORT:
            continue

        src_ip = packet.get("src_ip")
        timestamp_raw = packet.get("timestamp_raw")

        if src_ip and timestamp_raw:
            attempts[src_ip].append(timestamp_raw)
    
    #step 2 sliding window alaysis per IP
    for ip, timestamps in attempts.items():
        timestamps.sort()

        max_attempts_in_window = 0

        #slide a 60 second window accross all timestamps
        left = 0
        for right in range(len(timestamps)):
            #shrink window from left until it fits within 60 seconds
            while timestamps[right] - timestamps[left] > TIME_WINDOW:
                left += 1
            #count how many attempts fall in this window
            window_count = right - left + 1
            if window_count > max_attempts_in_window:
                max_attempts_in_window = window_count
        
        #step 3 - determine severity
        if max_attempts_in_window > CRITICAL_THRESHOLD:
            severity = "CRITICAL"
        elif max_attempts_in_window >= HIGH_THRESHOLD:
            severity = "HIGH"
        else:
            continue

        alerts.append({
            "type": "SSH Brute Force",
            "severity": severity,
            "src_ip": ip,
            "attempts_in_window": max_attempts_in_window,
            "ime_window_seconds": TIME_WINDOW,
            "description": f"SSH brute force detected: {ip} made {max_attempts_in_window} attempts to port 22 within {TIME_WINDOW} seconds",
            "mitre_id": "T1110.001",
            "mitre_name": "Brute Force: Password Guessing"
        })
    return alerts