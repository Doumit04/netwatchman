"""
sql_injection.py — SQL Injection Detector
NetWatchman | MITRE T1190

Logic:
  - Inspects the payload of every packet
  - Searches for known SQL injection patterns grouped by attack type
  - Fires a CRITICAL alert when a match is found
"""

import re

# Patterns 

# Each entry: (pattern, attack_type)
SQLI_PATTERNS = [
    # Auth bypass
    (re.compile(r"'\s*OR\s*'1'\s*=\s*'1", re.IGNORECASE), "Auth bypass: ' OR '1'='1"),
    (re.compile(r"'\s*OR\s*1\s*=\s*1", re.IGNORECASE), "Auth bypass: ' OR 1=1"),
    (re.compile(r'"\s*OR\s*"a"\s*=\s*"a', re.IGNORECASE), 'Auth bypass: " OR "a"="a'),
    (re.compile(r"'\s*OR\s*''\s*=\s*'", re.IGNORECASE), "Auth bypass: ' OR ''='"),
    (re.compile(r"admin'\s*--", re.IGNORECASE), "Auth bypass: admin'--"),

    # SQL meta characters
    (re.compile(r"'\s*--", re.IGNORECASE), "SQL comment: '--"),
    (re.compile(r"'\s*#", re.IGNORECASE), "SQL comment: '#"),
    (re.compile(r"';\s*--", re.IGNORECASE), "SQL terminator: ';--"),

    # Data extraction
    (re.compile(r"UNION\s+SELECT", re.IGNORECASE), "Data extraction: UNION SELECT"),
    (re.compile(r"UNION\s+ALL\s+SELECT", re.IGNORECASE), "Data extraction: UNION ALL SELECT"),
    (re.compile(r"SELECT\s+\*\s+FROM", re.IGNORECASE), "Data extraction: SELECT * FROM"),
    (re.compile(r"SELECT\s+.+\s+FROM\s+\w+", re.IGNORECASE), "Data extraction: SELECT FROM"),

    # Destructive queries
    (re.compile(r"DROP\s+TABLE", re.IGNORECASE), "Destructive: DROP TABLE"),
    (re.compile(r"DROP\s+DATABASE", re.IGNORECASE), "Destructive: DROP DATABASE"),
    (re.compile(r"DELETE\s+FROM", re.IGNORECASE), "Destructive: DELETE FROM"),
    (re.compile(r"TRUNCATE\s+TABLE", re.IGNORECASE), "Destructive: TRUNCATE TABLE"),

    # Blind SQL injection
    (re.compile(r"SLEEP\s*\(\s*\d+\s*\)", re.IGNORECASE), "Blind SQLi: SLEEP()"),
    (re.compile(r"WAITFOR\s+DELAY", re.IGNORECASE), "Blind SQLi: WAITFOR DELAY"),
    (re.compile(r"BENCHMARK\s*\(", re.IGNORECASE), "Blind SQLi: BENCHMARK()"),
    (re.compile(r"pg_sleep\s*\(", re.IGNORECASE), "Blind SQLi: pg_sleep()"),

    # Stacked queries
    (re.compile(r"';\s*INSERT", re.IGNORECASE), "Stacked query: INSERT"),
    (re.compile(r"';\s*UPDATE", re.IGNORECASE), "Stacked query: UPDATE"),
    (re.compile(r"';\s*EXEC", re.IGNORECASE), "Stacked query: EXEC"),
    (re.compile(r"';\s*DROP", re.IGNORECASE), "Stacked query: DROP"),

    # Encoded variants
    (re.compile(r"%27\s*(OR|AND)\s*%27", re.IGNORECASE), "URL encoded: %27 OR/AND %27"),
    (re.compile(r"%27\s*OR\s*1%3D1", re.IGNORECASE), "URL encoded: OR 1=1"),

    # Information gathering
    (re.compile(r"information_schema", re.IGNORECASE), "Schema enumeration: information_schema"),
    (re.compile(r"sys\.tables", re.IGNORECASE), "Schema enumeration: sys.tables"),
    (re.compile(r"xp_cmdshell", re.IGNORECASE), "RCE via SQL: xp_cmdshell"),
]


# Main detector 

def detect(packets: list[dict]) -> list[dict]:
    alerts = []

    for pkt in packets:
        payload = pkt.get("payload")
        if not payload:
            continue

        for pattern, label in SQLI_PATTERNS:
            match = pattern.search(payload)
            if match:
                alerts.append({
                    "alert":       "SQL Injection Detected",
                    "severity":    "CRITICAL",
                    "mitre":       "T1190",
                    "src_ip":      pkt.get("src_ip", "unknown"),
                    "dst_ip":      pkt.get("dst_ip", "unknown"),
                    "src_port":    pkt.get("src_port"),
                    "dst_port":    pkt.get("dst_port"),
                    "attack_type": label,
                    "matched":     match.group(0),
                    "timestamp":   pkt.get("timestamp", "unknown"),
                    "detail": (
                        f"SQL injection attempt from {pkt.get('src_ip')} → {pkt.get('dst_ip')}. "
                        f"Attack type: '{label}'. "
                        f"Matched: '{match.group(0)}'. MITRE T1190."
                    )
                })
                break  # One alert per packet

    return alerts