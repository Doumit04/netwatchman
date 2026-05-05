"""
xss.py — Cross-Site Scripting (XSS) Detector
NetWatchman | MITRE T1059.007

Logic:
  - Inspects the payload of every packet
  - Searches for known XSS patterns based on OWASP XSS Filter Evasion Cheat Sheet
  - Covers script tags, event handlers, javascript: URIs, DOM manipulation,
    encoded variants, HTML5 vectors, and cookie/session theft patterns
  - Fires a CRITICAL alert when a match is found
"""

import re

# ── Patterns ──────────────────────────────────────────────────────────────────

XSS_PATTERNS = [
    # Script tags — basic and variations
    (re.compile(r"<script[\s>]", re.IGNORECASE), "Script tag injection"),
    (re.compile(r"</script>", re.IGNORECASE), "Script closing tag"),
    (re.compile(r"<script/", re.IGNORECASE), "Script tag with slash"),
    (re.compile(r"%3Cscript", re.IGNORECASE), "URL encoded <script"),
    (re.compile(r"&lt;script", re.IGNORECASE), "HTML encoded <script"),

    # javascript: URI
    (re.compile(r"javascript\s*:", re.IGNORECASE), "javascript: URI"),
    (re.compile(r"java\s*script\s*:", re.IGNORECASE), "Obfuscated javascript: URI"),
    (re.compile(r"%6a%61%76%61%73%63%72%69%70%74", re.IGNORECASE), "URL encoded javascript"),
    (re.compile(r"&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;", re.IGNORECASE), "HTML entity encoded javascript"),

    # Event handlers
    (re.compile(r"on(error|load|click|mouseover|mouseout|focus|blur|change|submit|reset|select|keydown|keyup|keypress|input|dblclick|drag|drop|copy|paste|cut|wheel|scroll|resize|contextmenu|touchstart|touchend|touchmove)\s*=", re.IGNORECASE), "Event handler injection"),
    (re.compile(r"onreadystatechange\s*=", re.IGNORECASE), "onreadystatechange handler"),
    (re.compile(r"onanimationstart\s*=", re.IGNORECASE), "CSS animation event handler"),
    (re.compile(r"ontransitionend\s*=", re.IGNORECASE), "CSS transition event handler"),
    (re.compile(r"onpointerdown\s*=", re.IGNORECASE), "Pointer event handler"),
    (re.compile(r"onmessage\s*=", re.IGNORECASE), "onmessage handler"),

    # DOM manipulation
    (re.compile(r"document\.cookie", re.IGNORECASE), "Cookie theft: document.cookie"),
    (re.compile(r"document\.location", re.IGNORECASE), "Redirect: document.location"),
    (re.compile(r"document\.write\s*\(", re.IGNORECASE), "DOM write: document.write"),
    (re.compile(r"document\.writeln\s*\(", re.IGNORECASE), "DOM write: document.writeln"),
    (re.compile(r"window\.location", re.IGNORECASE), "Redirect: window.location"),
    (re.compile(r"window\.open\s*\(", re.IGNORECASE), "Popup: window.open"),
    (re.compile(r"innerHTML\s*=", re.IGNORECASE), "DOM injection: innerHTML"),
    (re.compile(r"outerHTML\s*=", re.IGNORECASE), "DOM injection: outerHTML"),
    (re.compile(r"insertAdjacentHTML\s*\(", re.IGNORECASE), "DOM injection: insertAdjacentHTML"),
    (re.compile(r"eval\s*\(", re.IGNORECASE), "Code execution: eval()"),
    (re.compile(r"setTimeout\s*\(", re.IGNORECASE), "Code execution: setTimeout"),
    (re.compile(r"setInterval\s*\(", re.IGNORECASE), "Code execution: setInterval"),
    (re.compile(r"Function\s*\(", re.IGNORECASE), "Code execution: Function()"),

    # Common XSS payloads
    (re.compile(r"alert\s*\(", re.IGNORECASE), "XSS probe: alert()"),
    (re.compile(r"confirm\s*\(", re.IGNORECASE), "XSS probe: confirm()"),
    (re.compile(r"prompt\s*\(", re.IGNORECASE), "XSS probe: prompt()"),
    (re.compile(r"console\.log\s*\(", re.IGNORECASE), "XSS probe: console.log()"),

    # Data exfiltration
    (re.compile(r"fetch\s*\(", re.IGNORECASE), "Data exfiltration: fetch()"),
    (re.compile(r"XMLHttpRequest", re.IGNORECASE), "Data exfiltration: XHR"),
    (re.compile(r"new\s+Image\s*\(\s*\)", re.IGNORECASE), "Data exfiltration: Image beacon"),
    (re.compile(r"navigator\.sendBeacon", re.IGNORECASE), "Data exfiltration: sendBeacon"),

    # HTML5 vectors
    (re.compile(r"<svg[\s>]", re.IGNORECASE), "HTML5 SVG vector"),
    (re.compile(r"<iframe[\s>]", re.IGNORECASE), "HTML5 iframe injection"),
    (re.compile(r"<object[\s>]", re.IGNORECASE), "HTML5 object injection"),
    (re.compile(r"<embed[\s>]", re.IGNORECASE), "HTML5 embed injection"),
    (re.compile(r"<video[\s>]", re.IGNORECASE), "HTML5 video injection"),
    (re.compile(r"<audio[\s>]", re.IGNORECASE), "HTML5 audio injection"),
    (re.compile(r"<math[\s>]", re.IGNORECASE), "HTML5 MathML injection"),
    (re.compile(r"<details[\s>]", re.IGNORECASE), "HTML5 details injection"),
    (re.compile(r"<body\s+on", re.IGNORECASE), "Body tag event handler"),
    (re.compile(r"<img\s+src\s*=\s*['\"]?\s*x", re.IGNORECASE), "Broken image XSS vector"),

    # Encoded variants
    (re.compile(r"%3Cscript%3E", re.IGNORECASE), "Double URL encoded script"),
    (re.compile(r"&#x3C;script", re.IGNORECASE), "Hex entity encoded script"),
    (re.compile(r"\\u003cscript", re.IGNORECASE), "Unicode escaped script"),
    (re.compile(r"\\x3cscript", re.IGNORECASE), "Hex escaped script"),

    # vbscript (IE legacy)
    (re.compile(r"vbscript\s*:", re.IGNORECASE), "VBScript URI injection"),

    # Expression injection
    (re.compile(r"expression\s*\(", re.IGNORECASE), "CSS expression injection"),
    (re.compile(r"-moz-binding", re.IGNORECASE), "Firefox binding injection"),
]


# Main detector 

def detect(packets: list[dict]) -> list[dict]:
    alerts = []

    for pkt in packets:
        payload = pkt.get("payload")
        if not payload:
            continue

        for pattern, label in XSS_PATTERNS:
            match = pattern.search(payload)
            if match:
                alerts.append({
                    "alert":       "XSS Attack Detected",
                    "severity":    "CRITICAL",
                    "mitre":       "T1059.007",
                    "src_ip":      pkt.get("src_ip", "unknown"),
                    "dst_ip":      pkt.get("dst_ip", "unknown"),
                    "src_port":    pkt.get("src_port"),
                    "dst_port":    pkt.get("dst_port"),
                    "attack_type": label,
                    "matched":     match.group(0),
                    "timestamp":   pkt.get("timestamp", "unknown"),
                    "detail": (
                        f"XSS attempt from {pkt.get('src_ip')} → {pkt.get('dst_ip')}. "
                        f"Attack type: '{label}'. "
                        f"Matched: '{match.group(0)}'. MITRE T1059.007."
                    )
                })
                break  # One alert per packet

    return alerts