<div align="center">

# 🛡️ NetWatchman

### Network Intrusion Detection System

[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Flask-3.1-000000?style=for-the-badge&logo=flask&logoColor=white)](https://flask.palletsprojects.com/)
[![Scapy](https://img.shields.io/badge/Scapy-2.6-009639?style=for-the-badge)](https://scapy.net/)
[![License](https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge)](LICENSE)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-FF0000?style=for-the-badge)](https://attack.mitre.org/)

**A Python-based modular NIDS with 16 independent attack detectors, a live web dashboard,
real-time SSE streaming, PCAP analysis, and full MITRE ATT&CK framework mapping.**

</div>

---

## 📋 Table of Contents

- [Overview](#-overview)
- [Features](#-features)
- [Architecture](#-architecture)
- [The 16 Detectors](#-the-16-detectors)
- [Dashboard](#-dashboard)
- [Installation](#-installation)
- [Usage](#-usage)
- [Project Structure](#-project-structure)
- [Tech Stack](#-tech-stack)
- [MITRE ATT&CK Coverage](#-mitre-attck-coverage)
- [License](#-license)

---

## 🔍 Overview

NetWatchman is a fully functional, Python-based Network Intrusion Detection System built from the ground up as a university-level cybersecurity project. It analyses pre-recorded PCAP network captures and replays them live through a Flask-powered web dashboard — enabling security analysts to inspect, classify, and export detected threats in real time.

Every alert is structured as a JSON object containing severity classification, IP pair, ports, a human-readable description, timestamp, and a direct MITRE ATT&CK technique mapping.

---

## ✨ Features

### 🔬 Detection Engine
- **16 independent attack detectors** — each in its own module, each with a single responsibility
- **Stateful detection** using sliding time windows and per-IP tracking dictionaries
- **Signature-based detection** for web application attacks (SQLi, XSS, directory traversal)
- **Live threat intelligence** via the Emerging Threats open IP blocklist
- **5 severity levels** — CRITICAL, HIGH, MEDIUM, LOW, INFO

### 📊 Web Dashboard
- **PCAP Analyzer mode** — upload and analyse an entire capture file at once
- **Live Replay mode** — stream alerts in real time via Server-Sent Events (SSE)
- **5-level speed control** slider for replay (Slow → Fastest)
- **7 severity summary cards** — Total, Packets, Critical, High, Medium, Low, Info
- **Donut + Bar charts** powered by Chart.js
- **Filter toolbar** — 6 severity filter buttons + live search box
- **Slide-in detail panel** — MITRE ATT&CK context, extra fields, raw JSON inspector
- **Message chip system** — inline MITRE chips, matched-credential chips
- **Empty state** for clean PCAPs ("No Threats Detected")
- **Detector warning section** for runtime detector failures

### 💾 Persistence & Export
- **Auto-save every scan** to SQLite — no manual save required
- **Scan History tab** — reload, compare, and delete past scans
- **History count badge** + **Clear All** button
- **PDF export** — styled dark-themed report via ReportLab
- **CSV export** — analyst-ready flat file for SIEM import

### 🎨 Design
- Dark cybersecurity aesthetic
- **IBM Plex Mono** (monospace elements) + **Oxanium** (headings) typography
- Animated live indicator dot (LIVE → COMPLETE → STOPPED)
- Colour-coded severity borders, badges, and filter buttons

---

## 🏗️ Architecture

```
PCAP File Upload
      │
      ▼
sniffer.py ──── Scapy rdpcap() — raw packet extraction
      │
      ▼
parser.py ───── Structured packet dictionaries
      │
      ▼
main.py ──────── Orchestrates all 16 detectors sequentially
      │
      ▼
JSON Alert Stream
      │
      ▼
dashboard/app.py ── Flask REST API + SSE streaming
      │
      ├── dashboard.html ── Chart.js, chips, filter toolbar, detail panel
      ├── db.py ──────────── SQLite auto-save + history
      └── export_utils.py ── ReportLab PDF + CSV
```

---

## 🔎 The 16 Detectors

| # | Detector | Protocol | MITRE ID | Max Severity |
|---|---|---|---|---|
| 1 | Port Scan | TCP | T1046 | HIGH |
| 2 | ARP Spoofing | ARP | T1557.002 | CRITICAL |
| 3 | SSH Brute Force | TCP/22 | T1110.001 | CRITICAL |
| 4 | FTP Brute Force | TCP/21 | T1110.001 | CRITICAL |
| 5 | SYN Flood | TCP | T1498.001 | CRITICAL |
| 6 | ICMP Flood | ICMP | T1498 | CRITICAL |
| 7 | DNS Spoofing | UDP/53 | T1557 | CRITICAL |
| 8 | Cleartext Credentials | TCP | T1040 | HIGH |
| 9 | Directory Traversal | HTTP | T1083 | HIGH |
| 10 | Malicious IP | Any | T1071.001 | CRITICAL |
| 11 | Service Version Detection | TCP | T1590.004 | MEDIUM |
| 12 | SQL Injection | HTTP | T1190 | CRITICAL |
| 13 | Telnet Detection | TCP/23 | T1021.004 | HIGH |
| 14 | Cross-Site Scripting (XSS) | HTTP | T1190 | CRITICAL |
| 15 | Suspicious User Agents | HTTP | T1595.002 | HIGH |
| 16 | Large Data Transfer | TCP/UDP | T1048 | HIGH |

---

## 📱 Dashboard

### PCAP Analyzer Tab
Upload a `.pcap`, `.pcapng`, or `.cap` file and get instant results:
- Severity summary cards update immediately
- Donut chart shows severity distribution
- Bar chart shows alerts per detector
- Click any row to open the slide-in detail panel with full MITRE context and raw JSON

### Live Replay Tab
Watch alerts stream in as packets are processed:
- Animated LIVE indicator → COMPLETE / STOPPED
- Real-time progress bar + packet counter (`Packets: X / Y`)
- Live alert count ticker (`Alerts detected: X`)
- New alerts **prepend to the top** of the table (newest first)
- Adjustable speed (Slow to Fastest)
- Stop button cancels the replay mid-stream

### Scan History Tab
Every scan is auto-saved to SQLite:
- Browse past scans with severity breakdowns
- Click any entry to reload full results into the dashboard
- A dismissable **history banner** appears when viewing archived data
- Delete individual entries or **Clear All** history at once

---

## ⚙️ Installation

### Prerequisites
- Python 3.10+
- pip
- A virtual environment (recommended)

### Steps

```bash
# 1. Clone the repository
git clone https://github.com/YOUR_USERNAME/netwatchman.git
cd netwatchman

# 2. Create and activate virtual environment
python -m venv venv

# Windows
venv\Scripts\activate

# macOS / Linux
source venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Create your .env file
cp .env.example .env
# Then edit .env and add your AbuseIPDB API key (optional)
```

---

## 🚀 Usage

### Run the Dashboard

```bash
cd dashboard
python app.py
```

Then open your browser at: **http://127.0.0.1:5000**

### Analyse a PCAP from the Terminal

```bash
python main.py path/to/your/capture.pcap
```

Alerts will be printed as JSON to stdout.

### Run a Single Detector (for testing)

```bash
python -c "
from scapy.all import rdpcap
from parser import parse_packet
from detectors import port_scan

packets = [parse_packet(p) for p in rdpcap('pcap_samples/port_scan.pcap')]
alerts = port_scan.detect(packets)
for a in alerts:
    print(a)
"
```

---

## 📁 Project Structure

```
netwatchman/
├── detectors/                   # 16 independent attack detector modules
│   ├── __init__.py
│   ├── port_scan.py
│   ├── arp_spoof.py
│   ├── ssh_brute.py
│   ├── ftp_brute.py
│   ├── syn_flood.py
│   ├── icmp_flood.py
│   ├── dns_spoof.py
│   ├── cleartext_creds.py
│   ├── dir_traversal.py
│   ├── malicious_ip.py
│   ├── service_version.py
│   ├── sql_injection.py
│   ├── telnet.py
│   ├── xss.py
│   ├── suspicious_agents.py
│   └── large_transfer.py
│
├── dashboard/                   # Flask web application
│   ├── app.py                   # Flask server + all API routes
│   ├── db.py                    # SQLite scan history layer
│   ├── export_utils.py          # ReportLab PDF + CSV export engine
│   ├── netwatchman_history.db   # Auto-created SQLite database (gitignored)
│   ├── static/
│   │   └── style.css            # Dark cybersecurity theme stylesheet
│   └── templates/
│       └── dashboard.html       # Single-page web UI
│
├── pcap_samples/                # Test PCAP files used during development
│
├── output/
│   └── reports/                 # Generated PDF/CSV exports
│
├── sniffer.py                   # PCAP file reader (Scapy rdpcap)
├── parser.py                    # Raw packet → structured dict converter
├── main.py                      # CLI detector orchestrator entry point
├── alert_manager.py             # Alert deduplication + MITRE enrichment
├── mitre.py                     # MITRE ATT&CK technique lookup helper
├── enrichment.py                # AbuseIPDB threat intelligence integration
├── requirements.txt
├── .env.example                 # Template for API keys
├── .gitignore
└── README.md
```

---

## 🛠️ Tech Stack

| Component | Technology |
|---|---|
| Packet ingestion | Scapy (`rdpcap`) |
| Web server | Flask |
| Frontend charts | Chart.js |
| Typography | IBM Plex Mono + Oxanium |
| Persistence | SQLite3 |
| PDF export | ReportLab |
| CSV export | Python `csv` module |
| Threat feed | Emerging Threats open blocklist |
| SSE streaming | Flask `Response` + generator |

---

## 🎯 MITRE ATT&CK Coverage

NetWatchman's 16 detectors span **9 MITRE ATT&CK Enterprise tactics**:

| Tactic | Detectors |
|---|---|
| TA0043 Reconnaissance | Service Version Detection, Suspicious User Agents |
| TA0001 Initial Access | SQL Injection, XSS |
| TA0006 Credential Access | ARP Spoofing, SSH Brute Force, FTP Brute Force, Cleartext Credentials |
| TA0007 Discovery | Port Scan, Directory Traversal |
| TA0008 Lateral Movement | Telnet Detection |
| TA0009 Collection | DNS Spoofing |
| TA0010 Exfiltration | Large Data Transfer |
| TA0011 Command & Control | Malicious IP |
| TA0040 Impact | SYN Flood, ICMP Flood |

---

## ⚠️ Disclaimer

NetWatchman is built for **academic and educational purposes only**. All PCAP files used for testing were sourced from publicly available repositories or synthesised in controlled lab environments. Do not use this tool against networks you do not own or have explicit written permission to test.

---

## 📄 License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.

---

<div align="center">
Built with Python · Flask · Scapy · Chart.js · ReportLab · SQLite
</div>
