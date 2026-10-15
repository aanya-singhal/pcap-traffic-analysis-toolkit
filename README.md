# Automated PCAP and Network Traffic Analysis Toolkit: CIA Triad Platform

Information Security Lab (ICT 3141) mini-project, B.Tech CCE 5th Semester, MIT Manipal.

A comprehensive network traffic analysis and threat detection platform structured around the **CIA Triad** (Confidentiality, Integrity, Authentication, Availability). The toolkit ingests network packet captures (PCAP/PCAPNG), extracts link-layer and application telemetry with PyShark, stores records in SQLite, evaluates attacks against formal security rules, computes an executive **CIA Security Posture Score (0–100)**, and provides an interactive web dashboard with an in-app viva defense guide.

![Dashboard: port scan findings](docs/screenshots/01_port_scan_findings.png)

## Team

| Name | Roll No | Module |
|---|---|---|
| Aanya Singhal | 08 | Threat detection rules, Flask dashboard, CIA Posture Scoring, visualization |
| Sanjai G | 19 | SQLite database design, schema migrations, SQL queries, traffic statistics |
| Akshat Richhariya | 17 | PCAP parsing with PyShark/TShark, MAC/ARP & full TCP flag extraction |

**Faculty:** Dr Adesh ND, Dr Chithra K

## Pipeline

**Upload / Capture → Parse → Store → CIA Detection Engine → Posture Scoring → Dashboard & Viva Guide**

| Stage | Implementation |
|---|---|
| Upload | Flask upload form (`.pcap`, `.pcapng`, `.cap`, max 50 MB) + live-capture mode |
| Parse | `parser/pcap_parser.py`: PyShark extracts IPs, MACs, ports, protocols, timestamps, TCP flags (SYN/ACK/RST/FIN/PSH/URG), DNS queries, HTTP bodies/headers, ARP frames |
| Store | `database/db.py`: SQLite tables `packets`, `dns_queries`, `http_requests`, `arp_entries`, `credentials`, `findings`, `analyses` |
| Detect | `detection/rules.py`: CIA Triad detection engine classifying threats into Confidentiality, Integrity, Authentication, and Availability |
| Score | `database/db.py`: Dynamic Executive CIA Security Posture Score (0–100) and 4 Triad status cards (Pass/Warning/Fail) |
| Visualize | `templates/dashboard.html`: Executive score banner, 4 CIA cards, findings table with cleartext evidence, 4 Chart.js charts, and in-app Viva Defense Guide |

## Detection Rules by CIA Triad Pillar

| Pillar | Rule | Logic & RFC Citations | Default Threshold |
|---|---|---|---|
| 🔒 **Confidentiality** | **Cleartext Credentials** | Extracts decoded HTTP Basic Auth (RFC 7617), plaintext form POST passwords, and unencrypted FTP `USER`/`PASS` commands | Any occurrence |
| 🔒 **Confidentiality** | **DNS Anomaly** | Long queried domain names (>50 chars) or query volume bursts (>100 queries) indicating covert DNS exfiltration | 100 queries / 50 chars |
| 🛡️ **Integrity** | **ARP Cache Poisoning** | Multiple physical MAC addresses claiming the same IPv4 address (Man-in-the-Middle positioning) | >1 MAC per IP |
| 🛡️ **Integrity** | **TCP Flag Evasion** | Illegal TCP control flag combinations violating RFC 793 state machine (Xmas scan: FIN+PSH+URG; Null scan: 0 flags) | Any occurrence |
| 🔑 **Authentication** | **Brute Force** | Rapid repeated connection attempts against login services (SSH:22, FTP:21, Telnet:23, RDP:3389, etc.) | 20 attempts / 60 s |
| 🔑 **Authentication** | **Port Scan** | Single source transmitting TCP SYN packets across multiple distinct destination ports (reconnaissance) | 15 ports / 60 s |
| 🔑 **Authentication** | **Suspicious Port** | Traffic contacting known backdoor or cleartext ports (4444, 31337, 12345, 23, 6667) | Any occurrence |
| ⚡ **Availability** | **TCP SYN Flood** | Excessive unacknowledged SYN packets without completing the 3-way handshake (DoS resource exhaustion) | ≥50 SYNs & ratio ≥3.0 |
| ⚡ **Availability** | **Volume Anomaly** | Single host dominating network throughput in multi-host captures | ≥50% bytes (min 100 pkts, 3 hosts) |

Every finding states the CIA pillar, severity, source and destination IPs, threshold used, and concrete packet evidence.

## Setup and Run

Requires Python 3.10+ and TShark (Wireshark).

```bash
git clone https://github.com/aanya-singhal/pcap-traffic-analysis-toolkit.git
cd pcap-traffic-analysis-toolkit
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python app.py
```

Open http://127.0.0.1:5001 and upload a capture (sample files are in `samples/`).

## Testing and Evaluation Benchmark

```bash
python tests/generate_test_pcaps.py   # builds 9 labelled ground-truth captures in samples/
python tests/run_evaluation.py        # runs the full pipeline across all 9 captures
```

Each capture contains realistic normal background traffic (4 hosts browsing over HTTP/HTTPS with DNS) plus one targeted attack. Expected findings and pillar mappings are stored in `samples/expected_findings.json`.

| Capture File | Expected Threat | Expected Pillar | Detected Threat | Result | Packets Stored / In File |
|---|---|---|---|---|---|
| `normal_traffic.pcap` | *(None)* | *(None)* | *(None)* | **PASS** | 782 / 782 (100%) |
| `cleartext_credentials.pcap` | Cleartext Credentials | Confidentiality | Cleartext Credentials | **PASS** | 862 / 862 (100%) |
| `arp_spoofing.pcap` | ARP Cache Poisoning | Integrity | ARP Cache Poisoning | **PASS** | 822 / 822 (100%) |
| `tcp_evasion.pcap` | TCP Flag Evasion | Integrity | TCP Flag Evasion | **PASS** | 848 / 848 (100%) |
| `syn_flood.pcap` | TCP SYN Flood | Availability | TCP SYN Flood | **PASS** | 916 / 916 (100%) |
| `brute_force_ssh.pcap` | Brute Force | Authentication | Brute Force | **PASS** | 1071 / 1071 (100%) |
| `port_scan.pcap` | Port Scan, Suspicious Port | Authentication | Port Scan, Suspicious Port | **PASS** | 1429 / 1429 (100%) |
| `volume_exfil.pcap` | Volume Anomaly | Availability | Volume Anomaly | **PASS** | 1052 / 1052 (100%) |
| `dns_tunnel_c2.pcap` | DNS Anomaly, Suspicious Port | Confidentiality | DNS Anomaly, Suspicious Port | **PASS** | 1096 / 1096 (100%) |

- **Rule True Positive Rate (TPR):** **100.0%** (10/10) · **Rule False Positive Rate (FPR):** **0.0%** (0/71)
- **Pillar Accuracy:** **100.0%** (8/8) · **Database Completeness:** **100.0%** of packets stored
- **Unit & Adversarial Hardening Suite:** 38 / 38 tests passing (`tests/test_boundary_stress.py`, `tests/test_adversarial_hardening.py`)
- Full evaluation benchmark table: [docs/evaluation_results.md](docs/evaluation_results.md).

## Live Capture Demo (extension beyond planned scope)

The original synopsis scoped the toolkit to **offline analysis of uploaded PCAP files only**. As an extension, we added an optional live-capture mode and a fully reproducible, self-contained demo that catches an attacker **in real time** on a private Docker network. This exercises the same parse → store → detect → visualize pipeline on traffic sniffed from the wire instead of a file; the upload flow is unchanged.

The demo brings up three containers on one isolated bridge network:

| Container | Role |
|---|---|
| `receiver` | Runs the dashboard **and** is the victim; captures its own interface with TShark |
| `attacker` | Loops an nmap SYN port scan (incl. backdoor ports 4444 / 31337) and an SSH brute-force burst against the receiver |
| `client` | Loops normal web requests to the receiver, providing a benign baseline |

```bash
docker compose up --build
# open http://localhost:5001  ->  click "Capture live traffic (20s)"
# view logs from all 3 containers:
./view_logs.sh
```

After ~20 s the dashboard shows the attacker's scan and brute-force **caught live** — Port Scan, Brute Force and Suspicious Port findings — standing out against the client's normal traffic. Everything targets our own receiver on an isolated network; nothing leaves the host.

Live capture requires TShark and permission to read the interface, so the button appears only when TShark is available (always true inside the `receiver` container). The capture interface and window are configurable via `CAPTURE_IFACE` and `CAPTURE_SECONDS`.

## Screenshots

| | |
|---|---|
| ![Traffic timeline](docs/screenshots/02_traffic_timeline.png) | ![Protocols and top talkers](docs/screenshots/03_protocols_top_talkers.png) |
| ![Ports and DNS](docs/screenshots/04_ports_dns.png) | ![Rules and thresholds](docs/screenshots/05_rules_thresholds.png) |

## Project Structure
app.py Flask app and pipeline orchestration
parser/pcap_parser.py PCAP parsing and field extraction
database/db.py SQLite schema, inserts and traffic-statistics queries
detection/rules.py Rule-based detection engine
templates/ Upload page and dashboard
samples/ Labelled test captures + expected findings
tests/ Test capture generator and evaluation script
docs/ Development log, evaluation results, screenshots
Dockerfile App image (Python + TShark) for the live-capture demo
docker-compose.yml Three-container live-capture demo (receiver / attacker / client)
docker/ Attacker + client scripts and their image


## Progress (Stage II)

Weeks 1–4 of the plan are complete (scope, parsing, storage, detection rules), and the Week 5 dashboard is already working. See [docs/devlog.md](docs/devlog.md) for progress against plan, issues encountered and how they were resolved.

**Next:** PDF report export, evaluation on public datasets, configurable thresholds from the UI.

## Scope

The core toolkit performs offline analysis of authorized PCAP files; it does not decrypt encrypted payloads. The synopsis originally listed live capture as out of scope — we have since **extended beyond that plan** with the optional Docker-based live-capture demo above, which captures only our own receiver container on an isolated private network. The upload-only workflow remains the primary, always-available path.
