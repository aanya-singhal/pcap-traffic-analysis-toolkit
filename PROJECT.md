# Project: PCAP Traffic Analysis Toolkit — CIA Triad Platform

## Architecture
The platform transforms raw network packet captures (PCAP/PCAPNG) into structured Information Security telemetry, evaluates attacks against formal security rules mapped to the CIA Triad (Confidentiality, Integrity, Authentication, Availability), computes an executive security posture score, and visualizes alerts alongside an academic viva guide.

```
                  ┌────────────────────────┐
                  │ Packet Capture (PCAP)  │
                  └───────────┬────────────┘
                              │
                              ▼
                  ┌────────────────────────┐
                  │   parser/pcap_parser   │  (PyShark / Asyncio / Linux Safe)
                  │  - MACs, ARP, TCP Flags│
                  │  - App: HTTP, FTP, DNS │
                  └───────────┬────────────┘
                              │
                              ▼
                  ┌────────────────────────┐
                  │     database/db.py     │  (SQLite Schema: packets, arp_records,
                  │  - Full Telemetry Store│   credentials, dns_queries, findings)
                  └───────────┬────────────┘
                              │
                              ▼
                  ┌────────────────────────┐
                  │   detection/rules.py   │  (CIA Threat Engine & Posture Scoring)
                  │  - C: Creds, DNS Tunnel│
                  │  - I: ARP MITM, TCP Eva│
                  │  - Auth: Scan, Brute   │
                  │  - Avail: SYN Flood,Vol│
                  └───────────┬────────────┘
                              │
               ┌──────────────┴──────────────┐
               ▼                             ▼
    ┌─────────────────────┐       ┌──────────────────────┐
    │ Web Dashboard (UI)  │       │  E2E Test Suite      │
    │ - Executive Score   │       │  - generate_pcaps.py │
    │ - 4 CIA Cards       │       │  - run_evaluation.py │
    │ - Findings & Evid.  │       │  - 100% TPR / 0% FPR │
    │ - Viva Defense Guide│       └──────────────────────┘
    └─────────────────────┘
```

---

## Feature Inventory
| # | Feature | Description | Milestone | Source |
|---|---------|-------------|-----------|--------|
| 1 | Full Telemetry Schema Persistence | Store MAC addresses, ARP records, full TCP flags (SYN, ACK, RST, FIN, PSH, URG), and credentials in SQLite. | M1 | Survey (R2) |
| 2 | Cleartext HTTP Basic Auth Detection | Extract and decode Base64 Authorization headers (RFC 7617) into credential evidence. | M2 | Survey (R1) |
| 3 | Cleartext HTTP POST Form Password Detection | Extract unencrypted passwords submitted in HTTP form bodies. | M2 | Survey (R1) |
| 4 | Cleartext FTP/Telnet Credential Detection | Intercept unencrypted USER/PASS commands on TCP 21 and Telnet sessions on TCP 23. | M2 | Survey (R1) |
| 5 | DNS Tunneling & Covert Exfiltration Detection | Flag high query length (>50 chars), entropy anomalies, or query bursts under Confidentiality. | M2 | Survey (R1) |
| 6 | ARP Cache Poisoning / MITM Detection | Flag conflicting MAC addresses claiming the same IPv4 address indicating cache poisoning. | M2 | Survey (R1) |
| 7 | TCP Protocol Evasion (Xmas Scan) | Detect illegal TCP flag combinations (FIN=1, PSH=1, URG=1, ACK=0, SYN=0) per RFC 793. | M2 | Survey (R1) |
| 8 | TCP Protocol Evasion (Null Scan) | Detect packets with all control flags set to 0 violating RFC 793 state machine. | M2 | Survey (R1) |
| 9 | Credential Brute-Force Detection | Flag >=20 connection attempts to authentication services (SSH:22, FTP:21, etc.) in 60s. | M2 | Survey (R1) |
| 10 | Unauthorized Port Scanning Detection | Flag single source contacting >=15 distinct ports within 60s under Authentication. | M2 | Survey (R1) |
| 11 | TCP SYN Flood DoS Detection | Flag high ratios of unacknowledged SYNs (>=50 SYNs and ratio >=3.0x) under Availability. | M2 | Survey (R1) |
| 12 | Abnormal Bandwidth Volume Anomaly | Flag single host responsible for >=50% total traffic in multi-host captures under Availability. | M2 | Survey (R1) |
| 13 | Executive CIA Security Posture Scoring | Compute bounded 0–100 overall score based on findings severity and pillar impacts. | M3 | Survey (R3) |
| 14 | Four CIA Status Indicator Cards | Render Pass/Warning/Fail cards for Confidentiality, Integrity, Authentication, Availability. | M3 | Survey (R3) |
| 15 | Enhanced Findings Table & Evidence Display | Display CIA pillar badges, severity badges, and cleartext monospace evidence snippets. | M3 | Survey (R3) |
| 16 | Educational Viva Defense Guide | Embed theoretical concepts, RFC citations, attack mechanics, and viva Q&A in dashboard. | M3 | Survey (R3) |
| 17 | Test Capture Generator with Ground Truth | Generate labelled synthetic PCAPs in `tests/generate_test_pcaps.py` covering all CIA scenarios. | T1 | Survey (R4) |
| 18 | Automated Verification Evaluation Suite | Benchmark runner in `tests/run_evaluation.py` asserting 100% TPR and 0% FPR with exit code 0. | T1 | Survey (R4) |
| 19 | Final E2E Integration & Coverage Hardening | Execute all E2E test tiers and perform adversarial coverage hardening. | M4 | Survey (R4) |

---

## Milestones

| # | Name | Scope | Dependencies | Status |
|---|------|-------|-------------|--------|
| M1 | Telemetry Persistence & Schema Unification | Extend `database/db.py` (`packets`, `arp_records`, `credentials`, `findings` schema) and connect `parser/pcap_parser.py` output. | none | DONE |
| M2 | CIA Triad Threat Detection Engine | Implement all 4 CIA pillar detectors in `detection/rules.py` with explicit `pillar` tags, thresholds, and evidence schemas. | M1 | DONE |
| M3 | CIA Posture Scoring & Educational Dashboard | Implement scoring logic in `app.py`, update `templates/dashboard.html` with Posture Score, 4 Status Cards, Findings badges, and Viva Guide. | M2 | DONE |
| T1 | E2E Testing Track: Harness & PCAP Generation | Build comprehensive test generator `tests/generate_test_pcaps.py`, `samples/expected_findings.json`, and `tests/run_evaluation.py` with strict TPR/FPR assertions. Publish `TEST_READY.md`. | none | DONE |
| M4 | Final Integration & Adversarial Verification | Run full E2E evaluation suite across all captures; assert 100% TPR / 0% FPR, run adversarial tests, and verify complete compliance. | M3, T1 | DONE |

---

## Interface Contracts

### 1. `parser/pcap_parser.py` ↔ `database/db.py`
`parse_pcap(path)` returns:
```python
{
    "packets": List[Dict]: {
        "timestamp": float, "src_ip": str, "dst_ip": str,
        "src_port": int, "dst_port": int, "transport": str,
        "protocol": str, "length": int,
        "src_mac": str, "dst_mac": str,
        "syn": bool, "ack": bool, "rst": bool,
        "fin": bool, "psh": bool, "urg": bool
    },
    "dns": List[Dict]: {"timestamp": float, "src_ip": str, "dst_ip": str, "query": str, "is_response": int},
    "http": List[Dict]: {"timestamp": float, "src_ip": str, "dst_ip": str, "method": str, "host": str, "uri": str, "user_agent": str},
    "arp": List[Dict]: {"timestamp": float, "src_ip": str, "dst_ip": str, "src_mac": str, "dst_mac": str, "opcode": str},
    "credentials": List[Dict]: {"timestamp": float, "src_ip": str, "dst_ip": str, "protocol": str, "type": str, "detail": str}
}
```
`db.insert_parsed(conn, analysis_id, parsed)` must insert into:
- `packets` table (including `src_mac`, `dst_mac`, `fin`, `psh`, `urg`)
- `arp_records` table
- `credentials` table
- `dns_queries` table
- `http_requests` table

### 2. `database/db.py` ↔ `detection/rules.py`
All finding dictionaries returned by `detection/rules.py` must adhere to:
```python
{
    "rule": str,              # e.g., "Cleartext Credentials", "ARP Cache Poisoning"
    "pillar": str,            # "Confidentiality" | "Integrity" | "Authentication" | "Availability"
    "severity": str,          # "High" | "Medium" | "Low"
    "src_ip": Optional[str],
    "dst_ip": Optional[str],
    "detail": str,            # Human-readable explanation with thresholds
    "evidence_count": int,    # Number of offending packets / records
    "evidence": str           # Decoded credential, offending MACs, flags, etc.
}
```
`db.save_findings(conn, analysis_id, findings)` stores `pillar` and `evidence`.

### 3. `detection/rules.py` ↔ `app.py`
Function `calculate_posture_score(findings: List[Dict]) -> Tuple[int, Dict[str, Dict]]`:
Returns:
- `overall_score`: integer `0–100`
- `pillar_cards`: dictionary keyed by `Confidentiality`, `Integrity`, `Authentication`, `Availability`:
  ```python
  {
      "status": "PASS" | "WARNING" | "FAIL",
      "score": int (0–25),
      "badge_color": str,
      "summary": str,
      "violations_count": int
  }
  ```

### 4. `tests/run_evaluation.py` Ground Truth Contract
`samples/expected_findings.json`:
```json
{
  "<capture_file>.pcap": {
    "expected_rules": ["<Rule Name>"],
    "expected_pillars": ["<Pillar Name>"]
  }
}
```
`run_evaluation.py` verifies both rule hits and pillar categorizations.

---

## Code Layout
- `parser/pcap_parser.py`: PyShark/TShark packet reading, link-layer, network, transport, application layer decoding.
- `database/db.py`: SQLite schema definition, insertion, querying, findings persistence.
- `detection/rules.py`: CIA Triad threat detection algorithms, threshold definitions, posture score calculation.
- `app.py`: Flask application, routes, posture and card aggregation, template rendering.
- `templates/base.html`, `templates/index.html`, `templates/dashboard.html`: Tailwind frontend views.
- `tests/generate_test_pcaps.py`: Scapy synthetic capture generators with exact ground truth.
- `tests/run_evaluation.py`: Automated verification suite asserting 100% TPR and 0% FPR.
