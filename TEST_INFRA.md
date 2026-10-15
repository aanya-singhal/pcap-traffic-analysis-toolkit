# Test Infrastructure Documentation (TEST_INFRA.md)

## 1. Overview & Test Architecture

The PCAP Traffic Analysis Toolkit test infrastructure provides an automated, reproducible, end-to-end verification framework structured directly around the **CIA Triad** (Confidentiality, Integrity, Authentication, Availability).

```
                                  Test Pipeline Architecture
                                  
  ┌──────────────────────────────┐                ┌──────────────────────────────┐
  │  tests/generate_test_pcaps.py│                │ samples/expected_findings.json│
  │  - Scapy Synthetic Generator │                │ - Ground Truth Rule Manifest │
  │  - Seeded, deterministic     │                │ - CIA Pillar Mappings        │
  └──────────────┬───────────────┘                └──────────────┬───────────────┘
                 │                                               │
                 ▼ (9 PCAPs)                                     │
  ┌──────────────────────────────┐                               │
  │          samples/            │                               │
  │ - normal_traffic.pcap        │                               │
  │ - cleartext_credentials.pcap │                               │
  │ - arp_spoofing.pcap          │                               │
  │ - tcp_evasion.pcap           │                               │
  │ - syn_flood.pcap             │                               │
  │ - brute_force_ssh.pcap       │                               │
  │ - port_scan.pcap             │                               │
  │ - volume_exfil.pcap          │                               │
  │ - dns_tunnel_c2.pcap         │                               │
  └──────────────┬───────────────┘                               │
                 │                                               │
                 └───────────────────────┬───────────────────────┘
                                         ▼
                         ┌──────────────────────────────┐
                         │   tests/run_evaluation.py    │
                         │   (Isolated 'eval.db' Store) │
                         ├──────────────────────────────┤
                         │ 1. PyShark Parsing           │
                         │ 2. Telemetry Ingestion       │
                         │ 3. Threat Rule Evaluation    │
                         │ 4. CIA Pillar Tag Validation │
                         │ 5. Confusion Matrix (TP/FP)  │
                         │ 6. Strict Assertions (TPR/FPR│
                         └──────────────┬───────────────┘
                                        ▼
                         ┌──────────────────────────────┐
                         │ docs/evaluation_results.md   │
                         │ - Benchmark & Accuracy Matrix│
                         │ - Pass/Fail Exit Code (0/1)  │
                         └──────────────────────────────┘
```

The test harness consists of three foundational components:

1. **Synthetic PCAP Generator (`tests/generate_test_pcaps.py`)**:
   - Crafts deterministic, reproducible packet captures using Scapy.
   - Combines a realistic baseline of normal browsing traffic (DNS queries, HTTP/HTTPS sessions, clean ARP resolutions, and orderly TCP handshakes) with isolated, mathematically precise attack patterns.
   - Outputs 9 distinct `.pcap` files into `samples/`.

2. **Ground Truth Manifest (`samples/expected_findings.json`)**:
   - Maintains the definitive authoritative mapping between each capture file, its expected rule detections, and its expected CIA Triad pillars.

3. **Evaluation Runner (`tests/run_evaluation.py`)**:
   - Executes the end-to-end ingestion, parsing, database storage, and threat detection pipeline on an isolated database (`eval.db`).
   - Computes confusion matrix metrics: True Positives (TP), False Positives (FP), False Negatives (FN), True Negatives (TN).
   - Validates that every detected security finding includes an explicit, valid CIA Triad pillar tag.
   - Exports comprehensive verification tables and performance metrics to `docs/evaluation_results.md`.
   - Programmatically asserts `tpr == 1.0` and `fpr == 0.0` and zero unhandled exceptions, enforcing exit code 0 on complete pass and exit code 1 on any failure.

---

## 2. Feature Inventory Coverage (Tiers 1–4)

The test harness comprehensively verifies the feature inventory across all four architectural tiers defined in `PROJECT.md`:

| Tier | Focus Area | Features Covered | Verification Mechanism |
|---|---|---|---|
| **Tier 1** | **Telemetry & Protocol Extraction** | • Link-layer Ethernet MAC extraction (`src_mac`, `dst_mac`)<br>• ARP frame parsing (`opcode`, IP-MAC mappings)<br>• Full TCP control flag decoding (`SYN`, `ACK`, `RST`, `FIN`, `PSH`, `URG`)<br>• Application-layer protocol parsing (HTTP Basic Auth Base64 decoding, HTTP POST form parameters, FTP `USER`/`PASS` commands, DNS queries/responses) | • Packet-level assertions in `run_evaluation.py`<br>• Database completeness verification (`stored / in_file` packet count) |
| **Tier 2** | **CIA Triad Threat Detection Rules** | • **Confidentiality**: Cleartext Credentials (HTTP/FTP), DNS Tunneling Covert Channel<br>• **Integrity**: ARP Cache Poisoning (conflicting MACs), TCP Protocol Evasion (Xmas & Null scans)<br>• **Authentication**: Credential Brute Force (SSH/FTP), Unauthorized Port Scanning<br>• **Availability**: TCP SYN Flood DoS, Abnormal Bandwidth Volume Spike | • Scenario-by-scenario evaluation against ground truth<br>• Strict rule confusion matrix (`TP`, `FP`, `FN`, `TN`)<br>• Sensitivity (`TPR`) and Fall-out (`FPR`) metrics |
| **Tier 3** | **Security Posture & Dashboard UI** | • Executive CIA Security Posture Score (0–100)<br>• Four Status Indicator Cards (Confidentiality, Integrity, Authentication, Availability)<br>• Cleartext evidence rendering in findings table<br>• Educational Viva Defense Guide embedding theoretical InfoSec concepts | • Validation that findings data model contains `pillar`, `severity`, and `evidence`<br>• Verification of pillar assignment validity across all findings |
| **Tier 4** | **E2E Integration & Verification** | • Zero unhandled runtime exceptions during bulk processing<br>• Complete regression prevention across all 9 scenarios<br>• Benchmark reporting (`s/MB`, processing throughput) | • Programmatic assertions in `tests/run_evaluation.py`<br>• Automated markdown generation in `docs/evaluation_results.md`<br>• Automated exit code reporting (0 = PASS, 1 = FAIL) |

---

## 3. Scenarios & Ground Truth Inventory

| Capture File | Attack Vector / Pattern | Expected Rules | Expected CIA Pillar | Target Telemetry Layer |
|---|---|---|---|---|
| `normal_traffic.pcap` | Baseline browsing: 4 clients, DNS queries, HTTP/HTTPS sessions, clean ARP handshakes | *(None)* | *(None)* | L2/L3/L4/L7 |
| `cleartext_credentials.pcap` | HTTP Basic Auth (`admin:Secret123`), HTTP POST password (`SuperSecretPassword123!`), FTP `USER ftpuser` & `PASS Hunter2` | `Cleartext Credentials` | `Confidentiality` | L7 (HTTP, FTP) |
| `arp_spoofing.pcap` | Conflicting ARP replies claiming gateway IP `192.168.1.1` from legitimate MAC (`02:...:01`) and attacker MAC (`02:...:99`) | `ARP Cache Poisoning` | `Integrity` | L2/L3 (ARP) |
| `tcp_evasion.pcap` | 15 Xmas scan packets (`FIN+PSH+URG`, `ack=0`, `syn=0`) + 15 Null scan packets (`flags=0`) to port 80 | `TCP Flag Evasion` | `Integrity` | L4 (TCP Control Flags) |
| `syn_flood.pcap` | Rapid burst of 80 unacknowledged TCP SYN packets (`flags="S"`, `ack=0`) to port 80 | `TCP SYN Flood` | `Availability` | L4 (TCP SYN/ACK ratio) |
| `brute_force_ssh.pcap` | 40 rapid connection attempts to SSH port 22 in 40s (exceeding threshold >=20) | `Brute Force` | `Authentication` | L4 (TCP Connection Rate) |
| `port_scan.pcap` | TCP SYN sweep across ports 1–300 (exceeding threshold >=15), touching Telnet port 23 | `Port Scan`, `Suspicious Port` | `Authentication` | L4 (TCP Port Diversity) |
| `volume_exfil.pcap` | Single host uploading 250 chunks of 1400 bytes (>50% of total capture bytes) | `Volume Anomaly` | `Availability` | L3/L4 (Bandwidth Share) |
| `dns_tunnel_c2.pcap` | 15 long queries (>50 chars), 120-query flood, 5 sessions to Metasploit port 4444 | `DNS Anomaly`, `Suspicious Port` | `Confidentiality` | L7 (DNS) & L4 (C2 Port) |

---

## 4. Pass / Fail Semantics

The evaluation runner enforces strict binary pass/fail criteria:

### Evaluation Metrics
- **True Positive (TP)**: An expected threat rule was correctly detected in a scenario where it was present.
- **False Positive (FP)**: A threat rule was detected in a scenario where it was not present.
- **False Negative (FN)**: An expected threat rule was not detected.
- **True Negative (TN)**: A threat rule was correctly absent in a scenario where it was not present.

### Programmatic Assertions
1. **True Positive Rate (TPR / Sensitivity)**:
   $$\text{TPR} = \frac{\text{TP}}{\text{TP} + \text{FN}} = 1.0 \quad (100\%)$$
   *Any missed threat results in an immediate failure.*

2. **False Positive Rate (FPR / Fall-out)**:
   $$\text{FPR} = \frac{\text{FP}}{\text{FP} + \text{TN}} = 0.0 \quad (0\%)$$
   *Any false alert results in an immediate failure.*

3. **Runtime Exception Invariance**:
   $$\text{unhandled\_exceptions} == 0$$
   *Any parser, database, or rule exception results in an immediate failure.*

4. **CIA Pillar Integrity**:
   $$\forall f \in \text{findings}, \quad \text{pillar}(f) \in \{\text{'Confidentiality'}, \text{'Integrity'}, \text{'Authentication'}, \text{'Availability'}\}$$
   *Any alert without a valid CIA pillar tag results in an immediate failure.*

### Exit Codes
- **Exit Code 0**: Full pass. 100% TPR, 0% FPR, 0 unhandled exceptions, 100% pillar integrity.
- **Exit Code 1**: Failure. Discrepancy detected in rules, pillars, or runtime errors.

---

## 5. Execution Instructions

### Generate Test Captures
```bash
./venv/bin/python tests/generate_test_pcaps.py
```
Builds all 9 reproducible captures in `samples/` and writes `samples/expected_findings.json`.

### Run Automated Verification Suite
```bash
./venv/bin/python tests/run_evaluation.py
```
Executes the full pipeline across all captures using `eval.db`, prints formatted metrics to the console, updates `docs/evaluation_results.md`, and exits with code 0 on pass.
