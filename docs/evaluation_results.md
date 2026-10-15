# E2E Automated Verification & Benchmark Results

Evaluates the CIA Triad threat detection engine against synthetic PCAP captures with known ground truth.

## 1. Executive Summary

- **Total Scenarios Evaluated**: 9
- **Evaluated Rules (9)**: ARP Cache Poisoning, Brute Force, Cleartext Credentials, DNS Anomaly, Port Scan, Suspicious Port, TCP Flag Evasion, TCP SYN Flood, Volume Anomaly
- **Evaluated Pillars (4)**: Confidentiality, Integrity, Authentication, Availability
- **Rule True Positive Rate (TPR)**: **100.0%**
- **Rule False Positive Rate (FPR)**: **0.0%**
- **Pillar TPR**: **100.0%** | **Pillar FPR**: **0.0%**
- **Unhandled Runtime Exceptions**: **0**
- **Pillar Tagging Integrity**: 100% Valid

## 2. Confusion Matrix (Rule Level)

| Metric | Value | Description |
|---|---|---|
| **True Positives (TP)** | 10 | Correctly triggered expected threat rules |
| **False Positives (FP)** | 0 | Spurious threat triggers on clean or unrelated traffic |
| **False Negatives (FN)** | 0 | Missed expected threats |
| **True Negatives (TN)** | 71 | Correctly suppressed benign rules |
| **Sensitivity / TPR** | 100.00% | Target: 100% |
| **Fall-out / FPR** | 0.00% | Target: 0% |

## 3. Scenario-by-Scenario Evaluation

| Capture File | Expected Rules | Detected Rules | Expected Pillars | Detected Pillars | Result | Packets Stored / In File | Size (MB) | Total Time (s) | s/MB |
|---|---|---|---|---|---|---|---|---|---|
| `normal_traffic.pcap` | *(None)* | *(None)* | *(None)* | *(None)* | **PASS** | 782 / 782 | 0.17 | 1.24 | 7.1 |
| `cleartext_credentials.pcap` | Cleartext Credentials | Cleartext Credentials | Confidentiality | Confidentiality | **PASS** | 862 / 862 | 0.19 | 1.34 | 7.1 |
| `arp_spoofing.pcap` | ARP Cache Poisoning | ARP Cache Poisoning | Integrity | Integrity | **PASS** | 822 / 822 | 0.18 | 1.21 | 6.7 |
| `tcp_evasion.pcap` | TCP Flag Evasion | TCP Flag Evasion | Integrity | Integrity | **PASS** | 848 / 848 | 0.18 | 1.44 | 7.8 |
| `syn_flood.pcap` | TCP SYN Flood | TCP SYN Flood | Availability | Availability | **PASS** | 916 / 916 | 0.19 | 1.55 | 8.0 |
| `brute_force_ssh.pcap` | Brute Force | Brute Force | Authentication | Authentication | **PASS** | 1071 / 1071 | 0.21 | 1.74 | 8.4 |
| `port_scan.pcap` | Port Scan, Suspicious Port | Port Scan, Suspicious Port | Authentication | Authentication | **PASS** | 1429 / 1429 | 0.22 | 2.41 | 10.7 |
| `volume_exfil.pcap` | Volume Anomaly | Volume Anomaly | Availability | Availability | **PASS** | 1052 / 1052 | 0.53 | 1.88 | 3.6 |
| `dns_tunnel_c2.pcap` | DNS Anomaly, Suspicious Port | DNS Anomaly, Suspicious Port | Confidentiality | Confidentiality | **PASS** | 1096 / 1096 | 0.22 | 1.66 | 7.7 |

---
*Report generated automatically by `tests/run_evaluation.py` on 2026-10-15 03:15:08 UTC.*
