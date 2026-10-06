# Preliminary Evaluation Results

Labelled synthetic captures (normal background traffic + one known attack each), generated with `tests/generate_test_pcaps.py`. Evaluated per scenario x rule (5 rules x 5 captures).

| Capture | Expected | Detected | Result | Packets stored / in file | Size (MB) | Time (s) | s/MB |
|---|---|---|---|---|---|---|---|
| normal_traffic.pcap | none | none | PASS | 774 / 774 | 0.17 | 3.11 | 18.0 |
| port_scan.pcap | Port Scan, Suspicious Port | Port Scan, Suspicious Port | PASS | 1430 / 1430 | 0.23 | 1.61 | 7.1 |
| brute_force_ssh.pcap | Brute Force | Brute Force | PASS | 1036 / 1036 | 0.20 | 1.20 | 5.9 |
| volume_exfil.pcap | Volume Anomaly | Volume Anomaly | PASS | 1017 / 1017 | 0.52 | 1.22 | 2.3 |
| dns_tunnel_c2.pcap | DNS Anomaly, Suspicious Port | DNS Anomaly, Suspicious Port | PASS | 1106 / 1106 | 0.22 | 1.07 | 4.9 |

**TP=6, FP=0, FN=0, TN=19**

- True Positive Rate: **100%**
- False Positive Rate: **0%**
