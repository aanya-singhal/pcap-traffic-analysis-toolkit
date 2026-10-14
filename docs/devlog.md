# Development Log

## Progress against plan

| Phase | Planned | Status |
|---|---|---|
| 1. Requirements and workflow design | Week 1 | Done: scope, module split, repo structure |
| 2. PCAP parsing module | Week 2 | Done: IPs, ports, protocol, timestamps, TCP flags, DNS, HTTP |
| 3. SQLite storage pipeline | Week 3 | Done: packets, dns_queries, http_requests, findings, analyses tables |
| 4. Detection rules | Week 4 | Done: port scan, brute force, volume anomaly, suspicious ports, DNS anomaly |
| 5. Flask dashboard | Week 5 | Ahead of plan: upload page + dashboard working |
| 6. Visualization and reporting | Week 6 | Partly ahead: 4 Chart.js charts done; PDF export pending |
| 7. Testing and evaluation | Week 7 | Started early: labelled synthetic captures + evaluation script |
| 8–9. Documentation, integration, demo | Weeks 8–9 | In progress |
| Extension: live capture demo | beyond plan | Done: Dockerized 3-container demo catches an attacker live |

## Issues encountered and how they were resolved

### 1. PyShark failed inside Flask request threads
- **Problem:** PyShark uses asyncio internally; Flask handles requests in worker threads that have no event loop.
- **Fix:** The parser creates a fresh event loop (`asyncio.new_event_loop()`) before opening each capture.

### 2. TShark flag values differ between versions
- **Problem:** TCP/DNS flags are reported as `1`/`0` on some TShark versions and `True`/`False` on others.
- **Fix:** A `_flag()` helper normalises both formats so the SYN/ACK logic is version-independent.

### 3. Port 5000 already in use on macOS
- **Problem:** macOS AirPlay Receiver occupies port 5000, so Flask could not start.
- **Fix:** App runs on port 5001.

### 4. TShark installation via Homebrew was very slow
- **Problem:** `brew install wireshark` spent a long time fetching and building dependencies.
- **Fix:** Installed the official Wireshark macOS disk image instead; PyShark detects the bundled TShark automatically.

### 5. "Top destination ports" chart showed random high ports
- **Problem:** Reply packets carry the client's ephemeral source port as their destination port, so ports like 47707 and 64983 dominated the chart.
- **Root cause:** Counting every packet's destination port mixes requests with replies.
- **Fix:** Only connection-initiating packets are counted (TCP SYN without ACK, and UDP sent to the lower-numbered port). The chart now shows real targeted services (53, 443, 80, scanned ports).

### 6. No ground truth for testing
- **Problem:** Public captures do not always state exactly which attacks are present, making TPR/FPR hard to measure.
- **Fix:** Wrote `tests/generate_test_pcaps.py` (Scapy) to build labelled captures: normal background traffic plus one known attack each, with expected findings saved to `samples/expected_findings.json`. `tests/run_evaluation.py` scores the rules automatically.

### 7. Avoiding false positives in brute-force and volume rules
- **Problem:** Normal browsing makes many connections to 443, and tiny captures make one host look "dominant".
- **Fix:** Brute-force is limited to login-service ports (SSH, FTP, RDP, SMB, etc.); volume anomaly requires at least 100 packets and 3 hosts.

### 8. Extending to live capture without touching the upload flow
- **Goal:** Demonstrate detection on real-time traffic, not just uploaded files, while keeping the offline workflow intact.
- **Design:** Added `parser.capture_to_file()` which uses TShark to sniff an interface for a fixed window and write a PCAP, then reused the *existing* parse → store → detect pipeline on it (refactored the shared steps into `_analyse_pcap()` so upload and `/capture` are identical downstream). Nothing downstream knows whether a capture came from a file or the wire.
- **Demo:** `docker-compose.yml` runs three containers on one isolated bridge network — `receiver` (dashboard + victim, captures its own `eth0`), `attacker` (nmap scan + SSH brute-force burst), and `client` (normal web baseline). `docker compose up`, click "Capture live traffic", and the attacker is caught within the window.
- **Safety:** All traffic targets our own receiver on a private network; nothing leaves the host. The capture button is shown only when TShark is present.
- **Verification:** End-to-end tested by capturing live loopback traffic while running the same nmap scan/brute-force locally — 494 packets captured, correctly flagged Port Scan, Brute Force and Suspicious Port (4444/31337).
- **Scope note:** The synopsis listed live capture as out of scope; this is a deliberate extension beyond the planned milestones, documented as such.

## Known limitations / next steps
- Current evaluation uses synthetic captures, so 100% TPR mainly validates correctness of the rules. Next: evaluate on public datasets (Wireshark samples, PCAP-ATTACK).
- PyShark parsing is the bottleneck (~2–18 s/MB). Larger captures may need a TShark field-export approach.
- PDF summary report export.
- Thresholds are fixed in code; could be made editable from the dashboard.

## Feature: Cleartext credential exposure detection

Added a sixth detection capability that recovers login credentials sent without encryption, a direct demonstration of why encrypted protocols matter.

- **`detection/credentials.py`** reads raw TCP payloads with scapy (independent of the PyShark parser, so it needs no TShark) and extracts credentials from HTTP Basic Auth (`Authorization: Basic ...`), HTTP POST login forms (`username=...&password=...`), and FTP (`USER`/`PASS` on port 21).
- Each disclosed login is reported as a **High-severity "Credential Exposure" finding** and shown in a highlighted panel on the dashboard, with the recovered username and password.
- **`tests/generate_credential_pcap.py`** builds a safe sample capture (`samples/credential_leak.pcap`) with three cleartext logins using invented credentials.
- Design choice: credential extraction reuses the existing finding schema (no DB change) and runs inside the same parse -> store -> detect pipeline, so the upload and live-capture flows both pick it up automatically.
