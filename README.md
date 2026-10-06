# Automated PCAP and Network Traffic Analysis Toolkit

Information Security Lab (ICT 3141) mini-project, B.Tech CCE 5th Semester, MIT Manipal.

A lightweight web tool that takes an uploaded PCAP file, parses packet metadata, stores it in SQLite, runs explainable rule-based security checks, and shows the findings on a dashboard.

## Team

| Name | Roll No | Module |
|---|---|---|
| Aanya Singhal | 08 | Threat detection rules, Flask dashboard, visualization, PDF report |
| Sanjai G | 19 | SQLite database design, storage, SQL queries, traffic statistics |
| Akshat Richhariya | 17 | PCAP parsing with PyShark/TShark, metadata extraction |

**Faculty:** Dr Adesh ND, Dr Chithra K

## Pipeline

Upload → Parse → Store → Detect → Visualize → Report

## Tech Stack

- **Parsing:** PyShark / TShark
- **Backend:** Python, Flask
- **Database:** SQLite (sqlite3)
- **Frontend:** HTML, Tailwind CSS, Chart.js
- **Test data:** Wireshark sample captures, PCAP-ATTACK

## Project Structure

## Detection Rules (planned)

- Port scan: one source IP contacts many distinct destination ports in a short window
- Brute-force: many connection attempts to a single port
- Volume anomaly: a host contributes a disproportionate share of traffic
- Suspicious ports: traffic on commonly abused ports
- DNS anomaly: unusually high DNS query counts

Rules use configurable thresholds and are indicators for investigation, not proof of malicious activity.

## Scope

Offline analysis of authorized PCAP files only. No live capture and no decryption of encrypted payloads.

## Status

Work in progress (Stage II progress evaluation).
