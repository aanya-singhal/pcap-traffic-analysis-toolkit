"""
Rule-based threat detection over the SQLite packet records structured around the CIA Triad.
Module owner: Aanya Singhal

Every rule is explainable: it reports which hosts triggered it, the threshold used,
and how much evidence was seen. Findings are indicators for investigation, mapped
to one of the four foundational CIA Triad pillars:
- Confidentiality: Unencrypted credentials, sensitive data leaks, DNS tunneling / covert channels.
- Integrity: ARP cache poisoning (MITM), TCP protocol evasion (Xmas, Null scans).
- Authentication: Credential brute-force bursts, unauthorized port reconnaissance.
- Availability: Denial-of-Service (TCP SYN floods, abnormal bandwidth volume spikes).
"""
from collections import defaultdict

# All thresholds are configurable here
THRESHOLDS = {
    "port_scan_min_ports": 15,        # distinct destination ports...
    "port_scan_window_s": 60,         # ...contacted within this many seconds
    "brute_force_min_attempts": 20,   # connection attempts to one service...
    "brute_force_window_s": 60,       # ...within this many seconds
    "brute_force_ports": [21, 22, 23, 25, 110, 143, 445, 3306, 3389, 5900],
    "volume_share": 0.5,              # one host sending >= 50% of all bytes
    "volume_min_packets": 100,        # ignore tiny captures
    "volume_min_hosts": 3,            # ignore captures with only 1-2 hosts
    "dns_max_queries_per_host": 100,  # DNS queries from a single host
    "dns_long_query_len": 50,         # very long domain names (possible tunneling)
    "syn_flood_min_syns": 50,         # minimum unacknowledged SYNs for SYN flood
    "syn_flood_ratio": 3.0,           # unacknowledged SYN to ACK ratio threshold
    "tcp_evasion_min_packets": 1,     # minimum illegal flag packets to flag evasion
    "arp_spoofing_min_macs": 2,       # distinct MACs claiming same IP
}

# (Description, Severity, CIA Pillar)
SUSPICIOUS_PORTS = {
    23: ("Telnet (cleartext remote login)", "Medium", "Authentication"),
    4444: ("Metasploit default listener", "High", "Confidentiality"),
    6667: ("IRC (common botnet C2 channel)", "Medium", "Confidentiality"),
    31337: ("Back Orifice / 'elite' backdoor port", "High", "Integrity"),
    12345: ("NetBus trojan", "High", "Integrity"),
    5555: ("Android ADB over network", "Medium", "Authentication"),
    1337: ("Common backdoor/test port", "Low", "Integrity"),
}

RULE_DESCRIPTIONS = {
    "Cleartext Credentials": "Unencrypted authentication credentials (HTTP Basic Auth, form submissions, FTP commands) transmitted in plaintext, violating Confidentiality.",
    "ARP Cache Poisoning": "Conflicting MAC addresses claiming the same IPv4 address, indicative of ARP spoofing and Man-in-the-Middle positioning, violating Integrity.",
    "TCP Flag Evasion": "Illegal TCP control flag combinations (Xmas: FIN+PSH+URG, Null: no flags) violating RFC 793 protocol state machine for firewall/IDS evasion, violating Integrity.",
    "TCP SYN Flood": "High volume of unacknowledged TCP SYN packets overwhelming connection state queues (half-open socket backlog exhaustion), violating Availability.",
    "Brute Force": "Repeated connection attempts to an authentication service (SSH, FTP, RDP) within a short window attempting unauthorized credential discovery, violating Authentication.",
    "Port Scan": "Reconnaissance probes across multiple destination ports on a target host within a short window, violating Authentication.",
    "Suspicious Port": "Traffic to well-known backdoor, trojan, botnet C2, or legacy cleartext service ports.",
    "Volume Anomaly": "A single host responsible for a disproportionate volume of total network traffic (exfiltration or bandwidth exhaustion), violating Availability.",
    "DNS Anomaly": "Unusually high DNS query volume or abnormally long query strings indicative of DNS tunneling or covert channel communication, violating Confidentiality.",
}


# ---------- Helpers ----------

def _max_distinct_in_window(events, window):
    """events: sorted list of (timestamp, port). Max distinct ports seen in any window."""
    counts = defaultdict(int)
    left = best = 0
    for ts, port in events:
        counts[port] += 1
        while ts - events[left][0] > window:
            old = events[left][1]
            counts[old] -= 1
            if counts[old] == 0:
                del counts[old]
            left += 1
        best = max(best, len(counts))
    return best


def _max_count_in_window(timestamps, window):
    """timestamps: sorted list. Max number of events in any window."""
    left = best = 0
    for right, ts in enumerate(timestamps):
        while ts - timestamps[left] > window:
            left += 1
        best = max(best, right - left + 1)
    return best


# ---------- Authentication Pillar Rules ----------

def detect_port_scan(conn, aid, t=THRESHOLDS):
    rows = conn.execute(
        """SELECT src_ip, dst_ip, dst_port, timestamp FROM packets
           WHERE analysis_id = ? AND transport = 'TCP' AND syn = 1 AND ack = 0
                 AND src_ip IS NOT NULL
           ORDER BY src_ip, dst_ip, timestamp""",
        (aid,),
    ).fetchall()

    groups = defaultdict(list)
    for r in rows:
        groups[(r["src_ip"], r["dst_ip"])].append((r["timestamp"], r["dst_port"]))

    findings = []
    for (src, dst), events in groups.items():
        peak = _max_distinct_in_window(events, t["port_scan_window_s"])
        if peak >= t["port_scan_min_ports"]:
            total_ports = len({p for _, p in events})
            findings.append({
                "rule": "Port Scan",
                "pillar": "Authentication",
                "severity": "High" if peak >= 100 else "Medium",
                "src_ip": src,
                "dst_ip": dst,
                "detail": (f"{src} sent SYN packets to {peak} distinct ports on {dst} within "
                           f"{t['port_scan_window_s']}s ({total_ports} ports in total). "
                           f"Threshold: {t['port_scan_min_ports']} ports."),
                "evidence_count": len(events),
                "evidence": f"SYN scan to {total_ports} ports on {dst} (peak {peak} distinct ports in {t['port_scan_window_s']}s window, {len(events)} packets)",
            })
    return findings


def detect_brute_force(conn, aid, t=THRESHOLDS):
    ports = t["brute_force_ports"]
    placeholders = ",".join("?" * len(ports))
    rows = conn.execute(
        f"""SELECT src_ip, dst_ip, dst_port, timestamp FROM packets
            WHERE analysis_id = ? AND transport = 'TCP' AND syn = 1 AND ack = 0
                  AND dst_port IN ({placeholders})
            ORDER BY src_ip, dst_ip, dst_port, timestamp""",
        (aid, *ports),
    ).fetchall()

    groups = defaultdict(list)
    for r in rows:
        groups[(r["src_ip"], r["dst_ip"], r["dst_port"])].append(r["timestamp"])

    findings = []
    for (src, dst, port), stamps in groups.items():
        peak = _max_count_in_window(stamps, t["brute_force_window_s"])
        if peak >= t["brute_force_min_attempts"]:
            findings.append({
                "rule": "Brute Force",
                "pillar": "Authentication",
                "severity": "High",
                "src_ip": src,
                "dst_ip": dst,
                "detail": (f"{src} made {peak} connection attempts to {dst}:{port} within "
                           f"{t['brute_force_window_s']}s ({len(stamps)} attempts in total). "
                           f"Threshold: {t['brute_force_min_attempts']}."),
                "evidence_count": len(stamps),
                "evidence": f"Brute-force connection burst: {peak} attempts in {t['brute_force_window_s']}s to {dst}:{port} ({len(stamps)} total attempts)",
            })
    return findings


def detect_suspicious_ports(conn, aid, t=THRESHOLDS):
    ports = list(SUSPICIOUS_PORTS)
    placeholders = ",".join("?" * len(ports))
    rows = conn.execute(
        f"""SELECT src_ip, dst_ip, dst_port, COUNT(*) AS count FROM packets
            WHERE analysis_id = ? AND dst_port IN ({placeholders})
            GROUP BY src_ip, dst_ip, dst_port ORDER BY count DESC""",
        (aid, *ports),
    ).fetchall()

    findings = []
    for r in rows:
        entry = SUSPICIOUS_PORTS[r["dst_port"]]
        label, severity = entry[0], entry[1]
        pillar = entry[2] if len(entry) > 2 else "Authentication"
        findings.append({
            "rule": "Suspicious Port",
            "pillar": pillar,
            "severity": severity,
            "src_ip": r["src_ip"],
            "dst_ip": r["dst_ip"],
            "detail": f"{r['count']} packets from {r['src_ip']} to {r['dst_ip']}:{r['dst_port']}, {label}.",
            "evidence_count": r["count"],
            "evidence": f"Observed {r['count']} packets destined to {r['dst_ip']}:{r['dst_port']} ({label})",
        })
    return findings


# ---------- Confidentiality Pillar Rules ----------

def detect_cleartext_credentials(conn, aid, t=THRESHOLDS):
    """
    Identifies unencrypted authentication credentials transmitted over plaintext protocols:
    - HTTP Basic Authentication headers (decoded username:password)
    - HTTP POST form body credentials (username, password, pass, pwd)
    - FTP plain authentication commands (USER, PASS)
    """
    rows = conn.execute(
        """SELECT src_ip, dst_ip, protocol, type, detail FROM credentials
           WHERE analysis_id = ?
           ORDER BY timestamp""",
        (aid,),
    ).fetchall()

    if not rows:
        return []

    groups = defaultdict(list)
    for r in rows:
        groups[(r["src_ip"], r["dst_ip"])].append(r)

    findings = []
    for (src, dst), creds in groups.items():
        sample_evidences = [c["detail"] for c in creds if c and c["detail"]]
        evidence_str = "; ".join(sample_evidences[:5])
        if len(sample_evidences) > 5:
            evidence_str += f" ... (+{len(sample_evidences) - 5} more)"
        types = sorted(list(set(c["type"] for c in creds if c and c["type"])))
        findings.append({
            "rule": "Cleartext Credentials",
            "pillar": "Confidentiality",
            "severity": "High",
            "src_ip": src,
            "dst_ip": dst,
            "detail": (f"Cleartext credentials transmitted from {src} to {dst} via "
                       f"{', '.join(types)} ({len(creds)} occurrences)."),
            "evidence_count": len(creds),
            "evidence": evidence_str,
        })
    return findings


def detect_dns_anomaly(conn, aid, t=THRESHOLDS):
    findings = []

    # High query volume from one host (DNS exfiltration / flood)
    rows = conn.execute(
        """SELECT src_ip, COUNT(*) AS total, COUNT(DISTINCT query) AS uniq FROM dns_queries
           WHERE analysis_id = ? AND is_response = 0
           GROUP BY src_ip HAVING total > ?""",
        (aid, t["dns_max_queries_per_host"]),
    ).fetchall()
    for r in rows:
        findings.append({
            "rule": "DNS Anomaly",
            "pillar": "Confidentiality",
            "severity": "Medium",
            "src_ip": r["src_ip"],
            "dst_ip": None,
            "detail": (f"{r['src_ip']} made {r['total']} DNS queries ({r['uniq']} unique names). "
                       f"Threshold: {t['dns_max_queries_per_host']}."),
            "evidence_count": r["total"],
            "evidence": f"DNS query flood: {r['total']} queries ({r['uniq']} unique domains) from {r['src_ip']}",
        })

    # Very long domain names (possible DNS tunneling / data exfiltration)
    rows = conn.execute(
        """SELECT src_ip, query, COUNT(*) AS count FROM dns_queries
           WHERE analysis_id = ? AND is_response = 0 AND LENGTH(query) > ?
           GROUP BY src_ip, query ORDER BY LENGTH(query) DESC LIMIT 20""",
        (aid, t["dns_long_query_len"]),
    ).fetchall()
    for r in rows:
        findings.append({
            "rule": "DNS Anomaly",
            "pillar": "Confidentiality",
            "severity": "Low",
            "src_ip": r["src_ip"],
            "dst_ip": None,
            "detail": (f"Unusually long domain queried ({len(r['query'])} chars): "
                       f"{r['query'][:80]}{'...' if len(r['query']) > 80 else ''}"),
            "evidence_count": r["count"],
            "evidence": f"Long DNS query ({len(r['query'])} characters): {r['query']}",
        })
    return findings


# ---------- Integrity Pillar Rules ----------

def detect_arp_spoofing(conn, aid, t=THRESHOLDS):
    """
    Identifies ARP Cache Poisoning / Man-in-the-Middle (MITM) attacks by detecting
    multiple distinct source MAC addresses asserting ownership of the same IPv4 address.
    """
    min_macs = t.get("arp_spoofing_min_macs", 2)
    rows = conn.execute(
        """SELECT src_ip, COUNT(DISTINCT src_mac) AS mac_count,
                  GROUP_CONCAT(DISTINCT src_mac) AS macs,
                  COUNT(*) AS count
           FROM arp_records
           WHERE analysis_id = ? AND src_ip IS NOT NULL AND src_mac IS NOT NULL
                 AND LOWER(src_mac) NOT IN ('ff:ff:ff:ff:ff:ff', '00:00:00:00:00:00')
           GROUP BY src_ip
           HAVING mac_count >= ?""",
        (aid, min_macs),
    ).fetchall()

    findings = []
    for r in rows:
        src_ip = r["src_ip"]
        macs = r["macs"]
        count = r["count"]
        findings.append({
            "rule": "ARP Cache Poisoning",
            "pillar": "Integrity",
            "severity": "High",
            "src_ip": src_ip,
            "dst_ip": None,
            "detail": (f"ARP Cache Poisoning (MITM) detected for IP {src_ip}: claimed by "
                       f"{r['mac_count']} conflicting MAC addresses ({macs}). "
                       f"Total conflicting ARP packets: {count}."),
            "evidence_count": count,
            "evidence": f"IP {src_ip} claimed by conflicting MACs: {macs} ({count} ARP packets)",
        })
    return findings


def detect_tcp_evasion(conn, aid, t=THRESHOLDS):
    """
    Identifies TCP protocol evasion techniques violating RFC 793 / RFC 9293 control flag semantics:
    - Xmas Scan: FIN=1, PSH=1, URG=1 with SYN=0 and ACK=0
    - Null Scan: All control flags (SYN, ACK, RST, FIN, PSH, URG) set to 0
    """
    min_pkts = t.get("tcp_evasion_min_packets", 1)
    findings = []

    # Xmas Scan: FIN=1, PSH=1, URG=1, SYN=0, ACK=0
    xmas_rows = conn.execute(
        """SELECT src_ip, dst_ip, COUNT(*) AS count
           FROM packets
           WHERE analysis_id = ? AND transport = 'TCP'
                 AND fin = 1 AND psh = 1 AND urg = 1 AND syn = 0 AND ack = 0
           GROUP BY src_ip, dst_ip
           HAVING count >= ?""",
        (aid, min_pkts),
    ).fetchall()

    for r in xmas_rows:
        findings.append({
            "rule": "TCP Flag Evasion",
            "pillar": "Integrity",
            "severity": "High",
            "src_ip": r["src_ip"],
            "dst_ip": r["dst_ip"],
            "detail": (f"TCP protocol evasion (Xmas Scan: FIN+PSH+URG) from {r['src_ip']} to {r['dst_ip']} "
                       f"({r['count']} packets). Violates RFC 793 protocol state machine."),
            "evidence_count": r["count"],
            "evidence": f"Xmas scan probes: {r['count']} packets with flags FIN=1, PSH=1, URG=1, SYN=0, ACK=0",
        })

    # Null Scan: SYN=0, ACK=0, RST=0, FIN=0, PSH=0, URG=0
    null_rows = conn.execute(
        """SELECT src_ip, dst_ip, COUNT(*) AS count
           FROM packets
           WHERE analysis_id = ? AND transport = 'TCP'
                 AND syn = 0 AND ack = 0 AND rst = 0 AND fin = 0 AND psh = 0 AND urg = 0
           GROUP BY src_ip, dst_ip
           HAVING count >= ?""",
        (aid, min_pkts),
    ).fetchall()

    for r in null_rows:
        findings.append({
            "rule": "TCP Flag Evasion",
            "pillar": "Integrity",
            "severity": "High",
            "src_ip": r["src_ip"],
            "dst_ip": r["dst_ip"],
            "detail": (f"TCP protocol evasion (Null Scan: zero flags) from {r['src_ip']} to {r['dst_ip']} "
                       f"({r['count']} packets). Violates RFC 793 protocol state machine."),
            "evidence_count": r["count"],
            "evidence": f"Null scan probes: {r['count']} packets with flags SYN=0, ACK=0, RST=0, FIN=0, PSH=0, URG=0",
        })

    return findings


# ---------- Availability Pillar Rules ----------

def detect_syn_flood(conn, aid, t=THRESHOLDS):
    """
    Identifies TCP SYN Flood Denial of Service (DoS) attacks attempting half-open
    socket state exhaustion (RFC 4987) via high ratios of unacknowledged SYN packets.
    """
    min_syns = t.get("syn_flood_min_syns", 50)
    min_ratio = t.get("syn_flood_ratio", 3.0)

    rows = conn.execute(
        """SELECT dst_ip, dst_port,
                  SUM(CASE WHEN syn = 1 AND ack = 0 THEN 1 ELSE 0 END) AS syn_count,
                  SUM(CASE WHEN ack = 1 THEN 1 ELSE 0 END) AS ack_count,
                  COUNT(DISTINCT src_ip) AS src_count,
                  MIN(src_ip) AS sample_src
           FROM packets
           WHERE analysis_id = ? AND transport = 'TCP'
           GROUP BY dst_ip, dst_port
           HAVING syn_count >= ?""",
        (aid, min_syns),
    ).fetchall()

    findings = []
    for r in rows:
        syn_cnt = r["syn_count"]
        ack_cnt = r["ack_count"]
        ratio = syn_cnt / (ack_cnt + 1.0)
        if ratio >= min_ratio:
            findings.append({
                "rule": "TCP SYN Flood",
                "pillar": "Availability",
                "severity": "High",
                "src_ip": r["sample_src"] if r["src_count"] == 1 else f"Distributed ({r['src_count']} sources)",
                "dst_ip": r["dst_ip"],
                "detail": (f"TCP SYN Flood DoS targeting {r['dst_ip']}:{r['dst_port']}: "
                           f"{syn_cnt} SYN packets with only {ack_cnt} ACKs "
                           f"(unacknowledged ratio: {ratio:.1f}x). "
                           f"Exhausts TCP connection state backlog."),
                "evidence_count": syn_cnt,
                "evidence": f"Target port {r['dst_port']}: {syn_cnt} SYNs, {ack_cnt} ACKs, unacknowledged ratio {ratio:.1f}x",
            })
    return findings


def detect_volume_anomaly(conn, aid, t=THRESHOLDS):
    total_pkts, total_bytes, hosts = conn.execute(
        """SELECT COUNT(*), COALESCE(SUM(length), 0), COUNT(DISTINCT src_ip)
           FROM packets WHERE analysis_id = ?""",
        (aid,),
    ).fetchone()
    if total_pkts < t["volume_min_packets"] or hosts < t["volume_min_hosts"] or total_bytes == 0:
        return []

    rows = conn.execute(
        """SELECT src_ip, COUNT(*) AS pkts, SUM(length) AS bytes FROM packets
           WHERE analysis_id = ? AND src_ip IS NOT NULL
           GROUP BY src_ip ORDER BY bytes DESC""",
        (aid,),
    ).fetchall()

    findings = []
    for r in rows:
        share = r["bytes"] / total_bytes
        if share >= t["volume_share"]:
            findings.append({
                "rule": "Volume Anomaly",
                "pillar": "Availability",
                "severity": "Medium",
                "src_ip": r["src_ip"],
                "dst_ip": None,
                "detail": (f"{r['src_ip']} sent {share:.0%} of all bytes in the capture "
                           f"({r['bytes']:,} of {total_bytes:,} bytes, {r['pkts']} packets). "
                           f"Threshold: {t['volume_share']:.0%}."),
                "evidence_count": r["pkts"],
                "evidence": f"Host {r['src_ip']} generated {r['bytes']:,} bytes ({share:.1%} of {total_bytes:,} total bytes) across {r['pkts']} packets",
            })
    return findings


# ---------- Engine Runner & Scoring ----------

def run_all_rules(conn, aid):
    """
    Executes all 9 detection rules across the CIA Triad:
    - Confidentiality: Cleartext Credentials, DNS Anomaly
    - Integrity: ARP Cache Poisoning, TCP Flag Evasion
    - Authentication: Port Scan, Brute Force, Suspicious Port
    - Availability: TCP SYN Flood, Volume Anomaly
    Returns a unified list of finding dictionaries with standard schema.
    """
    findings = []
    rule_executors = (
        detect_cleartext_credentials,
        detect_arp_spoofing,
        detect_tcp_evasion,
        detect_syn_flood,
        detect_port_scan,
        detect_brute_force,
        detect_volume_anomaly,
        detect_suspicious_ports,
        detect_dns_anomaly,
    )
    for rule_fn in rule_executors:
        findings.extend(rule_fn(conn, aid))
    return findings


class PostureResult(tuple):
    """
    Dual-access tuple (overall_score, pillar_cards) allowing:
    - overall_score, pillar_cards = calculate_posture_score(findings)
    - result['overall_score'], result['pillar_cards']
    - result.overall_score, result.pillar_cards
    """
    def __new__(cls, overall_score, pillar_cards):
        return super().__new__(cls, (overall_score, pillar_cards))

    @property
    def overall_score(self):
        return self[0]

    @property
    def pillar_cards(self):
        return self[1]

    def get(self, key, default=None):
        if key == "overall_score":
            return self[0]
        if key == "pillar_cards":
            return self[1]
        return default

    def __getitem__(self, item):
        if item == "overall_score":
            return self[0]
        if item == "pillar_cards":
            return self[1]
        return super().__getitem__(item)


def calculate_posture_score(findings):
    """
    Calculate executive CIA Security Posture Score (0-100) and pillar status cards.
    Returns PostureResult (overall_score: int, pillar_cards: Dict[str, Dict]).
    """
    pillars = ["Confidentiality", "Integrity", "Authentication", "Availability"]
    pillar_cards = {}

    for pillar in pillars:
        p_findings = [f for f in findings if (f.get("pillar") or f.get("category")) == pillar]
        v_count = len(p_findings)
        high = sum(1 for f in p_findings if f.get("severity", "").title() == "High")
        med = sum(1 for f in p_findings if f.get("severity", "").title() == "Medium")
        low = sum(1 for f in p_findings if f.get("severity", "").title() == "Low")

        if v_count == 0:
            score = 25
            status = "PASS"
            badge = "emerald"
            summary = "No violations detected. Telemetry conforms to security baseline."
        else:
            deduction = high * 15 + med * 8 + low * 3
            score = max(0, 25 - deduction)
            if high > 0 or score < 15:
                status = "FAIL"
                badge = "rose"
                summary = f"{v_count} threat violation(s) detected ({high} High, {med} Med, {low} Low)."
            else:
                status = "WARNING"
                badge = "amber"
                summary = f"{v_count} warning violation(s) detected ({med} Med, {low} Low)."

        pillar_cards[pillar] = {
            "status": status,
            "score": score,
            "badge_color": badge,
            "summary": summary,
            "violations_count": v_count,
        }

    overall_score = max(0, min(100, sum(c["score"] for c in pillar_cards.values())))
    return PostureResult(overall_score, pillar_cards)
