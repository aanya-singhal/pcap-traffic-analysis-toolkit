"""
Rule-based threat detection over the SQLite packet records.
Module owner: Aanya Singhal

Every rule is explainable: it reports which hosts triggered it, the threshold used,
and how much evidence was seen. Findings are indicators for investigation, not proof.
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
}

SUSPICIOUS_PORTS = {
    23: ("Telnet (cleartext remote login)", "Medium"),
    4444: ("Metasploit default listener", "High"),
    6667: ("IRC (common botnet C2 channel)", "Medium"),
    31337: ("Back Orifice / 'elite' backdoor port", "High"),
    12345: ("NetBus trojan", "High"),
    5555: ("Android ADB over network", "Medium"),
    1337: ("Common backdoor/test port", "Low"),
}

RULE_DESCRIPTIONS = {
    "Port Scan": "One source sends TCP SYN packets to many distinct ports on a host within a short window.",
    "Brute Force": "Many connection attempts to a single login service (SSH, FTP, RDP, ...) within a short window.",
    "Volume Anomaly": "A single host is responsible for a disproportionate share of total traffic.",
    "Suspicious Port": "Traffic to ports commonly associated with backdoors, malware or cleartext protocols.",
    "DNS Anomaly": "Unusually high DNS query volume from one host, or abnormally long domain names.",
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


# ---------- Rules ----------

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
                "severity": "High" if peak >= 100 else "Medium",
                "src_ip": src,
                "dst_ip": dst,
                "detail": (f"{src} sent SYN packets to {peak} distinct ports on {dst} within "
                           f"{t['port_scan_window_s']}s ({total_ports} ports in total). "
                           f"Threshold: {t['port_scan_min_ports']} ports."),
                "evidence_count": len(events),
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
                "severity": "High",
                "src_ip": src,
                "dst_ip": dst,
                "detail": (f"{src} made {peak} connection attempts to {dst}:{port} within "
                           f"{t['brute_force_window_s']}s ({len(stamps)} attempts in total). "
                           f"Threshold: {t['brute_force_min_attempts']}."),
                "evidence_count": len(stamps),
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
                "severity": "Medium",
                "src_ip": r["src_ip"],
                "dst_ip": None,
                "detail": (f"{r['src_ip']} sent {share:.0%} of all bytes in the capture "
                           f"({r['bytes']:,} of {total_bytes:,} bytes, {r['pkts']} packets). "
                           f"Threshold: {t['volume_share']:.0%}."),
                "evidence_count": r["pkts"],
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
        label, severity = SUSPICIOUS_PORTS[r["dst_port"]]
        findings.append({
            "rule": "Suspicious Port",
            "severity": severity,
            "src_ip": r["src_ip"],
            "dst_ip": r["dst_ip"],
            "detail": f"{r['count']} packets from {r['src_ip']} to {r['dst_ip']}:{r['dst_port']}, {label}.",
            "evidence_count": r["count"],
        })
    return findings


def detect_dns_anomaly(conn, aid, t=THRESHOLDS):
    findings = []

    # High query volume from one host
    rows = conn.execute(
        """SELECT src_ip, COUNT(*) AS total, COUNT(DISTINCT query) AS uniq FROM dns_queries
           WHERE analysis_id = ? AND is_response = 0
           GROUP BY src_ip HAVING total > ?""",
        (aid, t["dns_max_queries_per_host"]),
    ).fetchall()
    for r in rows:
        findings.append({
            "rule": "DNS Anomaly",
            "severity": "Medium",
            "src_ip": r["src_ip"],
            "dst_ip": None,
            "detail": (f"{r['src_ip']} made {r['total']} DNS queries ({r['uniq']} unique names). "
                       f"Threshold: {t['dns_max_queries_per_host']}."),
            "evidence_count": r["total"],
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
            "severity": "Low",
            "src_ip": r["src_ip"],
            "dst_ip": None,
            "detail": (f"Unusually long domain queried ({len(r['query'])} chars): "
                       f"{r['query'][:80]}{'...' if len(r['query']) > 80 else ''}"),
            "evidence_count": r["count"],
        })
    return findings


def run_all_rules(conn, aid):
    findings = []
    for rule in (detect_port_scan, detect_brute_force, detect_volume_anomaly,
                 detect_suspicious_ports, detect_dns_anomaly):
        findings.extend(rule(conn, aid))
    return findings
