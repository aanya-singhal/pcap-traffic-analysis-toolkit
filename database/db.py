"""
SQLite storage and traffic-statistics queries.
Module owner: Sanjai G
"""
import os
import sqlite3
import time

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.path.join(BASE_DIR, "toolkit.db")

SCHEMA = """
CREATE TABLE IF NOT EXISTS analyses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    filename TEXT,
    file_size INTEGER,
    uploaded_at REAL,
    packet_count INTEGER DEFAULT 0,
    parse_seconds REAL DEFAULT 0,
    detect_seconds REAL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS packets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    analysis_id INTEGER,
    timestamp REAL,
    src_ip TEXT,
    dst_ip TEXT,
    src_mac TEXT,
    dst_mac TEXT,
    src_port INTEGER,
    dst_port INTEGER,
    transport TEXT,
    protocol TEXT,
    length INTEGER,
    syn INTEGER DEFAULT 0,
    ack INTEGER DEFAULT 0,
    rst INTEGER DEFAULT 0,
    fin INTEGER DEFAULT 0,
    psh INTEGER DEFAULT 0,
    urg INTEGER DEFAULT 0,
    FOREIGN KEY (analysis_id) REFERENCES analyses(id)
);
CREATE INDEX IF NOT EXISTS idx_packets_analysis ON packets(analysis_id);
CREATE INDEX IF NOT EXISTS idx_packets_src ON packets(analysis_id, src_ip);

CREATE TABLE IF NOT EXISTS arp_records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    analysis_id INTEGER,
    timestamp REAL,
    src_ip TEXT,
    dst_ip TEXT,
    src_mac TEXT,
    dst_mac TEXT,
    opcode TEXT,
    FOREIGN KEY (analysis_id) REFERENCES analyses(id)
);
CREATE INDEX IF NOT EXISTS idx_arp_analysis ON arp_records(analysis_id);

CREATE TABLE IF NOT EXISTS credentials (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    analysis_id INTEGER,
    timestamp REAL,
    src_ip TEXT,
    dst_ip TEXT,
    protocol TEXT,
    type TEXT,
    detail TEXT,
    FOREIGN KEY (analysis_id) REFERENCES analyses(id)
);
CREATE INDEX IF NOT EXISTS idx_credentials_analysis ON credentials(analysis_id);

CREATE TABLE IF NOT EXISTS dns_queries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    analysis_id INTEGER,
    timestamp REAL,
    src_ip TEXT,
    dst_ip TEXT,
    query TEXT,
    is_response INTEGER,
    FOREIGN KEY (analysis_id) REFERENCES analyses(id)
);

CREATE TABLE IF NOT EXISTS http_requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    analysis_id INTEGER,
    timestamp REAL,
    src_ip TEXT,
    dst_ip TEXT,
    method TEXT,
    host TEXT,
    uri TEXT,
    user_agent TEXT,
    FOREIGN KEY (analysis_id) REFERENCES analyses(id)
);

CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    analysis_id INTEGER,
    rule TEXT,
    pillar TEXT,
    severity TEXT,
    src_ip TEXT,
    dst_ip TEXT,
    detail TEXT,
    evidence_count INTEGER,
    evidence TEXT,
    FOREIGN KEY (analysis_id) REFERENCES analyses(id)
);
CREATE INDEX IF NOT EXISTS idx_findings_analysis ON findings(analysis_id);
"""


# ---------- Setup & Migrations ----------

def migrate_db(conn):
    """
    Safely inspect and migrate existing tables to include newly added columns.
    Uses PRAGMA table_info to avoid column collisions or data loss.
    """
    # 1. Migrate packets table
    try:
        cur = conn.execute("PRAGMA table_info(packets)")
        existing_cols = {row[1] for row in cur.fetchall()}
        if existing_cols:
            cols_to_add = [
                ("src_mac", "TEXT"),
                ("dst_mac", "TEXT"),
                ("fin", "INTEGER DEFAULT 0"),
                ("psh", "INTEGER DEFAULT 0"),
                ("urg", "INTEGER DEFAULT 0"),
            ]
            for col_name, col_def in cols_to_add:
                if col_name not in existing_cols:
                    conn.execute(f"ALTER TABLE packets ADD COLUMN {col_name} {col_def}")
    except sqlite3.OperationalError:
        pass

    # 2. Migrate findings table
    try:
        cur = conn.execute("PRAGMA table_info(findings)")
        existing_cols = {row[1] for row in cur.fetchall()}
        if existing_cols:
            cols_to_add = [
                ("pillar", "TEXT"),
                ("evidence", "TEXT"),
            ]
            for col_name, col_def in cols_to_add:
                if col_name not in existing_cols:
                    conn.execute(f"ALTER TABLE findings ADD COLUMN {col_name} {col_def}")
    except sqlite3.OperationalError:
        pass


def get_connection(db_path=None):
    conn = sqlite3.connect(db_path or DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db(db_path=None):
    """
    Initialize SQLite schema and run non-destructive migrations.
    Automatically migrates DB_PATH as well as known database files (toolkit.db, eval.db).
    """
    target_path = db_path or DB_PATH
    conn = sqlite3.connect(target_path)
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA)
    migrate_db(conn)
    conn.commit()
    conn.close()

    # Also automatically ensure known workspace databases (toolkit.db, eval.db) are migrated if they exist
    for known in ("toolkit.db", "eval.db"):
        known_path = os.path.join(BASE_DIR, known)
        if os.path.exists(known_path) and os.path.abspath(known_path) != os.path.abspath(target_path):
            try:
                kconn = sqlite3.connect(known_path)
                kconn.row_factory = sqlite3.Row
                kconn.executescript(SCHEMA)
                migrate_db(kconn)
                kconn.commit()
                kconn.close()
            except Exception:
                pass


# ---------- Helpers & Writes ----------

def _clean_str(val):
    """Safely sanitize strings to prevent SQLite lone surrogate encoding errors."""
    if val is None or not isinstance(val, str):
        return val
    try:
        val.encode("utf-8")
        return val
    except UnicodeEncodeError:
        return val.encode("utf-8", "surrogatepass").decode("utf-8", "replace")


def create_analysis(conn, filename, file_size):
    cur = conn.execute(
        "INSERT INTO analyses (filename, file_size, uploaded_at) VALUES (?, ?, ?)",
        (_clean_str(filename), file_size, time.time()),
    )
    conn.commit()
    return cur.lastrowid


def update_analysis(conn, analysis_id, **fields):
    ALLOWED = {
        "filename", "file_size", "packet_count", "duration_seconds",
        "parse_seconds", "detect_seconds",
        "parse_duration_seconds", "detect_duration_seconds"
    }
    remapped = {}
    for k, v in fields.items():
        if k in ALLOWED:
            target_col = "parse_seconds" if k == "parse_duration_seconds" else ("detect_seconds" if k == "detect_duration_seconds" else k)
            remapped[target_col] = _clean_str(v) if isinstance(v, str) else v
    if not remapped:
        return
    cols = ", ".join(f"{k} = ?" for k in remapped)
    conn.execute(f"UPDATE analyses SET {cols} WHERE id = ?", (*remapped.values(), analysis_id))
    conn.commit()


def insert_parsed(conn, analysis_id, parsed):
    packets = parsed.get("packets", [])
    if packets:
        conn.executemany(
            """INSERT INTO packets (
                analysis_id, timestamp, src_ip, dst_ip, src_mac, dst_mac,
                src_port, dst_port, transport, protocol, length,
                syn, ack, rst, fin, psh, urg
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            [(
                analysis_id,
                p["timestamp"],
                _clean_str(p.get("src_ip")),
                _clean_str(p.get("dst_ip")),
                _clean_str(p.get("src_mac")),
                _clean_str(p.get("dst_mac")),
                p.get("src_port"),
                p.get("dst_port"),
                _clean_str(p.get("transport")),
                _clean_str(p.get("protocol")),
                int(p.get("length") or 0),
                1 if p.get("syn") else 0,
                1 if p.get("ack") else 0,
                1 if p.get("rst") else 0,
                1 if p.get("fin") else 0,
                1 if p.get("psh") else 0,
                1 if p.get("urg") else 0,
            ) for p in packets],
        )

    dns_list = parsed.get("dns", [])
    if dns_list:
        conn.executemany(
            """INSERT INTO dns_queries (analysis_id, timestamp, src_ip, dst_ip, query, is_response)
               VALUES (?, ?, ?, ?, ?, ?)""",
            [(analysis_id, d["timestamp"], _clean_str(d.get("src_ip")), _clean_str(d.get("dst_ip")),
              _clean_str(d.get("query")), int(d.get("is_response") or 0))
             for d in dns_list],
        )

    http_list = parsed.get("http", [])
    if http_list:
        conn.executemany(
            """INSERT INTO http_requests (analysis_id, timestamp, src_ip, dst_ip, method, host, uri, user_agent)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            [(analysis_id, h["timestamp"], _clean_str(h.get("src_ip")), _clean_str(h.get("dst_ip")),
              _clean_str(h.get("method")), _clean_str(h.get("host")), _clean_str(h.get("uri")), _clean_str(h.get("user_agent")))
             for h in http_list],
        )

    arp_list = parsed.get("arp", [])
    if arp_list:
        conn.executemany(
            """INSERT INTO arp_records (analysis_id, timestamp, src_ip, dst_ip, src_mac, dst_mac, opcode)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            [(analysis_id, a["timestamp"], _clean_str(a.get("src_ip")), _clean_str(a.get("dst_ip")),
              _clean_str(a.get("src_mac")), _clean_str(a.get("dst_mac")),
              _clean_str(str(a.get("opcode"))) if a.get("opcode") is not None else None)
             for a in arp_list],
        )

    cred_list = parsed.get("credentials", [])
    if cred_list:
        conn.executemany(
            """INSERT INTO credentials (analysis_id, timestamp, src_ip, dst_ip, protocol, type, detail)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            [(analysis_id, c["timestamp"], _clean_str(c.get("src_ip")), _clean_str(c.get("dst_ip")),
              _clean_str(c.get("protocol")), _clean_str(c.get("type")), _clean_str(c.get("detail")))
             for c in cred_list],
        )

    conn.commit()


DEFAULT_PILLARS = {
    "Cleartext Credentials": "Confidentiality",
    "Cleartext HTTP Basic Auth": "Confidentiality",
    "Cleartext HTTP Form Credentials": "Confidentiality",
    "Cleartext FTP Credentials": "Confidentiality",
    "Cleartext Telnet Session": "Confidentiality",
    "DNS Tunneling": "Confidentiality",
    "DNS Tunneling / Covert Channel": "Confidentiality",
    "DNS Anomaly": "Confidentiality",
    "ARP Cache Poisoning": "Integrity",
    "ARP Cache Poisoning (MITM)": "Integrity",
    "ARP Spoofing": "Integrity",
    "TCP Protocol Evasion": "Integrity",
    "TCP Protocol Evasion (Xmas Scan)": "Integrity",
    "TCP Protocol Evasion (Null Scan)": "Integrity",
    "Port Scan": "Authentication",
    "Port Scan / Reconnaissance": "Authentication",
    "Credential Brute Force": "Authentication",
    "Brute Force": "Authentication",
    "Suspicious Port": "Authentication",
    "TCP SYN Flood": "Availability",
    "TCP SYN Flood (DoS)": "Availability",
    "Volume Anomaly": "Availability",
    "Bandwidth Volume Anomaly": "Availability",
}


def save_findings(conn, analysis_id, findings):
    records = []
    for f in findings:
        rule = f.get("rule", "")
        pillar = f.get("pillar") or f.get("category") or DEFAULT_PILLARS.get(rule, "General")
        severity = f.get("severity", "Medium")
        src_ip = f.get("src_ip")
        dst_ip = f.get("dst_ip")
        detail = f.get("detail", "")
        evidence_count = f.get("evidence_count", 0)
        evidence = f.get("evidence")
        if evidence is None:
            evidence = detail

        records.append((
            analysis_id,
            _clean_str(rule),
            _clean_str(pillar),
            _clean_str(severity),
            _clean_str(src_ip),
            _clean_str(dst_ip),
            _clean_str(detail),
            evidence_count,
            _clean_str(str(evidence) if evidence is not None else ""),
        ))

    conn.executemany(
        """INSERT INTO findings (
            analysis_id, rule, pillar, severity, src_ip, dst_ip,
            detail, evidence_count, evidence
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        records,
    )
    conn.commit()


# ---------- Reads / traffic statistics ----------

def get_analysis(conn, analysis_id):
    return conn.execute("SELECT * FROM analyses WHERE id = ?", (analysis_id,)).fetchone()


def list_analyses(conn, limit=10):
    return conn.execute("SELECT * FROM analyses ORDER BY id DESC LIMIT ?", (limit,)).fetchall()


def get_summary(conn, analysis_id):
    row = conn.execute(
        """SELECT COUNT(*) AS total_packets,
                  COALESCE(SUM(length), 0) AS total_bytes,
                  COUNT(DISTINCT src_ip) AS unique_src,
                  COUNT(DISTINCT dst_ip) AS unique_dst,
                  COALESCE(MAX(timestamp) - MIN(timestamp), 0) AS duration
           FROM packets WHERE analysis_id = ?""",
        (analysis_id,),
    ).fetchone()
    summary = dict(row)
    summary["dns_queries"] = conn.execute(
        "SELECT COUNT(*) FROM dns_queries WHERE analysis_id = ? AND is_response = 0", (analysis_id,)
    ).fetchone()[0]
    summary["http_requests"] = conn.execute(
        "SELECT COUNT(*) FROM http_requests WHERE analysis_id = ?", (analysis_id,)
    ).fetchone()[0]
    try:
        summary["arp_records"] = conn.execute(
            "SELECT COUNT(*) FROM arp_records WHERE analysis_id = ?", (analysis_id,)
        ).fetchone()[0]
    except (sqlite3.OperationalError, IndexError):
        summary["arp_records"] = 0
    try:
        summary["credentials"] = conn.execute(
            "SELECT COUNT(*) FROM credentials WHERE analysis_id = ?", (analysis_id,)
        ).fetchone()[0]
    except (sqlite3.OperationalError, IndexError):
        summary["credentials"] = 0
    return summary


def protocol_distribution(conn, analysis_id, limit=8):
    return conn.execute(
        """SELECT protocol, COUNT(*) AS count FROM packets
           WHERE analysis_id = ? GROUP BY protocol ORDER BY count DESC LIMIT ?""",
        (analysis_id, limit),
    ).fetchall()


def top_talkers(conn, analysis_id, limit=10):
    return conn.execute(
        """SELECT src_ip, COUNT(*) AS packets, SUM(length) AS bytes FROM packets
           WHERE analysis_id = ? AND src_ip IS NOT NULL
           GROUP BY src_ip ORDER BY bytes DESC LIMIT ?""",
        (analysis_id, limit),
    ).fetchall()


def top_dst_ports(conn, analysis_id, limit=10):
    return conn.execute(
        """SELECT dst_port, COUNT(*) AS count FROM packets
           WHERE analysis_id = ? AND dst_port IS NOT NULL
                 AND ((transport = 'TCP' AND syn = 1 AND ack = 0)
                      OR (transport = 'UDP' AND dst_port < src_port))
           GROUP BY dst_port ORDER BY count DESC LIMIT ?""",
        (analysis_id, limit),
    ).fetchall()


def traffic_timeline(conn, analysis_id, points=60):
    """Packets per time bucket, so the dashboard can draw a traffic-over-time chart."""
    points = max(int(points or 60), 1)
    row = conn.execute(
        "SELECT MIN(timestamp), MAX(timestamp) FROM packets WHERE analysis_id = ? AND timestamp IS NOT NULL", (analysis_id,)
    ).fetchone()
    start, end = row[0], row[1]
    if start is None:
        return [], 1
    bucket = max((end - start) / points, 1.0)
    rows = conn.execute(
        """SELECT CAST((timestamp - ?) / ? AS INTEGER) AS b, COUNT(*) AS count
           FROM packets WHERE analysis_id = ? AND timestamp IS NOT NULL GROUP BY b ORDER BY b""",
        (start, bucket, analysis_id),
    ).fetchall()
    return rows, bucket


def top_dns_queries(conn, analysis_id, limit=10):
    return conn.execute(
        """SELECT query, COUNT(*) AS count FROM dns_queries
           WHERE analysis_id = ? AND is_response = 0
           GROUP BY query ORDER BY count DESC LIMIT ?""",
        (analysis_id, limit),
    ).fetchall()


def get_findings(conn, analysis_id):
    return conn.execute(
        """SELECT * FROM findings WHERE analysis_id = ?
           ORDER BY CASE severity WHEN 'High' THEN 0 WHEN 'Medium' THEN 1 ELSE 2 END, id""",
        (analysis_id,),
    ).fetchall()


def get_arp_records(conn, analysis_id):
    return conn.execute(
        "SELECT * FROM arp_records WHERE analysis_id = ? ORDER BY timestamp ASC, id ASC",
        (analysis_id,),
    ).fetchall()


def get_credentials(conn, analysis_id):
    return conn.execute(
        "SELECT * FROM credentials WHERE analysis_id = ? ORDER BY timestamp ASC, id ASC",
        (analysis_id,),
    ).fetchall()


# ---------- Verify-on-PCAP: packet-level evidence for a finding ----------

_EVID_BRUTE_PORTS = [21, 22, 23, 25, 110, 143, 445, 3306, 3389, 5900]
_EVID_SUSPICIOUS_PORTS = [23, 4444, 6667, 31337, 12345, 5555, 1337]
_EVID_FLAG_COLS = [("SYN", "syn"), ("ACK", "ack"), ("RST", "rst"),
                   ("FIN", "fin"), ("PSH", "psh"), ("URG", "urg")]

_EVID_SERVICE_NAMES = {
    20: "FTP-Data",
    21: "FTP (File Transfer)",
    22: "SSH (Secure Shell)",
    23: "Telnet (Cleartext Remote Login)",
    25: "SMTP (Mail)",
    53: "DNS (Domain Name System)",
    80: "HTTP (Plain Web)",
    110: "POP3 (Mail)",
    143: "IMAP (Mail)",
    443: "HTTPS (Encrypted TLS)",
    445: "SMB (File Sharing)",
    1337: "Elite / Backdoor Test Port",
    3306: "MySQL Database",
    3389: "RDP (Remote Desktop)",
    4444: "Metasploit Default C2 Listener",
    5555: "Android ADB Debug Bridge",
    5900: "VNC Remote Desktop",
    6667: "IRC Botnet C2 Channel",
    12345: "NetBus Trojan Backdoor",
    31337: "Back Orifice Trojan Backdoor",
}


def _service_desc(port):
    if port is None:
        return "Unknown"
    try:
        p_int = int(port)
        return _EVID_SERVICE_NAMES.get(p_int, f"Port {p_int}")
    except (ValueError, TypeError):
        return str(port)


def _evid_flag_str(row):
    flags = [name for name, col in _EVID_FLAG_COLS if row[col]]
    return ",".join(flags) if flags else "—"


def get_finding_evidence(conn, analysis_id, finding, limit=60):
    """Return the actual capture records that triggered a finding, so a detection
    can be verified packet-by-packet on the PCAP with rich forensic context.
    Returns {"headers": [...], "rows": [[...]], "caption": str, "count": int}."""
    rule = finding.get("rule") or ""
    src = finding.get("src_ip")
    dst = finding.get("dst_ip")
    headers, rows, caption = [], [], ""

    if rule == "Port Scan":
        cur = conn.execute(
            """SELECT timestamp, src_ip, dst_ip, src_port, dst_port, length,
                      syn, ack, rst, fin, psh, urg
               FROM packets
               WHERE analysis_id = ? AND transport = 'TCP' AND syn = 1 AND ack = 0
                     AND (? IS NULL OR src_ip = ?) AND (? IS NULL OR dst_ip = ?)
               ORDER BY timestamp LIMIT ?""",
            (analysis_id, src, src, dst, dst, limit),
        ).fetchall()
        headers = ["#", "Time (s)", "Scanner (Source)", "Target Host", "Probed Port", "Service / Known Protocol", "TCP Flags", "Size", "Forensic Verification Note"]
        seen_ports = set()
        rows = []
        for i, r in enumerate(cur):
            p = r["dst_port"]
            is_new = p not in seen_ports
            seen_ports.add(p)
            ts = ("%.3f" % r["timestamp"]) if r["timestamp"] is not None else "—"
            svc = _service_desc(p)
            probe_note = f"Distinct Port Probe #{len(seen_ports)} ({svc})" if is_new else f"Repeat probe to port {p}"
            rows.append([
                i + 1,
                ts,
                f"{r['src_ip']}:{r['src_port']}" if r["src_port"] else str(r["src_ip"] or "—"),
                str(r["dst_ip"] or "—"),
                f"Port {p}",
                svc,
                _evid_flag_str(r),
                f"{r['length'] or 0} B",
                probe_note
            ])
        caption = f"TCP SYN scan telemetry: {src} systematically contacted {len(seen_ports)} distinct destination port(s) on {dst or 'target'}. Below are the individual SYN probes:"

    elif rule == "Brute Force":
        ph = ",".join("?" * len(_EVID_BRUTE_PORTS))
        params = [analysis_id] + _EVID_BRUTE_PORTS
        q = f"""SELECT timestamp, src_ip, dst_ip, src_port, dst_port, length,
                       syn, ack, rst, fin, psh, urg
                FROM packets
                WHERE analysis_id = ? AND transport = 'TCP' AND syn = 1 AND ack = 0
                      AND dst_port IN ({ph})"""
        if src:
            q += " AND src_ip = ?"
            params.append(src)
        if dst:
            q += " AND dst_ip = ?"
            params.append(dst)
        q += " ORDER BY timestamp LIMIT ?"
        params.append(limit)
        cur = conn.execute(q, params).fetchall()

        headers = ["#", "Time (s)", "Attacker (Source)", "Target Host", "Target Port & Service", "TCP Flags", "Packet Size", "Burst Sequence & Timing"]
        rows = []
        prev_ts = None
        for i, r in enumerate(cur):
            ts_val = r["timestamp"]
            ts = ("%.3f" % ts_val) if ts_val is not None else "—"
            delta_str = ""
            if prev_ts is not None and ts_val is not None:
                delta = ts_val - prev_ts
                delta_str = f" (+{delta:.2f}s)"
            prev_ts = ts_val
            p = r["dst_port"]
            svc = _service_desc(p)
            burst_note = f"Rapid Auth Attempt #{i + 1}{delta_str}"
            rows.append([
                i + 1,
                ts,
                f"{r['src_ip']}:{r['src_port']}" if r["src_port"] else str(r["src_ip"] or "—"),
                str(r["dst_ip"] or "—"),
                f"Port {p} ({svc})",
                _evid_flag_str(r),
                f"{r['length'] or 0} B",
                burst_note
            ])
        caption = f"Rapid authentication burst: repeated TCP connection attempts targeting login service ({rows[0][4] if rows else 'service'}) within 60s window."

    elif rule == "TCP SYN Flood":
        cur = conn.execute(
            """SELECT timestamp, src_ip, dst_ip, src_port, dst_port, length,
                      syn, ack, rst, fin, psh, urg
               FROM packets
               WHERE analysis_id = ? AND transport = 'TCP' AND syn = 1 AND ack = 0
                     AND (? IS NULL OR dst_ip = ?)
               ORDER BY timestamp LIMIT ?""",
            (analysis_id, dst, dst, limit),
        ).fetchall()
        headers = ["#", "Time (s)", "Source IP:Port", "Target Host", "Target Port & Service", "TCP Flags", "Packet Size", "Socket State & Backlog Impact"]
        rows = []
        for i, r in enumerate(cur):
            ts = ("%.3f" % r["timestamp"]) if r["timestamp"] is not None else "—"
            p = r["dst_port"]
            rows.append([
                i + 1,
                ts,
                f"{r['src_ip']}:{r['src_port']}" if r["src_port"] else str(r["src_ip"] or "—"),
                str(r["dst_ip"] or "—"),
                f"Port {p} ({_service_desc(p)})",
                _evid_flag_str(r),
                f"{r['length'] or 0} B",
                "Unacknowledged SYN — Half-Open Backlog Queue"
            ])
        caption = f"Volumetric SYN flood directed at {dst or 'target'}: continuous unacknowledged SYNs exhausting target kernel connection backlog."

    elif rule == "TCP Flag Evasion":
        cur = conn.execute(
            """SELECT timestamp, src_ip, dst_ip, src_port, dst_port, length,
                      syn, ack, rst, fin, psh, urg
               FROM packets
               WHERE analysis_id = ? AND transport = 'TCP'
                     AND ((fin=1 AND psh=1 AND urg=1 AND syn=0 AND ack=0)
                          OR (syn=0 AND ack=0 AND rst=0 AND fin=0 AND psh=0 AND urg=0))
                     AND (? IS NULL OR src_ip = ?) AND (? IS NULL OR dst_ip = ?)
               ORDER BY timestamp LIMIT ?""",
            (analysis_id, src, src, dst, dst, limit),
        ).fetchall()
        headers = ["#", "Time (s)", "Source Host", "Target Host:Port", "Active TCP Flags", "Evasion Technique", "RFC 793 State Machine Violation"]
        rows = []
        for i, r in enumerate(cur):
            ts = ("%.3f" % r["timestamp"]) if r["timestamp"] is not None else "—"
            flags = _evid_flag_str(r)
            if r["fin"] and r["psh"] and r["urg"]:
                technique = "Xmas Scan (FIN+PSH+URG)"
                violation = "Illegal RFC 793 permutation: probes closed ports to bypass stateless packet filters"
            else:
                technique = "Null Scan (Zero Flags)"
                violation = "Illegal RFC 793 permutation: packet with zero control flags set"
            dp = f":{r['dst_port']}" if r["dst_port"] else ""
            rows.append([
                i + 1,
                ts,
                f"{r['src_ip']}:{r['src_port']}" if r["src_port"] else str(r["src_ip"] or "—"),
                f"{r['dst_ip']}{dp}",
                flags if flags != "—" else "None (All 6 flags = 0)",
                technique,
                violation
            ])
        caption = "Packets with illegal TCP control flag combinations engineered to bypass firewalls by violating RFC 793 protocol state specifications."

    elif rule == "Volume Anomaly":
        tot_bytes = conn.execute(
            "SELECT COALESCE(SUM(length), 0) FROM packets WHERE analysis_id = ?",
            (analysis_id,)
        ).fetchone()[0] or 1
        cur = conn.execute(
            """SELECT timestamp, src_ip, dst_ip, src_port, dst_port, transport, protocol, length,
                      syn, ack, rst, fin, psh, urg
               FROM packets
               WHERE analysis_id = ? AND (? IS NULL OR src_ip = ?)
               ORDER BY length DESC, timestamp LIMIT ?""",
            (analysis_id, src, src, limit),
        ).fetchall()
        headers = ["#", "Time (s)", "Heavy Talker (Source)", "Destination Host:Port", "Protocol", "Packet Length (Bytes)", "Running Total (KB)", "Bandwidth Share Contribution"]
        rows = []
        running_bytes = 0
        for i, r in enumerate(cur):
            ts = ("%.3f" % r["timestamp"]) if r["timestamp"] is not None else "—"
            plen = int(r["length"] or 0)
            running_bytes += plen
            dp = f":{r['dst_port']}" if r["dst_port"] else ""
            share_pct = (running_bytes / tot_bytes) * 100
            rows.append([
                i + 1,
                ts,
                f"{r['src_ip']}:{r['src_port']}" if r["src_port"] else str(r["src_ip"] or "—"),
                f"{r['dst_ip']}{dp}",
                r["protocol"] or r["transport"] or "—",
                f"{plen:,} Bytes",
                f"{running_bytes / 1024:.1f} KB",
                f"Cumulative {share_pct:.1f}% of capture"
            ])
        caption = f"Largest payload packets generated by {src or 'host'}: illustrates disproportionate traffic concentration resulting in bandwidth monopolization."

    elif rule == "Suspicious Port":
        ph = ",".join("?" * len(_EVID_SUSPICIOUS_PORTS))
        params = [analysis_id] + _EVID_SUSPICIOUS_PORTS
        q = f"""SELECT timestamp, src_ip, dst_ip, src_port, dst_port, transport, protocol, length,
                       syn, ack, rst, fin, psh, urg
                FROM packets
                WHERE analysis_id = ? AND dst_port IN ({ph})"""
        if src:
            q += " AND src_ip = ?"
            params.append(src)
        if dst:
            q += " AND dst_ip = ?"
            params.append(dst)
        q += " ORDER BY timestamp LIMIT ?"
        params.append(limit)
        cur = conn.execute(q, params).fetchall()
        headers = ["#", "Time (s)", "Source Host", "Target Host", "Destination Port", "Known Threat / C2 Service", "Protocol", "Security Implication"]
        rows = []
        for i, r in enumerate(cur):
            ts = ("%.3f" % r["timestamp"]) if r["timestamp"] is not None else "—"
            p = r["dst_port"]
            svc = _service_desc(p)
            if p in (4444, 31337, 12345, 1337):
                implication = "High Severity — Backdoor listener / Remote shell compromise"
            elif p in (23, 5555):
                implication = "Medium Severity — Insecure legacy or unauthenticated remote access"
            else:
                implication = "Medium Severity — Known malicious / C2 channel"
            rows.append([
                i + 1,
                ts,
                f"{r['src_ip']}:{r['src_port']}" if r["src_port"] else str(r["src_ip"] or "—"),
                str(r["dst_ip"] or "—"),
                f"Port {p}",
                svc,
                r["protocol"] or r["transport"] or "TCP",
                implication
            ])
        caption = "Packets connecting to known backdoor, remote-shell, or legacy cleartext administrative service ports."

    elif rule == "Cleartext Credentials":
        cur = conn.execute(
            """SELECT timestamp, src_ip, dst_ip, protocol, type, detail FROM credentials
               WHERE analysis_id = ? AND (? IS NULL OR src_ip = ?) AND (? IS NULL OR dst_ip = ?)
               ORDER BY timestamp LIMIT ?""",
            (analysis_id, src, src, dst, dst, limit)).fetchall()
        headers = ["#", "Time (s)", "Client (Source)", "Target Server", "Protocol", "Authentication Method", "Exposed Secret / Payload"]
        rows = []
        for i, r in enumerate(cur):
            ts = ("%.3f" % r["timestamp"]) if r["timestamp"] is not None else "—"
            rows.append([
                i + 1,
                ts,
                str(r["src_ip"] or "—"),
                str(r["dst_ip"] or "—"),
                r["protocol"] or "—",
                r["type"] or "—",
                r["detail"] or "—"
            ])
        caption = "Unencrypted authentication credentials extracted directly from application payloads — conclusive proof of Confidentiality breach."

    elif rule == "DNS Anomaly":
        cur = conn.execute(
            """SELECT timestamp, src_ip, query FROM dns_queries
               WHERE analysis_id = ? AND is_response = 0 AND (? IS NULL OR src_ip = ?)
               ORDER BY LENGTH(query) DESC, timestamp LIMIT ?""",
            (analysis_id, src, src, limit)).fetchall()
        headers = ["#", "Time (s)", "Querying Client", "Queried Domain (Smuggled Payload)", "Character Length", "Covert Channel Analysis"]
        rows = []
        for i, r in enumerate(cur):
            ts = ("%.3f" % r["timestamp"]) if r["timestamp"] is not None else "—"
            qname = r["query"] or "—"
            qlen = len(qname)
            analysis = "High Probability DNS Tunneling Exfiltration (>50 chars)" if qlen > 50 else "High-Frequency Query Flood"
            rows.append([
                i + 1,
                ts,
                str(r["src_ip"] or "—"),
                qname,
                f"{qlen} chars",
                analysis
            ])
        caption = "DNS query telemetry: each query string represents encoded data escaping the network via port 53 (Confidentiality / Exfiltration breach)."

    elif rule == "ARP Cache Poisoning":
        cur = conn.execute(
            """SELECT timestamp, src_ip, dst_ip, src_mac, dst_mac, opcode
               FROM arp_records
               WHERE analysis_id = ? AND (? IS NULL OR src_ip = ?) AND src_mac IS NOT NULL
               ORDER BY timestamp LIMIT ?""",
            (analysis_id, src, src, limit),
        ).fetchall()
        headers = ["#", "Time (s)", "Target / Claimed IP", "Asserted Hardware MAC", "Destination MAC", "ARP Opcode", "MITM Conflict Status"]
        rows = []
        seen_macs = []
        for i, r in enumerate(cur):
            ts = ("%.3f" % r["timestamp"]) if r["timestamp"] is not None else "—"
            mac = r["src_mac"]
            if mac not in seen_macs:
                seen_macs.append(mac)
            mac_idx = seen_macs.index(mac) + 1
            op = "Reply (2)" if str(r["opcode"]) in ("2", "reply") else ("Request (1)" if str(r["opcode"]) in ("1", "request") else str(r["opcode"] or "ARP"))
            conflict_note = f"Conflicting MAC #{mac_idx} claiming IP" if len(seen_macs) > 1 else "Claimant MAC #1"
            rows.append([
                i + 1,
                ts,
                str(r["src_ip"] or "—"),
                str(mac or "—"),
                str(r["dst_mac"] or "Broadcast (ff:ff:ff:ff:ff:ff)"),
                op,
                conflict_note
            ])
        caption = f"ARP resolution telemetry for IP {src}: multiple distinct MAC addresses claiming ownership — conclusive proof of ARP Cache Poisoning (Layer 2 MITM)."

    else:
        q = ("SELECT timestamp, src_ip, dst_ip, src_port, dst_port, transport, protocol, "
             "length, syn, ack, rst, fin, psh, urg FROM packets WHERE analysis_id = ?")
        params = [analysis_id]
        if src:
            q += " AND src_ip = ?"
            params.append(src)
        if dst:
            q += " AND dst_ip = ?"
            params.append(dst)
        q += " ORDER BY timestamp LIMIT ?"
        params.append(limit)
        cur = conn.execute(q, params).fetchall()
        headers = ["#", "Time (s)", "Source", "Destination", "Protocol", "TCP Flags", "Packet Length"]
        rows = []
        for i, r in enumerate(cur):
            sp = f":{r['src_port']}" if r["src_port"] is not None else ""
            dp = f":{r['dst_port']}" if r["dst_port"] is not None else ""
            ts = ("%.3f" % r["timestamp"]) if r["timestamp"] is not None else "—"
            rows.append([
                i + 1,
                ts,
                f"{r['src_ip']}{sp}",
                f"{r['dst_ip']}{dp}",
                r["protocol"] or r["transport"] or "—",
                _evid_flag_str(r),
                f"{r['length'] or 0} B"
            ])
        caption = "Packets from the capture that triggered this finding."

    return {"headers": headers, "rows": rows, "caption": caption, "count": len(rows)}
