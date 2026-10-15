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
        "parse_duration_seconds", "detect_duration_seconds"
    }
    valid_fields = {k: (_clean_str(v) if isinstance(v, str) else v) for k, v in fields.items() if k in ALLOWED}
    if not valid_fields:
        return
    cols = ", ".join(f"{k} = ?" for k in valid_fields)
    conn.execute(f"UPDATE analyses SET {cols} WHERE id = ?", (*valid_fields.values(), analysis_id))
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

