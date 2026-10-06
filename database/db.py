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
    src_port INTEGER,
    dst_port INTEGER,
    transport TEXT,
    protocol TEXT,
    length INTEGER,
    syn INTEGER,
    ack INTEGER,
    rst INTEGER,
    FOREIGN KEY (analysis_id) REFERENCES analyses(id)
);
CREATE INDEX IF NOT EXISTS idx_packets_analysis ON packets(analysis_id);
CREATE INDEX IF NOT EXISTS idx_packets_src ON packets(analysis_id, src_ip);

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
    severity TEXT,
    src_ip TEXT,
    dst_ip TEXT,
    detail TEXT,
    evidence_count INTEGER,
    FOREIGN KEY (analysis_id) REFERENCES analyses(id)
);
"""


# ---------- Setup ----------

def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_connection()
    conn.executescript(SCHEMA)
    conn.commit()
    conn.close()


# ---------- Writes ----------

def create_analysis(conn, filename, file_size):
    cur = conn.execute(
        "INSERT INTO analyses (filename, file_size, uploaded_at) VALUES (?, ?, ?)",
        (filename, file_size, time.time()),
    )
    conn.commit()
    return cur.lastrowid


def update_analysis(conn, analysis_id, **fields):
    cols = ", ".join(f"{k} = ?" for k in fields)
    conn.execute(f"UPDATE analyses SET {cols} WHERE id = ?", (*fields.values(), analysis_id))
    conn.commit()


def insert_parsed(conn, analysis_id, parsed):
    conn.executemany(
        """INSERT INTO packets (analysis_id, timestamp, src_ip, dst_ip, src_port, dst_port,
           transport, protocol, length, syn, ack, rst)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        [(analysis_id, p["timestamp"], p["src_ip"], p["dst_ip"], p["src_port"], p["dst_port"],
          p["transport"], p["protocol"], p["length"], int(p["syn"]), int(p["ack"]), int(p["rst"]))
         for p in parsed["packets"]],
    )
    conn.executemany(
        """INSERT INTO dns_queries (analysis_id, timestamp, src_ip, dst_ip, query, is_response)
           VALUES (?, ?, ?, ?, ?, ?)""",
        [(analysis_id, d["timestamp"], d["src_ip"], d["dst_ip"], d["query"], int(d["is_response"]))
         for d in parsed["dns"]],
    )
    conn.executemany(
        """INSERT INTO http_requests (analysis_id, timestamp, src_ip, dst_ip, method, host, uri, user_agent)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        [(analysis_id, h["timestamp"], h["src_ip"], h["dst_ip"], h["method"], h["host"], h["uri"], h["user_agent"])
         for h in parsed["http"]],
    )
    conn.commit()


def save_findings(conn, analysis_id, findings):
    conn.executemany(
        """INSERT INTO findings (analysis_id, rule, severity, src_ip, dst_ip, detail, evidence_count)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        [(analysis_id, f["rule"], f["severity"], f.get("src_ip"), f.get("dst_ip"),
          f["detail"], f.get("evidence_count", 0)) for f in findings],
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
           GROUP BY dst_port ORDER BY count DESC LIMIT ?""",
        (analysis_id, limit),
    ).fetchall()


def traffic_timeline(conn, analysis_id, points=60):
    """Packets per time bucket, so the dashboard can draw a traffic-over-time chart."""
    row = conn.execute(
        "SELECT MIN(timestamp), MAX(timestamp) FROM packets WHERE analysis_id = ?", (analysis_id,)
    ).fetchone()
    start, end = row[0], row[1]
    if start is None:
        return [], 1
    bucket = max((end - start) / points, 1.0)
    rows = conn.execute(
        """SELECT CAST((timestamp - ?) / ? AS INTEGER) AS b, COUNT(*) AS count
           FROM packets WHERE analysis_id = ? GROUP BY b ORDER BY b""",
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
