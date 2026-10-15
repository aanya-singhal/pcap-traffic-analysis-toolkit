"""
White-Box Adversarial Coverage Hardening Test Suite for PCAP Traffic Analysis Toolkit.
Author: Challenger 2 (White-Box Adversarial Coverage Hardening Challenger)
Updated by Remediation Worker 1 with positive assertions for hardened behavior.

Probes:
- SQL injection vectors and empty kwarg queries (e.g. db.update_analysis).
- Unhandled NoneTypes, NULL database columns, and ZeroDivisionErrors (traffic_timeline, app.py).
- Resource leaks in parser (leaked /tmp/parse_*.pcap on non-existent files) and upload directory.
- Case-sensitivity edge cases in threat rules (e.g. uppercase MACs in ARP spoofing).
- Severity casing and normalization anomalies in posture scoring.
- Unicode surrogate handling in database ingestion.
- NULL detail protection in cleartext credential detection.
"""
import glob
import io
import os
import shutil
import sqlite3
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app import app, UPLOAD_DIR
import database.db as db
import detection.rules as rules
from parser.pcap_parser import parse_pcap


class TestSQLInjectionAndQueryHardening(unittest.TestCase):
    """Probes dynamic queries and parameterization safety."""

    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.db_path = self.tmp.name
        self.tmp.close()
        db.init_db(self.db_path)
        self.conn = db.get_connection(self.db_path)
        self.aid = db.create_analysis(self.conn, "test_sqli.pcap", 1000)

    def tearDown(self):
        self.conn.close()
        if os.path.exists(self.db_path):
            os.remove(self.db_path)

    def test_update_analysis_empty_fields_safe(self):
        """db.update_analysis with no fields returns early without syntax error."""
        db.update_analysis(self.conn, self.aid)
        row = db.get_analysis(self.conn, self.aid)
        self.assertIsNotNone(row)
        self.assertEqual(row["filename"], "test_sqli.pcap")

    def test_update_analysis_dynamic_column_injection_rejected(self):
        """db.update_analysis rejects column injection via allowlist."""
        injection_payload = {"packet_count = 777, filename": "injected_name.pcap"}
        db.update_analysis(self.conn, self.aid, **injection_payload)
        row = db.get_analysis(self.conn, self.aid)
        # Demonstrates that unallowlisted injected keys are ignored
        self.assertNotEqual(row["packet_count"], 777)
        self.assertEqual(row["filename"], "test_sqli.pcap")

        # Confirm valid allowlisted update works
        db.update_analysis(self.conn, self.aid, packet_count=123)
        row2 = db.get_analysis(self.conn, self.aid)
        self.assertEqual(row2["packet_count"], 123)

    def test_parameterization_against_sql_characters_in_findings(self):
        """Ensure save_findings and get_findings handle quotes, semicolons, and comments safely."""
        malicious_findings = [
            {
                "rule": "Test'; DROP TABLE findings; --",
                "pillar": "Confidentiality",
                "severity": "High",
                "src_ip": "1.1.1.1' OR '1'='1",
                "dst_ip": "2.2.2.2'; DELETE FROM packets; --",
                "detail": "SQLi payload in detail: ' UNION SELECT null, null, null --",
                "evidence_count": 1,
                "evidence": "evidence with ' and \" quotes and -- comments",
            }
        ]
        db.save_findings(self.conn, self.aid, malicious_findings)
        saved = db.get_findings(self.conn, self.aid)
        self.assertEqual(len(saved), 1)
        self.assertIn("DROP TABLE", saved[0]["rule"])
        # Ensure findings table still exists and was not dropped
        cur = self.conn.execute("SELECT COUNT(*) FROM findings")
        self.assertEqual(cur.fetchone()[0], 1)


class TestNoneTypeNullAndZeroDivisionRobustness(unittest.TestCase):
    """Probes NoneTypes, NULL timestamps, NULL lengths, and division by zero."""

    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.db_path = self.tmp.name
        self.tmp.close()
        db.init_db(self.db_path)
        self.conn = db.get_connection(self.db_path)
        self.aid = db.create_analysis(self.conn, "null_test.pcap", 500)

    def tearDown(self):
        self.conn.close()
        if os.path.exists(self.db_path):
            os.remove(self.db_path)

    def test_null_timestamp_handling_in_timeline(self):
        """A packet with NULL timestamp is filtered in traffic_timeline and formatted safely in app.py."""
        db.insert_parsed(self.conn, self.aid, {
            "packets": [
                {"timestamp": 1000.0, "src_ip": "1.1.1.1", "dst_ip": "2.2.2.2", "transport": "TCP", "protocol": "TCP", "length": 64},
                {"timestamp": None, "src_ip": "1.1.1.1", "dst_ip": "2.2.2.2", "transport": "TCP", "protocol": "TCP", "length": 64},
            ]
        })
        timeline, bucket = db.traffic_timeline(self.conn, self.aid)
        # Check that no row has b=None
        b_values = [r["b"] for r in timeline]
        self.assertNotIn(None, b_values)

        # Confirm that formatting timeline labels with guarded or 0 does not crash
        formatted_labels = [f"{int((r['b'] or 0) * bucket)}s" for r in timeline]
        self.assertEqual(len(formatted_labels), 1)

    def test_traffic_timeline_zero_points_guarded(self):
        """traffic_timeline with points=0 is safely guarded against ZeroDivisionError."""
        db.insert_parsed(self.conn, self.aid, {
            "packets": [
                {"timestamp": 1000.0, "src_ip": "1.1.1.1", "dst_ip": "2.2.2.2", "transport": "TCP", "protocol": "TCP", "length": 64},
                {"timestamp": 1010.0, "src_ip": "1.1.1.1", "dst_ip": "2.2.2.2", "transport": "TCP", "protocol": "TCP", "length": 64},
            ]
        })
        timeline, bucket = db.traffic_timeline(self.conn, self.aid, points=0)
        self.assertGreaterEqual(bucket, 1.0)

    def test_null_packet_length_handling_in_top_talkers(self):
        """Packets with NULL length return None or 0 in SUM(length) without error."""
        self.conn.execute(
            """INSERT INTO packets (analysis_id, timestamp, src_ip, dst_ip, length)
               VALUES (?, 1000.0, '192.168.1.100', '192.168.1.1', NULL)""",
            (self.aid,),
        )
        self.conn.commit()
        talkers = db.top_talkers(self.conn, self.aid)
        self.assertEqual(len(talkers), 1)


class TestParserResourceManagementAndTempLeaks(unittest.TestCase):
    """Probes temporary file handling, resource cleanup, and crash behavior in pcap_parser."""

    def test_parse_pcap_cleans_temp_file_on_nonexistent_path(self):
        """parse_pcap cleans up temp files in finally block even on non-existent file input."""
        before = set(glob.glob("/tmp/parse_*.pcap"))
        non_existent_file = "/non_existent_dir_12345/non_existent.pcap"
        with self.assertRaises(FileNotFoundError):
            parse_pcap(non_existent_file)
        after = set(glob.glob("/tmp/parse_*.pcap"))
        leaked = after - before
        self.assertEqual(len(leaked), 0, f"Non-existent file input leaked temp files in /tmp: {leaked}")

    def test_parse_pcap_empty_file_returns_clean_schema(self):
        """parse_pcap on an empty 0-byte file returns empty lists without leaking files."""
        fd, empty_path = tempfile.mkstemp(suffix=".pcap")
        os.close(fd)
        try:
            res = parse_pcap(empty_path)
            self.assertEqual(res["packets"], [])
            self.assertEqual(res["dns"], [])
            self.assertEqual(res["http"], [])
            self.assertEqual(res["arp"], [])
            self.assertEqual(res["credentials"], [])
        finally:
            if os.path.exists(empty_path):
                os.remove(empty_path)


class TestRuleEdgeCasesAndCaseSensitivity(unittest.TestCase):
    """Probes threat detection rule edge cases, case-sensitivity, and threshold logic."""

    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.db_path = self.tmp.name
        self.tmp.close()
        db.init_db(self.db_path)
        self.conn = db.get_connection(self.db_path)
        self.aid = db.create_analysis(self.conn, "rules_edge.pcap", 100)

    def tearDown(self):
        self.conn.close()
        if os.path.exists(self.db_path):
            os.remove(self.db_path)

    def test_arp_spoofing_case_sensitivity_broadcast_excluded(self):
        """Uppercase broadcast MAC 'FF:FF:FF:FF:FF:FF' is safely excluded from ARP spoofing."""
        db.insert_parsed(self.conn, self.aid, {
            "arp": [
                {"timestamp": 1.0, "src_ip": "192.168.1.1", "dst_ip": "192.168.1.2", "src_mac": "00:11:22:33:44:55", "dst_mac": "FF:FF:FF:FF:FF:FF", "opcode": "1"},
                {"timestamp": 2.0, "src_ip": "192.168.1.1", "dst_ip": "192.168.1.2", "src_mac": "FF:FF:FF:FF:FF:FF", "dst_mac": "00:11:22:33:44:55", "opcode": "2"},
            ]
        })
        findings = rules.detect_arp_spoofing(self.conn, self.aid)
        # Demonstrates that uppercase broadcast MAC is safely excluded by LOWER(src_mac) check
        self.assertEqual(len(findings), 0)

    def test_posture_score_severity_casing_normalized(self):
        """calculate_posture_score normalizes severity casing with .title()."""
        findings_lowercase = [
            {"rule": "Cleartext Credentials", "pillar": "Confidentiality", "severity": "high", "detail": "test"},
        ]
        score, cards = rules.calculate_posture_score(findings_lowercase)
        # 'high' is normalized to 'High', applying 15pt deduction -> score 10, status FAIL
        self.assertEqual(cards["Confidentiality"]["score"], 10)
        self.assertEqual(cards["Confidentiality"]["status"], "FAIL")
        self.assertEqual(score, 85)

    def test_null_detail_in_credentials_handled_safely(self):
        """Null detail in credentials table does not cause TypeError in detect_cleartext_credentials."""
        self.conn.execute(
            "INSERT INTO credentials (analysis_id, timestamp, src_ip, dst_ip, protocol, type, detail) VALUES (?, 100.0, '1.1.1.1', '2.2.2.2', 'HTTP', 'Basic', NULL)",
            (self.aid,)
        )
        self.conn.commit()
        findings = rules.detect_cleartext_credentials(self.conn, self.aid)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["evidence"], "")


class TestLoneSurrogateHandling(unittest.TestCase):
    """Probes handling of lone surrogate characters in database insertion."""

    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.db_path = self.tmp.name
        self.tmp.close()
        db.init_db(self.db_path)
        self.conn = db.get_connection(self.db_path)
        self.aid = db.create_analysis(self.conn, "surrogate_test.pcap", 100)

    def tearDown(self):
        self.conn.close()
        if os.path.exists(self.db_path):
            os.remove(self.db_path)

    def test_lone_surrogate_insertion_sanitized(self):
        """Inserting lone surrogate characters into database does not crash SQLite with UnicodeEncodeError."""
        surrogate_text = "corrupted\ud800credential"
        db.insert_parsed(self.conn, self.aid, {
            "credentials": [
                {"timestamp": 1000.0, "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "protocol": "HTTP", "type": "Basic", "detail": surrogate_text}
            ]
        })
        cur = self.conn.execute("SELECT detail FROM credentials WHERE analysis_id = ?", (self.aid,))
        row = cur.fetchone()
        self.assertIsNotNone(row)
        self.assertIn("corrupted", row["detail"])


class TestAppUploadRouteLeaksAndBoundaryHandling(unittest.TestCase):
    """Probes app.py upload routes, error handling, and upload directory leaks."""

    def setUp(self):
        app.config["TESTING"] = True
        self.client = app.test_client()

    def test_upload_corrupt_file_cleans_upload(self):
        """Uploading a corrupt file that fails _analyse_pcap cleans up file in uploads/."""
        before = set(glob.glob(os.path.join(UPLOAD_DIR, "*")))
        data = {"pcap": (io.BytesIO(b"CORRUPT_NON_PCAP_GARBAGE_BYTES"), "adversarial_corrupt.pcap")}
        resp = self.client.post("/upload", data=data, content_type="multipart/form-data")
        self.assertEqual(resp.status_code, 302)  # Redirected with flash error

        after = set(glob.glob(os.path.join(UPLOAD_DIR, "*")))
        leaked = after - before
        self.assertEqual(len(leaked), 0, f"Failed upload left leaked file in uploads directory: {leaked}")

    def test_nonexistent_analysis_returns_404(self):
        """Querying a non-existent analysis_id returns 404 without crashing."""
        resp = self.client.get("/analysis/99999999")
        self.assertEqual(resp.status_code, 404)


if __name__ == "__main__":
    unittest.main()
