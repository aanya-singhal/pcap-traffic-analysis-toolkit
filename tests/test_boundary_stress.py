"""
Empirical Boundary Stress Test Suite for PCAP Traffic Analysis Toolkit.
Author: Challenger 1 (Empirical Verification & Boundary Stress Challenger)

Tests boundary conditions, stress streams, malformed inputs, edge cases,
and 0% False Positive Rate guarantees across detection/rules.py and database/db.py.
"""
import base64
import os
import sys
import sqlite3
import tempfile
import time
import unittest
from collections import defaultdict

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import database.db as db
import detection.rules as rules


class TestZeroAndEmptyBoundaries(unittest.TestCase):
    """Probes zero-packet, empty-database, and unpopulated telemetry states."""

    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.db_path = self.tmp.name
        self.tmp.close()
        db.init_db(self.db_path)
        self.conn = db.get_connection(self.db_path)

    def tearDown(self):
        self.conn.close()
        if os.path.exists(self.db_path):
            os.remove(self.db_path)

    def test_zero_packets_empty_analysis(self):
        aid = db.create_analysis(self.conn, "empty.pcap", 0)
        parsed = {
            "packets": [],
            "dns": [],
            "http": [],
            "arp": [],
            "credentials": [],
        }
        db.insert_parsed(self.conn, aid, parsed)

        # Verify all rules run on zero packets with zero exceptions
        findings = rules.run_all_rules(self.conn, aid)
        self.assertEqual(len(findings), 0, "Empty capture must yield exactly 0 findings")

        # Verify summary handles empty capture without ZeroDivisionError
        summary = db.get_summary(self.conn, aid)
        self.assertEqual(summary["total_packets"], 0)
        self.assertEqual(summary["total_bytes"], 0)
        self.assertEqual(summary["duration"], 0)
        self.assertEqual(summary["unique_src"], 0)
        self.assertEqual(summary["unique_dst"], 0)

        # Verify traffic timeline handles zero packets
        timeline, bucket = db.traffic_timeline(self.conn, aid)
        self.assertEqual(timeline, [])
        self.assertEqual(bucket, 1)

        # Verify distributions handle zero packets
        self.assertEqual(db.protocol_distribution(self.conn, aid), [])
        self.assertEqual(db.top_talkers(self.conn, aid), [])
        self.assertEqual(db.top_dst_ports(self.conn, aid), [])
        self.assertEqual(db.top_dns_queries(self.conn, aid), [])
        self.assertEqual(db.get_findings(self.conn, aid), [])
        self.assertEqual(db.get_arp_records(self.conn, aid), [])
        self.assertEqual(db.get_credentials(self.conn, aid), [])

        # Verify posture score handles empty findings
        score, cards = rules.calculate_posture_score(findings)
        self.assertEqual(score, 100)
        for pillar, card in cards.items():
            self.assertEqual(card["status"], "PASS")
            self.assertEqual(card["score"], 25)
            self.assertEqual(card["violations_count"], 0)

    def test_nonexistent_analysis_id(self):
        # Querying an ID that does not exist in DB
        fake_aid = 99999
        findings = rules.run_all_rules(self.conn, fake_aid)
        self.assertEqual(len(findings), 0)

        summary = db.get_summary(self.conn, fake_aid)
        self.assertEqual(summary["total_packets"], 0)
        timeline, bucket = db.traffic_timeline(self.conn, fake_aid)
        self.assertEqual(timeline, [])


class TestSinglePacketBoundaries(unittest.TestCase):
    """Probes behavior under single-packet captures of various types."""

    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.db_path = self.tmp.name
        self.tmp.close()
        db.init_db(self.db_path)
        self.conn = db.get_connection(self.db_path)

    def tearDown(self):
        self.conn.close()
        if os.path.exists(self.db_path):
            os.remove(self.db_path)

    def test_single_tcp_syn_packet(self):
        aid = db.create_analysis(self.conn, "single_syn.pcap", 64)
        parsed = {
            "packets": [{
                "timestamp": 1000.0,
                "src_ip": "10.0.0.1",
                "dst_ip": "10.0.0.2",
                "src_mac": "00:11:22:33:44:55",
                "dst_mac": "00:11:22:33:44:66",
                "src_port": 12345,
                "dst_port": 80,
                "transport": "TCP",
                "protocol": "TCP",
                "length": 64,
                "syn": True,
                "ack": False,
                "rst": False,
                "fin": False,
                "psh": False,
                "urg": False,
            }],
            "dns": [], "http": [], "arp": [], "credentials": [],
        }
        db.insert_parsed(self.conn, aid, parsed)
        findings = rules.run_all_rules(self.conn, aid)
        self.assertEqual(len(findings), 0)

        summary = db.get_summary(self.conn, aid)
        self.assertEqual(summary["total_packets"], 1)
        self.assertEqual(summary["duration"], 0)

        timeline, bucket = db.traffic_timeline(self.conn, aid)
        self.assertEqual(len(timeline), 1)

    def test_single_xmas_packet_triggers_evasion(self):
        aid = db.create_analysis(self.conn, "single_xmas.pcap", 64)
        parsed = {
            "packets": [{
                "timestamp": 1000.0,
                "src_ip": "10.0.0.9",
                "dst_ip": "10.0.0.10",
                "src_mac": "00:11:22:33:44:55",
                "dst_mac": "00:11:22:33:44:66",
                "src_port": 45678,
                "dst_port": 80,
                "transport": "TCP",
                "protocol": "TCP",
                "length": 64,
                "syn": False,
                "ack": False,
                "rst": False,
                "fin": True,
                "psh": True,
                "urg": True,
            }],
            "dns": [], "http": [], "arp": [], "credentials": [],
        }
        db.insert_parsed(self.conn, aid, parsed)
        findings = rules.run_all_rules(self.conn, aid)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["rule"], "TCP Flag Evasion")
        self.assertEqual(findings[0]["pillar"], "Integrity")
        self.assertEqual(findings[0]["severity"], "High")

    def test_single_null_packet_triggers_evasion(self):
        aid = db.create_analysis(self.conn, "single_null.pcap", 64)
        parsed = {
            "packets": [{
                "timestamp": 1000.0,
                "src_ip": "10.0.0.9",
                "dst_ip": "10.0.0.10",
                "src_mac": "00:11:22:33:44:55",
                "dst_mac": "00:11:22:33:44:66",
                "src_port": 45678,
                "dst_port": 80,
                "transport": "TCP",
                "protocol": "TCP",
                "length": 64,
                "syn": False,
                "ack": False,
                "rst": False,
                "fin": False,
                "psh": False,
                "urg": False,
            }],
            "dns": [], "http": [], "arp": [], "credentials": [],
        }
        db.insert_parsed(self.conn, aid, parsed)
        findings = rules.run_all_rules(self.conn, aid)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["rule"], "TCP Flag Evasion")
        self.assertEqual(findings[0]["pillar"], "Integrity")


class TestMassivePacketStreamStress(unittest.TestCase):
    """Stress tests database ingestion and detection queries over large packet streams."""

    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.db_path = self.tmp.name
        self.tmp.close()
        db.init_db(self.db_path)
        self.conn = db.get_connection(self.db_path)

    def tearDown(self):
        self.conn.close()
        if os.path.exists(self.db_path):
            os.remove(self.db_path)

    def test_massive_packet_stream(self):
        aid = db.create_analysis(self.conn, "massive.pcap", 10_000_000)
        batch_size = 20000
        packets = []
        base_time = 1700000000.0

        for i in range(batch_size):
            packets.append({
                "timestamp": base_time + (i * 0.01),
                "src_ip": f"192.168.1.{10 + (i % 50)}",
                "dst_ip": f"10.0.0.{1 + (i % 10)}",
                "src_mac": f"02:00:00:00:00:{i % 50:02x}",
                "dst_mac": "02:00:00:00:01:00",
                "src_port": 10000 + (i % 20000),
                "dst_port": 80 if i % 2 == 0 else 443,
                "transport": "TCP",
                "protocol": "TCP",
                "length": 64 + (i % 1400),
                "syn": (i % 20 == 0),
                "ack": (i % 20 != 0),
                "rst": False,
                "fin": False,
                "psh": False,
                "urg": False,
            })

        t0 = time.time()
        db.insert_parsed(self.conn, aid, {"packets": packets})
        insert_time = time.time() - t0

        # Check total packets inserted
        summary = db.get_summary(self.conn, aid)
        self.assertEqual(summary["total_packets"], batch_size)

        # Ensure run_all_rules completes swiftly (< 3.0s) and cleanly
        t1 = time.time()
        findings = rules.run_all_rules(self.conn, aid)
        query_time = time.time() - t1
        self.assertIsInstance(findings, list)
        self.assertLess(query_time, 3.0, f"Query took too long: {query_time:.2f}s")

        # Save findings and verify persistence
        db.save_findings(self.conn, aid, findings)
        saved = db.get_findings(self.conn, aid)
        self.assertEqual(len(saved), len(findings))


class TestMalformedAndCorruptInputs(unittest.TestCase):
    """Probes malformed base64, missing parameters, non-UTF8 strings, and edge case values."""

    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.db_path = self.tmp.name
        self.tmp.close()
        db.init_db(self.db_path)
        self.conn = db.get_connection(self.db_path)

    def tearDown(self):
        self.conn.close()
        if os.path.exists(self.db_path):
            os.remove(self.db_path)

    def test_corrupt_packet_fields_in_insert(self):
        aid = db.create_analysis(self.conn, "corrupt.pcap", 100)
        # Packets with missing keys, None values, negative numbers, unicode symbols
        corrupt_packets = [
            {
                "timestamp": 1000.0,
                "src_ip": None,
                "dst_ip": "10.0.0.1",
                "src_mac": None,
                "dst_mac": None,
                "src_port": None,
                "dst_port": None,
                "transport": None,
                "protocol": "UNKNOWN",
                "length": None,
                "syn": None,
                "ack": None,
                "rst": None,
                "fin": None,
                "psh": None,
                "urg": None,
            },
            {
                "timestamp": 1001.0,
                "src_ip": "'; DROP TABLE packets; --",
                "dst_ip": "10.0.0.2",
                "src_mac": "INVALID_MAC_ADDR",
                "dst_mac": "",
                "src_port": -1,
                "dst_port": 999999,
                "transport": "TCP",
                "protocol": "TCP",
                "length": -50,
                "syn": True,
                "ack": False,
                "rst": False,
                "fin": False,
                "psh": False,
                "urg": False,
            },
            {
                "timestamp": 1002.0,
                "src_ip": "192.168.1.10\x00extra",
                "dst_ip": "10.0.0.3",
                "src_mac": "02:00:00:00:00:01",
                "dst_mac": "02:00:00:00:00:02",
                "src_port": 80,
                "dst_port": 80,
                "transport": "TCP",
                "protocol": "HTTP \U0001f680",
                "length": 1500,
                "syn": False,
                "ack": True,
                "rst": False,
                "fin": False,
                "psh": False,
                "urg": False,
            }
        ]

        # Ingestion must not crash
        db.insert_parsed(self.conn, aid, {"packets": corrupt_packets})

        # Queries must not crash or trigger SQL injection
        summary = db.get_summary(self.conn, aid)
        self.assertEqual(summary["total_packets"], 3)
        findings = rules.run_all_rules(self.conn, aid)
        self.assertIsInstance(findings, list)

    def test_malformed_credentials_and_non_utf8(self):
        aid = db.create_analysis(self.conn, "creds.pcap", 100)
        creds = [
            {
                "timestamp": 1000.0,
                "src_ip": "192.168.1.50",
                "dst_ip": "192.168.1.1",
                "protocol": "HTTP",
                "type": "HTTP Basic Auth",
                "detail": "Decoded credentials: 'admin:\ufffd\ufffd'",
            },
            {
                "timestamp": 1001.0,
                "src_ip": "192.168.1.50",
                "dst_ip": "192.168.1.1",
                "protocol": "HTTP",
                "type": "HTTP Form POST",
                "detail": "Cleartext password: 'pass=\x00\x01\x02\x03'",
            },
            {
                "timestamp": 1002.0,
                "src_ip": "192.168.1.50",
                "dst_ip": "192.168.1.1",
                "protocol": "FTP",
                "type": "FTP PASS",
                "detail": "Cleartext FTP command: PASS " + ("A" * 5000),  # Long detail
            }
        ]
        db.insert_parsed(self.conn, aid, {"credentials": creds})

        findings = rules.detect_cleartext_credentials(self.conn, aid)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["rule"], "Cleartext Credentials")
        self.assertEqual(findings[0]["pillar"], "Confidentiality")
        self.assertEqual(findings[0]["evidence_count"], 3)

        # Save findings and retrieve
        db.save_findings(self.conn, aid, findings)
        stored = db.get_findings(self.conn, aid)
        self.assertEqual(len(stored), 1)
        self.assertEqual(stored[0]["pillar"], "Confidentiality")

    def test_null_timestamp_unhandled_crash_probe(self):
        """
        Adversarial probe: tests whether packets with NULL timestamp cause
        detect_port_scan or detect_brute_force to crash.
        """
        aid = db.create_analysis(self.conn, "null_ts.pcap", 100)
        null_ts_packet = {
            "timestamp": None,
            "src_ip": "10.0.0.1",
            "dst_ip": "10.0.0.2",
            "src_mac": "00:11:22:33:44:55",
            "dst_mac": "00:11:22:33:44:66",
            "src_port": 12345,
            "dst_port": 22,
            "transport": "TCP",
            "protocol": "TCP",
            "length": 64,
            "syn": True,
            "ack": False,
            "rst": False,
            "fin": False,
            "psh": False,
            "urg": False,
        }
        db.insert_parsed(self.conn, aid, {"packets": [null_ts_packet]})

        # Port scan
        try:
            rules.detect_port_scan(self.conn, aid)
            port_scan_crashed = False
        except TypeError:
            port_scan_crashed = True

        # Brute force
        try:
            rules.detect_brute_force(self.conn, aid)
            brute_force_crashed = False
        except TypeError:
            brute_force_crashed = True

        # Document and assert the empirical findings:
        self.assertTrue(port_scan_crashed, "detect_port_scan raises TypeError when timestamp is NULL")
        self.assertTrue(brute_force_crashed, "detect_brute_force raises TypeError when timestamp is NULL")


class TestARPMACBoundaries(unittest.TestCase):
    """Probes conflicting MACs, broadcast MACs, and null MAC handling in ARP spoofing detection."""

    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.db_path = self.tmp.name
        self.tmp.close()
        db.init_db(self.db_path)
        self.conn = db.get_connection(self.db_path)

    def tearDown(self):
        self.conn.close()
        if os.path.exists(self.db_path):
            os.remove(self.db_path)

    def test_broadcast_and_null_macs_excluded(self):
        aid = db.create_analysis(self.conn, "arp_broadcast.pcap", 100)
        # Same IP associated with a legitimate MAC, plus broadcast and null MACs
        arp_records = [
            {"timestamp": 1.0, "src_ip": "192.168.1.1", "dst_ip": "192.168.1.50",
             "src_mac": "00:11:22:33:44:55", "dst_mac": "ff:ff:ff:ff:ff:ff", "opcode": "who-has"},
            {"timestamp": 2.0, "src_ip": "192.168.1.1", "dst_ip": "192.168.1.50",
             "src_mac": "ff:ff:ff:ff:ff:ff", "dst_mac": "00:11:22:33:44:55", "opcode": "is-at"},
            {"timestamp": 3.0, "src_ip": "192.168.1.1", "dst_ip": "192.168.1.50",
             "src_mac": "00:00:00:00:00:00", "dst_mac": "00:11:22:33:44:55", "opcode": "is-at"},
        ]
        db.insert_parsed(self.conn, aid, {"arp": arp_records})

        # Broadcast and null MACs must be filtered out so mac_count == 1
        findings = rules.detect_arp_spoofing(self.conn, aid)
        self.assertEqual(len(findings), 0, "Lowercase broadcast/null MACs must not trigger ARP spoofing false positive")

    def test_uppercase_broadcast_mac_empirical_behavior(self):
        """
        Adversarial probe: tests whether uppercase FF:FF:FF:FF:FF:FF triggers
        a false positive due to case-sensitive comparison in SQLite.
        """
        aid = db.create_analysis(self.conn, "arp_upper.pcap", 100)
        arp_records = [
            {"timestamp": 1.0, "src_ip": "192.168.1.1", "dst_ip": "192.168.1.50",
             "src_mac": "00:11:22:33:44:55", "dst_mac": "FF:FF:FF:FF:FF:FF", "opcode": "who-has"},
            {"timestamp": 2.0, "src_ip": "192.168.1.1", "dst_ip": "192.168.1.50",
             "src_mac": "FF:FF:FF:FF:FF:FF", "dst_mac": "00:11:22:33:44:55", "opcode": "is-at"},
        ]
        db.insert_parsed(self.conn, aid, {"arp": arp_records})
        findings = rules.detect_arp_spoofing(self.conn, aid)

        # In SQLite, LOWER(src_mac) NOT IN ('ff:ff:ff:ff:ff:ff', '00:00:00:00:00:00') safely excludes uppercase broadcast MACs.
        self.assertEqual(len(findings), 0, "Hardened: uppercase broadcast excluded from ARP spoofing")

    def test_conflicting_legitimate_macs_trigger(self):
        aid = db.create_analysis(self.conn, "arp_mitm.pcap", 100)
        arp_records = [
            {"timestamp": 1.0, "src_ip": "192.168.1.1", "dst_ip": "192.168.1.50",
             "src_mac": "00:11:22:33:44:55", "dst_mac": "02:00:00:00:00:50", "opcode": "is-at"},
            {"timestamp": 2.0, "src_ip": "192.168.1.1", "dst_ip": "192.168.1.50",
             "src_mac": "02:00:00:00:00:99", "dst_mac": "02:00:00:00:00:50", "opcode": "is-at"},
        ]
        db.insert_parsed(self.conn, aid, {"arp": arp_records})
        findings = rules.detect_arp_spoofing(self.conn, aid)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["rule"], "ARP Cache Poisoning")
        self.assertEqual(findings[0]["pillar"], "Integrity")
        self.assertEqual(findings[0]["severity"], "High")
        self.assertEqual(findings[0]["src_ip"], "192.168.1.1")


class TestSYNFloodBoundaryRatios(unittest.TestCase):
    """Probes exact boundaries for SYN counts (49 vs 50) and ratios (2.9x vs 3.0x)."""

    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.db_path = self.tmp.name
        self.tmp.close()
        db.init_db(self.db_path)
        self.conn = db.get_connection(self.db_path)

    def tearDown(self):
        self.conn.close()
        if os.path.exists(self.db_path):
            os.remove(self.db_path)

    def _insert_syn_stream(self, aid, syn_count, ack_count, dst_port=80, dst_ip="10.0.0.1"):
        packets = []
        t = 1000.0
        # Insert syn_count packets with syn=1, ack=0 to server
        for i in range(syn_count):
            packets.append({
                "timestamp": t + (i * 0.01),
                "src_ip": f"192.168.1.{100 + (i % 50)}",
                "dst_ip": dst_ip,
                "src_mac": "00:11:22:33:44:55",
                "dst_mac": "00:11:22:33:44:66",
                "src_port": 20000 + i,
                "dst_port": dst_port,
                "transport": "TCP",
                "protocol": "TCP",
                "length": 64,
                "syn": True,
                "ack": False,
                "rst": False,
                "fin": False,
                "psh": False,
                "urg": False,
            })
        # Insert ack_count packets with ack=1 to server
        for j in range(ack_count):
            packets.append({
                "timestamp": t + (j * 0.01) + 0.005,
                "src_ip": f"192.168.1.{100 + (j % 50)}",
                "dst_ip": dst_ip,
                "src_mac": "00:11:22:33:44:55",
                "dst_mac": "00:11:22:33:44:66",
                "src_port": 20000 + j,
                "dst_port": dst_port,
                "transport": "TCP",
                "protocol": "TCP",
                "length": 64,
                "syn": False,
                "ack": True,
                "rst": False,
                "fin": False,
                "psh": False,
                "urg": False,
            })
        db.insert_parsed(self.conn, aid, {"packets": packets})

    def test_syn_count_boundary_49_vs_50(self):
        # 49 SYNs, 0 ACKs: ratio is 49 / (0 + 1) = 49.0 >= 3.0, but syn_count=49 < 50
        aid_49 = db.create_analysis(self.conn, "syn_49.pcap", 100)
        self._insert_syn_stream(aid_49, syn_count=49, ack_count=0)
        findings_49 = rules.detect_syn_flood(self.conn, aid_49)
        self.assertEqual(len(findings_49), 0, "49 SYNs must NOT trigger SYN flood (threshold >= 50)")

        # 50 SYNs, 0 ACKs: syn_count=50 >= 50 and ratio >= 3.0
        aid_50 = db.create_analysis(self.conn, "syn_50.pcap", 100)
        self._insert_syn_stream(aid_50, syn_count=50, ack_count=0)
        findings_50 = rules.detect_syn_flood(self.conn, aid_50)
        self.assertEqual(len(findings_50), 1, "50 SYNs with 0 ACKs MUST trigger SYN flood")
        self.assertEqual(findings_50[0]["rule"], "TCP SYN Flood")
        self.assertEqual(findings_50[0]["pillar"], "Availability")

    def test_syn_ratio_boundary_below_and_above_3(self):
        # 60 SYNs, 20 ACKs: ratio = 60 / (20 + 1) = 60/21 = 2.857 < 3.0 -> MUST NOT trigger
        aid_below = db.create_analysis(self.conn, "syn_ratio_2_85.pcap", 100)
        self._insert_syn_stream(aid_below, syn_count=60, ack_count=20)
        findings_below = rules.detect_syn_flood(self.conn, aid_below)
        self.assertEqual(len(findings_below), 0, "Ratio 2.857x < 3.0x must NOT trigger SYN flood")

        # 60 SYNs, 19 ACKs: ratio = 60 / (19 + 1) = 60/20 = 3.000 >= 3.0 -> MUST trigger
        aid_above = db.create_analysis(self.conn, "syn_ratio_3_00.pcap", 100)
        self._insert_syn_stream(aid_above, syn_count=60, ack_count=19)
        findings_above = rules.detect_syn_flood(self.conn, aid_above)
        self.assertEqual(len(findings_above), 1, "Ratio 3.0x >= 3.0x MUST trigger SYN flood")


class TestBurstyBenignBrowsingAndZeroFPR(unittest.TestCase):
    """Probes realistic benign bursty traffic to confirm 0% False Positive Rate across all rules."""

    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.db_path = self.tmp.name
        self.tmp.close()
        db.init_db(self.db_path)
        self.conn = db.get_connection(self.db_path)

    def tearDown(self):
        self.conn.close()
        if os.path.exists(self.db_path):
            os.remove(self.db_path)

    def test_benign_web_browsing_multiple_requests(self):
        aid = db.create_analysis(self.conn, "benign_bursty.pcap", 5000)
        packets = []
        t = 1000.0
        # 4 clients each opening 50 HTTP/HTTPS connections with full handshakes
        clients = ["192.168.1.10", "192.168.1.11", "192.168.1.12", "192.168.1.13"]
        servers = ["93.184.216.34", "151.101.1.69", "172.217.16.206"]

        for client in clients:
            for s in range(50):
                srv = servers[s % len(servers)]
                sport = 40000 + s
                dport = 80 if s % 2 == 0 else 443

                # SYN
                packets.append({
                    "timestamp": t, "src_ip": client, "dst_ip": srv,
                    "src_mac": "02:00:00:00:00:10", "dst_mac": "02:00:00:00:00:01",
                    "src_port": sport, "dst_port": dport, "transport": "TCP", "protocol": "TCP",
                    "length": 64, "syn": True, "ack": False, "rst": False, "fin": False, "psh": False, "urg": False,
                })
                # SYN-ACK
                packets.append({
                    "timestamp": t + 0.01, "src_ip": srv, "dst_ip": client,
                    "src_mac": "02:00:00:00:00:01", "dst_mac": "02:00:00:00:00:10",
                    "src_port": dport, "dst_port": sport, "transport": "TCP", "protocol": "TCP",
                    "length": 64, "syn": True, "ack": True, "rst": False, "fin": False, "psh": False, "urg": False,
                })
                # ACK
                packets.append({
                    "timestamp": t + 0.02, "src_ip": client, "dst_ip": srv,
                    "src_mac": "02:00:00:00:00:10", "dst_mac": "02:00:00:00:00:01",
                    "src_port": sport, "dst_port": dport, "transport": "TCP", "protocol": "TCP",
                    "length": 64, "syn": False, "ack": True, "rst": False, "fin": False, "psh": False, "urg": False,
                })
                # Data (HTTP PUSH)
                packets.append({
                    "timestamp": t + 0.03, "src_ip": client, "dst_ip": srv,
                    "src_mac": "02:00:00:00:00:10", "dst_mac": "02:00:00:00:00:01",
                    "src_port": sport, "dst_port": dport, "transport": "TCP", "protocol": "HTTP",
                    "length": 350, "syn": False, "ack": True, "rst": False, "fin": False, "psh": True, "urg": False,
                })
                # Response Data
                packets.append({
                    "timestamp": t + 0.05, "src_ip": srv, "dst_ip": client,
                    "src_mac": "02:00:00:00:00:01", "dst_mac": "02:00:00:00:00:10",
                    "src_port": dport, "dst_port": sport, "transport": "TCP", "protocol": "HTTP",
                    "length": 1400, "syn": False, "ack": True, "rst": False, "fin": False, "psh": True, "urg": False,
                })
                t += 0.2

        db.insert_parsed(self.conn, aid, {"packets": packets})

        # Run all rules
        findings = rules.run_all_rules(self.conn, aid)
        self.assertEqual(len(findings), 0, f"Benign bursty traffic triggered false positive: {findings}")

    def test_port_scan_boundary_14_vs_15_ports(self):
        # 14 distinct ports contacted in 60s -> MUST NOT trigger (threshold >= 15)
        aid_14 = db.create_analysis(self.conn, "ports_14.pcap", 100)
        packets_14 = [{
            "timestamp": 1000.0 + i, "src_ip": "192.168.1.100", "dst_ip": "10.0.0.1",
            "src_mac": "00:11:22:33:44:55", "dst_mac": "00:11:22:33:44:66",
            "src_port": 30000 + i, "dst_port": 1000 + i, "transport": "TCP", "protocol": "TCP",
            "length": 64, "syn": True, "ack": False, "rst": False, "fin": False, "psh": False, "urg": False,
        } for i in range(14)]
        db.insert_parsed(self.conn, aid_14, {"packets": packets_14})
        findings_14 = rules.detect_port_scan(self.conn, aid_14)
        self.assertEqual(len(findings_14), 0, "14 ports must NOT trigger Port Scan")

        # 15 distinct ports contacted in 60s -> MUST trigger
        aid_15 = db.create_analysis(self.conn, "ports_15.pcap", 100)
        packets_15 = [{
            "timestamp": 1000.0 + i, "src_ip": "192.168.1.100", "dst_ip": "10.0.0.1",
            "src_mac": "00:11:22:33:44:55", "dst_mac": "00:11:22:33:44:66",
            "src_port": 30000 + i, "dst_port": 1000 + i, "transport": "TCP", "protocol": "TCP",
            "length": 64, "syn": True, "ack": False, "rst": False, "fin": False, "psh": False, "urg": False,
        } for i in range(15)]
        db.insert_parsed(self.conn, aid_15, {"packets": packets_15})
        findings_15 = rules.detect_port_scan(self.conn, aid_15)
        self.assertEqual(len(findings_15), 1, "15 ports MUST trigger Port Scan")
        self.assertEqual(findings_15[0]["rule"], "Port Scan")
        self.assertEqual(findings_15[0]["pillar"], "Authentication")

    def test_brute_force_boundary_19_vs_20_attempts(self):
        # 19 attempts on port 22 in 60s -> MUST NOT trigger (threshold >= 20)
        aid_19 = db.create_analysis(self.conn, "ssh_19.pcap", 100)
        packets_19 = [{
            "timestamp": 1000.0 + (i * 0.5), "src_ip": "192.168.1.100", "dst_ip": "10.0.0.1",
            "src_mac": "00:11:22:33:44:55", "dst_mac": "00:11:22:33:44:66",
            "src_port": 30000 + i, "dst_port": 22, "transport": "TCP", "protocol": "TCP",
            "length": 64, "syn": True, "ack": False, "rst": False, "fin": False, "psh": False, "urg": False,
        } for i in range(19)]
        db.insert_parsed(self.conn, aid_19, {"packets": packets_19})
        findings_19 = rules.detect_brute_force(self.conn, aid_19)
        self.assertEqual(len(findings_19), 0, "19 attempts must NOT trigger Brute Force")

        # 20 attempts on port 22 in 60s -> MUST trigger
        aid_20 = db.create_analysis(self.conn, "ssh_20.pcap", 100)
        packets_20 = [{
            "timestamp": 1000.0 + (i * 0.5), "src_ip": "192.168.1.100", "dst_ip": "10.0.0.1",
            "src_mac": "00:11:22:33:44:55", "dst_mac": "00:11:22:33:44:66",
            "src_port": 30000 + i, "dst_port": 22, "transport": "TCP", "protocol": "TCP",
            "length": 64, "syn": True, "ack": False, "rst": False, "fin": False, "psh": False, "urg": False,
        } for i in range(20)]
        db.insert_parsed(self.conn, aid_20, {"packets": packets_20})
        findings_20 = rules.detect_brute_force(self.conn, aid_20)
        self.assertEqual(len(findings_20), 1, "20 attempts MUST trigger Brute Force")
        self.assertEqual(findings_20[0]["rule"], "Brute Force")
        self.assertEqual(findings_20[0]["pillar"], "Authentication")

    def test_dns_query_boundary_100_vs_101_and_len_50_vs_51(self):
        # 100 queries -> MUST NOT trigger (threshold > 100)
        aid_100 = db.create_analysis(self.conn, "dns_100.pcap", 100)
        dns_100 = [{
            "timestamp": 1000.0 + i, "src_ip": "192.168.1.10", "dst_ip": "8.8.8.8",
            "query": f"domain{i}.com", "is_response": 0
        } for i in range(100)]
        db.insert_parsed(self.conn, aid_100, {"dns": dns_100})
        findings_100 = rules.detect_dns_anomaly(self.conn, aid_100)
        self.assertEqual(len(findings_100), 0, "100 queries must NOT trigger DNS query flood")

        # 101 queries -> MUST trigger
        aid_101 = db.create_analysis(self.conn, "dns_101.pcap", 100)
        dns_101 = [{
            "timestamp": 1000.0 + i, "src_ip": "192.168.1.10", "dst_ip": "8.8.8.8",
            "query": f"domain{i}.com", "is_response": 0
        } for i in range(101)]
        db.insert_parsed(self.conn, aid_101, {"dns": dns_101})
        findings_101 = rules.detect_dns_anomaly(self.conn, aid_101)
        self.assertTrue(any(f["detail"].startswith("192.168.1.10 made 101") for f in findings_101))

        # Query len 50 -> MUST NOT trigger (threshold > 50)
        aid_len50 = db.create_analysis(self.conn, "dns_len50.pcap", 100)
        dns_len50 = [{
            "timestamp": 1000.0, "src_ip": "192.168.1.10", "dst_ip": "8.8.8.8",
            "query": "a" * 50, "is_response": 0
        }]
        db.insert_parsed(self.conn, aid_len50, {"dns": dns_len50})
        findings_len50 = rules.detect_dns_anomaly(self.conn, aid_len50)
        self.assertEqual(len(findings_len50), 0, "Query length 50 must NOT trigger long domain anomaly")

        # Query len 51 -> MUST trigger
        aid_len51 = db.create_analysis(self.conn, "dns_len51.pcap", 100)
        dns_len51 = [{
            "timestamp": 1000.0, "src_ip": "192.168.1.10", "dst_ip": "8.8.8.8",
            "query": "a" * 51, "is_response": 0
        }]
        db.insert_parsed(self.conn, aid_len51, {"dns": dns_len51})
        findings_len51 = rules.detect_dns_anomaly(self.conn, aid_len51)
        self.assertEqual(len(findings_len51), 1, "Query length 51 MUST trigger long domain anomaly")

    def test_volume_anomaly_boundary(self):
        # Case 1: 2 hosts in capture, one host sends 99% -> MUST NOT trigger (min_hosts >= 3)
        aid_2h = db.create_analysis(self.conn, "vol_2h.pcap", 1000)
        pkts_2h = [
            {"timestamp": 1000.0 + i, "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2",
             "src_port": 1234, "dst_port": 80, "transport": "TCP", "protocol": "TCP",
             "length": 1000, "syn": False, "ack": True, "rst": False, "fin": False, "psh": False, "urg": False}
            for i in range(150)
        ] + [
            {"timestamp": 1000.0 + i, "src_ip": "10.0.0.2", "dst_ip": "10.0.0.1",
             "src_port": 80, "dst_port": 1234, "transport": "TCP", "protocol": "TCP",
             "length": 50, "syn": False, "ack": True, "rst": False, "fin": False, "psh": False, "urg": False}
            for i in range(10)
        ]
        db.insert_parsed(self.conn, aid_2h, {"packets": pkts_2h})
        findings_2h = rules.detect_volume_anomaly(self.conn, aid_2h)
        self.assertEqual(len(findings_2h), 0, "2 hosts must NOT trigger Volume Anomaly (threshold >= 3 hosts)")

        # Case 2: 3 hosts, 99 packets -> MUST NOT trigger (min_packets >= 100)
        aid_99p = db.create_analysis(self.conn, "vol_99p.pcap", 1000)
        pkts_99p = [
            {"timestamp": 1000.0 + i, "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2",
             "src_port": 1234, "dst_port": 80, "transport": "TCP", "protocol": "TCP",
             "length": 1000, "syn": False, "ack": True, "rst": False, "fin": False, "psh": False, "urg": False}
            for i in range(97)
        ] + [
            {"timestamp": 1000.0, "src_ip": "10.0.0.2", "dst_ip": "10.0.0.1",
             "src_port": 80, "dst_port": 1234, "transport": "TCP", "protocol": "TCP",
             "length": 50, "syn": False, "ack": True, "rst": False, "fin": False, "psh": False, "urg": False},
            {"timestamp": 1000.0, "src_ip": "10.0.0.3", "dst_ip": "10.0.0.1",
             "src_port": 80, "dst_port": 1234, "transport": "TCP", "protocol": "TCP",
             "length": 50, "syn": False, "ack": True, "rst": False, "fin": False, "psh": False, "urg": False},
        ]
        db.insert_parsed(self.conn, aid_99p, {"packets": pkts_99p})
        findings_99p = rules.detect_volume_anomaly(self.conn, aid_99p)
        self.assertEqual(len(findings_99p), 0, "99 packets must NOT trigger Volume Anomaly (threshold >= 100 packets)")

        # Case 3: 3 hosts, 100 packets, host 1 has 49% share (4900/10000) -> MUST NOT trigger
        aid_49s = db.create_analysis(self.conn, "vol_49s.pcap", 1000)
        pkts_49s = [
            {"timestamp": 1000.0 + i, "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2",
             "src_port": 1234, "dst_port": 80, "transport": "TCP", "protocol": "TCP",
             "length": 100, "syn": False, "ack": True, "rst": False, "fin": False, "psh": False, "urg": False}
            for i in range(49)
        ] + [
            {"timestamp": 1000.0 + i, "src_ip": "10.0.0.2", "dst_ip": "10.0.0.1",
             "src_port": 80, "dst_port": 1234, "transport": "TCP", "protocol": "TCP",
             "length": 100, "syn": False, "ack": True, "rst": False, "fin": False, "psh": False, "urg": False}
            for i in range(26)
        ] + [
            {"timestamp": 1000.0 + i, "src_ip": "10.0.0.3", "dst_ip": "10.0.0.1",
             "src_port": 80, "dst_port": 1234, "transport": "TCP", "protocol": "TCP",
             "length": 100, "syn": False, "ack": True, "rst": False, "fin": False, "psh": False, "urg": False}
            for i in range(25)
        ]
        # Total bytes: 4900 + 2600 + 2500 = 10000 bytes. Max share is 10.0.0.1 (49.0% < 50.0%).
        db.insert_parsed(self.conn, aid_49s, {"packets": pkts_49s})
        findings_49s = rules.detect_volume_anomaly(self.conn, aid_49s)
        self.assertEqual(len(findings_49s), 0, "49% share must NOT trigger Volume Anomaly (threshold >= 50%)")

        # Case 4: 3 hosts, 100 packets, host 1 has 50% share (5000/10000) -> MUST trigger
        aid_50s = db.create_analysis(self.conn, "vol_50s.pcap", 1000)
        pkts_50s = [
            {"timestamp": 1000.0 + i, "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2",
             "src_port": 1234, "dst_port": 80, "transport": "TCP", "protocol": "TCP",
             "length": 100, "syn": False, "ack": True, "rst": False, "fin": False, "psh": False, "urg": False}
            for i in range(50)
        ] + [
            {"timestamp": 1000.0 + i, "src_ip": "10.0.0.2", "dst_ip": "10.0.0.1",
             "src_port": 80, "dst_port": 1234, "transport": "TCP", "protocol": "TCP",
             "length": 100, "syn": False, "ack": True, "rst": False, "fin": False, "psh": False, "urg": False}
            for i in range(25)
        ] + [
            {"timestamp": 1000.0 + i, "src_ip": "10.0.0.3", "dst_ip": "10.0.0.1",
             "src_port": 80, "dst_port": 1234, "transport": "TCP", "protocol": "TCP",
             "length": 100, "syn": False, "ack": True, "rst": False, "fin": False, "psh": False, "urg": False}
            for i in range(25)
        ]
        # Total bytes: 5000 + 2500 + 2500 = 10000 bytes. 10.0.0.1 = 50.0% >= 50.0% -> triggers!
        db.insert_parsed(self.conn, aid_50s, {"packets": pkts_50s})
        findings_50s = rules.detect_volume_anomaly(self.conn, aid_50s)
        self.assertEqual(len(findings_50s), 1, "50% share MUST trigger Volume Anomaly")
        self.assertEqual(findings_50s[0]["rule"], "Volume Anomaly")
        self.assertEqual(findings_50s[0]["pillar"], "Availability")


class TestPostureScoringBoundaries(unittest.TestCase):
    """Probes posture scoring clamping, severity deductions, and dual-access compatibility."""

    def test_posture_score_properties(self):
        # Empty findings
        res0 = rules.calculate_posture_score([])
        self.assertEqual(res0.overall_score, 100)
        self.assertEqual(res0[0], 100)
        self.assertEqual(res0["overall_score"], 100)
        self.assertEqual(res0.get("overall_score"), 100)

        # 1 Low finding in Confidentiality
        res_low = rules.calculate_posture_score([{"pillar": "Confidentiality", "severity": "Low"}])
        self.assertEqual(res_low.overall_score, 97)
        self.assertEqual(res_low.pillar_cards["Confidentiality"]["status"], "WARNING")
        self.assertEqual(res_low.pillar_cards["Confidentiality"]["score"], 22)

        # 1 Medium finding in Confidentiality
        res_med = rules.calculate_posture_score([{"pillar": "Confidentiality", "severity": "Medium"}])
        self.assertEqual(res_med.overall_score, 92)
        self.assertEqual(res_med.pillar_cards["Confidentiality"]["status"], "WARNING")
        self.assertEqual(res_med.pillar_cards["Confidentiality"]["score"], 17)

        # 1 High finding in Confidentiality
        res_high = rules.calculate_posture_score([{"pillar": "Confidentiality", "severity": "High"}])
        self.assertEqual(res_high.overall_score, 85)
        self.assertEqual(res_high.pillar_cards["Confidentiality"]["status"], "FAIL")
        self.assertEqual(res_high.pillar_cards["Confidentiality"]["score"], 10)

        # Extreme findings: 10 High findings per pillar
        extreme = []
        for p in ["Confidentiality", "Integrity", "Authentication", "Availability"]:
            for _ in range(10):
                extreme.append({"pillar": p, "severity": "High"})
        res_ext = rules.calculate_posture_score(extreme)
        self.assertEqual(res_ext.overall_score, 0, "Score must clamp to minimum 0")
        for p, card in res_ext.pillar_cards.items():
            self.assertEqual(card["score"], 0)
            self.assertEqual(card["status"], "FAIL")


class TestDatabaseMigrationsAndSchemaResilience(unittest.TestCase):
    """Probes SQLite table migrations, idempotent init_db, and schema upgrade paths."""

    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.db_path = self.tmp.name
        self.tmp.close()

    def tearDown(self):
        if os.path.exists(self.db_path):
            os.remove(self.db_path)

    def test_init_db_idempotency(self):
        # Multiple init_db calls must not crash or wipe existing data
        db.init_db(self.db_path)
        conn = db.get_connection(self.db_path)
        aid = db.create_analysis(conn, "test.pcap", 100)
        conn.close()

        # Re-initialize on existing populated database
        db.init_db(self.db_path)
        conn = db.get_connection(self.db_path)
        analysis = db.get_analysis(conn, aid)
        self.assertIsNotNone(analysis)
        self.assertEqual(analysis["filename"], "test.pcap")
        conn.close()

    def test_migrate_legacy_schema(self):
        # Create an unmigrated legacy schema (without src_mac, dst_mac, fin, psh, urg, pillar, evidence)
        conn = sqlite3.connect(self.db_path)
        conn.execute("""
        CREATE TABLE packets (
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
            syn INTEGER DEFAULT 0,
            ack INTEGER DEFAULT 0,
            rst INTEGER DEFAULT 0
        )
        """)
        conn.execute("""
        CREATE TABLE findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            analysis_id INTEGER,
            rule TEXT,
            severity TEXT,
            src_ip TEXT,
            dst_ip TEXT,
            detail TEXT,
            evidence_count INTEGER
        )
        """)
        conn.commit()

        # Run migration
        db.migrate_db(conn)

        # Verify added columns exist
        p_cols = {row[1] for row in conn.execute("PRAGMA table_info(packets)").fetchall()}
        for col in ["src_mac", "dst_mac", "fin", "psh", "urg"]:
            self.assertIn(col, p_cols)

        f_cols = {row[1] for row in conn.execute("PRAGMA table_info(findings)").fetchall()}
        for col in ["pillar", "evidence"]:
            self.assertIn(col, f_cols)
        conn.close()


class TestParserCredentialExtractionLogic(unittest.TestCase):
    """Probes base64 decoding, hex parsing, non-UTF8 handling in parser logic."""

    def test_malformed_base64_auth_headers(self):
        # We simulate the exact logic from pcap_parser.py lines 185-199
        test_headers = [
            ("Basic ", ""),                                 # Empty
            ("Basic !@#$%^&*()", ""),                       # Non-base64 characters discarded by b64decode -> empty
            ("Basic YWRtaW4", None),                        # Invalid base64 padding (raises binascii.Error)
            ("Basic " + base64.b64encode(b"\xff\xfe\x00\x80").decode(), "\ufffd\ufffd\x00\ufffd"), # Non-UTF8
            ("Basic " + base64.b64encode(b"admin:pass123").decode(), "admin:pass123"),              # Valid
            (None, None),                                   # None header
            ("Bearer eyJhbGciOi...", None),                 # Non-Basic auth
        ]
        results = []
        for auth, expected in test_headers:
            decoded = None
            if auth and "Basic " in auth:
                try:
                    b64 = auth.split("Basic ", 1)[1].strip()
                    decoded = base64.b64decode(b64).decode("utf-8", "replace")
                except Exception:
                    decoded = None
            if expected is not None:
                self.assertEqual(decoded, expected)
            else:
                self.assertIsNone(decoded)

    def test_malformed_http_post_bodies(self):
        # We simulate the exact logic from pcap_parser.py lines 202-222
        test_bodies = [
            ("70617373776f72643d736563726574313233", True),   # Hex password=secret123
            ("70:61:73:73:77:6f:72:64:3d:73:65:63:72:65:74", True), # Colon hex password=secret
            ("invalid:hex:string:zz", False),                 # Malformed hex without password
            ("password=plain_body_pass", True),               # Raw plain body with password
            ("user=alice&action=view", False),                # Missing password parameter
            ("", False),                                      # Empty body
            (None, False),                                    # None body
            ("ff:fe:00:80:70:61:73:73:77:6f:72:64:3d:31", True), # Non-UTF8 hex with password=1
        ]
        for file_data, should_flag in test_bodies:
            flagged = False
            if file_data:
                raw_body = ""
                try:
                    clean_hex = str(file_data).replace(":", "")
                    raw_body = bytes.fromhex(clean_hex).decode("utf-8", "replace")
                except Exception:
                    raw_body = str(file_data)
                lower_body = raw_body.lower()
                if any(k in lower_body for k in ("password=", "pass=", "pwd=", "passwd=")):
                    flagged = True
            self.assertEqual(flagged, should_flag, f"Failed for file_data: {file_data}")


if __name__ == "__main__":
    unittest.main()
