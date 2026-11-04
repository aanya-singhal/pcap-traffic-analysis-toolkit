#!/usr/bin/env python3
"""
Generate a labelled PCAP evaluation corpus for the CIA Triad toolkit.

Each capture embeds a known attack (or benign traffic) against a background,
so ground truth is exact and reproducible. Writes the .pcap files plus a
labels.json manifest mapping each file to the rule(s) it should trigger.

Run:  python3 generate_datasets.py
Output: datasets/*.pcap  and  datasets/labels.json

Scapy only — no root, no live capture. Re-running reproduces byte-identical intent.
"""
import json
import os
import random
from scapy.all import Ether, IP, TCP, UDP, DNS, DNSQR, ARP, Raw, wrpcap

random.seed(1337)
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "datasets")
os.makedirs(OUT, exist_ok=True)

MAC_A = "aa:bb:cc:00:00:01"
MAC_B = "aa:bb:cc:00:00:02"
MAC_GW = "aa:bb:cc:00:00:fe"
MAC_ATT = "de:ad:be:ef:00:99"


def eth(src_mac, dst_mac):
    return Ether(src=src_mac, dst=dst_mac)


def tcp_pkt(src_mac, dst_mac, sip, dip, sport, dport, flags, ts, payload=None, size=0):
    p = eth(src_mac, dst_mac) / IP(src=sip, dst=dip) / TCP(sport=sport, dport=dport, flags=flags)
    if payload:
        p = p / Raw(load=payload)
    elif size:
        p = p / Raw(load=b"x" * size)
    p.time = ts
    return p


def udp_dns_query(src_mac, sip, dip, qname, ts, sport=40000):
    p = (eth(src_mac, MAC_GW) / IP(src=sip, dst=dip) / UDP(sport=sport, dport=53)
         / DNS(rd=1, qr=0, qd=DNSQR(qname=qname)))
    p.time = ts
    return p


def benign_background(start_ts=0.0, n_hosts=4, base="10.0.0."):
    """A little normal traffic: completed TCP handshakes, short DNS, single-MAC ARP."""
    pkts = []
    ts = start_ts
    clients = [f"{base}{10+i}" for i in range(n_hosts)]
    server = f"{base}200"
    for c in clients:
        # normal 3-way handshake + data + DNS lookup
        pkts.append(tcp_pkt(MAC_A, MAC_GW, c, server, 51000, 443, "S", ts)); ts += 0.01
        pkts.append(tcp_pkt(MAC_GW, MAC_A, server, c, 443, 51000, "SA", ts)); ts += 0.01
        pkts.append(tcp_pkt(MAC_A, MAC_GW, c, server, 51000, 443, "A", ts)); ts += 0.01
        pkts.append(tcp_pkt(MAC_A, MAC_GW, c, server, 51000, 443, "PA", ts, size=400)); ts += 0.02
        pkts.append(udp_dns_query(MAC_A, c, "10.0.0.53", "www.example.com", ts)); ts += 0.05
    return pkts


# ---------------- individual attack captures ----------------

def gen_port_scan():
    pkts, ts = [], 100.0
    att, tgt = "10.0.0.50", "10.0.0.10"
    for port in range(1000, 1031):          # 31 distinct ports, none in the suspicious list
        pkts.append(tcp_pkt(MAC_ATT, MAC_GW, att, tgt, 55000, port, "S", ts)); ts += 0.05
    return pkts, ["Port Scan"]


def gen_brute_force():
    pkts, ts = [], 200.0
    att, tgt = "10.0.0.60", "10.0.0.22"
    for _ in range(30):                      # 30 SYNs to one auth port (22) -> brute force, not a scan
        pkts.append(tcp_pkt(MAC_ATT, MAC_GW, att, tgt, random.randint(40000, 60000), 22, "S", ts)); ts += 0.3
    return pkts, ["Brute Force"]


def gen_arp_spoof():
    pkts, ts = [], 300.0
    # gateway IP 10.0.0.1 claimed by two different MACs = poisoning
    for i in range(6):
        pkts.append((eth(MAC_GW, "ff:ff:ff:ff:ff:ff") / ARP(op=2, psrc="10.0.0.1", hwsrc=MAC_GW,
                     pdst="10.0.0.10", hwdst=MAC_A))); pkts[-1].time = ts; ts += 1.0
        pkts.append((eth(MAC_ATT, "ff:ff:ff:ff:ff:ff") / ARP(op=2, psrc="10.0.0.1", hwsrc=MAC_ATT,
                     pdst="10.0.0.10", hwdst=MAC_A))); pkts[-1].time = ts; ts += 1.0
    return pkts, ["ARP Cache Poisoning"]


def gen_syn_flood():
    pkts, ts = [], 400.0
    tgt = "10.0.0.80"
    for i in range(200):                     # 200 unacked SYNs to one port, no ACKs
        src = f"10.0.{random.randint(1,254)}.{random.randint(1,254)}"
        pkts.append(tcp_pkt(MAC_ATT, MAC_GW, src, tgt, random.randint(1024, 65000), 80, "S", ts)); ts += 0.01
    return pkts, ["TCP SYN Flood"]


def gen_dns_tunnel():
    pkts, ts = [], 500.0
    att = "10.0.0.66"
    for i in range(120):                     # 120 queries (>100) AND long encoded names (>50 chars)
        label = "".join(random.choice("0123456789abcdef") for _ in range(40))
        qname = f"{label}{i:04d}.exfil.attacker-c2.net"
        pkts.append(udp_dns_query(MAC_ATT, att, "10.0.0.53", qname, ts)); ts += 0.1
    return pkts, ["DNS Anomaly"]


def gen_xmas_null_scan():
    pkts, ts = [], 600.0
    att, tgt = "10.0.0.55", "10.0.0.11"
    for port in (80, 443, 22):               # Xmas: FIN+PSH+URG
        pkts.append(tcp_pkt(MAC_ATT, MAC_GW, att, tgt, 55500, port, "FPU", ts)); ts += 0.1
    for port in (80, 443, 22):               # Null: no flags
        pkts.append(tcp_pkt(MAC_ATT, MAC_GW, att, tgt, 55500, port, "", ts)); ts += 0.1
    return pkts, ["TCP Flag Evasion"]


def gen_cleartext_creds():
    pkts, ts = [], 700.0
    att, srv = "10.0.0.77", "10.0.0.21"
    # FTP USER/PASS (plaintext, port 21)
    for cmd in (b"USER admin\r\n", b"PASS Secret123\r\n"):
        pkts.append(tcp_pkt(MAC_A, MAC_GW, att, srv, 52000, 21, "PA", ts, payload=cmd)); ts += 0.2
    # HTTP Basic Auth header (admin:password -> base64 YWRtaW46cGFzc3dvcmQ=)
    http = (b"GET /admin HTTP/1.1\r\nHost: 10.0.0.90\r\n"
            b"Authorization: Basic YWRtaW46cGFzc3dvcmQ=\r\n\r\n")
    pkts.append(tcp_pkt(MAC_A, MAC_GW, att, "10.0.0.90", 52001, 80, "PA", ts, payload=http)); ts += 0.2
    # HTTP POST form credentials
    form = (b"POST /login HTTP/1.1\r\nHost: 10.0.0.90\r\nContent-Type: application/x-www-form-urlencoded\r\n"
            b"Content-Length: 31\r\n\r\nusername=alice&password=hunter2")
    pkts.append(tcp_pkt(MAC_A, MAC_GW, att, "10.0.0.90", 52002, 80, "PA", ts, payload=form)); ts += 0.2
    return pkts, ["Cleartext Credentials"]


def gen_suspicious_port():
    pkts, ts = [], 800.0
    att, tgt = "10.0.0.70", "10.0.0.90"
    for _ in range(8):                        # traffic to 4444 (Metasploit default listener)
        pkts.append(tcp_pkt(MAC_ATT, MAC_GW, att, tgt, 53000, 4444, "PA", ts, size=120)); ts += 0.3
    return pkts, ["Suspicious Port"]


def gen_volume_anomaly():
    pkts, ts = [], 900.0
    # >=3 hosts, >=100 packets, >=200KB total, one host sends >=50% of bytes
    heavy, srv = "10.0.0.99", "10.0.0.200"
    others = ["10.0.0.11", "10.0.0.12", "10.0.0.13"]
    # heavy host: ~300KB of established data (ack=1, not a SYN flood, not null)
    for i in range(220):
        pkts.append(tcp_pkt(MAC_A, MAC_GW, heavy, srv, 52500, 443, "PA", ts, size=1400)); ts += 0.01
    # light background from other hosts
    for h in others:
        for i in range(20):
            pkts.append(tcp_pkt(MAC_B, MAC_GW, h, srv, 52600, 443, "PA", ts, size=200)); ts += 0.02
    return pkts, ["Volume Anomaly"]


def gen_benign():
    # pure background -> should produce ZERO findings (false-positive test)
    return benign_background(start_ts=1000.0, n_hosts=5), []


def gen_multi_attack():
    # realistic mixed capture: scan + flood + dns tunnel + benign background
    pkts = []
    pkts += benign_background(start_ts=0.0, n_hosts=3)
    s, _ = gen_port_scan(); pkts += s
    f, _ = gen_syn_flood(); pkts += f
    d, _ = gen_dns_tunnel(); pkts += d
    return pkts, ["Port Scan", "TCP SYN Flood", "DNS Anomaly"]


CAPTURES = {
    "port_scan.pcap": gen_port_scan,
    "brute_force.pcap": gen_brute_force,
    "arp_spoof.pcap": gen_arp_spoof,
    "syn_flood.pcap": gen_syn_flood,
    "dns_tunnel.pcap": gen_dns_tunnel,
    "xmas_null_scan.pcap": gen_xmas_null_scan,
    "cleartext_creds.pcap": gen_cleartext_creds,
    "suspicious_port.pcap": gen_suspicious_port,
    "volume_anomaly.pcap": gen_volume_anomaly,
    "benign.pcap": gen_benign,
    "multi_attack.pcap": gen_multi_attack,
}


def main():
    manifest = {}
    for fname, fn in CAPTURES.items():
        pkts, labels = fn()
        # sort by time so replay/parse order is chronological
        pkts.sort(key=lambda p: float(p.time))
        wrpcap(os.path.join(OUT, fname), pkts)
        manifest[fname] = {
            "expected_rules": labels,
            "packets": len(pkts),
        }
        print(f"  wrote {fname:24s} {len(pkts):4d} pkts  expect={labels}")
    with open(os.path.join(OUT, "labels.json"), "w") as f:
        json.dump(manifest, f, indent=2)
    print(f"\nManifest: {os.path.join(OUT, 'labels.json')}  ({len(manifest)} captures)")


if __name__ == "__main__":
    main()
