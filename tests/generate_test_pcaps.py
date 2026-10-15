"""
Generates labelled test captures with known ground truth across the CIA Triad:
Confidentiality, Integrity, Authentication, Availability.
Each capture = normal background traffic + one known attack pattern.

Run:  python tests/generate_test_pcaps.py
"""
import json
import os
import random

from scapy.all import Ether, IP, TCP, UDP, DNS, DNSQR, DNSRR, ARP, Raw, wrpcap

random.seed(42)  # reproducible captures

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SAMPLES = os.path.join(BASE_DIR, "samples")
START = 1760000000.0  # fixed base timestamp

GATEWAY = "192.168.1.1"
GATEWAY_MAC = "02:00:00:00:00:01"
CLIENTS = ["192.168.1.10", "192.168.1.11", "192.168.1.12", "192.168.1.13"]
CLIENT_MACS = {
    "192.168.1.10": "02:00:00:00:00:10",
    "192.168.1.11": "02:00:00:00:00:11",
    "192.168.1.12": "02:00:00:00:00:12",
    "192.168.1.13": "02:00:00:00:00:13",
}
WEB_SERVERS = ["93.184.216.34", "142.250.183.14", "151.101.1.69", "104.16.132.229"]
RESOLVER = "8.8.8.8"
DOMAINS = ["example.com", "google.com", "github.com", "wikipedia.org", "stackoverflow.com", "manipal.edu"]


def pkt(src, dst, l4, t, src_mac=None, dst_mac=None):
    """Craft an Ethernet / IP packet with explicit MACs and timestamp."""
    smac = src_mac or CLIENT_MACS.get(src, GATEWAY_MAC)
    dmac = dst_mac or (CLIENT_MACS.get(dst) if dst in CLIENT_MACS else GATEWAY_MAC)
    p = Ether(src=smac, dst=dmac) / IP(src=src, dst=dst) / l4
    p.time = t
    return p


def tcp_session(client, server, dport, t, req=None, resp=None):
    """Full TCP conversation: handshake, request, response, teardown."""
    sport = random.randint(49152, 65000)
    seq, sseq = random.randint(1000, 9000), random.randint(1000, 9000)
    if req is None:
        if dport == 80:
            host = random.choice(DOMAINS)
            req = (f"GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Mozilla/5.0\r\n"
                   f"Accept: */*\r\n\r\n").encode()
        else:
            req = random.randbytes(300)
    if resp is None:
        if dport == 80:
            body = b"x" * 1200
            resp = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 1200\r\n\r\n" + body
        else:
            resp = random.randbytes(1200)

    return [
        pkt(client, server, TCP(sport=sport, dport=dport, flags="S", seq=seq), t),
        pkt(server, client, TCP(sport=dport, dport=sport, flags="SA", seq=sseq, ack=seq + 1), t + 0.01),
        pkt(client, server, TCP(sport=sport, dport=dport, flags="A", seq=seq + 1, ack=sseq + 1), t + 0.02),
        pkt(client, server, TCP(sport=sport, dport=dport, flags="PA", seq=seq + 1, ack=sseq + 1) / Raw(req), t + 0.03),
        pkt(server, client, TCP(sport=dport, dport=sport, flags="PA", seq=sseq + 1,
                                ack=seq + 1 + len(req)) / Raw(resp), t + 0.08),
        pkt(client, server, TCP(sport=sport, dport=dport, flags="FA", seq=seq + 1 + len(req),
                                ack=sseq + 1 + len(resp)), t + 0.10),
        pkt(server, client, TCP(sport=dport, dport=sport, flags="FA", seq=sseq + 1 + len(resp),
                                ack=seq + 2 + len(req)), t + 0.11),
    ]


def dns_lookup(client, name, t):
    sport, qid = random.randint(49152, 65000), random.randint(0, 65535)
    return [
        pkt(client, RESOLVER, UDP(sport=sport, dport=53) / DNS(id=qid, rd=1, qd=DNSQR(qname=name)), t),
        pkt(RESOLVER, client, UDP(sport=53, dport=sport) /
            DNS(id=qid, qr=1, rd=1, ra=1, qd=DNSQR(qname=name),
                an=DNSRR(rrname=name, rdata="93.184.216.34")), t + 0.02),
    ]


def clean_arp(t):
    """Benign ARP resolution between gateway and clients (consistent MAC-IP mapping)."""
    out = []
    for client in CLIENTS:
        cmac = CLIENT_MACS.get(client, "02:00:00:00:00:10")
        # Client asks for gateway MAC
        p1 = Ether(src=cmac, dst="ff:ff:ff:ff:ff:ff") / ARP(
            op="who-has", hwsrc=cmac, psrc=client,
            hwdst="00:00:00:00:00:00", pdst=GATEWAY
        )
        p1.time = t
        out.append(p1)

        # Gateway answers
        p2 = Ether(src=GATEWAY_MAC, dst=cmac) / ARP(
            op="is-at", hwsrc=GATEWAY_MAC, psrc=GATEWAY,
            hwdst=cmac, pdst=client
        )
        p2.time = t + 0.005
        out.append(p2)
        t += 0.02
    return out


# ---------- Traffic patterns ----------

def normal_traffic(start, duration=120):
    """4 clients browsing: clean ARP, DNS lookups, then HTTP/HTTPS sessions every few seconds."""
    out = []
    out += clean_arp(start + 0.05)
    for client in CLIENTS:
        t = start + random.uniform(0, 5)
        while t < start + duration:
            name = random.choice(DOMAINS)
            out += dns_lookup(client, name, t)
            out += tcp_session(client, random.choice(WEB_SERVERS), random.choice([80, 443]), t + 0.05)
            t += random.uniform(3, 8)
    return out


def cleartext_credentials(t):
    """
    Confidentiality violation scenario:
    1. HTTP Basic Auth header: Authorization: Basic YWRtaW46U2VjcmV0MTIz (admin:Secret123)
    2. HTTP POST form password: username=alice&password=SuperSecretPassword123!
    3. Cleartext FTP session: USER ftpuser and PASS Hunter2
    """
    out = []

    # 1. HTTP Basic Auth
    basic_req = (
        b"GET /admin/dashboard HTTP/1.1\r\n"
        b"Host: 93.184.216.34\r\n"
        b"Authorization: Basic YWRtaW46U2VjcmV0MTIz\r\n"
        b"User-Agent: Mozilla/5.0 (X11; Linux x86_64)\r\n"
        b"Accept: */*\r\n\r\n"
    )
    basic_resp = (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: text/html\r\n"
        b"Content-Length: 32\r\n\r\n"
        b"<h1>Admin Dashboard Access</h1>\n"
    )
    out += tcp_session("192.168.1.10", "93.184.216.34", 80, t, req=basic_req, resp=basic_resp)

    # 2. HTTP POST Form Password
    post_body = b"username=alice&password=SuperSecretPassword123!"
    post_req = (
        b"POST /api/login HTTP/1.1\r\n"
        b"Host: 142.250.183.14\r\n"
        b"Content-Type: application/x-www-form-urlencoded\r\n"
        b"Content-Length: " + str(len(post_body)).encode() + b"\r\n"
        b"User-Agent: Mozilla/5.0 (X11; Linux x86_64)\r\n\r\n" + post_body
    )
    post_resp = (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: application/json\r\n"
        b"Content-Length: 22\r\n\r\n"
        b"{\"status\":\"authenticated\"}"
    )
    out += tcp_session("192.168.1.11", "142.250.183.14", 80, t + 2.0, req=post_req, resp=post_resp)

    # 3. Cleartext FTP USER and PASS
    ftp_client = "192.168.1.12"
    ftp_server = "192.168.1.50"
    sport = random.randint(49152, 65000)
    ts = t + 4.0

    out.append(pkt(ftp_client, ftp_server, TCP(sport=sport, dport=21, flags="S", seq=1000), ts))
    out.append(pkt(ftp_server, ftp_client, TCP(sport=21, dport=sport, flags="SA", seq=2000, ack=1001), ts + 0.01))
    out.append(pkt(ftp_client, ftp_server, TCP(sport=sport, dport=21, flags="A", seq=1001, ack=2001), ts + 0.02))

    banner = b"220 Service ready for new user.\r\n"
    out.append(pkt(ftp_server, ftp_client, TCP(sport=21, dport=sport, flags="PA", seq=2001, ack=1001) / Raw(banner), ts + 0.03))
    out.append(pkt(ftp_client, ftp_server, TCP(sport=sport, dport=21, flags="A", seq=1001, ack=2001 + len(banner)), ts + 0.04))

    user_cmd = b"USER ftpuser\r\n"
    out.append(pkt(ftp_client, ftp_server, TCP(sport=sport, dport=21, flags="PA", seq=1001, ack=2001 + len(banner)) / Raw(user_cmd), ts + 0.05))
    user_resp = b"331 User name okay, need password.\r\n"
    out.append(pkt(ftp_server, ftp_client, TCP(sport=21, dport=sport, flags="PA", seq=2001 + len(banner), ack=1001 + len(user_cmd)) / Raw(user_resp), ts + 0.06))

    pass_cmd = b"PASS Hunter2\r\n"
    out.append(pkt(ftp_client, ftp_server, TCP(sport=sport, dport=21, flags="PA", seq=1001 + len(user_cmd), ack=2001 + len(banner) + len(user_resp)) / Raw(pass_cmd), ts + 0.07))
    pass_resp = b"230 User logged in, proceed.\r\n"
    out.append(pkt(ftp_server, ftp_client, TCP(sport=21, dport=sport, flags="PA", seq=2001 + len(banner) + len(user_resp), ack=1001 + len(user_cmd) + len(pass_cmd)) / Raw(pass_resp), ts + 0.08))

    # Teardown
    c_ack = 1001 + len(user_cmd) + len(pass_cmd)
    s_ack = 2001 + len(banner) + len(user_resp) + len(pass_resp)
    out.append(pkt(ftp_client, ftp_server, TCP(sport=sport, dport=21, flags="FA", seq=c_ack, ack=s_ack), ts + 0.09))
    out.append(pkt(ftp_server, ftp_client, TCP(sport=21, dport=sport, flags="FA", seq=s_ack, ack=c_ack + 1), ts + 0.10))
    out.append(pkt(ftp_client, ftp_server, TCP(sport=sport, dport=21, flags="A", seq=c_ack + 1, ack=s_ack + 1), ts + 0.11))

    return out


def arp_spoofing(t):
    """
    Integrity violation scenario:
    ARP Cache Poisoning / MITM:
    Legitimate ARP replies associate 192.168.1.1 with 02:00:00:00:00:01.
    Attacker (02:00:00:00:00:99) sends conflicting ARP replies claiming 192.168.1.1.
    """
    out = []
    attacker_mac = "02:00:00:00:00:99"
    target_ip = GATEWAY
    victim_ip = "192.168.1.10"
    victim_mac = CLIENT_MACS[victim_ip]

    # Legitimate mapping ARP reply
    p_legit = Ether(src=GATEWAY_MAC, dst=victim_mac) / ARP(
        op="is-at", hwsrc=GATEWAY_MAC, psrc=target_ip,
        hwdst=victim_mac, pdst=victim_ip
    )
    p_legit.time = t
    out.append(p_legit)

    # Poisoned conflicting ARP replies from attacker claiming target_ip
    for i in range(12):
        ts = t + 0.1 + i * 0.2
        p_poison = Ether(src=attacker_mac, dst=victim_mac) / ARP(
            op="is-at", hwsrc=attacker_mac, psrc=target_ip,
            hwdst=victim_mac, pdst=victim_ip
        )
        p_poison.time = ts
        out.append(p_poison)

    return out


def tcp_evasion(attacker, target, t):
    """
    Integrity violation scenario:
    TCP Flag Evasion:
    1. Xmas scan: TCP flags FIN + PSH + URG (flags="FPU", ack=0, syn=0).
    2. Null scan: TCP flags all zero (flags=0).
    Targeting standard web port 80 (not suspicious port) without SYN packets.
    """
    out = []
    attacker_mac = "02:00:00:00:00:88"
    target_mac = GATEWAY_MAC

    # Xmas scan probes (FIN + PSH + URG)
    for i in range(15):
        sport = 51000 + i
        ts = t + i * 0.02
        p = Ether(src=attacker_mac, dst=target_mac) / IP(src=attacker, dst=target) / TCP(
            sport=sport, dport=80, flags="FPU", seq=1000 + i, ack=0
        )
        p.time = ts
        out.append(p)

    # Null scan probes (Zero control flags)
    for i in range(15):
        sport = 52000 + i
        ts = t + 1.0 + i * 0.02
        p = Ether(src=attacker_mac, dst=target_mac) / IP(src=attacker, dst=target) / TCP(
            sport=sport, dport=80, flags=0, seq=2000 + i, ack=0
        )
        p.time = ts
        out.append(p)

    return out


def syn_flood(attacker, target, t, count=80):
    """
    Availability violation scenario:
    TCP SYN Flood DoS:
    Rapid burst of unacknowledged TCP SYN packets (>= 50 SYNs, ratio >= 3.0x).
    Targeting port 80 with no corresponding ACKs.
    """
    out = []
    attacker_mac = "02:00:00:00:00:77"
    target_mac = GATEWAY_MAC

    for i in range(count):
        sport = 40000 + (i % 20000)
        ts = t + i * 0.005  # burst completed in 0.4 seconds
        p = Ether(src=attacker_mac, dst=target_mac) / IP(src=attacker, dst=target) / TCP(
            sport=sport, dport=80, flags="S", seq=random.randint(10000, 90000), ack=0
        )
        p.time = ts
        out.append(p)

    return out


def port_scan(attacker, target, t, ports=range(1, 301)):
    """
    Authentication violation scenario:
    SYN scan across >=15 distinct ports.
    Probes port 23 (Telnet), which triggers both Port Scan and Suspicious Port.
    """
    out, sport = [], random.randint(40000, 48000)
    for i, port in enumerate(ports):
        ts = t + i * 0.005
        out.append(pkt(attacker, target, TCP(sport=sport, dport=port, flags="S", seq=1000), ts))
        if port in (22, 80):
            out.append(pkt(target, attacker, TCP(sport=port, dport=sport, flags="SA", seq=5000, ack=1001), ts + 0.001))
            out.append(pkt(attacker, target, TCP(sport=sport, dport=port, flags="R", seq=1001), ts + 0.002))
        else:
            out.append(pkt(target, attacker, TCP(sport=port, dport=sport, flags="RA", seq=0, ack=1001), ts + 0.001))
    return out


def ssh_brute_force(attacker, target, t, attempts=40, gap=1.0):
    """
    Authentication violation scenario:
    Repeated short SSH connections exceeding threshold (>= 20 attempts within 60s).
    """
    out = []
    for i in range(attempts):
        out += tcp_session(attacker, target, 22, t + i * gap,
                           req=b"SSH-2.0-libssh_0.9.6\r\n" + random.randbytes(120),
                           resp=b"SSH-2.0-OpenSSH_8.9p1\r\n" + random.randbytes(200))
    return out


def volume_exfil(host, dest, t, chunks=250):
    """
    Availability violation scenario:
    One internal host pushing a disproportionate amount of data (> 50% capture volume).
    """
    out, sport, seq = [], random.randint(49152, 65000), 1000
    out.append(pkt(host, dest, TCP(sport=sport, dport=443, flags="S", seq=seq), t))
    out.append(pkt(dest, host, TCP(sport=443, dport=sport, flags="SA", seq=7000, ack=seq + 1), t + 0.01))
    seq += 1
    for i in range(chunks):
        data = random.randbytes(1400)
        out.append(pkt(host, dest, TCP(sport=sport, dport=443, flags="PA", seq=seq, ack=7001) / Raw(data),
                       t + 0.02 + i * 0.02))
        seq += len(data)
    return out


def dns_tunnel_and_c2(t):
    """
    Confidentiality violation scenario:
    Long DNS queries (> 50 chars) indicative of covert data tunneling, query flood,
    and sessions to Metasploit backdoor port 4444.
    """
    out = []
    # Long, encoded-looking subdomains (DNS tunneling)
    alphabet = "abcdefghijklmnopqrstuvwxyz234567"
    for i in range(15):
        label = "".join(random.choice(alphabet) for _ in range(45))
        out += dns_lookup("192.168.1.12", f"{label}.s{i}.exfil-test.net", t + i * 2)
    # Query flood from another host
    for i in range(120):
        out += dns_lookup("192.168.1.13", f"img{i}.cdn-test.net", t + i * 0.5)
    # Sessions to a Metasploit-style listener on port 4444
    for i in range(5):
        out += tcp_session("192.168.1.12", "203.0.113.50", 4444, t + 5 + i * 10)
    return out


# ---------- Build files ----------

SCENARIOS = {
    "normal_traffic.pcap": {
        "generator": lambda: [],
        "expected_rules": [],
        "expected_pillars": [],
    },
    "cleartext_credentials.pcap": {
        "generator": lambda: cleartext_credentials(START + 30),
        "expected_rules": ["Cleartext Credentials"],
        "expected_pillars": ["Confidentiality"],
    },
    "arp_spoofing.pcap": {
        "generator": lambda: arp_spoofing(START + 30),
        "expected_rules": ["ARP Cache Poisoning"],
        "expected_pillars": ["Integrity"],
    },
    "tcp_evasion.pcap": {
        "generator": lambda: tcp_evasion("10.0.0.88", "192.168.1.20", START + 30),
        "expected_rules": ["TCP Flag Evasion"],
        "expected_pillars": ["Integrity"],
    },
    "syn_flood.pcap": {
        "generator": lambda: syn_flood("10.0.0.99", "192.168.1.20", START + 30, count=80),
        "expected_rules": ["TCP SYN Flood"],
        "expected_pillars": ["Availability"],
    },
    "brute_force_ssh.pcap": {
        "generator": lambda: ssh_brute_force("10.0.0.77", "192.168.1.30", START + 30),
        "expected_rules": ["Brute Force"],
        "expected_pillars": ["Authentication"],
    },
    "port_scan.pcap": {
        "generator": lambda: port_scan("10.0.0.66", "192.168.1.20", START + 30),
        "expected_rules": ["Port Scan", "Suspicious Port"],
        "expected_pillars": ["Authentication"],
    },
    "volume_exfil.pcap": {
        "generator": lambda: volume_exfil("192.168.1.11", "198.51.100.25", START + 30),
        "expected_rules": ["Volume Anomaly"],
        "expected_pillars": ["Availability"],
    },
    "dns_tunnel_c2.pcap": {
        "generator": lambda: dns_tunnel_and_c2(START + 30),
        "expected_rules": ["DNS Anomaly", "Suspicious Port"],
        "expected_pillars": ["Confidentiality"],
    },
}


def main():
    os.makedirs(SAMPLES, exist_ok=True)
    expected_manifest = {}

    for filename, conf in SCENARIOS.items():
        attack_fn = conf["generator"]
        exp_rules = conf["expected_rules"]
        exp_pillars = conf["expected_pillars"]

        packets = normal_traffic(START) + attack_fn()
        packets.sort(key=lambda p: float(p.time))
        target_path = os.path.join(SAMPLES, filename)
        wrpcap(target_path, packets)

        expected_manifest[filename] = {
            "expected_rules": exp_rules,
            "expected_pillars": exp_pillars,
        }
        print(f"{filename:<28} {len(packets):>5} packets   rules: {exp_rules or 'none'}   pillars: {exp_pillars or 'none'}")

    expected_json_path = os.path.join(SAMPLES, "expected_findings.json")
    with open(expected_json_path, "w") as f:
        json.dump(expected_manifest, f, indent=2)
    print(f"\nSaved {len(SCENARIOS)} captures + expected_findings.json to samples/")


if __name__ == "__main__":
    main()
