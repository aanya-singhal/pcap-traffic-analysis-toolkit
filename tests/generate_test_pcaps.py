"""
Generates labelled test captures with known ground truth, used to evaluate the detection rules.
Each capture = normal background traffic + one known attack pattern.

Run:  python tests/generate_test_pcaps.py
"""
import json
import os
import random

from scapy.all import Ether, IP, TCP, UDP, DNS, DNSQR, DNSRR, Raw, wrpcap

random.seed(42)  # reproducible captures

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SAMPLES = os.path.join(BASE_DIR, "samples")
START = 1760000000.0  # fixed base timestamp

CLIENTS = ["192.168.1.10", "192.168.1.11", "192.168.1.12", "192.168.1.13"]
WEB_SERVERS = ["93.184.216.34", "142.250.183.14", "151.101.1.69", "104.16.132.229"]
RESOLVER = "8.8.8.8"
DOMAINS = ["example.com", "google.com", "github.com", "wikipedia.org", "stackoverflow.com", "manipal.edu"]


def pkt(src, dst, l4, t):
    # Fixed MACs so Scapy doesn't try to resolve them on the network
    p = Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") / IP(src=src, dst=dst) / l4
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


# ---------- Traffic patterns ----------

def normal_traffic(start, duration=120):
    """4 clients browsing: DNS lookup then an HTTP/HTTPS session every few seconds."""
    out = []
    for client in CLIENTS:
        t = start + random.uniform(0, 5)
        while t < start + duration:
            name = random.choice(DOMAINS)
            out += dns_lookup(client, name, t)
            out += tcp_session(client, random.choice(WEB_SERVERS), random.choice([80, 443]), t + 0.05)
            t += random.uniform(3, 8)
    return out


def port_scan(attacker, target, t, ports=range(1, 301)):
    """SYN scan: closed ports reply RST, open ports (22, 80) reply SYN-ACK."""
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
    """Repeated short SSH connections, like a password-guessing tool."""
    out = []
    for i in range(attempts):
        out += tcp_session(attacker, target, 22, t + i * gap,
                           req=b"SSH-2.0-libssh_0.9.6\r\n" + random.randbytes(120),
                           resp=b"SSH-2.0-OpenSSH_8.9p1\r\n" + random.randbytes(200))
    return out


def volume_exfil(host, dest, t, chunks=250):
    """One internal host pushing a large amount of data to an external server."""
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
    out = []
    # Long, encoded-looking subdomains (typical of DNS tunneling)
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
    "normal_traffic.pcap": (lambda: [], []),
    "port_scan.pcap": (lambda: port_scan("10.0.0.66", "192.168.1.20", START + 30),
                       ["Port Scan", "Suspicious Port"]),  # scan also probes Telnet port 23
    "brute_force_ssh.pcap": (lambda: ssh_brute_force("10.0.0.77", "192.168.1.30", START + 30),
                             ["Brute Force"]),
    "volume_exfil.pcap": (lambda: volume_exfil("192.168.1.11", "198.51.100.25", START + 30),
                          ["Volume Anomaly"]),
    "dns_tunnel_c2.pcap": (lambda: dns_tunnel_and_c2(START + 30),
                           ["DNS Anomaly", "Suspicious Port"]),
}


def main():
    os.makedirs(SAMPLES, exist_ok=True)
    expected = {}
    for filename, (attack_fn, expected_rules) in SCENARIOS.items():
        packets = normal_traffic(START) + attack_fn()
        packets.sort(key=lambda p: p.time)
        wrpcap(os.path.join(SAMPLES, filename), packets)
        expected[filename] = expected_rules
        print(f"{filename:<24} {len(packets):>5} packets   expected: {expected_rules or 'none'}")

    with open(os.path.join(SAMPLES, "expected_findings.json"), "w") as f:
        json.dump(expected, f, indent=2)
    print("\nSaved captures + expected_findings.json to samples/")


if __name__ == "__main__":
    main()
