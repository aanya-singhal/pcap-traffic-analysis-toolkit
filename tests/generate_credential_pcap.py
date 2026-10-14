"""
Generates a safe, self-contained capture that demonstrates credential exposure.

All usernames and passwords here are FAKE and invented purely for the demo. The
capture mixes a little normal traffic with three cleartext logins:
  - HTTP Basic Auth  (admin / hunter2)        to an internal web admin panel
  - HTTP POST form   (alice / Spring2024!)     to a login page
  - FTP USER/PASS    (bob   / ftpP@ssw0rd)     to a file server

Run:  python tests/generate_credential_pcap.py
Output: samples/credential_leak.pcap
"""
import base64
import os
import random

from scapy.all import Ether, IP, TCP, Raw, wrpcap

random.seed(7)
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SAMPLES = os.path.join(BASE_DIR, "samples")
START = 1760000000.0

CLIENT = "192.168.1.50"
WEB = "192.168.1.10"      # web server (HTTP)
FTP_SRV = "192.168.1.20"  # FTP server


def pkt(src, dst, sport, dport, payload, t, flags="PA"):
    p = (Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
         / IP(src=src, dst=dst)
         / TCP(sport=sport, dport=dport, flags=flags, seq=random.randint(1000, 90000))
         / Raw(load=payload.encode() if isinstance(payload, str) else payload))
    p.time = t
    return p


def http_basic_auth(t):
    """GET /admin with an Authorization: Basic header (admin:hunter2)."""
    token = base64.b64encode(b"admin:hunter2").decode()
    req = (
        "GET /admin HTTP/1.1\r\n"
        f"Host: {WEB}\r\n"
        f"Authorization: Basic {token}\r\n"
        "User-Agent: Mozilla/5.0\r\n"
        "Accept: */*\r\n\r\n"
    )
    return [pkt(CLIENT, WEB, 51000, 80, req, t)]


def http_post_form(t):
    """POST /login with a urlencoded body carrying username & password."""
    body = "username=alice&password=Spring2024%21&remember=1"
    req = (
        "POST /login HTTP/1.1\r\n"
        f"Host: {WEB}\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        f"Content-Length: {len(body)}\r\n"
        "User-Agent: Mozilla/5.0\r\n\r\n"
        f"{body}"
    )
    return [pkt(CLIENT, WEB, 51002, 80, req, t)]


def ftp_login(t):
    """FTP USER then PASS, as two separate packets on port 21."""
    return [
        pkt(FTP_SRV, CLIENT, 21, 52000, "220 FileServer FTP ready\r\n", t, flags="PA"),
        pkt(CLIENT, FTP_SRV, 52000, 21, "USER bob\r\n", t + 0.1),
        pkt(FTP_SRV, CLIENT, 21, 52000, "331 Password required for bob\r\n", t + 0.2),
        pkt(CLIENT, FTP_SRV, 52000, 21, "PASS ftpP@ssw0rd\r\n", t + 0.3),
        pkt(FTP_SRV, CLIENT, 21, 52000, "230 Login successful\r\n", t + 0.4),
    ]


def normal_traffic(t):
    """A bit of benign HTTP so the capture isn't only logins."""
    out = []
    for i in range(6):
        req = (f"GET /page{i}.html HTTP/1.1\r\nHost: {WEB}\r\n"
               "User-Agent: Mozilla/5.0\r\nAccept: */*\r\n\r\n")
        out.append(pkt(CLIENT, WEB, 51100 + i, 80, req, t + i * 0.5))
    return out


def main():
    os.makedirs(SAMPLES, exist_ok=True)
    packets = []
    packets += normal_traffic(START + 1)
    packets += http_basic_auth(START + 5)
    packets += http_post_form(START + 8)
    packets += ftp_login(START + 12)
    packets.sort(key=lambda p: p.time)

    out = os.path.join(SAMPLES, "credential_leak.pcap")
    wrpcap(out, packets)
    print(f"Wrote {len(packets)} packets to {out}")
    print("Contains 3 cleartext logins: HTTP Basic (admin), HTTP form (alice), FTP (bob).")


if __name__ == "__main__":
    main()
