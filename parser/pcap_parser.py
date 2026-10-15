"""
PCAP parser: reads a capture file with PyShark and returns structured records.
Module owner: Akshat Richhariya

Enriched with InfoSec telemetry:
- Link-layer MAC addresses & ARP resolution (Integrity / MITM detection)
- Full TCP flags (SYN, ACK, RST, FIN, PSH, URG for protocol anomaly & evasion)
- Cleartext credentials & sensitive data audit (Confidentiality violation detection)
"""
import asyncio
import base64
import os
import shutil
import subprocess
import tempfile

# Python 3.12+ / 3.14 asyncio compatibility for PyShark
class _DummyWatcher:
    def attach_loop(self, loop):
        pass
    def close(self):
        pass

if not hasattr(asyncio, "get_child_watcher"):
    asyncio.get_child_watcher = lambda: _DummyWatcher()
if not hasattr(asyncio, "set_child_watcher"):
    asyncio.set_child_watcher = lambda w: None
    asyncio.SafeChildWatcher = _DummyWatcher

import pyshark


def _get(layer, field):
    """Safely read a field from a PyShark layer (returns None if missing)."""
    try:
        return getattr(layer, field)
    except AttributeError:
        return None


def _flag(value):
    """TShark reports flags as '1'/'0' or 'True'/'False' depending on version."""
    if value is None:
        return False
    return str(value).strip().lower() in ("1", "true")


def parse_pcap(path, max_packets=None):
    """
    Parse a PCAP file and return:
      packets:     list of dicts (timestamp, IPs, MACs, ports, protocol, length, TCP flags)
      dns:         list of DNS query records
      http:        list of HTTP request records
      arp:         list of ARP records (for MITM / Integrity analysis)
      credentials: list of leaked cleartext credentials (for Confidentiality analysis)
    """
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    packets, dns_records, http_records = [], [], []
    arp_records, cred_records = [], []

    # AppArmor on Ubuntu restricts tshark to reading from /tmp or /var/tmp.
    # If the file is not in /tmp, copy it to a secure temp file in /tmp while parsing.
    tmp_path = None
    parse_target = path
    cap = None
    try:
        abs_path = os.path.abspath(path)
        if not abs_path.startswith(("/tmp", "/var/tmp")):
            fd, tmp_path = tempfile.mkstemp(prefix="parse_", suffix=".pcap")
            os.close(fd)
            shutil.copyfile(abs_path, tmp_path)
            parse_target = tmp_path

        cap = pyshark.FileCapture(parse_target, keep_packets=False)

        for i, pkt in enumerate(cap):
            if max_packets and i >= max_packets:
                break

            ts = float(pkt.sniff_timestamp)

            # Link layer (MAC addresses)
            src_mac = dst_mac = None
            if hasattr(pkt, "eth"):
                src_mac = _get(pkt.eth, "src")
                dst_mac = _get(pkt.eth, "dst")
            elif hasattr(pkt, "wlan"):
                src_mac = _get(pkt.wlan, "sa")
                dst_mac = _get(pkt.wlan, "da")
            elif hasattr(pkt, "arp"):
                src_mac = _get(pkt.arp, "src_hw_mac")
                dst_mac = _get(pkt.arp, "dst_hw_mac")

            # Network layer (IPv4 or IPv6 or ARP)
            if hasattr(pkt, "ip"):
                src_ip, dst_ip = pkt.ip.src, pkt.ip.dst
            elif hasattr(pkt, "ipv6"):
                src_ip, dst_ip = pkt.ipv6.src, pkt.ipv6.dst
            elif hasattr(pkt, "arp"):
                src_ip = _get(pkt.arp, "src_proto_ipv4")
                dst_ip = _get(pkt.arp, "dst_proto_ipv4")
            else:
                src_ip, dst_ip = None, None

            # Transport layer (TCP / UDP)
            transport = pkt.transport_layer
            src_port = dst_port = None
            if transport and hasattr(pkt, transport.lower()):
                layer = getattr(pkt, transport.lower())
                src_port = _get(layer, "srcport")
                dst_port = _get(layer, "dstport")
                src_port = int(src_port) if src_port else None
                dst_port = int(dst_port) if dst_port else None

            # TCP flags (used for port-scan, brute-force, DoS SYN flood, and Xmas/Null evasion detection)
            syn = ack = rst = fin = psh = urg = False
            if hasattr(pkt, "tcp"):
                syn = _flag(_get(pkt.tcp, "flags_syn"))
                ack = _flag(_get(pkt.tcp, "flags_ack"))
                rst = _flag(_get(pkt.tcp, "flags_reset"))
                fin = _flag(_get(pkt.tcp, "flags_fin"))
                psh = _flag(_get(pkt.tcp, "flags_push"))
                urg = _flag(_get(pkt.tcp, "flags_urg"))

            packets.append({
                "timestamp": ts,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_mac": src_mac,
                "dst_mac": dst_mac,
                "src_port": src_port,
                "dst_port": dst_port,
                "transport": transport,
                "protocol": pkt.highest_layer,
                "length": int(pkt.length),
                "syn": syn,
                "ack": ack,
                "rst": rst,
                "fin": fin,
                "psh": psh,
                "urg": urg,
            })

            # ARP records (used to detect ARP Poisoning / MITM Integrity violations)
            if hasattr(pkt, "arp"):
                arp_src_mac = _get(pkt.arp, "src_hw_mac") or src_mac
                arp_dst_mac = _get(pkt.arp, "dst_hw_mac") or dst_mac
                arp_records.append({
                    "timestamp": ts,
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "src_mac": arp_src_mac,
                    "dst_mac": arp_dst_mac,
                    "opcode": _get(pkt.arp, "opcode"),
                })

            # DNS queries (used for C2, high-volume anomaly, covert exfiltration)
            if hasattr(pkt, "dns"):
                qname = _get(pkt.dns, "qry_name")
                if qname:
                    dns_records.append({
                        "timestamp": ts,
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "query": qname,
                        "is_response": _flag(_get(pkt.dns, "flags_response")),
                    })

            # HTTP requests & Cleartext Credential Extraction (Confidentiality)
            if hasattr(pkt, "http"):
                method = _get(pkt.http, "request_method")
                if method:
                    http_records.append({
                        "timestamp": ts,
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "method": method,
                        "host": _get(pkt.http, "host"),
                        "uri": _get(pkt.http, "request_uri"),
                        "user_agent": _get(pkt.http, "user_agent"),
                    })

                # Check HTTP Basic Auth header
                auth = _get(pkt.http, "authorization")
                if auth and "Basic " in auth:
                    try:
                        b64 = auth.split("Basic ", 1)[1].strip()
                        decoded = base64.b64decode(b64).decode("utf-8", "replace")
                        cred_records.append({
                            "timestamp": ts,
                            "src_ip": src_ip,
                            "dst_ip": dst_ip,
                            "protocol": "HTTP",
                            "type": "HTTP Basic Auth",
                            "detail": f"Decoded credentials from Authorization header: '{decoded}'",
                        })
                    except Exception:
                        pass

                # Check HTTP POST form data for passwords
                file_data = _get(pkt.http, "file_data")
                if not file_data:
                    file_data = _get(pkt.http, "urlencoded_form") or _get(pkt.http, "data")
                if file_data:
                    raw_body = ""
                    try:
                        clean_hex = str(file_data).replace(":", "")
                        raw_body = bytes.fromhex(clean_hex).decode("utf-8", "replace")
                    except Exception:
                        raw_body = str(file_data)
                    lower_body = raw_body.lower()
                    if any(k in lower_body for k in ("password=", "pass=", "pwd=", "passwd=")):
                        cred_records.append({
                            "timestamp": ts,
                            "src_ip": src_ip,
                            "dst_ip": dst_ip,
                            "protocol": "HTTP",
                            "type": "HTTP Form POST",
                            "detail": f"Cleartext password in HTTP payload: '{raw_body[:80]}'",
                        })

            # FTP Cleartext Credentials (Confidentiality)
            if hasattr(pkt, "ftp"):
                cmd = _get(pkt.ftp, "request_command")
                arg = _get(pkt.ftp, "request_arg")
                if cmd in ("USER", "PASS"):
                    cred_records.append({
                        "timestamp": ts,
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "protocol": "FTP",
                        "type": f"FTP {cmd}",
                        "detail": f"Cleartext FTP command: {cmd} {arg}",
                    })
    finally:
        if cap is not None:
            try:
                cap.close()
            except Exception:
                pass
            try:
                cap.close = lambda: None
            except Exception:
                pass
        try:
            loop.close()
        except Exception:
            pass
        if tmp_path and os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
            except OSError:
                pass

    return {
        "packets": packets,
        "dns": dns_records,
        "http": http_records,
        "arp": arp_records,
        "credentials": cred_records,
    }


def capture_to_file(iface, seconds, out_path=None):
    """
    Capture live traffic on `iface` for `seconds` using TShark, writing a PCAP
    to `out_path` (a temp file if not given) and returning the path.
    """
    if shutil.which("tshark") is None:
        raise RuntimeError(
            "TShark is not installed, so live capture is unavailable. "
            "Live capture is intended to run inside the Docker demo (see docker-compose.yml)."
        )
    if out_path is None:
        fd, out_path = tempfile.mkstemp(prefix="live_", suffix=".pcap")
        os.close(fd)

    cmd = [
        "tshark", "-i", iface,
        "-a", f"duration:{int(seconds)}",
        "-f", "ip or arp",
        "-w", out_path,
    ]
    try:
        subprocess.run(
            cmd, check=True, timeout=int(seconds) + 30,
            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
        )
    except subprocess.CalledProcessError as e:
        stderr = (e.stderr or b"").decode("utf-8", "replace").strip()
        raise RuntimeError(f"TShark capture failed on {iface}: {stderr or e}")
    except subprocess.TimeoutExpired:
        raise RuntimeError(f"TShark capture on {iface} did not finish in time.")

    return out_path
