"""
PCAP parser: reads a capture file with PyShark and returns structured records.
Module owner: Akshat Richhariya
"""
import asyncio
import os
import shutil
import subprocess
import tempfile

import pyshark


def _get(layer, field):
    """Safely read a field from a PyShark layer (returns None if missing)."""
    try:
        return getattr(layer, field)
    except AttributeError:
        return None


def _flag(value):
    """TShark reports flags as '1'/'0' or 'True'/'False' depending on version."""
    return str(value) in ("1", "True", "true")


def parse_pcap(path, max_packets=None):
    """
    Parse a PCAP file and return:
      packets: list of dicts (timestamp, IPs, ports, protocol, length, TCP flags)
      dns:     list of DNS query records
      http:    list of HTTP request records
    """
    # PyShark needs an asyncio event loop; Flask worker threads don't have one by default
    asyncio.set_event_loop(asyncio.new_event_loop())

    packets, dns_records, http_records = [], [], []
    cap = pyshark.FileCapture(path, keep_packets=False)

    try:
        for i, pkt in enumerate(cap):
            if max_packets and i >= max_packets:
                break

            ts = float(pkt.sniff_timestamp)

            # Network layer (IPv4 or IPv6)
            if hasattr(pkt, "ip"):
                src_ip, dst_ip = pkt.ip.src, pkt.ip.dst
            elif hasattr(pkt, "ipv6"):
                src_ip, dst_ip = pkt.ipv6.src, pkt.ipv6.dst
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

            # TCP flags (used for port-scan and brute-force detection)
            syn = ack = rst = False
            if hasattr(pkt, "tcp"):
                syn = _flag(_get(pkt.tcp, "flags_syn"))
                ack = _flag(_get(pkt.tcp, "flags_ack"))
                rst = _flag(_get(pkt.tcp, "flags_reset"))

            packets.append({
                "timestamp": ts,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "transport": transport,
                "protocol": pkt.highest_layer,
                "length": int(pkt.length),
                "syn": syn,
                "ack": ack,
                "rst": rst,
            })

            # DNS queries
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

            # HTTP requests
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
    finally:
        cap.close()

    return {"packets": packets, "dns": dns_records, "http": http_records}


def capture_to_file(iface, seconds, out_path=None):
    """
    Capture live traffic on `iface` for `seconds` using TShark, writing a PCAP
    to `out_path` (a temp file if not given) and returning the path.

    This is the only live-capture code: once the window closes, the resulting
    file goes through the exact same parse/store/detect pipeline as an upload,
    so nothing downstream has to know whether a capture came from a file or the
    wire. Requires TShark and permission to read the interface (inside the
    receiver container TShark runs as root on eth0).
    """
    if shutil.which("tshark") is None:
        raise RuntimeError(
            "TShark is not installed, so live capture is unavailable. "
            "Live capture is intended to run inside the Docker demo (see docker-compose.yml)."
        )
    if out_path is None:
        fd, out_path = tempfile.mkstemp(prefix="live_", suffix=".pcap")
        os.close(fd)

    # -a duration:N stops capture after N seconds; -f limits to IP traffic so we
    # don't record ARP/loopback noise on the container bridge.
    cmd = [
        "tshark", "-i", iface,
        "-a", f"duration:{int(seconds)}",
        "-f", "ip",
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
