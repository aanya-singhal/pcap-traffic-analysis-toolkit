"""
PCAP parser: reads a capture file with PyShark and returns structured records.
Module owner: Akshat Richhariya
"""
import asyncio
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
