"""
Cleartext credential exposure detection.
Module owner: Aanya Singhal

Many legacy / misconfigured services send login credentials with no encryption.
Anyone capturing the traffic (an attacker on the same network, or this toolkit)
can read the username and password straight out of the packet payload. This
module reads the raw TCP payloads from a capture and extracts any credentials
that were sent in the clear, demonstrating exactly why protocols like HTTPS,
FTPS and SSH exist.

It deliberately works on the raw bytes with scapy rather than through PyShark,
so it is independent of the main parser and needs no TShark. Findings produced
here are reported with High severity: an exposed credential is not an "indicator",
it is a confirmed disclosure.

Protocols covered:
  - HTTP Basic Authentication  (Authorization: Basic base64(user:pass))
  - HTTP POST login forms      (username=...&password=... style bodies)
  - FTP                        (USER / PASS commands, port 21)

Everything here is read-only analysis of an already-captured file.
"""
import base64
import binascii
import re
from urllib.parse import parse_qs, unquote_plus

from scapy.all import rdpcap, TCP, IP, IPv6, Raw

# Form field names commonly used for usernames and passwords
USER_KEYS = ("username", "user", "uname", "login", "email", "userid", "user_id", "acct")
PASS_KEYS = ("password", "pass", "passwd", "pwd", "pw", "secret")

# Only treat these as "login form" posts; avoids flagging every POST
LOGINish = re.compile(r"(user|login|email|pass|pwd|secret|acct)", re.IGNORECASE)


def _endpoints(pkt):
    """Return (src_ip, dst_ip, dst_port) for a TCP packet, or Nones."""
    if IP in pkt:
        src, dst = pkt[IP].src, pkt[IP].dst
    elif IPv6 in pkt:
        src, dst = pkt[IPv6].src, pkt[IPv6].dst
    else:
        src, dst = None, None
    dport = pkt[TCP].dport if TCP in pkt else None
    return src, dst, dport


def _payload(pkt):
    """Raw TCP payload as text (best-effort decode), or '' if none."""
    if TCP in pkt and Raw in pkt:
        try:
            return bytes(pkt[Raw].load).decode("utf-8", "replace")
        except Exception:
            return ""
    return ""


# ---------- Per-protocol extractors ----------

def _http_basic_auth(text, src, dst, dport):
    """HTTP Basic Auth: 'Authorization: Basic <base64(user:pass)>'."""
    out = []
    for m in re.finditer(r"Authorization:\s*Basic\s+([A-Za-z0-9+/=]+)", text, re.IGNORECASE):
        try:
            decoded = base64.b64decode(m.group(1)).decode("utf-8", "replace")
        except (binascii.Error, ValueError):
            continue
        if ":" in decoded:
            user, pwd = decoded.split(":", 1)
            # Recover the request line for context (e.g. "GET /admin HTTP/1.1")
            req = re.search(r"^(GET|POST|PUT|DELETE|HEAD)\s+(\S+)", text, re.MULTILINE)
            context = f"{req.group(1)} {req.group(2)}" if req else "HTTP request"
            out.append({
                "protocol": "HTTP Basic Auth",
                "src_ip": src, "dst_ip": dst, "dst_port": dport,
                "username": user, "password": pwd,
                "context": context,
            })
    return out


def _http_post_form(text, src, dst, dport):
    """HTTP POST login form: body like 'username=alice&password=Spring2024!'."""
    out = []
    # Only look at POST requests
    if not text.startswith("POST"):
        return out
    # Split headers from body on the blank line
    parts = re.split(r"\r?\n\r?\n", text, maxsplit=1)
    if len(parts) < 2:
        return out
    headers, body = parts[0], parts[1]
    if not body or "=" not in body or not LOGINish.search(body):
        return out

    fields = parse_qs(body, keep_blank_values=True)
    lower = {k.lower(): v for k, v in fields.items()}
    user = next((lower[k][0] for k in USER_KEYS if k in lower and lower[k]), None)
    pwd = next((lower[k][0] for k in PASS_KEYS if k in lower and lower[k]), None)
    if user is None and pwd is None:
        return out

    path = re.match(r"POST\s+(\S+)", text)
    host = re.search(r"Host:\s*(\S+)", headers, re.IGNORECASE)
    where = (host.group(1) if host else "") + (path.group(1) if path else "")
    out.append({
        "protocol": "HTTP POST form",
        "src_ip": src, "dst_ip": dst, "dst_port": dport,
        "username": unquote_plus(user) if user else "(none)",
        "password": unquote_plus(pwd) if pwd else "(none)",
        "context": f"POST {where}".strip(),
    })
    return out


def _ftp(state, text, src, dst, dport):
    """FTP USER/PASS, tracked per connection since they are separate packets."""
    out = []
    key = (src, dst)
    for line in text.splitlines():
        line = line.strip()
        um = re.match(r"USER\s+(.+)", line, re.IGNORECASE)
        pm = re.match(r"PASS\s+(.+)", line, re.IGNORECASE)
        if um:
            state.setdefault(key, {})["user"] = um.group(1).strip()
        elif pm:
            pending = state.setdefault(key, {})
            pending["pass"] = pm.group(1).strip()
            out.append({
                "protocol": "FTP",
                "src_ip": src, "dst_ip": dst, "dst_port": dport,
                "username": pending.get("user", "(unknown)"),
                "password": pending["pass"],
                "context": "FTP login (port 21)",
            })
            state.pop(key, None)
    return out


# ---------- Public entry point ----------

def extract_credentials(pcap_path, max_packets=200000):
    """
    Scan a capture for credentials sent in cleartext.

    Returns a list of dicts:
      {protocol, src_ip, dst_ip, dst_port, username, password, context}

    De-duplicates identical disclosures so one login shown across retransmits is
    reported once.
    """
    try:
        packets = rdpcap(pcap_path)
    except Exception:
        return []

    found = []
    ftp_state = {}

    for i, pkt in enumerate(packets):
        if i >= max_packets:
            break
        if TCP not in pkt or Raw not in pkt:
            continue
        text = _payload(pkt)
        if not text:
            continue
        src, dst, dport = _endpoints(pkt)

        if "Authorization: Basic" in text or "authorization: basic" in text.lower():
            found += _http_basic_auth(text, src, dst, dport)
        if text.startswith("POST"):
            found += _http_post_form(text, src, dst, dport)
        if dport == 21 or re.search(r"^(USER|PASS)\s", text, re.MULTILINE | re.IGNORECASE):
            found += _ftp(ftp_state, text, src, dst, dport)

    # De-duplicate
    seen, unique = set(), []
    for c in found:
        sig = (c["protocol"], c["src_ip"], c["dst_ip"], c["username"], c["password"])
        if sig not in seen:
            seen.add(sig)
            unique.append(c)
    return unique


def credentials_to_findings(creds):
    """
    Convert extracted credentials into finding dicts matching the schema used by
    detection.rules (rule, severity, src_ip, dst_ip, detail, evidence_count), so
    they are stored and displayed exactly like any other finding.
    """
    findings = []
    for c in creds:
        findings.append({
            "rule": "Credential Exposure",
            "severity": "High",
            "src_ip": c["src_ip"],
            "dst_ip": c["dst_ip"],
            "detail": (
                f"{c['protocol']}: username '{c['username']}' and password "
                f"'{c['password']}' were sent in cleartext"
                + (f" to {c['dst_ip']}:{c['dst_port']}" if c.get("dst_port") else "")
                + (f" ({c['context']})" if c.get("context") else "")
                + ". Anyone capturing this traffic can read the login."
            ),
            "evidence_count": 1,
        })
    return findings
