"""
Flask web app: upload a PCAP, run the analysis pipeline, show the dashboard.
Pipeline: Upload -> Parse -> Store -> Detect -> Visualize
"""
import os
import re
import shutil
import subprocess
import time

from flask import Flask, render_template, request, redirect, url_for, flash, abort, Response
from werkzeug.utils import secure_filename

from parser.pcap_parser import parse_pcap, capture_to_file
from database import db
from detection.rules import (
    run_all_rules,
    calculate_posture_score,
    RULE_DESCRIPTIONS,
    THRESHOLDS,
)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")
ALLOWED_EXTENSIONS = {".pcap", ".pcapng", ".cap"}

def _detect_default_iface():
    env_iface = os.environ.get("CAPTURE_IFACE")
    if env_iface:
        return env_iface
    try:
        out = subprocess.check_output(["ip", "route", "show", "default"], text=True)
        parts = out.strip().split()
        if "dev" in parts:
            return parts[parts.index("dev") + 1]
    except Exception:
        pass
    return "wlo1" if shutil.which("tshark") else "eth0"

# Live capture (auto-detects active interface like wlo1 / eth0)
CAPTURE_IFACE = _detect_default_iface()
CAPTURE_SECONDS = int(os.environ.get("CAPTURE_SECONDS", "15"))

def get_available_interfaces():
    """Enumerate real network interfaces available via tshark."""
    interfaces = []
    if shutil.which("tshark"):
        try:
            out = subprocess.check_output(["tshark", "-D"], text=True, stderr=subprocess.DEVNULL)
            for line in out.strip().splitlines():
                parts = line.strip().split(". ", 1)
                if len(parts) == 2:
                    name = parts[1].split()[0]
                    desc = parts[1]
                    if not any(name.startswith(p) for p in ("dbus", "bluetooth", "nflog", "nfqueue")):
                        interfaces.append({"name": name, "description": desc})
        except Exception:
            pass
    if not interfaces:
        interfaces = [
            {"name": CAPTURE_IFACE, "description": f"{CAPTURE_IFACE} (Default)"},
            {"name": "lo", "description": "lo (Loopback)"},
            {"name": "any", "description": "any (All Interfaces)"},
        ]
    return interfaces

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024  # 50 MB upload limit
app.secret_key = "dev-only-secret"

os.makedirs(UPLOAD_DIR, exist_ok=True)
db.init_db()


@app.route("/")
def index():
    conn = db.get_connection()
    recent = db.list_analyses(conn)
    conn.close()
    interfaces = get_available_interfaces()
    return render_template(
        "index.html",
        recent=recent,
        live_capture=shutil.which("tshark") is not None,
        interfaces=interfaces,
        capture_iface=CAPTURE_IFACE,
        capture_seconds=CAPTURE_SECONDS,
    )


@app.route("/upload", methods=["POST"])
def upload():
    file = request.files.get("pcap")
    if not file or file.filename == "":
        flash("Please choose a PCAP file to upload.")
        return redirect(url_for("index"))

    ext = os.path.splitext(file.filename)[1].lower()
    if ext not in ALLOWED_EXTENSIONS:
        flash("Only .pcap, .pcapng and .cap files are supported.")
        return redirect(url_for("index"))

    filename = secure_filename(file.filename)
    saved_path = os.path.join(UPLOAD_DIR, f"{int(time.time())}_{filename}")
    file.save(saved_path)
    file_size = os.path.getsize(saved_path)

    try:
        analysis_id = _analyse_pcap(saved_path, filename, file_size)
    except Exception as e:
        if os.path.exists(saved_path):
            try:
                os.remove(saved_path)
            except OSError:
                pass
        flash(f"Could not analyse this file: {e}")
        return redirect(url_for("index"))

    return redirect(url_for("dashboard", analysis_id=analysis_id))


@app.route("/capture", methods=["POST"])
def capture():
    # Read user-selected interface and duration from the form
    selected_iface = request.form.get("interface", "").strip() or CAPTURE_IFACE
    # Sanitize interface name to prevent command injection
    if not re.match(r"^[a-zA-Z0-9_\-\.\:]+$", selected_iface):
        selected_iface = CAPTURE_IFACE

    raw_seconds = request.form.get("seconds", str(CAPTURE_SECONDS))
    try:
        seconds = max(5, min(60, int(raw_seconds)))
    except ValueError:
        seconds = CAPTURE_SECONDS

    try:
        pcap_path = capture_to_file(selected_iface, seconds)
        file_size = os.path.getsize(pcap_path)
        label = f"live_{selected_iface}_{int(time.time())}.pcap"
        analysis_id = _analyse_pcap(pcap_path, label, file_size)
    except Exception as e:
        flash(f"Live capture failed on {selected_iface}: {e}")
        return redirect(url_for("index"))

    return redirect(url_for("dashboard", analysis_id=analysis_id))


def _analyse_pcap(path, filename, file_size):
    """Shared pipeline for both uploaded and live-captured PCAPs."""
    conn = db.get_connection()
    analysis_id = db.create_analysis(conn, filename, file_size)
    try:
        # 1. Parse
        t0 = time.time()
        parsed = parse_pcap(path)
        parse_seconds = time.time() - t0

        # 2. Store
        db.insert_parsed(conn, analysis_id, parsed)

        # 3. Detect
        t1 = time.time()
        findings = run_all_rules(conn, analysis_id)
        detect_seconds = time.time() - t1
        db.save_findings(conn, analysis_id, findings)

        db.update_analysis(
            conn, analysis_id,
            packet_count=len(parsed["packets"]),
            parse_seconds=round(parse_seconds, 3),
            detect_seconds=round(detect_seconds, 3),
        )
    finally:
        conn.close()
    return analysis_id


@app.route("/analysis/<int:analysis_id>")
def dashboard(analysis_id):
    conn = db.get_connection()
    analysis = db.get_analysis(conn, analysis_id)
    if analysis is None:
        conn.close()
        abort(404)

    summary = db.get_summary(conn, analysis_id)
    protocols = db.protocol_distribution(conn, analysis_id)
    talkers = db.top_talkers(conn, analysis_id)
    ports = db.top_dst_ports(conn, analysis_id)
    timeline, bucket = db.traffic_timeline(conn, analysis_id)
    dns = db.top_dns_queries(conn, analysis_id)
    raw_findings = db.get_findings(conn, analysis_id)
    findings = [dict(f) for f in raw_findings]

    # If findings table was empty but packets exist, run rules and persist findings
    if not findings:
        pkt_count = conn.execute("SELECT COUNT(*) FROM packets WHERE analysis_id = ?", (analysis_id,)).fetchone()[0]
        if pkt_count > 0:
            generated = run_all_rules(conn, analysis_id)
            if generated:
                db.save_findings(conn, analysis_id, generated)
                findings = [dict(f) for f in db.get_findings(conn, analysis_id)]

    # Verify-on-PCAP: attach the packets/records that triggered each finding
    for _f in findings:
        _f["evidence_packets"] = db.get_finding_evidence(conn, analysis_id, _f)
    conn.close()

    # Normalize findings attributes
    for f in findings:
        if not f.get("pillar"):
            f["pillar"] = db.DEFAULT_PILLARS.get(f.get("rule", ""), "Confidentiality")
        if not f.get("evidence"):
            f["evidence"] = f.get("detail", "")

    # Calculate CIA posture score & pillar cards
    posture_score, pillar_cards = calculate_posture_score(findings)

    # Health band rating and styling
    if posture_score >= 90:
        posture_band = {
            "rating": "Secure / Clean",
            "badge_class": "bg-emerald-500/15 text-emerald-400 border-emerald-500/40",
            "bar_class": "bg-emerald-500",
            "color": "emerald",
            "description": "Nominal baseline. Zero critical CIA threats or protocol anomalies detected in network telemetry.",
        }
    elif posture_score >= 70:
        posture_band = {
            "rating": "Guarded / Low Risk",
            "badge_class": "bg-amber-500/15 text-amber-300 border-amber-500/40",
            "bar_class": "bg-amber-500",
            "color": "amber",
            "description": "Minor anomalies or low/medium severity reconnaissance probes detected.",
        }
    elif posture_score >= 40:
        posture_band = {
            "rating": "Degraded / High Risk",
            "badge_class": "bg-orange-500/15 text-orange-400 border-orange-500/40",
            "bar_class": "bg-orange-500",
            "color": "orange",
            "description": "Active reconnaissance, protocol evasion, or abnormal resource consumption detected.",
        }
    else:
        posture_band = {
            "rating": "Critical / Compromised",
            "badge_class": "bg-rose-500/15 text-rose-300 border-rose-500/40",
            "bar_class": "bg-rose-500",
            "color": "rose",
            "description": "Critical security violations: cleartext credentials exposed, link-layer MITM, or active DoS flood in progress.",
        }

    severity_counts = {"High": 0, "Medium": 0, "Low": 0}
    pillar_counts = {"Confidentiality": 0, "Integrity": 0, "Authentication": 0, "Availability": 0}
    detected_rule_names = set()
    for f in findings:
        sev = f.get("severity", "Medium")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
        p = f.get("pillar", "Confidentiality")
        pillar_counts[p] = pillar_counts.get(p, 0) + 1
        if f.get("rule"):
            detected_rule_names.add(f["rule"])

    # Identify primary risk pillar (lowest score with violations)
    sorted_pillars = sorted(pillar_cards.items(), key=lambda kv: (kv[1]["score"], -kv[1]["violations_count"]))
    primary_risk_pillar = sorted_pillars[0][0] if sorted_pillars and sorted_pillars[0][1]["score"] < 25 else "None"

    size_mb = analysis["file_size"] / (1024 * 1024) if analysis["file_size"] else 0
    total_seconds = (analysis["parse_seconds"] or 0) + (analysis["detect_seconds"] or 0)

    chart_data = {
        "protocols": {"labels": [r["protocol"] for r in protocols],
                      "values": [r["count"] for r in protocols]},
        "timeline": {"labels": [f"{int((r['b'] or 0) * bucket)}s" for r in timeline],
                     "values": [r["count"] for r in timeline]},
        "talkers": {"labels": [r["src_ip"] for r in talkers],
                    "values": [r["bytes"] for r in talkers]},
        "ports": {"labels": [str(r["dst_port"]) for r in ports],
                  "values": [r["count"] for r in ports]},
    }

    return render_template(
        "dashboard.html",
        analysis=analysis,
        summary=summary,
        findings=findings,
        severity_counts=severity_counts,
        pillar_counts=pillar_counts,
        posture_score=posture_score,
        posture_band=posture_band,
        pillar_cards=pillar_cards,
        primary_risk_pillar=primary_risk_pillar,
        dns=dns,
        chart_data=chart_data,
        rule_descriptions=RULE_DESCRIPTIONS,
        thresholds=THRESHOLDS,
        size_mb=size_mb,
        total_seconds=total_seconds,
        seconds_per_mb=(total_seconds / size_mb) if size_mb else 0,
    )


def _posture_band_for(score):
    if score >= 90:
        return {"rating": "Secure / Clean", "description": "Nominal baseline. Zero critical CIA threats or protocol anomalies detected."}
    if score >= 70:
        return {"rating": "Guarded / Low Risk", "description": "Minor anomalies or low/medium severity reconnaissance probes detected."}
    if score >= 40:
        return {"rating": "Degraded / High Risk", "description": "Active reconnaissance, protocol evasion, or abnormal resource consumption detected."}
    return {"rating": "Critical / Compromised", "description": "Critical security violations: cleartext credentials, link-layer MITM, or active DoS flood."}


@app.route("/analysis/<int:analysis_id>/report.pdf")
def report_pdf(analysis_id):
    from report_pdf import generate_report_pdf
    conn = db.get_connection()
    analysis = db.get_analysis(conn, analysis_id)
    if analysis is None:
        conn.close()
        abort(404)
    findings = [dict(f) for f in db.get_findings(conn, analysis_id)]
    conn.close()
    for f in findings:
        if not f.get("pillar"):
            f["pillar"] = db.DEFAULT_PILLARS.get(f.get("rule", ""), "Confidentiality")
    posture_score, pillar_cards = calculate_posture_score(findings)
    posture_band = _posture_band_for(posture_score)
    severity_counts = {"High": 0, "Medium": 0, "Low": 0}
    for f in findings:
        sev = f.get("severity", "Medium")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
    pdf = generate_report_pdf(dict(analysis), findings, posture_score,
                              pillar_cards, posture_band, severity_counts)
    return Response(pdf, mimetype="application/pdf", headers={
        "Content-Disposition": 'attachment; filename="posture_report_%d.pdf"' % analysis_id})


@app.route("/settings", methods=["GET", "POST"])
def settings():
    from detection.rules import THRESHOLDS as _T, load_thresholds, save_thresholds, reset_thresholds
    if request.method == "POST":
        overrides = {k: request.form.get(k) for k in _T
                     if not isinstance(_T[k], list) and request.form.get(k) not in (None, "")}
        save_thresholds(overrides)
        flash("Detection thresholds saved. They apply to the next analysis.")
        return redirect(url_for("settings"))
    if request.args.get("reset"):
        reset_thresholds()
        flash("Thresholds reset to built-in defaults.")
        return redirect(url_for("settings"))
    current = load_thresholds()
    editable = {k: v for k, v in current.items() if not isinstance(v, list)}
    defaults = {k: v for k, v in _T.items() if not isinstance(v, list)}
    return render_template("settings.html", thresholds=editable, defaults=defaults)


if __name__ == "__main__":
    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", "5001"))
    debug = os.environ.get("FLASK_DEBUG", "1") == "1"
    app.run(host=host, debug=debug, port=port)
