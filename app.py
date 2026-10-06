"""
Flask web app: upload a PCAP, run the analysis pipeline, show the dashboard.
Pipeline: Upload -> Parse -> Store -> Detect -> Visualize
"""
import os
import time

from flask import Flask, render_template, request, redirect, url_for, flash, abort
from werkzeug.utils import secure_filename

from parser.pcap_parser import parse_pcap
from database import db
from detection.rules import run_all_rules, RULE_DESCRIPTIONS, THRESHOLDS

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")
ALLOWED_EXTENSIONS = {".pcap", ".pcapng", ".cap"}

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
    return render_template("index.html", recent=recent)


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

    conn = db.get_connection()
    analysis_id = db.create_analysis(conn, filename, file_size)
    try:
        # 1. Parse
        t0 = time.time()
        parsed = parse_pcap(saved_path)
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
    except Exception as e:
        conn.close()
        flash(f"Could not analyse this file: {e}")
        return redirect(url_for("index"))

    conn.close()
    return redirect(url_for("dashboard", analysis_id=analysis_id))


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
    findings = db.get_findings(conn, analysis_id)
    conn.close()

    severity_counts = {"High": 0, "Medium": 0, "Low": 0}
    for f in findings:
        severity_counts[f["severity"]] = severity_counts.get(f["severity"], 0) + 1

    size_mb = analysis["file_size"] / (1024 * 1024) if analysis["file_size"] else 0
    total_seconds = (analysis["parse_seconds"] or 0) + (analysis["detect_seconds"] or 0)

    chart_data = {
        "protocols": {"labels": [r["protocol"] for r in protocols],
                      "values": [r["count"] for r in protocols]},
        "timeline": {"labels": [f"{int(r['b'] * bucket)}s" for r in timeline],
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
        dns=dns,
        chart_data=chart_data,
        rule_descriptions=RULE_DESCRIPTIONS,
        thresholds=THRESHOLDS,
        size_mb=size_mb,
        total_seconds=total_seconds,
        seconds_per_mb=(total_seconds / size_mb) if size_mb else 0,
    )


if __name__ == "__main__":
    app.run(debug=True, port=5001)
