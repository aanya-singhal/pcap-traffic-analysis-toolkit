"""
Evaluates the detection rules against the labelled test captures in samples/.
Metrics (from the synopsis): TPR, FPR, processing time per MB, database completeness.

Run:  python tests/run_evaluation.py
"""
import json
import os
import sys
import time

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE_DIR)

from scapy.all import rdpcap
from database import db
from parser.pcap_parser import parse_pcap
from detection.rules import run_all_rules, RULE_DESCRIPTIONS

# Use a separate database so evaluation runs don't mix with dashboard uploads
db.DB_PATH = os.path.join(BASE_DIR, "eval.db")
if os.path.exists(db.DB_PATH):
    os.remove(db.DB_PATH)

SAMPLES = os.path.join(BASE_DIR, "samples")
RULES = list(RULE_DESCRIPTIONS)


def main():
    with open(os.path.join(SAMPLES, "expected_findings.json")) as f:
        expected = json.load(f)

    db.init_db()
    conn = db.get_connection()
    tp = fp = fn = tn = 0
    results = []

    for filename, exp_rules in expected.items():
        path = os.path.join(SAMPLES, filename)
        size_mb = os.path.getsize(path) / (1024 * 1024)
        packets_in_file = len(rdpcap(path))

        t0 = time.time()
        parsed = parse_pcap(path)
        parse_s = time.time() - t0

        aid = db.create_analysis(conn, filename, os.path.getsize(path))
        db.insert_parsed(conn, aid, parsed)
        stored = conn.execute("SELECT COUNT(*) FROM packets WHERE analysis_id = ?", (aid,)).fetchone()[0]

        t1 = time.time()
        findings = run_all_rules(conn, aid)
        detect_s = time.time() - t1

        detected = sorted({f["rule"] for f in findings})
        for rule in RULES:
            e, d = rule in exp_rules, rule in detected
            if e and d: tp += 1
            elif d and not e: fp += 1
            elif e and not d: fn += 1
            else: tn += 1

        results.append({
            "file": filename,
            "expected": exp_rules,
            "detected": detected,
            "status": "PASS" if set(exp_rules) == set(detected) else "FAIL",
            "findings": len(findings),
            "packets_in_file": packets_in_file,
            "stored": stored,
            "size_mb": size_mb,
            "total_s": parse_s + detect_s,
            "s_per_mb": (parse_s + detect_s) / size_mb if size_mb else 0,
        })

    conn.close()

    tpr = tp / (tp + fn) if (tp + fn) else 0
    fpr = fp / (fp + tn) if (fp + tn) else 0

    # ---- Print to terminal ----
    print(f"\n{'File':<22} {'Status':<6} {'Expected':<34} {'Detected':<34} {'Stored/File':<12} {'s/MB':>6}")
    print("-" * 120)
    for r in results:
        print(f"{r['file']:<22} {r['status']:<6} {', '.join(r['expected']) or 'none':<34} "
              f"{', '.join(r['detected']) or 'none':<34} {r['stored']}/{r['packets_in_file']:<7} {r['s_per_mb']:>6.1f}")
    print("-" * 120)
    print(f"TP={tp}  FP={fp}  FN={fn}  TN={tn}")
    print(f"True Positive Rate (TPR):  {tpr:.0%}")
    print(f"False Positive Rate (FPR): {fpr:.0%}")

    # ---- Save markdown for the report ----
    os.makedirs(os.path.join(BASE_DIR, "docs"), exist_ok=True)
    with open(os.path.join(BASE_DIR, "docs", "evaluation_results.md"), "w") as f:
        f.write("# Preliminary Evaluation Results\n\n")
        f.write("Labelled synthetic captures (normal background traffic + one known attack each), "
                "generated with `tests/generate_test_pcaps.py`. Evaluated per scenario x rule "
                f"({len(RULES)} rules x {len(results)} captures).\n\n")
        f.write("| Capture | Expected | Detected | Result | Packets stored / in file | Size (MB) | Time (s) | s/MB |\n")
        f.write("|---|---|---|---|---|---|---|---|\n")
        for r in results:
            f.write(f"| {r['file']} | {', '.join(r['expected']) or 'none'} | {', '.join(r['detected']) or 'none'} | "
                    f"{r['status']} | {r['stored']} / {r['packets_in_file']} | {r['size_mb']:.2f} | "
                    f"{r['total_s']:.2f} | {r['s_per_mb']:.1f} |\n")
        f.write(f"\n**TP={tp}, FP={fp}, FN={fn}, TN={tn}**\n\n")
        f.write(f"- True Positive Rate: **{tpr:.0%}**\n")
        f.write(f"- False Positive Rate: **{fpr:.0%}**\n")
    print("\nSaved docs/evaluation_results.md")


if __name__ == "__main__":
    main()
