"""
Evaluates threat detection rules and CIA Triad classifications against labelled
test captures in samples/. Computes confusion matrix, TPR, FPR, database
completeness, and validates CIA pillar assignments.

Run:  python tests/run_evaluation.py
"""
import json
import os
import sys
import time
import traceback

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE_DIR)

from scapy.all import rdpcap
from database import db
from parser.pcap_parser import parse_pcap

try:
    from detection.rules import run_all_rules, RULE_DESCRIPTIONS
except ImportError:
    run_all_rules = None
    RULE_DESCRIPTIONS = {}

# Use a separate database so evaluation runs don't interfere with production/development data
db.DB_PATH = os.path.join(BASE_DIR, "eval.db")

SAMPLES = os.path.join(BASE_DIR, "samples")

EVALUATED_PILLARS = [
    "Confidentiality",
    "Integrity",
    "Authentication",
    "Availability",
]

EVALUATED_RULES = [
    "Cleartext Credentials",
    "ARP Cache Poisoning",
    "TCP Flag Evasion",
    "TCP SYN Flood",
    "Brute Force",
    "Port Scan",
    "Suspicious Port",
    "Volume Anomaly",
    "DNS Anomaly",
]

# Merge with any dynamically declared rules in RULE_DESCRIPTIONS
ALL_RULES = sorted(list(set(EVALUATED_RULES) | set(RULE_DESCRIPTIONS.keys())))


def evaluate():
    if os.path.exists(db.DB_PATH):
        try:
            os.remove(db.DB_PATH)
        except OSError:
            pass

    expected_file = os.path.join(SAMPLES, "expected_findings.json")
    if not os.path.exists(expected_file):
        print(f"Error: Expected findings manifest not found at {expected_file}")
        sys.exit(1)

    with open(expected_file) as f:
        expected = json.load(f)

    db.init_db()
    conn = db.get_connection()

    tp = fp = fn = tn = 0
    pillar_tp = pillar_fp = pillar_fn = pillar_tn = 0
    unhandled_exceptions = 0
    results = []
    invalid_pillar_findings = []

    print(f"\nEvaluating {len(expected)} captures against {len(ALL_RULES)} rules across 4 CIA pillars...")
    print(f"Rules:   {', '.join(ALL_RULES)}")
    print(f"Pillars: {', '.join(EVALUATED_PILLARS)}\n")

    for filename, exp_data in expected.items():
        if isinstance(exp_data, dict):
            exp_rules = exp_data.get("expected_rules", [])
            exp_pillars = exp_data.get("expected_pillars", [])
        else:
            exp_rules = exp_data
            exp_pillars = []

        path = os.path.join(SAMPLES, filename)
        if not os.path.exists(path):
            print(f"Warning: Capture file missing: {path}")
            unhandled_exceptions += 1
            results.append({
                "file": filename,
                "status": "MISSING",
                "error": "File not found",
                "expected_rules": exp_rules,
                "detected_rules": [],
                "expected_pillars": exp_pillars,
                "detected_pillars": [],
                "findings": 0,
                "packets_in_file": 0,
                "stored": 0,
                "size_mb": 0,
                "total_s": 0,
                "s_per_mb": 0,
            })
            continue

        size_mb = os.path.getsize(path) / (1024 * 1024)
        packets_in_file = len(rdpcap(path))

        try:
            t0 = time.time()
            parsed = parse_pcap(path)
            parse_s = time.time() - t0

            aid = db.create_analysis(conn, filename, os.path.getsize(path))
            db.insert_parsed(conn, aid, parsed)
            stored = conn.execute("SELECT COUNT(*) FROM packets WHERE analysis_id = ?", (aid,)).fetchone()[0]

            t1 = time.time()
            findings = run_all_rules(conn, aid) if run_all_rules else []
            detect_s = time.time() - t1

            # Validate CIA pillar on each detected finding
            detected_rules_set = set()
            detected_pillars_set = set()
            for f in findings:
                rule_name = f.get("rule", "Unknown")
                pillar = f.get("pillar") or f.get("category")
                detected_rules_set.add(rule_name)
                if pillar:
                    detected_pillars_set.add(pillar)
                    if pillar not in EVALUATED_PILLARS:
                        invalid_pillar_findings.append({
                            "file": filename,
                            "rule": rule_name,
                            "invalid_pillar": pillar,
                        })
                else:
                    invalid_pillar_findings.append({
                        "file": filename,
                        "rule": rule_name,
                        "invalid_pillar": None,
                    })

            detected_rules = sorted(list(detected_rules_set))
            detected_pillars = sorted(list(detected_pillars_set))

            # Rule confusion matrix update
            for rule in ALL_RULES:
                e = rule in exp_rules
                d = rule in detected_rules
                if e and d:
                    tp += 1
                elif d and not e:
                    fp += 1
                elif e and not d:
                    fn += 1
                else:
                    tn += 1

            # Pillar confusion matrix update
            for pillar in EVALUATED_PILLARS:
                pe = pillar in exp_pillars
                pd = pillar in detected_pillars
                if pe and pd:
                    pillar_tp += 1
                elif pd and not pe:
                    pillar_fp += 1
                elif pe and not pd:
                    pillar_fn += 1
                else:
                    pillar_tn += 1

            rules_matched = set(exp_rules) == set(detected_rules)
            pillars_matched = set(exp_pillars) == set(detected_pillars)
            status = "PASS" if rules_matched and pillars_matched else "FAIL"

            results.append({
                "file": filename,
                "expected_rules": exp_rules,
                "detected_rules": detected_rules,
                "expected_pillars": exp_pillars,
                "detected_pillars": detected_pillars,
                "status": status,
                "findings": len(findings),
                "packets_in_file": packets_in_file,
                "stored": stored,
                "size_mb": size_mb,
                "total_s": parse_s + detect_s,
                "s_per_mb": (parse_s + detect_s) / size_mb if size_mb else 0,
            })

        except Exception as ex:
            unhandled_exceptions += 1
            print(f"Exception evaluating {filename}: {ex}")
            traceback.print_exc()
            results.append({
                "file": filename,
                "status": "ERROR",
                "error": str(ex),
                "expected_rules": exp_rules,
                "detected_rules": [],
                "expected_pillars": exp_pillars,
                "detected_pillars": [],
                "findings": 0,
                "packets_in_file": packets_in_file,
                "stored": 0,
                "size_mb": size_mb,
                "total_s": 0,
                "s_per_mb": 0,
            })

    conn.close()

    tpr = tp / (tp + fn) if (tp + fn) > 0 else 1.0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    pillar_tpr = pillar_tp / (pillar_tp + pillar_fn) if (pillar_tp + pillar_fn) > 0 else 1.0
    pillar_fpr = pillar_fp / (pillar_fp + pillar_tn) if (pillar_fp + pillar_tn) > 0 else 0.0

    # ---- Terminal Output ----
    print(f"\n{'Capture File':<28} {'Status':<6} {'Expected Rules':<30} {'Detected Rules':<30} {'Pillars (Exp/Det)':<24} {'Packets':<12}")
    print("-" * 140)
    for r in results:
        exp_r_str = ", ".join(r["expected_rules"]) or "none"
        det_r_str = ", ".join(r["detected_rules"]) or "none"
        exp_p_str = ",".join(p[:4] for p in r["expected_pillars"]) or "-"
        det_p_str = ",".join(p[:4] for p in r["detected_pillars"]) or "-"
        p_str = f"{exp_p_str} / {det_p_str}"
        pkts_str = f"{r['stored']}/{r['packets_in_file']}"
        print(f"{r['file']:<28} {r['status']:<6} {exp_r_str:<30} {det_r_str:<30} {p_str:<24} {pkts_str:<12}")
    print("-" * 140)

    print("\n=== RULE CONFUSION MATRIX & METRICS ===")
    print(f"True Positives  (TP): {tp:>3}    False Positives (FP): {fp:>3}")
    print(f"False Negatives (FN): {fn:>3}    True Negatives  (TN): {tn:>3}")
    print(f"True Positive Rate (TPR):  {tpr:>6.1%}")
    print(f"False Positive Rate (FPR): {fpr:>6.1%}")

    print("\n=== PILLAR CONFUSION MATRIX & METRICS ===")
    print(f"Pillar TP: {pillar_tp:>2} | Pillar FP: {pillar_fp:>2} | Pillar FN: {pillar_fn:>2} | Pillar TN: {pillar_tn:>2}")
    print(f"Pillar TPR: {pillar_tpr:>6.1%} | Pillar FPR: {pillar_fpr:>6.1%}")

    if invalid_pillar_findings:
        print(f"\nWARNING: {len(invalid_pillar_findings)} findings had invalid or missing CIA pillars:")
        for inv in invalid_pillar_findings:
            print(f"  - [{inv['file']}] Rule '{inv['rule']}': pillar='{inv['invalid_pillar']}'")
    else:
        print("\nPillar Integrity: All detected findings possess valid CIA Triad pillar tags.")

    # ---- Save docs/evaluation_results.md ----
    docs_dir = os.path.join(BASE_DIR, "docs")
    os.makedirs(docs_dir, exist_ok=True)
    report_path = os.path.join(docs_dir, "evaluation_results.md")

    with open(report_path, "w") as f:
        f.write("# E2E Automated Verification & Benchmark Results\n\n")
        f.write("Evaluates the CIA Triad threat detection engine against synthetic PCAP captures with known ground truth.\n\n")

        f.write("## 1. Executive Summary\n\n")
        f.write(f"- **Total Scenarios Evaluated**: {len(results)}\n")
        f.write(f"- **Evaluated Rules ({len(ALL_RULES)})**: {', '.join(ALL_RULES)}\n")
        f.write(f"- **Evaluated Pillars ({len(EVALUATED_PILLARS)})**: {', '.join(EVALUATED_PILLARS)}\n")
        f.write(f"- **Rule True Positive Rate (TPR)**: **{tpr:.1%}**\n")
        f.write(f"- **Rule False Positive Rate (FPR)**: **{fpr:.1%}**\n")
        f.write(f"- **Pillar TPR**: **{pillar_tpr:.1%}** | **Pillar FPR**: **{pillar_fpr:.1%}**\n")
        f.write(f"- **Unhandled Runtime Exceptions**: **{unhandled_exceptions}**\n")
        f.write(f"- **Pillar Tagging Integrity**: {'100% Valid' if not invalid_pillar_findings else f'{len(invalid_pillar_findings)} Invalid'}\n\n")

        f.write("## 2. Confusion Matrix (Rule Level)\n\n")
        f.write("| Metric | Value | Description |\n")
        f.write("|---|---|---|\n")
        f.write(f"| **True Positives (TP)** | {tp} | Correctly triggered expected threat rules |\n")
        f.write(f"| **False Positives (FP)** | {fp} | Spurious threat triggers on clean or unrelated traffic |\n")
        f.write(f"| **False Negatives (FN)** | {fn} | Missed expected threats |\n")
        f.write(f"| **True Negatives (TN)** | {tn} | Correctly suppressed benign rules |\n")
        f.write(f"| **Sensitivity / TPR** | {tpr:.2%} | Target: 100% |\n")
        f.write(f"| **Fall-out / FPR** | {fpr:.2%} | Target: 0% |\n\n")

        f.write("## 3. Scenario-by-Scenario Evaluation\n\n")
        f.write("| Capture File | Expected Rules | Detected Rules | Expected Pillars | Detected Pillars | Result | Packets Stored / In File | Size (MB) | Total Time (s) | s/MB |\n")
        f.write("|---|---|---|---|---|---|---|---|---|---|\n")
        for r in results:
            exp_r = ", ".join(r["expected_rules"]) or "*(None)*"
            det_r = ", ".join(r["detected_rules"]) or "*(None)*"
            exp_p = ", ".join(r["expected_pillars"]) or "*(None)*"
            det_p = ", ".join(r["detected_pillars"]) or "*(None)*"
            status_badge = f"**{r['status']}**" if r["status"] == "PASS" else f"<span style='color:red'>{r['status']}</span>"
            f.write(f"| `{r['file']}` | {exp_r} | {det_r} | {exp_p} | {det_p} | {status_badge} | {r['stored']} / {r['packets_in_file']} | {r['size_mb']:.2f} | {r['total_s']:.2f} | {r['s_per_mb']:.1f} |\n")

        f.write("\n---\n")
        f.write(f"*Report generated automatically by `tests/run_evaluation.py` on {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}.*\n")

    print(f"\nSaved detailed evaluation report to {report_path}")

    # ---- Programmatic Assertions ----
    passed = (unhandled_exceptions == 0 and tpr == 1.0 and fpr == 0.0 and len(invalid_pillar_findings) == 0)
    if passed:
        print("\n>>> ALL VERIFICATION CHECKS PASSED: 100% TPR, 0% FPR, 0 EXCEPTIONS, 100% PILLAR INTEGRITY. <<<")
        sys.exit(0)
    else:
        print(f"\n>>> VERIFICATION FAILED: TPR={tpr:.1%}, FPR={fpr:.1%}, Exceptions={unhandled_exceptions}, PillarErrors={len(invalid_pillar_findings)} <<<")
        sys.exit(1)


if __name__ == "__main__":
    evaluate()
