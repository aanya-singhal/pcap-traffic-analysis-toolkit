#!/usr/bin/env python3
"""
Evaluate the CIA Triad detection engine against a labelled PCAP corpus.

For every capture in datasets/ (listed in datasets/labels.json) this runs the
REAL pipeline the app uses -- parse_pcap -> insert_parsed -> run_all_rules --
then compares the rules that fired to the ground-truth labels and reports
precision / recall / F1 per rule plus an overall score.

Run from the project root:   python3 evaluate.py
Outputs: a printed report + datasets/eval_results.json

It uses its own throwaway SQLite DB, so your real analyses are untouched.
"""
import json
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from parser.pcap_parser import parse_pcap          # the app's real parser
from database import db as dbm
from detection.rules import run_all_rules

DATASETS = os.path.join(HERE, "datasets")
LABELS = os.path.join(DATASETS, "labels.json")


def detect_on(path, tmp_db):
    """Run the full pipeline on one pcap; return the set of rule names that fired."""
    dbm.init_db(tmp_db)
    conn = dbm.get_connection(tmp_db)
    try:
        aid = dbm.create_analysis(conn, os.path.basename(path), os.path.getsize(path))
        parsed = parse_pcap(path)
        dbm.insert_parsed(conn, aid, parsed)
        findings = run_all_rules(conn, aid)
        return sorted({f["rule"] for f in findings}), len(parsed.get("packets", []))
    finally:
        conn.close()


def prf(tp, fp, fn):
    p = tp / (tp + fp) if (tp + fp) else 0.0
    r = tp / (tp + fn) if (tp + fn) else 0.0
    f = 2 * p * r / (p + r) if (p + r) else 0.0
    return p, r, f


def main():
    if not os.path.exists(LABELS):
        sys.exit(f"No labels.json at {LABELS}. Run generate_datasets.py first.")
    with open(LABELS) as f:
        manifest = json.load(f)

    all_rules = sorted({r for m in manifest.values() for r in m["expected_rules"]})
    per_rule = {r: {"tp": 0, "fp": 0, "fn": 0} for r in all_rules}
    rows, exact_match = [], 0

    fd, tmp_db = tempfile.mkstemp(suffix=".db"); os.close(fd)
    try:
        for fname, meta in manifest.items():
            path = os.path.join(DATASETS, fname)
            if not os.path.exists(path):
                print(f"  ! missing {fname}, skipping"); continue
            expected = set(meta["expected_rules"])
            detected, npkts = detect_on(path, tmp_db)
            detected = set(detected)
            for r in all_rules:
                if r in expected and r in detected: per_rule[r]["tp"] += 1
                elif r in detected and r not in expected: per_rule[r]["fp"] += 1
                elif r in expected and r not in detected: per_rule[r]["fn"] += 1
            ok = (expected == detected)
            exact_match += ok
            rows.append({"capture": fname, "packets": npkts,
                         "expected": sorted(expected), "detected": sorted(detected),
                         "pass": ok})
    finally:
        os.remove(tmp_db)

    # aggregate
    tot = {"tp": sum(v["tp"] for v in per_rule.values()),
           "fp": sum(v["fp"] for v in per_rule.values()),
           "fn": sum(v["fn"] for v in per_rule.values())}
    micro = prf(tot["tp"], tot["fp"], tot["fn"])

    # ---- print report ----
    print("\n" + "=" * 72)
    print("  CIA TRIAD TOOLKIT — DETECTION EVALUATION")
    print("=" * 72)
    print(f"  Corpus: {len(rows)} captures   |   Rules evaluated: {len(all_rules)}")
    print("-" * 72)
    print(f"  {'Capture':22s} {'Pkts':>5s}  {'Result':7s} {'Detected'}")
    for r in rows:
        tag = "PASS" if r["pass"] else "FAIL"
        det = ", ".join(r["detected"]) or "(none)"
        print(f"  {r['capture']:22s} {r['packets']:5d}  {tag:7s} {det}")
    print("-" * 72)
    print(f"  {'Rule':26s} {'TP':>3s} {'FP':>3s} {'FN':>3s}  {'Prec':>6s} {'Rec':>6s} {'F1':>6s}")
    for r in all_rules:
        v = per_rule[r]; p, rc, f1 = prf(v["tp"], v["fp"], v["fn"])
        print(f"  {r:26s} {v['tp']:3d} {v['fp']:3d} {v['fn']:3d}  {p:6.2f} {rc:6.2f} {f1:6.2f}")
    print("-" * 72)
    print(f"  Exact-match captures : {exact_match}/{len(rows)} ({exact_match/len(rows):.0%})")
    print(f"  Micro precision/recall/F1 : {micro[0]:.2f} / {micro[1]:.2f} / {micro[2]:.2f}")
    print("=" * 72 + "\n")

    results = {
        "corpus_size": len(rows),
        "rules_evaluated": all_rules,
        "exact_match": exact_match,
        "micro": {"precision": round(micro[0], 4), "recall": round(micro[1], 4), "f1": round(micro[2], 4)},
        "per_rule": {r: {**per_rule[r], "precision": round(prf(**{k: per_rule[r][k] for k in ('tp','fp','fn')})[0], 4),
                         "recall": round(prf(**{k: per_rule[r][k] for k in ('tp','fp','fn')})[1], 4),
                         "f1": round(prf(**{k: per_rule[r][k] for k in ('tp','fp','fn')})[2], 4)}
                     for r in all_rules},
        "captures": rows,
    }
    with open(os.path.join(DATASETS, "eval_results.json"), "w") as f:
        json.dump(results, f, indent=2)
    print(f"  Wrote {os.path.join(DATASETS, 'eval_results.json')}")
    return 0 if exact_match == len(rows) else 1


if __name__ == "__main__":
    sys.exit(main())
