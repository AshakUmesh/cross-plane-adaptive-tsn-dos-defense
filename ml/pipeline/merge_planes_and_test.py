#!/usr/bin/env python3
"""
merge_planes_and_test.py

Merges Data-plane (5 features) and Schedule-plane (5 features) CSVs on
(config, run, window_index) and trains/scores IsoForest with all 10
features -- to empirically test whether adding Schedule-plane signal
recovers detection of attacks that Data-plane-alone missed at a strict
threshold, rather than assuming it would from the raw feature values
alone.

Usage:
    python3 merge_planes_and_test.py \
        --data-csv combined_features.csv --data-stream attackNode \
        --schedule-csv schedule_features_attacker.csv \
        --benign-data-csv combined_features.csv --benign-data-stream radarNode \
        --benign-schedule-csv schedule_features_radar.csv \
        --config-filter GateBoundaryProximityAttack \
        --contamination 0.01
"""

import argparse
import csv
import sys
from collections import defaultdict

try:
    import numpy as np
    from sklearn.ensemble import IsolationForest
except ImportError:
    print("ERROR: pip install scikit-learn numpy", file=sys.stderr)
    sys.exit(1)

DATA_COLS = ["mean_IAT", "IAT_variance", "mean_frame_size", "burst_length", "count"]
SCHED_COLS = ["phase_offset_mean_us", "phase_offset_std_us", "gate_util",
              "queue_depth_max", "drops"]


def load_data_plane(path, stream, config_filter=None):
    rows = {}
    with open(path, newline="") as f:
        for row in csv.DictReader(f):
            if row["stream"] != stream:
                continue
            if config_filter and row["config"] != config_filter:
                continue
            if not row["count"] or int(row["count"]) == 0:
                continue
            key = (row["config"], row["run"], row["window_index"])
            try:
                rows[key] = [float(row[c]) for c in DATA_COLS]
            except (ValueError, TypeError):
                continue
    return rows


def load_schedule_plane(path, config_filter=None):
    rows = {}
    with open(path, newline="") as f:
        for row in csv.DictReader(f):
            if config_filter and row["config"] != config_filter:
                continue
            key = (row["config"], row["run"], row["window_index"])
            try:
                feat = []
                for c in SCHED_COLS:
                    v = row[c]
                    feat.append(float(v) if v not in ("", None) else 0.0)
                rows[key] = feat
            except (ValueError, TypeError):
                continue
    return rows


def merge(data_rows, sched_rows):
    """Inner join on the shared key; returns list of 10-dim feature vectors."""
    merged = []
    missing_sched = 0
    for key, dvec in data_rows.items():
        if key in sched_rows:
            merged.append(dvec + sched_rows[key])
        else:
            missing_sched += 1
    return merged, missing_sched


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--data-csv", required=True)
    ap.add_argument("--data-stream", default="attackNode")
    ap.add_argument("--schedule-csv", required=True)
    ap.add_argument("--benign-data-csv", required=True)
    ap.add_argument("--benign-data-stream", default="radarNode")
    ap.add_argument("--benign-schedule-csv", required=True)
    ap.add_argument("--config-filter", default=None,
                     help="Restrict attack rows to this config (benign "
                          "rows are never filtered by this)")
    ap.add_argument("--contamination", type=float, default=0.01)
    args = ap.parse_args()

    # ---- Benign baseline (10-dim: data + schedule, from the legit port) ----
    benign_data = load_data_plane(args.benign_data_csv, args.benign_data_stream)
    benign_sched = load_schedule_plane(args.benign_schedule_csv)
    X_benign, missing = merge(benign_data, benign_sched)
    print(f"Benign: {len(X_benign)} merged windows "
          f"({missing} data-plane windows had no schedule-plane match)")
    if not X_benign:
        print("No benign windows merged -- check keys align (config/run/"
              "window_index) between the two CSVs.", file=sys.stderr)
        sys.exit(1)
    X_benign = np.array(X_benign)

    # ---- Attack windows (10-dim, from the attacker's own port) ----
    attack_data = load_data_plane(args.data_csv, args.data_stream, args.config_filter)
    attack_sched = load_schedule_plane(args.schedule_csv, args.config_filter)
    X_attack, missing_a = merge(attack_data, attack_sched)
    print(f"Attack ({args.config_filter}): {len(X_attack)} merged windows "
          f"({missing_a} unmatched)")
    if not X_attack:
        print("No attack windows merged.", file=sys.stderr)
        sys.exit(1)
    X_attack = np.array(X_attack)

    print(f"\nFeature vector: {DATA_COLS + SCHED_COLS}  (10-dim)\n")

    # ---- Compare: Data-plane-only (5-dim) vs Data+Schedule (10-dim) ----
    for label, X_b, X_a in [
        ("Data-plane ONLY (5 features, baseline)",
         X_benign[:, :5], X_attack[:, :5]),
        ("Data + Schedule COMBINED (10 features)",
         X_benign, X_attack),
    ]:
        clf = IsolationForest(n_estimators=100, contamination=args.contamination,
                               random_state=42)
        clf.fit(X_b)
        pred = clf.predict(X_a)
        detected = int(np.sum(pred == -1))
        total = len(X_a)
        tpr = detected / total if total else 0.0
        fpr = float(np.mean(clf.predict(X_b) == -1))
        print(f"{label}")
        print(f"  contamination={args.contamination}  "
              f"in-sample FPR={fpr*100:.2f}%  "
              f"TPR={tpr*100:.1f}%  ({detected}/{total} windows flagged)")


if __name__ == "__main__":
    main()
