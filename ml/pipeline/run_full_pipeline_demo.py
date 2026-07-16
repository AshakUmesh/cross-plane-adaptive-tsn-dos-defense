#!/usr/bin/env python3
"""
run_full_pipeline_demo.py

Runs the complete chain on REAL data and prints a per-window trace table:

    Window -> IsoForest (flag?) -> RF (attack type) -> RL (recommended action)

This is the single script that proves/disproves whether each stage of
the architecture is genuinely wired together, rather than three
separately-tested components.

IMPORTANT, STATED EXPLICITLY:
    The "RL recommended action" column shows what the agent WOULD do.
    Nothing in this script (or anywhere in this project) writes that
    action into a real PSFP parameter or applies it to a running
    simulation. That is the one remaining, unbuilt piece -- see the
    script's final summary for what's still needed to close this gap.

Usage:
    python3 run_full_pipeline_demo.py \
        --csv combined_features_multiclass.csv \
        --stream attackNode \
        --isoforest-model experiments/pooled_for_pipeline/trained_model.pkl \
        --isoforest-threshold experiments/pooled_for_pipeline/threshold.txt \
        --rf-model experiments/random_forest/random_forest.pkl \
        --rf-report experiments/random_forest/rf_report.json \
        --rl-qtable experiments/rl_agent/q_table.npy \
        --rl-report experiments/rl_agent/rl_report.json
"""

import argparse
import csv
import json
import pickle
import sys
from pathlib import Path

try:
    import numpy as np
except ImportError:
    print("ERROR: pip install numpy scikit-learn", file=sys.stderr)
    sys.exit(1)

FEATURE_COLS = ["mean_IAT", "IAT_variance", "mean_frame_size", "burst_length", "count"]

ACTIONS = ["no_op", "tighten_gate_10", "tighten_gate_15",
           "reduce_cir_0.5", "reduce_cir_0.6", "reduce_cbs_0.5"]


def load_threshold(path):
    text = Path(path).read_text()
    for line in text.splitlines():
        if line.startswith("isoforest_offset_="):
            return float(line.split("=", 1)[1])
    raise ValueError(f"Could not parse threshold from {path}")


def load_windows(csv_path, stream, config_filter=None):
    rows = []
    with open(csv_path, newline="") as f:
        for row in csv.DictReader(f):
            if row["stream"] != stream:
                continue
            if config_filter and row["config"] != config_filter:
                continue
            if not row["count"] or int(row["count"]) == 0:
                continue
            try:
                feat = [float(row[c]) for c in FEATURE_COLS]
            except (ValueError, TypeError):
                continue
            rows.append({
                "config": row["config"], "window_index": row["window_index"],
                "features": feat, "true_label": int(row["label"]),
            })
    return rows


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--csv", default="combined_features_multiclass.csv")
    ap.add_argument("--stream", default="attackNode")
    ap.add_argument("--config-filter", default=None)
    ap.add_argument("--max-rows", type=int, default=30,
                     help="Max rows to print in the trace table (data "
                          "beyond this is still processed for the summary)")
    ap.add_argument("--isoforest-model", required=True)
    ap.add_argument("--isoforest-threshold", required=True)
    ap.add_argument("--rf-model", required=True)
    ap.add_argument("--rf-report", required=True)
    ap.add_argument("--rl-qtable", required=True)
    ap.add_argument("--rl-report", required=True)
    args = ap.parse_args()

    with open(args.isoforest_model, "rb") as f:
        iso = pickle.load(f)
    threshold = load_threshold(args.isoforest_threshold)

    with open(args.rf_model, "rb") as f:
        rf = pickle.load(f)
    with open(args.rf_report) as f:
        rf_report = json.load(f)
    label_names = {int(k): v for k, v in rf_report["label_names"].items()}

    Q = np.load(args.rl_qtable)
    with open(args.rl_report) as f:
        rl_report = json.load(f)
    rl_states = rl_report["states"]
    state_idx = {s: i for i, s in enumerate(rl_states)}

    windows = load_windows(args.csv, args.stream, args.config_filter)
    if not windows:
        print("No windows loaded.", file=sys.stderr)
        sys.exit(1)

    print(f"Stream: {args.stream}   Windows: {len(windows)}")
    print(f"IsoForest threshold: {threshold:.6f}\n")

    print(f"{'Config':26s} {'Win':>4s} {'IsoScore':>9s} {'Flagged':>8s} "
          f"{'RF Class':22s} {'RL Action (recommended, NOT applied)':38s}")
    print("-" * 115)

    trace_rows = []
    flagged_count = 0
    for i, w in enumerate(windows):
        x = np.array([w["features"]])
        score = float(iso.score_samples(x)[0])
        flagged = score < threshold

        rf_pred_name = "-"
        rl_action = "-"
        if flagged:
            flagged_count += 1
            rf_pred = int(rf.predict(x)[0])
            rf_pred_name = label_names.get(rf_pred, str(rf_pred))

            if rf_pred_name in state_idx:
                s = state_idx[rf_pred_name]
                rl_action = ACTIONS[int(np.argmax(Q[s]))]
            else:
                rl_action = "no_op (unseen class, fail-safe)"

        row = {
            "config": w["config"], "window": w["window_index"],
            "score": round(score, 4), "flagged": flagged,
            "rf_class": rf_pred_name, "rl_action": rl_action,
        }
        trace_rows.append(row)

        if i < args.max_rows:
            print(f"{w['config']:26s} {w['window_index']:>4s} {score:9.4f} "
                  f"{'YES' if flagged else 'no':>8s} {rf_pred_name:22s} {rl_action:38s}")

    if len(windows) > args.max_rows:
        print(f"... ({len(windows) - args.max_rows} more rows processed, "
              f"not printed -- see --max-rows to show more)")

    print(f"\n{'='*70}")
    print(f"SUMMARY")
    print(f"{'='*70}")
    print(f"Total windows:    {len(windows)}")
    print(f"Flagged (Stage 1 -> Stage 2 invoked): {flagged_count} "
          f"({flagged_count/len(windows)*100:.1f}%)")
    print(f"Non-op actions recommended: "
          f"{sum(1 for r in trace_rows if r['rl_action'] not in ('-', 'no_op'))}")

    print(f"\n{'!'*70}")
    print(f"GAP CONFIRMED: every 'RL Action' above is a RECOMMENDATION only.")
    print(f"No code in this pipeline writes these actions into a real PSFP")
    print(f"parameter (CIR/CBS/gate) or applies them to a running simulation.")
    print(f"To close this gap: (1) obtain real PSFP meter parameter names")
    print(f"from omnetpp.ini, (2) build a script that translates each action")
    print(f"into a concrete new parameter value and writes a new .ini Config")
    print(f"block, (3) [optional] rerun that Config in OMNeT++ to measure the")
    print(f"attack's throughput reduction empirically.")
    print(f"{'!'*70}")


if __name__ == "__main__":
    main()
