#!/usr/bin/env python3
"""
two_tier_pipeline.py

Implements the fast-path / slow-path detection architecture:

    TSN traffic window
          |
          v
    Stage 1: IsoForest (fast, runs on EVERY window)
          |
      normal? -----> continue, no further action, no latency cost
          |
      suspicious?
          |
          v
    Stage 2: Random Forest classifier (slower, runs ONLY on flagged windows)
          |
          v
    attack_type  ------> handed to psfp_policy.py for a corrective action

Why this split matters for TSN specifically: Stage 1 must be cheap enough
to run on every window without threatening the network's own latency
bounds; Stage 2 is only invoked on the small fraction of windows Stage 1
flags (empirically ~1-7% depending on threshold -- see Chapter 8), so its
extra cost is off the real-time critical path. This is what makes a
heavier classifier (RF here, LSTM in future work) acceptable even in a
latency-sensitive TSN context.

Usage:
    python3 two_tier_pipeline.py \
        --isoforest-model experiments/mimicry_gcl_c05/trained_model.pkl \
        --isoforest-threshold experiments/mimicry_gcl_c05/threshold.txt \
        --rf-model experiments/classifier_benchmark/random_forest.pkl \
        --csv combined_features_multiclass.csv \
        --stream attackNode \
        --label-names-json experiments/classifier_benchmark/benchmark_summary.json

This replays a CSV window-by-window to demonstrate/evaluate the pipeline.
For live use, replace load_windows_from_csv() with a live feature feed
(e.g. read the latest 10ms window's features as they're computed).
"""

import argparse
import csv
import json
import pickle
import sys
import time
from pathlib import Path

try:
    import numpy as np
except ImportError:
    print("ERROR: numpy not installed. pip install numpy", file=sys.stderr)
    sys.exit(1)

FEATURE_COLS = ["mean_IAT", "IAT_variance", "mean_frame_size", "burst_length", "count"]


def load_windows_from_csv(csv_path, stream, config_filter=None):
    windows = []
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
            windows.append({
                "config": row["config"],
                "window_index": row.get("window_index"),
                "features": feat,
                "true_label": int(row["label"]),
            })
    return windows


def load_threshold(threshold_path):
    """Parses threshold.txt written by train_isoforest.py."""
    text = Path(threshold_path).read_text()
    for line in text.splitlines():
        if line.startswith("isoforest_offset_="):
            return float(line.split("=", 1)[1])
    raise ValueError(f"Could not parse offset_ from {threshold_path}")


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--isoforest-model", required=True)
    ap.add_argument("--isoforest-threshold", required=True,
                     help="Path to threshold.txt from train_isoforest.py")
    ap.add_argument("--rf-model", required=True)
    ap.add_argument("--csv", required=True)
    ap.add_argument("--stream", default="attackNode")
    ap.add_argument("--config-filter", default=None)
    ap.add_argument("--label-names-json", default=None,
                     help="benchmark_summary.json from benchmark_classifiers.py, "
                          "used to print human-readable attack names")
    args = ap.parse_args()

    with open(args.isoforest_model, "rb") as f:
        iso_clf = pickle.load(f)
    with open(args.rf_model, "rb") as f:
        rf_clf = pickle.load(f)
    threshold = load_threshold(args.isoforest_threshold)

    label_names = {0: "Benign"}
    if args.label_names_json:
        with open(args.label_names_json) as f:
            summary = json.load(f)
        label_names.update({int(k): v for k, v in summary.get("label_names", {}).items()})

    windows = load_windows_from_csv(args.csv, args.stream, args.config_filter)
    if not windows:
        print("No windows loaded -- check --stream / --config-filter / --csv.",
              file=sys.stderr)
        sys.exit(1)

    print(f"Replaying {len(windows)} windows from stream={args.stream}")
    print(f"Stage 1 (IsoForest) threshold: {threshold:.6f}\n")

    stage1_flagged = 0
    stage2_calls = 0
    t_stage1_total = 0.0
    t_stage2_total = 0.0
    results = []

    for w in windows:
        x = np.array([w["features"]])

        t0 = time.perf_counter()
        score = iso_clf.score_samples(x)[0]
        flagged = score < threshold
        t_stage1_total += time.perf_counter() - t0

        decision = {
            "config": w["config"],
            "window_index": w["window_index"],
            "stage1_score": round(float(score), 6),
            "stage1_flagged": bool(flagged),
            "stage2_predicted_label": None,
            "stage2_predicted_name": None,
        }

        if flagged:
            stage1_flagged += 1
            stage2_calls += 1
            t1 = time.perf_counter()
            pred = int(rf_clf.predict(x)[0])
            t_stage2_total += time.perf_counter() - t1
            decision["stage2_predicted_label"] = pred
            decision["stage2_predicted_name"] = label_names.get(pred, str(pred))

        results.append(decision)

    n = len(windows)
    print(f"{'='*60}")
    print(f"PIPELINE SUMMARY")
    print(f"{'='*60}")
    print(f"Total windows processed      : {n}")
    print(f"Stage 1 flagged (suspicious) : {stage1_flagged} "
          f"({stage1_flagged/n*100:.1f}%)")
    print(f"Stage 2 invoked               : {stage2_calls} "
          f"({stage2_calls/n*100:.1f}% of total windows)")
    print()
    print(f"Stage 1 avg latency per window: {t_stage1_total/n*1e6:.2f} us")
    if stage2_calls:
        print(f"Stage 2 avg latency per call   : {t_stage2_total/stage2_calls*1e6:.2f} us")
    print()
    print(f"Effective avg latency per window (Stage1 always + Stage2 "
          f"only when flagged): "
          f"{(t_stage1_total + t_stage2_total)/n*1e6:.2f} us")
    print(f"  -> Stage 2's cost is amortized over only "
          f"{stage2_calls/n*100:.1f}% of windows, keeping the common-case "
          f"path cheap -- this is the argument for why a heavier Stage 2 "
          f"classifier remains viable under TSN latency constraints.")

    print(f"\n{'='*60}")
    print(f"Sample decisions (first 10 flagged windows):")
    print(f"{'='*60}")
    shown = 0
    for r in results:
        if r["stage1_flagged"] and shown < 10:
            print(f"  {r['config']:28s} win={r['window_index']:>3}  "
                  f"score={r['stage1_score']:.4f}  "
                  f"-> Stage2: {r['stage2_predicted_name']}")
            shown += 1


if __name__ == "__main__":
    main()
