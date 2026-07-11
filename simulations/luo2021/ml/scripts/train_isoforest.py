#!/usr/bin/env python3
"""
train_isoforest.py

Trains an Isolation Forest on BENIGN-ONLY windows from combined_features.csv,
then scores every window (benign + attack) and reports per-attack detection
rates. This is Stage 1 of your two-stage pipeline (IsoForest -> LSTM).

Why fit on benign-only:
    IsoForest is unsupervised. We are NOT teaching it what attacks look like;
    we are teaching it what NORMAL looks like, so it can flag anything that
    deviates -- including attack types it has never seen (the "zero-day"
    argument in your vulnerability analysis, V3).

Usage:
    python3 train_isoforest.py --csv combined_features.csv --stream attackNode
    python3 train_isoforest.py --csv combined_features.csv --stream av1 --contamination 0.01

Notes:
- We train separately per stream (--stream), since av1/av2/radar/control/
  attackNode have very different nominal traffic patterns. Training one
  model across all streams mixed together would blur the benign baseline.
- Rows with count=0 (empty windows) are dropped before fitting/scoring --
  an empty window carries no timing information for these 5 features.
- contamination is an IsoForest hyperparameter = expected fraction of
  outliers in the TRAINING set. Since we train on benign-only data, this
  should be small (default 0.01) -- it mainly affects the internal
  decision threshold, not correctness.
"""

import argparse
import csv
import json
import pickle
import sys
from collections import defaultdict
from pathlib import Path

try:
    import numpy as np
    from sklearn.ensemble import IsolationForest
except ImportError:
    print("ERROR: scikit-learn / numpy not installed.\n"
          "Run: pip install scikit-learn --break-system-packages",
          file=sys.stderr)
    sys.exit(1)

FEATURE_COLS = ["mean_IAT", "IAT_variance", "mean_frame_size", "burst_length", "count"]


def load_rows(csv_path, streams):
    """streams: list of stream names to pool together into one dataset."""
    rows = []
    with open(csv_path, newline="") as f:
        for row in csv.DictReader(f):
            if row["stream"] not in streams:
                continue
            if not row["count"] or int(row["count"]) == 0:
                continue
            try:
                feat = [float(row[c]) for c in FEATURE_COLS]
            except (ValueError, TypeError):
                continue
            rows.append({
                "config": row["config"],
                "stream": row["stream"],
                "label": int(row["label"]),
                "features": feat,
            })
    return rows


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--csv", default="combined_features.csv")
    ap.add_argument("--stream", required=True,
                     help="Which stream(s) to train/score. Comma-separated "
                          "for pooling, e.g. 'av1,av2,radarNode,zonalHost,"
                          "attackNode' or just 'all' to pool every stream "
                          "in STREAMS. Pooling is recommended: attackNode "
                          "has no benign baseline on its own (it's silent "
                          "in BenignDiverse runs), and av1/av2/radar/zonal "
                          "show no attack signal on their own (their send "
                          "timing is attack-invariant) -- the discriminating "
                          "signal only appears when all streams are scored "
                          "together as one feature space per window.")
    ap.add_argument("--contamination", type=float, default=0.01)
    ap.add_argument("--n-estimators", type=int, default=100)
    ap.add_argument("--random-state", type=int, default=42)
    ap.add_argument("--score-config", default=None,
                     help="Restrict scoring to a single attack config "
                          "(e.g. GateBoundaryProximityAttack). Default: "
                          "score all attack configs found in the CSV.")
    ap.add_argument("--score-stream", default=None,
                     help="Score windows from THIS stream instead of the "
                          "training stream(s). Use this for cross-stream "
                          "mimicry tests: train on a genuine baseline "
                          "(e.g. --stream radarNode) and score the "
                          "attacker's own stream (e.g. --score-stream "
                          "attackNode) to test whether the attack's "
                          "size/timing looks anomalous against the "
                          "legitimate traffic it is imitating.")
    ap.add_argument("--threshold", type=float, default=None,
                     help="Override anomaly-score threshold (0-1). "
                          "Default: use IsoForest's own predict() (-1/1).")
    ap.add_argument("--test-split", type=float, default=0.3,
                     help="Fraction of BENIGN rows held out for a true "
                          "(not in-sample) FPR test. Default 0.3 (70/30 "
                          "train/test). Set to 0 to disable and use the "
                          "old in-sample-only behavior.")
    ap.add_argument("--split-seed", type=int, default=42,
                     help="Random seed for the benign train/test split "
                          "(separate from --random-state, which seeds the "
                          "IsolationForest itself).")
    ap.add_argument("--experiment-dir", default=None,
                     help="If set, freeze this run's inputs/outputs into "
                          "this directory: trained_model.pkl, threshold.txt, "
                          "metrics.csv, summary.txt, config.json. Prevents "
                          "overwriting results from a previous run.")
    args = ap.parse_args()

    ALL_STREAMS = ["av1", "av2", "radarNode", "zonalHost", "attackNode"]
    if args.stream.strip().lower() == "all":
        streams = ALL_STREAMS
    else:
        streams = [s.strip() for s in args.stream.split(",")]

    rows = load_rows(args.csv, streams)
    if not rows:
        print(f"No non-empty rows found for stream(s)={streams}. "
              f"Check spelling / that these streams have traffic.",
              file=sys.stderr)
        sys.exit(1)

    # Cross-stream scoring: load attack rows from a DIFFERENT stream than
    # the one we trained on (e.g. train on radarNode benign, score
    # attackNode's attack windows against that baseline).
    score_streams = [args.score_stream] if args.score_stream else streams
    if args.score_stream and args.score_stream not in streams:
        score_rows_source = load_rows(args.csv, score_streams)
    else:
        score_rows_source = rows

    benign_rows = [r for r in rows if r["label"] == 0]
    attack_rows = [r for r in score_rows_source if r["label"] != 0]
    if args.score_config:
        attack_rows = [r for r in attack_rows if r["config"] == args.score_config]

    if not benign_rows:
        print("No benign (label=0) rows found -- cannot fit IsoForest.",
              file=sys.stderr)
        sys.exit(1)
    if not attack_rows:
        print(f"No attack rows found for score-config={args.score_config} "
              f"score-stream={args.score_stream}. Check spelling.",
              file=sys.stderr)
        sys.exit(1)

    X_benign_all = np.array([r["features"] for r in benign_rows])

    # ---- Item 1: held-out benign split (not in-sample) ----
    rng = np.random.default_rng(args.split_seed)
    n_benign = len(benign_rows)
    perm = rng.permutation(n_benign)
    n_test = int(round(n_benign * args.test_split)) if args.test_split > 0 else 0
    test_idx = perm[:n_test]
    train_idx = perm[n_test:]
    X_benign_train = X_benign_all[train_idx]
    X_benign_test = X_benign_all[test_idx] if n_test > 0 else None

    print(f"Train streams (benign baseline): {streams}")
    print(f"Score streams (attack windows): {score_streams if args.score_stream else streams}")
    if args.score_config:
        print(f"Score config restricted to: {args.score_config}")
    print(f"Benign windows total: {n_benign}  "
          f"(train: {len(X_benign_train)}, held-out test: {n_test})")
    print(f"Attack windows scored: {len(attack_rows)}")
    print(f"Feature columns: {FEATURE_COLS}")
    print()

    clf = IsolationForest(
        n_estimators=args.n_estimators,
        contamination=args.contamination,
        random_state=args.random_state,
    )
    clf.fit(X_benign_train)

    # ---- False Positive Rate ----
    # In-sample (on the SAME data used to fit) -- optimistic, kept for
    # comparison so you can see the gap vs. the honest held-out number.
    insample_pred = clf.predict(X_benign_train)
    fpr_insample = float(np.mean(insample_pred == -1))
    print(f"FPR (in-sample, on training data itself): "
          f"{fpr_insample*100:.2f}%  <- optimistic, do not report this alone")

    fpr_heldout = None
    if X_benign_test is not None and len(X_benign_test) > 0:
        heldout_pred = clf.predict(X_benign_test)
        fpr_heldout = float(np.mean(heldout_pred == -1))
        print(f"FPR (held-out, n={len(X_benign_test)} unseen benign "
              f"windows): {fpr_heldout*100:.2f}%  <- report THIS in your thesis")
    else:
        print("WARNING: --test-split=0, no held-out FPR computed. "
              "Only the optimistic in-sample number is available.")
    print()

    # ---- Per-attack detection rate ----
    by_config = defaultdict(list)
    for r in attack_rows:
        by_config[r["config"]].append(r["features"])

    print(f"{'Attack Config':30s} {'n':>5s} {'Detected':>9s} {'TPR':>8s}")
    print("-" * 56)
    overall_detected = 0
    overall_total = 0
    config_results = []
    for cfg, feats in sorted(by_config.items()):
        X_atk = np.array(feats)
        pred = clf.predict(X_atk)  # -1 = anomaly = correctly flagged
        detected = int(np.sum(pred == -1))
        total = len(feats)
        tpr = detected / total if total else 0.0
        overall_detected += detected
        overall_total += total
        print(f"{cfg:30s} {total:5d} {detected:9d} {tpr*100:7.1f}%")
        config_results.append({
            "config": cfg, "n_windows": total, "detected": detected,
            "TPR_pct": round(tpr * 100, 2),
        })

    print("-" * 56)
    overall_tpr = overall_detected / overall_total if overall_total else 0.0
    print(f"{'OVERALL':30s} {overall_total:5d} {overall_detected:9d} "
          f"{overall_tpr*100:7.1f}%")

    # ---- Per-(config, stream) breakdown ----
    # Pooled TPR above is diluted by unaffected legitimate streams
    # (av1/av2/radar/zonal, whose own send timing is attack-invariant).
    # This breakdown shows WHERE detections actually land.
    by_config_stream = defaultdict(list)
    for r in attack_rows:
        by_config_stream[(r["config"], r["stream"])].append(r["features"])

    print(f"\nPer-(config, stream) breakdown "
          f"(shows whether detections concentrate on attackNode):")
    print(f"{'Config':26s} {'Stream':12s} {'n':>4s} {'Det':>4s} {'TPR':>7s}")
    print("-" * 58)
    for (cfg, stream), feats in sorted(by_config_stream.items()):
        X_atk = np.array(feats)
        pred = clf.predict(X_atk)
        detected = int(np.sum(pred == -1))
        total = len(feats)
        tpr = detected / total if total else 0.0
        print(f"{cfg:26s} {stream:12s} {total:4d} {detected:4d} {tpr*100:6.1f}%")

    print(f"\nReminder: Luo 2021's static PSFP detects 0% of these attacks")
    print(f"by design (that's the vulnerability your thesis documents).")
    print(f"Any TPR > 0% here from an UNSUPERVISED model trained only on")
    print(f"benign data is your core result.")

    # ---- Items 2 & 3: save model + freeze experiment ----
    if args.experiment_dir:
        exp_dir = Path(args.experiment_dir)
        exp_dir.mkdir(parents=True, exist_ok=True)

        # Item 2: trained model + everything needed to reuse it later
        # (LSTM pipeline, inference) without re-deriving choices from memory.
        with open(exp_dir / "trained_model.pkl", "wb") as f:
            pickle.dump(clf, f)

        model_meta = {
            "feature_order": FEATURE_COLS,
            "train_streams": streams,
            "score_streams": score_streams if args.score_stream else streams,
            "score_config_filter": args.score_config,
            "contamination": args.contamination,
            "n_estimators": args.n_estimators,
            "random_state": args.random_state,
            "split_seed": args.split_seed,
            "test_split_fraction": args.test_split,
            "n_benign_train": int(len(X_benign_train)),
            "n_benign_heldout_test": int(n_test),
            "fpr_insample_pct": round(fpr_insample * 100, 3),
            "fpr_heldout_pct": (round(fpr_heldout * 100, 3)
                                 if fpr_heldout is not None else None),
            "isoforest_offset_": float(clf.offset_),
        }
        with open(exp_dir / "config.json", "w") as f:
            json.dump(model_meta, f, indent=2)

        (exp_dir / "threshold.txt").write_text(
            f"isoforest_offset_={clf.offset_}\n"
            f"contamination={args.contamination}\n"
            f"(scoring rule: score_samples(x) < offset_  =>  flagged anomalous)\n"
        )

        # Item 3: freeze metrics as CSV
        with open(exp_dir / "metrics.csv", "w", newline="") as f:
            fieldnames = ["config", "n_windows", "detected", "TPR_pct"]
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(config_results)
            writer.writerow({
                "config": "OVERALL", "n_windows": overall_total,
                "detected": overall_detected,
                "TPR_pct": round(overall_tpr * 100, 2),
            })

        # Item 3: human-readable summary
        summary_lines = [
            "ISOLATION FOREST -- FROZEN EXPERIMENT SUMMARY",
            f"Train streams: {streams}",
            f"Score streams: {score_streams if args.score_stream else streams}",
            f"Score config filter: {args.score_config}",
            f"Contamination: {args.contamination}",
            f"Benign train / held-out test: {len(X_benign_train)} / {n_test}",
            f"FPR (in-sample, optimistic): {fpr_insample*100:.2f}%",
            f"FPR (held-out, REPORT THIS): "
            f"{fpr_heldout*100:.2f}%" if fpr_heldout is not None else
            "FPR (held-out): N/A (--test-split=0)",
            "",
            f"{'Config':30s} {'n':>5s} {'Det':>5s} {'TPR%':>7s}",
        ]
        for r in config_results:
            summary_lines.append(
                f"{r['config']:30s} {r['n_windows']:5d} {r['detected']:5d} "
                f"{r['TPR_pct']:7.2f}"
            )
        summary_lines.append(
            f"{'OVERALL':30s} {overall_total:5d} {overall_detected:5d} "
            f"{overall_tpr*100:7.2f}"
        )
        (exp_dir / "summary.txt").write_text("\n".join(summary_lines))

        # Copy the exact CSV used, so this experiment is fully self-contained
        import shutil
        try:
            shutil.copy(args.csv, exp_dir / "combined_features.csv")
        except shutil.SameFileError:
            pass

        print(f"\nExperiment frozen to: {exp_dir}/")
        print(f"  trained_model.pkl, config.json, threshold.txt,")
        print(f"  metrics.csv, summary.txt, combined_features.csv")


if __name__ == "__main__":
    main()
