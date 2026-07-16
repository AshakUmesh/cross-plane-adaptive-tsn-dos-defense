#!/usr/bin/env python3
"""
train_random_forest.py

Standalone Random Forest training script -- the offline, supervised
attack-classification counterpart to train_isoforest.py's unsupervised
anomaly detection. Mirrors train_isoforest.py's structure (held-out
split, experiment freezing) so the two are directly comparable.

ROLE IN ARCHITECTURE:

    Historical labelled data
            |
            v
    Random Forest (offline)   <-- THIS SCRIPT
            |
    Learns attack patterns/severity
            |
            v
    (feature_importances_ + per-attack recall feed
     rf_calibrates_isoforest.py, which updates IsoForest's
     feature set and per-attack threshold recommendations)

Usage:
    python3 train_random_forest.py --csv combined_features_multiclass.csv \
        --stream all --experiment-dir experiments/random_forest

    python3 train_random_forest.py --csv combined_features_multiclass.csv \
        --stream attackNode --n-estimators 300 --experiment-dir experiments/rf_v2
"""

import argparse
import csv
import json
import pickle
import sys
from pathlib import Path

try:
    import numpy as np
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.model_selection import train_test_split, cross_val_score, StratifiedKFold
    from sklearn.metrics import classification_report, confusion_matrix
except ImportError:
    print("ERROR: pip install scikit-learn numpy", file=sys.stderr)
    sys.exit(1)

FEATURE_COLS = ["mean_IAT", "IAT_variance", "mean_frame_size", "burst_length", "count"]


def load_rows(csv_path, streams):
    X, y, configs = [], [], []
    with open(csv_path, newline="") as f:
        for row in csv.DictReader(f):
            if row["stream"] not in streams:
                continue
            if not row["count"] or int(row["count"]) == 0:
                continue
            try:
                feat = [float(row[c]) for c in FEATURE_COLS]
                label = int(row["label"])
            except (ValueError, TypeError):
                continue
            X.append(feat)
            y.append(label)
            configs.append(row["config"])
    return np.array(X), np.array(y), configs


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--csv", default="combined_features_multiclass.csv")
    ap.add_argument("--stream", default="all",
                     help="Comma-separated streams, or 'all'")
    ap.add_argument("--n-estimators", type=int, default=200)
    ap.add_argument("--test-split", type=float, default=0.3,
                     help="Held-out fraction for the reported test accuracy "
                          "(mirrors train_isoforest.py's held-out FPR split)")
    ap.add_argument("--cv-folds", type=int, default=5,
                     help="Also report k-fold CV accuracy (more reliable "
                          "than a single split at small sample sizes -- "
                          "see Chapter 8 S8.5)")
    ap.add_argument("--random-state", type=int, default=42)
    ap.add_argument("--experiment-dir", default=None,
                     help="If set, freeze model + metrics + report here")
    args = ap.parse_args()

    ALL_STREAMS = ["av1", "av2", "radarNode", "zonalHost", "attackNode"]
    streams = ALL_STREAMS if args.stream.lower() == "all" else \
        [s.strip() for s in args.stream.split(",")]

    X, y, configs = load_rows(args.csv, streams)
    if len(X) == 0:
        print(f"No rows found for streams={streams}. Check --stream / --csv.",
              file=sys.stderr)
        sys.exit(1)

    label_names = {0: "Benign"}
    for cfg, lbl in zip(configs, y):
        if lbl != 0:
            label_names[int(lbl)] = cfg

    class_counts = {label_names.get(int(l), str(l)): int(c)
                     for l, c in zip(*np.unique(y, return_counts=True))}

    print(f"Streams: {streams}")
    print(f"Total windows: {len(X)}")
    print(f"Classes: {label_names}")
    print(f"Class distribution: {class_counts}\n")

    # ---- Held-out split (mirrors train_isoforest.py's evaluation protocol) ----
    counts = np.bincount(y)
    stratify = y if min(counts[counts > 0]) >= 2 else None
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=args.test_split, random_state=args.random_state,
        stratify=stratify,
    )
    print(f"Train: {len(X_train)}  Held-out test: {len(X_test)}\n")

    rf = RandomForestClassifier(
        n_estimators=args.n_estimators,
        random_state=args.random_state,
        class_weight="balanced",
    )
    rf.fit(X_train, y_train)

    pred = rf.predict(X_test)
    test_acc = float(np.mean(pred == y_test))
    print(f"Held-out test accuracy: {test_acc*100:.2f}%\n")

    present_labels = sorted(set(y_test.tolist()) | set(pred.tolist()))
    print(classification_report(
        y_test, pred,
        labels=present_labels,
        target_names=[label_names.get(l, str(l)) for l in present_labels],
        zero_division=0,
    ))

    cm = confusion_matrix(y_test, pred, labels=present_labels)
    print("Confusion matrix (rows=true, cols=predicted):")
    print(f"  labels: {[label_names.get(l, str(l)) for l in present_labels]}")
    print(cm)

    # ---- k-fold CV: more reliable estimate given small per-class samples ----
    print(f"\n{args.cv_folds}-fold cross-validation (more reliable than a "
          f"single split at this sample size -- see Chapter 8 S8.5):")
    min_class_count = min(counts[counts > 0])
    n_splits = min(args.cv_folds, min_class_count)
    if n_splits < 2:
        print("  Skipped -- smallest class has <2 samples, CV not meaningful.")
        cv_mean, cv_std, cv_scores = None, None, []
    else:
        cv = StratifiedKFold(n_splits=n_splits, shuffle=True,
                              random_state=args.random_state)
        cv_scores = cross_val_score(
            RandomForestClassifier(n_estimators=args.n_estimators,
                                    random_state=args.random_state,
                                    class_weight="balanced"),
            X, y, cv=cv, scoring="accuracy",
        )
        cv_mean, cv_std = float(cv_scores.mean()), float(cv_scores.std())
        print(f"  {n_splits}-fold: {cv_mean*100:.1f}% +/- {cv_std*100:.1f}%  "
              f"(folds: {[round(s*100,1) for s in cv_scores]})")

    # ---- Feature importances (this is what feeds rf_calibrates_isoforest.py) ----
    importances = dict(zip(FEATURE_COLS, rf.feature_importances_.tolist()))
    print(f"\nFeature importances (learned attack patterns -- feeds "
          f"rf_calibrates_isoforest.py's IsoForest feature selection):")
    for f, imp in sorted(importances.items(), key=lambda x: -x[1]):
        print(f"  {f:20s} {imp:.4f}")

    # ---- Save ----
    if args.experiment_dir:
        out = Path(args.experiment_dir)
        out.mkdir(parents=True, exist_ok=True)

        with open(out / "random_forest.pkl", "wb") as f:
            pickle.dump(rf, f)

        report = {
            "streams": streams,
            "n_estimators": args.n_estimators,
            "test_split_fraction": args.test_split,
            "n_train": int(len(X_train)),
            "n_test": int(len(X_test)),
            "held_out_test_accuracy": round(test_acc, 4),
            "cv_folds": n_splits if n_splits >= 2 else None,
            "cv_mean_accuracy": round(cv_mean, 4) if cv_mean is not None else None,
            "cv_std_accuracy": round(cv_std, 4) if cv_std is not None else None,
            "feature_importances": importances,
            "label_names": {str(k): v for k, v in label_names.items()},
            "class_distribution": class_counts,
        }
        with open(out / "rf_report.json", "w") as f:
            json.dump(report, f, indent=2, default=str)

        summary_lines = [
            "RANDOM FOREST -- FROZEN EXPERIMENT SUMMARY",
            f"Streams: {streams}",
            f"Train/Test: {len(X_train)}/{len(X_test)}",
            f"Held-out test accuracy: {test_acc*100:.2f}%",
        ]
        if cv_mean is not None:
            summary_lines.append(
                f"{n_splits}-fold CV accuracy: {cv_mean*100:.1f}% +/- {cv_std*100:.1f}%"
            )
        summary_lines.append("\nFeature importances:")
        for f, imp in sorted(importances.items(), key=lambda x: -x[1]):
            summary_lines.append(f"  {f:20s} {imp:.4f}")
        (out / "summary.txt").write_text("\n".join(summary_lines))

        print(f"\nSaved: {out}/random_forest.pkl, rf_report.json, summary.txt")


if __name__ == "__main__":
    main()
