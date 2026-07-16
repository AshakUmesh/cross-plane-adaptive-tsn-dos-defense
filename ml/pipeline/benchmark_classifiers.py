#!/usr/bin/env python3
"""
benchmark_classifiers.py

Benchmarks multiple classifiers on the SAME tabular feature set
(mean_IAT, IAT_variance, mean_frame_size, burst_length, count) to answer:
"which classifier best fits this TSN feature representation?" -- rather
than assuming LSTM (built for sequences) is the right choice for
single-window tabular statistics.

Trains: RandomForest, XGBoost (if installed), SVM (RBF kernel).
Reports: accuracy, macro-F1, per-class precision/recall, confusion matrix,
and (for RF/XGBoost) feature importances.

Usage:
    python3 benchmark_classifiers.py --csv combined_features_multiclass.csv \
        --stream attackNode --out-dir experiments/classifier_benchmark

Notes:
- Filters to rows where count > 0 (same convention as train_isoforest.py).
- If --stream is not attackNode-only, benign windows (label=0) from
  legitimate streams will dominate the "benign" class -- that's fine for
  this classification task (attack-vs-attack-type + benign).
- Stratified 70/30 train/test split with a fixed seed for reproducibility.
"""

import argparse
import csv
import json
import pickle
import sys
from pathlib import Path

try:
    import numpy as np
    from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
    from sklearn.svm import SVC
    from sklearn.model_selection import train_test_split, cross_val_score, StratifiedKFold
    from sklearn.metrics import (
        accuracy_score, f1_score, classification_report, confusion_matrix
    )
except ImportError:
    print("ERROR: scikit-learn / numpy not installed.\n"
          "Run: pip install scikit-learn", file=sys.stderr)
    sys.exit(1)

try:
    import xgboost as xgb
    HAS_XGB = True
except ImportError:
    HAS_XGB = False

try:
    import lightgbm as lgb
    HAS_LGB = True
except ImportError:
    HAS_LGB = False

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


def run_model(name, clf, X_train, y_train, X_test, y_test, label_names):
    clf.fit(X_train, y_train)
    pred = clf.predict(X_test)
    acc = accuracy_score(y_test, pred)
    f1 = f1_score(y_test, pred, average="macro", zero_division=0)
    report = classification_report(
        y_test, pred, target_names=[label_names.get(l, str(l))
                                     for l in sorted(set(y_test) | set(pred))],
        zero_division=0, output_dict=True
    )
    cm = confusion_matrix(y_test, pred)
    print(f"\n{'='*60}\n{name}\n{'='*60}")
    print(f"Accuracy : {acc*100:.2f}%")
    print(f"Macro-F1 : {f1*100:.2f}%")
    print(classification_report(
        y_test, pred,
        target_names=[label_names.get(l, str(l)) for l in sorted(set(y_test) | set(pred))],
        zero_division=0
    ))
    importances = None
    if hasattr(clf, "feature_importances_"):
        importances = dict(zip(FEATURE_COLS, clf.feature_importances_.tolist()))
        print("Feature importances:")
        for k, v in sorted(importances.items(), key=lambda x: -x[1]):
            print(f"  {k:20s} {v:.4f}")
    return {
        "name": name, "accuracy": acc, "macro_f1": f1,
        "report": report, "confusion_matrix": cm.tolist(),
        "feature_importances": importances,
    }, clf


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--csv", default="combined_features_multiclass.csv")
    ap.add_argument("--stream", default="attackNode",
                     help="Comma-separated streams, or 'all'. Default "
                          "attackNode (where the labelled attack signal "
                          "actually lives -- see Chapter 8 §8.2).")
    ap.add_argument("--test-size", type=float, default=0.3)
    ap.add_argument("--random-state", type=int, default=42)
    ap.add_argument("--out-dir", default=None)
    args = ap.parse_args()

    ALL_STREAMS = ["av1", "av2", "radarNode", "zonalHost", "attackNode"]
    streams = ALL_STREAMS if args.stream.lower() == "all" else \
        [s.strip() for s in args.stream.split(",")]

    X, y, configs = load_rows(args.csv, streams)
    if len(X) == 0:
        print(f"No rows found for streams={streams}", file=sys.stderr)
        sys.exit(1)

    label_names = {0: "Benign"}
    for cfg, lbl in zip(configs, y):
        if lbl != 0:
            label_names[int(lbl)] = cfg

    print(f"Streams: {streams}")
    print(f"Total windows: {len(X)}")
    print(f"Classes: {label_names}")
    unique, counts = np.unique(y, return_counts=True)
    print(f"Class distribution: {dict(zip(unique.tolist(), counts.tolist()))}")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=args.test_size, random_state=args.random_state,
        stratify=y if min(counts) >= 2 else None,
    )
    print(f"\nTrain: {len(X_train)}  Test: {len(X_test)}")

    results = []
    models = {}

    r, clf = run_model(
        "Random Forest",
        RandomForestClassifier(n_estimators=200, random_state=args.random_state,
                                class_weight="balanced"),
        X_train, y_train, X_test, y_test, label_names,
    )
    results.append(r); models["random_forest"] = clf

    if HAS_XGB:
        # xgboost needs 0-indexed contiguous labels
        classes_sorted = sorted(set(y))
        remap = {c: i for i, c in enumerate(classes_sorted)}
        inv_remap = {i: c for c, i in remap.items()}
        y_train_x = np.array([remap[v] for v in y_train])
        y_test_x = np.array([remap[v] for v in y_test])
        label_names_x = {i: label_names.get(inv_remap[i], str(inv_remap[i]))
                          for i in inv_remap}
        r, clf = run_model(
            "XGBoost",
            xgb.XGBClassifier(n_estimators=200, random_state=args.random_state,
                               eval_metric="mlogloss"),
            X_train, y_train_x, X_test, y_test_x, label_names_x,
        )
        results.append(r); models["xgboost"] = clf
    else:
        print(f"\n{'='*60}\nXGBoost not installed -- skipping.")
        print(f"Install with: pip install xgboost\n{'='*60}")

    r, clf = run_model(
        "SVM (RBF)",
        SVC(kernel="rbf", class_weight="balanced", random_state=args.random_state),
        X_train, y_train, X_test, y_test, label_names,
    )
    results.append(r); models["svm"] = clf

    print(f"\n{'='*60}\nSUMMARY (single 70/30 split) -- see 5-fold CV below for the")
    print(f"more reliable comparison given small per-class sample size")
    print(f"{'='*60}")
    print(f"{'Model':20s} {'Accuracy':>10s} {'Macro-F1':>10s}")
    for r in sorted(results, key=lambda x: -x["accuracy"]):
        print(f"{r['name']:20s} {r['accuracy']*100:9.2f}% {r['macro_f1']*100:9.2f}%")

    # ---- 5-fold cross-validation: the reliable comparison ----
    # A single 70/30 split is noisy with only ~14 samples/class (test
    # folds of 4-5 samples flip a class's score by 20-25 points on one
    # misclassification). 5-fold CV gives mean +/- std across folds,
    # which is what should actually be reported/compared in the thesis.
    print(f"\n{'='*60}\n5-FOLD CROSS-VALIDATION (the reliable comparison)\n{'='*60}")
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=args.random_state)
    cv_models = {
        "Random Forest": RandomForestClassifier(
            n_estimators=200, random_state=args.random_state, class_weight="balanced"),
        "Gradient Boosting": GradientBoostingClassifier(random_state=args.random_state),
        "SVM (RBF)": SVC(kernel="rbf", class_weight="balanced", random_state=args.random_state),
    }
    if HAS_XGB:
        classes_sorted = sorted(set(y))
        remap = {c: i for i, c in enumerate(classes_sorted)}
        y_remapped = np.array([remap[v] for v in y])
        cv_models["XGBoost"] = (xgb.XGBClassifier(
            n_estimators=200, random_state=args.random_state, eval_metric="mlogloss"), y_remapped)
    else:
        print("(XGBoost not installed -- pip install xgboost to include it)")
    if HAS_LGB:
        cv_models["LightGBM"] = (lgb.LGBMClassifier(
            n_estimators=200, random_state=args.random_state, verbose=-1), y)
    else:
        print("(LightGBM not installed -- pip install lightgbm to include it)")

    cv_results = []
    for name, entry in cv_models.items():
        clf_cv, y_use = entry if isinstance(entry, tuple) else (entry, y)
        scores = cross_val_score(clf_cv, X, y_use, cv=cv, scoring="accuracy")
        cv_results.append((name, scores.mean(), scores.std(), scores))
        print(f"{name:20s} {scores.mean()*100:6.1f}% +/- {scores.std()*100:5.1f}%  "
              f"(folds: {[round(s*100,1) for s in scores]})")

    print(f"\n{'='*60}\nRECOMMENDATION\n{'='*60}")
    best = max(cv_results, key=lambda r: r[1] - r[2])  # favor high mean, low variance
    print(f"Best (mean accuracy, penalized for instability): {best[0]}  "
          f"({best[1]*100:.1f}% +/- {best[2]*100:.1f}%)")
    print(f"Selection criterion: highest 5-fold mean accuracy adjusted for")
    print(f"fold-to-fold variance (a high-mean/high-variance model, like SVM")
    print(f"in earlier runs, is less trustworthy on this small a dataset than")
    print(f"a slightly-lower-mean/low-variance model).")

    if args.out_dir:
        out = Path(args.out_dir)
        out.mkdir(parents=True, exist_ok=True)
        for mname, clf in models.items():
            with open(out / f"{mname}.pkl", "wb") as f:
                pickle.dump(clf, f)
        summary = {
            "streams": streams, "label_names": label_names,
            "results": [{k: v for k, v in r.items() if k != "report"}
                        for r in results],
        }
        with open(out / "benchmark_summary.json", "w") as f:
            json.dump(summary, f, indent=2, default=str)
        print(f"\nSaved models + summary to: {out}/")


if __name__ == "__main__":
    main()
