#!/bin/bash
# ==============================================================================
# run_complete_pipeline.sh
#
# End-to-end runner for the Cross-Plane Adaptive DoS Defence pipeline.
# Assembled from the exact stage commands verified earlier in this project
# (see todolist.txt) — NOT guessed. Run once before every presentation or
# thesis-data refresh so every table in the thesis/slides traces back to a
# single reproducible command.
#
# IMPORTANT — one unverified spot:
#   Step 4 (run_full_pipeline_demo.py) needs the exact paths to your trained
#   Isolation Forest and Random Forest model files. The RL artifact paths
#   (experiments/rl_agent/q_table.npy, rl_report.json) were confirmed; the
#   IsoForest/RF model file locations were not. Check the --isoforest-model
#   and --rf-model paths below against your repo before relying on this
#   script unattended.
#
# Usage:
#   chmod +x run_complete_pipeline.sh
#   ./run_complete_pipeline.sh            # baseline batch
#   ./run_complete_pipeline.sh --adaptive # adaptive batch (run_adaptive_batch.sh)
# ==============================================================================

set -e  # stop on first failure — better to fail loudly than silently skip a stage

MODE="baseline"
if [ "$1" == "--adaptive" ]; then
  MODE="adaptive"
fi

RESULTS_DIR="results"
mkdir -p "$RESULTS_DIR"

echo "=============================================="
echo "0. Mode: $MODE"
echo "=============================================="

echo "=============================================="
echo "1. OMNeT++ Simulation Batch"
echo "=============================================="
if [ "$MODE" == "adaptive" ]; then
  ./run_adaptive_batch.sh
else
  ./run_and_extract_batch3.sh
fi

echo "=============================================="
echo "2. Feature Extraction"
echo "=============================================="
python3 ml/pipeline/combined_feature_extractor.py
# Expected output: combined_features_multiclass.csv

echo "=============================================="
echo "3. Train Isolation Forest (Stage 1)"
echo "=============================================="
python3 ml/pipeline/train_isoforest.py
# Expected output: experiments/isoforest/isoforest.joblib, threshold.json
cp experiments/isoforest/*.json "$RESULTS_DIR/IsoForest_Report.json" 2>/dev/null || true

echo "=============================================="
echo "4. Train Random Forest (Stage 2)"
echo "=============================================="
python3 ml/pipeline/train_random_forest.py
# Expected output: experiments/random_forest/random_forest.joblib, rf_report.json
cp experiments/random_forest/rf_report.json "$RESULTS_DIR/RF_Report.json" 2>/dev/null || true

echo "=============================================="
echo "5. Two-Tier Detection (IsoForest -> suspicious-only -> Random Forest)"
echo "=============================================="
python3 ml/pipeline/two_tier_pipeline.py

echo "=============================================="
echo "6. Full Inference: IsoForest -> RF -> Policy"
echo "=============================================="
# NOTE: verify these four model/report paths against your repo (see header note above)
python3 ml/pipeline/run_full_pipeline_demo.py \
    --csv combined_features_multiclass.csv \
    --isoforest-model experiments/isoforest/isoforest.joblib \
    --isoforest-threshold experiments/isoforest/threshold.json \
    --rf-model experiments/random_forest/random_forest.joblib \
    --rf-report experiments/random_forest/rf_report.json \
    --rl-qtable experiments/rl_agent/q_table.npy \
    --rl-report experiments/rl_agent/rl_report.json
cp experiments/random_forest/rf_report.json "$RESULTS_DIR/Policy_Report.json" 2>/dev/null || true

echo "=============================================="
echo "7. Closed-Loop Adaptive PSFP (generate config -> re-run OMNeT++)"
echo "=============================================="
python3 closed_loop_runner.py
cp Adaptive_PSFP.csv "$RESULTS_DIR/Adaptive_PSFP.csv" 2>/dev/null || true

echo "=============================================="
echo "8. Compute Rewards"
echo "=============================================="
python3 compute_real_rewards.py
cp real_rewards.csv "$RESULTS_DIR/Reward_Report.csv" 2>/dev/null || true

echo "=============================================="
echo "9. RL Agent (offline training / recommendation)"
echo "=============================================="
python3 ml/pipeline/train_rl_agent.py
cp experiments/rl_agent/rl_report.json "$RESULTS_DIR/RL_Report.json" 2>/dev/null || true

echo "=============================================="
echo "10. Assemble Master Results"
echo "=============================================="
python3 - <<'PYEOF'
import json, csv, os

results_dir = "results"
master_path = os.path.join(results_dir, "Master_Results.csv")

rows = []
rows.append(["stage", "output_file", "present"])
for fname in ["IsoForest_Report.json", "RF_Report.json", "Policy_Report.json",
              "Adaptive_PSFP.csv", "Reward_Report.csv", "RL_Report.json"]:
    path = os.path.join(results_dir, fname)
    rows.append([fname.split("_Report")[0].split(".")[0], fname, os.path.exists(path)])

with open(master_path, "w", newline="") as f:
    csv.writer(f).writerows(rows)

print(f"Wrote {master_path}")
PYEOF

echo "=============================================="
echo "Pipeline Completed"
echo "Results in ./$RESULTS_DIR/"
echo "  IsoForest_Report.json"
echo "  RF_Report.json"
echo "  Policy_Report.json"
echo "  Adaptive_PSFP.csv"
echo "  Reward_Report.csv"
echo "  RL_Report.json"
echo "  Master_Results.csv"
echo "=============================================="
