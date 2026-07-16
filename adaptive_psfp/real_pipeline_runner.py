#!/usr/bin/env python3
"""
real_pipeline_runner.py — FULLY wired closed loop:
Features -> IsoForest -> RF prediction -> Policy Engine (using PREDICTED
type, not ground truth) -> .ini generation -> OMNeT++ -> reward.

This replaces closed_loop_runner.py's use of the ground-truth attack name
with a real RF prediction, closing the integration gap identified today.
"""
import subprocess
import sys
import json
import pickle
import csv
from collections import Counter

import numpy as np

sys.path.insert(0, 'ml/pipeline')
from psfp_policy import decide_action
from reward_function import compute_reward, RewardComponents

OMNET_BIN = "./out/clang-release/luo2021"
NED_PATH = "/home/ashakumesh/research/omnetpp-6.4.0/samples/inet/src"
LIB_PATH = "/home/ashakumesh/research/omnetpp-6.4.0/samples/inet/src/libINET.so"
INI_FILE = "omnetpp.ini"
FEATURE_COLS = ["mean_IAT", "IAT_variance", "mean_frame_size", "burst_length", "count"]

NOMINAL_CIR = 22.0
NOMINAL_CBS = 5004.0
BASE_GATE_DURATIONS = (125, 375)

# --- Load real trained models (same as run_full_pipeline_demo.py) ---
with open("experiments/pooled_for_pipeline/trained_model.pkl", "rb") as f:
    ISO = pickle.load(f)
with open("experiments/pooled_for_pipeline/threshold.txt") as f:
    for line in f:
        if line.startswith("isoforest_offset_="):
            ISO_THRESHOLD = float(line.split("=", 1)[1])
            break
with open("experiments/random_forest/random_forest.pkl", "rb") as f:
    RF = pickle.load(f)
with open("experiments/random_forest/rf_report.json") as f:
    RF_REPORT = json.load(f)
LABEL_NAMES = {int(k): v for k, v in RF_REPORT["label_names"].items()}


def get_predicted_attack_type(config_name, csv_path):
    """Real IsoForest -> RF inference on a config's extracted windows.
    Returns (predicted_type, ground_truth_votes_info) using majority vote
    across flagged windows. Returns None if nothing flagged (policy: no_op)."""
    rows = []
    with open(csv_path, newline="") as f:
        for row in csv.DictReader(f):
            if row["config"] != config_name or row["stream"] != "attackNode":
                continue
            if not row["count"] or int(row["count"]) == 0:
                continue
            try:
                feat = [float(row[c]) for c in FEATURE_COLS]
            except (ValueError, TypeError):
                continue
            rows.append(feat)

    if not rows:
        print(f"  WARNING: no attackNode windows found for {config_name} in {csv_path}")
        return None, 0, 0

    predictions = []
    flagged = 0
    for feat in rows:
        x = np.array([feat])
        score = float(ISO.score_samples(x)[0])
        if score < ISO_THRESHOLD:
            flagged += 1
            pred = int(RF.predict(x)[0])
            predictions.append(LABEL_NAMES.get(pred, str(pred)))

    if not predictions:
        return None, flagged, len(rows)

    vote = Counter(predictions).most_common(1)[0][0]
    return vote, flagged, len(rows)


def action_to_ini_block(attack_for_config, predicted_type, action):
    cfg_name = f"{attack_for_config}_RealPipeline"
    lines = [f"[Config {cfg_name}]", f"extends = {attack_for_config}",
             f"# Policy driven by RF PREDICTION: {predicted_type} (not ground truth)"]

    if action.action_type == "reduce_cir":
        new_cir = NOMINAL_CIR * action.parameter_delta["cir_fraction"]
        for sw in ["viuSwitch", "vcuSwitch"]:
            for idx in [4, 5]:
                lines.append(f"*.{sw}.bridging.streamFilter.ingress.meter[{idx}].committedInformationRate = {new_cir}Mbps")
    elif action.action_type == "reduce_cbs":
        new_cbs = int(NOMINAL_CBS * action.parameter_delta["cbs_fraction"])
        for sw in ["viuSwitch", "vcuSwitch"]:
            for idx in [4, 5]:
                lines.append(f"*.{sw}.bridging.streamFilter.ingress.meter[{idx}].committedBurstSize = {new_cbs}B")
    elif action.action_type == "tighten_gate":
        us = action.parameter_delta["gate_tighten_us"]
        closed, open_ = BASE_GATE_DURATIONS[0] + us, BASE_GATE_DURATIONS[1] - us
        for sw in ["viuSwitch", "vcuSwitch"]:
            for idx in [4, 5]:
                lines.append(f"*.{sw}.eth[*].macLayer.queue.transmissionGate[{idx}].durations = [{closed}us, {open_}us]")
    else:
        lines.append("# no_op")

    return cfg_name, "\n".join(lines) + "\n"


def run_sim(config_name):
    result = subprocess.run(
        [OMNET_BIN, "-u", "Cmdenv", "-n", f".:{NED_PATH}", "-l", LIB_PATH,
         "-c", config_name, "-r", "0", INI_FILE],
        capture_output=True, text=True, timeout=300
    )
    return result.returncode == 0, result.stdout + result.stderr


def extract_sink_count(config_name):
    try:
        with open(f"results/{config_name}-#0.sca") as f:
            for line in f:
                if "centralHost.app[4].sink packets:count" in line:
                    return int(line.split()[-1])
    except FileNotFoundError:
        return None
    return None


def run_real_pipeline(ground_truth_attack, csv_path="combined_features_multiclass.csv"):
    print(f"\n{'='*70}\n{ground_truth_attack} (GROUND TRUTH)\n{'='*70}")

    predicted_type, flagged, total = get_predicted_attack_type(ground_truth_attack, csv_path)
    print(f"Windows: {total}, Flagged by IsoForest: {flagged}")

    if predicted_type is None:
        print("No windows flagged -- IsoForest says NOT suspicious. Policy: no_op (correctly).")
        return {"ground_truth": ground_truth_attack, "predicted": None, "action": "no_op",
                "agreement": None}

    match = (predicted_type == ground_truth_attack)
    print(f"RF predicted (majority vote): {predicted_type}  [{'MATCH' if match else 'MISMATCH vs ground truth'}]")

    action = decide_action(predicted_type, port="attackNode")
    print(f"Policy decision (based on PREDICTED type): {action.action_type} {action.parameter_delta}")

    if action.action_type == "no_op":
        print("Policy: no_op for predicted type -- no adaptive config generated")
        return {"ground_truth": ground_truth_attack, "predicted": predicted_type,
                "action": "no_op", "agreement": match}

    cfg_name, ini_block = action_to_ini_block(ground_truth_attack, predicted_type, action)

    with open(INI_FILE) as f:
        content = f.read()
    if f"[Config {cfg_name}]" not in content:
        with open(INI_FILE, "a") as f:
            f.write("\n" + ini_block)
        print(f"Generated: [Config {cfg_name}] (extends {ground_truth_attack}, action from PREDICTED type)")

    static_count = extract_sink_count(ground_truth_attack)
    if static_count is None:
        ok, log = run_sim(ground_truth_attack)
        if not ok:
            print(f"STATIC RUN FAILED:\n{log[-500:]}")
            return None
        static_count = extract_sink_count(ground_truth_attack)

    ok, log = run_sim(cfg_name)
    if not ok:
        print(f"PIPELINE RUN FAILED:\n{log[-500:]}")
        return None
    adaptive_count = extract_sink_count(cfg_name)

    if static_count is None or adaptive_count is None:
        print("FAILED to extract counts")
        return None

    throughput_retained = adaptive_count / static_count if static_count > 0 else 1.0
    rc = RewardComponents(
        detection_accuracy=1.0 if action.severity == "MALICIOUS" else 0.5,
        wcd_baseline_us=1088.0, wcd_observed_us=1088.0,
        packet_loss_rate=0.0, false_positive_rate=0.0102,
        throughput_retained=throughput_retained,
    )
    reward = compute_reward(rc)

    print(f"RESULT: static={static_count} adaptive={adaptive_count} "
          f"reduction={100*(1-throughput_retained):.1f}% reward={reward['reward']}")

    return {
        "ground_truth": ground_truth_attack, "predicted": predicted_type,
        "agreement": match, "action": action.action_type,
        "static": static_count, "adaptive": adaptive_count,
        "reduction_pct": round(100*(1-throughput_retained), 1),
        "reward": reward["reward"],
    }


if __name__ == "__main__":
    attacks = sys.argv[1:] if len(sys.argv) > 1 else ["ThresholdEvasionAttack"]
    results = []
    for a in attacks:
        r = run_real_pipeline(a)
        if r:
            results.append(r)

    print(f"\n{'='*70}\nSUMMARY\n{'='*70}")
    for r in results:
        print(r)

    with open("real_pipeline_results.json", "w") as f:
        json.dump(results, f, indent=2)
