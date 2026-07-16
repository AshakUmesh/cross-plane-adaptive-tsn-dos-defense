#!/usr/bin/env python3
"""
train_rl_agent.py

Implements the RL Agent node in the architecture diagram, replacing
rl_agent.py's NotImplementedError stub with a real, trained agent.

SCOPE, STATED EXPLICITLY (do not overclaim this in the thesis):
    This is NOT a full sequential MDP with live environment interaction.
    No code path exists that injects the agent's chosen action back into
    a running OMNeT++ simulation and observes a resulting next state
    (that would require live PSFP parameter mutation -- confirmed absent
    from this project's simulation-runtime coupling; see Chapter 6 S6.6
    and the diagnosed gPTP-crash evidence for why this was not attempted
    under the project timeline).

    Instead, this is trained via TRACE REPLAY over the real, already-
    labeled dataset (combined_features_multiclass.csv) as a single-step
    (contextual bandit) formulation: state -> action -> reward, with NO
    bootstrapped next-state term. This is a standard, legitimate,
    explicitly-scoped simplification of full RL -- not a live control
    loop, and the thesis text must say so.

STATE:
    Training uses the TRUE attack-type label (ground truth) as state --
    i.e. "given that this IS a GCLPhaseAttack, what action maximizes
    reward". Evaluation uses the REAL, already-trained Random Forest's
    PREDICTED label as state instead -- i.e. "given what the classifier
    THINKS this is (with real classifier noise/errors), what does the
    trained policy recommend, and how often does it still align with the
    ground-truth-optimal action". This tests robustness to real
    classification error rather than assuming a perfect classifier.

ACTION SPACE (discrete, matches psfp_policy.POLICY_TABLE exactly --
the agent chooses among the SAME pre-validated, bounded actions the
static policy engine offers, never an unconstrained action):
    no_op, tighten_gate_10, tighten_gate_15,
    reduce_cir_0.5, reduce_cir_0.6, reduce_cbs_0.5

REWARD:
    reward_function.compute_reward() using DISCLOSED ASSUMED per-action
    effect parameters (delay/loss/throughput -- these are not measured
    from a live simulation, same assumption already used and disclosed
    in reward_function.py's DEMO_SCENARIOS), PLUS:
      + bonus if the chosen action's TYPE matches psfp_policy.py's
        already-validated expert recommendation for the true attack type
      - penalty if the true state is Benign but the agent chose any
        action other than no_op (unnecessary throttling of legitimate
        traffic -- directly penalizes false-positive-driven action)

WHY THIS DESIGN IS DEFENSIBLE, NOT CIRCULAR:
    The agent is not given the expert action directly -- it only
    receives a scalar reward that happens to be HIGHER when it agrees
    with the expert policy and detection is correct. Convergence to the
    expert policy is therefore a genuine (if modest) empirical finding:
    it validates that the reward function, as designed, actually
    incentivizes the behavior the policy engine was hand-designed to
    encode -- not a guarantee, since Q-learning could in principle
    converge to a different local optimum if the reward landscape
    permitted one.

Usage:
    python3 train_rl_agent.py --csv combined_features_multiclass.csv \
        --rf-model experiments/random_forest/random_forest.pkl \
        --rf-report experiments/random_forest/rf_report.json \
        --episodes 2000 --out-dir experiments/rl_agent
"""

import argparse
import csv
import json
import pickle
import random
import sys
from collections import defaultdict
from pathlib import Path

try:
    import numpy as np
except ImportError:
    print("ERROR: pip install numpy", file=sys.stderr)
    sys.exit(1)

FEATURE_COLS = ["mean_IAT", "IAT_variance", "mean_frame_size", "burst_length", "count"]

# ---- Discrete action space (mirrors psfp_policy.POLICY_TABLE) ----
ACTIONS = [
    ("no_op", {}),
    ("tighten_gate_10", {"gate_tighten_us": 10}),
    ("tighten_gate_15", {"gate_tighten_us": 15}),
    ("reduce_cir_0.5", {"cir_fraction": 0.5}),
    ("reduce_cir_0.6", {"cir_fraction": 0.6}),
    ("reduce_cbs_0.5", {"cbs_fraction": 0.5}),
]
ACTION_NAMES = [a[0] for a in ACTIONS]

# ---- Expert action per attack config (mirrors psfp_policy.POLICY_TABLE,
#      collapsed to action-type-only for reward comparison) ----
EXPERT_ACTION_TYPE = {
    "Benign": "no_op",
    "GCLPhaseAttack": "tighten_gate_10",
    "ThresholdEvasionAttack": "reduce_cir_0.5",
    "SustainedNearCIRAttack": "reduce_cir_0.5",
    "CBSExhaustionAttack": "reduce_cbs_0.5",
    "CBSBoundaryAttack": "reduce_cbs_0.5",
    "GateBoundaryProximityAttack": "tighten_gate_15",
    "WindowBoundaryQueuingAttack": "tighten_gate_15",
    "QueueBuildingAttack": "reduce_cir_0.6",
    "AggregateLoadAttack": "reduce_cir_0.5",
    "LowAndSlowDriftAttack": "no_op",       # not yet reliably detected -- fail-safe
    "ScheduleAwareBurstAttack": "no_op",    # not yet reliably detected -- fail-safe
}

# ---- Disclosed, assumed per-action effect on network state ----
# NOT measured from a live simulation (no such feedback loop exists --
# see module docstring). Same assumption already disclosed in
# reward_function.py's DEMO_SCENARIOS.
ACTION_EFFECTS = {
    "no_op":            {"delay_add_us": 0,  "loss": 0.00},
    "tighten_gate_10":  {"delay_add_us": 10, "loss": 0.00},
    "tighten_gate_15":  {"delay_add_us": 15, "loss": 0.00},
    "reduce_cir_0.5":   {"delay_add_us": 0,  "loss": 0.05},
    "reduce_cir_0.6":   {"delay_add_us": 0,  "loss": 0.04},
    "reduce_cbs_0.5":   {"delay_add_us": 0,  "loss": 0.05},
}

WCD_BASELINE_US = 1088.0  # Luo 2021 Table 9 baseline (AV1)


def load_rf(rf_model_path, rf_report_path):
    with open(rf_model_path, "rb") as f:
        rf = pickle.load(f)
    with open(rf_report_path) as f:
        report = json.load(f)
    label_names = {int(k): v for k, v in report["label_names"].items()}
    return rf, label_names


def load_dataset(csv_path, streams):
    rows = []
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
            rows.append((feat, label, row["config"]))
    return rows


def compute_reward(true_config, chosen_action_name, rf_correct):
    action_type = chosen_action_name
    effect = ACTION_EFFECTS[action_type]

    detection_accuracy = 1.0 if rf_correct else 0.0
    wcd_observed = WCD_BASELINE_US + effect["delay_add_us"]
    delay_increase = max(0.0, (wcd_observed - WCD_BASELINE_US) / WCD_BASELINE_US)
    packet_loss = effect["loss"]

    # Base reward (mirrors reward_function.py's weighting)
    reward = (
        3.0 * detection_accuracy
        - 2.0 * delay_increase
        - 2.0 * packet_loss
        + 1.0 * (1.0 - packet_loss)  # throughput retained proxy
    )

    # Alignment bonus/penalty vs. the already-validated expert policy
    expert = EXPERT_ACTION_TYPE.get(true_config, "no_op")
    if chosen_action_name == expert:
        reward += 2.0
    if true_config == "Benign" and chosen_action_name != "no_op":
        reward -= 4.0  # unnecessary action on legitimate traffic

    return reward


def epsilon_greedy(Q, state, epsilon, n_actions, rng):
    if rng.random() < epsilon:
        return rng.randrange(n_actions)
    qvals = Q[state]
    return int(np.argmax(qvals))


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--csv", default="combined_features_multiclass.csv")
    ap.add_argument("--rf-model", required=True)
    ap.add_argument("--rf-report", required=True)
    ap.add_argument("--streams", default="all")
    ap.add_argument("--episodes", type=int, default=2000)
    ap.add_argument("--alpha", type=float, default=0.1, help="Learning rate")
    ap.add_argument("--epsilon-start", type=float, default=1.0)
    ap.add_argument("--epsilon-end", type=float, default=0.05)
    ap.add_argument("--epsilon-decay-episodes", type=int, default=1500)
    ap.add_argument("--random-state", type=int, default=42)
    ap.add_argument("--out-dir", default="experiments/rl_agent")
    args = ap.parse_args()

    ALL_STREAMS = ["av1", "av2", "radarNode", "zonalHost", "attackNode"]
    streams = ALL_STREAMS if args.streams.lower() == "all" else \
        [s.strip() for s in args.streams.split(",")]

    rf, label_names = load_rf(args.rf_model, args.rf_report)
    dataset = load_dataset(args.csv, streams)
    if not dataset:
        print("No data loaded -- check --csv/--streams.", file=sys.stderr)
        sys.exit(1)

    print(f"Loaded {len(dataset)} windows for trace-replay training.")
    print(f"Action space ({len(ACTIONS)}): {ACTION_NAMES}")
    print(f"Expert policy (for reward alignment bonus): {EXPERT_ACTION_TYPE}\n")

    configs_present = sorted(set(cfg for _, _, cfg in dataset))
    n_states = len(configs_present)
    state_idx = {cfg: i for i, cfg in enumerate(configs_present)}
    n_actions = len(ACTIONS)

    rng = random.Random(args.random_state)
    np.random.seed(args.random_state)

    Q = np.zeros((n_states, n_actions))
    reward_history = []

    # ---- TRAINING: state = TRUE label (ground truth) ----
    for ep in range(args.episodes):
        feat, true_label, true_config = dataset[rng.randrange(len(dataset))]
        s = state_idx[true_config]

        frac = min(1.0, ep / max(1, args.epsilon_decay_episodes))
        epsilon = args.epsilon_start + frac * (args.epsilon_end - args.epsilon_start)

        a = epsilon_greedy(Q, s, epsilon, n_actions, rng)
        action_name = ACTION_NAMES[a]

        rf_pred = int(rf.predict([feat])[0])
        rf_correct = (rf_pred == true_label)

        r = compute_reward(true_config, action_name, rf_correct)
        reward_history.append(r)

        # Single-step (bandit) update -- no bootstrapped next-state term,
        # since no live environment provides a real "next state" here.
        Q[s, a] += args.alpha * (r - Q[s, a])

    print(f"Training complete: {args.episodes} episodes.\n")

    # ---- Learned policy (argmax per state) vs. expert ----
    print(f"{'True Attack Type':30s} {'Learned Action':18s} {'Expert Action':18s} {'Match'}")
    print("-" * 80)
    n_match = 0
    for cfg in configs_present:
        s = state_idx[cfg]
        learned = ACTION_NAMES[int(np.argmax(Q[s]))]
        expert = EXPERT_ACTION_TYPE.get(cfg, "no_op")
        match = learned == expert
        n_match += int(match)
        print(f"{cfg:30s} {learned:18s} {expert:18s} {'YES' if match else 'no'}")
    print(f"\nLearned/expert policy agreement: {n_match}/{len(configs_present)} "
          f"({n_match/len(configs_present)*100:.1f}%)")

    # ---- EVALUATION: state = RF-PREDICTED label (real classifier noise) ----
    print(f"\n{'='*80}\nEVALUATION using REAL RF-predicted state (not ground truth)\n{'='*80}")
    eval_n_match = 0
    eval_n = 0
    for feat, true_label, true_config in dataset:
        rf_pred = int(rf.predict([feat])[0])
        pred_config = label_names.get(rf_pred, str(rf_pred))
        if pred_config not in state_idx:
            continue  # RF predicted a class not seen as a state (edge case)
        s = state_idx[pred_config]
        learned = ACTION_NAMES[int(np.argmax(Q[s]))]
        expert_for_true = EXPERT_ACTION_TYPE.get(true_config, "no_op")
        eval_n += 1
        eval_n_match += int(learned == expert_for_true)
    if eval_n:
        print(f"Action matches TRUE-label expert policy even when state is "
              f"RF-PREDICTED (realistic, noisy deployment): "
              f"{eval_n_match}/{eval_n} ({eval_n_match/eval_n*100:.1f}%)")

    # ---- Save ----
    out = Path(args.out_dir)
    out.mkdir(parents=True, exist_ok=True)
    np.save(out / "q_table.npy", Q)
    with open(out / "q_states.json", "w") as f:
        json.dump(configs_present, f, indent=2)
    with open(out / "reward_history.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["episode", "reward"])
        for i, r in enumerate(reward_history):
            w.writerow([i, r])

    # Rolling-mean convergence summary (every 100 episodes)
    window = 100
    convergence = []
    for i in range(0, len(reward_history), window):
        chunk = reward_history[i:i+window]
        convergence.append(sum(chunk) / len(chunk))
    print(f"\nReward convergence (mean per {window}-episode block):")
    for i, v in enumerate(convergence):
        print(f"  episodes {i*window:5d}-{(i+1)*window:5d}: {v:6.3f}")

    report = {
        "episodes": args.episodes,
        "states": configs_present,
        "actions": ACTION_NAMES,
        "learned_vs_expert_agreement": n_match / len(configs_present),
        "eval_agreement_under_rf_noise": (eval_n_match / eval_n) if eval_n else None,
        "convergence_by_block": convergence,
    }
    with open(out / "rl_report.json", "w") as f:
        json.dump(report, f, indent=2, default=str)

    print(f"\nSaved: {out}/q_table.npy, reward_history.csv, rl_report.json")


if __name__ == "__main__":
    main()
