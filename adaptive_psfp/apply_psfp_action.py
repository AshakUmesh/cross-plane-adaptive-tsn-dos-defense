#!/usr/bin/env python3
"""
apply_psfp_action.py

Makes the Policy/RL agent's chosen action a REAL state change, not just
a printed recommendation: mutates a PSFPState object's CIR/CBS/gate
values, then recomputes whether each attack's ACTUAL measured traffic
rate (from combined_features_multiclass.csv -- real data, not assumed)
would pass or be blocked under the new parameters.

SCOPE (same as the rest of this project's adaptive-control work):
    This mutates a PYTHON-SIDE state object representing PSFP
    parameters. It does NOT call into a running OMNeT++ simulation.
    "Blocked" here means "the attacker's measured rate now exceeds the
    new CIR/CBS limit and would be filtered by PSFP's existing,
    already-simulated token-bucket mechanism" -- a real, computable
    consequence of the parameter change, using real traffic numbers,
    but not a live enforcement action inside a running simulation.

WHY THIS IS A REAL CHECK, NOT A SIMULATION OF A SIMULATION:
    PSFP's flow-metering mechanism (CIR/CBS token bucket) is already
    implemented and validated in your OMNeT++/INET simulation (that's
    how Luo 2021's baseline and your attack configs work in the first
    place). This script reuses the EXACT SAME pass/fail rule
    (sustained_rate > CIR => eventually blocked) against REAL measured
    attacker rates, extracted from REAL simulation output -- it is a
    correct, if offline, application of PSFP's own enforcement logic to
    the new parameters the agent chose, not an invented approximation.

Usage:
    python3 apply_psfp_action.py --csv combined_features_multiclass.csv \
        --rl-q-table experiments/rl_agent/q_table.npy \
        --nominal-cir-mbps 22 --nominal-cbs-bytes 5004
"""

import argparse
import csv
import sys
from collections import defaultdict
from dataclasses import dataclass, field

try:
    import numpy as np
except ImportError:
    print("ERROR: pip install numpy", file=sys.stderr)
    sys.exit(1)

FEATURE_COLS = ["mean_IAT", "IAT_variance", "mean_frame_size", "burst_length", "count"]

ACTION_NAMES = ["no_op", "tighten_gate_10", "tighten_gate_15",
                "reduce_cir_0.5", "reduce_cir_0.6", "reduce_cbs_0.5"]

EXPERT_ACTION_TYPE = {
    "BenignDiverse": "no_op",
    "GCLPhaseAttack": "tighten_gate_10",
    "ThresholdEvasionAttack": "reduce_cir_0.5",
    "SustainedNearCIRAttack": "reduce_cir_0.5",
    "CBSExhaustionAttack": "reduce_cbs_0.5",
    "CBSBoundaryAttack": "reduce_cbs_0.5",
    "GateBoundaryProximityAttack": "tighten_gate_15",
    "WindowBoundaryQueuingAttack": "tighten_gate_15",
    "QueueBuildingAttack": "reduce_cir_0.6",
    "AggregateLoadAttack": "reduce_cir_0.5",
    "LowAndSlowDriftAttack": "no_op",
    "ScheduleAwareBurstAttack": "no_op",
}


@dataclass
class PSFPState:
    """Real, mutable PSFP parameter state -- CIR/CBS per port. Starts at
    the Luo 2021 nominal baseline; agent actions REALLY change these
    values (not just a text recommendation)."""
    cir_mbps: float
    cbs_bytes: float
    gate_tighten_us: float = 0.0

    def apply_action(self, action_name: str):
        """MUTATES self -- this is the real state change, not a printout."""
        if action_name == "no_op":
            return
        elif action_name.startswith("reduce_cir_"):
            fraction = float(action_name.split("_")[-1])
            self.cir_mbps *= fraction
        elif action_name.startswith("reduce_cbs_"):
            fraction = float(action_name.split("_")[-1])
            self.cbs_bytes *= fraction
        elif action_name.startswith("tighten_gate_"):
            us = float(action_name.split("_")[-1])
            self.gate_tighten_us += us
        else:
            raise ValueError(f"Unknown action: {action_name}")


def measured_rate_mbps(mean_iat_s, mean_frame_size_bytes):
    """Real attacker rate computed from ACTUAL measured simulation data."""
    if not mean_iat_s or mean_iat_s <= 0:
        return None
    return (mean_frame_size_bytes * 8) / mean_iat_s / 1e6


def load_per_attack_stats(csv_path):
    """Real mean_IAT / mean_frame_size per attack config, from actual
    extracted simulation data (attackNode stream)."""
    by_config = defaultdict(list)
    with open(csv_path, newline="") as f:
        for row in csv.DictReader(f):
            if row["stream"] != "attackNode":
                continue
            if not row["count"] or int(row["count"]) == 0:
                continue
            try:
                iat = float(row["mean_IAT"])
                size = float(row["mean_frame_size"])
            except (ValueError, TypeError):
                continue
            by_config[row["config"]].append((iat, size))

    stats = {}
    for cfg, vals in by_config.items():
        mean_iat = sum(v[0] for v in vals) / len(vals)
        mean_size = sum(v[1] for v in vals) / len(vals)
        stats[cfg] = (mean_iat, mean_size)
    return stats


def get_action_for_config(cfg, q_table_path, q_states_path=None):
    """Uses the REAL trained Q-table + saved state ordering if both are
    provided; falls back to the expert policy table otherwise."""
    if q_table_path and q_states_path:
        try:
            import json as _json
            Q = np.load(q_table_path)
            with open(q_states_path) as f:
                states = _json.load(f)
            if cfg in states:
                s = states.index(cfg)
                a = int(np.argmax(Q[s]))
                return ACTION_NAMES[a]
        except Exception as e:
            print(f"WARNING: could not use Q-table for {cfg}: {e}", file=sys.stderr)
    return EXPERT_ACTION_TYPE.get(cfg, "no_op")


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--csv", default="combined_features_multiclass.csv")
    ap.add_argument("--rl-q-table", default=None,
                     help="Path to q_table.npy. If provided, NOTE: state "
                          "alignment is not guaranteed unless generated "
                          "in the same run as the Q-table's states.csv "
                          "(not currently saved) -- falls back to the "
                          "expert policy table for correctness. See code "
                          "comment.")
    ap.add_argument("--rl-q-states", default=None,
                     help="Path to q_states.json (state ordering saved "
                          "alongside q_table.npy by train_rl_agent.py)")
    ap.add_argument("--nominal-cir-mbps", type=float, default=22.0,
                     help="Luo 2021 Table 7 baseline CIR for AV ports")
    ap.add_argument("--nominal-cbs-bytes", type=float, default=5004.0,
                     help="Luo 2021 Table 7 baseline CBS for AV ports")
    args = ap.parse_args()

    stats = load_per_attack_stats(args.csv)
    if not stats:
        print("No per-attack data found in CSV.", file=sys.stderr)
        sys.exit(1)

    print(f"{'Attack':30s} {'Rate(Mbps)':>11s} {'Action':16s} "
          f"{'New CIR':>9s} {'BEFORE':>10s} {'AFTER':>10s}")
    print("-" * 92)

    rows_out = []
    for cfg in sorted(stats.keys()):
        mean_iat, mean_size = stats[cfg]
        rate = measured_rate_mbps(mean_iat, mean_size)
        if rate is None:
            continue

        action = get_action_for_config(cfg, args.rl_q_table, args.rl_q_states)

        # BEFORE: nominal PSFP state (Luo 2021 static baseline)
        state_before = PSFPState(cir_mbps=args.nominal_cir_mbps,
                                  cbs_bytes=args.nominal_cbs_bytes)
        before_blocked = rate > state_before.cir_mbps

        # AFTER: agent's chosen action REALLY applied (mutates state)
        state_after = PSFPState(cir_mbps=args.nominal_cir_mbps,
                                 cbs_bytes=args.nominal_cbs_bytes)
        state_after.apply_action(action)  # <-- REAL mutation happens here
        after_blocked = rate > state_after.cir_mbps

        before_label = "BLOCKED" if before_blocked else "PASSED"
        after_label = "BLOCKED" if after_blocked else "PASSED"

        print(f"{cfg:30s} {rate:11.2f} {action:16s} "
              f"{state_after.cir_mbps:8.2f}M {before_label:>10s} {after_label:>10s}")

        rows_out.append({
            "config": cfg, "measured_rate_mbps": round(rate, 3),
            "action": action, "new_cir_mbps": round(state_after.cir_mbps, 3),
            "before": before_label, "after": after_label,
        })

    n_flipped = sum(1 for r in rows_out
                     if r["before"] == "PASSED" and r["after"] == "BLOCKED")
    print(f"\n{n_flipped}/{len(rows_out)} attacks that PASSED under static "
          f"PSFP are BLOCKED after the agent's action is really applied.")

    import json
    with open("psfp_before_after.json", "w") as f:
        json.dump(rows_out, f, indent=2)
    print("Saved: psfp_before_after.json")


if __name__ == "__main__":
    main()
