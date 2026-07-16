#!/usr/bin/env python3
"""
psfp_policy.py

Rule-based adaptive PSFP controller: maps a detected attack type (from
two_tier_pipeline.py's Stage 2 output) to a bounded corrective action on
PSFP parameters (CIR, CBS, gate window). This is the "static -> adaptive"
transition described in the thesis architecture, WITHOUT requiring a
trained reinforcement-learning agent.

WHY RULE-BASED FIRST (not RL):
  - Requires no training episodes, no reward convergence, no live
    OMNeT++ interaction loop -- all of which are open feasibility
    questions for this simulator (see Chapter 9, future work).
  - Every action is bounded ahead of time to a SAFE ACTION SPACE, so the
    policy cannot violate TSN's deterministic scheduling guarantees --
    this constraint is enforced structurally here, not learned.
  - It is a legitimate, complete proof-of-concept for "detection drives
    adaptive control," and a natural stepping stone: Phase 7 (RL) would
    later learn to select among the SAME bounded action space, rather
    than inventing new unconstrained actions.

SAFE ACTION SPACE (hard bounds, never violated regardless of policy):
  - CIR may be reduced to a floor of MIN_CIR_FRACTION x nominal, never
    to zero (avoids fully starving a stream that may still be partly
    legitimate, e.g. false positive resilience).
  - CBS may be reduced to a floor of MIN_CBS_FRACTION x nominal.
  - Gate window may only be tightened (narrowed), never widened beyond
    its Luo-2021-configured baseline -- widening could violate the
    worst-case delay bound the schedule was originally verified against.
  - Every action has an auto-revert timer; nothing is permanent without
    re-confirmation, bounding the damage of a false positive.

Usage:
    python3 psfp_policy.py --attack-type GateBoundaryProximityAttack --port radarNode
    python3 psfp_policy.py --demo   # runs the policy against all known attack types
"""

import argparse
import json
import sys
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone

# ---- Safe action-space bounds (never violated) ----
MIN_CIR_FRACTION = 0.5      # never drop CIR below 50% of nominal
MIN_CBS_FRACTION = 0.5      # never drop CBS below 50% of nominal
MAX_GATE_TIGHTEN_US = 20    # never narrow a gate window by more than 20us
AUTO_REVERT_SECONDS = 5.0   # every action auto-reverts unless re-confirmed


@dataclass
class PSFPAction:
    attack_type: str
    port: str
    action_type: str            # "reduce_cir" | "reduce_cbs" | "tighten_gate" | "no_op"
    parameter_delta: dict = field(default_factory=dict)
    severity: str = "SUSPECT"   # "SUSPECT" | "MALICIOUS"
    auto_revert_seconds: float = AUTO_REVERT_SECONDS
    rationale: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def clamp_to_safe_space(self):
        """Enforce hard bounds regardless of what the policy table requested."""
        if "cir_fraction" in self.parameter_delta:
            self.parameter_delta["cir_fraction"] = max(
                MIN_CIR_FRACTION, self.parameter_delta["cir_fraction"]
            )
        if "cbs_fraction" in self.parameter_delta:
            self.parameter_delta["cbs_fraction"] = max(
                MIN_CBS_FRACTION, self.parameter_delta["cbs_fraction"]
            )
        if "gate_tighten_us" in self.parameter_delta:
            self.parameter_delta["gate_tighten_us"] = min(
                MAX_GATE_TIGHTEN_US, self.parameter_delta["gate_tighten_us"]
            )
        return self


# ---- Policy table: attack type -> corrective action ----
# Grounded in the vulnerability analysis (V1-V5) and the empirical
# detection results in Chapter 8. Each entry's rationale cites the
# specific finding that motivates it.
POLICY_TABLE = {
    "GCLPhaseAttack": {
        "action_type": "tighten_gate",
        "parameter_delta": {"gate_tighten_us": 10},
        "severity": "MALICIOUS",
        "rationale": "V1: attacker times bursts to gate-open window. "
                      "Detected at 100% TPR (attackNode, pooled model). "
                      "Tightening the gate window reduces the exploitable "
                      "burst-absorption margin.",
    },
    "ThresholdEvasionAttack": {
        "action_type": "reduce_cir",
        "parameter_delta": {"cir_fraction": 0.5},
        "severity": "MALICIOUS",
        "rationale": "V3: attacker sustains just below CIR (21.9 Mbps < "
                      "22 Mbps). Detected at 100% TPR. Halving CIR forces "
                      "the attacker's sustained rate above the new limit, "
                      "triggering the existing flow-meter response.",
    },
    "SustainedNearCIRAttack": {
        "action_type": "reduce_cir",
        "parameter_delta": {"cir_fraction": 0.5},
        "severity": "MALICIOUS",
        "rationale": "Same mechanism as ThresholdEvasionAttack -- see above.",
    },
    "CBSExhaustionAttack": {
        "action_type": "reduce_cbs",
        "parameter_delta": {"cbs_fraction": 0.5},
        "severity": "MALICIOUS",
        "rationale": "V1: attacker exhausts the committed burst budget "
                      "before the meter reacts. Detected at 100% TPR. "
                      "Halving CBS shortens the undetected burst window.",
    },
    "CBSBoundaryAttack": {
        "action_type": "reduce_cbs",
        "parameter_delta": {"cbs_fraction": 0.5},
        "severity": "MALICIOUS",
        "rationale": "Same mechanism as CBSExhaustionAttack -- see above.",
    },
    "GateBoundaryProximityAttack": {
        "action_type": "tighten_gate",
        "parameter_delta": {"gate_tighten_us": 15},
        "severity": "SUSPECT",
        "rationale": "Mimicry attack (Ch.8 S8.3): 529B frame timed to "
                      "match legitimate radarNode/zonalHost traffic. Only "
                      "detected via per-port model at relaxed (5%) "
                      "threshold -- flagged SUSPECT, not MALICIOUS, given "
                      "the higher false-positive rate (7.14% held-out) "
                      "at this threshold. Tighten rather than hard-block.",
    },
    "WindowBoundaryQueuingAttack": {
        "action_type": "tighten_gate",
        "parameter_delta": {"gate_tighten_us": 15},
        "severity": "SUSPECT",
        "rationale": "Same mimicry mechanism as GateBoundaryProximityAttack.",
    },
    "QueueBuildingAttack": {
        "action_type": "reduce_cir",
        "parameter_delta": {"cir_fraction": 0.6},
        "severity": "MALICIOUS",
        "rationale": "Detected at 100% TPR (attackNode). Queue-building "
                      "pressure reduced by rate-limiting the source.",
    },
    "AggregateLoadAttack": {
        "action_type": "reduce_cir",
        "parameter_delta": {"cir_fraction": 0.5},
        "severity": "MALICIOUS",
        "rationale": "Detected at 100% TPR (attackNode). Aggregate "
                      "load reduced at the source before it reaches "
                      "downstream queues.",
    },
    "LowAndSlowDriftAttack": {
        "action_type": "no_op",
        "parameter_delta": {},
        "severity": "SUSPECT",
        "rationale": "NOT YET RELIABLY DETECTED (Ch.8 S8.4): sub-window "
                      "packet rate falls below the current feature "
                      "extractor's resolution. No action taken because "
                      "no confident classification exists yet -- "
                      "acting on an unconfirmed detection risks "
                      "unnecessary throughput loss on legitimate traffic. "
                      "Listed explicitly as future work (multi-window "
                      "rate features).",
    },
    "ScheduleAwareBurstAttack": {
        "action_type": "no_op",
        "parameter_delta": {},
        "severity": "SUSPECT",
        "rationale": "Same reasoning as LowAndSlowDriftAttack -- "
                      "detection not yet confirmed reliable at this "
                      "window resolution.",
    },
}


def decide_action(attack_type: str, port: str) -> PSFPAction:
    entry = POLICY_TABLE.get(attack_type)
    if entry is None:
        return PSFPAction(
            attack_type=attack_type, port=port, action_type="no_op",
            rationale=f"Unknown attack type '{attack_type}' -- no policy "
                      f"defined. Defaulting to no_op rather than guessing "
                      f"an action (fail-safe default).",
        )
    action = PSFPAction(
        attack_type=attack_type, port=port,
        action_type=entry["action_type"],
        parameter_delta=dict(entry["parameter_delta"]),
        severity=entry["severity"],
        rationale=entry["rationale"],
    )
    return action.clamp_to_safe_space()


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--attack-type", default=None)
    ap.add_argument("--port", default="unspecified")
    ap.add_argument("--demo", action="store_true",
                     help="Run the policy against every known attack type")
    args = ap.parse_args()

    if args.demo:
        print(f"{'Attack Type':30s} {'Action':15s} {'Severity':10s} {'Delta'}")
        print("-" * 90)
        for attack_type in POLICY_TABLE:
            action = decide_action(attack_type, port="demoPort")
            print(f"{action.attack_type:30s} {action.action_type:15s} "
                  f"{action.severity:10s} {action.parameter_delta}")
        return

    if not args.attack_type:
        print("Provide --attack-type or --demo", file=sys.stderr)
        sys.exit(1)

    action = decide_action(args.attack_type, args.port)
    print(json.dumps(asdict(action), indent=2))


if __name__ == "__main__":
    main()
