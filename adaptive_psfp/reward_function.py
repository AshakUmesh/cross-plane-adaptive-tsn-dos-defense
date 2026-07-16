#!/usr/bin/env python3
"""
reward_function.py

Defines the reward function for a future reinforcement-learning PSFP
agent (Phase 7, not yet implemented -- see Chapter 9). Defining and
computing this NOW, against real numbers from the completed experiments,
is valuable independent of whether an RL agent is ever trained: it
forces the tradeoffs (delay vs. detection vs. false positives) to be
made concrete rather than left as a vague future promise.

REWARD FORMULA:

    reward = w1 * detection_accuracy
           - w2 * normalized_delay_increase
           - w3 * packet_loss_rate
           - w4 * false_positive_rate
           + w5 * normalized_throughput_retained

    Default weights (w1..w5) reflect automotive TSN priorities: a missed
    detection is treated as more costly than a moderate delay increase,
    but delay increase is weighted higher than in a general-purpose IDS
    because TSN's entire value proposition is bounded worst-case delay
    (WCD). Weights are exposed as CLI args so they can be tuned/justified
    explicitly rather than hidden as magic numbers.

WHY THESE COMPONENTS:
    detection_accuracy         - the core security objective
    normalized_delay_increase  - TSN's defining constraint (Ch.1); an
                                  action that fixes detection but blows
                                  the WCD budget is not an acceptable
                                  trade in this domain
    packet_loss_rate           - a mitigation action (e.g. gate close)
                                  that drops legitimate traffic is
                                  penalized directly, not just implied
                                  by delay
    false_positive_rate        - penalizes over-aggressive policies;
                                  ties directly to the held-out FPR
                                  numbers already measured in Ch.8
    normalized_throughput_retained - rewards actions that mitigate the
                                  attack while preserving as much
                                  legitimate bandwidth as possible

Usage (compute reward for a specific measured scenario):
    python3 reward_function.py \
        --detection-accuracy 1.0 \
        --wcd-baseline-us 1088 \
        --wcd-observed-us 1088 \
        --packet-loss-rate 0.0 \
        --false-positive-rate 0.0714 \
        --throughput-retained 0.95

Usage (demo -- computes reward for several already-measured Chapter 8
scenarios, so the function is grounded in real numbers, not hypothetical
ones):
    python3 reward_function.py --demo
"""

import argparse
from dataclasses import dataclass


DEFAULT_WEIGHTS = {
    "w1_detection": 3.0,
    "w2_delay": 2.0,
    "w3_loss": 2.0,
    "w4_false_positive": 1.5,
    "w5_throughput": 1.0,
}


@dataclass
class RewardComponents:
    detection_accuracy: float          # 0-1, TPR of the action's trigger
    wcd_baseline_us: float             # Luo 2021 baseline WCD for this stream
    wcd_observed_us: float             # WCD observed under this action
    packet_loss_rate: float            # 0-1, legitimate packets lost
    false_positive_rate: float         # 0-1, measured held-out FPR
    throughput_retained: float         # 0-1, fraction of legitimate throughput kept


def compute_reward(rc: RewardComponents, weights: dict = None) -> dict:
    w = weights or DEFAULT_WEIGHTS

    # Normalized delay increase: 0 if WCD unchanged or improved,
    # grows linearly with WCD overrun relative to baseline.
    delay_increase = max(0.0, (rc.wcd_observed_us - rc.wcd_baseline_us)
                          / rc.wcd_baseline_us) if rc.wcd_baseline_us > 0 else 0.0

    reward = (
        w["w1_detection"] * rc.detection_accuracy
        - w["w2_delay"] * delay_increase
        - w["w3_loss"] * rc.packet_loss_rate
        - w["w4_false_positive"] * rc.false_positive_rate
        + w["w5_throughput"] * rc.throughput_retained
    )

    return {
        "reward": round(reward, 4),
        "components": {
            "detection_term": round(w["w1_detection"] * rc.detection_accuracy, 4),
            "delay_penalty": round(-w["w2_delay"] * delay_increase, 4),
            "loss_penalty": round(-w["w3_loss"] * rc.packet_loss_rate, 4),
            "fp_penalty": round(-w["w4_false_positive"] * rc.false_positive_rate, 4),
            "throughput_term": round(w["w5_throughput"] * rc.throughput_retained, 4),
        },
        "delay_increase_fraction": round(delay_increase, 4),
    }


# ---- Demo scenarios grounded in real Chapter 8 measurements ----
DEMO_SCENARIOS = {
    "no_op (undetected mimicry attack, pooled model, c=0.01)": RewardComponents(
        detection_accuracy=0.0,       # measured: 0% TPR pooled/strict
        wcd_baseline_us=1088.0,       # Luo 2021 Table 9 baseline (AV1)
        wcd_observed_us=1088.0,       # no action taken -> WCD unaffected by policy
        packet_loss_rate=0.0,
        false_positive_rate=0.0100,   # in-sample FPR at c=0.01
        throughput_retained=1.0,
    ),
    "tighten_gate (mimicry attack, per-port model, c=0.05)": RewardComponents(
        detection_accuracy=1.0,       # measured: 100% TPR per-port, c=0.05
        wcd_baseline_us=1088.0,
        wcd_observed_us=1088.0 + 15,  # approx: gate tightened by 15us
        packet_loss_rate=0.0,         # tighten, not block -- no loss assumed
        false_positive_rate=0.0714,   # measured held-out FPR at c=0.05
        throughput_retained=0.95,     # assumed retained (not measured in sim)
    ),
    "reduce_cir (ThresholdEvasionAttack, detected 100% TPR)": RewardComponents(
        detection_accuracy=1.0,       # measured: 100% TPR, attackNode
        wcd_baseline_us=1088.0,
        wcd_observed_us=1088.0,       # CIR change on attacker port; own
                                       # stream's WCD assumed unaffected
        packet_loss_rate=0.05,        # assumed: halved CIR drops some
                                       # attacker traffic (not measured)
        false_positive_rate=0.0102,   # pooled held-out FPR (Ch.8 S8.2)
        throughput_retained=0.90,
    ),
}


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--detection-accuracy", type=float)
    ap.add_argument("--wcd-baseline-us", type=float)
    ap.add_argument("--wcd-observed-us", type=float)
    ap.add_argument("--packet-loss-rate", type=float)
    ap.add_argument("--false-positive-rate", type=float)
    ap.add_argument("--throughput-retained", type=float)
    ap.add_argument("--demo", action="store_true")
    args = ap.parse_args()

    if args.demo:
        print(f"{'Scenario':55s} {'Reward':>8s}  Components")
        print("-" * 110)
        for name, rc in DEMO_SCENARIOS.items():
            result = compute_reward(rc)
            print(f"{name:55s} {result['reward']:8.4f}  {result['components']}")
        print("\nNOTE: WCD/loss/throughput figures marked 'assumed' above are "
              "NOT measured in simulation -- they illustrate the reward "
              "function's mechanics using real detection/FPR numbers from "
              "Chapter 8 combined with plausible placeholder values for "
              "quantities not yet instrumented (packet loss under a live "
              "policy change, throughput retained). Measuring these "
              "properly requires the live OMNeT++ interaction loop "
              "described as Phase 7 future work.")
        return

    required = [args.detection_accuracy, args.wcd_baseline_us,
                args.wcd_observed_us, args.packet_loss_rate,
                args.false_positive_rate, args.throughput_retained]
    if any(v is None for v in required):
        print("Provide all --detection-accuracy/--wcd-*/--packet-loss-rate/"
              "--false-positive-rate/--throughput-retained, or use --demo")
        return

    rc = RewardComponents(
        detection_accuracy=args.detection_accuracy,
        wcd_baseline_us=args.wcd_baseline_us,
        wcd_observed_us=args.wcd_observed_us,
        packet_loss_rate=args.packet_loss_rate,
        false_positive_rate=args.false_positive_rate,
        throughput_retained=args.throughput_retained,
    )
    result = compute_reward(rc)
    print(f"Reward: {result['reward']}")
    print(f"Components: {result['components']}")


if __name__ == "__main__":
    main()
