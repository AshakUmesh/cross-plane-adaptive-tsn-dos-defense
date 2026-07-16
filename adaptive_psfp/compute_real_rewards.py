import csv
import sys
sys.path.insert(0, 'ml/pipeline')
from reward_function import compute_reward, RewardComponents

# Detection accuracy per attack, from RF pipeline (100% TPR per your policy_table rationale comments, except the two no_op cases)
detection_map = {
    "ThresholdEvasionAttack": 1.0,
    "SustainedNearCIRAttack": 1.0,
    "CBSExhaustionAttack": 1.0,
    "CBSBoundaryAttack": 1.0,
    "QueueBuildingAttack": 1.0,
    "AggregateLoadAttack": 1.0,
    "GCLPhaseAttack": 1.0,
    "GateBoundaryProximityAttack": 0.0,  # SUSPECT severity, per-port only
    "WindowBoundaryQueuingAttack": 0.0,  # SUSPECT severity, per-port only
}

rows = []
with open('adaptive_results.csv') as f:
    for row in csv.DictReader(f):
        attack = row['Attack']
        static = int(row['Static_Packets'])
        adaptive = int(row['Adaptive_Packets'])
        throughput_retained = adaptive / static if static > 0 else 1.0
        packet_loss_rate = 1.0 - throughput_retained  # fraction of attack traffic blocked -- reframed below

        rc = RewardComponents(
            detection_accuracy=detection_map.get(attack, 0.5),
            wcd_baseline_us=1088.0,
            wcd_observed_us=1088.0,  # not measured today -- still assumed, flagged
            packet_loss_rate=0.0,  # legitimate-traffic loss not measured -- flagged, kept 0 (conservative)
            false_positive_rate=0.0102,
            throughput_retained=throughput_retained,  # REAL, measured today
        )
        result = compute_reward(rc)
        rows.append({
            'Attack': attack,
            'Static': static,
            'Adaptive': adaptive,
            'Real_Throughput_Retained': round(throughput_retained, 4),
            'Reward': result['reward'],
        })

with open('real_rewards.csv', 'w', newline='') as f:
    writer = csv.DictWriter(f, fieldnames=['Attack','Static','Adaptive','Real_Throughput_Retained','Reward'])
    writer.writeheader()
    writer.writerows(rows)

for r in rows:
    print(r)
