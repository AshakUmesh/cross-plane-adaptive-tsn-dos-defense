#!/bin/bash
CONFIGS=(
  "ThresholdEvasionAttack"
  "SustainedNearCIRAttack"
  "CBSExhaustionAttack"
  "CBSBoundaryAttack"
  "QueueBuildingAttack"
  "AggregateLoadAttack"
  "ScheduleAwareBurstAttack"
  "GCLPhaseAttack"
  "WindowBoundaryQueuingAttack"
)

REPS=1   # <-- change this once confirmed

for cfg in "${CONFIGS[@]}"; do
  for variant in "$cfg" "${cfg}_Adaptive"; do
    for r in $(seq 0 $((REPS-1))); do
      echo ">>> Running $variant rep $r"
      ./out/clang-release/luo2021 \
        -u Cmdenv \
        -n .:/home/ashakumesh/research/omnetpp-6.4.0/samples/inet/src \
        -l /home/ashakumesh/research/omnetpp-6.4.0/samples/inet/src/libINET.so \
        -c "$variant" -r $r \
        omnetpp.ini
    done
  done
done
