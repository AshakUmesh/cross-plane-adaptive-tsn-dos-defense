#!/bin/bash
CONFIGS=(
  "ThresholdEvasionAttack_ClosedLoop"
  "SustainedNearCIRAttack_ClosedLoop"
  "CBSExhaustionAttack_ClosedLoop"
  "CBSBoundaryAttack_ClosedLoop"
  "QueueBuildingAttack_ClosedLoop"
  "AggregateLoadAttack_ClosedLoop"
  "GCLPhaseAttack_ClosedLoop"
  "GateBoundaryProximityAttack_ClosedLoop"
  "WindowBoundaryQueuingAttack_ClosedLoop"
)

OUT="new_closedloop_features.csv"
rm -f "$OUT"

for i in "${!CONFIGS[@]}"; do
  cfg="${CONFIGS[$i]}"
  first_flag=""
  if [ "$i" -eq 0 ]; then
    mode_args="--out $OUT"
  else
    mode_args="--out $OUT --append"
  fi
  echo ">>> Extracting: $cfg"
  python3 ml/pipeline/feature_extractor.py \
    --results-dir results \
    --config "$cfg" \
    --runs 0 \
    --window-ms 10 \
    --sim-time-ms 150 \
    --label 1 \
    $mode_args
done

echo "Done. Row count:"
wc -l "$OUT"
