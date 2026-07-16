#!/bin/bash
# Run from luo2021/ (where results/ lives). Extractor is in ml/pipeline/.
set -u
EX=ml/pipeline/combined_feature_extractor.py
RESULTS_DIR=results
WIN_MS=10
SIM_MS=150
BENIGN_RUNS="0-19"
ATTACK_RUNS="0"

DATA_SCHED_CONFIGS=(
  "BenignDiverse:0" "GCLPhaseAttack:1" "AggregateLoadAttack:2"
  "ThresholdEvasionAttack:3" "SustainedNearCIRAttack:4" "LowAndSlowDriftAttack:5"
  "CBSBoundaryAttack:6" "CBSExhaustionAttack:7" "QueueBuildingAttack:8"
  "ScheduleAwareBurstAttack:9" "GateBoundaryProximityAttack:10"
  "WindowBoundaryQueuingAttack:11"
)
GPTP_CONFIGS=(
  "BenignDiverse_gPTP_Working:0" "GateBoundaryProximityAttack_gPTP:10"
)
OUT_MAIN=combined_features_multiclass.csv
OUT_FUSED=combined_15_fused.csv

echo "=== PART 1: data+schedule -> $OUT_MAIN ==="
rm -f "$OUT_MAIN"; first=1
for entry in "${DATA_SCHED_CONFIGS[@]}"; do
  cfg="${entry%%:*}"; lbl="${entry##*:}"
  runs="$ATTACK_RUNS"; [ "$cfg" = "BenignDiverse" ] && runs="$BENIGN_RUNS"
  echo "--- $cfg (label=$lbl, runs=$runs) ---"
  if [ $first -eq 1 ]; then
    python3 "$EX" --results-dir "$RESULTS_DIR" --config "$cfg" --runs "$runs" \
      --window-ms $WIN_MS --sim-time-ms $SIM_MS --label "$lbl" \
      --planes data,schedule --out "$OUT_MAIN"; first=0
  else
    python3 "$EX" --results-dir "$RESULTS_DIR" --config "$cfg" --runs "$runs" \
      --window-ms $WIN_MS --sim-time-ms $SIM_MS --label "$lbl" \
      --planes data,schedule --out "$OUT_MAIN" --append
  fi
done

echo "=== PART 2: data+schedule+timesync -> $OUT_FUSED ==="
rm -f "$OUT_FUSED"; first=1
for entry in "${GPTP_CONFIGS[@]}"; do
  cfg="${entry%%:*}"; lbl="${entry##*:}"
  echo "--- $cfg (label=$lbl) ---"
  if [ $first -eq 1 ]; then
    python3 "$EX" --results-dir "$RESULTS_DIR" --config "$cfg" --runs "$BENIGN_RUNS" \
      --window-ms $WIN_MS --sim-time-ms $SIM_MS --label "$lbl" \
      --planes data,schedule,timesync --out "$OUT_FUSED"; first=0
  else
    python3 "$EX" --results-dir "$RESULTS_DIR" --config "$cfg" --runs "$BENIGN_RUNS" \
      --window-ms $WIN_MS --sim-time-ms $SIM_MS --label "$lbl" \
      --planes data,schedule,timesync --out "$OUT_FUSED" --append
  fi
done

echo "=== DONE ==="
for f in "$OUT_MAIN" "$OUT_FUSED"; do
  [ -f "$f" ] && echo "  $f : $(($(wc -l < "$f") - 1)) rows"
done
