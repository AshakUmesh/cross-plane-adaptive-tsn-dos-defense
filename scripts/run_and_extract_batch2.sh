#!/bin/bash
OMNET_BIN="./out/clang-release/luo2021"
NED_PATH="/home/ashakumesh/research/omnetpp-6.4.0/samples/inet/src"
LIB_PATH="/home/ashakumesh/research/omnetpp-6.4.0/samples/inet/src/libINET.so"
CSV="adaptive_results.csv"

CONFIGS=(
  "GCLPhaseAttack"
  "GateBoundaryProximityAttack"
  "WindowBoundaryQueuingAttack"
  "LowAndSlowDriftAttack"
)

for cfg in "${CONFIGS[@]}"; do
  echo ">>> Running $cfg (static)"
  $OMNET_BIN -u Cmdenv -n .:$NED_PATH -l $LIB_PATH -c "$cfg" -r 0 omnetpp.ini > /tmp/${cfg}_static.log 2>&1

  echo ">>> Running ${cfg}_Adaptive"
  $OMNET_BIN -u Cmdenv -n .:$NED_PATH -l $LIB_PATH -c "${cfg}_Adaptive" -r 0 omnetpp.ini > /tmp/${cfg}_adaptive.log 2>&1

  static_file="results/${cfg}-#0.sca"
  adaptive_file="results/${cfg}_Adaptive-#0.sca"

  if [ ! -f "$static_file" ] || [ ! -f "$adaptive_file" ]; then
    echo "!!! MISSING OUTPUT for $cfg — check /tmp/${cfg}_static.log and /tmp/${cfg}_adaptive.log"
    echo "$cfg,ERROR,ERROR,ERROR,ERROR" >> "$CSV"
    continue
  fi

  static_count=$(grep "centralHost.app\[4\].sink packets:count" "$static_file" | awk '{print $NF}')
  adaptive_count=$(grep "centralHost.app\[4\].sink packets:count" "$adaptive_file" | awk '{print $NF}')

  if [ -z "$static_count" ] || [ -z "$adaptive_count" ]; then
    echo "!!! COULD NOT EXTRACT COUNT for $cfg"
    echo "$cfg,$static_count,$adaptive_count,PARSE_ERROR,PARSE_ERROR" >> "$CSV"
    continue
  fi

  reduction=$((static_count - adaptive_count))
  pct=$(python3 -c "print(f'{($static_count - $adaptive_count) / $static_count * 100:.1f}')")

  echo "$cfg,$static_count,$adaptive_count,$reduction,$pct" >> "$CSV"
  echo ">>> $cfg: $static_count -> $adaptive_count (-$pct%)"
done

echo ""
echo "=== DONE. Full results: ==="
cat "$CSV"
