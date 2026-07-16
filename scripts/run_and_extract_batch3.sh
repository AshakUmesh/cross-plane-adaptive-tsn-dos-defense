#!/bin/bash
OMNET_BIN="./out/clang-release/luo2021"
NED_PATH="/home/ashakumesh/research/omnetpp-6.4.0/samples/inet/src"
LIB_PATH="/home/ashakumesh/research/omnetpp-6.4.0/samples/inet/src/libINET.so"
CSV="adaptive_results_policy_accurate.csv"

echo "Attack,Static_Packets,Adaptive_Packets,Reduction_Count,Reduction_Pct" > "$CSV"

CONFIGS=(
  "GCLPhaseAttack"
  "GateBoundaryProximityAttack"
  "WindowBoundaryQueuingAttack"
)

for cfg in "${CONFIGS[@]}"; do
  echo ">>> Running $cfg (static)"
  $OMNET_BIN -u Cmdenv -n .:$NED_PATH -l $LIB_PATH -c "$cfg" -r 0 omnetpp.ini > /tmp/${cfg}_static2.log 2>&1

  echo ">>> Running ${cfg}_Adaptive (policy-accurate)"
  $OMNET_BIN -u Cmdenv -n .:$NED_PATH -l $LIB_PATH -c "${cfg}_Adaptive" -r 0 omnetpp.ini > /tmp/${cfg}_adaptive2.log 2>&1

  static_file="results/${cfg}-#0.sca"
  adaptive_file="results/${cfg}_Adaptive-#0.sca"

  static_count=$(grep "centralHost.app\[4\].sink packets:count" "$static_file" | awk '{print $NF}')
  adaptive_count=$(grep "centralHost.app\[4\].sink packets:count" "$adaptive_file" | awk '{print $NF}')

  if [ -z "$static_count" ] || [ -z "$adaptive_count" ]; then
    echo "!!! COULD NOT EXTRACT COUNT for $cfg"
    echo "$cfg,ERROR,ERROR,ERROR,ERROR" >> "$CSV"
    continue
  fi

  reduction=$((static_count - adaptive_count))
  pct=$(python3 -c "print(f'{($static_count - $adaptive_count) / $static_count * 100:.1f}')")

  echo "$cfg,$static_count,$adaptive_count,$reduction,$pct" >> "$CSV"
  echo ">>> $cfg: $static_count -> $adaptive_count (-$pct%)"
done

echo ""
cat "$CSV"
