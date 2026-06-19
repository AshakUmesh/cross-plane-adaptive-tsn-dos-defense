package src.attacks;

import src.attacks.ScheduleAwareBurstAttack;
import src.psfp.FlowMeter;
import src.psfp.TestSink;

//
// ScheduleAwareBurstAttackTest — standalone harness for Gap 4 proof
//
// Wiring:  ScheduleAwareBurstAttack → FlowMeter → TestSink
//
// FlowMeter at AV1 stream limits (Luo 2021 Table 7):
//   CIR = 22 Mbps, CBS = 5004B
//
// What to observe in this standalone test (FlowMeter side):
//   FlowMeter.greenFrames  = ALL frames (3703B/burst < CBS 5004B)
//   FlowMeter.redFrames    = 0          (avg rate 16.28 < CIR 22 Mbps)
//   TestSink.receivedBytes = 529 × totalFrames
//   EV_INFO "totalBursts" ≈ 82          (150ms / 1.82ms)
//
// NOTE: queue contention (the primary damage mechanism) is only visible
// in the full Luo2021Network where AV1/AV2/Radar share the egress queue.
// Run [Config ScheduleAwareBurstAttack] in the full network for:
//   - AV1/AV2 E2E delay spike (+253.92µs per burst occurrence)
//   - gateDrops = 0 (all frames inside open window)
//   - qciAlarm = false (all PSFP checks pass)
//
// Run with sim-time-limit = 150ms.
// Key result: redFrames = 0 throughout → FlowMeter completely blind.
//
network ScheduleAwareBurstAttackTest
{
    submodules:

        attacker: ScheduleAwareBurstAttack {
            parameters:
                attackStartTime    = 0s;
                cyclePeriod        = 500us;
                gateOpenOffset     = 125us;
                burstGuardOffset   = 2us;
                burstSize          = 7;      // 7 × 529B = 3703B < CBS 5004B
                intraburstSpacing  = 0.1us;  // near back-to-back
                interburstInterval = 1820us; // CBS refill time
                payloadSize        = 529;    // maxMsdu - 1
                streamId           = 5;
        }

        meter: FlowMeter {
            parameters:
                cir = 22000000;   // 22 Mbps  — AV1 CIR (Luo Table 7)
                cbs = 5004;       // 5004 B   — AV1 CBS (Luo Table 7)
        }

        sink: TestSink;

    connections:
        attacker.out --> meter.in;
        meter.out    --> sink.in;
}
