package src.attacks;

import src.attacks.ThresholdEvasionAttack;
import src.psfp.FlowMeter;
import src.psfp.TestSink;

//
// ThresholdEvasionAttackTest — standalone harness for V3 proof
//
// Wiring:  ThresholdEvasionAttack → FlowMeter → TestSink
//
// FlowMeter configured with AV1 limits from Luo 2021 Table 7:
//   CIR = 22 Mbps,  CBS = 5004B
//
// What to observe:
//   FlowMeter.greenFrames  = ALL frames  (rate 21.93 Mbps < CIR 22 Mbps)
//   FlowMeter.redFrames    = 0           (token bucket never empties)
//   TestSink.receivedBytes = 529 * greenFrames  (all reach sink)
//
// Run with sim-time-limit = 10ms to collect ~52 frames/window × 10 windows.
// Key result for thesis: redFrames = 0 throughout entire simulation.
// This proves: Luo's FlowMeter is blind to the sustained 21.93 Mbps attack.
//
// Compare against OversizeAttackTest where redFrames = all frames (CIR=0).
// The contrast is the vulnerability gap your thesis closes.
//
network ThresholdEvasionAttackTest
{
    submodules:

        attacker: ThresholdEvasionAttack {
            parameters:
                attackStartTime = 0s;
                attackInterval  = 193us;   // 21.93 Mbps — just below 22 Mbps CIR
                payloadSize     = 529;     // 529B — just below 530B maxMsdu
                streamId        = 5;
        }

        meter: FlowMeter {
            parameters:
                // AV1 limits from Luo 2021 Table 7
                cir = 22000000;   // 22 Mbps
                cbs = 5004;       // 5004 B
        }

        sink: TestSink;

    connections:
        attacker.out --> meter.in;
        meter.out    --> sink.in;
}
