package src.attacks;

import src.attacks.GCLPhaseAttack;
import src.psfp.FlowMeter;
import src.psfp.TestSink;

//
// GCLPhaseAttackTest — standalone harness
//
// Wiring:  GCLPhaseAttack → FlowMeter → TestSink
//
// What to observe:
//   - FlowMeter.greenFrames: all frames during CBS window (≈9 at 529B default)
//   - FlowMeter.redFrames:   frames after CBS exhausted
//   - TestSink.receivedFrames: total frames that reached the sink
//
// Run with sim-time-limit = 5ms to capture a few hundred bursts.
// Compare greenFrames count to burstSize to measure the CBS absorption gap
// (this is the "N free frames" number for your thesis table).
//
network GCLPhaseAttackTest
{
    submodules:

        attacker: GCLPhaseAttack {
            parameters:
                attackStartTime  = 0s;
                cyclePeriod      = 500us;
                gateOpenStart    = 125us;
                gateOpenEnd      = 450us;
                burstSize        = 8;
                payloadSize      = 529;   // 1B below maxMsdu — evades StreamFilter
                streamId         = 5;
        }

        meter: FlowMeter {
            parameters:
                cir = 22000000;   // 22 Mbps — AV1 CIR from Luo 2021 Table 7
                cbs = 5004;       // 5004 B  — AV1 CBS from Luo 2021 Table 7
        }

        sink: TestSink;

    connections:
        attacker.out --> meter.in;
        meter.out    --> sink.in;
}
