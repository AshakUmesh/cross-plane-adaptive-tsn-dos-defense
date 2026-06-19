package src.attacks;

import src.attacks.LowAndSlowDriftAttack;
import src.psfp.FlowMeter;
import src.psfp.TestSink;

//
// LowAndSlowDriftAttackTest — standalone harness for Gap 3 proof
//
// Wiring:  LowAndSlowDriftAttack → FlowMeter → TestSink
//
// FlowMeter set to AV1 limits from Luo 2021 Table 7:
//   CIR = 22 Mbps, CBS = 5004B
//
// What to observe:
//   FlowMeter.greenFrames  = ALL frames (rate always < CIR throughout)
//   FlowMeter.redFrames    = 0          (rate drifts DOWN, never spikes UP)
//   TestSink.receivedBytes = green * 500B
//
// This test proves the FlowMeter side of the three-way evasion:
//   meterRedFrames = 0 even though the attacker's rate is drifting.
//
// The gate-drop behaviour (frames crossing the guard band) is only
// visible in the full Luo2021Network where TAS/StreamGate is active.
// Run [Config LowAndSlowDriftAttack] in the full network for that result.
//
// Run with sim-time-limit = 150ms.
// Key results:
//   redFrames = 0              → FlowMeter blind (confirms rate evasion)
//   EV_INFO log "finalDrift"   → verify 150ms × 0.09us/pkt = ~135-150us total drift
//   EV_INFO phase log per 10ms → observe phase_offset monotonic increase
//
network LowAndSlowDriftAttackTest
{
    submodules:

        attacker: LowAndSlowDriftAttack {
            parameters:
                attackStartTime = 0s;
                nominalInterval = 90us;    // AV1 declared period
                driftPerPacket  = 0.09us;  // 0.5us/cycle × (90us/500us)
                payloadSize     = 500;     // Exactly nominal — passes StreamFilter
                streamId        = 5;
        }

        meter: FlowMeter {
            parameters:
                cir = 22000000;   // 22 Mbps — AV1 CIR (Luo Table 7)
                cbs = 5004;       // 5004 B  — AV1 CBS (Luo Table 7)
        }

        sink: TestSink;

    connections:
        attacker.out --> meter.in;
        meter.out    --> sink.in;
}
