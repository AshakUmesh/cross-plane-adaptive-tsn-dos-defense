package src.attacks;

//
// LowAndSlowDriftAttack — Gap 3: Memoryless StreamGate Exploitation
//
// Sends frames that are INDIVIDUALLY INDISTINGUISHABLE from legitimate
// AV1 traffic at every point in time, but whose arrival PHASE within
// the GCL cycle drifts monotonically toward the guard band.
//
// The StreamGate is stateless — it only sees the present frame.
// It cannot detect a trend spread across hundreds of cycles.
// This is the fundamental architectural gap this attack proves.
//
// -----------------------------------------------------------------------
// THREE-WAY EVASION (why Luo 2021 never raises an alarm):
//
//   1. StreamFilter MSDU check:
//      payloadSize = 500B = exactly nominal AV1 frame size
//      Limit = 530B → PASS on every frame throughout the entire simulation.
//
//   2. FlowMeter token bucket check:
//      Effective rate starts at 44.44 Mbps, drifts DOWN to ~22 Mbps by 150ms.
//      CIR = 22 Mbps per AV1 stream → rate stays below CIR throughout.
//      meterRedFrames = 0. Always GREEN.
//
//   3. StreamGate timing check:
//      Each individual frame is evaluated independently.
//      Early frames: clearly inside window (phase ≈ 280-350us) → PASS.
//      Late frames: as phase drifts toward 450us, occasional frames
//      cross into the guard band (450-500us) → FAIL.
//      But failures are sparse and gradual — never a spike.
//      Luo's static drop-count threshold is never crossed at any instant.
//
// -----------------------------------------------------------------------
// DETECTION REQUIRES TEMPORAL REASONING:
//
//   Luo 2021: counts drops per instant → blind to gradual drift
//   Your LSTM: sees sequence of phase_offset_mean values per 10ms window
//              → detects monotonic increase as attack signature
//   Your IsoForest: flags windows where phase_offset_mean deviates from
//                   benign training distribution (starts ~window 8)
//
// -----------------------------------------------------------------------
// DEFAULT PARAMETERS — Luo 2021 Table 5/6/7 (AV1 stream):
//
//   nominalInterval = 90us   (AV1 declared period, Luo Table 5)
//   driftPerPacket  = 0.09us (= 0.5us/GCLcycle × 90us/500us)
//                    → 0.1% of nominal interval per packet
//                    → 0.5us drift per 500us GCL cycle
//                    → first gate drop at t ≈ 35ms (23% into simulation)
//                    → Luo alarm: never (gradual ramp, no spike)
//   payloadSize     = 500B   (nominal AV1, below 530B maxMsdu)
//
simple LowAndSlowDriftAttack
{
    parameters:
        // When to start. Default 1ms lets the baseline settle so that
        // the early-phase feature vectors (benign region) are clean.
        double attackStartTime @unit(s) = default(0.001s);

        // Nominal inter-frame interval — MUST match the legitimate stream's
        // declared period. Default 90us = AV1 period (Luo Table 5).
        // At t=0 the attacker is indistinguishable from a real AV1 node.
        double nominalInterval @unit(s) = default(90us);

        // Drift added to the interval on every packet send.
        //
        // Derivation from driftPerCycle = 0.5us:
        //   driftPerPacket = driftPerCycle × (nominalInterval / cyclePeriod)
        //                  = 0.5us × (90us / 500us) = 0.09us
        //
        // Effect: after N packets, currentInterval = 90us + N × 0.09us
        //   After 389 packets (35ms): drift = 35us → last frame hits 450us edge
        //   After 1000 packets (90ms): drift = 90us → strong degradation
        //   After 1666 packets (150ms): drift = 150us → full cycle disruption
        //
        // To make attack more aggressive (for comparison experiment):
        //   set driftPerPacket = 0.36us → first drop at ~8.75ms
        //   (equivalent to original 2us/cycle, too fast for 'low and slow')
        double driftPerPacket @unit(s) = default(0.09us);

        // Frame size. Must equal the legitimate stream's size to evade
        // StreamFilter MSDU check. Default 500B = AV1 nominal (Luo Table 5).
        int payloadSize = default(500);

        // Stream tag for statistics. 5 = attack stream (PCP=5 in ini).
        int streamId = default(5);

    gates:
        output out;
}
