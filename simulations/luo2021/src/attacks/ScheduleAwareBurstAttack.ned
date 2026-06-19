package src.attacks;

//
// ScheduleAwareBurstAttack — Gap 4: TAS Schedule Knowledge Exploitation
//
// An attacker who has learned the GCL schedule fires a coordinated burst
// at the exact gate-open moment, filling the shared egress queue before
// legitimate AV1/AV2 frames can occupy it.
//
// The attack is engineered to satisfy ALL three PSFP checks simultaneously:
//
//   StreamFilter MSDU:    529B < 530B maxMsdu          → PASS always
//   FlowMeter token:      3703B < 5004B CBS             → all GREEN
//                         16.28 Mbps < 22 Mbps CIR     → never RED
//   StreamGate timing:    burst at t=127µs, gate open   → PASS always
//                         at t=125µs
//
// Net result: 7 attack frames (296.84µs transmission) occupy the shared
// egress queue at gate-open. Legitimate AV1 frame arriving at t=190µs
// finds 6 frames still ahead of it → +253.92µs queueing delay per burst,
// repeating every 1.82ms throughout the simulation.
//
// Luo 2021 sees: gateDrops=0, meterRedFrames=0, qciAlarm=false — always.
//
// Your IsoForest catches it from window 1:
//   burst_length = 7  (vs benign = 1)  ← strongest single feature
//   IAT_variance = 1,579,427µs²        ← extreme bimodal distribution
//
// -----------------------------------------------------------------------
// PARAMETER DERIVATION (Luo 2021 Table 6/7):
//
//   burstSize = 7:
//     7 × 529B = 3703B < CBS(5004B) → all frames GREEN
//     7 × 42.32µs tx = 296.24µs < window(325µs) → all frames pass gate
//
//   interburstInterval = 1820µs:
//     CBS(5004B) / CIR(22Mbps/8) = 5004 / 2750000 B/s = 1.820ms
//     Token bucket fully refills between bursts → next burst is all-GREEN
//
//   burstGuardOffset = 2µs:
//     Fires 2µs after gateOpenOffset(125µs) = at t=127µs per cycle
//     Avoids the exact gate-open edge to prevent any scheduling race
//
simple ScheduleAwareBurstAttack
{
    parameters:
        // Start time — 1ms default lets baseline settle before attack begins.
        double attackStartTime @unit(s) = default(0.001s);

        // GCL cycle period — must match Luo 2021 Table 6 (500µs).
        double cyclePeriod @unit(s) = default(500us);

        // Q0-Q6 gate-open offset within cycle — Luo Table 6: 125µs.
        double gateOpenOffset @unit(s) = default(125us);

        // How long after gate opens to fire the burst.
        // 2µs avoids the exact gate-open edge for scheduling safety.
        double burstGuardOffset @unit(s) = default(2us);

        // Number of frames per burst.
        //
        // Constraints:
        //   burstSize × payloadSize ≤ CBS(5004B) for all-GREEN treatment
        //   burstSize × txTime(payloadSize) < window(325µs) for gate passage
        //
        // Verified:  7 × 529B = 3703B < 5004B ✓
        //            7 × 42.32µs = 296.24µs < 325µs ✓
        //
        // Increase to 9 for the "partial detection" experiment:
        //   9 × 529B = 4761B < 5004B (still GREEN)
        //   9 × 42.32µs = 380.88µs > 325µs (last 2 frames hit guard band)
        //   Shows Luo's gate drop counter, but PSFP meter still silent.
        int burstSize = default(7);

        // Time between consecutive frames within a burst.
        // 0.1µs ≈ back-to-back at 100Mbps link rate.
        // The actual inter-frame gap at the wire is dominated by frame
        // transmission time (42.32µs per 529B frame at 100Mbps), so this
        // parameter mainly controls scheduling resolution.
        double intraburstSpacing @unit(s) = default(0.1us);

        // Time between burst starts = CBS token refill time.
        //   CBS(5004B) / (CIR(22Mbps) / 8 bits/byte) = 1.820ms
        // This ensures the token bucket is full at each burst start
        // → every burst gets full GREEN treatment → meterRedFrames = 0.
        double interburstInterval @unit(s) = default(1820us);

        // Per-frame payload in bytes. Must satisfy:
        //   payloadSize < maxMsdu(530B)            — StreamFilter evasion
        //   burstSize × payloadSize < CBS(5004B)   — FlowMeter evasion
        //   payloadSize × 8 / 100Mbps × burstSize < window(325µs) — gate evasion
        int payloadSize = default(529);

        // Stream identifier for statistics collection.
        // 5 = attack stream (matches PCP=5 in omnetpp.ini).
        int streamId = default(5);

    gates:
        output out;
}
