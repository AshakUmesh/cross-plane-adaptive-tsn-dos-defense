//
// TimingAttackApp.ned
// ───────────────────────────────────────────────────────────────────────────
// NED module definition for the V1 GCL-Phase Timing Attack application.
//
// All default values are taken directly from Luo 2021 (TSN for Automotive
// Ethernet, Table 7 & Table 8):
//   GCL period   : 500 µs
//   Q7 window    : 0–125 µs    (highest priority, not targeted by V1)
//   Q4/AV window : 125–450 µs  (target window — AV1/AV2 streams)
//   ALL-CLOSED   : 450–500 µs  (guard band)
//   AV1 VLAN     : 10, PCP=4
//   AV1 CIR      : 22 Mbps, CBS=5004 bytes, MSDU=530 bytes
//   AV1 declared interval: ~90 µs for 400–500 B frames at ~6.4 Mbps
//
// Author  : Ashak Umesh (M250691CS), NIT Calicut
// Project : Cross-Plane Adaptive DoS Defence for Automotive TSN
//

package luo2021;

//
// TimingAttackApp
// ───────────────────────────────────────────────────────────────────────────
// Implements the V1 vulnerability: sends at 10× declared AV1 rate but phases
// every frame inside the GCL gate-open window (125–450 µs). Luo 2021's gate
// check is binary and memoryless — it cannot detect burst patterns. The flow
// meter fires only after CBS=5004 bytes are consumed.
//
// Connect to a switch port that has AV1 stream access (same VLAN, same path).
//
simple TimingAttackApp
{
    parameters:
        // ── Attack timing ───────────────────────────────────────────────────
        double attackStartTime @unit(s) = default(0.050s);
            // Begin attack at t=50ms (after baseline established at t=0..50ms)

        double attackStopTime @unit(s) = default(0.150s);
            // End attack at t=150ms (gives 100ms of attack data)

        double attackInterval_us = default(9);
            // Inter-frame interval in µs. 9 µs = 10× the declared AV1 rate of 90 µs.
            // This is the core V1 parameter: a legitimate sender at 400B/90µs = ~35 Mbps
            // would violate CIR, but at 9µs/450B we are testing meter saturation timing.
            // NOTE: unit is µs (not nanoseconds). Multiply by 1e-6 to get seconds.

        // ── Frame parameters ────────────────────────────────────────────────
        int frameSize_bytes = default(450);
            // Attack frame payload size in bytes.
            // Must be < 530 (MSDU limit for AV ports in Luo 2021).
            // Keep between 400–500 B to match legitimate AV1 frame profile.

        // ── Stream identity (must match AV1 stream to pass stream filter) ───
        int targetVlanId = default(10);
            // VLAN ID for AV1 stream. Luo 2021 uses VLAN 10 for AV streams.

        int targetPcp = default(4);
            // Priority Code Point for AV1. PCP=4 maps to Traffic Class TC4
            // which is assigned to queue Q4 in Luo 2021's schedule.

        string targetDestMac = default("01:00:5E:00:00:01");
            // Destination MAC matching the AV1 stream's multicast group.
            // This is the value the PSFP StreamFilter checks.
            // MUST match the StreamFilter entry in the switch configuration.

        // ── GCL schedule parameters ─────────────────────────────────────────
        double gcl_period_us = default(500);
            // GCL hyperperiod in µs. Luo 2021 uses 500 µs = 500000 ns.

        double gcl_open_start_us = default(125);
            // Start of Q4/AV open window within the GCL cycle (µs).
            // From Luo 2021: Q7 occupies 0–125 µs, so AV window starts here.

        double gcl_open_end_us = default(450);
            // End of Q4/AV open window (µs).
            // From Luo 2021: ALL-CLOSED guard band is 450–500 µs.

        double phase_jitter_us = default(0.5);
            // ±Jitter added to each send time (µs) to model realistic
            // clock imperfection. Keep < 5 µs so frames stay inside window.
            // A perfectly-timed attacker would use 0, but 0.5 is realistic.

        // ── Display ─────────────────────────────────────────────────────────
        @display("i=device/laptop;is=s");

        @statistic[attackIAT_us](
            title="Attack Frame IAT (µs)";
            source=attackIAT_us;
            record=vector,stats;
            unit=µs;
        );
        @statistic[attackPhaseOffset_us](
            title="Attack Phase Offset in GCL Cycle (µs)";
            source=attackPhaseOffset_us;
            record=vector,stats;
            unit=µs;
        );
        @statistic[attackFramesPerWindow](
            title="Attack Frames per 10ms Window";
            source=attackFramesPerWindow;
            record=vector,stats;
        );

    gates:
        output out;   // connect to switch port input (via cable/eth channel)
}
