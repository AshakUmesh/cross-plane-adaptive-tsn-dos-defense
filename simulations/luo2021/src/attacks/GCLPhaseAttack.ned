package src.attacks;

//
// GCLPhaseAttack — Gate-Control-List Phase Burst Attack module
//
// Sends burstSize frames per GCL cycle, all timed to land inside the
// Q0-Q6 gate-open window (gateOpenStart..gateOpenEnd).
//
// Each frame is individually valid:
//   - arrival timestamp is inside the open window  → StreamGate: PASS
//   - byte length < maxMsdu (530B)                 → StreamFilter: PASS
//   - initial burst fits within CBS (5004B)        → FlowMeter: GREEN (initially)
//
// The gate never fires.  The flow meter fires only after CBS is exhausted
// (≈9 frames at 529B).  During those free frames, legitimate AV1/AV2
// traffic faces queue contention and measurable delay increase.
//
// This directly proves Vulnerability V1 (GCL-phase evasion) and V3
// (below-threshold evasion) from the thesis vulnerability analysis.
//
// Default parameter values match Luo 2021 Table 6 / Table 7.
//
simple GCLPhaseAttack
{
    parameters:
        // When the attack starts (seconds).
        // Default: 1ms — lets the baseline settle first.
        double attackStartTime @unit(s) = default(0.001s);

        // GCL cycle period — must match omnetpp.ini GCL configuration.
        // Luo 2021 Table 6: 500µs.
        double cyclePeriod @unit(s) = default(500us);

        // Start of the Q0-Q6 gate-open window within the cycle.
        // Luo 2021 Table 6: 125µs.
        double gateOpenStart @unit(s) = default(125us);

        // End of the Q0-Q6 gate-open window within the cycle.
        // Luo 2021 Table 6: 450µs (guard band starts at 450µs).
        double gateOpenEnd @unit(s) = default(450us);

        // Number of frames to send per gate-open window.
        // 8 frames × 529B = 4232B per cycle = ~8.5 Mbps
        // Well above normal AV1 rate (6.4 Mbps) but below CIR (22 Mbps).
        // Increase to 12-15 for the CBS saturation experiment.
        int burstSize = default(2);

        // Payload size in bytes.
        // MUST be < maxMsdu to evade the StreamFilter size check.
        // Luo 2021 Table 7: maxMsdu = 530B  →  use 529B.
        int payloadSize = default(529);

        // Stream identifier copied into each packet parameter.
        // Used by TestSink / statistics collection.
        // Set to 5 to match the "attack" stream in Luo2021Network.
        int streamId = default(5);

    gates:
        output out;
}	
