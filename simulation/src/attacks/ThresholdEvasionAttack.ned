package src.attacks;

//
// ThresholdEvasionAttack — V3 Static Threshold Misconfiguration Exploit
//
// Sends frames that permanently stay below EVERY Luo 2021 PSFP threshold:
//
//   StreamFilter check:  frame size = 529B < maxMsdu (530B) → PASS
//   FlowMeter check:     rate = 21.93 Mbps < CIR (22 Mbps)  → GREEN always
//                        token bucket net gain = +9067 B/s    → never RED
//
// Luo 2021 paper quote: "if the traffic is discarded by the accurately
// configured PSFP, there must be abnormal traffic" — this logic fails
// completely when the attacker stays below all configured thresholds.
//
// Expected simulation results:
//   gateDrops      = 0      (size check always passes)
//   meterRedFrames = 0      (rate always below CIR)
//   qciAlarm       = false  (no PSFP violation ever triggered)
//   AV1 E2E delay  = INCREASED (21.93 Mbps of contention on AV1 port)
//
// Default values match Luo 2021 Table 7 (AV1 stream limits):
//   maxMsdu = 530B  → payloadSize = 529B
//   CIR     = 22 Mbps → interval = 193us → 21.927 Mbps
//   CBS     = 5004B (not exploited — rate evasion keeps bucket full)
//
simple ThresholdEvasionAttack
{
    parameters:
        // When to start — default 1ms lets the network settle to steady-state
        // before the attack begins, so delay measurements are clean.
        double attackStartTime @unit(s) = default(0.001s);

        // Inter-frame interval.
        // 193us → 21.927 Mbps = CIR(22 Mbps) - 73kbps headroom.
        // Token bucket refills at 22 Mbps, drains at 21.927 Mbps → net gain
        // = +9067 B/s → bucket always positive → all frames GREEN → zero alarms.
        //
        // To run the CBS-exhaustion variant (partial detection experiment):
        //   set attackInterval = 5us  → ~848 Mbps burst → CBS gone in 1 frame
        //   This shows WHEN Luo eventually detects vs what YOUR detector catches first.
        double attackInterval @unit(s) = default(193us);

        // Frame size in bytes. Must be < 530 (maxMsdu) to evade StreamFilter.
        // Default 529 = maxMsdu - 1: maximises damage while guaranteeing evasion.
        int payloadSize = default(529);

        // Stream tag copied to each packet for statistics collection.
        // 5 = attack stream (matches PCP=5 in omnetpp.ini).
        int streamId = default(5);

    gates:
        output out;
}
