#ifndef __ATTACKS_LOWANDSLOWDRIFTATTACK_H
#define __ATTACKS_LOWANDSLOWDRIFTATTACK_H

#include <omnetpp.h>

using namespace omnetpp;

/**
 * LowAndSlowDriftAttack — Gap 3 vulnerability proof module
 *
 * ==========================================================================
 * VULNERABILITY: Luo 2021 StreamGate is MEMORYLESS and STATELESS.
 *
 * Luo's gate checks one thing per frame:
 *   "Did this frame arrive inside the configured GCL time window?"
 *
 * It NEVER checks:
 *   "Is this stream's phase offset drifting across GCL cycles?"
 *   "Is the inter-arrival interval consistent with the declared period?"
 *   "Is the cumulative drift trending toward the guard band?"
 *
 * A memoryless gate cannot detect a trend. It can only react to the
 * present moment. This is the architectural blind spot this attack exploits.
 * ==========================================================================
 *
 * ATTACK MODEL — Low-and-Slow Phase Drift:
 *
 *   The attacker mimics a legitimate AV1 stream exactly:
 *     - Same frame size: 500B (passes StreamFilter, size=nominal)
 *     - Same nominal rate: ~44.27 Mbps (below CIR=22Mbps per stream)
 *     - Same PCP tag: 4 (Q0-Q6, open 125-450us)
 *
 *   But adds a tiny increment to the inter-frame interval each packet:
 *     - nominalInterval = 90us (AV1 declared period)
 *     - driftPerPacket  = 0.09us (= 0.5us/cycle × 90us/500us)
 *
 *   This causes the arrival phase of frames within each GCL cycle to
 *   DRIFT SLOWLY toward the guard band (450-500us):
 *
 *     t=0ms:   phase ≈ 280us  [deep inside window]  → gate: PASS
 *     t=35ms:  phase ≈ 315us  [still inside]         → gate: PASS
 *     t=50ms:  phase ≈ 330us  [moving toward edge]   → gate: PASS
 *     t=80ms:  phase ≈ 350us  [getting close]        → gate: PASS (mostly)
 *     t=120ms: phase ≈ 390us  [near edge]             → gate: occasional PASS/FAIL
 *     t=150ms: phase ≈ 420us  [close to 450us limit]  → gate: degrading
 *
 *   Rate deviation: 0.39% (44.27 vs 44.44 Mbps) — invisible to FlowMeter.
 *   Frame size: 500B = exactly nominal — invisible to StreamFilter.
 *   Per-frame: every decision is borderline-normal — invisible to Luo.
 *   Over time: cumulative effect degrades AV1 WCD — visible to YOUR LSTM.
 *
 * ==========================================================================
 * WHY THIS IS STRONGER THAN gPTP SPOOFING (V2):
 *
 *   gPTP spoofing requires:
 *     - Access to the physical network to inject Announce messages
 *     - Crafting a better-quality clock advertisement
 *     - Risk of detection at the gPTP layer (clock anomaly logs)
 *
 *   Low-and-slow drift requires:
 *     - ONLY the ability to send Ethernet frames (any connected node)
 *     - No knowledge of or access to the gPTP clock infrastructure
 *     - No detectable anomaly at any individual time step
 *     - Entirely Layer-2 — no special privileges
 *
 * ==========================================================================
 * WHAT LUO 2021 SEES vs WHAT YOUR DETECTOR SEES:
 *
 *   Luo counter     | 0ms      | 35ms     | 80ms     | 150ms
 *   ----------------+----------+----------+----------+----------
 *   gateDrops       | 0        | ~0       | ~2/ms    | ~4/ms
 *   meterRedFrames  | 0        | 0        | 0        | 0
 *   qciAlarm        | false    | false    | false    | false
 *   [Luo conclusion: no attack — all counters below static thresholds]
 *
 *   Your feature    | Window 1 | Window 5 | Window 10| Window 15
 *   ----------------+----------+----------+----------+----------
 *   phase_offset_µ  | 280us    | 320us    | 370us    | 420us  ← LINEAR TREND
 *   phase_offset_σ  | low      | low      | mid      | high   ← VARIANCE RISE
 *   gate_drop_rate  | 0        | 0        | ~2/ms    | ~4/ms  ← RAMP
 *   IAT_variance    | low      | low      | rising   | high   ← JITTER RISE
 *   [LSTM conclusion: monotonic drift in phase_offset_µ = ATTACK at window 4+]
 *
 * Parameters:
 *   attackStartTime   — when attack begins (default: 0.001s)
 *   nominalInterval   — declared AV1 inter-frame interval (default: 90us)
 *   driftPerPacket    — extra interval added per packet (default: 0.09us)
 *                       = 0.5us/cycle × (90us/500us cycle) = 0.09us/packet
 *   payloadSize       — must match AV1 nominal to evade StreamFilter (default: 500B)
 *   streamId          — packet tag for statistics (default: 5)
 */
class LowAndSlowDriftAttack : public cSimpleModule
{
  private:
    cMessage  *sendTimer;

    simtime_t  attackStartTime;
    simtime_t  nominalInterval;    // 90us — declared AV1 period
    simtime_t  driftPerPacket;     // 0.09us — added to interval each packet

    int        payloadSize;        // 500B — exactly nominal, evades StreamFilter
    int        streamId;

    // State: current effective interval (grows by driftPerPacket each send)
    simtime_t  currentInterval;

    // Diagnostics: track accumulated drift for EV_INFO logging
    long       packetsSent;
    simtime_t  totalDrift;

  protected:
    virtual void initialize()                   override;
    virtual void handleMessage(cMessage *msg)   override;
    virtual void finish()                       override;
};

#endif // __ATTACKS_LOWANDSLOWDRIFTATTACK_H
