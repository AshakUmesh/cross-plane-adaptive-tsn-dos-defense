#ifndef __ATTACKS_SCHEDULEAWAREBURSTATTACK_H
#define __ATTACKS_SCHEDULEAWAREBURSTATTACK_H

#include <omnetpp.h>

using namespace omnetpp;

/**
 * ScheduleAwareBurstAttack — Gap 4 vulnerability proof module
 *
 * ==========================================================================
 * VULNERABILITY: Luo 2021 PSFP evaluates each stream independently.
 *
 * The FlowMeter tracks a token bucket PER STREAM.
 * The StreamGate checks timing PER FRAME.
 * Neither mechanism has any knowledge of:
 *   - The shared egress queue depth at the moment of transmission
 *   - What other streams are sending simultaneously
 *   - Whether a burst will displace legitimate frames from the shared queue
 *
 * All Q0-Q6 streams (AV1, AV2, Radar, attack) share the SAME gate-open
 * window (125-450µs). An attacker who learns this schedule can inject a
 * tight burst at the EXACT gate-open moment, filling the shared egress
 * queue before legitimate AV1/AV2 frames can occupy it.
 * ==========================================================================
 *
 * ATTACK MODEL — Schedule-Aware Coordinated Bursting:
 *
 *   The attacker knows the GCL schedule (trivially observable on shared
 *   Ethernet bus via passive sniffing). Every 1.82ms (CBS token refill
 *   time), it fires a burst of 7 × 529B frames at t = gateOpenOffset + 2µs.
 *
 *   The burst is engineered to satisfy ALL three PSFP checks simultaneously:
 *
 *   Check 1 — StreamFilter MSDU:
 *     Frame size = 529B = maxMsdu - 1 → PASS on every frame.
 *
 *   Check 2 — FlowMeter token bucket:
 *     Burst bytes = 7 × 529B = 3703B < CBS (5004B) → all 7 frames GREEN.
 *     Average rate = 16.28 Mbps < CIR (22 Mbps) → bucket never empties.
 *     meterRedFrames = 0. Always.
 *
 *   Check 3 — StreamGate timing:
 *     All frames arrive at t = 127µs into the cycle (gateOpenOffset + 2µs).
 *     Gate opens at 125µs → PASS on every frame.
 *     gateDrops = 0. Always.
 *
 *   Net effect: 7 attack frames (296.84µs of back-to-back transmission) fill
 *   the shared egress queue at gate-open. Legitimate AV1 (next frame at
 *   t=190µs) finds 6 attack frames still transmitting → 253.92µs of extra
 *   queueing delay per burst, every 1.82ms throughout the simulation.
 *
 * ==========================================================================
 * WHAT MAKES THIS DISTINCT FROM V1 (GCLPhaseAttack):
 *
 *   GCLPhaseAttack: uniform inter-frame spacing (~40µs) throughout the
 *                   open window. Rate is continuously elevated.
 *
 *   Gap 4:          bimodal IAT distribution:
 *                     intra-burst IAT ≈ 42.4µs (frame tx time + 0.1µs)
 *                     inter-burst gap ≈ 1820µs (CBS refill period)
 *                   IAT ratio = 43× — IAT_variance is enormous.
 *                   burst_length = 7 consecutive frames — far outside
 *                   benign training distribution (benign burst_length = 1).
 *                   IsoForest catches it from the FIRST 10ms window because
 *                   burst_length and IAT_variance are immediate outliers.
 *
 * ==========================================================================
 * WHAT LUO 2021 SEES vs WHAT YOUR DETECTOR SEES:
 *
 *   Luo counter         Value       Reason
 *   ------------------  ------      ------------------------------------
 *   gateDrops           0           burst within open window 125-450µs
 *   meterRedFrames      0           3703B < CBS 5004B, 16.28 < CIR 22Mbps
 *   filterDrops         0           529B < maxMsdu 530B
 *   qciAlarm            false       no threshold crossed at any point
 *
 *   Your feature        Benign      Attack
 *   ------------------  --------    ------------------------------------
 *   burst_length        1           7  ← PRIMARY detection feature
 *   IAT_variance        low         1,579,427µs² ← EXTREME outlier
 *   mean_IAT            90µs        BIMODAL (42µs / 1820µs)
 *   mean_frame_size     500B        529B
 *   phase_offset_µ      stable      SPIKE at exactly t=127µs every 1.82ms
 *   queue_depth_max     ~2          7+ per burst
 *
 * Parameters (all defaulting to Luo 2021 Table 6/7 values):
 *   attackStartTime     — when to start (default: 0.001s, after baseline settles)
 *   cyclePeriod         — GCL cycle period (default: 500µs)
 *   gateOpenOffset      — Q0-Q6 gate open time within cycle (default: 125µs)
 *   burstGuardOffset    — how far after gate open to send (default: 2µs)
 *   burstSize           — frames per burst (default: 7, fits 296.84µs < 325µs window)
 *   intraburstSpacing   — gap between frames in burst (default: 0.1µs ≈ back-to-back)
 *   interburstInterval  — gap between bursts = CBS refill time (default: 1820µs)
 *   payloadSize         — per-frame size in bytes (default: 529 = maxMsdu-1)
 *   streamId            — packet tag for statistics (default: 5)
 */
class ScheduleAwareBurstAttack : public cSimpleModule
{
  private:
    // Two-level scheduling: burstTimer fires per-frame within a burst;
    // burstTrigger fires to start each new burst.
    cMessage  *burstTrigger;    // fires to start a new burst cycle
    cMessage  *frameTimer;      // fires to send each frame within a burst

    // GCL geometry
    simtime_t  cyclePeriod;
    simtime_t  gateOpenOffset;
    simtime_t  burstGuardOffset; // delay after gate-open before first frame

    // Burst parameters
    int        burstSize;
    simtime_t  intraburstSpacing;
    simtime_t  interburstInterval;

    // Frame parameters
    int        payloadSize;
    int        streamId;

    // State
    simtime_t  attackStartTime;
    int        burstIndex;          // which frame in current burst (0..burstSize-1)
    long       totalBursts;
    long       totalFramesSent;

  protected:
    virtual void initialize()                   override;
    virtual void handleMessage(cMessage *msg)   override;
    virtual void finish()                       override;

  private:
    void sendBurstFrame();
    void scheduleBurstTrigger();   // schedule next burst start
};

#endif // __ATTACKS_SCHEDULEAWAREBURSTATTACK_H
