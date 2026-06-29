#ifndef __ATTACKS_THRESHOLDEVASIONATTACK_H
#define __ATTACKS_THRESHOLDEVASIONATTACK_H

#include <omnetpp.h>

using namespace omnetpp;

/**
 * ThresholdEvasionAttack — V3 vulnerability proof module
 *
 * Attack model (Vulnerability V3 — Static Threshold Misconfiguration Exploitation):
 *
 *   Luo 2021 configures ALL PSFP thresholds once at design time and never
 *   changes them (paper quote: "the configuration of the parameters in PSFP
 *   is deterministic at the beginning").  An attacker who reads those values
 *   can stay permanently below every threshold and sustain a damaging traffic
 *   level that generates ZERO alarms in Luo's ADS.
 *
 *   Two simultaneous evasions:
 *     1. Size evasion:  frame = maxMsdu-1 bytes (529B) → StreamFilter PASS always
 *     2. Rate evasion:  rate  = CIR - δ  (21.9 Mbps) → FlowMeter GREEN always
 *                       token bucket refills faster than it drains → never RED
 *
 *   Net effect on the network:
 *     - Attacker occupies ~21.9 Mbps of the shared AV1 port bandwidth
 *     - AV1 camera stream (needs ~6.4 Mbps) faces sustained queue contention
 *     - AV1 E2E delay increases; Worst-Case Delay (WCD) degrades
 *     - Luo counters: gateDrops=0, meterRedFrames=0, qciAlarm=false — always
 *
 *   What YOUR ML detector sees (why IsoForest catches it):
 *     - mean_frame_size  = 529B  (vs benign 500B — trained distribution shift)
 *     - frame_count/10ms = 52    (vs benign 111 at 90us interval)
 *     - mean_IAT         = 193us (vs benign 90us — different cadence)
 *     - sustained_rate   = 21.93 Mbps from a node that sends 0 in baseline
 *     These four features collectively are a strong IsoForest anomaly.
 *
 * Parameters:
 *   attackStartTime  — when to start (default: 1ms, after baseline settles)
 *   attackInterval   — inter-frame interval = 193us → 21.93 Mbps (default)
 *   payloadSize      — must be < maxMsdu; default 529 = maxMsdu-1
 *   streamId         — packet tag for receiver statistics (default: 5)
 */
class ThresholdEvasionAttack : public cSimpleModule
{
  private:
    cMessage  *sendTimer;

    simtime_t  attackStartTime;
    simtime_t  attackInterval;   // 193us → 21.93 Mbps just below 22 Mbps CIR

    int        payloadSize;      // 529B → just below 530B maxMsdu
    int        streamId;

  protected:
    virtual void initialize()                   override;
    virtual void handleMessage(cMessage *msg)   override;
    virtual void finish()                       override;
};

#endif // __ATTACKS_THRESHOLDEVASIONATTACK_H
