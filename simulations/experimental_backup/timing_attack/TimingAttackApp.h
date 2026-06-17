#ifndef __LUO2021_TIMINGATTACKAPP_H
#define __LUO2021_TIMINGATTACKAPP_H

/**
 * TimingAttackApp.h
 * ─────────────────────────────────────────────────────────────────────────────
 * V1 GCL-Phase Timing Attack — OMNeT++ Application Module
 *
 * Purpose
 * ───────
 * Implements the V1 vulnerability proof: an attacker who knows the GCL
 * schedule can flood at 10× the declared stream rate while keeping EVERY
 * individual frame inside the gate-open window. Luo 2021's binary gate
 * check passes each frame (correct window). Flow meter fires only after
 * CBS tokens (5004 bytes) are exhausted. During that burst-absorption
 * interval, legitimate AV1/AV2 streams starve.
 *
 * Attack parameters (matching Luo 2021 Table 7):
 *   Declared AV1 inter-arrival interval:  90 µs  (legitimate sender)
 *   Attack inter-arrival interval:         9 µs  (10× rate)
 *   Frame size:                        400–500 B  (same as AV1, passes MSDU=530)
 *   GCL open window (Q4/AV1 priority):  125–450 µs within 500 µs cycle
 *   Attack VLAN / Priority / DestMAC:   same as AV1 (passes stream filter)
 *
 * Key measurables this module produces:
 *   - Per-window frame count injected by attacker
 *   - Timestamps of each injected frame (for IAT calculation in Python)
 *   - Signal to enable/disable attack (attack active t=50ms … t=150ms)
 *
 * Build dependencies: INET 4.x (for EthernetFrame / L2 packet helpers)
 *
 * Author  : Ashak Umesh (M250691CS), NIT Calicut
 * Project : Cross-Plane Adaptive DoS Defence for Automotive TSN
 * Date    : June 2026
 */

#include <omnetpp.h>
#include "inet/common/INETDefs.h"
#include "inet/common/packet/Packet.h"
#include "inet/linklayer/common/MacAddress.h"
#include "inet/linklayer/common/Ieee802SapTag_m.h"
#include "inet/linklayer/ethernet/common/EthernetMacHeader_m.h"

using namespace omnetpp;
using namespace inet;

class TimingAttackApp : public cSimpleModule
{
  protected:
    // ─── NED parameters ──────────────────────────────────────────────────────
    double   attackStartTime;       // when to begin injecting (s), default 0.050
    double   attackStopTime;        // when to stop injecting (s),  default 0.150
    double   attackInterval_us;     // inter-frame interval (µs),   default 9 µs
    int      frameSize_bytes;       // payload size (bytes),         default 450
    int      targetVlanId;          // VLAN ID matching AV1 stream,  default 10
    int      targetPcp;             // Priority Code Point for AV1,  default 4
    MacAddress targetDestMac;       // DestMAC matching AV1 stream filter

    // GCL parameters for phase-alignment
    double   gcl_period_us;         // GCL cycle period (µs),        default 500
    double   gcl_open_start_us;     // window open offset (µs),      default 125
    double   gcl_open_end_us;       // window close offset (µs),     default 450
    double   phase_jitter_us;       // ±jitter to model real attacker (µs), default 0.5

    // ─── Internal state ───────────────────────────────────────────────────────
    cMessage *sendTimer    = nullptr;   // self-message: fire next attack frame
    cMessage *startSignal  = nullptr;   // self-message: arm attack at t=attackStart
    cMessage *stopSignal   = nullptr;   // self-message: disarm attack at t=attackStop
    bool      attackActive = false;

    simtime_t lastSendTime;             // track actual IAT for logging
    long      framesSentTotal   = 0;    // total injected frames
    long      framesThisWindow  = 0;    // frames in current 10ms stats window
    simtime_t windowStart;              // start of current 10ms window

    // ─── Statistics (recorded to .sca / .vec for Python analysis) ────────────
    cOutVector  iatVector;              // inter-arrival time of injected frames (µs)
    cOutVector  frameSizeVector;        // frame size per packet (bytes)
    cOutVector  windowCountVector;      // frames injected per 10ms window
    cOutVector  phaseOffsetVector;      // offset of send time within GCL cycle (µs)
    cHistogram  iatHistogram;           // IAT distribution histogram

    cMessage *windowTimer = nullptr;    // 10ms window boundary timer

    // ─── Scalars (recorded at simulation end) ─────────────────────────────────
    long      totalFramesSent  = 0;
    long      totalWindowsFired= 0;

  protected:
    // Lifecycle
    virtual void initialize() override;
    virtual void handleMessage(cMessage *msg) override;
    virtual void finish() override;

    // Core logic
    void sendAttackFrame();
    simtime_t computeNextSendTime();
    simtime_t alignToGclWindow(simtime_t t);
    void recordWindowStats();

    // Helpers
    Packet* buildAttackPacket();
    double  phaseOffsetInCycle(simtime_t t);   // returns µs offset within GCL cycle
};

#endif // __LUO2021_TIMINGATTACKAPP_H
