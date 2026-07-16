#ifndef __ATTACKS_GCLPHASEATTACK_H
#define __ATTACKS_GCLPHASEATTACK_H

#include <omnetpp.h>

using namespace omnetpp;

/**
 * GCLPhaseAttack — V1 / V3 vulnerability proof module
 *
 * Attack model:
 *   Each GCL cycle (500 µs) the attacker sends a burst of `burstSize`
 *   frames, all timed to land inside the Q0-Q6 gate-open window
 *   (125–450 µs by default).  Every individual frame arrives during a
 *   valid gate-open slot, so the StreamGate passes all of them.
 *   Frame size is held at (maxMsdu - 1) bytes — always below the MSDU
 *   limit — so the StreamFilter size-check also passes.
 *   The token bucket (FlowMeter / SingleRateTwoColorMeter) absorbs the
 *   first CBS bytes before marking frames RED, but by then legitimate
 *   AV1/AV2 frames have already experienced queueing delay.
 *
 * What Luo 2021 sees:   gateDrops=0, filterDrops=0, no alarm.
 * What YOUR ML sees:    mean_IAT << normal, IAT_variance high, burst_len > 1.
 *
 * Parameters (all have defaults matching Luo 2021 Table 6/7):
 *   attackStartTime   — when to start (default: 1ms, after baseline settles)
 *   cyclePeriod       — GCL cycle period (default: 500µs)
 *   gateOpenStart     — start of Q0-Q6 open window (default: 125µs)
 *   gateOpenEnd       — end of Q0-Q6 open window   (default: 450µs)
 *   burstSize         — frames per gate-open window (default: 8)
 *   payloadSize       — bytes per frame; keep < maxMsdu (default: 529)
 *   streamId          — copied into pkt parameter for receiver stats (default: 5)
 */
class GCLPhaseAttack : public cSimpleModule
{
  private:
    // Scheduling
    cMessage *burstTimer;           // fires at start of each gate-open window
    int       burstIndex;           // which frame in the current burst we're on
    simtime_t nextWindowStart;      // absolute time of the next gate-open start

    // GCL geometry (from omnetpp.ini / NED parameters)
    simtime_t cyclePeriod;
    simtime_t gateOpenStart;        // offset into cycle where Q0-Q6 opens
    simtime_t gateOpenEnd;          // offset into cycle where Q0-Q6 closes
    simtime_t attackStartTime;

    // Frame parameters
    int burstSize;                  // how many frames to send per open window
    int payloadSize;                // bytes — must be < maxMsdu (530) to evade filter
    int streamId;

    // Derived spacing between frames within a burst
    simtime_t intraburstSpacing;

  protected:
    virtual void initialize() override;
    virtual void handleMessage(cMessage *msg) override;
    virtual void finish() override;

  private:
    // Compute the absolute time of the next gate-open window start
    // given a reference time (usually simTime()).
    simtime_t nextGateOpenTime(simtime_t fromTime) const;

    // Build and send one attack frame.
    void sendFrame();
};

#endif // __ATTACKS_GCLPHASEATTACK_H
