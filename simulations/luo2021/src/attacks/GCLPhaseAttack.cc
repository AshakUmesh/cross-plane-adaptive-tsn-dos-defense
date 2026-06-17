#include "GCLPhaseAttack.h"

Define_Module(GCLPhaseAttack);

// ---------------------------------------------------------------------------
// initialize
// ---------------------------------------------------------------------------
void GCLPhaseAttack::initialize()
{
    // ---- Read parameters (all defined in GCLPhaseAttack.ned) ----
    attackStartTime  = par("attackStartTime");
    cyclePeriod      = par("cyclePeriod");
    gateOpenStart    = par("gateOpenStart");
    gateOpenEnd      = par("gateOpenEnd");
    burstSize        = par("burstSize");
    payloadSize      = par("payloadSize");
    streamId         = par("streamId");

    // ---- Sanity checks ----
    ASSERT(gateOpenEnd > gateOpenStart);
    ASSERT(gateOpenEnd <= cyclePeriod);
    ASSERT(burstSize >= 1);

    // ---- Compute intraburst spacing ----
    // Spread all burstSize frames evenly across the open window.
    // e.g. window = 325µs, burstSize = 8  → spacing ≈ 40µs
    // We use (N+1) divisions so the last frame is not right at gateOpenEnd.
    simtime_t windowDuration = gateOpenEnd - gateOpenStart;
    intraburstSpacing = windowDuration / (burstSize + 1);

    // ---- State init ----
    burstIndex      = 0;
    burstTimer      = new cMessage("burstTimer");

    // ---- Schedule first event ----
    // Find the first gate-open window at or after attackStartTime.
    nextWindowStart = nextGateOpenTime(attackStartTime);
    scheduleAt(nextWindowStart + intraburstSpacing, burstTimer);

    EV_INFO << "GCLPhaseAttack: initialized."
            << " cyclePeriod="    << cyclePeriod
            << " window="         << gateOpenStart << "-" << gateOpenEnd
            << " burstSize="      << burstSize
            << " payloadSize="    << payloadSize << "B"
            << " intraburstSpacing=" << intraburstSpacing
            << " firstWindow="    << nextWindowStart << endl;
}

// ---------------------------------------------------------------------------
// handleMessage
// ---------------------------------------------------------------------------
void GCLPhaseAttack::handleMessage(cMessage *msg)
{
    if (msg != burstTimer)
        return;   // should never happen — we own the only self-message

    // ---- Send one frame from the current burst ----
    sendFrame();
    burstIndex++;

    if (burstIndex < burstSize)
    {
        // More frames left in this burst — schedule next frame within
        // the same gate-open window.
        scheduleAt(simTime() + intraburstSpacing, burstTimer);
    }
    else
    {
        // Burst complete — advance to the next GCL cycle.
        burstIndex = 0;
        nextWindowStart = nextWindowStart + cyclePeriod;
        scheduleAt(nextWindowStart + intraburstSpacing, burstTimer);
    }
}

// ---------------------------------------------------------------------------
// finish
// ---------------------------------------------------------------------------
void GCLPhaseAttack::finish()
{
    // burstTimer is either scheduled or we own it — cancel before cleanup.
    cancelAndDelete(burstTimer);
    burstTimer = nullptr;
}

// ---------------------------------------------------------------------------
// nextGateOpenTime
// ---------------------------------------------------------------------------
// Returns the absolute time of the gate-open window start in the cycle that
// contains 'fromTime', or the next cycle if we're already past gateOpenStart
// in the current cycle.
simtime_t GCLPhaseAttack::nextGateOpenTime(simtime_t fromTime) const
{
    // How far are we into the current cycle?
    simtime_t phaseInCycle = fmod(fromTime.dbl(), cyclePeriod.dbl());

    // Absolute start of the current cycle
    simtime_t cycleBase = fromTime - phaseInCycle;

    simtime_t candidate = cycleBase + gateOpenStart;

    if (candidate < fromTime)
    {
        // The gate-open moment in this cycle is already past — use next cycle.
        candidate = candidate + cyclePeriod;
    }

    return candidate;
}

// ---------------------------------------------------------------------------
// sendFrame
// ---------------------------------------------------------------------------
void GCLPhaseAttack::sendFrame()
{
    cPacket *pkt = new cPacket("gclPhaseAttack");

    // payloadSize is always < maxMsdu (530B by default) — passes StreamFilter.
    pkt->setByteLength(payloadSize);

    // Tag with streamId so the receiver/sink can attribute the traffic.
    // Mirrors the pattern used by FrequencyAttack and OversizeAttack.
    pkt->addPar("streamId") = streamId;

    // Record per-frame arrival offset within the gate window for the thesis
    // (optional — comment out if TestSink does not consume this parameter).
    simtime_t phaseInCycle   = fmod(simTime().dbl(), cyclePeriod.dbl());
    simtime_t offsetFromOpen = phaseInCycle - gateOpenStart;
    pkt->addPar("gatePhaseOffset") = offsetFromOpen.dbl();   // seconds

    send(pkt, "out");
}
