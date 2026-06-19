#include "ScheduleAwareBurstAttack.h"

Define_Module(ScheduleAwareBurstAttack);

// ---------------------------------------------------------------------------
// initialize
// ---------------------------------------------------------------------------
void ScheduleAwareBurstAttack::initialize()
{
    attackStartTime    = par("attackStartTime");
    cyclePeriod        = par("cyclePeriod");
    gateOpenOffset     = par("gateOpenOffset");
    burstGuardOffset   = par("burstGuardOffset");
    burstSize          = par("burstSize");
    intraburstSpacing  = par("intraburstSpacing");
    interburstInterval = par("interburstInterval");
    payloadSize        = par("payloadSize");
    streamId           = par("streamId");

    burstIndex       = 0;
    totalBursts      = 0;
    totalFramesSent  = 0;

    // Verify burst bytes fit within CBS to guarantee all-GREEN treatment.
    // CBS = 5004B for AV1 stream (Luo Table 7). 7 × 529B = 3703B < 5004B.
    int burstBytes = burstSize * payloadSize;
    if (burstBytes > 5004) {
        EV_WARN << "ScheduleAwareBurstAttack: burstBytes=" << burstBytes
                << "B > CBS=5004B. Some frames will be marked RED. "
                << "Reduce burstSize or payloadSize for full CBS evasion." << endl;
    }

    double avg_rate_mbps = (burstBytes * 8.0) / interburstInterval.dbl() / 1e6;
    EV_INFO << "ScheduleAwareBurstAttack initialized:" << endl
            << "  burstSize          = " << burstSize << " frames" << endl
            << "  payloadSize        = " << payloadSize << "B (maxMsdu-1=529B)" << endl
            << "  burstBytes         = " << burstBytes << "B (CBS=5004B)" << endl
            << "  intraburstSpacing  = " << intraburstSpacing * 1e6 << "us" << endl
            << "  interburstInterval = " << interburstInterval * 1e3 << "ms" << endl
            << "  averageRate        = " << avg_rate_mbps << " Mbps (CIR=22Mbps)" << endl
            << "  gateOpenOffset     = " << gateOpenOffset * 1e6 << "us" << endl
            << "  burstGuardOffset   = " << burstGuardOffset * 1e6 << "us" << endl;

    burstTrigger = new cMessage("burstTrigger");
    frameTimer   = new cMessage("frameTimer");

    // Schedule first burst: at attackStartTime, aligned to gate-open.
    // First burst fires at attackStartTime + gateOpenOffset + burstGuardOffset.
    simtime_t firstBurst = attackStartTime + gateOpenOffset + burstGuardOffset;
    scheduleAt(firstBurst, burstTrigger);
}

// ---------------------------------------------------------------------------
// handleMessage
// ---------------------------------------------------------------------------
void ScheduleAwareBurstAttack::handleMessage(cMessage *msg)
{
    if (msg == burstTrigger)
    {
        // Start a new burst: reset index and send the first frame immediately.
        burstIndex = 0;
        totalBursts++;

        EV_DEBUG << "ScheduleAwareBurstAttack: burst #" << totalBursts
                 << " starts at t=" << simTime() * 1e6 << "us" << endl;

        sendBurstFrame();
        burstIndex++;

        if (burstIndex < burstSize)
        {
            // Schedule next frame in this burst.
            scheduleAt(simTime() + intraburstSpacing, frameTimer);
        }
        else
        {
            // Single-frame burst (burstSize=1): skip to next burst trigger.
            scheduleBurstTrigger();
        }
    }
    else if (msg == frameTimer)
    {
        // Send the next frame in the current burst.
        sendBurstFrame();
        burstIndex++;

        if (burstIndex < burstSize)
        {
            // More frames in this burst — continue.
            scheduleAt(simTime() + intraburstSpacing, frameTimer);
        }
        else
        {
            // Burst complete — schedule the next burst trigger.
            scheduleBurstTrigger();
        }
    }
}

// ---------------------------------------------------------------------------
// sendBurstFrame
// ---------------------------------------------------------------------------
void ScheduleAwareBurstAttack::sendBurstFrame()
{
    cPacket *pkt = new cPacket("scheduleAwareBurst");

    // 529B = maxMsdu-1: passes StreamFilter MSDU check (limit=530B).
    pkt->setByteLength(payloadSize);

    // Stream tag: same convention as all other attack modules.
    pkt->addPar("streamId") = streamId;

    // Tag with burst index for Python feature extractor.
    // burst_length is computed per 10ms window as max consecutive frames
    // with IAT < threshold (e.g., < 100µs). This parameter lets you
    // verify burst boundaries directly without timestamp arithmetic.
    pkt->addPar("burstIndex") = burstIndex;
    pkt->addPar("burstNumber") = (long)totalBursts;

    // Phase within current GCL cycle — for phase_offset ML feature.
    double phase_us = fmod(simTime().dbl() * 1e6, cyclePeriod.dbl() * 1e6);
    pkt->addPar("gclPhase_us") = phase_us;

    send(pkt, "out");
    totalFramesSent++;
}

// ---------------------------------------------------------------------------
// scheduleBurstTrigger
// ---------------------------------------------------------------------------
// After a burst completes, schedule the trigger for the NEXT burst.
// Next burst fires exactly interburstInterval after the CURRENT burst trigger
// time — not after the last frame's transmission. This keeps the burst period
// stable regardless of burst duration.
void ScheduleAwareBurstAttack::scheduleBurstTrigger()
{
    // Next burst trigger = current burst start + interburstInterval.
    // Current burst start = simTime() - (burstSize-1)*intraburstSpacing.
    simtime_t currentBurstStart = simTime()
        - (simtime_t)(burstSize - 1) * intraburstSpacing;
    simtime_t nextTrigger = currentBurstStart + interburstInterval;

    scheduleAt(nextTrigger, burstTrigger);

    EV_DEBUG << "ScheduleAwareBurstAttack: next burst #" << (totalBursts + 1)
             << " scheduled at t=" << nextTrigger * 1e3 << "ms" << endl;
}

// ---------------------------------------------------------------------------
// finish
// ---------------------------------------------------------------------------
void ScheduleAwareBurstAttack::finish()
{
    EV_INFO << "ScheduleAwareBurstAttack finished:" << endl
            << "  totalBursts      = " << totalBursts << endl
            << "  totalFramesSent  = " << totalFramesSent << endl
            << "  expectedBursts   = ~82  (150ms / 1.82ms)" << endl;

    recordScalar("totalBursts",     (double)totalBursts);
    recordScalar("totalFramesSent", (double)totalFramesSent);
    recordScalar("avgBurstRate_Mbps",
        (totalFramesSent * payloadSize * 8.0) / 0.150 / 1e6);

    cancelAndDelete(burstTrigger);
    cancelAndDelete(frameTimer);
    burstTrigger = nullptr;
    frameTimer   = nullptr;
}
