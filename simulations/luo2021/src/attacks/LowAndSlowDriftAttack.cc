#include "LowAndSlowDriftAttack.h"

Define_Module(LowAndSlowDriftAttack);

// ---------------------------------------------------------------------------
// initialize
// ---------------------------------------------------------------------------
void LowAndSlowDriftAttack::initialize()
{
    attackStartTime = par("attackStartTime");
    nominalInterval = par("nominalInterval");
    driftPerPacket  = par("driftPerPacket");
    payloadSize     = par("payloadSize");
    streamId        = par("streamId");

    // Start at the nominal AV1 interval — indistinguishable from legitimate
    // traffic at t=0. The drift accumulates gradually from this point.
    currentInterval = nominalInterval;

    packetsSent = 0;
    totalDrift  = SimTime(0);

    // Sanity: warn if payloadSize would trigger StreamFilter
    if (payloadSize >= 530) {
        EV_WARN << "LowAndSlowDriftAttack: payloadSize=" << payloadSize
                << "B >= maxMsdu(530B). StreamFilter will catch this. "
                << "Set payloadSize <= 529 for evasion." << endl;
    }

    double rate_mbps = (payloadSize * 8.0) / nominalInterval.dbl() / 1e6;
    double drift_ppm = driftPerPacket.dbl() / nominalInterval.dbl() * 1e6;

    EV_INFO << "LowAndSlowDriftAttack initialized:" << endl
            << "  nominalInterval = " << nominalInterval * 1e6 << " us" << endl
            << "  driftPerPacket  = " << driftPerPacket  * 1e9 << " ns" << endl
            << "  drift rate      = " << drift_ppm << " ppm of nominal interval" << endl
            << "  initial rate    = " << rate_mbps << " Mbps (CIR = 22 Mbps)" << endl
            << "  payloadSize     = " << payloadSize << " B (maxMsdu = 530 B)" << endl;

    sendTimer = new cMessage("sendTimer");
    scheduleAt(attackStartTime, sendTimer);
}

// ---------------------------------------------------------------------------
// handleMessage
// ---------------------------------------------------------------------------
void LowAndSlowDriftAttack::handleMessage(cMessage *msg)
{
    if (msg != sendTimer)
        return;

    // ---- Build frame ----
    // Size = nominalInterval (500B by default): passes StreamFilter exactly.
    // Rate drifts by 0.09us per packet: 0.39% below nominal, invisible to meter.
    cPacket *pkt = new cPacket("lowAndSlowDriftAttack");
    pkt->setByteLength(payloadSize);

    // Stream tag — same convention as FrequencyAttack, OversizeAttack.
    pkt->addPar("streamId") = streamId;

    // Record accumulated drift as a packet parameter.
    // Your Python feature extractor reads this to compute phase_offset_µ
    // and phase_offset_σ per 10ms window — these are two of your 15 ML features.
    pkt->addPar("accumulatedDrift_us") = totalDrift.dbl() * 1e6;

    // Also record the current phase within the GCL cycle so the Python script
    // can directly verify drift trajectory without recomputing from timestamps.
    // cycle = 500us (Luo Table 6)
    double phase_in_cycle_us = fmod(simTime().dbl() * 1e6, 500.0);
    pkt->addPar("gclPhase_us") = phase_in_cycle_us;

    send(pkt, "out");

    // ---- Update state ----
    packetsSent++;
    totalDrift = totalDrift + driftPerPacket;

    // Grow the interval by driftPerPacket each send.
    // After N packets: currentInterval = nominalInterval + N * driftPerPacket
    // After 1000 packets (90ms): currentInterval = 90us + 1000*0.09us = 180us
    // This is the long-term drift that eventually pushes frames outside the window.
    currentInterval = currentInterval + driftPerPacket;

    // Log milestones for thesis verification
    if (packetsSent % 111 == 0) {  // every ~10ms window
        double current_rate_mbps = (payloadSize * 8.0) / currentInterval.dbl() / 1e6;
        EV_INFO << "LowAndSlowDrift @ " << simTime() * 1e3 << "ms:"
                << "  pkt#" << packetsSent
                << "  interval=" << currentInterval * 1e6 << "us"
                << "  drift=" << totalDrift * 1e6 << "us"
                << "  rate=" << current_rate_mbps << "Mbps"
                << "  phase=" << phase_in_cycle_us << "us" << endl;
    }

    scheduleAt(simTime() + currentInterval, sendTimer);
}

// ---------------------------------------------------------------------------
// finish
// ---------------------------------------------------------------------------
void LowAndSlowDriftAttack::finish()
{
    double final_drift_us = totalDrift.dbl() * 1e6;
    double final_rate_mbps = (payloadSize * 8.0) / currentInterval.dbl() / 1e6;

    EV_INFO << "LowAndSlowDriftAttack finished:" << endl
            << "  totalPackets   = " << packetsSent << endl
            << "  finalDrift     = " << final_drift_us << " us" << endl
            << "  finalInterval  = " << currentInterval * 1e6 << " us" << endl
            << "  finalRate      = " << final_rate_mbps << " Mbps" << endl;

    // Emit final drift as a scalar for OMNeT++ results collection.
    // Visible in General-#0.sca as "finalDrift_us" under this module.
    recordScalar("finalDrift_us", final_drift_us);
    recordScalar("totalPacketsSent", (double)packetsSent);
    recordScalar("finalRate_Mbps", final_rate_mbps);

    cancelAndDelete(sendTimer);
    sendTimer = nullptr;
}
