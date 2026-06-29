#include "ThresholdEvasionAttack.h"

Define_Module(ThresholdEvasionAttack);

// ---------------------------------------------------------------------------
// initialize
// ---------------------------------------------------------------------------
void ThresholdEvasionAttack::initialize()
{
    attackStartTime = par("attackStartTime");
    attackInterval  = par("attackInterval");
    payloadSize     = par("payloadSize");
    streamId        = par("streamId");

    // Verify the attack is actually below maxMsdu (530B).
    // If someone misconfigures payloadSize >= 530, the StreamFilter would
    // catch it and this would become an OversizeAttack, not a V3 proof.
    if (payloadSize >= 530) {
        EV_WARN << "ThresholdEvasionAttack: payloadSize=" << payloadSize
                << " >= maxMsdu(530). This will be caught by StreamFilter. "
                << "Set payloadSize <= 529 for threshold evasion." << endl;
    }

    // Compute and log the effective attack rate for thesis verification.
    double rate_bps  = (payloadSize * 8.0) / attackInterval.dbl();
    double rate_mbps = rate_bps / 1e6;
    EV_INFO << "ThresholdEvasionAttack: initialized." << endl
            << "  payloadSize    = " << payloadSize   << " B  (maxMsdu-1)" << endl
            << "  attackInterval = " << attackInterval * 1e6 << " us" << endl
            << "  effective rate = " << rate_mbps << " Mbps  (CIR = 22 Mbps)" << endl
            << "  CIR headroom   = " << (22.0 - rate_mbps) << " Mbps  (stays GREEN)" << endl;

    sendTimer = new cMessage("sendTimer");
    scheduleAt(attackStartTime, sendTimer);
}

// ---------------------------------------------------------------------------
// handleMessage
// ---------------------------------------------------------------------------
void ThresholdEvasionAttack::handleMessage(cMessage *msg)
{
    if (msg != sendTimer)
        return;

    // Build the evasion frame.
    // payloadSize = 529B:  passes StreamFilter maxMsdu check (limit = 530B).
    // Rate = CIR - 100kbps: token bucket refills faster than consumed → GREEN.
    // Both checks pass → Luo 2021 raises zero alarms for every single frame.
    cPacket *pkt = new cPacket("thresholdEvasionAttack");
    pkt->setByteLength(payloadSize);

    // Tag with streamId so the TestSink / centralHost sink can attribute stats.
    // Same convention as FrequencyAttack and OversizeAttack.
    pkt->addPar("streamId") = streamId;

    send(pkt, "out");

    // Reschedule at fixed interval — sustained, indefinite attack.
    // No burst logic needed: the evasion works at constant rate, which is
    // actually more damaging than a burst because it never triggers the
    // flow meter's burst-absorption mechanism either.
    scheduleAt(simTime() + attackInterval, sendTimer);
}

// ---------------------------------------------------------------------------
// finish
// ---------------------------------------------------------------------------
void ThresholdEvasionAttack::finish()
{
    cancelAndDelete(sendTimer);
    sendTimer = nullptr;
}
