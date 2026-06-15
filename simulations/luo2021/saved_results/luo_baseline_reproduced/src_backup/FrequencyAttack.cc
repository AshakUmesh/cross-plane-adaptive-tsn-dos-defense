#include "FrequencyAttack.h"

Define_Module(FrequencyAttack);

void FrequencyAttack::initialize()
{
    attackStartTime = par("attackStartTime");
    attackInterval = par("attackInterval");

    streamId = par("streamId");
    payloadSize = par("payloadSize");

    sendTimer = new cMessage("sendTimer");

    scheduleAt(attackStartTime, sendTimer);
}

void FrequencyAttack::handleMessage(cMessage *msg)
{
    if (msg == sendTimer)
    {
        cPacket *pkt = new cPacket("frequencyAttack");

        pkt->setByteLength(payloadSize);

        pkt->addPar("streamId") = streamId;

        send(pkt, "out");

        scheduleAt(simTime() + attackInterval,
                   sendTimer);
    }
}
