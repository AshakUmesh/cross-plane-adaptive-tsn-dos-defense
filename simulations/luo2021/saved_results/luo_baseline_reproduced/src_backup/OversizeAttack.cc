#include "OversizeAttack.h"

Define_Module(OversizeAttack);

void OversizeAttack::initialize()
{
    targetStreamId = par("targetStreamId");
    oversizeBytes = par("oversizeBytes");
    maxMsdu = par("maxMsdu");

    attackStartTime = par("attackStartTime");

    attackEvent = new cMessage("attackEvent");

    scheduleAt(attackStartTime, attackEvent);
}

void OversizeAttack::handleMessage(cMessage *msg)
{
    if (msg == attackEvent)
    {
        cPacket *pkt = new cPacket("oversizeAttackPacket");

        pkt->setByteLength(maxMsdu + oversizeBytes);

        pkt->addPar("streamId") = targetStreamId;

        send(pkt, "out");

        scheduleAt(simTime() + SimTime(1, SIMTIME_MS), attackEvent);
    }
}
