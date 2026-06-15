#include "TestSource.h"

Define_Module(TestSource);

void TestSource::initialize()
{
    packetsSent = 0;

    sendEvent = new cMessage("sendEvent");

    scheduleAt(simTime(), sendEvent);
}

void TestSource::handleMessage(cMessage *msg)
{
    if (packetsSent < 10)
    {
        cPacket *pkt = new cPacket("testPacket");

        pkt->setByteLength(100);

        pkt->addPar("streamId") = 1;

        send(pkt, "out");

        packetsSent++;

        // Send every 50 ms
        scheduleAt(simTime() + 0.05, sendEvent);
    }
}
