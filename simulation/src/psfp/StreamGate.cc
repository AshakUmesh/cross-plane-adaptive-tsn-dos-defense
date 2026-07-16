#include "StreamGate.h"
#include <iostream>
#include <cmath>

Define_Module(StreamGate);

void StreamGate::initialize()
{
    gateInterval = par("gateInterval");
    linkedStreamId = par("linkedStreamId");

    dropCounter = 0;
    passCounter = 0;
    streamGateDropSignal =
        registerSignal("streamGateDrop");

    // Test GCL:
    // open:100us,closed:400us
    //gclEntries.push_back({true, SimTime(100, SIMTIME_US)});
    //gclEntries.push_back({false, SimTime(400, SIMTIME_US)});
    gclEntries.clear();

    gclEntries.push_back({false, SimTime(125, SIMTIME_US)}); // 0-125us CLOSED
    gclEntries.push_back({true,  SimTime(325, SIMTIME_US)}); // 125-450us OPEN
    gclEntries.push_back({false, SimTime(50,  SIMTIME_US)}); // 450-500us CLOSED
}

bool StreamGate::isGateOpen()
{
    simtime_t now = simTime();

    simtime_t offset =
        fmod(now.dbl(), gateInterval.dbl());

    simtime_t accumulated = SIMTIME_ZERO;

    for (auto& entry : gclEntries)
    {
        accumulated += entry.duration;

        if (offset < accumulated)
            return entry.open;
    }

    return false;
}

void StreamGate::handleMessage(cMessage *msg)
{
    if (isGateOpen())
    {
        passCounter++;
        send(msg, "out");
    }
    else
    {
        dropCounter++;

        emit(streamGateDropSignal, 1L);

        std::cout
            << "StreamGate dropped packet"
            << std::endl;

        delete msg;
    }
}
void StreamGate::finish()
{
    recordScalar("gatePasses", passCounter);
    recordScalar("gateDrops", dropCounter);
}
