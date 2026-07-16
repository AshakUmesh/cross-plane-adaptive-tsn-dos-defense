#include "FlowMeter.h"
#include <iostream>
#include <algorithm>

Define_Module(FlowMeter);

void FlowMeter::initialize()
{
    cir = par("cir");
    cbs = par("cbs");

    tokens = cbs;   // bucket starts full
    lastUpdate = simTime();
    greenCount = 0;
    yellowCount = 0;
    dropCount = 0;

    flowMeterGreenSignal =
        registerSignal("flowMeterGreen");

    flowMeterYellowSignal =
        registerSignal("flowMeterYellow");

    flowMeterDropSignal =
        registerSignal("flowMeterDrop");
}

void FlowMeter::updateTokens()
{
    simtime_t now = simTime();

    double elapsed = (now - lastUpdate).dbl();

    // convert CIR from bits/sec to bytes/sec
    double bytesPerSec = cir / 8.0;

    tokens += elapsed * bytesPerSec;

    tokens = std::min(tokens, (double)cbs);

    lastUpdate = now;
}

void FlowMeter::handleMessage(cMessage *msg)
{
    updateTokens();

    cPacket *pkt = check_and_cast<cPacket *>(msg);

    int frameSize = pkt->getByteLength();

    if (tokens >= frameSize)
    {
        tokens -= frameSize;
        greenCount++;
        emit(flowMeterGreenSignal, 1L);

        std::cout
            << "FlowMeter GREEN"
            << std::endl;

        send(pkt, "out");
    }
    else
    {	yellowCount++;
	dropCount++;
        emit(flowMeterYellowSignal, 1L);
        emit(flowMeterDropSignal, 1L);

        std::cout
            << "FlowMeter YELLOW/DROP"
            << std::endl;

        delete pkt;
    }
}
void FlowMeter::finish()
{
    recordScalar("meterPasses", greenCount);
    recordScalar("greenPackets", greenCount);
    recordScalar("yellowPackets", yellowCount);
    recordScalar("dropPackets", dropCount);
}
