#include "StreamFilter.h"
#include <iostream>
Define_Module(StreamFilter);

void StreamFilter::initialize()
{
    allowedStreamId = par("streamId");
    maxMsdu = par("maxMsdu");

    dropCounter = 0;
   passCounter = 0;
    streamFilterDropSignal =
        registerSignal("streamFilterDrop");
}

void StreamFilter::handleMessage(cMessage *msg)
{
    cPacket *pkt = check_and_cast<cPacket *>(msg);

     int streamId = pkt->hasPar("streamId")
                   ? (int)pkt->par("streamId").longValue()
                   : -1;                       

    int frameSize = pkt->getByteLength();

    bool validStream =
        (streamId == allowedStreamId);

    bool validSize =
        (frameSize <= maxMsdu);

    if (!validStream || !validSize)
    {
        dropCounter++;

        emit(streamFilterDropSignal, 1L);

        delete pkt;

        std::cout << "StreamFilter dropped packet" << std::endl;

        return;
    }

    passCounter++;
    send(pkt, "out");
}
void StreamFilter::finish()
{
    recordScalar("filterPasses", passCounter);
    recordScalar("filterDrops", dropCounter);
}
