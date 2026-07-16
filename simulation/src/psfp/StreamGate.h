#ifndef __PSFP_STREAMGATE_H
#define __PSFP_STREAMGATE_H

#include <omnetpp.h>
#include <vector>
#include <string>

using namespace omnetpp;

struct GateEntry
{
    bool open;
    simtime_t duration;
};

class StreamGate : public cSimpleModule
{
  private:
    simtime_t gateInterval;
    int linkedStreamId;

    std::vector<GateEntry> gclEntries;

    long dropCounter;
    long passCounter;
    simsignal_t streamGateDropSignal;

  protected:
    virtual void initialize() override;
    virtual void handleMessage(cMessage *msg) override;
    virtual void finish() override;
    bool isGateOpen();
};

#endif
