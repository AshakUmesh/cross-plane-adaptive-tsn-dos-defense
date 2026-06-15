#ifndef __PSFP_FLOWMETER_H
#define __PSFP_FLOWMETER_H

#include <omnetpp.h>

using namespace omnetpp;

class FlowMeter : public cSimpleModule
{
  private:
    double cir;          // bits/sec
    int cbs;             // bytes

    double tokens;       // current tokens in bucket
    simtime_t lastUpdate;
    
    long greenCount;
    long yellowCount;
    long dropCount;

    simsignal_t flowMeterGreenSignal;
    simsignal_t flowMeterYellowSignal;
    simsignal_t flowMeterDropSignal;

  protected:
    virtual void initialize() override;
    virtual void handleMessage(cMessage *msg) override;
    virtual void finish() override;
    void updateTokens();
};

#endif
