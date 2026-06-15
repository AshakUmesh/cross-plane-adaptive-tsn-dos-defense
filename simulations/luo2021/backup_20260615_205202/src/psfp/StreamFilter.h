#ifndef __PSFP_STREAMFILTER_H
#define __PSFP_STREAMFILTER_H

#include <omnetpp.h>

using namespace omnetpp;

class StreamFilter : public cSimpleModule
{
  private:
    int allowedStreamId;
    int maxMsdu;

    long dropCounter;
    long passCounter;
    simsignal_t streamFilterDropSignal;

  protected:
    virtual void initialize() override;
    virtual void handleMessage(cMessage *msg) override;
    virtual void finish() override;  
};

#endif
