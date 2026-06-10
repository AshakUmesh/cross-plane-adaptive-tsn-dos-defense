#ifndef __PSFP_TESTSOURCE_H
#define __PSFP_TESTSOURCE_H

#include <omnetpp.h>

using namespace omnetpp;

class TestSource : public cSimpleModule
{
  private:
    cMessage *sendEvent;
    int packetsSent;

  protected:
    virtual void initialize() override;
    virtual void handleMessage(cMessage *msg) override;
};

#endif
