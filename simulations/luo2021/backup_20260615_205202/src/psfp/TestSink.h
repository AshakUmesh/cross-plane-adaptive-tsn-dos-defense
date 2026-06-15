#ifndef __PSFP_TESTSINK_H
#define __PSFP_TESTSINK_H

#include <omnetpp.h>

using namespace omnetpp;

class TestSink : public cSimpleModule
{
  protected:
    virtual void handleMessage(cMessage *msg) override;
};

#endif
