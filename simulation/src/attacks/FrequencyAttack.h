#ifndef __ATTACKS_FREQUENCYATTACK_H
#define __ATTACKS_FREQUENCYATTACK_H

#include <omnetpp.h>

using namespace omnetpp;

class FrequencyAttack : public cSimpleModule
{
  private:
    cMessage *sendTimer;

    simtime_t attackStartTime;
    simtime_t attackInterval;

    int streamId;
    int payloadSize;

  protected:
    virtual void initialize() override;
    virtual void handleMessage(cMessage *msg) override;
};

#endif
