#ifndef __ATTACKS_OVERSIZEATTACK_H
#define __ATTACKS_OVERSIZEATTACK_H

#include <omnetpp.h>

using namespace omnetpp;

class OversizeAttack : public cSimpleModule
{
  private:
    int targetStreamId;
    int oversizeBytes;
    int maxMsdu;

    simtime_t attackStartTime;

    cMessage *attackEvent;

  protected:
    virtual void initialize() override;
    virtual void handleMessage(cMessage *msg) override;
};

#endif
