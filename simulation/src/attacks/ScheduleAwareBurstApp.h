#ifndef __ATTACKS_SCHEDULEAWAREBURSTAPP_H
#define __ATTACKS_SCHEDULEAWAREBURSTAPP_H

#include "inet/applications/base/ApplicationBase.h"
#include "inet/transportlayer/contract/udp/UdpSocket.h"

using namespace inet;

/**
 * ScheduleAwareBurstApp — Gap 4 proof, fully integrated into Luo2021Network
 *
 * INET ApplicationBase version of ScheduleAwareBurstAttack.
 * Runs inside TsnDevice.app[] — full INET stack, full PSFP pipeline.
 *
 * Attack pattern: every interburstInterval (1.82ms), sends burstSize (7)
 * frames in rapid succession at t = gateOpenOffset + burstGuardOffset
 * (127µs into each CBS-refill period). All frames land inside the
 * Q0-Q6 gate-open window (125-450µs), all pass within CBS budget.
 *
 *   gateDrops      = 0   (burst timing inside open window)
 *   meterRedFrames = 0   (3703B burst < CBS 5004B, avg rate < CIR)
 *   qciAlarm       = false
 *   AV1 E2E delay  = INCREASED (queue contention from burst)
 *
 * This produces thesis-valid results: measured AV1 delay degradation
 * in the actual Luo2021Network topology with all PSFP counters at zero.
 */
class ScheduleAwareBurstApp : public ApplicationBase, public UdpSocket::ICallback
{
  private:
    // UDP socket
    UdpSocket socket;
    L3Address destAddress;
    int destPort  = -1;
    int localPort = -1;

    // Attack parameters
    simtime_t attackStartTime;
    simtime_t cyclePeriod;
    simtime_t gateOpenOffset;
    simtime_t burstGuardOffset;
    int       burstSize;
    simtime_t intraburstSpacing;
    simtime_t interburstInterval;
    int       payloadSize;

    // State
    int  burstIndex      = 0;
    long totalBursts     = 0;
    long totalFramesSent = 0;

    // Two-timer burst scheduling (same design as ScheduleAwareBurstAttack.cc)
    cMessage *burstTrigger = nullptr;
    cMessage *frameTimer   = nullptr;

  protected:
    virtual void initialize(int stage) override;
    virtual int  numInitStages() const override { return NUM_INIT_STAGES; }
    virtual void handleMessageWhenUp(cMessage *msg) override;
    virtual void finish() override;

    virtual void handleStartOperation(LifecycleOperation *operation) override;
    virtual void handleStopOperation(LifecycleOperation *operation) override;
    virtual void handleCrashOperation(LifecycleOperation *operation) override;

    virtual void socketDataArrived(UdpSocket *socket, Packet *packet) override;
    virtual void socketErrorArrived(UdpSocket *socket, Indication *indication) override;
    virtual void socketClosed(UdpSocket *socket) override;

  private:
    void sendBurstFrame();
    void scheduleBurstTrigger();
};

#endif // __ATTACKS_SCHEDULEAWAREBURSTAPP_H
