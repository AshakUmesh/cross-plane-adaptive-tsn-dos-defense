#ifndef __ATTACKS_LOWANDSLOWDRIFTAPP_H
#define __ATTACKS_LOWANDSLOWDRIFTAPP_H

#include "inet/applications/base/ApplicationBase.h"
#include "inet/transportlayer/contract/udp/UdpSocket.h"

using namespace inet;

/**
 * LowAndSlowDriftApp — Gap 3 proof, fully integrated into Luo2021Network
 *
 * This is the INET ApplicationBase version of LowAndSlowDriftAttack.
 * It runs inside TsnDevice.app[] exactly like UdpSourceApp, so it
 * goes through the full INET stack:
 *
 *   LowAndSlowDriftApp
 *       ↓ UDP socket sendTo()
 *   TsnDevice UDP layer
 *       ↓ PCP encoding (attack stream, PCP=5)
 *   viuSwitch PSFP (StreamFilter → FlowMeter → StreamGate)
 *       ↓ TAS egress queue
 *   vcuSwitch → centralHost
 *
 * The attack logic is identical to LowAndSlowDriftAttack.cc:
 *   - Sends at nominalInterval (90µs) initially
 *   - Adds driftPerPacket (0.09µs) to the interval on every send
 *   - Frame size = 500B (nominal AV1, passes StreamFilter)
 *   - Drift causes arrival phase within GCL cycle to move toward guard band
 *
 * Thesis-valid claim: AV1 E2E delay increases in Luo2021Network while
 * all PSFP counters remain at zero. Proven in the actual topology.
 */
class LowAndSlowDriftApp : public ApplicationBase, public UdpSocket::ICallback
{
  private:
    // UDP socket
    UdpSocket socket;
    L3Address destAddress;
    int destPort = -1;
    int localPort = -1;

    // Drift parameters (read from NED parameters)
    simtime_t nominalInterval;
    simtime_t driftPerPacket;
    int       payloadSize;
    simtime_t attackStartTime;

    // State
    simtime_t currentInterval;   // grows by driftPerPacket each packet
    simtime_t totalDrift;
    long      packetsSent;

    // Self-message for packet scheduling
    cMessage *sendTimer = nullptr;

  protected:
    // ApplicationBase interface
    virtual void initialize(int stage) override;
    virtual int  numInitStages() const override { return NUM_INIT_STAGES; }
    virtual void handleMessageWhenUp(cMessage *msg) override;
    virtual void finish() override;

    // ApplicationBase lifecycle
    virtual void handleStartOperation(LifecycleOperation *operation) override;
    virtual void handleStopOperation(LifecycleOperation *operation) override;
    virtual void handleCrashOperation(LifecycleOperation *operation) override;

    // UdpSocket::ICallback interface
    virtual void socketDataArrived(UdpSocket *socket, Packet *packet) override;
    virtual void socketErrorArrived(UdpSocket *socket, Indication *indication) override;
    virtual void socketClosed(UdpSocket *socket) override;

  private:
    void sendPacket();
};

#endif // __ATTACKS_LOWANDSLOWDRIFTAPP_H
