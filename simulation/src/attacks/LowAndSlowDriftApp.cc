#include "LowAndSlowDriftApp.h"

#include "inet/common/ModuleAccess.h"
#include "inet/common/packet/Packet.h"
#include "inet/common/packet/chunk/ByteCountChunk.h"
#include "inet/networklayer/common/L3AddressResolver.h"

Define_Module(LowAndSlowDriftApp);

// ---------------------------------------------------------------------------
// initialize
// ---------------------------------------------------------------------------
void LowAndSlowDriftApp::initialize(int stage)
{
    ApplicationBase::initialize(stage);

    if (stage == INITSTAGE_LOCAL) {
        nominalInterval  = par("nominalInterval");
        driftPerPacket   = par("driftPerPacket");
        payloadSize      = par("payloadSize");
        attackStartTime  = par("attackStartTime");
        destPort         = par("destPort");
        localPort        = par("localPort");

        currentInterval = nominalInterval;
        totalDrift      = SimTime(0);
        packetsSent     = 0;

        sendTimer = new cMessage("sendTimer");

        EV_INFO << "LowAndSlowDriftApp: initialized." << endl
                << "  nominalInterval = " << nominalInterval * 1e6 << "us" << endl
                << "  driftPerPacket  = " << driftPerPacket  * 1e9 << "ns" << endl
                << "  payloadSize     = " << payloadSize << "B" << endl;
    }
    else if (stage == INITSTAGE_APPLICATION_LAYER) {
        destAddress = L3AddressResolver().resolve(par("destAddress"));
    }
}

// ---------------------------------------------------------------------------
// handleStartOperation — called when simulation starts
// ---------------------------------------------------------------------------
void LowAndSlowDriftApp::handleStartOperation(LifecycleOperation *operation)
{
    socket.setOutputGate(gate("socketOut"));
    socket.setCallback(this);
    socket.bind(localPort);

    scheduleAt(simTime() + attackStartTime, sendTimer);
}

// ---------------------------------------------------------------------------
// handleMessageWhenUp
// ---------------------------------------------------------------------------
void LowAndSlowDriftApp::handleMessageWhenUp(cMessage *msg)
{
    if (msg == sendTimer) {
        sendPacket();
        scheduleAt(simTime() + currentInterval, sendTimer);
    }
    else {
        socket.processMessage(msg);
    }
}

// ---------------------------------------------------------------------------
// sendPacket
// ---------------------------------------------------------------------------
void LowAndSlowDriftApp::sendPacket()
{
    // Build a UDP payload of payloadSize bytes.
    // ByteCountChunk is the standard INET way to create fixed-size payloads
    // without needing a specific message format.
    auto payload = makeShared<ByteCountChunk>(B(payloadSize));
    auto packet  = new Packet("lowAndSlowDrift", payload);

    // Send via UDP socket → goes through TsnDevice IP/UDP stack → PCP encoder
    // → viuSwitch PSFP → TAS gate → centralHost
    socket.sendTo(packet, destAddress, destPort);

    // Update drift state
    packetsSent++;
    totalDrift      = totalDrift + driftPerPacket;
    currentInterval = currentInterval + driftPerPacket;

    // Log per 10ms window (~111 packets) for EV trace verification
    if (packetsSent % 111 == 0) {
        double rate_mbps = (payloadSize * 8.0) / currentInterval.dbl() / 1e6;
        EV_INFO << "LowAndSlowDrift @ " << simTime() * 1e3 << "ms"
                << "  pkt#"      << packetsSent
                << "  interval=" << currentInterval * 1e6 << "us"
                << "  drift="    << totalDrift * 1e6 << "us"
                << "  rate="     << rate_mbps << "Mbps" << endl;
    }
}

// ---------------------------------------------------------------------------
// finish
// ---------------------------------------------------------------------------
void LowAndSlowDriftApp::finish()
{
    double finalDrift_us   = totalDrift.dbl() * 1e6;
    double finalRate_Mbps  = (payloadSize * 8.0) / currentInterval.dbl() / 1e6;

    EV_INFO << "LowAndSlowDriftApp finished:"
            << "  totalPackets=" << packetsSent
            << "  finalDrift="   << finalDrift_us  << "us"
            << "  finalRate="    << finalRate_Mbps << "Mbps" << endl;

    // These scalars appear in General-#0.sca under attackNode.app[0]
    recordScalar("finalDrift_us",    finalDrift_us);
    recordScalar("totalPacketsSent", (double)packetsSent);
    recordScalar("finalRate_Mbps",   finalRate_Mbps);

    ApplicationBase::finish();
}

// ---------------------------------------------------------------------------
// handleStopOperation / handleCrashOperation
// ---------------------------------------------------------------------------
void LowAndSlowDriftApp::handleStopOperation(LifecycleOperation *operation)
{
    cancelEvent(sendTimer);
    socket.close();
}

void LowAndSlowDriftApp::handleCrashOperation(LifecycleOperation *operation)
{
    cancelEvent(sendTimer);
    socket.destroy();
}

// ---------------------------------------------------------------------------
// UdpSocket::ICallback stubs — we only send, never receive
// ---------------------------------------------------------------------------
void LowAndSlowDriftApp::socketDataArrived(UdpSocket *socket, Packet *packet)
{
    delete packet;
}

void LowAndSlowDriftApp::socketErrorArrived(UdpSocket *socket, Indication *indication)
{
    delete indication;
}

void LowAndSlowDriftApp::socketClosed(UdpSocket *socket)
{
    // nothing
}
