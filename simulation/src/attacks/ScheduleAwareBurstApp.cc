#include "ScheduleAwareBurstApp.h"

#include "inet/common/ModuleAccess.h"
#include "inet/common/packet/Packet.h"
#include "inet/common/packet/chunk/ByteCountChunk.h"
#include "inet/networklayer/common/L3AddressResolver.h"

Define_Module(ScheduleAwareBurstApp);

// ---------------------------------------------------------------------------
// initialize
// ---------------------------------------------------------------------------
void ScheduleAwareBurstApp::initialize(int stage)
{
    ApplicationBase::initialize(stage);

    if (stage == INITSTAGE_LOCAL) {
        attackStartTime    = par("attackStartTime");
        cyclePeriod        = par("cyclePeriod");
        gateOpenOffset     = par("gateOpenOffset");
        burstGuardOffset   = par("burstGuardOffset");
        burstSize          = par("burstSize");
        intraburstSpacing  = par("intraburstSpacing");
        interburstInterval = par("interburstInterval");
        payloadSize        = par("payloadSize");
        destPort           = par("destPort");
        localPort          = par("localPort");

        burstTrigger = new cMessage("burstTrigger");
        frameTimer   = new cMessage("frameTimer");

        int burstBytes = burstSize * payloadSize;
        double avgRate = (burstBytes * 8.0) / interburstInterval.dbl() / 1e6;

        EV_INFO << "ScheduleAwareBurstApp initialized:" << endl
                << "  burstSize          = " << burstSize << " frames" << endl
                << "  payloadSize        = " << payloadSize << "B" << endl
                << "  burstBytes         = " << burstBytes << "B (CBS=5004B)" << endl
                << "  interburstInterval = " << interburstInterval * 1e3 << "ms" << endl
                << "  averageRate        = " << avgRate << "Mbps (CIR=22Mbps)" << endl;
    }
    else if (stage == INITSTAGE_APPLICATION_LAYER) {
        destAddress = L3AddressResolver().resolve(par("destAddress"));
    }
}

// ---------------------------------------------------------------------------
// handleStartOperation
// ---------------------------------------------------------------------------
void ScheduleAwareBurstApp::handleStartOperation(LifecycleOperation *operation)
{
    socket.setOutputGate(gate("socketOut"));
    socket.setCallback(this);
    socket.bind(localPort);

    // First burst fires at attackStartTime + gateOpenOffset + burstGuardOffset.
    // This places the first burst frame at 127µs into the simulation —
    // exactly 2µs after the Q0-Q6 gate opens at 125µs.
    simtime_t firstBurst = attackStartTime + gateOpenOffset + burstGuardOffset;
    scheduleAt(simTime() + firstBurst, burstTrigger);
}

// ---------------------------------------------------------------------------
// handleMessageWhenUp
// ---------------------------------------------------------------------------
void ScheduleAwareBurstApp::handleMessageWhenUp(cMessage *msg)
{
    if (msg == burstTrigger) {
        // Start new burst
        burstIndex = 0;
        totalBursts++;

        sendBurstFrame();
        burstIndex++;

        if (burstIndex < burstSize) {
            scheduleAt(simTime() + intraburstSpacing, frameTimer);
        } else {
            scheduleBurstTrigger();
        }
    }
    else if (msg == frameTimer) {
        // Continue current burst
        sendBurstFrame();
        burstIndex++;

        if (burstIndex < burstSize) {
            scheduleAt(simTime() + intraburstSpacing, frameTimer);
        } else {
            scheduleBurstTrigger();
        }
    }
    else {
        socket.processMessage(msg);
    }
}

// ---------------------------------------------------------------------------
// sendBurstFrame
// ---------------------------------------------------------------------------
void ScheduleAwareBurstApp::sendBurstFrame()
{
    auto payload = makeShared<ByteCountChunk>(B(payloadSize));
    auto packet  = new Packet("scheduleAwareBurst", payload);

    socket.sendTo(packet, destAddress, destPort);
    totalFramesSent++;

    EV_DEBUG << "ScheduleAwareBurstApp: burst #" << totalBursts
             << " frame #" << burstIndex
             << " at t=" << simTime() * 1e6 << "us"
             << " phase=" << fmod(simTime().dbl() * 1e6, cyclePeriod.dbl() * 1e6) << "us"
             << endl;
}

// ---------------------------------------------------------------------------
// scheduleBurstTrigger
// ---------------------------------------------------------------------------
// Schedules the next burst start exactly interburstInterval after the
// current burst's start time. This keeps the burst period stable.
void ScheduleAwareBurstApp::scheduleBurstTrigger()
{
    simtime_t currentBurstStart = simTime()
        - (burstSize - 1) * intraburstSpacing;
    simtime_t nextTrigger = currentBurstStart + interburstInterval;
    scheduleAt(nextTrigger, burstTrigger);
}

// ---------------------------------------------------------------------------
// finish
// ---------------------------------------------------------------------------
void ScheduleAwareBurstApp::finish()
{
    EV_INFO << "ScheduleAwareBurstApp finished:"
            << "  totalBursts=" << totalBursts
            << "  totalFramesSent=" << totalFramesSent << endl;

    recordScalar("totalBursts",      (double)totalBursts);
    recordScalar("totalFramesSent",  (double)totalFramesSent);
    recordScalar("avgBurstRate_Mbps",
        (totalFramesSent * payloadSize * 8.0) / simTime().dbl() / 1e6);

    ApplicationBase::finish();
}

// ---------------------------------------------------------------------------
// handleStopOperation / handleCrashOperation
// ---------------------------------------------------------------------------
void ScheduleAwareBurstApp::handleStopOperation(LifecycleOperation *operation)
{
    cancelEvent(burstTrigger);
    cancelEvent(frameTimer);
    socket.close();
}

void ScheduleAwareBurstApp::handleCrashOperation(LifecycleOperation *operation)
{
    cancelEvent(burstTrigger);
    cancelEvent(frameTimer);
    socket.destroy();
}

// ---------------------------------------------------------------------------
// UdpSocket::ICallback stubs
// ---------------------------------------------------------------------------
void ScheduleAwareBurstApp::socketDataArrived(UdpSocket *socket, Packet *packet) { delete packet; }
void ScheduleAwareBurstApp::socketErrorArrived(UdpSocket *socket, Indication *indication) { delete indication; }
void ScheduleAwareBurstApp::socketClosed(UdpSocket *socket) {}
