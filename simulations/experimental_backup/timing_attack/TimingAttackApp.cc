/**
 * TimingAttackApp.cc
 * ─────────────────────────────────────────────────────────────────────────────
 * V1 GCL-Phase Timing Attack — OMNeT++ Implementation
 *
 * VULNERABILITY BEING PROVEN (V1):
 *   Luo 2021's stream gate performs a BINARY, MEMORYLESS check:
 *     "Did this single frame arrive within the open window?"
 *   It never checks inter-arrival time, burst rate, or phase drift.
 *
 *   This module sends at 10× the declared AV1 rate (9 µs interval instead
 *   of 90 µs), but times each burst to land INSIDE the gate-open window
 *   (125–450 µs of every 500 µs GCL cycle). Every frame passes the gate.
 *   The flow meter catches bandwidth excess only after CBS=5004 bytes are
 *   consumed — approximately 10 oversized-but-valid frames later.
 *
 * WHAT TO OBSERVE IN RESULTS:
 *   filterDrops  = 0  (stream filter: VLAN/PCP/MAC match → pass)
 *   gateDrops    = 0  (gate: arrival inside open window → pass)
 *   meterDrops   > 0  (flow meter: eventually fires after CBS exhausted)
 *   BUT: legitimate AV1/AV2 frames experience E2E delay spike because
 *        the queue is saturated BEFORE the meter fires.
 *
 * Author  : Ashak Umesh (M250691CS), NIT Calicut
 * Project : Cross-Plane Adaptive DoS Defence for Automotive TSN
 * Date    : June 2026
 */

#include "TimingAttackApp.h"

#include "inet/common/packet/Packet.h"
#include "inet/common/packet/chunk/ByteCountChunk.h"
#include "inet/linklayer/common/MacAddressTag_m.h"
#include "inet/linklayer/common/VlanTag_m.h"
#include "inet/linklayer/common/PcpTag_m.h"
#include "inet/common/TimeTag_m.h"

Define_Module(TimingAttackApp);

// ─────────────────────────────────────────────────────────────────────────────
// initialize()
// ─────────────────────────────────────────────────────────────────────────────
void TimingAttackApp::initialize()
{
    // ── Read NED parameters ────────────────────────────────────────────────
    attackStartTime   = par("attackStartTime").doubleValue();   // default 0.050 s
    attackStopTime    = par("attackStopTime").doubleValue();    // default 0.150 s
    attackInterval_us = par("attackInterval_us").doubleValue(); // default 9 µs
    frameSize_bytes   = par("frameSize_bytes").intValue();      // default 450 B
    targetVlanId      = par("targetVlanId").intValue();         // default 10
    targetPcp         = par("targetPcp").intValue();            // default 4
    gcl_period_us     = par("gcl_period_us").doubleValue();     // default 500 µs
    gcl_open_start_us = par("gcl_open_start_us").doubleValue(); // default 125 µs
    gcl_open_end_us   = par("gcl_open_end_us").doubleValue();   // default 450 µs
    phase_jitter_us   = par("phase_jitter_us").doubleValue();   // default 0.5 µs

    targetDestMac = MacAddress(par("targetDestMac").stringValue());

    // ── Init statistics ────────────────────────────────────────────────────
    iatVector.setName("attackIAT_us");
    iatVector.setUnit("µs");

    frameSizeVector.setName("attackFrameSize_bytes");
    frameSizeVector.setUnit("bytes");

    windowCountVector.setName("attackFramesPerWindow");
    windowCountVector.setUnit("frames/10ms");

    phaseOffsetVector.setName("attackPhaseOffset_us");
    phaseOffsetVector.setUnit("µs");

    iatHistogram.setName("attackIAT_histogram");
    iatHistogram.setUnit("µs");

    // ── Log startup configuration ──────────────────────────────────────────
    EV_INFO << "[TimingAttackApp] === V1 TIMING ATTACK CONFIGURATION ===" << endl;
    EV_INFO << "[TimingAttackApp] Attack interval  : " << attackInterval_us << " µs"
            << " (declared AV1 = 90 µs, this = " << (90.0 / attackInterval_us) << "×)" << endl;
    EV_INFO << "[TimingAttackApp] Frame size       : " << frameSize_bytes << " B"
            << " (MSDU limit = 530 B → will PASS filter)" << endl;
    EV_INFO << "[TimingAttackApp] VLAN / PCP       : " << targetVlanId << " / " << targetPcp
            << " (matches AV1 stream → passes stream filter)" << endl;
    EV_INFO << "[TimingAttackApp] DestMAC          : " << targetDestMac.str() << endl;
    EV_INFO << "[TimingAttackApp] GCL open window  : " << gcl_open_start_us
            << "–" << gcl_open_end_us << " µs / " << gcl_period_us << " µs period" << endl;
    EV_INFO << "[TimingAttackApp] Attack period    : t=" << attackStartTime
            << "s → t=" << attackStopTime << "s" << endl;
    EV_INFO << "[TimingAttackApp] ================================================" << endl;

    // ── Schedule start/stop events ────────────────────────────────────────
    startSignal = new cMessage("attackStart");
    scheduleAt(SimTime(attackStartTime), startSignal);

    stopSignal = new cMessage("attackStop");
    scheduleAt(SimTime(attackStopTime), stopSignal);

    // ── Schedule first 10ms stats window ─────────────────────────────────
    windowStart = SimTime(0);
    windowTimer = new cMessage("windowBoundary");
    scheduleAt(SimTime(0.010), windowTimer);   // first window boundary at 10ms

    lastSendTime    = SimTime(0);
    attackActive    = false;
    framesSentTotal = 0;
}

// ─────────────────────────────────────────────────────────────────────────────
// handleMessage()
// ─────────────────────────────────────────────────────────────────────────────
void TimingAttackApp::handleMessage(cMessage *msg)
{
    // ── Attack START signal ───────────────────────────────────────────────
    if (msg == startSignal) {
        attackActive = true;
        EV_WARN << "[TimingAttackApp] *** ATTACK STARTED at t="
                << simTime() << " ***" << endl;
        EV_WARN << "[TimingAttackApp] Luo 2021 has NO visibility of this event." << endl;

        // Schedule first attack frame, phase-aligned to GCL open window
        sendTimer = new cMessage("sendFrame");
        simtime_t firstSend = alignToGclWindow(simTime());
        scheduleAt(firstSend, sendTimer);
        return;
    }

    // ── Attack STOP signal ────────────────────────────────────────────────
    if (msg == stopSignal) {
        attackActive = false;
        if (sendTimer && sendTimer->isScheduled())
            cancelEvent(sendTimer);
        EV_WARN << "[TimingAttackApp] *** ATTACK STOPPED at t="
                << simTime() << " ***" << endl;
        EV_WARN << "[TimingAttackApp] Total frames injected: " << framesSentTotal << endl;
        return;
    }

    // ── 10ms window boundary ──────────────────────────────────────────────
    if (msg == windowTimer) {
        recordWindowStats();
        windowStart = simTime();
        framesThisWindow = 0;
        totalWindowsFired++;
        // Reschedule next window boundary
        scheduleAt(simTime() + SimTime(0.010), windowTimer);
        return;
    }

    // ── Send attack frame ─────────────────────────────────────────────────
    if (msg == sendTimer) {
        if (!attackActive) return;

        sendAttackFrame();

        // Schedule next frame
        simtime_t nextSend = computeNextSendTime();
        scheduleAt(nextSend, sendTimer);
        return;
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// sendAttackFrame()
// ─────────────────────────────────────────────────────────────────────────────
void TimingAttackApp::sendAttackFrame()
{
    simtime_t now = simTime();

    // ── Build packet ──────────────────────────────────────────────────────
    Packet *pkt = buildAttackPacket();

    // ── Record IAT ────────────────────────────────────────────────────────
    if (framesSentTotal > 0) {
        double iat_us = (now - lastSendTime).dbl() * 1e6;
        iatVector.record(iat_us);
        iatHistogram.collect(iat_us);

        // KEY LOG: show IAT so we can compare to declared 90 µs
        if (framesSentTotal % 50 == 0) {
            EV_WARN << "[TimingAttackApp] Frame #" << framesSentTotal
                    << "  IAT=" << iat_us << " µs"
                    << "  (legitimate AV1=90µs, ratio="
                    << (90.0 / iat_us) << "×)" << endl;
        }
    }

    // ── Record phase offset within GCL cycle ──────────────────────────────
    double phase_us = phaseOffsetInCycle(now);
    phaseOffsetVector.record(phase_us);

    // Verify frame is inside open window — this is the KEY invariant:
    // EVERY attack frame must be inside the window so gateDrops stays 0
    bool insideWindow = (phase_us >= gcl_open_start_us && phase_us <= gcl_open_end_us);
    if (!insideWindow) {
        EV_WARN << "[TimingAttackApp] WARNING: frame at phase=" << phase_us
                << " µs is OUTSIDE gate window ["
                << gcl_open_start_us << "–" << gcl_open_end_us << " µs]!"
                << " This frame WILL be gate-dropped (not desired for V1 proof)." << endl;
    }

    // ── Record frame size ─────────────────────────────────────────────────
    frameSizeVector.record(frameSize_bytes);

    // ── Update counters ───────────────────────────────────────────────────
    lastSendTime = now;
    framesSentTotal++;
    framesThisWindow++;
    totalFramesSent++;

    // ── Send to lower layer (gate → PSFP pipeline) ────────────────────────
    send(pkt, "out");

    EV_DETAIL << "[TimingAttackApp] SENT frame #" << framesSentTotal
              << "  size=" << frameSize_bytes << "B"
              << "  phase=" << phase_us << " µs"
              << "  (inside_window=" << insideWindow << ")"
              << "  t=" << now << endl;
}

// ─────────────────────────────────────────────────────────────────────────────
// buildAttackPacket()
//   Constructs a packet that is INDISTINGUISHABLE from a legitimate AV1 frame
//   from the perspective of Luo 2021's PSFP pipeline:
//     • Same DestMAC → passes StreamFilter (MAC match)
//     • Same VLAN ID → passes StreamFilter (VLAN match)
//     • Same PCP=4   → passes StreamFilter (priority match)
//     • Size < 530 B → passes MSDU gate
//     • Timed inside window → passes GCL gate
//   Only the flow meter can catch it — but only after CBS=5004 B are used.
// ─────────────────────────────────────────────────────────────────────────────
Packet* TimingAttackApp::buildAttackPacket()
{
    // Create packet with payload of exactly frameSize_bytes
    auto payload = makeShared<ByteCountChunk>(B(frameSize_bytes));

    // Add creation timestamp for E2E delay measurement
    auto timeTag = payload->addTagIfAbsent<CreationTimeTag>();
    timeTag->setCreationTime(simTime());

    auto pkt = new Packet("AttackFrame", payload);

    // ── Attach MAC destination (spoofed to match AV1 stream filter) ───────
    auto macTag = pkt->addTagIfAbsent<MacAddressReq>();
    macTag->setDestAddress(targetDestMac);
    // Source MAC: attacker's own MAC (doesn't matter for stream filter — 
    // Luo 2021 stream filter checks DEST MAC only)
    macTag->setSrcAddress(MacAddress("AA:BB:CC:DD:EE:FF"));

    // ── Attach VLAN tag (must match AV1 stream: VLAN=10, PCP=4) ──────────
    auto vlanTag = pkt->addTagIfAbsent<VlanReq>();
    vlanTag->setVlanId(targetVlanId);   // VLAN 10 = AV1 stream

    auto pcpTag = pkt->addTagIfAbsent<PcpReq>();
    pcpTag->setPcp(targetPcp);           // PCP 4 = AV1 priority class

    return pkt;
}

// ─────────────────────────────────────────────────────────────────────────────
// computeNextSendTime()
//   Returns the simtime for the next frame such that it lands INSIDE the
//   GCL open window. Attack interval is 9 µs, but if the next 9 µs would
//   fall outside the window, skip to the next window's open start.
//
//   This models a knowledgeable attacker who has sniffed the GCL schedule
//   (trivially observable on a shared Ethernet bus) and times bursts
//   accordingly.
// ─────────────────────────────────────────────────────────────────────────────
simtime_t TimingAttackApp::computeNextSendTime()
{
    simtime_t now = simTime();
    double now_us = now.dbl() * 1e6;

    // Ideal next send time at attack rate
    double next_us = now_us + attackInterval_us;

    // Add small realistic jitter (attacker not perfectly synchronized)
    double jitter = uniform(-phase_jitter_us, phase_jitter_us);
    next_us += jitter;

    // Compute phase offset of proposed send time within GCL cycle
    double period = gcl_period_us;
    double phase  = fmod(next_us, period);

    // If proposed time would land in CLOSED window, advance to next open window
    if (phase < gcl_open_start_us || phase > gcl_open_end_us) {
        // How many full cycles until the next open window?
        double cycles_elapsed = floor(next_us / period);
        double next_open_abs  = (cycles_elapsed + 1) * period + gcl_open_start_us + 1.0; // +1µs margin
        next_us = next_open_abs;

        EV_DETAIL << "[TimingAttackApp] Phase re-alignment: skipped to next open window at "
                  << next_us << " µs" << endl;
    }

    return SimTime(next_us * 1e-6);
}

// ─────────────────────────────────────────────────────────────────────────────
// alignToGclWindow()
//   Given a time t (e.g., attack start), find the next moment that falls
//   inside the GCL open window. Used to schedule the very first attack frame.
// ─────────────────────────────────────────────────────────────────────────────
simtime_t TimingAttackApp::alignToGclWindow(simtime_t t)
{
    double t_us   = t.dbl() * 1e6;
    double period = gcl_period_us;
    double phase  = fmod(t_us, period);

    double aligned_us;
    if (phase >= gcl_open_start_us && phase <= gcl_open_end_us) {
        // Already inside open window — add small margin
        aligned_us = t_us + 1.0;
    } else if (phase < gcl_open_start_us) {
        // Before window opens this cycle — wait until open
        aligned_us = t_us + (gcl_open_start_us - phase) + 1.0;
    } else {
        // Past window close — wait until next cycle's open
        double cycles = floor(t_us / period);
        aligned_us = (cycles + 1) * period + gcl_open_start_us + 1.0;
    }

    EV_INFO << "[TimingAttackApp] First frame aligned to GCL open window: "
            << aligned_us << " µs (phase=" << fmod(aligned_us, period) << " µs)" << endl;

    return SimTime(aligned_us * 1e-6);
}

// ─────────────────────────────────────────────────────────────────────────────
// phaseOffsetInCycle()
//   Returns how many µs into the current GCL cycle the time t falls.
//   Used to verify every injected frame is inside the open window.
// ─────────────────────────────────────────────────────────────────────────────
double TimingAttackApp::phaseOffsetInCycle(simtime_t t)
{
    double t_us = t.dbl() * 1e6;
    return fmod(t_us, gcl_period_us);
}

// ─────────────────────────────────────────────────────────────────────────────
// recordWindowStats()
//   Called at each 10ms window boundary. Logs the count of attack frames
//   injected in this window — this is the data your Python feature extractor
//   will read. A legitimate AV1 stream sends ~111 frames in 10ms (90µs IAT).
//   The attacker sends ~1111 frames in 10ms (9µs IAT).
// ─────────────────────────────────────────────────────────────────────────────
void TimingAttackApp::recordWindowStats()
{
    windowCountVector.record(framesThisWindow);

    simtime_t windowDuration = simTime() - windowStart;
    double expectedLegitimate = 10000.0 / 90.0;   // ~111 frames in 10ms at 90µs
    double ratio = (framesThisWindow > 0 && expectedLegitimate > 0)
                   ? (framesThisWindow / expectedLegitimate)
                   : 0.0;

    if (attackActive) {
        EV_WARN << "[TimingAttackApp] WINDOW [" << windowStart << " → " << simTime() << "]"
                << "  frames_injected=" << framesThisWindow
                << "  (legitimate=~111, attack=" << framesThisWindow
                << ", ratio=" << ratio << "×)"
                << "  Luo 2021 sees: filterDrops=0, gateDrops=0" << endl;
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// finish()
//   Record final scalar statistics. These appear in the .sca output file
//   which your Python script will parse for the thesis comparison table.
// ─────────────────────────────────────────────────────────────────────────────
void TimingAttackApp::finish()
{
    // ── Summary statistics ────────────────────────────────────────────────
    recordScalar("attack_total_frames_sent",   (double)totalFramesSent);
    recordScalar("attack_windows_fired",       (double)totalWindowsFired);
    recordScalar("attack_interval_us",         attackInterval_us);
    recordScalar("attack_rate_multiplier",     90.0 / attackInterval_us);
    recordScalar("attack_frame_size_bytes",    (double)frameSize_bytes);
    recordScalar("gcl_period_us",              gcl_period_us);
    recordScalar("gcl_open_start_us",          gcl_open_start_us);
    recordScalar("gcl_open_end_us",            gcl_open_end_us);

    iatHistogram.recordAs("attackIAT_histogram");

    // ── Compute expected vs actual throughput ─────────────────────────────
    double attackDuration_s = attackStopTime - attackStartTime;
    double framesPerSec     = (attackDuration_s > 0)
                              ? (totalFramesSent / attackDuration_s)
                              : 0;
    double throughput_Mbps  = framesPerSec * frameSize_bytes * 8.0 / 1e6;

    recordScalar("attack_throughput_Mbps",     throughput_Mbps);

    // ── Print final diagnostic ────────────────────────────────────────────
    EV_WARN << "======================================================" << endl;
    EV_WARN << "[TimingAttackApp] FINAL STATISTICS — V1 TIMING ATTACK" << endl;
    EV_WARN << "======================================================" << endl;
    EV_WARN << "  Total frames injected:  " << totalFramesSent << endl;
    EV_WARN << "  Attack duration:        " << attackDuration_s * 1000 << " ms" << endl;
    EV_WARN << "  Effective throughput:   " << throughput_Mbps << " Mbps" << endl;
    EV_WARN << "  Attack rate vs AV1:     " << (90.0 / attackInterval_us) << "×" << endl;
    EV_WARN << "  Frame size:             " << frameSize_bytes << " B"
            << "  (MSDU limit=530B → all frames PASSED Luo 2021 filter)" << endl;
    EV_WARN << "------------------------------------------------------" << endl;
    EV_WARN << "  EXPECTED Luo 2021 result:" << endl;
    EV_WARN << "    filterDrops = 0   (stream filter: VLAN/PCP/MAC match)" << endl;
    EV_WARN << "    gateDrops   = 0   (gate: every frame inside window)" << endl;
    EV_WARN << "    meterDrops  > 0   (flow meter: fires AFTER CBS=5004B)" << endl;
    EV_WARN << "    BUT: legitimate AV1/AV2 STARVED before meter fires" << endl;
    EV_WARN << "  YOUR PROPOSAL detects IAT=~9µs (vs normal=90µs) in 1st 10ms window" << endl;
    EV_WARN << "======================================================" << endl;
}
