package src.attacks;

//
// ScheduleAwareBurstApp — Gap 4 INET-integrated attack application
//
// Runs inside TsnDevice.app[] in place of UdpSourceApp.
// Fires a burst of burstSize frames at the exact GCL gate-open moment,
// every interburstInterval (CBS token refill period = 1.82ms).
//
// Set in omnetpp.ini:
//   *.attackNode.app[0].typename = "ScheduleAwareBurstApp"
//   *.attackNode.app[0].destAddress = "centralHost"
//   *.attackNode.app[0].destPort = 6001
//   *.attackNode.app[0].localPort = 6101
//
// NOTE: "like IApp" is intentionally omitted — see LowAndSlowDriftApp.ned.
//
import inet.applications.contract.IApp;

simple ScheduleAwareBurstApp like IApp
{
    parameters:
        string destAddress = default("centralHost");
        int    destPort    = default(6001);
        int    localPort   = default(6101);

        // Attack start time (default 1ms — lets baseline settle)
        double attackStartTime @unit(s) = default(0.001s);

        // GCL geometry — must match Luo 2021 Table 6
        double cyclePeriod      @unit(s) = default(500us);
        double gateOpenOffset   @unit(s) = default(125us);  // Q0-Q6 opens at 125µs
        double burstGuardOffset @unit(s) = default(2us);    // 2µs after gate opens

        // Burst design — verified: 7×529B=3703B < CBS(5004B), 7×42.32µs=296µs < window(325µs)
        int    burstSize          = default(7);
        double intraburstSpacing  @unit(s) = default(0.1us);   // near back-to-back
        double interburstInterval @unit(s) = default(1820us);  // CBS refill time

        // Frame size — must be < maxMsdu(530B) for StreamFilter evasion
        int payloadSize = default(529);

        @display("i=block/app");

    gates:
        input  socketIn;
        output socketOut;
}
