package src.attacks;

//
// LowAndSlowDriftApp — Gap 3 INET-integrated attack application
//
// Runs inside TsnDevice.app[] in place of UdpSourceApp.
// Declares socketIn/socketOut gates so TsnDevice can wire it into
// the UDP socket infrastructure — same structural interface as all
// INET application modules without requiring IApp to be resolved.
//
// Set in omnetpp.ini:
//   *.attackNode.app[0].typename = "LowAndSlowDriftApp"
//   *.attackNode.app[0].destAddress = "centralHost"
//   *.attackNode.app[0].destPort = 6001
//   *.attackNode.app[0].localPort = 6100
//
// NOTE: "like IApp" is intentionally omitted. TsnDevice resolves the
// app typename at runtime from the ini file. Gate compatibility
// (socketIn/socketOut) is sufficient for structural wiring.
//
import inet.applications.contract.IApp;

simple LowAndSlowDriftApp like IApp
{
    parameters:
        // Destination host (centralHost in Luo2021Network)
        string destAddress = default("centralHost");

        // UDP destination port (must match UdpSinkApp at centralHost)
        int destPort = default(6001);

        // Local UDP port for binding
        int localPort = default(6100);

        // When to start sending (default 1ms — after baseline settles)
        double attackStartTime @unit(s) = default(0.001s);

        // Starting inter-frame interval — identical to AV1's declared period.
        // At t=0 the attacker is indistinguishable from a legitimate AV1 node.
        double nominalInterval @unit(s) = default(90us);

        // Drift increment added to interval per packet sent.
        // 0.09us = 0.5us/cycle × (90us/500us) = ppm-level drift.
        // After 150ms: ~1666 packets × 0.09us = 150us total drift.
        double driftPerPacket @unit(s) = default(0.09us);

        // Payload size — must equal AV1's nominal size (500B) so that
        // StreamFilter MSDU check always passes (limit = 530B).
        int payloadSize = default(500);

        @display("i=block/app");

    gates:
        input  socketIn;
        output socketOut;
}
