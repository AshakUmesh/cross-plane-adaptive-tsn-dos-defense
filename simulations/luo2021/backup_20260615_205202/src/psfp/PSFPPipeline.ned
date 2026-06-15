package src.psfp;

module PSFPPipeline
{
    parameters:
        int streamId = default(1);

    gates:
        input in;
        output out;

    submodules:
        filter: StreamFilter {
            parameters:
                streamId = parent.streamId;
                maxMsdu = 1500;
        }

        gate: StreamGate {
            parameters:
                linkedStreamId = parent.streamId;
                gateInterval = 500e-6;
        }

        meter: FlowMeter {
            parameters:
                cir = 1000000;
                cbs = 500;
        }

    connections:
        in --> filter.in;
        filter.out --> gate.in;
        gate.out --> meter.in;
        meter.out --> out;
}
