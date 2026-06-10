package src.psfp;

network FlowMeterTest
{
    submodules:
        source: TestSource;
        meter: FlowMeter {
            parameters:
                cir = 8000;    // 8000 bps = 1000 bytes/sec
                cbs = 500;     // bucket capacity 500 bytes
        }
        sink: TestSink;

    connections:
        source.out --> meter.in;
        meter.out --> sink.in;
}
