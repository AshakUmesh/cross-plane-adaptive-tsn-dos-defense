package src.psfp;

network StreamGateTest
{
    submodules:
        source: TestSource;
        gate: StreamGate {
    parameters:
        gateInterval = 500e-6;
}
        sink: TestSink;

    connections:
        source.out --> gate.in;
        gate.out --> sink.in;
}

