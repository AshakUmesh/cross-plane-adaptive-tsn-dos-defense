package src.psfp;

simple TestSource
{
    gates:
        output out;
}

simple TestSink
{
    gates:
        input in;
}

network StreamFilterTest
{
    submodules:
        source: TestSource;
        filter: StreamFilter {
            parameters:
                streamId = 1;
                maxMsdu = 1500;
        }
        sink: TestSink;

    connections:
        source.out --> filter.in;
        filter.out --> sink.in;
}
