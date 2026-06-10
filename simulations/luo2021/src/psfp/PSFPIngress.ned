package src.psfp;

module PSFPIngress
{
    parameters:
        int streamId = default(1);

    gates:
        input in;
        output out;

    submodules:
        psfp: PSFPPipeline {
            parameters:
                streamId = parent.streamId;
        }

    connections:
        in --> psfp.in;
        psfp.out --> out;
}
