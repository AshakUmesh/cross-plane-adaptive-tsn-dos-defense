package src.psfp;

simple StreamGate
{
    parameters:
        string gcl = default("open:100us,closed:400us");
        double gateInterval = default(500e-6);
        int linkedStreamId = default(1);

        @display("i=block/gate");

    gates:
        input in;
        output out;
}
