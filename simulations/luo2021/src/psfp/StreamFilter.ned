package src.psfp;

simple StreamFilter
{
    parameters:
        int streamId = default(1);
        int maxMsdu = default(1500);

        @display("i=block/filter");

    gates:
        input in;
        output out;
}
