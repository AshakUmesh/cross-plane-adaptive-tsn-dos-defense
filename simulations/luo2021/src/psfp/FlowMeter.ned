package src.psfp;

simple FlowMeter
{
    parameters:
        double cir = default(1000000);   // bits per second
        int cbs = default(500);          // bytes

        @display("i=block/process");

    gates:
        input in;
        output out;
}
