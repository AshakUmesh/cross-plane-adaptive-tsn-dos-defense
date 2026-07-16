package src.attacks;

simple OversizeAttack
{
    parameters:
        int targetStreamId = default(1);
        int oversizeBytes = default(500);
        int maxMsdu = default(1500);
        double attackStartTime @unit(s) = default(1s);

        @display("i=block/source");

    gates:
        output out;
}
