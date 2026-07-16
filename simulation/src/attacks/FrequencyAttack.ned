package src.attacks;

simple FrequencyAttack
{
    parameters:
        double attackStartTime @unit(s);
        double attackInterval @unit(s);

        int streamId = default(1);
        int payloadSize = default(500);

    gates:
        output out;
}
