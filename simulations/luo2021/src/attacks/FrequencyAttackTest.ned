package src.attacks;

import src.attacks.FrequencyAttack;
import src.psfp.FlowMeter;
import src.psfp.TestSink;

network FrequencyAttackTest
{
    submodules:

        attacker: FrequencyAttack {
            parameters:
                attackStartTime = 0s;
                attackInterval = 100us;   // 10x faster
                streamId = 1;
                payloadSize = 500;
        }

        meter: FlowMeter {
            parameters:
                cir = 1000000;
                cbs = 500;
        }

        sink: TestSink;
    connections:

        attacker.out --> meter.in;
        meter.out --> sink.in;
}
