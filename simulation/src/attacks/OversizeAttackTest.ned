package src.attacks;

import src.attacks.OversizeAttack;
import src.psfp.StreamFilter;
import src.psfp.TestSink;

network OversizeAttackTest
{
    submodules:
        attacker: OversizeAttack {
            parameters:
                targetStreamId = 1;
                oversizeBytes = 500;
                maxMsdu = 1500;
                attackStartTime = 0s;
        }

        filter: StreamFilter {
            parameters:
                streamId = 1;
                maxMsdu = 1500;
        }

        sink: TestSink;

    connections:
        attacker.out --> filter.in;
        filter.out --> sink.in;
}
