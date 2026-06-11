import src.attacks.OversizeAttack;
import inet.networklayer.configurator.ipv4.Ipv4NetworkConfigurator;	
import inet.node.tsn.TsnSwitch;
import inet.node.tsn.TsnDevice;

network Luo2021NetworkAttack
{
    submodules:
	configurator: Ipv4NetworkConfigurator {
        }
        viuSwitch: TsnSwitch {
            parameters:
                numEthInterfaces = 5;
        }

        vcuSwitch: TsnSwitch {
            parameters:
                numEthInterfaces = 2;
        }

        av1: TsnDevice;
        av2: TsnDevice;
        radarNode: TsnDevice;
        zonalHost: TsnDevice;
        attacker: OversizeAttack {
            parameters:
                targetStreamId = 1;
                oversizeBytes = 500;
                maxMsdu = 1500;
                attackStartTime = 1s;
        }

        centralHost: TsnDevice;

    connections:
        av1.ethg++ <--> { delay = 0.5us; datarate = 100Mbps; } <--> viuSwitch.ethg++;
        av2.ethg++ <--> { delay = 0.5us; datarate = 100Mbps; } <--> viuSwitch.ethg++;
        radarNode.ethg++ <--> { delay = 0.5us; datarate = 100Mbps; } <--> viuSwitch.ethg++;
        zonalHost.ethg++ <--> { delay = 0.5us; datarate = 100Mbps; } <--> viuSwitch.ethg++;

        viuSwitch.ethg++ <--> { delay = 0.5us; datarate = 100Mbps; } <--> vcuSwitch.ethg++;

        centralHost.ethg++ <--> { delay = 0.5us; datarate = 100Mbps; } <--> vcuSwitch.ethg++;
}
