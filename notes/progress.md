# Automotive Ethernet Security Project

Date: Jun 4, 2026

## Day 1 - Environment Setup

* Installed required development tools.
* Verified GCC, G++, Make, Git, Python.
* Installed Tcl/Tk development libraries.
* Prepared Linux development environment.

## Day 2 - OMNeT++ Setup

* Built OMNeT++ 6.4.0 successfully.
* Configured environment using setenv.
* Compiled and executed Aloha sample simulation.
* Verified OMNeT++ simulation environment.

## Day 3 - INET Framework Setup

* Verified INET 4.6.0 installation.
* Generated makefiles using make makefiles.
* Built INET successfully.
* Verified creation of libINET.so.
* Executed Ethernet LinearNetwork simulation.
* Simulation completed successfully up to 10 seconds.

## Current Status

* OMNeT++: Operational
* INET: Operational
* Ethernet Simulations: Operational

## Next Steps

* Study Ethernet and TSN examples.
* Understand automotive Ethernet topologies.
* Begin modeling ECU and switch-based architectures.

## Day 4

- Successfully cloned CoRE4INET.
- Configured INET path and generated makefiles.
- Investigated build failures.
- Determined CoRE4INET requires OMNeT++ 6.0.2 + INET 3.8.x.
- Current environment uses OMNeT++ 6.4 + INET 4.6.
- Build stopped due to deprecated INET APIs (EtherFrame, Ieee802Ctrl).
- Read CoRE4INET documentation and identified supported TSN features:
  * TAS (802.1Qbv)
  * CBS (802.1Qav)
  * AVB
  * Credit-Based Shaper
  * TTEthernet
- Need supervisor confirmation whether CoRE4INET is mandatory or native INET TSN is sufficient.

## Day 5
✓ Investigated CoRE4INET IEEE 802.1Qci implementation
✓ Located PSFP components:
   - IEEE8021QciFilter
   - IEEE8021QciGate
   - CreditBasedMeter / FrameSizeMeter

✓ Investigated INET 4.6 TSN support
✓ Verified TSN showcase execution
✓ Identified:
   - StreamFilterLayer
   - EligibilityTimeFilter
   - EligibilityTimeGate
   - EligibilityTimeMeter

✓ Decision:
   Primary simulator = INET 4.6
   Reference implementation = CoRE4INET

⚠ NeSTiNg repository inaccessible (authentication required)
⚠ Formal IEEE 802.1Qci tutorial/spec review pending

## Day 6

✓ Verified Python virtual environment (vehicular_env)

✓ Installed and verified ML stack:
   - PyTorch 2.12.0+cu130
   - Scikit-learn 1.7.2
   - Pandas
   - NumPy
   - Matplotlib
   - Seaborn
   - Scapy

✓ Installed and verified ONNX ecosystem:
   - ONNX 1.21.0
   - ONNX Runtime 1.23.2

✓ Verified Python imports and package functionality

✓ Verified packet analysis environment:
   - Wireshark 3.6.2
   - TShark 3.6.2

✓ Added user to Wireshark capture group

✓ Environment ready for:
   - ML model development
   - Dataset processing
   - Network packet analysis
   - ONNX model export and inference

⚠ ONNX Runtime C++ package (libonnxruntime-dev) not available in Ubuntu repository

✓ Decision:
   Primary ML framework = PyTorch
   Model exchange format = ONNX
   Packet analysis tools = Wireshark + TShark
   Python ONNX Runtime sufficient for current research phase
   
## Day 7
 
 ✓ Read Luo 2021 paper completely

✓ Extracted topology
   - 2 switches (VCU/VIU)
   - 5 end devices
   - 100 Mbps links
   - 8 µs switch delay

✓ Extracted TAS configuration
   - 500 µs cycle
   - Q7 / Q0-Q6 schedule
   - Guard band
   - Buffer size = 30 packets

✓ Extracted traffic streams (Table 5)
   - periods
   - payloads
   - priorities
   - stream assignments

✓ Extracted PSFP configuration
   - Stream Filter
   - Stream Gate
   - Flow Meter
   - CIR/CBS/EIR/EBS values

✓ Extracted attack scenarios
   - Wrong Timing
   - DoS Attack
   - Undefined Traffic
   - MSDU Violation

✓ Extracted baseline results (Table 9)

✓ Created topology diagram

✓ Created luo2021_notes.md

✓ Defined Phase-1 reproduction target

✓ Identified thesis research gap



