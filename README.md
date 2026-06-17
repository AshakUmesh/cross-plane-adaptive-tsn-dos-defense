# Automotive Ethernet Security using TSN and IEEE 802.1Qci

Research project focused on evaluating timing-aware denial-of-service attacks and protection mechanisms in Time-Sensitive Networking (TSN) for Automotive Ethernet.

## Overview

Modern automotive networks increasingly rely on Ethernet and TSN to support deterministic communication for safety-critical applications such as cameras, radar sensors, and vehicle control systems.

This project reproduces the Luo 2021 automotive TSN architecture and investigates security vulnerabilities arising from timing-aware attacks. The work evaluates the effectiveness of IEEE 802.1Qci Per-Stream Filtering and Policing (PSFP) mechanisms in mitigating malicious traffic while preserving deterministic communication guarantees.

## Research Objectives

* Reproduce the Luo 2021 TSN automotive network architecture.
* Validate baseline TSN communication behavior.
* Implement IEEE 802.1Qci PSFP components.
* Evaluate denial-of-service attacks against TSN traffic.
* Analyze limitations of timing-based protection mechanisms.
* Develop and validate enhanced security strategies.

## Implemented Components

### PSFP Modules

* Stream Filter
* Flow Meter
* Stream Gate

### Attack Modules

* Oversize Packet Attack
* Frequency-Based Attack
* GCL Phase Timing Attack

## Simulation Environment

| Component        | Version      |
| ---------------- | ------------ |
| OMNeT++          | 6.4          |
| INET Framework   | 4.x          |
| Operating System | Ubuntu 22.04 |

## Project Structure

```text
automotive-ethernet-security/
├── docs/
├── notes/
├── papers/
├── thesis/
├── simulations/
│   └── luo2021/
│       ├── src/
│       │   ├── attacks/
│       │   └── psfp/
│       ├── saved_results/
│       ├── network.ned
│       ├── omnetpp.ini
│       └── Makefile
└── README.md
```

## Current Status

### Completed

* Luo 2021 topology reproduction
* Baseline validation
* PSFP integration
* Oversize attack evaluation
* Frequency attack evaluation
* GCL phase attack implementation

### In Progress

* Advanced timing-aware attack analysis
* Security evaluation and benchmarking
* Experimental result analysis
* Thesis documentation

## Key Files

| File             | Description                     |
| ---------------- | ------------------------------- |
| `network.ned`    | Automotive TSN network topology |
| `omnetpp.ini`    | Simulation configuration        |
| `src/psfp/`      | PSFP implementation             |
| `src/attacks/`   | Attack implementations          |
| `saved_results/` | Experimental outputs            |

## Results

Experimental outputs and validation datasets are available under:

```text
simulations/luo2021/saved_results/
```

## Author

Ashak Umesh

M.Tech – Computer Science and Information Security

National Institute of Technology Calicut

## Reference

Luo et al., "TSN for Automotive Ethernet", 2021.
