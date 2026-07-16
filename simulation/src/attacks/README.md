# Attack Modules

## Evaluated (thesis Chapter 4, 11 attacks)
GCLPhaseAttack, ThresholdEvasionAttack, LowAndSlowDriftApp, ScheduleAwareBurstApp — implemented here.
(SustainedNearCIR, AggregateLoad, QueueBuilding, CBSBoundary, CBSExhaustion, GateBoundaryProximity,
WindowBoundaryQueuing are configuration variants of these modules, driven via `simulation/omnetpp.ini`
rather than separate source files — see the `[Config ...]` sections in that file for each.)

## Not evaluated — exploratory / early-stage
`OversizeAttack` and `FrequencyAttack` were implemented during early exploration of the attack space
and are **not** part of the thesis's evaluated 11-attack taxonomy (Chapter 4). No detection, classification,
or enforcement results in this repository correspond to them. Included for completeness / possible future work.
