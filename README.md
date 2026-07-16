# Cross-Plane Adaptive DoS Defence for Automotive TSN

**Detecting and mitigating protocol-compliant Denial-of-Service attacks against IEEE 802.1Qci PSFP in Time-Sensitive-Networking-based Automotive Ethernet.**

M.Tech thesis project — Department of Computer Science & Engineering, National Institute of Technology Calicut.
Author: Ashak Umesh (M250691CS) · Guide: Dr. Arun Raj Kumar P

---

## What this is

IEEE 802.1Qci PSFP (Per-Stream Filtering and Policing) defends TSN networks with three stateless, per-packet checks: a Stream Filter (Stream-ID / max frame size), a Stream Gate (Gate-Control-List timing), and a Flow Meter (CIR/CBS rate policing). This project shows, experimentally, that an attacker who respects every one of these static thresholds can still degrade the network — and then builds a cross-plane, closed-loop system that detects and adaptively mitigates that traffic.

**Two halves:**

1. **Vulnerability analysis** — 11 protocol-compliant DoS attacks (timing manipulation, rate/threshold evasion, queue-dynamics exploitation), each implemented as a real INET application module (`simulation/src/attacks/`) against a PSFP implementation (`simulation/src/psfp/`) on the Luo et al. (2021) reference topology. All 11 pass Stream Filter, Stream Gate, and Flow Meter with **zero recorded violations**, while increasing legitimate-stream mean delay by **8.4×–14.2×**.
2. **Cross-plane defence** — a 10-feature (data-plane + schedule-plane) Isolation Forest / Random Forest detection pipeline, a rule-based adaptive PSFP policy engine, and a reward-driven offline RL agent, closing the loop: detect → classify → reconfigure PSFP → re-simulate → measure → reward.

## Key results (all measured, not estimated)

| Metric | Value |
|---|---|
| Attacks detected (data plane, 7 with a data-plane signature) | 100% TPR, held-out FPR 1.7%, ROC-AUC 0.998 |
| Attacks detected overall (data + schedule plane combined) | 10 / 11 |
| Attack-type classification accuracy (Random Forest, 7 classes) | 71.4% |
| Adaptive PSFP: attack traffic reduction (CIR-bounded attacks) | 39–50%, measured from real OMNeT++ `.sca` output |
| Adaptive PSFP: legitimate traffic recovery | ~+22% on affected streams |
| RL policy agreement with hand-authored policy | 88.9% (ground truth) / 77.8% (realistic classifier noise) |

**One attack (Schedule-Aware Burst) evades detection on both planes** — its burst is timed to coincide with the switch's own natural queue-draining, producing a feature signature statistically indistinguishable from benign traffic. This is documented, not hidden; see [`docs/`](docs/) for the full analysis.

## Repository structure

```
.
├── simulation/               OMNeT++/INET network + PSFP configuration
│   ├── omnetpp.ini
│   ├── network.ned
│   ├── attack_network.ned
│   └── src/
│       ├── psfp/              PSFP implementation (Stream Filter, Stream Gate, Flow Meter)
│       └── attacks/           Protocol-compliant attack application modules
├── ml/pipeline/               Feature extraction, detection, classification
│   ├── feature_extractor.py               data-plane extractor
│   ├── feature_extractor_schedule.py      schedule-plane extractor
│   ├── feature_extractor_timesync.py      time-sync-plane extractor
│   ├── combined_feature_extractor.py      single-pass, all 3 planes
│   ├── merge_planes_and_test.py           plane-fusion ablation utility
│   ├── train_isoforest.py                 Stage-1 unsupervised detector
│   ├── train_random_forest.py             Stage-2 attack-type classifier
│   ├── benchmark_classifiers.py           classifier comparison / selection
│   ├── two_tier_pipeline.py               IsoForest → RF chained pipeline
│   ├── run_full_pipeline_demo.py          end-to-end trace replay
│   ├── run_full_pipeline_verified.py      end-to-end pipeline, all 5 stages
│   └── mimicry_aware_detector.py          schedule-plane mimicry-attack detector
├── adaptive_psfp/             Policy engine, reward, RL, closed-loop orchestration
│   ├── psfp_policy.py                     rule-based bounded action space
│   ├── apply_psfp_action.py               offline PSFP-state mutation check
│   ├── reward_function.py                 base + measured-blocking reward
│   ├── rl_agent.py                        RL agent interface / feasibility gate
│   ├── train_rl_agent.py                  offline trace-replay RL training
│   ├── closed_loop_runner.py              policy → config generation → re-simulation
│   └── compute_real_rewards.py            reward from measured .sca output
├── scripts/                   Simulation batch + pipeline orchestration
│   ├── run_complete_pipeline.sh
│   ├── run_feature_extraction.sh
│   └── run_luo.sh, run_and_extract*.sh, run_adaptive_batch.sh, extract_all_closedloop.sh
├── data/                      Extracted feature datasets (see data/README.md)
├── results/                   Curated evidence: reward/enforcement/detection reports (JSON/txt)
├── docs/                      Topology diagram, build notes, thesis, presentation
├── requirements.txt
└── .gitignore
```

Raw OMNeT++ `.vec`/`.sca` simulation output (~2.8GB across 194 files in the original research repository) is intentionally **not** included — see `.gitignore` and `data/README.md` for why, and how to regenerate it.

## Getting started

```bash
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt --break-system-packages

# Regenerate the feature dataset from raw OMNeT++ output (requires results/*.vec)
./scripts/run_feature_extraction.sh

# Train and evaluate the detector
python3 ml/pipeline/train_isoforest.py --csv data/combined_features_multiclass.csv --stream all
python3 ml/pipeline/train_random_forest.py --csv data/combined_features_multiclass.csv --stream attackNode
python3 ml/pipeline/two_tier_pipeline.py --csv data/combined_features_multiclass.csv --stream attackNode ...

# Run the full verified end-to-end pipeline
python3 ml/pipeline/run_full_pipeline_verified.py --csv data/combined_features_multiclass.csv
```

Simulation configuration (`simulation/omnetpp.ini`, `simulation/network.ned`) requires OMNeT++ 6.0+ and INET 4.5+.

## Honest limitations (see thesis for full detail)

- The time-synchronisation feature plane is implemented and its fusion mechanism is verified, but is **not used** in the evaluated detector: gPTP measurement density (~100 ms–1 s cycle) is far below the 10 ms detection window, and no attack in this set targets time synchronisation.
- Adaptive PSFP reconfiguration is **offline / inter-run** (regenerate config → re-simulate), not a live in-simulation parameter mutation.
- Two attack classes (CBS-directed, gate-directed mitigation) show near-zero measured enforcement effect — traced to a specific, diagnosed lever/attack-behaviour mismatch, not a broken pipeline.
- Evaluation is simulation-only, on a single reference topology, with a modest per-attack sample size (15 windows/attack).

Full reasoning, evidence, and future-work scope for each of the above is in the thesis document (`docs/`).

## Citation / reference

Luo, F. et al., "Security Analysis of TSN Backbone Architecture Based on IEEE 802.1Qci," *Security and Communication Networks*, 2021 — reference topology and PSFP baseline this work extends.

## License

See [LICENSE](LICENSE).
