# Cross-Plane Adaptive DoS Defense for TSN-based Automotive Ethernet

> Detecting and mitigating protocol-compliant Denial-of-Service attacks against IEEE 802.1Qci PSFP in Time-Sensitive Networking-based automotive Ethernet.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![OMNeT++](https://img.shields.io/badge/OMNeT%2B%2B-6.0%2B-orange.svg)](https://omnetpp.org/)
[![INET](https://img.shields.io/badge/INET-4.5%2B-blue.svg)](https://inet.omnetpp.org/)
[![Python](https://img.shields.io/badge/Python-3.10%2B-green.svg)](https://www.python.org/)
[![Status](https://img.shields.io/badge/status-thesis%20defense%202026-brightgreen.svg)](#)

**M.Tech Thesis · Department of Computer Science & Engineering · National Institute of Technology Calicut**
Author: **Ashak Umesh** (M250691CS) · Supervisor: **Dr. Arun Raj Kumar P.**, Associate Professor, CSED

---

## Overview

Modern vehicles are becoming rolling data centers. IEEE 802.1 Time-Sensitive Networking (TSN) carries safety-critical streams — brake commands, radar feeds, steering signals — over shared automotive Ethernet with sub-millisecond timing budgets. IEEE 802.1Qci Per-Stream Filtering and Policing (PSFP) protects those streams with three stateless per-packet checks: a **Stream Filter** (Stream-ID / max frame size), a **Stream Gate** (Gate-Control-List timing), and a **Flow Meter** (CIR/CBS rate policing).

This project shows, experimentally, that an attacker who respects *every one* of these static thresholds can still degrade the network — and then builds a **cross-plane, closed-loop defense** that detects and adaptively mitigates that traffic, while formally preserving ASIL-D safety-critical streams from any ML decision.

**The project has two halves:**

1. **Vulnerability analysis** — Eleven protocol-compliant DoS attacks (timing manipulation, rate/threshold evasion, queue-dynamics exploitation) implemented as INET application modules against a reference PSFP implementation on the Luo et al. (2021) topology. All eleven pass Stream Filter, Stream Gate, and Flow Meter with zero recorded violations while measurably degrading network behavior.

2. **Cross-plane defense** — A three-tier closed-loop system: (i) multi-plane feature extraction (data-plane + schedule-plane) per Stream-ID per 10 ms window, (ii) a two-stage ML detection cascade (Isolation Forest → Random Forest), and (iii) an adaptive IEEE 802.1Qci PSFP enforcement engine driven by a Q-learning RL agent. ASIL-D streams are statically bypassed from all ML decisions by construction.

---

## Key Results

All numbers below are measured on OMNeT++ 6.4 + INET 4.5, verified against source data files, and locked as of 30 July 2026.

### Headline metrics

| Metric | Value | Method |
|---|---|---|
| **Binary anomaly detection (ROC-AUC)** | **0.9262** | Isolation Forest, StratifiedKFold, dedup |
| **Cross-plane balanced-accuracy lift** | **+20.45 pp** | Data plane only (15.60%) → Data + Schedule (36.05%) |
| **Statistical significance (McNemar)** | **p < 10⁻⁵** | 16:1 odds ratio, cross-plane vs. single-plane |
| **Adaptive PSFP mitigation** | **66.7%** | 4 of 6 leaking attacks blocked (attacks that static PSFP fails on) |
| **RL policy agreement** | **83.33%** | Learned Q-policy vs. hand-authored expert policy |
| **ASIL-D safety guarantee** | **100%** | Statically enforced bypass — formally verified separation |

### Full multiclass results (12 classes: Benign + 11 attacks)

| Metric | Value |
|---|---|
| Accuracy | 74.37% |
| Balanced accuracy | 16.14% |
| Macro-F1 | 19.70% |

**Read the accuracy honestly:** predicting "Benign" for every row gives 60.2% accuracy on the 11-attack set, 69.6% on 7 attacks, and 81.6% on 4 attacks — with *no learning at all*. The Random Forest sits only ~3 pp above this trivial baseline, which is why the primary contribution is framed as **binary detection + adaptive mitigation + cross-plane McNemar validation**, not multiclass attribution.

### Cross-plane ablation (primary novelty evidence)

Identical rows (819 after dedup), identical folds:

| Feature set | Balanced accuracy | Macro-F1 |
|---|---|---|
| 5 data-plane features | 15.60% | 16.90% |
| 5 data + 5 schedule features | **36.05%** | **36.20%** |
| **Absolute lift** | **+20.45 pp** | **+19.30 pp** |

McNemar test on paired predictions: **p < 10⁻⁵** (reported as p = 1×10⁻⁶), odds ratio 16:1.

### Adaptive PSFP enforcement

Nine attacks reach the PSFP rate threshold (LowAndSlowDrift and ScheduleAwareBurst do not).
- Under static PSFP: 6 pass, 3 blocked.
- After RL-driven adaptation: **4 of the 6 leaking attacks become blocked** (AggregateLoad, QueueBuilding, SustainedNearCIR, ThresholdEvasion).
- 2 remain leaking (GateBoundaryProximity, WindowBoundaryQueuing — rate 8.46 Mbps is below any effective CIR-reduction threshold; documented, not hidden).

---

## System Architecture

```
                    ┌───────────────────────────────────────────┐
                    │        Ingress TSN frames (10 ms windows) │
                    └────────────────────┬──────────────────────┘
                                         │
      ┌──────────────┐    ┌──────────────▼──────────────────┐
      │   ASIL-D     │    │ TIER 1 · Multi-plane extraction │
      │   BYPASS     │    │  ┌─────────┐┌──────────┐┌─────┐ │
      │  (statically │    │  │  Data   ││ Schedule ││Time-│ │
      │   preserved) │    │  │  plane  ││  plane   ││ sync│ │
      │              │    │  └─────────┘└──────────┘└─────┘ │
      │  Never       │    │                    time-sync    │
      │  touches     │    │            reserved: gPTP > win │
      │  ML          │    └────────────────┬────────────────┘
      │              │                     │
      │              │    ┌────────────────▼────────────────┐
      │              │    │ TIER 2 · Two-stage ML cascade    │
      │              │    │  IsoForest → Random Forest       │
      │              │    │  anomaly scoring → attribution   │
      │              │    └────────────────┬────────────────┘
      │              │                     │
      │              │    ┌────────────────▼────────────────┐    ┌──────────┐
      │              │    │ TIER 3 · Adaptive PSFP           │◀───│ Reward   │
      │              │    │  Q-learning agent → 802.1Qci     │    │ (RL loop)│
      │              │    │  tighten_gate · reduce_cir · …   │    └──────────┘
      │              │    └────────────────┬────────────────┘
      │              │                     │
      └──────────────┴─────────────────────▼───────────────────────
                              Egress · safety preserved
```

**Key design decisions:**
- **10 ms detection window** — chosen to balance schedule-plane observability against reaction latency.
- **Two-stage cascade** — unsupervised anomaly scoring absorbs zero-day drift; supervised attribution provides labels for enforcement.
- **RL agent operates offline / inter-run** — INET's PSFP modules lack runtime `handleParameterChange` support; the adaptive loop is honestly characterized as inter-simulation, not intra-simulation.
- **ASIL-D bypass is compile-time, not runtime** — no ML decision can affect safety-critical streams by construction, satisfying ISO 26262 separation requirements.

---

## Repository Structure

```
.
├── simulation/                        OMNeT++ / INET network + PSFP configuration
│   ├── omnetpp.ini
│   ├── network.ned
│   ├── attack_network.ned
│   └── src/
│       ├── psfp/                      PSFP: Stream Filter, Stream Gate, Flow Meter
│       └── attacks/                   Protocol-compliant attack application modules
│
├── ml/pipeline/                       Feature extraction, detection, classification
│   ├── feature_extractor.py                    data-plane extractor
│   ├── feature_extractor_schedule.py           schedule-plane extractor
│   ├── feature_extractor_timesync.py           time-sync-plane extractor (reserved)
│   ├── combined_feature_extractor.py           single-pass, all three planes
│   ├── merge_planes_and_test.py                plane-fusion ablation utility
│   ├── train_isoforest.py                      Stage-1 unsupervised detector
│   ├── train_random_forest.py                  Stage-2 attack-type classifier
│   ├── benchmark_classifiers.py                classifier comparison / selection
│   ├── ablation_comparison.py                  cross-plane ablation runner
│   ├── ablation_significance.py                McNemar test on paired predictions
│   ├── two_tier_pipeline.py                    IsoForest → RF chained pipeline
│   ├── run_full_pipeline_verified.py           end-to-end, all five stages
│   └── mimicry_aware_detector.py               schedule-plane mimicry detector
│
├── adaptive_psfp/                     Policy engine, reward function, RL, orchestration
│   ├── psfp_policy.py                          rule-based bounded action space
│   ├── apply_psfp_action.py                    offline PSFP-state mutation check
│   ├── reward_function.py                      base + measured-blocking reward
│   ├── rl_agent.py                             Q-learning agent
│   ├── train_rl_agent.py                       offline trace-replay training
│   ├── closed_loop_runner.py                   policy → config → re-simulation
│   └── compute_real_rewards.py                 reward from measured .sca output
│
├── scripts/                           Batch + pipeline orchestration
│   ├── run_complete_pipeline.sh
│   ├── run_feature_extraction.sh
│   ├── run_luo.sh
│   ├── run_and_extract*.sh
│   ├── run_adaptive_batch.sh
│   └── extract_all_closedloop.sh
│
├── data/                              Extracted feature datasets
│   ├── combined_15_fused.csv                   3 planes × 5 features × 150 rows
│   ├── combined_features_multiclass.csv        5 streams × 12 classes × 2325 rows
│   └── README.md                               how to regenerate raw data
│
├── results/                           Curated evidence
│   ├── experiments/rl_agent/rl_report.json
│   ├── psfp_before_after.json
│   ├── psfp_enforcement_baseline.txt
│   └── psfp_enforcement_rl_dynamic.txt
│
├── docs/                              Topology diagram, thesis, presentation, poster
├── requirements.txt
├── LICENSE                            MIT
└── .gitignore
```

Raw OMNeT++ `.vec`/`.sca` output (~2.8 GB across 194 files) is intentionally not committed. See [`data/README.md`](data/README.md) for regeneration instructions.

---

## Requirements

**Simulation stack**
- OMNeT++ 6.0 or later ([download](https://omnetpp.org/download/))
- INET Framework 4.5 or later ([download](https://inet.omnetpp.org/Download.html))
- CoRE4INET ([repository](https://github.com/CoRE-RG/CoRE4INET))
- NeSTiNg ([repository](https://gitlab.com/ipvs/nesting))

**ML / analysis stack**
- Python 3.10+
- scikit-learn, pandas, numpy, scipy, matplotlib (see `requirements.txt`)

---

## Getting Started

```bash
# 1. Clone
git clone https://github.com/AshakUmesh/cross-plane-adaptive-tsn-dos-defense.git
cd cross-plane-adaptive-tsn-dos-defense

# 2. Python environment
python3 -m venv venv
source venv/bin/activate            # Windows: venv\Scripts\activate
pip install -r requirements.txt

# 3. (Optional) Regenerate feature dataset from raw OMNeT++ output
./scripts/run_feature_extraction.sh

# 4. Train and evaluate the two-stage detector
python3 ml/pipeline/train_isoforest.py \
    --csv data/combined_features_multiclass.csv --stream all

python3 ml/pipeline/train_random_forest.py \
    --csv data/combined_features_multiclass.csv --stream attackNode

# 5. Reproduce the cross-plane ablation (primary novelty evidence)
python3 ml/pipeline/ablation_comparison.py \
    --csv data/combined_15_fused.csv

python3 ml/pipeline/ablation_significance.py \
    --csv data/combined_15_fused.csv                    # McNemar test

# 6. Full end-to-end verified pipeline
python3 ml/pipeline/run_full_pipeline_verified.py \
    --csv data/combined_features_multiclass.csv

# 7. Adaptive PSFP closed-loop
python3 adaptive_psfp/closed_loop_runner.py \
    --policy adaptive_psfp/psfp_policy.py
```

---

## Reproducing Published Results

To reproduce the headline metrics reported in the thesis and paper:

```bash
# Binary ROC-AUC 0.9262
python3 ml/pipeline/train_isoforest.py --csv data/combined_features_multiclass.csv --stream all --report

# Cross-plane lift +20.45 pp with McNemar p < 10⁻⁵
python3 ml/pipeline/ablation_comparison.py --csv data/combined_15_fused.csv --seed 42
python3 ml/pipeline/ablation_significance.py --csv data/combined_15_fused.csv --seed 42

# Adaptive PSFP 66.7% (4/6 leaking attacks blocked)
python3 adaptive_psfp/compute_real_rewards.py --results results/psfp_before_after.json

# RL policy agreement 83.33%
python3 adaptive_psfp/train_rl_agent.py --episodes 2000 --dump-q --seed 42
```

All published results use `seed=42` and StratifiedKFold with `class_weight='balanced'`. Dedup removes 16.3% duplicate rows before evaluation.

---

## Honest Limitations & Disclosures

This project follows an "honest disclosure first" principle. The following are documented explicitly:

1. **Time-synchronization plane extracted but excluded from the evaluated detector.** gPTP events fire approximately every 100 ms while the detection window is 10 ms — 63% of time-sync feature values are missing. The extractor is implemented (`ml/pipeline/feature_extractor_timesync.py`) and fusion is verified, but the plane is reserved for future evaluation with adaptive-window techniques.

2. **Feature separability is the primary blocker, not class imbalance.** Silhouette score on the 5 data-plane features is 0.012 — attack classes overlap heavily on data-plane statistics alone. `class_weight='balanced'` contributes only +0.6 pp. This is *why* the cross-plane approach exists.

3. **295 rows have identical feature vectors but disagreeing labels.** Attack pairs such as WindowBoundary and AggregateLoad are fundamentally indistinguishable on data-plane statistics — label noise is measured and reported, not hidden.

4. **Multiclass raw accuracy is misleading for this dataset.** Predicting "Benign" for every row yields 60–82% accuracy depending on subset (11-attack, 7-attack, 4-attack). Macro-F1, per-class recall, and binary ROC-AUC are the defensible metrics.

5. **ScheduleAwareBurst is genuinely undetectable by any traffic-statistics feature set.** Its burst is timed to coincide with the switch's own natural queue-draining; the resulting feature signature is statistically indistinguishable from benign bursty traffic. Detection would require schedule-authorization-aware stream verification (out of scope; noted as future work).

6. **Both 7-attack subset and full 11-attack results are reported.** The IsoForest 100% recall figure was measured on a 7-attack subset; the full 11-attack overall TPR is 15.97% at 0.83% FPR, with per-stream variance (av1 = 21.43%, av2 = 14.29%, radarNode = 0%, zonalHost = 0%). Both figures appear in the thesis with clear subset disclosure.

7. **Adaptive PSFP reconfiguration is inter-run / offline, not intra-simulation.** INET's PSFP modules do not implement runtime `handleParameterChange`. The closed loop regenerates configuration between runs, re-simulates, and measures — an honest architectural constraint, not a broken pipeline.

8. **Simulation-only evaluation on a single reference topology** with modest per-attack sample size (15 windows per attack). Hardware-in-the-loop validation and multi-topology generalization are explicit future work.

Full reasoning, evidence tables, and future-work scope for each of the above are in the thesis document (`docs/`).

---

## Documentation

- [`docs/thesis.pdf`](docs/) — Full M.Tech thesis with all methodology, results, and analysis
- [`docs/paper.pdf`](docs/) — IEEE-format paper (target venue: IEEE TVT / COMSNETS 2027)
- [`docs/poster.pdf`](docs/) — Conference-format defense poster (A0)
- [`docs/topology.png`](docs/) — Luo 2021 reference topology diagram
- [`docs/architecture.png`](docs/) — Three-tier system architecture

---

## Citation

If you use this work, please cite:

```bibtex
@mastersthesis{umesh2026crossplane,
  author  = {Ashak Umesh},
  title   = {Cross-Plane Adaptive Denial-of-Service Defense for
             Time-Sensitive Networking-based Automotive Ethernet},
  school  = {National Institute of Technology Calicut},
  year    = {2026},
  address = {Kozhikode, Kerala, India},
  type    = {{M.Tech Thesis}},
  note    = {Department of Computer Science and Engineering}
}
```

### Related work referenced

- Luo, F. et al., "Security Analysis of TSN Backbone Architecture Based on IEEE 802.1Qci," *Security and Communication Networks*, 2021. **Reference topology this work extends.**
- Meyer, P. et al., "Intrusion Detection for Time-Sensitive Networking," *IEEE VNC*, 2019/2020.
- Häckel, T. et al., "Attack Surface Analysis of Automotive TSN Networks," 2023.
- Adil, M. et al., "IDS for Automotive Networks: A Survey," *IEEE Transactions on Intelligent Transportation Systems*, 2026.
- IEEE Std 802.1Qci-2017 — Per-Stream Filtering and Policing.
- IEEE Std 802.1Qbv-2015 — Enhancements for Scheduled Traffic.
- ISO 26262:2018 — Road vehicles — Functional safety.

---

## Acknowledgments

- **Dr. Arun Raj Kumar P.**, Associate Professor, CSED, NIT Calicut — thesis supervision and technical guidance.
- **Department of Computer Science & Engineering, NIT Calicut** — computing resources and academic support.
- **OMNeT++, INET, CoRE4INET, and NeSTiNg communities** — open-source simulation infrastructure.
- **F. Luo et al.** — for the reference topology and PSFP baseline this work builds on.

---

## License

Released under the [MIT License](LICENSE).

---

## Contact

**Ashak Umesh** — M.Tech Computer Science & Engineering, NIT Calicut
- GitHub: [@AshakUmesh](https://github.com/AshakUmesh)
- LinkedIn: [linkedin.com/in/ashakumesh](https://linkedin.com/in/ashakumesh)
- Institute: National Institute of Technology Calicut, Kerala, India

For questions about the methodology, simulation setup, or reproducing results, please open a [GitHub Issue](https://github.com/AshakUmesh/cross-plane-adaptive-tsn-dos-defense/issues).
