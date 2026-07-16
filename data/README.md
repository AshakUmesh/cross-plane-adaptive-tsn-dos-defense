# Dataset

`combined_features_multiclass.csv` — the primary detection dataset. 2325 windows across 12 simulation configurations (1 benign, 11 attack), 5 streams each, 10 ms windows over a 150 ms simulation. Columns: `config, run, stream, window_index, window_start_s`, 5 data-plane features (`mean_IAT, IAT_variance, mean_frame_size, burst_length, count`), 5 schedule-plane features (`phase_offset_mean_us, phase_offset_std_us, gate_util, queue_depth_max, drops`), `label`.

`combined_15_fused.csv` — the 3-plane fusion demonstration dataset. 150 windows across 2 gPTP-enabled configurations (benign + one attack). Adds 5 time-synchronisation features (`sync_event_interval_mean_us, sync_event_interval_var, gm_rate_ratio_mean, gm_rate_ratio_std, pdelay_mean_us`). **Not used for detection** — see the thesis (Chapter 5–6) for why: gPTP measurement density is far below the 10 ms window rate, and no attack in this set targets time synchronisation.

## Regenerating from scratch

Both files are deterministically reproducible from raw OMNeT++ `.vec` output (not included in this repository — see `.gitignore` — regenerate by running the simulation configurations in `simulation/omnetpp.ini`, then):

```bash
./scripts/run_feature_extraction.sh
```

This was independently re-verified during this project: a fresh re-extraction from raw `.vec` files reproduced `combined_features_multiclass.csv` with **zero row or value drift** against the version these results were computed from.

## What is NOT included, and why

- Raw `results/*.vec` and `results/*.sca` files: these are simulator output, typically hundreds of MB to several GB depending on run count, and are fully regenerable from `simulation/omnetpp.ini` — not appropriate for git.
- Intermediate/exploratory CSV variants produced during development (backup copies, alternate window sizes, retraining experiments): excluded to keep the dataset provenance unambiguous. The two files above are the ones every result in the thesis traces back to.
