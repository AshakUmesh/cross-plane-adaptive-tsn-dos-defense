# Results

Curated evidence supporting specific claims in the thesis. Raw model binaries and raw OMNeT++ output are excluded (regenerable); everything here is small text/JSON.

| File / folder | What it is | Thesis reference |
|---|---|---|
| closed_loop_results.json, real_pipeline_results.json | End-to-end pipeline run output | Ch. 7.8 |
| psfp_before_after.json | Offline PSFP-state before/after check | Ch. 7 |
| psfp_enforcement_baseline.txt, psfp_enforcement_rl_dynamic.txt | Static vs RL-driven enforcement | Ch. 7.7 |
| experiments/table1_isoforest_final/ | Primary Stage-1 Isolation Forest | Ch. 6.2 |
| experiments/random_forest/ | Primary Random Forest classifier | Ch. 6.5 |
| experiments/classifier_benchmark/ | Model comparison (RF vs SVM vs XGBoost) | Ch. 6.5 |
| experiments/pooled_for_pipeline/ | IsoForest model for two-tier pipeline | Ch. 6.5, 7.8 |
| experiments/rl_agent/ | RL training artifacts | Ch. 7.7 |
| experiments/mimicry_gcl_c01/, mimicry_gcl_c05/, mimicry_window_c05/ | Contamination sweep for mimicry detection | Ch. 6.3 |
| experiments/per_stream_*/, pooled_all/ | Per-stream vs pooled baseline variants | Ch. 6.3 |
| experiments/rf_calibrated_isoforest/ | RF feature-importance calibration | train_random_forest.py |
| experiments/random_forest_before/, random_forest_after/ | Retraining distribution-shift experiment | Ch. 10.1 |
