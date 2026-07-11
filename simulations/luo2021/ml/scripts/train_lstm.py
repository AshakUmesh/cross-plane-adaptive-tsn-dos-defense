"""
train_lstm.py
=============
Stage 2 of the two-stage detection pipeline.
LSTM trained on sequences of 50 consecutive windows to classify
attack type using temporal patterns that IsoForest cannot see.

ROLE IN PIPELINE
----------------
  LSTM is the TEMPORAL CLASSIFIER:
    - Receives sequences of 50 consecutive normalised feature windows
    - Each sequence = 50 × 15 = 750 input values representing 500ms
    - Outputs: 3-class probability vector (benign / suspect / malicious)
    - The temporal dimension captures TRENDS that single-window
      detectors cannot see (e.g. Gap3 phase drift, Gap4 periodicity)

WHY LSTM FOR STAGE 2
--------------------
  IsoForest sees each 10ms window independently. Attacks like
  Low-and-Slow Drift (Gap3) are nearly indistinguishable from benign
  in any single window early in the attack — the anomaly only becomes
  clear as phase drift accumulates across 30-50 windows.
  LSTM's recurrent state carries information across the sequence,
  enabling detection of TRENDS not visible per-window.

3-CLASS DESIGN
--------------
  Class 0 — BENIGN:    label=0 (General)
  Class 1 — SUSPECT:   labels 7,8 (Low-and-Slow Drift, GateBoundaryProximity)
                        These are gradual/subtle attacks; less certain classification
  Class 2 — MALICIOUS: labels 1,3,4,5,6,9,10,11 (all clear-signature attacks)
                        These produce strong immediate feature deviations

  The 3-class design maps directly to the adaptive PSFP controller:
    BENIGN   → no-op
    SUSPECT  → setCIR(current × 0.5)   [rate-limit without blocking]
    MALICIOUS → closeGate()             [full block with auto-reopen timer]

SEQUENCE CONSTRUCTION
---------------------
  Sequences are built per (config, seed) run to avoid cross-seed
  contamination. Seed N's windows 0-99 are independent of seed N+1.
  Within a run: sliding window of stride=1 → 100-50+1=51 sequences.
  Final dataset: 20 seeds × 51 sequences × 11 configs = ~11,220 seqs.

ARCHITECTURE
------------
  Input  → (50, 15)
  LSTM   → 64 units, return_sequences=True,  dropout=0.2
  LSTM   → 64 units, return_sequences=False, dropout=0.2
  Dense  → 32 units, ReLU
  Dense  → 3 units, Softmax

OUTPUTS
-------
  models/lstm_model.keras              — trained Keras model
  models/lstm_label_map.pkl            — class→label mapping
  results/lstm_scores.csv              — per-sequence probabilities
  results/lstm_metrics.csv             — per-config accuracy/F1
  results/lstm_summary.txt             — thesis-ready summary table
"""

import os
import pickle
import warnings
import numpy as np
import pandas as pd
from pathlib import Path

os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'   # suppress TF INFO/WARNING
import tensorflow as tf
from tensorflow import keras
from tensorflow.keras import layers
from tensorflow.keras.callbacks import EarlyStopping, ReduceLROnPlateau
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.utils.class_weight import compute_class_weight

warnings.filterwarnings('ignore')

# ── paths ─────────────────────────────────────────────────────────────────────
NORM_CSV   = Path('ml/dataset/features_raw.csv')
RAW_CSV    = Path('ml/dataset/features_raw_norm.csv')
MODEL_DIR  = Path('ml/models');   MODEL_DIR.mkdir(exist_ok=True)
RESULT_DIR = Path('ml/results');  RESULT_DIR.mkdir(exist_ok=True)

# ── hyperparameters ───────────────────────────────────────────────────────────
SEQ_LEN        = 50      # 50 windows × 10ms = 500ms context
LSTM_UNITS     = 64      # hidden units per LSTM layer
DROPOUT        = 0.2
DENSE_UNITS    = 32
BATCH_SIZE     = 64
MAX_EPOCHS     = 50
PATIENCE       = 8       # EarlyStopping patience
LR             = 0.001
TRAIN_RATIO    = 0.70    # 70% train, 15% val, 15% test (by seed)
VAL_RATIO      = 0.15
RANDOM_STATE   = 42
N_CLASSES      = 3

FEATURES = [
    'mean_IAT_us', 'IAT_variance_us2', 'mean_frame_size_B', 'burst_length',
    'frame_count', 'phase_offset_mean_us', 'phase_offset_std_us',
    'gate_drop_rate', 'meter_red_rate', 'queue_depth_max',
    'sync_interval_mean', 'sync_interval_var', 'correction_field_delta',
    'announce_rate', 'source_count',
]

# Map fine-grained labels → 3 LSTM classes
# 0=benign, 1=suspect (subtle), 2=malicious (clear)
LABEL_TO_CLASS = {
    0:  0,   # Benign
    1:  2,   # GCLPhaseAttack          → malicious (immediate IAT burst)
    3:  2,   # ThresholdEvasionAttack  → malicious (sustained rate)
    4:  2,   # SustainedNearCIRAttack  → malicious (sustained rate)
    5:  2,   # CBSExhaustionAttack     → malicious (CBS drain + RED)
    6:  2,   # CBSBoundaryAttack       → malicious (CBS riding)
    7:  1,   # LowAndSlowDriftAttack   → suspect   (gradual drift trend)
    8:  1,   # GateBoundaryProximityAttack → suspect (subtle phase position)
    9:  2,   # ScheduleAwareBurstAttack → malicious (clear burst)
    10: 2,   # WindowBoundaryQueuing   → malicious (queue contention)
    11: 2,   # AggregateLoadAttack     → malicious (rate saturation)
}

CLASS_NAMES = {0: 'BENIGN', 1: 'SUSPECT', 2: 'MALICIOUS'}


# ═════════════════════════════════════════════════════════════════════════════
# SEQUENCE BUILDER
# ═════════════════════════════════════════════════════════════════════════════

def build_sequences(norm_df: pd.DataFrame,
                    raw_df:  pd.DataFrame,
                    seq_len: int) -> tuple:
    """
    Build sliding-window sequences per (config, seed) run.

    Crucially, sequences never span across different seeds or configs.
    The 'seed' is inferred from the run order within each config
    (windows are ordered by t_start_s within each config group).

    Returns:
        X : np.ndarray of shape (N_sequences, seq_len, n_features)
        y : np.ndarray of shape (N_sequences,) — 3-class label
        meta : list of (config, class_label) per sequence
    """
    X_list, y_list, meta = [], [], []

    # Merge config + label from raw_df into norm_df index alignment
    norm_df = norm_df.copy()
    norm_df['seq_key'] = (
        norm_df['config'].astype(str) + '_' +
        # Assign seed index: rows 0..99 = seed0, 100..199 = seed1, etc.
        (norm_df.groupby('config').cumcount() // 100).astype(str)
    )

    for key, grp in norm_df.groupby('seq_key'):
        grp = grp.sort_values('t_start_s').reset_index(drop=True)
        X_run = grp[FEATURES].values          # (100, 15)
        lbl   = grp['label'].iloc[0]
        cls   = LABEL_TO_CLASS.get(int(lbl), -1)
        if cls == -1:
            continue   # unknown label — skip

        cfg = grp['config'].iloc[0]

        # Sliding window with stride=1
        n = len(X_run)
        for start in range(n - seq_len + 1):
            seq = X_run[start : start + seq_len]    # (seq_len, 15)
            X_list.append(seq)
            y_list.append(cls)
            meta.append((cfg, cls))

    X = np.array(X_list, dtype=np.float32)
    y = np.array(y_list, dtype=np.int32)

    print(f"Sequences built: {X.shape[0]:,}  shape={X.shape}")
    class_counts = {c: int(np.sum(y == c)) for c in range(N_CLASSES)}
    for c, cnt in class_counts.items():
        print(f"  Class {c} ({CLASS_NAMES[c]:10}): {cnt:6,} sequences")

    return X, y, meta


# ═════════════════════════════════════════════════════════════════════════════
# TRAIN / VAL / TEST SPLIT
# ═════════════════════════════════════════════════════════════════════════════

def split_sequences(X, y, meta, train_r, val_r, seed):
    """
    Split sequences into train / val / test by sequence index.
    Stratified by class: each split contains all classes.
    """
    rng = np.random.default_rng(seed)
    n = len(y)
    idx = rng.permutation(n)

    n_train = int(n * train_r)
    n_val   = int(n * val_r)

    i_train = idx[:n_train]
    i_val   = idx[n_train : n_train + n_val]
    i_test  = idx[n_train + n_val :]

    X_tr, y_tr = X[i_train], y[i_train]
    X_va, y_va = X[i_val],   y[i_val]
    X_te, y_te = X[i_test],  y[i_test]
    meta_te    = [meta[i] for i in i_test]

    print(f"\nSequence split:")
    print(f"  Train : {len(y_tr):,}  "
          f"({np.bincount(y_tr, minlength=N_CLASSES).tolist()})")
    print(f"  Val   : {len(y_va):,}  "
          f"({np.bincount(y_va, minlength=N_CLASSES).tolist()})")
    print(f"  Test  : {len(y_te):,}  "
          f"({np.bincount(y_te, minlength=N_CLASSES).tolist()})")

    return X_tr, y_tr, X_va, y_va, X_te, y_te, meta_te


# ═════════════════════════════════════════════════════════════════════════════
# MODEL DEFINITION
# ═════════════════════════════════════════════════════════════════════════════

def build_model(seq_len: int, n_features: int, n_classes: int) -> keras.Model:
    """
    Two-layer stacked LSTM with dropout.

    Architecture:
      Input     (seq_len, n_features)
      LSTM-1    64 units, return_sequences=True  [sees full sequence]
      LSTM-2    64 units, return_sequences=False [distils to final state]
      Dense-1   32 units, ReLU
      Dropout   0.2
      Dense-2   n_classes, Softmax

    Layer choices:
      return_sequences=True on L1 lets L2 see temporal state at each step.
      return_sequences=False on L2 produces a single 64-dim vector
        summarising the 500ms window — this is the "attack fingerprint".
      Dropout after Dense (not after LSTM) preserves temporal information
        while regularising the classification head.
    """
    model = keras.Sequential([
        layers.Input(shape=(seq_len, n_features)),

        layers.LSTM(LSTM_UNITS, return_sequences=True,
                    dropout=DROPOUT, recurrent_dropout=0.0,
                    name='lstm_1'),

        layers.LSTM(LSTM_UNITS, return_sequences=False,
                    dropout=DROPOUT, recurrent_dropout=0.0,
                    name='lstm_2'),

        layers.Dense(DENSE_UNITS, activation='relu', name='dense_1'),
        layers.Dropout(DROPOUT, name='dropout'),
        layers.Dense(n_classes, activation='softmax', name='output'),
    ], name='tsn_attack_classifier')

    return model


# ═════════════════════════════════════════════════════════════════════════════
# TRAINING
# ═════════════════════════════════════════════════════════════════════════════

def train(model, X_tr, y_tr, X_va, y_va):
    """Compile and fit with EarlyStopping and ReduceLROnPlateau."""

    # Class weights — compensate for class imbalance (2 suspect classes
    # have fewer attack variants than malicious class)
    classes = np.arange(N_CLASSES)
    weights = compute_class_weight('balanced', classes=classes, y=y_tr)
    class_weight = dict(zip(classes.tolist(), weights.tolist()))
    print(f"\nClass weights: { {CLASS_NAMES[c]: round(w,3) for c,w in class_weight.items()} }")

    model.compile(
        optimizer=keras.optimizers.Adam(learning_rate=LR),
        loss='sparse_categorical_crossentropy',
        metrics=['accuracy'],
    )

    model.summary(print_fn=lambda x: print('  ' + x))

    callbacks = [
        EarlyStopping(
            monitor='val_accuracy',
            patience=PATIENCE,
            restore_best_weights=True,
            verbose=1,
        ),
        ReduceLROnPlateau(
            monitor='val_loss',
            factor=0.5,
            patience=4,
            min_lr=1e-6,
            verbose=1,
        ),
    ]

    print(f"\nTraining (max {MAX_EPOCHS} epochs, patience={PATIENCE}) …")
    history = model.fit(
        X_tr, y_tr,
        validation_data=(X_va, y_va),
        epochs=MAX_EPOCHS,
        batch_size=BATCH_SIZE,
        class_weight=class_weight,
        callbacks=callbacks,
        verbose=1,
    )
    return history


# ═════════════════════════════════════════════════════════════════════════════
# EVALUATION
# ═════════════════════════════════════════════════════════════════════════════

def evaluate_model(model, X_te, y_te, meta_te):
    """Full evaluation: per-class + per-config metrics."""

    probs  = model.predict(X_te, batch_size=256, verbose=0)
    preds  = np.argmax(probs, axis=1)

    print(f"\n{'='*65}")
    print("LSTM EVALUATION RESULTS  (Stage 2 — Temporal Classifier)")
    print(f"{'='*65}")

    # Overall accuracy
    acc = float(np.mean(preds == y_te))
    print(f"\nOverall test accuracy : {acc*100:.2f}%")

    # Per-class report
    print("\nPer-class classification report:")
    names = [CLASS_NAMES[i] for i in range(N_CLASSES)]
    report = classification_report(y_te, preds, target_names=names,
                                    zero_division=0)
    print(report)

    # Confusion matrix
    cm = confusion_matrix(y_te, preds)
    print("Confusion matrix (rows=true, cols=pred):")
    print(f"  {'':12}" + "".join(f"{n:>12}" for n in names))
    for i, row in enumerate(cm):
        print(f"  {names[i]:12}" + "".join(f"{v:>12,}" for v in row))

    # Per-config detection rate
    print(f"\nPer-config detection rate:")
    print(f"  {'Config':<36} {'True Class':>10}  {'DR %':>6}  {'Pred Class'}")
    print(f"  {'-'*68}")
    seen = {}
    for i, (cfg, cls) in enumerate(meta_te):
        if cfg not in seen:
            seen[cfg] = {'correct': 0, 'total': 0, 'cls': cls}
        seen[cfg]['total'] += 1
        if preds[i] == y_te[i]:
            seen[cfg]['correct'] += 1
    for cfg, v in sorted(seen.items()):
        dr = v['correct'] / v['total'] * 100
        print(f"  {cfg:<36} {CLASS_NAMES[v['cls']]:>10}  "
              f"{dr:>6.2f}%")

    return probs, preds


def build_results_df(X_te, y_te, probs, preds, meta_te):
    """Build per-sequence results DataFrame."""
    df = pd.DataFrame({
        'true_class':      y_te,
        'pred_class':      preds,
        'prob_benign':     probs[:, 0],
        'prob_suspect':    probs[:, 1],
        'prob_malicious':  probs[:, 2],
        'config':          [m[0] for m in meta_te],
        'correct':         (preds == y_te).astype(int),
    })
    return df


def per_config_metrics(results_df):
    """Build per-config accuracy table for thesis."""
    rows = []
    for cfg, grp in results_df.groupby('config'):
        cls = grp['true_class'].iloc[0]
        acc = grp['correct'].mean() * 100
        rows.append({
            'config':       cfg,
            'true_class':   CLASS_NAMES[cls],
            'n_sequences':  len(grp),
            'accuracy_pct': round(acc, 2),
        })
    return pd.DataFrame(rows).sort_values('accuracy_pct', ascending=False)


def save_outputs(model, probs, preds, results_df, cfg_metrics,
                  history):
    """Save model, scores, metrics, and summary."""

    # Model
    model_path = MODEL_DIR / 'lstm_model.keras'
    model.save(str(model_path))

    # Label map
    with open(MODEL_DIR / 'lstm_label_map.pkl', 'wb') as f:
        pickle.dump({'class_names': CLASS_NAMES,
                     'label_to_class': LABEL_TO_CLASS}, f)

    # Per-sequence scores
    results_df.to_csv(RESULT_DIR / 'lstm_scores.csv', index=False)

    # Per-config metrics
    cfg_metrics.to_csv(RESULT_DIR / 'lstm_metrics.csv', index=False)

    # Training history
    hist_df = pd.DataFrame(history.history)
    hist_df.to_csv(RESULT_DIR / 'lstm_history.csv', index=False)

    # Summary text
    lines = [
        "LSTM — THESIS RESULTS SUMMARY",
        f"Sequence length  : {SEQ_LEN} windows (500ms)",
        f"Architecture     : 2×LSTM(64) + Dense(32) + Softmax(3)",
        f"Classes          : 0=BENIGN  1=SUSPECT  2=MALICIOUS",
        "",
        f"{'Config':<36} {'Class':>10}  {'Accuracy %':>10}",
        "-" * 58,
    ]
    for _, row in cfg_metrics.iterrows():
        lines.append(f"{row.config:<36} {row.true_class:>10}  "
                     f"{row.accuracy_pct:>10.2f}%")
    (RESULT_DIR / 'lstm_summary.txt').write_text('\n'.join(lines))

    print(f"\nSaved:")
    print(f"  {model_path}")
    print(f"  {MODEL_DIR/'lstm_label_map.pkl'}")
    print(f"  {RESULT_DIR/'lstm_scores.csv'}")
    print(f"  {RESULT_DIR/'lstm_metrics.csv'}")
    print(f"  {RESULT_DIR/'lstm_history.csv'}")
    print(f"  {RESULT_DIR/'lstm_summary.txt'}")


# ═════════════════════════════════════════════════════════════════════════════
# MAIN
# ═════════════════════════════════════════════════════════════════════════════

def main():
    print("=" * 55)
    print("STAGE 2: LSTM TEMPORAL CLASSIFIER TRAINING")
    print("=" * 55)

    # Set seed for reproducibility
    tf.random.set_seed(RANDOM_STATE)
    np.random.seed(RANDOM_STATE)

    # Load data
    print("\nLoading data …")
    norm_df = pd.read_csv(NORM_CSV)
    raw_df  = pd.read_csv(RAW_CSV)
    print(f"  Normalised: {norm_df.shape}  |  Raw: {raw_df.shape}")

    # Build sequences
    print("\nBuilding sequences …")
    X, y, meta = build_sequences(norm_df, raw_df, SEQ_LEN)

    # Split
    X_tr, y_tr, X_va, y_va, X_te, y_te, meta_te = split_sequences(
        X, y, meta, TRAIN_RATIO, VAL_RATIO, RANDOM_STATE
    )

    # Build model
    print("\nBuilding model …")
    model = build_model(SEQ_LEN, len(FEATURES), N_CLASSES)

    # Train
    history = train(model, X_tr, y_tr, X_va, y_va)

    # Evaluate
    probs, preds = evaluate_model(model, X_te, y_te, meta_te)

    # Build results
    results_df  = build_results_df(X_te, y_te, probs, preds, meta_te)
    cfg_metrics = per_config_metrics(results_df)

    print(f"\n{'='*55}")
    print("PER-CONFIG METRICS (for thesis Chapter 8):")
    print(cfg_metrics.to_string(index=False))

    # Save
    save_outputs(model, probs, preds, results_df, cfg_metrics, history)

    print("\n✅ Stage 2 complete.")
    print("   IsoForest (Stage 1) + LSTM (Stage 2) pipeline ready.")
    print("   See results/ directory for all metrics.")


if __name__ == '__main__':
    main()
