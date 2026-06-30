"""
feature_extractor.py  v2
========================
Parses OMNeT++ .vec / .sca output from Luo2021Network simulations,
produces 15-feature vectors per 10 ms window, computes V2 gPTP
time-sync features with real variance, and applies Z-score
normalisation fitted on benign-only data.

WHY NORMALISATION IS CRITICAL
------------------------------
Without Z-score normalisation IsoForest distances are dominated by
IAT_variance_us2 (range 0–2730) while features like gate_drop_rate
(range 0–1) contribute almost nothing.  After normalisation every
feature lives on the same scale (μ=0, σ=1 over benign windows) so
IsoForest can detect anomalies in ANY dimension equally.

The scaler is fitted ONLY on label=0 (benign) windows, then applied
to all windows.  This mirrors real deployment: the scaler is calibrated
during a known-clean commissioning phase, then used at runtime.

ZERO-VARIANCE HANDLING
-----------------------
If a feature has std=0 over the benign fit set (e.g. time-sync features
when no V2 attack is present), StandardScaler would produce NaN.
We replace NaN Z-scores with 0 (no contribution to anomaly distance),
which is the statistically correct interpretation: a constant feature
carries no information for anomaly detection.

V2 TIME-SYNC FEATURE DESIGN
-----------------------------
gPTP spoofing (V2) is not yet simulated in Luo2021Network. To give
F11–F15 real variance and enable V2 detection in future runs, we:
  (a) generate synthetic gPTP perturbation for windows labelled V2
  (b) document the expected attack values so a real gPTP vec signal
      can replace the synthetic values with zero code changes

Real signal path (future): parse gPTP Sync/Announce packet timestamps
from the .vec file, compute inter-message intervals per window, feed
them into F11–F15 exactly as F01–F05 use packet arrival timestamps.

15 FEATURES
-----------
Data Plane  (F01–F05):
  F01  mean_IAT_us          Mean inter-arrival time (µs)
  F02  IAT_variance_us2     Variance of IAT (µs²)           [catches V1 burst]
  F03  mean_frame_size_B    Mean payload size (bytes)        [catches V3 529B]
  F04  burst_length         Max consecutive frames IAT<50µs  [catches V1, Gap4]
  F05  frame_count          Frames per 10ms window           [catches V3 cadence]

Schedule Plane (F06–F10):
  F06  phase_offset_mean_us Mean GCL arrival phase (µs)     [catches Gap3 drift]
  F07  phase_offset_std_us  Std of GCL arrival phase (µs)   [catches Gap3 spread]
  F08  gate_drop_rate       Gate drops per ms                [catches Gap3 ramp]
  F09  meter_red_rate       Meter RED marks per ms           [catches CBS exhaust]
  F10  queue_depth_max      Peak egress queue depth          [catches Gap4 burst]

Time-Sync Plane (F11–F15):
  F11  sync_interval_mean   Mean gPTP sync interval (µs)    [catches V2 rogue GM]
  F12  sync_interval_var    Variance of sync interval (µs²) [catches V2 jitter]
  F13  correction_field_delta gPTP correction field (ns)    [catches V2 clock err]
  F14  announce_rate        Announce msgs/s                  [catches V2 flooding]
  F15  source_count         Distinct grandmaster IDs seen    [catches V2 rogue GM]

OUTPUTS (from --batch or normalise mode)
----------------------------------------
  features_raw.csv     — raw feature values, all windows, all labels
  features_norm.csv    — Z-score normalised, same rows
  scaler_params.csv    — per-feature mean and std used for normalisation
                         (save these for IsoForest / LSTM training)

USAGE
-----
  # Extract raw features from all result files
  python feature_extractor.py --batch results/ --out features_raw.csv

  # Extract + normalise in one step (most common for ML pipeline)
  python feature_extractor.py --batch results/ --out features_raw.csv --normalise

  # Single config
  python feature_extractor.py \\
      --vec results/GCLPhaseAttack-#0.vec \\
      --sca results/GCLPhaseAttack-#0.sca \\
      --label 1 --out features_gclphase.csv --normalise

LABEL CONVENTION
----------------
  0 = benign                   (General / Baseline config)
  1 = GCL Phase Burst          (V1)
  2 = Threshold Evasion        (V3)
  3 = Low-and-Slow Drift       (Gap3)
  4 = Schedule-Aware Burst     (Gap4)
  5 = Multi-Flow Coordinated
  6 = Identity Mimicry
  7 = Oversize Attack          (V1 baseline — Luo detects this)
  8 = gPTP Spoofing            (V2 — synthetic / future hardware)
"""

import argparse
import os
import re
import sys
from pathlib import Path
from collections import defaultdict

import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler

# ── tuneable constants ────────────────────────────────────────────────────────
WINDOW_S            = 0.010        # 10 ms tumbling window
GCL_CYCLE_US        = 500.0        # Luo 2021 Table 6
BURST_IAT_THRESH_US = 50.0         # IAT < 50µs → same burst
#   50µs = half of nominal AV1 interval (90µs)
#   Benign AV1:       IAT≈90µs  > 50µs → burst_length=0  ✓
#   GCL Phase attack: IAT≈40µs  < 50µs → burst_length>0  ✓
#   CBS burst attack: IAT≈0.1µs < 50µs → burst_length=7  ✓
SIM_TIME_S          = 0.150        # 150 ms simulation

# ── gPTP benign baseline (F11–F15) ───────────────────────────────────────────
# Values reflect IEEE 802.1AS default timings for automotive TSN.
GPTP_BENIGN = {
    'sync_interval_mean':       125_000.0,   # µs  (125 ms standard sync period)
    'sync_interval_var':              0.0,   # µs² (ideal clock, no jitter)
    'correction_field_delta':         0.0,   # ns  (no correction needed)
    'announce_rate':                  1.0,   # msg/s (standard announce interval)
    'source_count':                   1.0,   # one grandmaster
}

# ── gPTP V2 attack perturbation ───────────────────────────────────────────────
# Applied to windows labelled as V2 (label=8) when no real gPTP vec signal
# is present.  Represents a rogue grandmaster announcing at 2x rate with
# large correction field offsets and clock jitter.
# Replace with real parsed gPTP timestamps when hardware capture is available.
GPTP_V2_ATTACK = {
    'sync_interval_mean':        62_500.0,   # µs  — rogue GM syncs at 2x rate
    'sync_interval_var':         50_000.0,   # µs² — jitter from rogue clock
    'correction_field_delta':       500.0,   # ns  — large correction field delta
    'announce_rate':                  4.0,   # msg/s — rogue floods Announce msgs
    'source_count':                   2.0,   # two GMs competing → rogue detected
}

# ── config-name → label ───────────────────────────────────────────────────────
CONFIG_LABEL_MAP = {
    'General':                      0,
    'Baseline':                     0,
    'GCLPhaseAttack':               1,
    'ThresholdEvasionAttack':       2,
    'SustainedNearCIRAttack':       2,
    'LowAndSlowDriftAttack':        3,
    'GateBoundaryProximityAttack':  3,
    'ScheduleAwareBurstAttack':     4,
    'CBSExhaustionAttack':          4,
    'CBSBoundaryAttack':            4,
    'MultiFlowCoordinatedAttack':   5,
    'AggregateLoadAttack':          5,
    'IdentityMimicryAttack':        6,
    'OversizeAttack':               7,
    'WindowBoundaryQueuingAttack':  4,
    'gPTPSpoofingAttack':           8,
}

# ── module-path regexes ───────────────────────────────────────────────────────
RE_PKT_RX    = re.compile(
    r'Luo2021Network\.(centralHost|attackNode\d*)\.app\[(\d+)\]')
RE_GATE_DROP = re.compile(
    r'Luo2021Network\.(viuSwitch|vcuSwitch)\.bridging\.streamFilter\.ingress$')
RE_METER_RED = re.compile(
    r'Luo2021Network\.(viuSwitch|vcuSwitch)\.bridging\.streamFilter\.ingress\.meter\[\d+\]')
RE_QUEUE     = re.compile(
    r'Luo2021Network\.(viuSwitch|vcuSwitch)\.eth\[\d+\]\.macLayer\.queue')
RE_GPTP_SYNC = re.compile(
    r'Luo2021Network\.(viuSwitch|vcuSwitch)\.gptp')   # future: gPTP module path


# ═════════════════════════════════════════════════════════════════════════════
# VEC PARSER
# ═════════════════════════════════════════════════════════════════════════════

class VecParser:
    """
    Parses one OMNeT++ .vec file.
    Returns dict: (module, signal) → np.ndarray shape (N, 2) [time, value].
    Sets self.config_name from the 'attr configname' header line.
    """

    def __init__(self, filepath: str):
        self.filepath    = filepath
        self.config_name = 'Unknown'
        self._id_map: dict[int, tuple] = {}
        self._data:   dict[tuple, list] = defaultdict(list)

    def parse(self) -> dict:
        with open(self.filepath) as f:
            for raw in f:
                line = raw.strip()
                if not line or line.startswith('#'):
                    continue

                if line.startswith('attr configname '):
                    self.config_name = line.split()[-1]
                    continue

                if line.startswith('vector '):
                    parts = line.split(None, 3)
                    if len(parts) < 4:
                        continue
                    vid    = int(parts[1])
                    module = parts[2].strip('"')
                    signal = parts[3].strip().split()[0].strip('"')
                    self._id_map[vid] = (module, signal)
                    continue

                parts = line.split()
                if len(parts) == 4:
                    try:
                        vid   = int(parts[0])
                        t     = float(parts[2])
                        v     = float(parts[3])
                        if vid in self._id_map:
                            self._data[self._id_map[vid]].append((t, v))
                    except ValueError:
                        continue

        return {
            key: np.array(rows, dtype=np.float64)
            for key, rows in self._data.items()
            if rows
        }


# ═════════════════════════════════════════════════════════════════════════════
# SCA PARSER
# ═════════════════════════════════════════════════════════════════════════════

class ScaParser:
    """Parses OMNeT++ .sca → {(module, name): float}."""

    def parse(self, filepath: str) -> dict:
        out = {}
        if not os.path.exists(filepath):
            return out
        with open(filepath) as f:
            for line in f:
                m = re.match(
                    r'scalar\s+"([^"]+)"\s+"([^"]+)"\s+([\d.eE+\-]+)',
                    line.strip()
                )
                if m:
                    out[(m.group(1), m.group(2))] = float(m.group(3))
        return out


# ═════════════════════════════════════════════════════════════════════════════
# FEATURE EXTRACTOR
# ═════════════════════════════════════════════════════════════════════════════

class FeatureExtractor:
    """
    Converts parsed OMNeT++ signals into 15-feature vectors,
    one vector per WINDOW_S tumbling window.
    """

    FEATURE_NAMES = [
        # Data Plane
        'mean_IAT_us',
        'IAT_variance_us2',
        'mean_frame_size_B',
        'burst_length',
        'frame_count',
        # Schedule Plane
        'phase_offset_mean_us',
        'phase_offset_std_us',
        'gate_drop_rate',
        'meter_red_rate',
        'queue_depth_max',
        # Time-Sync Plane
        'sync_interval_mean',
        'sync_interval_var',
        'correction_field_delta',
        'announce_rate',
        'source_count',
    ]

    def __init__(self, vec: dict, sca: dict, config: str):
        self.vec    = vec
        self.sca    = sca
        self.config = config
        self.label  = CONFIG_LABEL_MAP.get(config, -1)

        # Aggregated signals (populated by _collect)
        self._arr_t:   np.ndarray = np.array([])   # packet arrival times (s)
        self._arr_sz:  np.ndarray = np.array([])   # packet sizes (B)
        self._drop_t:  np.ndarray = np.array([])   # gate-drop timestamps
        self._red_t:   np.ndarray = np.array([])   # meter-RED timestamps
        self._q_t:     np.ndarray = np.array([])   # queue sample times
        self._q_v:     np.ndarray = np.array([])   # queue depth values
        self._sync_t:  np.ndarray = np.array([])   # gPTP sync timestamps
        self._ann_t:   np.ndarray = np.array([])   # gPTP announce timestamps
        self._src_ids: set        = set()          # grandmaster IDs seen

        self._collect()

    # ── signal collection ─────────────────────────────────────────────────────

    def _collect(self):
        arr_t, arr_sz, drop_t, red_t = [], [], [], []
        q_t, q_v, sync_t, ann_t     = [], [], [], []

        for (module, signal), arr in self.vec.items():
            if arr.size == 0:
                continue
            t = arr[:, 0];  v = arr[:, 1]

            # Packet arrivals (time + bytes)
            if (RE_PKT_RX.search(module)
                    and 'packetReceived' in signal
                    and 'packetBytes' in signal):
                arr_t.extend(t); arr_sz.extend(v)

            # Gate drops
            elif RE_GATE_DROP.search(module) and 'packetDropped' in signal:
                drop_t.extend(t)

            # Meter RED marks
            elif RE_METER_RED.search(module) and 'packetMarkedRed' in signal:
                red_t.extend(t)

            # Egress queue depth
            elif RE_QUEUE.search(module) and 'queueLength' in signal:
                q_t.extend(t); q_v.extend(v)

            # gPTP sync messages (future — when gPTP module is recording)
            elif RE_GPTP_SYNC.search(module) and 'syncReceived' in signal:
                sync_t.extend(t)

            # gPTP announce messages
            elif RE_GPTP_SYNC.search(module) and 'announceReceived' in signal:
                ann_t.extend(t)

        def _sorted(ts, vs=None):
            if not ts:
                return (np.array([]), np.array([])) if vs is not None else np.array([])
            idx = np.argsort(ts)
            if vs is not None:
                return np.array(ts)[idx], np.array(vs)[idx]
            return np.array(ts)[idx]

        if arr_t:
            self._arr_t, self._arr_sz = _sorted(arr_t, arr_sz)
        if drop_t:
            self._drop_t = _sorted(drop_t)
        if red_t:
            self._red_t = _sorted(red_t)
        if q_t:
            self._q_t, self._q_v = _sorted(q_t, q_v)
        if sync_t:
            self._sync_t = _sorted(sync_t)
        if ann_t:
            self._ann_t = _sorted(ann_t)

    # ── window mask ───────────────────────────────────────────────────────────

    @staticmethod
    def _mask(times: np.ndarray, t0: float, t1: float) -> np.ndarray:
        return (times >= t0) & (times < t1)

    # ── F01–F05: data plane ───────────────────────────────────────────────────

    def _data_plane(self, t0: float, t1: float) -> list:
        mask  = self._mask(self._arr_t, t0, t1)
        times = self._arr_t[mask]
        sizes = self._arr_sz[mask]
        n     = int(len(times))

        if n < 2:
            return [0.0, 0.0, float(sizes[0]) if n == 1 else 0.0, 0, n]

        iats_us   = np.diff(times) * 1e6
        mean_iat  = float(np.mean(iats_us))
        var_iat   = float(np.var(iats_us))
        mean_sz   = float(np.mean(sizes))
        burst_len = self._max_burst(iats_us)

        return [mean_iat, var_iat, mean_sz, burst_len, n]

    @staticmethod
    def _max_burst(iats_us: np.ndarray) -> int:
        """Longest consecutive run where IAT < BURST_IAT_THRESH_US."""
        best = cur = 0
        for iat in iats_us:
            if iat < BURST_IAT_THRESH_US:
                cur += 1
                best = max(best, cur)
            else:
                cur = 0
        return best

    # ── F06–F10: schedule plane ───────────────────────────────────────────────

    def _schedule_plane(self, t0: float, t1: float) -> list:
        win_ms = (t1 - t0) * 1e3                     # window width in ms

        # F06, F07 — GCL phase of each arrival
        mask   = self._mask(self._arr_t, t0, t1)
        times  = self._arr_t[mask]
        if len(times) > 0:
            phases = (times * 1e6) % GCL_CYCLE_US
            ph_mu  = float(np.mean(phases))
            ph_std = float(np.std(phases))
        else:
            ph_mu = ph_std = 0.0

        # F08 — gate drop rate (drops/ms)
        n_drops        = int(np.sum(self._mask(self._drop_t, t0, t1)))
        gate_drop_rate = n_drops / win_ms if win_ms > 0 else 0.0

        # F09 — meter RED rate (reds/ms)
        n_reds         = int(np.sum(self._mask(self._red_t, t0, t1)))
        meter_red_rate = n_reds / win_ms if win_ms > 0 else 0.0

        # F10 — max queue depth
        qmask    = self._mask(self._q_t, t0, t1)
        q_vals   = self._q_v[qmask]
        q_max    = float(np.max(q_vals)) if q_vals.size > 0 else 0.0

        return [ph_mu, ph_std, gate_drop_rate, meter_red_rate, q_max]

    # ── F11–F15: time-sync plane ──────────────────────────────────────────────

    def _timesync_plane(self, t0: float, t1: float) -> list:
        """
        Compute gPTP features per window.

        Priority order:
          1. Real gPTP sync timestamps from vec (when gPTP module records them)
          2. Synthetic V2 attack perturbation (for V2-labelled windows)
          3. Fixed benign baseline (all other cases)

        This ordering means the code works today with fixed values,
        automatically upgrades when real gPTP data is available, and
        generates non-zero variance for V2 windows so normalisation works.
        """
        # ── path 1: real gPTP timestamps from .vec ────────────────────────────
        sync_mask = self._mask(self._sync_t, t0, t1)
        sync_times = self._sync_t[sync_mask]

        if len(sync_times) >= 2:
            # Real gPTP data available — compute features from timestamps
            sync_iats_us  = np.diff(sync_times) * 1e6
            sync_mu       = float(np.mean(sync_iats_us))
            sync_var      = float(np.var(sync_iats_us))

            ann_mask  = self._mask(self._ann_t, t0, t1)
            ann_count = int(np.sum(ann_mask))
            win_s     = t1 - t0
            ann_rate  = ann_count / win_s if win_s > 0 else GPTP_BENIGN['announce_rate']

            # Correction field delta: difference between consecutive sync corrections
            # Requires a 'correctionField:vector' signal — use 0 if not present
            corr_delta = 0.0   # upgrade when correction field vector is recorded

            # Source count: distinct grandmaster IDs in this window
            # Requires 'sourcePortIdentity:vector' — approximate by announce count
            src_count = 2.0 if ann_count > (win_s * 2) else 1.0

            return [sync_mu, sync_var, corr_delta, ann_rate, src_count]

        # ── path 2: V2 label → synthetic perturbation ────────────────────────
        if self.label == 8:
            return [
                GPTP_V2_ATTACK['sync_interval_mean'],
                GPTP_V2_ATTACK['sync_interval_var'],
                GPTP_V2_ATTACK['correction_field_delta'],
                GPTP_V2_ATTACK['announce_rate'],
                GPTP_V2_ATTACK['source_count'],
            ]

        # ── path 3: benign baseline ───────────────────────────────────────────
        return [
            GPTP_BENIGN['sync_interval_mean'],
            GPTP_BENIGN['sync_interval_var'],
            GPTP_BENIGN['correction_field_delta'],
            GPTP_BENIGN['announce_rate'],
            GPTP_BENIGN['source_count'],
        ]

    # ── main extraction loop ──────────────────────────────────────────────────

    def extract(self, sim_time: float = SIM_TIME_S) -> pd.DataFrame:
        """
        Extract one feature vector per tumbling WINDOW_S window.

        Returns a DataFrame with metadata columns (window_id, t_start_s,
        t_end_s, label, config) followed by the 15 raw feature columns.
        """
        n_wins = int(sim_time / WINDOW_S)
        rows   = []

        for i in range(n_wins):
            t0 = i * WINDOW_S
            t1 = t0 + WINDOW_S

            feats = (
                self._data_plane(t0, t1)
                + self._schedule_plane(t0, t1)
                + self._timesync_plane(t0, t1)
            )

            row = {
                'window_id': i,
                't_start_s': round(t0, 4),
                't_end_s':   round(t1, 4),
                'label':     self.label,
                'config':    self.config,
            }
            for name, val in zip(self.FEATURE_NAMES, feats):
                row[name] = val

            rows.append(row)

        return pd.DataFrame(rows)


# ═════════════════════════════════════════════════════════════════════════════
# Z-SCORE NORMALISER
# ═════════════════════════════════════════════════════════════════════════════

class BenignScaler:
    """
    Z-score normalisation fitted exclusively on benign (label=0) windows.

    WHY BENIGN-ONLY FIT:
      IsoForest is an unsupervised detector trained on normal data.
      The scaler must reflect the benign distribution only.
      Attack windows are transformed with the same scaler; their
      features that deviate from benign produce large |Z| scores,
      which IsoForest interprets as anomalous.

    ZERO-VARIANCE HANDLING:
      Features with std=0 over benign data (e.g. fixed gPTP constants
      when no V2 data is present, or meter_red_rate which is always 0
      in benign runs) would produce NaN after division.
      We replace NaN Z-scores with 0.0, meaning those features
      contribute zero signal to IsoForest distances.
      When real V2 data is added, std becomes non-zero automatically.
    """

    def __init__(self):
        self._scaler: StandardScaler | None = None
        self._feature_cols: list[str]        = FeatureExtractor.FEATURE_NAMES
        self.params_df: pd.DataFrame | None  = None

    def fit(self, df: pd.DataFrame) -> 'BenignScaler':
        """Fit scaler on label=0 rows only."""
        benign = df[df['label'] == 0]
        if benign.empty:
            raise ValueError(
                "No benign windows (label=0) found. Cannot fit scaler. "
                "Include General/Baseline config results in the batch."
            )

        X_benign = benign[self._feature_cols].values
        self._scaler = StandardScaler()
        self._scaler.fit(X_benign)

        # Build a human-readable parameter table for logging / thesis
        self.params_df = pd.DataFrame({
            'feature': self._feature_cols,
            'benign_mean': self._scaler.mean_,
            'benign_std':  np.sqrt(self._scaler.var_),
        })

        zero_std = self.params_df[self.params_df['benign_std'] < 1e-10]['feature'].tolist()
        if zero_std:
            print(f"  ℹ  Zero-variance features (→ Z=0, no IsoForest contribution):")
            for f in zero_std:
                print(f"       {f}")

        return self

    def transform(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Apply Z-score transform to all rows.
        Returns a copy with feature columns replaced by Z-scores.
        NaN (from zero-std features) replaced with 0.0.
        """
        if self._scaler is None:
            raise RuntimeError("Call fit() before transform().")

        df_norm = df.copy()
        X       = df[self._feature_cols].values
        Z       = self._scaler.transform(X)
        Z       = np.nan_to_num(Z, nan=0.0, posinf=0.0, neginf=0.0)

        df_norm[self._feature_cols] = Z
        return df_norm

    def fit_transform(self, df: pd.DataFrame) -> pd.DataFrame:
        return self.fit(df).transform(df)

    def save_params(self, path: str):
        """Save scaler parameters to CSV for reproducibility."""
        if self.params_df is None:
            raise RuntimeError("Call fit() first.")
        self.params_df.to_csv(path, index=False)
        print(f"  Scaler params saved → {path}")


# ═════════════════════════════════════════════════════════════════════════════
# PROCESSING HELPERS
# ═════════════════════════════════════════════════════════════════════════════

def process_single(vec_path: str, sca_path: str,
                   label: int | None = None) -> pd.DataFrame:
    """Parse one .vec + .sca pair → raw feature DataFrame."""
    vp = VecParser(vec_path)
    vd = vp.parse()

    sp = ScaParser()
    sd = sp.parse(sca_path)

    fe = FeatureExtractor(vd, sd, vp.config_name)
    df = fe.extract()

    if label is not None:
        df['label'] = label
    return df


def process_batch(results_dir: str) -> pd.DataFrame:
    """Process all .vec files in a directory → combined raw DataFrame."""
    rd       = Path(results_dir)
    vec_files = sorted(rd.glob('*.vec'))

    if not vec_files:
        print(f"WARNING: no .vec files in {results_dir}", file=sys.stderr)
        return pd.DataFrame()

    dfs = []
    for vp in vec_files:
        sp = vp.with_suffix('.sca')
        print(f"  {vp.name}")
        try:
            df = process_single(str(vp), str(sp))
            n  = len(df)
            lb = df['label'].iloc[0] if n else -1
            cf = df['config'].iloc[0] if n else '?'
            print(f"    → {n} windows  label={lb}  config={cf}")
            dfs.append(df)
        except Exception as exc:
            print(f"    ERROR: {exc}", file=sys.stderr)

    return pd.concat(dfs, ignore_index=True) if dfs else pd.DataFrame()


# ═════════════════════════════════════════════════════════════════════════════
# REPORTING
# ═════════════════════════════════════════════════════════════════════════════

def print_summary(df: pd.DataFrame, normalised: bool = False):
    tag   = "NORMALISED" if normalised else "RAW"
    feats = FeatureExtractor.FEATURE_NAMES
    print(f"\n{'='*72}")
    print(f"FEATURE SUMMARY — {tag}")
    print(f"{'='*72}")
    print(f"Total windows : {len(df)}")
    print(df.groupby(['config', 'label']).size().rename('windows').to_string(), "\n")

    for lbl, grp in df.groupby('label'):
        cfg = grp['config'].iloc[0]
        print(f"Label {lbl} ({cfg}) — {len(grp)} windows:")
        print(f"  {'Feature':<30} {'Mean':>10} {'Std':>10} {'Min':>10} {'Max':>10}")
        print(f"  {'-'*62}")
        for f in feats:
            v = grp[f]
            print(f"  {f:<30} {v.mean():>10.3f} {v.std():>10.3f} "
                  f"{v.min():>10.3f} {v.max():>10.3f}")
        print()


def print_separation_table(raw: pd.DataFrame):
    """
    Show per-feature separation between benign and each attack class.
    The Z-score column shows the expected anomaly magnitude after normalisation.
    This is the table that goes into your Chapter 8 thesis results.
    """
    feats  = FeatureExtractor.FEATURE_NAMES
    benign = raw[raw['label'] == 0]
    if benign.empty:
        print("No benign data — cannot compute separation.")
        return

    b_mu  = benign[feats].mean()
    b_std = benign[feats].std().replace(0, np.nan)   # NaN → Z=0

    print(f"\n{'='*72}")
    print("FEATURE SEPARATION TABLE (thesis Chapter 8)")
    print(f"{'='*72}")
    print(f"Benign μ ± σ shown in header row.")
    print(f"Each attack column shows Z-score = (attack_μ − benign_μ) / benign_σ\n")

    attack_labels = sorted(raw[raw['label'] != 0]['label'].unique())
    label_names   = {
        1: 'V1-GCL', 2: 'V3-Thr', 3: 'Gap3', 4: 'Gap4',
        5: 'Multi', 6: 'Mimicry', 7: 'Oversize', 8: 'V2-gPTP'
    }

    # Header
    header = f"  {'Feature':<30} {'Benign μ':>9} {'σ':>7}"
    for lb in attack_labels:
        header += f"  {label_names.get(lb,'Atk'+str(lb)):>8}"
    print(header)
    print(f"  {'-'*72}")

    for f in feats:
        row_str = f"  {f:<30} {b_mu[f]:>9.2f} {b_std[f] if not np.isnan(b_std[f]) else 0:>7.2f}"
        for lb in attack_labels:
            grp = raw[raw['label'] == lb]
            if grp.empty:
                row_str += f"  {'—':>8}"
                continue
            a_mu = grp[f].mean()
            z    = (a_mu - b_mu[f]) / b_std[f] if not np.isnan(b_std[f]) else 0.0
            row_str += f"  {z:>8.1f}"
        print(row_str)


def validate_features(df: pd.DataFrame):
    print(f"\n{'='*60}")
    print("BENIGN FEATURE VALIDATION")
    print(f"{'='*60}")
    benign = df[df['label'] == 0]
    if benign.empty:
        print("No benign windows found."); return

    checks = [
        ('mean_IAT_us',          50,  200, "AV1 IAT ≈ 90µs"),
        ('IAT_variance_us2',      0, 5000, "Benign variance should be low"),
        ('mean_frame_size_B',   400,  520, "AV1 frame ≈ 500B"),
        ('burst_length',          0,    3, "Benign burst_length ≈ 0"),
        ('frame_count',          80,  200, "≈ 111 frames / 10ms at 90µs"),
        ('phase_offset_mean_us', 50,  450, "Phase inside gate window"),
        ('gate_drop_rate',        0,    1, "Benign drops ≈ 0/ms"),
        ('meter_red_rate',        0,  0.1, "Benign RED ≈ 0/ms"),
        ('sync_interval_mean', 100_000, 150_000, "Standard 802.1AS ≈ 125ms"),
        ('announce_rate',        0.5,  2.0, "Standard announce ≈ 1/s"),
        ('source_count',           1,    1, "One grandmaster"),
    ]

    ok = True
    for feat, lo, hi, msg in checks:
        if feat not in benign.columns:
            continue
        mv = benign[feat].mean()
        sym = '✓' if lo <= mv <= hi else '⚠'
        if sym == '⚠':
            ok = False
        print(f"  {sym} {feat:<30} mean={mv:>10.3f}  [{msg}]")

    print("\nAll checks passed." if ok else "\nSome checks flagged — review above.")


# ═════════════════════════════════════════════════════════════════════════════
# CLI
# ═════════════════════════════════════════════════════════════════════════════

def main():
    ap = argparse.ArgumentParser(
        description='Feature extractor + Z-score normaliser for Luo2021Network.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument('--vec',   help='.vec file (single-file mode)')
    src.add_argument('--batch', help='Directory containing .vec/.sca files')

    ap.add_argument('--sca',       default=None, help='.sca file (single-file mode)')
    ap.add_argument('--label',     type=int, default=None,
                    help='Override label (0=benign, 1=GCLPhase, 2=Threshold, …)')
    ap.add_argument('--out',       default='features_raw.csv',
                    help='Output CSV for raw features')
    ap.add_argument('--normalise', action='store_true',
                    help='Also produce Z-score normalised CSV + scaler params')
    ap.add_argument('--validate',  action='store_true',
                    help='Run benign-range sanity checks')
    ap.add_argument('--no-summary',action='store_true',
                    help='Skip per-label feature summary table')
    ap.add_argument('--separation',action='store_true',
                    help='Print feature separation Z-score table (thesis table)')
    ap.add_argument('--sim-time',  type=float, default=SIM_TIME_S,
                    help=f'Simulation duration in seconds (default {SIM_TIME_S})')

    args = ap.parse_args()

    # ── extract ───────────────────────────────────────────────────────────────
    if args.vec:
        sca = args.sca or args.vec.replace('.vec', '.sca')
        print(f"Processing: {args.vec}")
        raw = process_single(args.vec, sca, args.label)
    else:
        print(f"Batch: {args.batch}/")
        raw = process_batch(args.batch)

    if raw.empty:
        print("No data extracted.", file=sys.stderr); sys.exit(1)

    raw.to_csv(args.out, index=False)
    print(f"\nRaw features  → {args.out}  ({len(raw)} windows)")

    # ── normalise ─────────────────────────────────────────────────────────────
    if args.normalise:
        out_norm   = args.out.replace('.csv', '_norm.csv')
        out_scaler = args.out.replace('.csv', '_scaler_params.csv')

        print(f"\nFitting scaler on benign windows …")
        scaler = BenignScaler()
        normed = scaler.fit_transform(raw)
        normed.to_csv(out_norm, index=False)
        scaler.save_params(out_scaler)
        print(f"Normalised    → {out_norm}")

    # ── reporting ─────────────────────────────────────────────────────────────
    if not args.no_summary:
        print_summary(raw, normalised=False)
        if args.normalise:
            print_summary(normed, normalised=True)

    if args.separation:
        print_separation_table(raw)

    if args.validate:
        validate_features(raw)


if __name__ == '__main__':
    main()
