#!/usr/bin/env python3
"""
feature_extractor.py

Parses OMNeT++ .vec result files (ETV format) from the BenignDiverse sweep
(or any config) and computes the 5 Data-Plane features per stream per 10ms
window:

    mean_IAT        - mean inter-arrival time within the window (seconds)
    IAT_variance     - variance of inter-arrival time within the window
    mean_frame_size  - mean packet size within the window (bytes)
    burst_length     - max number of consecutive packets whose IAT is below
                        a "burst threshold" (default: 50% of the stream's
                        nominal interval) -- flags tight bursts within window
    count            - number of packets sent within the window

Usage:
    python3 feature_extractor.py \
        --results-dir results \
        --config BenignDiverse \
        --runs 0-19 \
        --window-ms 10 \
        --sim-time-ms 150 \
        --label 0 \
        --out benign_features.csv

    # For an attack run (single run, label != 0):
    python3 feature_extractor.py \
        --results-dir results \
        --config GCLPhaseAttack \
        --runs 0 \
        --window-ms 10 \
        --sim-time-ms 150 \
        --label 1 \
        --out gclphase_features.csv \
        --append

Notes:
- Vector IDs are NOT stable across runs/files -- this script rebuilds the
  id->name mapping fresh for every .vec file it reads. Never hardcode IDs.
- We use the "packetSent:vector(packetBytes)" vector as the per-packet
  ground truth: it gives us (time, size) for every packet actually
  transmitted by app[0].source for each end-host stream.
- Streams covered by default: av1, av2, radarNode, zonalHost, attackNode.
  attackNode is included but you will normally only care about it for
  attack-config runs (label != 0); for BenignDiverse runs attackNode has
  numApps=0 so no packets will be found (that's expected -- not an error).
"""

import argparse
import csv
import glob
import os
import re
import statistics
import sys
from collections import defaultdict

VECTOR_LINE_RE = re.compile(
    r'^vector\s+(\d+)\s+(\S+)\s+([^\t]+?)\s+ETV\s*$'
)
# Data line format: <id> <eventNum> <time> <value>
DATA_LINE_RE = re.compile(r'^(\d+)\t(\d+)\t([0-9.eE+-]+)\t([0-9.eE+-]+)\s*$')

STREAMS = ["av1", "av2", "radarNode", "zonalHost", "attackNode"]
TARGET_VECTOR_SUFFIX = "packetSent:vector(packetBytes)"


def parse_vec_file(path):
    """
    Returns dict: stream_name -> sorted list of (time_s, size_bytes) tuples,
    for every stream in STREAMS whose app[0].source packetSent vector is
    present in this file.
    """
    id_to_stream = {}
    stream_events = defaultdict(list)

    with open(path, "r", errors="replace") as f:
        for line in f:
            if line.startswith("vector "):
                m = VECTOR_LINE_RE.match(line.rstrip("\n"))
                if not m:
                    continue
                vec_id, module, vecname = m.group(1), m.group(2), m.group(3)
                if not vecname.endswith(TARGET_VECTOR_SUFFIX):
                    continue
                # module looks like: Luo2021Network.av1.app[0].io
                # (packetSent is recorded under .app[0].io, NOT .app[0].source)
                for stream in STREAMS:
                    if f".{stream}.app[0].io" in module or module.endswith(
                        f".{stream}.app[0].io"
                    ):
                        id_to_stream[vec_id] = stream
                        break
            elif line[0].isdigit():
                m = DATA_LINE_RE.match(line.rstrip("\n"))
                if not m:
                    continue
                vec_id, _event, time_s, value = m.groups()
                if vec_id in id_to_stream:
                    stream_events[id_to_stream[vec_id]].append(
                        (float(time_s), float(value))
                    )

    for stream in stream_events:
        stream_events[stream].sort(key=lambda t: t[0])

    return stream_events


def compute_window_features(events, window_start, window_end, burst_threshold_s):
    """
    events: list of (time_s, size_bytes) sorted, ALL events for the stream
            (we filter to the window here).
    Returns dict of features, or None if the window has < 2 packets
    (can't compute IAT).
    """
    window_events = [
        (t, s) for (t, s) in events if window_start <= t < window_end
    ]
    count = len(window_events)
    if count == 0:
        return {
            "mean_IAT": None,
            "IAT_variance": None,
            "mean_frame_size": None,
            "burst_length": 0,
            "count": 0,
        }

    sizes = [s for (_t, s) in window_events]
    mean_frame_size = statistics.mean(sizes)

    if count < 2:
        return {
            "mean_IAT": None,
            "IAT_variance": None,
            "mean_frame_size": mean_frame_size,
            "burst_length": 1,
            "count": count,
        }

    times = [t for (t, _s) in window_events]
    iats = [times[i] - times[i - 1] for i in range(1, len(times))]
    mean_iat = statistics.mean(iats)
    iat_var = statistics.variance(iats) if len(iats) > 1 else 0.0

    # burst_length: longest run of consecutive packets with IAT < threshold
    max_run = 1
    cur_run = 1
    for iat in iats:
        if iat < burst_threshold_s:
            cur_run += 1
            max_run = max(max_run, cur_run)
        else:
            cur_run = 1

    return {
        "mean_IAT": mean_iat,
        "IAT_variance": iat_var,
        "mean_frame_size": mean_frame_size,
        "burst_length": max_run,
        "count": count,
    }


# Nominal production interval per stream, used only to set a sensible
# burst-detection threshold (50% of nominal). Matches omnetpp.ini General.
NOMINAL_INTERVAL_S = {
    "av1": 90e-6,
    "av2": 90e-6,
    "radarNode": 500e-6,
    "zonalHost": 500e-6,
    "attackNode": 90e-6,  # arbitrary fallback; attack configs vary widely
}


def parse_run_range(s):
    """'0-19' -> [0,1,...,19]; '0,3,7' -> [0,3,7]; '5' -> [5]"""
    runs = []
    for part in s.split(","):
        part = part.strip()
        if "-" in part:
            lo, hi = part.split("-")
            runs.extend(range(int(lo), int(hi) + 1))
        else:
            runs.append(int(part))
    return runs


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--results-dir", default="results")
    ap.add_argument("--config", required=True,
                     help="Config name, e.g. BenignDiverse or GCLPhaseAttack")
    ap.add_argument("--runs", default="0",
                     help="Run indices, e.g. '0-19' or '0,1,2' or '0'")
    ap.add_argument("--window-ms", type=float, default=10.0)
    ap.add_argument("--sim-time-ms", type=float, default=150.0)
    ap.add_argument("--label", type=int, required=True,
                     help="0=benign, 1=timing_attack, 2=bandwidth_attack, "
                          "3=oversize, etc. -- define your own mapping")
    ap.add_argument("--out", required=True)
    ap.add_argument("--append", action="store_true",
                     help="Append to --out instead of overwriting "
                          "(use when combining benign + multiple attack CSVs)")
    ap.add_argument("--streams", default=",".join(STREAMS),
                     help="Comma-separated list of streams to extract")
    args = ap.parse_args()

    run_indices = parse_run_range(args.runs)
    streams = args.streams.split(",")
    window_s = args.window_ms / 1000.0
    sim_time_s = args.sim_time_ms / 1000.0
    n_windows = int(sim_time_s // window_s)

    rows = []
    missing_files = []

    for run in run_indices:
        vec_path = os.path.join(
            args.results_dir, f"{args.config}-#{run}.vec"
        )
        if not os.path.exists(vec_path):
            missing_files.append(vec_path)
            continue

        stream_events = parse_vec_file(vec_path)

        for stream in streams:
            events = stream_events.get(stream, [])
            burst_thresh = 0.5 * NOMINAL_INTERVAL_S.get(stream, 90e-6)

            for w in range(n_windows):
                w_start = w * window_s
                w_end = w_start + window_s
                feats = compute_window_features(
                    events, w_start, w_end, burst_thresh
                )
                rows.append({
                    "config": args.config,
                    "run": run,
                    "stream": stream,
                    "window_index": w,
                    "window_start_s": round(w_start, 6),
                    "mean_IAT": feats["mean_IAT"],
                    "IAT_variance": feats["IAT_variance"],
                    "mean_frame_size": feats["mean_frame_size"],
                    "burst_length": feats["burst_length"],
                    "count": feats["count"],
                    "label": args.label,
                })

    if missing_files:
        print(f"WARNING: {len(missing_files)} expected .vec files not found:",
              file=sys.stderr)
        for f in missing_files:
            print(f"  {f}", file=sys.stderr)

    fieldnames = [
        "config", "run", "stream", "window_index", "window_start_s",
        "mean_IAT", "IAT_variance", "mean_frame_size", "burst_length",
        "count", "label",
    ]

    mode = "a" if (args.append and os.path.exists(args.out)) else "w"
    write_header = not (mode == "a")

    with open(args.out, mode, newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        if write_header:
            writer.writeheader()
        writer.writerows(rows)

    n_nonempty = sum(1 for r in rows if r["count"] > 0)
    print(f"Wrote {len(rows)} window-rows ({n_nonempty} non-empty) "
          f"from {len(run_indices) - len(missing_files)} run(s) "
          f"to {args.out} (mode={mode})")


if __name__ == "__main__":
    main()
