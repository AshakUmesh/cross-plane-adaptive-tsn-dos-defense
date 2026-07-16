#!/usr/bin/env python3
"""
feature_extractor_timesync.py

Extracts TIME-SYNC-PLANE features from REAL gPTP simulation output
(requires the BenignDiverse_gPTP_Working config -- see project notes on
enabling gPTP: hasTimeSynchronization=true, EthernetStreamThroughPhyLayer,
StreamingTransmitter/DestreamingReceiver, WITHOUT hasCutthroughSwitching).

WHY THIS DIFFERS FROM THE ORIGINAL 15-FEATURE DESIGN:
    Original design specified: sync_interval_mean, sync_interval_var,
    correction_field_delta, announce_rate, source_count.

    This topology uses a SINGLE FIXED GRANDMASTER (viuSwitch), not
    multi-master election via BMCA. Consequently:
      - announce_rate: NOT APPLICABLE. Announce messages exist to elect
        a master among candidates; INET's Gptp does not emit them in a
        single-fixed-master configuration. Confirmed empirically: zero
        "*announce*" vectors in the recorded output.
      - source_count: would be a STRUCTURAL CONSTANT (always 1, one
        grandmaster) -- carries no discriminative signal, same
        situation as gate_util in the schedule plane (see
        feature_extractor_schedule.py).

    Using REAL signals actually present in this simulation instead:
      gmRateRatio       - ratio of grandmaster clock rate to local clock
                           rate, as measured by this node. Deviation
                           from 1.0 indicates clock drift/quality.
      neighborRateRatio - rate ratio measured against the immediate
                           upstream neighbor (one hop), not the GM.
      pdelay             - measured peer (link) propagation delay.

COMPUTED FEATURES (5, all from real recorded data):
    sync_event_interval_mean_us  - mean time between consecutive gPTP
                                    sync-related events in the window
    sync_event_interval_var      - variance of that interval
    gm_rate_ratio_mean           - mean grandmaster rate ratio (1.0 =
                                    perfect sync; deviation = drift)
    gm_rate_ratio_std            - std dev of rate ratio in window
    pdelay_mean_us                - mean measured peer delay

Usage:
    python3 feature_extractor_timesync.py \
        --results-dir results --config BenignDiverse_gPTP_Working \
        --runs 0 --node av1 --window-ms 10 --sim-time-ms 150 \
        --label 0 --out timesync_features.csv
"""

import argparse
import csv
import os
import re
import statistics
import sys
from collections import defaultdict

VECTOR_LINE_RE = re.compile(r'^vector\s+(\d+)\s+(\S+)\s+([^\t]+?)\s+ETV\s*$')
DATA_LINE_RE = re.compile(r'^(\d+)\t(\d+)\t([0-9.eE+-]+)\t([0-9.eE+-]+)\s*$')


def parse_timesync_vectors(path, node):
    """
    Returns dict: signal -> list of (time_s, value) for gmRateRatio,
    neighborRateRatio, pdelay under the given node's .gptp module.
    """
    id_to_signal = {}
    events = defaultdict(list)
    node_re = re.compile(rf"\.{re.escape(node)}\.gptp$")

    with open(path, "r", errors="replace") as f:
        for line in f:
            if line.startswith("vector "):
                m = VECTOR_LINE_RE.match(line.rstrip("\n"))
                if not m:
                    continue
                vec_id, module, vecname = m.group(1), m.group(2), m.group(3)
                if not node_re.search(module):
                    continue
                for sig in ("gmRateRatio", "neighborRateRatio", "pdelay"):
                    if vecname.startswith(sig):
                        id_to_signal[vec_id] = sig
                        break
            elif line[0].isdigit():
                m = DATA_LINE_RE.match(line.rstrip("\n"))
                if not m:
                    continue
                vec_id, _event, time_s, value = m.groups()
                if vec_id in id_to_signal:
                    events[id_to_signal[vec_id]].append((float(time_s), float(value)))

    for k in events:
        events[k].sort(key=lambda t: t[0])
    return events


def compute_timesync_window_features(events, w_start, w_end):
    # Sync event timing: use gmRateRatio update timestamps as the proxy
    # for "sync activity" in this window (each update corresponds to a
    # sync/pdelay measurement cycle).
    sync_times = [t for (t, _v) in events.get("gmRateRatio", []) if w_start <= t < w_end]
    if len(sync_times) >= 2:
        intervals = [sync_times[i] - sync_times[i-1] for i in range(1, len(sync_times))]
        interval_mean = statistics.mean(intervals) * 1e6  # us
        interval_var = statistics.variance(intervals) if len(intervals) > 1 else 0.0
        interval_var *= 1e12  # us^2
    else:
        interval_mean, interval_var = None, None

    gm_values = [v for (t, v) in events.get("gmRateRatio", []) if w_start <= t < w_end]
    gm_mean = statistics.mean(gm_values) if gm_values else None
    gm_std = statistics.stdev(gm_values) if len(gm_values) > 1 else (0.0 if gm_values else None)

    pdelay_values = [v for (t, v) in events.get("pdelay", []) if w_start <= t < w_end]
    pdelay_mean = statistics.mean(pdelay_values) * 1e6 if pdelay_values else None  # us

    return {
        "sync_event_interval_mean_us": interval_mean,
        "sync_event_interval_var": interval_var,
        "gm_rate_ratio_mean": gm_mean,
        "gm_rate_ratio_std": gm_std,
        "pdelay_mean_us": pdelay_mean,
    }


def parse_run_range(s):
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
    ap.add_argument("--config", required=True)
    ap.add_argument("--runs", default="0")
    ap.add_argument("--node", default="av1",
                     help="Node whose .gptp submodule to extract from "
                          "(e.g. av1, av2, radarNode, zonalHost, "
                          "attackNode, viuSwitch, vcuSwitch)")
    ap.add_argument("--window-ms", type=float, default=10.0)
    ap.add_argument("--sim-time-ms", type=float, default=150.0)
    ap.add_argument("--label", type=int, required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--append", action="store_true")
    args = ap.parse_args()

    run_indices = parse_run_range(args.runs)
    window_s = args.window_ms / 1000.0
    sim_time_s = args.sim_time_ms / 1000.0
    n_windows = int(round(sim_time_s / window_s, 6))

    rows = []
    missing = []

    for run in run_indices:
        vec_path = os.path.join(args.results_dir, f"{args.config}-#{run}.vec")
        if not os.path.exists(vec_path):
            missing.append(vec_path)
            continue

        events = parse_timesync_vectors(vec_path, args.node)

        for w in range(n_windows):
            w_start = w * window_s
            w_end = w_start + window_s
            feats = compute_timesync_window_features(events, w_start, w_end)
            rows.append({
                "config": args.config, "run": run, "node": args.node,
                "window_index": w, "window_start_s": round(w_start, 6),
                **feats,
                "label": args.label,
            })

    if missing:
        print(f"WARNING: {len(missing)} .vec files not found:", file=sys.stderr)
        for m in missing:
            print(f"  {m}", file=sys.stderr)

    fieldnames = ["config", "run", "node", "window_index", "window_start_s",
                  "sync_event_interval_mean_us", "sync_event_interval_var",
                  "gm_rate_ratio_mean", "gm_rate_ratio_std", "pdelay_mean_us",
                  "label"]
    mode = "a" if (args.append and os.path.exists(args.out)) else "w"
    with open(args.out, mode, newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        if mode == "w":
            writer.writeheader()
        writer.writerows(rows)

    n_with_data = sum(1 for r in rows if r["gm_rate_ratio_mean"] is not None)
    print(f"Wrote {len(rows)} window-rows ({n_with_data} with real gPTP "
          f"data) from {len(run_indices)-len(missing)} run(s) to "
          f"{args.out} (mode={mode})")


if __name__ == "__main__":
    main()
