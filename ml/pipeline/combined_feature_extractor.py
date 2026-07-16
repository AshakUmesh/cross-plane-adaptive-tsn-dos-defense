#!/usr/bin/env python3
"""
combined_feature_extractor.py

Unified extractor for all three feature planes, parsing each .vec file
ONCE (more efficient than running 3 separate scripts against the same
file) and emitting one row per (config, run, stream, window_index) with
all 15 columns.

IMPORTANT, READ BEFORE USING FOR ML:
    Time-sync columns (sync_event_interval_mean_us, sync_event_interval_var,
    gm_rate_ratio_mean, gm_rate_ratio_std, pdelay_mean_us) will be EMPTY
    for any (config) that did not have gPTP enabled. As of this writing,
    that is every config EXCEPT BenignDiverse_gPTP_Working -- none of the
    11 attack configs have a gPTP-enabled variant yet.

    Consequently: a straightforward "train on all 15 features" run will
    have real time-sync signal for benign windows and MISSING values for
    every attack window. Do NOT impute/fill these with fixed placeholder
    values to make IsoForest run -- that reintroduces exactly the kind
    of fabricated-feature problem flagged earlier in this project (the
    abandoned 15-feature script's synthetic GPTP_V2_ATTACK data).

    Two valid options once you have this CSV:
      (a) Train/evaluate on the 10 REAL Data+Schedule features only
          (--planes data,schedule) -- valid for both benign and all 11
          attacks today, no gaps.
      (b) Separately demonstrate the time-sync plane's feasibility on
          benign-only data (--planes timesync), documented as a
          standalone proof-of-concept, not merged into the attack
          detection comparison until at least one attack config also
          has gPTP enabled.

STREAM -> viuSwitch PORT MAPPING (confirmed from network.ned connection
order -- see project notes; auto-assigned by connection appearance order):
    av1        -> eth0
    av2        -> eth1
    radarNode  -> eth2
    zonalHost  -> eth3
    (vcuSwitch uplink -> eth4, not a traffic-generating stream)
    attackNode -> eth5

Usage:
    python3 combined_feature_extractor.py \
        --results-dir results --config BenignDiverse --runs 0-19 \
        --window-ms 10 --sim-time-ms 150 --label 0 \
        --planes data,schedule --out combined_15.csv

    python3 combined_feature_extractor.py \
        --results-dir results --config GCLPhaseAttack --runs 0 \
        --window-ms 10 --sim-time-ms 150 --label 1 \
        --planes data,schedule --out combined_15.csv --append
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

STREAMS = ["av1", "av2", "radarNode", "zonalHost", "attackNode"]
DATA_TARGET_SUFFIX = "packetSent:vector(packetBytes)"

STREAM_PORT_MAP = {
    "av1": "0", "av2": "1", "radarNode": "2", "zonalHost": "3", "attackNode": "5",
}
SWITCH = "viuSwitch"

GCL_CYCLE_S = 500e-6
GCL_WINDOWS_BOUNDARIES = sorted({0.0, 125e-6, 450e-6, 500e-6})

NOMINAL_INTERVAL_S = {
    "av1": 90e-6, "av2": 90e-6, "radarNode": 500e-6, "zonalHost": 500e-6,
    "attackNode": 90e-6,
}


# ---------------- Single-pass parser: all signals, all planes ----------------

def parse_all_vectors(path):
    """
    One pass over the .vec file. Returns:
      data_events[stream]         -> list of (t, size_bytes)
      sched_events[port][sigtype] -> list of (t, value); sigtype in
                                      {gateState, queueLength, drops}
      sync_events[node][sigtype]  -> list of (t, value); sigtype in
                                      {gmRateRatio, pdelay}
    """
    data_events = defaultdict(list)
    sched_events = defaultdict(lambda: defaultdict(list))
    sync_events = defaultdict(lambda: defaultdict(list))

    id_kind = {}   # vec_id -> ("data", stream) | ("sched", port, sigtype) | ("sync", node, sigtype)

    gate_re = re.compile(rf"\.{SWITCH}\.eth\[(\d+)\]\.macLayer\.queue\.transmissionGate\[\d+\]$")
    queue_re = re.compile(rf"\.{SWITCH}\.eth\[(\d+)\]\.macLayer\.queue\.queue\[\d+\]$")
    sync_node_re = re.compile(r"\.([A-Za-z0-9_]+)\.gptp$")

    with open(path, "r", errors="replace") as f:
        for line in f:
            if line.startswith("vector "):
                m = VECTOR_LINE_RE.match(line.rstrip("\n"))
                if not m:
                    continue
                vec_id, module, vecname = m.group(1), m.group(2), m.group(3)

                # Data plane: <stream>.app[0].io packetSent:vector(packetBytes)
                if vecname.endswith(DATA_TARGET_SUFFIX):
                    for stream in STREAMS:
                        if module.endswith(f".{stream}.app[0].io"):
                            id_kind[vec_id] = ("data", stream)
                            break
                    continue

                # Schedule plane
                gm = gate_re.search(module)
                qm = queue_re.search(module)
                if vecname.startswith("gateState") and gm:
                    id_kind[vec_id] = ("sched", gm.group(1), "gateState")
                    continue
                if vecname.startswith("queueLength") and qm:
                    id_kind[vec_id] = ("sched", qm.group(1), "queueLength")
                    continue
                if vecname.startswith("droppedPacketLengthsQueueOverflow") and qm:
                    id_kind[vec_id] = ("sched", qm.group(1), "drops")
                    continue

                # Time-sync plane
                sm = sync_node_re.search(module)
                if sm and vecname.startswith("gmRateRatio"):
                    id_kind[vec_id] = ("sync", sm.group(1), "gmRateRatio")
                    continue
                if sm and vecname.startswith("pdelay") and not vecname.startswith("pdelayRatio"):
                    id_kind[vec_id] = ("sync", sm.group(1), "pdelay")
                    continue

            elif line[0].isdigit():
                m = DATA_LINE_RE.match(line.rstrip("\n"))
                if not m:
                    continue
                vec_id, _event, time_s, value = m.groups()
                if vec_id not in id_kind:
                    continue
                kind = id_kind[vec_id]
                t, v = float(time_s), float(value)
                if kind[0] == "data":
                    data_events[kind[1]].append((t, v))
                elif kind[0] == "sched":
                    sched_events[kind[1]][kind[2]].append((t, v))
                elif kind[0] == "sync":
                    sync_events[kind[1]][kind[2]].append((t, v))

    for d in (data_events,):
        for k in d:
            d[k].sort(key=lambda x: x[0])
    for d in (sched_events, sync_events):
        for k1 in d:
            for k2 in d[k1]:
                d[k1][k2].sort(key=lambda x: x[0])

    return data_events, sched_events, sync_events


# ---------------- Per-window feature computation, per plane ----------------

def data_plane_features(events, w_start, w_end, burst_threshold_s):
    win = [(t, s) for (t, s) in events if w_start <= t < w_end]
    count = len(win)
    if count == 0:
        return {"mean_IAT": None, "IAT_variance": None, "mean_frame_size": None,
                "burst_length": 0, "count": 0}
    sizes = [s for (_t, s) in win]
    mean_size = statistics.mean(sizes)
    if count < 2:
        return {"mean_IAT": None, "IAT_variance": None, "mean_frame_size": mean_size,
                "burst_length": 1, "count": count}
    times = [t for (t, _s) in win]
    iats = [times[i] - times[i-1] for i in range(1, len(times))]
    mean_iat = statistics.mean(iats)
    iat_var = statistics.variance(iats) if len(iats) > 1 else 0.0
    max_run, cur_run = 1, 1
    for iat in iats:
        if iat < burst_threshold_s:
            cur_run += 1
            max_run = max(max_run, cur_run)
        else:
            cur_run = 1
    return {"mean_IAT": mean_iat, "IAT_variance": iat_var, "mean_frame_size": mean_size,
            "burst_length": max_run, "count": count}


def schedule_plane_features(port_events, w_start, w_end):
    activity_times = [t for (t, _v) in port_events.get("queueLength", []) if w_start <= t < w_end]
    if activity_times:
        offsets = [min(abs((t % GCL_CYCLE_S) - b) for b in GCL_WINDOWS_BOUNDARIES) * 1e6
                   for t in activity_times]
        phase_mean = statistics.mean(offsets)
        phase_std = statistics.stdev(offsets) if len(offsets) > 1 else 0.0
    else:
        phase_mean, phase_std = None, None

    all_gate = sorted(port_events.get("gateState", []), key=lambda x: x[0])
    if all_gate:
        state_before = None
        for (t, v) in all_gate:
            if t <= w_start:
                state_before = v
            else:
                break
        cursor = w_start
        cursor_state = state_before if state_before is not None else all_gate[0][1]
        open_time = 0.0
        for (t, v) in all_gate:
            if t <= w_start:
                continue
            if t >= w_end:
                break
            if cursor_state and cursor_state > 0:
                open_time += (t - cursor)
            cursor, cursor_state = t, v
        if cursor_state and cursor_state > 0:
            open_time += (w_end - cursor)
        gate_util = open_time / (w_end - w_start)
    else:
        gate_util = None

    q_vals = [v for (t, v) in port_events.get("queueLength", []) if w_start <= t < w_end]
    queue_depth_max = max(q_vals) if q_vals else 0
    drops = len([1 for (t, v) in port_events.get("drops", []) if w_start <= t < w_end])

    return {"phase_offset_mean_us": phase_mean, "phase_offset_std_us": phase_std,
            "gate_util": gate_util, "queue_depth_max": queue_depth_max, "drops": drops}


def timesync_plane_features(node_events, w_start, w_end):
    sync_times = [t for (t, _v) in node_events.get("gmRateRatio", []) if w_start <= t < w_end]
    if len(sync_times) >= 2:
        intervals = [sync_times[i] - sync_times[i-1] for i in range(1, len(sync_times))]
        interval_mean = statistics.mean(intervals) * 1e6
        interval_var = (statistics.variance(intervals) * 1e12) if len(intervals) > 1 else 0.0
    else:
        interval_mean, interval_var = None, None

    gm_vals = [v for (t, v) in node_events.get("gmRateRatio", []) if w_start <= t < w_end]
    gm_mean = statistics.mean(gm_vals) if gm_vals else None
    gm_std = statistics.stdev(gm_vals) if len(gm_vals) > 1 else (0.0 if gm_vals else None)

    pd_vals = [v for (t, v) in node_events.get("pdelay", []) if w_start <= t < w_end]
    pdelay_mean = statistics.mean(pd_vals) * 1e6 if pd_vals else None

    return {"sync_event_interval_mean_us": interval_mean, "sync_event_interval_var": interval_var,
            "gm_rate_ratio_mean": gm_mean, "gm_rate_ratio_std": gm_std,
            "pdelay_mean_us": pdelay_mean}


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
    ap.add_argument("--window-ms", type=float, default=10.0)
    ap.add_argument("--sim-time-ms", type=float, default=150.0)
    ap.add_argument("--label", type=int, required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--append", action="store_true")
    ap.add_argument("--planes", default="data,schedule,timesync",
                     help="Comma list of planes to include: data,schedule,timesync")
    ap.add_argument("--streams", default=",".join(STREAMS))
    args = ap.parse_args()

    planes = set(args.planes.split(","))
    run_indices = parse_run_range(args.runs)
    streams = args.streams.split(",")
    window_s = args.window_ms / 1000.0
    sim_time_s = args.sim_time_ms / 1000.0
    n_windows = int(round(sim_time_s / window_s, 6))

    fieldnames = ["config", "run", "stream", "window_index", "window_start_s"]
    if "data" in planes:
        fieldnames += ["mean_IAT", "IAT_variance", "mean_frame_size", "burst_length", "count"]
    if "schedule" in planes:
        fieldnames += ["phase_offset_mean_us", "phase_offset_std_us", "gate_util",
                        "queue_depth_max", "drops"]
    if "timesync" in planes:
        fieldnames += ["sync_event_interval_mean_us", "sync_event_interval_var",
                        "gm_rate_ratio_mean", "gm_rate_ratio_std", "pdelay_mean_us"]
    fieldnames.append("label")

    rows = []
    missing = []

    for run in run_indices:
        vec_path = os.path.join(args.results_dir, f"{args.config}-#{run}.vec")
        if not os.path.exists(vec_path):
            missing.append(vec_path)
            continue

        data_events, sched_events, sync_events = parse_all_vectors(vec_path)

        for stream in streams:
            port = STREAM_PORT_MAP.get(stream)
            burst_thresh = 0.5 * NOMINAL_INTERVAL_S.get(stream, 90e-6)

            for w in range(n_windows):
                w_start, w_end = w * window_s, w * window_s + window_s
                row = {"config": args.config, "run": run, "stream": stream,
                       "window_index": w, "window_start_s": round(w_start, 6)}

                if "data" in planes:
                    row.update(data_plane_features(data_events.get(stream, []), w_start, w_end, burst_thresh))
                if "schedule" in planes:
                    row.update(schedule_plane_features(sched_events.get(port, {}), w_start, w_end))
                if "timesync" in planes:
                    row.update(timesync_plane_features(sync_events.get(stream, {}), w_start, w_end))

                row["label"] = args.label
                rows.append(row)

    if missing:
        print(f"WARNING: {len(missing)} .vec files not found:", file=sys.stderr)
        for m in missing:
            print(f"  {m}", file=sys.stderr)

    mode = "a" if (args.append and os.path.exists(args.out)) else "w"
    with open(args.out, mode, newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        if mode == "w":
            writer.writeheader()
        writer.writerows(rows)

    n_data = sum(1 for r in rows if r.get("count", 0) and r["count"] > 0) if "data" in planes else 0
    n_sched = sum(1 for r in rows if r.get("queue_depth_max")) if "schedule" in planes else 0
    n_sync = sum(1 for r in rows if r.get("gm_rate_ratio_mean") is not None) if "timesync" in planes else 0
    print(f"Wrote {len(rows)} rows (planes={sorted(planes)}) from "
          f"{len(run_indices)-len(missing)} run(s) to {args.out} (mode={mode})")
    if "data" in planes:
        print(f"  data-plane non-empty windows: {n_data}")
    if "schedule" in planes:
        print(f"  schedule-plane non-empty windows: {n_sched}")
    if "timesync" in planes:
        print(f"  timesync-plane non-empty windows: {n_sync}  "
              f"(EXPECT 0 unless this config had gPTP enabled)")


if __name__ == "__main__":
    main()
