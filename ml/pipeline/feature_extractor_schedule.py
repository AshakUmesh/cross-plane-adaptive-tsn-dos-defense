#!/usr/bin/env python3
"""
feature_extractor_schedule.py

Extracts the SCHEDULE-PLANE features (5 of the intended 15) from real
OMNeT++ .vec files:

    phase_offset_mean_us  - mean offset of packet arrival relative to
                             the nearest GCL gate-open boundary
    phase_offset_std_us   - std dev of that offset within the window
    gate_util             - fraction of the window during which the
                             monitored gate was OPEN (from gateState)
    queue_depth_max       - max observed queueLength within the window
    drops                 - count of droppedPacketLengthsQueueOverflow
                             events within the window

Unlike the time-sync plane (no gPTP data exists in this simulation --
see feature_extractor_timesync.py's status), every signal used here is
REAL, recorded simulation output. Nothing in this extractor is
synthesized.

VECTOR NAMES USED (confirmed present via `grep "^vector "` on real
.vec files earlier in this project):
    <switch>.eth[N].macLayer.queue.transmissionGate[Q] gateState:vector
    <switch>.eth[N].macLayer.queue.queue[Q] queueLength:vector
    <switch>.eth[N].macLayer.queue.queue[Q] droppedPacketLengthsQueueOverflow:vector

GCL SCHEDULE (from Luo 2021 / this project's omnetpp.ini, 500us cycle):
    Q7 open:      0 - 125 us
    Q0-Q6 open: 125 - 450 us
    ALL closed: 450 - 500 us

Usage:
    python3 feature_extractor_schedule.py \
        --results-dir results --config BenignDiverse --runs 0-19 \
        --switch viuSwitch --port 4 --window-ms 10 --sim-time-ms 150 \
        --label 0 --out schedule_features.csv
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

# GCL schedule, seconds. Update if your .ini uses different windows.
GCL_CYCLE_S = 500e-6
GCL_WINDOWS = [
    (0.0, 125e-6, "Q7"),
    (125e-6, 450e-6, "Q0-Q6"),
    (450e-6, 500e-6, "CLOSED"),
]


def nearest_gate_boundary_offset(t_s):
    """
    Returns signed offset (seconds) from t_s to the nearest gate
    open/close boundary within its GCL cycle. Used as phase_offset.
    """
    t_in_cycle = t_s % GCL_CYCLE_S
    boundaries = sorted(set(b for w in GCL_WINDOWS for b in w[:2]))
    return min(abs(t_in_cycle - b) for b in boundaries)


def parse_schedule_vectors(path, switch, port):
    """
    Returns dict: signal_type -> list of (time_s, value) for the given
    switch/port. signal_type in {"gateState", "queueLength", "drops"}.
    Pools across ALL transmissionGate[Q] / queue[Q] indices at that port
    (Q0-Q7), since we want port-level utilization/depth, not per-queue.
    """
    id_to_type = {}
    events = defaultdict(list)

    gate_re = re.compile(
        rf"\.{re.escape(switch)}\.eth\[{port}\]\.macLayer\.queue\.transmissionGate\[\d+\]$"
    )
    queue_re = re.compile(
        rf"\.{re.escape(switch)}\.eth\[{port}\]\.macLayer\.queue\.queue\[\d+\]$"
    )

    with open(path, "r", errors="replace") as f:
        for line in f:
            if line.startswith("vector "):
                m = VECTOR_LINE_RE.match(line.rstrip("\n"))
                if not m:
                    continue
                vec_id, module, vecname = m.group(1), m.group(2), m.group(3)
                if vecname.startswith("gateState") and gate_re.search(module):
                    id_to_type[vec_id] = "gateState"
                elif vecname.startswith("queueLength") and queue_re.search(module):
                    id_to_type[vec_id] = "queueLength"
                elif vecname.startswith("droppedPacketLengthsQueueOverflow") and queue_re.search(module):
                    id_to_type[vec_id] = "drops"
            elif line[0].isdigit():
                m = DATA_LINE_RE.match(line.rstrip("\n"))
                if not m:
                    continue
                vec_id, _event, time_s, value = m.groups()
                if vec_id in id_to_type:
                    events[id_to_type[vec_id]].append((float(time_s), float(value)))

    for k in events:
        events[k].sort(key=lambda t: t[0])
    return events


def compute_schedule_window_features(events, w_start, w_end):
    # Phase offset: computed from queueLength change-events as a proxy
    # for "activity" timestamps within this port -- true per-packet
    # arrival timestamps at the switch ingress are not separately
    # recorded; this uses queue-state transition times as the nearest
    # available proxy. Documented explicitly as an approximation.
    activity_times = [t for (t, _v) in events.get("queueLength", []) if w_start <= t < w_end]
    if activity_times:
        offsets = [nearest_gate_boundary_offset(t) * 1e6 for t in activity_times]  # us
        phase_mean = statistics.mean(offsets)
        phase_std = statistics.stdev(offsets) if len(offsets) > 1 else 0.0
    else:
        phase_mean, phase_std = None, None

    # Gate utilization: TIME-WEIGHTED fraction of window the gate was
    # OPEN. gateState:vector is change-triggered (one sample per state
    # flip, not periodic), so a naive average of raw 0/1 samples is
    # WRONG -- it reflects how many transitions occurred, not how long
    # each state persisted. We must weight each state by its duration.
    all_gate_events = sorted(events.get("gateState", []), key=lambda t: t[0])
    if all_gate_events:
        # Find the state active at w_start (the last event at or before
        # w_start, or the first event's state if none precede it).
        state_before = None
        for (t, v) in all_gate_events:
            if t <= w_start:
                state_before = v
            else:
                break
        cursor = w_start
        cursor_state = state_before if state_before is not None else all_gate_events[0][1]
        open_time = 0.0
        for (t, v) in all_gate_events:
            if t <= w_start:
                continue
            if t >= w_end:
                break
            if cursor_state and cursor_state > 0:
                open_time += (t - cursor)
            cursor = t
            cursor_state = v
        if cursor_state and cursor_state > 0:
            open_time += (w_end - cursor)
        gate_util = open_time / (w_end - w_start)
    else:
        gate_util = None

    # Max queue depth observed in window.
    q_events = [v for (t, v) in events.get("queueLength", []) if w_start <= t < w_end]
    queue_depth_max = max(q_events) if q_events else 0

    # Drop count in window.
    drop_events = [(t, v) for (t, v) in events.get("drops", []) if w_start <= t < w_end]
    drops = len(drop_events)

    return {
        "phase_offset_mean_us": phase_mean,
        "phase_offset_std_us": phase_std,
        "gate_util": gate_util,
        "queue_depth_max": queue_depth_max,
        "drops": drops,
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
    ap.add_argument("--switch", default="viuSwitch",
                     help="Switch module name, e.g. viuSwitch")
    ap.add_argument("--port", default="4",
                     help="eth[N] port index to monitor")
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

        events = parse_schedule_vectors(vec_path, args.switch, args.port)

        for w in range(n_windows):
            w_start = w * window_s
            w_end = w_start + window_s
            feats = compute_schedule_window_features(events, w_start, w_end)
            rows.append({
                "config": args.config, "run": run,
                "switch": args.switch, "port": args.port,
                "window_index": w, "window_start_s": round(w_start, 6),
                **feats,
                "label": args.label,
            })

    if missing:
        print(f"WARNING: {len(missing)} .vec files not found:", file=sys.stderr)
        for m in missing:
            print(f"  {m}", file=sys.stderr)

    fieldnames = ["config", "run", "switch", "port", "window_index",
                  "window_start_s", "phase_offset_mean_us",
                  "phase_offset_std_us", "gate_util", "queue_depth_max",
                  "drops", "label"]
    mode = "a" if (args.append and os.path.exists(args.out)) else "w"
    with open(args.out, mode, newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        if mode == "w":
            writer.writeheader()
        writer.writerows(rows)

    n_with_data = sum(1 for r in rows if r["queue_depth_max"] or r["drops"])
    print(f"Wrote {len(rows)} window-rows ({n_with_data} with nonzero "
          f"queue/drop activity) from {len(run_indices)-len(missing)} "
          f"run(s) to {args.out} (mode={mode})")


if __name__ == "__main__":
    main()
