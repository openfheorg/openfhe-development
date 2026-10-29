#!/usr/bin/env python3
"""Thread-scaling table from guarded ci-fft-boot logs (item 5.1).

usage: thread-scaling.py LOG [LOG ...]

Logs of runs with OMP_NUM_THREADS = t (one thread count per process) give the per-process table below. Logs with
CI_THREAD_SWEEP (one process bootstraps at several thread counts, "SWEEP" lines) give the sweep table: per process
and round, the speedup over the 1-thread bootstrap of the same round (adjacent in time), then the medians.

Each run starts with a '=== HH:MM:SS uptime t=THREADS cmd' line (wsl-guard job scripts) and ends with RESULT.
Per bootstrap the stage sum is taken (CI: [CI-BT] CtS + EvalMod + StC; std (BOOTSTRAPTIMING build): Encoding +
Approximate modular reduction + Decoding). The first bootstrap of each run is the cold one and is skipped.
Prints one line per run (warm median, load average at start), then per (scheme, threads): the minimum and median
over all warm bootstraps, the speedup over 1 thread, and CI / std (time per bootstrap; the CI/2xstd ratio for the
same number of real values is 2 x std / CI).
"""
import re, sys, statistics as st

runs, sweeps = [], []
for path in sys.argv[1:]:
    cur = None
    for line in open(path, errors="replace"):
        m = re.match(r"=== (\d\d:\d\d:\d\d) ([\d.]+) t=(\d+) .*ci-fft-boot (ci|std) ", line)
        if m:
            cur = dict(log=path.split("/")[-1], start=m.group(1), t=int(m.group(3)), scheme=m.group(4),
                       boots=[], stage=[], load=None)
            runs.append(cur)
            continue
        if cur is None:
            continue
        m = re.match(r"SWEEP scheme=(\w+) round=(\d+) threads=(\d+) s=([\d.]+)", line)
        if m:
            sweeps.append((path.split("/")[-1], cur["start"], m.group(1), int(m.group(2)), int(m.group(3)),
                           float(m.group(4))))
            continue
        if cur["load"] is None and "load average" in line:
            cur["load"] = line.split("load average:")[1].split(",")[0].strip()
        if cur["scheme"] == "ci":
            m = re.match(r"\[CI-BT\] (CtS|EvalMod|StC) ([\d.]+) s", line)
            if m:
                cur["stage"].append(float(m.group(2)))
                if m.group(1) == "StC":
                    cur["boots"].append(sum(cur["stage"])); cur["stage"] = []
        else:
            m = re.match(r"(Encoding|Approximate modular reduction|Decoding) time: ([\d.]+) s", line)
            if m:
                cur["stage"].append(float(m.group(2)))
                if m.group(1) == "Decoding":
                    cur["boots"].append(sum(cur["stage"])); cur["stage"] = []
        m = re.search(r"warm_median_s=([\d.]+).*rms_bits=([\d.]+).*peakRSS_GB=([\d.]+)", line)
        if line.startswith("RESULT") and m:
            cur["warm"] = float(m.group(1)); cur["rms"] = float(m.group(2)); cur["rss"] = float(m.group(3))

print("log start scheme threads load1 warm_median_s stage-sum-per-warm-boot rms peakRSS")
for r in runs:
    if "warm" not in r:
        continue
    print(r["log"], r["start"], r["scheme"], r["t"], r["load"], r["warm"],
          " ".join(f"{x:.2f}" for x in r["boots"][1:]), r["rms"], r["rss"])

if sweeps:
    print("\nsweep: log start scheme round | seconds per thread count | speedup over the same round's 1 thread")
    sp = {}
    groups = {}
    for lg, start, sch, rnd, t, sec in sweeps:
        groups.setdefault((lg, start, sch, rnd), {})[t] = sec
    for (lg, start, sch, rnd), d in groups.items():
        if 1 not in d:
            continue
        ts = sorted(d)
        print(lg, start, sch, rnd, "|", " ".join(f"{t}:{d[t]:.2f}" for t in ts), "|",
              " ".join(f"{t}:{d[1]/d[t]:.2f}x" for t in ts if t != 1))
        for t in ts:
            sp.setdefault((sch, t), []).append(d[1] / d[t])
    print("\nsweep medians: threads | CI speedup med (range) | std speedup med (range) | CI/std speedup")
    for t in sorted({t for _, t in sp}):
        c, d = sp.get(("ci", t)), sp.get(("std", t))
        if c and d:
            print(f"{t:3d} | {st.median(c):.2f}x ({min(c):.2f}-{max(c):.2f}) | {st.median(d):.2f}x "
                  f"({min(d):.2f}-{max(d):.2f}) | {st.median(c)/st.median(d):.2f}")

agg = {}
for r in runs:
    if "warm" in r and not any(sw[1] == r["start"] for sw in sweeps):
        agg.setdefault((r["scheme"], r["t"]), []).extend(r["boots"][1:])
threads = sorted({t for _, t in agg})
if agg:
    print("\nthreads | CI min / med s | std min / med s | CI speedup (min) | std speedup (min) | CI/std (min) | CI/2xstd (min) | CI/std (med)")
for t in threads:
    c, s = agg.get(("ci", t), []), agg.get(("std", t), [])
    if not c or not s:
        continue
    c1, s1 = min(agg[("ci", threads[0])]), min(agg[("std", threads[0])])
    print(f"{t:3d} | {min(c):.2f} / {st.median(c):.2f} (n={len(c)}) | {min(s):.2f} / {st.median(s):.2f} (n={len(s)}) | "
          f"{c1/min(c):.2f}x | {s1/min(s):.2f}x | {min(c)/min(s):.3f} | {2*min(s)/min(c):.2f}x | {st.median(c)/st.median(s):.3f}")
