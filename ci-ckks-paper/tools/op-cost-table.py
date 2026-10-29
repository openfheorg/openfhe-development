#!/usr/bin/env python3
"""Item 4.2: CI vs std per-op cost table from a ci-op-cost job log.

usage: op-cost-table.py LOG [LOG ...]

The job runs ci-op-cost processes interleaved (e.g. ci std std ci ...). Each process prints OPMED lines (median over
its reps). Processes are paired in order of appearance (k-th ci with k-th std, which are neighbours in an ABBA
order). For every (towers, op) the script prints:
  ci_ms, std_ms   medians over processes
  ratio           median over pairs of ci/std
  ratio_norm      median over pairs of norm_ci / norm_std, where norm = op time / calibrator time, timed back to
                  back in every iteration (ci-op-cost: the calibrator is a std NTT round trip per tower on a fixed
                  prime, the same work in both processes). Logs without norm fall back to ptmult as the calibrator.
  spread          min-max of the per-pair normalized ratios
"""
import re
import statistics as st
import sys

procs = []  # list of (scheme, {(towers, op): ms})
for path in sys.argv[1:]:
    cur = None
    for line in open(path, errors="replace"):
        m = re.match(r"CONFIG scheme=(\w+)", line)
        if m:
            cur = (m.group(1), {})
            procs.append(cur)
            continue
        m = re.match(r"OPMED scheme=(\w+) towers=(\d+) op=(\w+) ms=([\d.]+)(?: norm=([\d.]+))?", line)
        if m and cur is not None:
            k = (int(m.group(2)), m.group(3))
            cur[1][k] = float(m.group(4))
            if m.group(5):
                cur[1][("norm",) + k] = float(m.group(5))

ci = [p[1] for p in procs if p[0] == "ci" and p[1]]
sd = [p[1] for p in procs if p[0] == "std" and p[1]]
pairs = list(zip(ci, sd))
print(f"processes: ci {len(ci)}, std {len(sd)}, pairs {len(pairs)}")
keys = [k for k in ci[0].keys() if len(k) == 2 and all(k in p for p in ci + sd)] if ci else []
print(f"| towers | op | CI ms | std ms | CI/std (raw) | CI/std (normalized) | normalized per-pair range |")
print("|---|---|---|---|---|---|---|")
for k in keys:
    t, op = k
    r = [a[k] / b[k] for a, b in pairs]
    nk = ("norm",) + k
    if all(nk in p for p in ci + sd):
        rn = [a[nk] / b[nk] for a, b in pairs]
    else:
        rn = [(a[k] / b[k]) / (a[(t, "ptmult")] / b[(t, "ptmult")]) for a, b in pairs]
    print(f"| {t} | {op} | {st.median(p[k] for p in ci):.3f} | {st.median(p[k] for p in sd):.3f} | "
          f"{st.median(r):.3f} | {st.median(rn):.3f} | {min(rn):.3f}-{max(rn):.3f} |")
