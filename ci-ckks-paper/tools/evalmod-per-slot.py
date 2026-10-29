#!/usr/bin/env python3
"""EvalMod time per real slot, CI vs std, side by side (item 3.3).

usage: evalmod-per-slot.py LOG [LOG ...]

Reads guarded-job logs of benchmark/src/ci-fft-boot runs (one "=== ... ci-fft-boot ..." header per run):
  - CI EvalMod time: the "[CI-BT] EvalMod X s" lines (build with -DBOOTSTRAPTIMING, e.g. build-wsl-bt),
  - std EvalMod time: the "Approximate modular reduction time: X s" lines (build-wsl-bt / build-bt binary,
    -DBOOTSTRAPTIMING; for std CtS-first full packing this one time covers both EvalMod calls).
The first bootstrap of each run is the driver's "first" (cold) bootstrap and is dropped; the stage time is the
median of the remaining (warm) ones, as warm_median_s in the RESULT line.

Real slots per bootstrap = RESULT slots (CI: N reals; std: N/2 reals). EvalMod calls per bootstrap: CI 1 (one
real ciphertext), std CtS-first 2 (real and imaginary part of the full-packed coefficients), std StC-first 1.
Printed per run: EvalMod s, us per real slot, s per EvalMod call, share of the bootstrap, and for every CI run the
ratio of its us per real slot (and per EvalMod call) to the nearest std run of each ordering in the same log.
"""
import re
import statistics
import sys


def parse(path):
    runs, cur = [], None
    for line in open(path, errors="replace"):
        if line.startswith("=== ") and "ci-fft-boot" in line and not line.startswith("=== end"):
            cur = {"cmd": line.split("ci-fft-boot", 1)[1].strip(), "em": [], "log": path}
            runs.append(cur)
            continue
        if cur is None:
            continue
        m = re.match(r"\[CI-BT\] EvalMod ([0-9.eE+-]+) s", line)
        if m:
            cur["em"].append(float(m.group(1)))
        m = re.match(r"Approximate modular reduction time: ([0-9.eE+-]+) s", line)
        if m:
            cur["em"].append(float(m.group(1)))
        if line.startswith("RESULT"):
            cur["res"] = dict(re.findall(r"(\w[\w+]*)=([^\s]+)", line))
    return [r for r in runs if "res" in r and len(r["em"]) >= 2]


def main(paths):
    runs = [r for p in paths for r in parse(p)]
    rows = []
    for r in runs:
        d = r["res"]
        warm = r["em"][1:]
        em = statistics.median(warm)
        slots = int(d["slots"])
        stc = d.get("stcfirst", "0") == "1"
        calls = 2 if (d["scheme"] == "std" and not stc) else 1
        boot = float(d["warm_median_s"])
        rows.append(dict(scheme=d["scheme"], order="StC-first" if stc else "CtS-first", logN=d["logN"],
                         budget=d["budget"], corr=d["corr"], slots=slots, calls=calls, em=em, n=len(warm),
                         us=em / slots * 1e6, per_call=em / calls, share=em / boot, boot=boot,
                         rms=d.get("rms_bits", ""), log=r["log"].rsplit("/", 1)[-1]))
    print("| # | log | scheme | order | logN | budget | corr | real slots | EvalMod calls | EvalMod s (warm median, n) "
          "| us / real slot | s / call | share of bootstrap | bootstrap s | RMS bits |")
    print("|" + "---|" * 15)
    for i, x in enumerate(rows):
        print(f"| {i} | {x['log']} | {x['scheme']} | {x['order']} | {x['logN']} | {x['budget']} | {x['corr']} | {x['slots']} "
              f"| {x['calls']} | {x['em']:.3f} ({x['n']}) | {x['us']:.1f} | {x['per_call']:.3f} | {x['share']*100:.0f}% "
              f"| {x['boot']:.2f} | {x['rms']} |")
    print()
    # Each CI run is paired with the nearest std run (by position in the same log, same N / budget) of each
    # ordering: on a laptop whose clock drifts between runs only neighbouring runs compare.
    print("| log | budget | CI run (#) | nearest std run (#) | CI / std per real slot | CI / std per call |")
    print("|---|---|---|---|---|---|")
    for i, c in enumerate(rows):
        if c["scheme"] != "ci":
            continue
        for order in ("CtS-first", "StC-first"):
            cand = [(abs(j - i), j) for j, s in enumerate(rows)
                    if s["scheme"] == "std" and s["order"] == order and s["log"] == c["log"]
                    and (s["logN"], s["budget"]) == (c["logN"], c["budget"])]
            if not cand:
                continue
            j = min(cand)[1]
            s = rows[j]
            print(f"| {c['log']} | {c['budget']} | {c['order']} corr {c['corr']} (#{i}) | {s['order']} corr {s['corr']} (#{j}) "
                  f"| {c['us']/s['us']:.3f}x | {c['per_call']/s['per_call']:.3f}x |")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    main(sys.argv[1:])
