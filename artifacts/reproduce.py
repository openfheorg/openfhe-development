#!/usr/bin/env python3
"""Reproduce the supplied Sparse Hermite paper. No full runs without --execute.

plan/theory/report never execute the FHE binary. smoke runs only insecure small
rings. run --execute is the expensive paper experiment entry point.
"""
import argparse
import csv
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import hashlib
import io
import json
import math
import os
from pathlib import Path
import platform
import shlex
import statistics
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
REFERENCE = Path(__file__).resolve().parent / "reference"
DEFAULT_BINARY = ROOT / "build-artifact" / "bin" / "examples" / "pke" / "fbt-benchmark"
LABELS = {"AKP": "AKP", "BKSS": "BKSS", "FULL_THI": "CKKL", "SPARSE_THI": "Sparse-THI"}


@dataclass(frozen=True)
class Case:
    table: int
    p: int
    order: int
    method: str
    ring: int
    slots: int
    unsafe: bool = False

    @property
    def id(self):
        return f"table{self.table}-p{self.p}-n{self.order}-{self.method}-N{self.ring}-slots{self.slots}"


def paper_cases(table="all"):
    cases = []
    for number in (4, 5):
        if table != "all" and int(table) != number:
            continue
        for row in read_csv(REFERENCE / f"table{number}.csv"):
            p, n, method = int(row["p"]), int(row["order"]), row["method"]
            ring = 65536 if p == 16 else 131072
            if number == 5 and p == 16 and method == "SPARSE_THI" and n >= 3:
                ring = 131072
            unsafe = number == 4 and p == 16 and method == "SPARSE_THI" and n >= 3
            cases.append(Case(number, p, n, method, ring, ring, unsafe))
    return cases


def smoke_cases():
    # Full and sparse packing, all interpolation orders supported by each method.
    return [Case(0, 16, n, method, 256, slots, True)
            for slots in (256, 64)
            for method, orders in (("AKP", (1, 2, 3)), ("BKSS", (1,)), ("BKSS_LEGACY", (1,)),
                                   ("FULL_THI", (1, 2, 3)), ("SPARSE_THI", (1, 2, 3, 5)))
            for n in orders]


def count_cases():
    return [Case(0, c.p, c.order, c.method, 256, 256, True) for c in paper_cases("4")]


def check_counts(binary, output, cpu, resume):
    cases = count_cases()
    run_cases(cases, binary, output, cpu, resume)
    comparisons = []
    for case, target in zip(cases, read_csv(REFERENCE / "table4.csv")):
        rows, _ = load_case(case, output)
        count, levels = int(rows[0]["key_switches"]), int(rows[0]["lut_levels"])
        if count != 2 * int(target["key_switches"]) or levels != int(target["lut_levels"]):
            raise ValueError(f"{case.id}: operation counts differ from Table 4")
        comparisons.append({"p": case.p, "order": case.order, "method": LABELS[case.method],
                            "key_switches": count // 2, "lut_levels": levels})
    write_table(output / "operation-counts", comparisons)
    print("All 15 Table 4 operation counts match at N=256; no paper latency benchmark was run.")


def noise_bases(case):
    return list(range(24, 59 - int(math.log2(case.p)) - 1)) if case.table == 5 else [10]


def command(case, binary):
    mode = "benchmark" if case.table == 4 else "precision" if case.table == 5 else "verify"
    budget = "3,2" if case.table else "1,1"
    result = [str(binary), f"--mode={mode}", f"--method={case.method}", f"--p={case.p}",
              f"--order={case.order}", f"--ring-dim={case.ring}", f"--slots={case.slots}",
              "--sf=59", f"--level-budget={budget}",
              "--noise-base=" + ",".join(map(str, noise_bases(case)))]
    if case.unsafe:
        result.append("--unsafe")
    return result


def read_csv(path):
    with path.open(newline="") as handle:
        return list(csv.DictReader(handle))


def write_table(path, rows):
    if not rows:
        raise ValueError("Cannot write an empty table")
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.with_suffix(".csv").open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    def formatted(value):
        return f"{value:.3f}" if isinstance(value, float) else str(value)
    headers = list(rows[0])
    lines = ["| " + " | ".join(headers) + " |", "| " + " | ".join("---" for _ in headers) + " |"]
    lines += ["| " + " | ".join(formatted(row[h]) for h in headers) + " |" for row in rows]
    path.with_suffix(".md").write_text("\n".join(lines) + "\n")
    def latex(value):
        return formatted(value).replace("_", r"\_")
    tex = [r"\begin{tabular}{" + "l" * len(headers) + "}", " & ".join(map(latex, headers)) + r" \\"]
    tex += [" & ".join(latex(row[h]) for h in headers) + r" \\" for row in rows]
    tex += [r"\end{tabular}"]
    path.with_suffix(".tex").write_text("\n".join(tex) + "\n")


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def source_digest():
    digest = hashlib.sha256()
    paths = [ROOT / "CMakeLists.txt", ROOT / "OpenFHEConfig.cmake.in"]
    for directory in ("src", "configure"):
        paths.extend(p for p in (ROOT / directory).rglob("*") if p.is_file()
                     and p.suffix in (".cpp", ".h", ".in", ".txt"))
    paths.extend(p for p in (ROOT / "artifacts").iterdir() if p.is_file()
                 and p.suffix in (".py", ".sh", ".txt"))
    paths.extend(REFERENCE.glob("*.csv"))
    for path in sorted(paths):
        digest.update(str(path.relative_to(ROOT)).encode())
        digest.update(path.read_bytes())
    return digest.hexdigest()


def environment(binary, cpu):
    cache = binary.parents[3] / "CMakeCache.txt"
    cmake = {}
    if cache.exists():
        for line in cache.read_text().splitlines():
            if ":" in line and "=" in line and not line.startswith(("/", "#")):
                key, value = line.split("=", 1)
                name = key.split(":", 1)[0]
                if name.startswith(("CMAKE_", "WITH_", "MATH", "NATIVE")):
                    cmake[name] = value
    compiler = cmake.get("CMAKE_CXX_COMPILER")
    version = subprocess.check_output([compiler, "--version"], text=True) if compiler else "unknown"
    linked = subprocess.check_output(["ldd", str(binary)], text=True)
    libraries = {}
    for line in linked.splitlines():
        fields = line.split()
        if len(fields) >= 3 and fields[1] == "=>" and Path(fields[2]).is_file():
            libraries[fields[0]] = sha256(Path(fields[2]))
    commit = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True)
    return {"platform": platform.platform(), "python": sys.version, "cpu": cpu,
            "cpu_info": subprocess.check_output(["lscpu"], text=True),
            "memory": Path("/proc/meminfo").read_text(), "cmake": cmake, "compiler": version,
            "commit": commit.stdout.strip(), "source_sha256": source_digest(), "binary_sha256": sha256(binary),
            "library_sha256": libraries, "ldd": linked,
            "threads": {"OMP_NUM_THREADS": "1", "OPENBLAS_NUM_THREADS": "1", "MKL_NUM_THREADS": "1"}}


def parse_log(text, case):
    headers = [line for line in text.splitlines() if line.startswith("CONFIG ")]
    if len(headers) != 1 or text.count("CSV_BEGIN\n") != 1 or text.count("CSV_END\n") != 1:
        raise ValueError(f"{case.id}: incomplete or duplicated output")
    config = dict(item.split("=", 1) for item in headers[0].split()[1:])
    expected = {"method": case.method, "p": str(case.p), "order": str(case.order), "ring_dim": str(case.ring),
                "slots": str(case.slots), "sf": "59", "eval_exp_degree": "58", "scaling": "FIXEDMANUAL",
                "key_dist": "SPARSE_TERNARY", "unsafe": str(int(case.unsafe)),
                "mode": "benchmark" if case.table == 4 else "precision" if case.table == 5 else "verify",
                "level_budget": "3,2" if case.table else "1,1", "warmups": "1" if case.table == 4 else "0",
                "measured_runs": "5" if case.table == 4 else "1"}
    if case.method == "BKSS":
        expected["implementation"] = "BKSS_NEW"
    for key, value in expected.items():
        if config.get(key) != value:
            raise ValueError(f"{case.id}: wrong {key}: {config.get(key)!r}, expected {value!r}")
    block = text.split("CSV_BEGIN\n")[1].split("CSV_END\n")[0]
    rows = list(csv.DictReader(io.StringIO(block)))
    expected_points = [(i, int(i == 0), 10) for i in range(6)] if case.table == 4 else [(0, 0, b) for b in noise_bases(case)]
    actual_points = [(int(r["run"]), int(r["warmup"]), int(r["noise_base"])) for r in rows]
    if actual_points != expected_points:
        raise ValueError(f"{case.id}: missing, duplicate or out-of-order measurements")
    for r in rows:
        for key in ("key_switches", "lut_levels", "max_error"):
            if int(r[key]) < 0:
                raise ValueError(f"{case.id}: negative {key}")
        for key in (("input_noise", "lut_noise") if case.table == 5 else ("total_ms", "lut_ms")):
            if not math.isfinite(float(r[key])):
                raise ValueError(f"{case.id}: nonfinite {key}")
        if case.table != 5 and int(r["max_error"]) != 0:
            raise ValueError(f"{case.id}: failed exact RLWE correctness")
    if case.table == 5 and int(rows[0]["max_error"]) != 0:
        raise ValueError(f"{case.id}: baseline precision point fails exact correctness")
    return config, rows


def run_cases(cases, binary, output, cpu, resume):
    binary = binary.resolve()
    provenance = environment(binary, cpu)
    output.mkdir(parents=True, exist_ok=True)
    for case in cases:
        log = output / (case.id + ".log")
        meta = output / (case.id + ".json")
        if log.exists() or meta.exists():
            if not resume:
                raise FileExistsError(f"{case.id}: use a new output directory or --resume")
            old = json.loads(meta.read_text())
            if any(old["environment"].get(key) != provenance[key]
                   for key in ("source_sha256", "binary_sha256", "library_sha256", "cmake")):
                raise ValueError(f"{case.id}: source/binary changed; use a new output directory")
            if old["case"] != asdict(case) or old["log_sha256"] != sha256(log) or old["returncode"] != 0:
                raise ValueError(f"{case.id}: invalid cached result")
            parse_log(log.read_text(), case)
            print(f"Validated existing {case.id}", flush=True)
            continue
        cmd = ["taskset", "-c", str(cpu)] + command(case, binary)
        print(shlex.join(cmd), flush=True)
        started = datetime.now(timezone.utc).isoformat()
        start = time.monotonic()
        with log.open("x") as handle:
            completed = subprocess.run(cmd, cwd=ROOT, env={**os.environ, **provenance["threads"]},
                                       stdout=handle, stderr=subprocess.STDOUT)
        record = {"case": asdict(case), "command": cmd, "environment": provenance, "started_utc": started,
                  "wall_seconds": time.monotonic() - start, "returncode": completed.returncode, "log_sha256": sha256(log)}
        meta.write_text(json.dumps(record, indent=2) + "\n")
        completed.check_returncode()
        parse_log(log.read_text(), case)
        print(f"Validated {case.id} ({record['wall_seconds']:.1f}s)", flush=True)


def load_case(case, source):
    log = source / (case.id + ".log")
    meta = json.loads((source / (case.id + ".json")).read_text())
    if meta["case"] != asdict(case) or meta["log_sha256"] != sha256(log) or meta["returncode"] != 0:
        raise ValueError(f"{case.id}: metadata/checksum mismatch")
    return parse_log(log.read_text(), case)[1], meta


def bound(rows):
    # Preserve get_B_from_csv in the supplied private plot_method_compare.py.
    result = float(rows[0]["lut_noise"])
    for r in rows:
        x, y = float(r["input_noise"]), float(r["lut_noise"])
        if x < y + 1 and x < -25:
            result = max(result, y)
    return result


def report(source, output, table):
    from theory import capacity, lut_values, threshold
    tables = {4: [], 5: []}
    phases = []
    provenance = set()
    for case in paper_cases(table):
        rows, meta = load_case(case, source)
        provenance.add((meta["environment"]["source_sha256"], meta["environment"]["binary_sha256"],
                        json.dumps(meta["environment"].get("library_sha256", {}), sort_keys=True)))
        row = {"p": case.p, "order": case.order, "method": LABELS[case.method], "ring_dim": case.ring}
        target = next(r for r in read_csv(REFERENCE / f"table{case.table}.csv")
                      if int(r["p"]) == case.p and int(r["order"]) == case.order and r["method"] == case.method)
        if case.table == 4:
            measured = [r for r in rows if r["warmup"] == "0"]
            counts = {int(r["key_switches"]) for r in measured}
            levels = {int(r["lut_levels"]) for r in measured}
            if len(counts) != 1 or len(levels) != 1 or next(iter(counts)) % 2:
                raise ValueError(f"{case.id}: inconsistent operation counts")
            lut = [float(r["lut_ms"]) / 1000 for r in measured]
            total = [float(r["total_ms"]) / 1000 for r in measured]
            ks, depth = next(iter(counts)) // 2, next(iter(levels))
            row.update(key_switches=ks, lut_levels=depth, lut_s=statistics.mean(lut), total_s=statistics.mean(total),
                       lut_stddev_s=statistics.stdev(lut), total_stddev_s=statistics.stdev(total),
                       key_switch_delta=ks - int(target["key_switches"]), level_delta=depth - int(target["lut_levels"]),
                       lut_ratio_to_paper=statistics.mean(lut) / float(target["lut_s"]),
                       total_ratio_to_paper=statistics.mean(total) / float(target["total_s"]))
        else:
            t = threshold(lut_values("ID", case.p), case.order, case.method, full_packing=True)
            b = bound(rows)
            _, _, c = capacity(t, b, case.order)
            row.update(log_t=t, log_b=b, capacity_bits=c, bound_delta=b - float(target["log_b"]),
                       capacity_delta=c - float(target["capacity_bits"]))
            phases.extend({"p": case.p, "order": case.order, "method": case.method,
                           "input_noise": float(r["input_noise"]), "lut_noise": float(r["lut_noise"]),
                           "max_error": int(r["max_error"])} for r in rows)
        tables[case.table].append(row)
    if len(provenance) != 1:
        raise ValueError("Mixed source or binary versions; report each experiment release separately")
    for number, rows in tables.items():
        if rows:
            write_table(output / f"table{number}", rows)
    if phases:
        write_table(output / "phase-data", phases)
        from figures import experimental_phase
        experimental_phase(phases, output)
    print(f"Wrote complete tables to {output}")


def theory_report(output):
    from theory import TABLE3_ROWS, lut_values, threshold
    rows = [{"lut": lut, "p": p, **{f"n{n}": threshold(lut_values(lut, p), n, "SPARSE_THI") for n in range(1, 6)}}
            for lut, p in TABLE3_ROWS]
    write_table(output / "table3", rows)
    from figures import theoretical_figures
    theoretical_figures(output)
    print(f"Wrote Table 3 and Figures 2–3 to {output}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("plan", "run", "smoke", "check-counts", "theory", "report", "archived-report"))
    parser.add_argument("--table", choices=("4", "5", "all"), default="all")
    parser.add_argument("--binary", type=Path, default=DEFAULT_BINARY)
    parser.add_argument("--output", type=Path, help="Default: artifacts/results/<action>")
    parser.add_argument("--input", type=Path, help="Raw input directory; defaults to results/run or results/archived")
    parser.add_argument("--execute", action="store_true", help="Execute full paper runs (otherwise print commands)")
    parser.add_argument("--resume", action="store_true", help="Reuse only checksum/source/binary-validated complete runs")
    parser.add_argument("--cpu", type=int, default=min(os.sched_getaffinity(0)), help="Logical CPU to pin the FHE process to")
    args = parser.parse_args()
    output = args.output or ROOT / "artifacts/results" / args.action
    if args.action == "theory":
        theory_report(output)
    elif args.action == "report":
        report(args.input or ROOT / "artifacts/results/run", output, args.table)
    elif args.action == "archived-report":
        from archived_report import report_archive
        report_archive(args.input or ROOT / "artifacts/results/archived", output, args.table)
    elif args.action == "check-counts":
        check_counts(args.binary, output, args.cpu, args.resume)
    elif args.action == "smoke":
        run_cases(smoke_cases(), args.binary, output, args.cpu, args.resume)
    elif args.action == "plan" or not args.execute:
        cases = paper_cases(args.table)
        print(f"# {len(cases)} paper configurations. Full packing, one thread; commands are NOT executed.")
        for case in cases:
            print(shlex.join(["taskset", "-c", str(args.cpu)] + command(case, args.binary)))
    else:
        run_cases(paper_cases(args.table), args.binary, output, args.cpu, args.resume)


if __name__ == "__main__":
    main()
