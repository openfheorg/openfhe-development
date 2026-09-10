"""Read the bundled historical measurements without running FHE experiments.

This format deliberately remains separate from the strict current-run parser:
the archive lacks build provenance and individual warm-up records.
"""
import csv
from dataclasses import asdict
import io
import json
import math
import re
import statistics

from reproduce import LABELS, REFERENCE, bound, paper_cases, read_csv, sha256, write_table
from theory import capacity, lut_values, threshold


def fields(line):
    return dict(re.findall(r"(\w+)=([^\s]+)", line))


def require(condition, message):
    if not condition:
        raise ValueError(message)


def load(entry, source, case):
    require(entry["case"] == asdict(case), "Archive case differs from the paper matrix")
    for name, checksum in entry["files"].items():
        require(sha256(source / name) == checksum, f"Archive checksum mismatch: {name}")
    log_name, = (name for name in entry["files"] if name.endswith(".log"))
    text = (source / log_name).read_text()
    headers = [line for line in text.splitlines() if line.startswith("Mode=")]
    require(len(headers) == 1, f"Missing or duplicated header: {log_name}")
    config = fields(headers[0])
    expected = {"Mode": "benchmark" if case.table == 4 else "precision",
                "ring_dim": str(case.ring), "slots": str(case.slots), "sf": "59",
                "order": str(case.order), "p_input": str(case.p), "p_output": str(case.p),
                "eval_exp_degree": "58", "noise_stage": "PRE_EVALEXP", "scaling": "FIXEDMANUAL",
                "key_dist": "SPARSE_TERNARY", "level_budget": "3,2", "complex_lut": "0",
                "all_inputs": "0" if case.table == 4 else "1"}
    for key, value in expected.items():
        require(config.get(key) == value, f"{log_name}: wrong {key}")
    return text, config, log_name


def timing(text, config, case, target):
    protocol, = (line for line in text.splitlines() if line.startswith("Measured runs="))
    require(fields(protocol) == {"runs": "5", "warmup_runs": "1", "noise_base": "10"},
            "Timing protocol differs from five measured runs and one warm-up")
    lines = [line for line in text.splitlines() if " run=" in line]
    method = {"AKP": "AKP25", "BKSS": "BKSS24_NEW", "SPARSE_THI": "Sparse THI"}[case.method]
    require(all(line.split("run=")[0].split() == ["ID"] + method.split() and " PASS " in line
                for line in lines), "Wrong timing LUT/method or failed correctness")
    rows = [fields(line) for line in lines]
    require([int(row["run"]) for row in rows] == list(range(1, 6)), "Incomplete measured runs")
    for row in rows:
        require(int(row["max_error"]) == 0 and int(row["noise"]) == 10, "Invalid timing measurement")
        require(int(row["lut_ks"]) == 2 * int(target["key_switches"]), "Wrong key-switch count")
        require(all(math.isfinite(float(row[k])) and float(row[k]) > 0 for k in ("overall_ms", "lut_ms")),
                "Invalid timing value")
    # The old logs record total depth, not LUT-stage levels. Label this derivation.
    levels = int(config["mul_depth"]) - 5 - 9
    require(levels == int(target["lut_levels"]), "Wrong inferred LUT depth")
    lut = [float(row["lut_ms"]) / 1000 for row in rows]
    total = [float(row["overall_ms"]) / 1000 for row in rows]
    return {"samples": len(rows), "key_switches": int(rows[0]["lut_ks"]) // 2,
            "lut_levels_inferred": levels, "lut_s": statistics.mean(lut), "total_s": statistics.mean(total),
            "lut_stddev_s": statistics.stdev(lut), "total_stddev_s": statistics.stdev(total)}


def precision(entry, source, text, case):
    csv_name, = (name for name in entry["files"] if name.endswith(".csv"))
    rows = read_csv(source / csv_name)
    method = {"AKP": "AKP25", "BKSS": "BKSS24", "SPARSE_THI": "Sparse THI", "FULL_THI": "FULL THI"}[case.method]
    # The subsequently supplied order-5 run uses the current 24–53 sweep.
    updated_order5 = case.p == 16 and case.method == "SPARSE_THI" and case.order == 5
    first = 24 if updated_order5 else 16
    require([int(row["noise_base"]) for row in rows] == list(range(first, 54 if case.p == 16 else 47)),
            "Unexpected archived noise sweep")
    require(int(rows[0]["max_error"]) == 0, "Failed baseline precision measurement")
    for row in rows:
        require(row["lut"] == "ID" and row["method"] == method and row["run"] == "1", "Wrong precision LUT/method")
        require(int(row["max_error"]) >= 0, "Invalid precision correctness result")
        require(all(math.isfinite(float(row[k])) for k in ("input_precision", "lut_precision")),
                "Nonfinite precision measurement")
    require(text.count("CSV_BEGIN\n") == text.count("CSV_END") == 1, "Incomplete precision log")
    logged = list(csv.DictReader(io.StringIO(text.split("CSV_BEGIN\n")[1].split("CSV_END")[0])))
    log_end = 54 if updated_order5 else 51 if case.p == 16 else 47
    require([int(row["noise_base"]) for row in logged] == list(range(first, log_end)),
            "Unexpected logged noise sweep")
    for a, b in zip(rows, logged):
        require(a["lut"] == b["lut"] and a["method"] == b["method"], "CSV/log LUT mismatch")
        require(all(float(a[k]) == float(b[k]) for k in ("noise_base", "max_error", "input_precision",
                                                        "lut_precision", "key_switch_count")), "CSV/log mismatch")
    points = [{"input_noise": float(row["input_precision"]), "lut_noise": float(row["lut_precision"])} for row in rows]
    log_points = [{"input_noise": float(row["input_precision"]), "lut_noise": float(row["lut_precision"])} for row in logged]
    b = bound(points)
    require(b == bound(log_points), "Uncorroborated CSV tail changes the estimated noise bound")
    t = threshold(lut_values("ID", case.p), case.order, case.method, full_packing=True)
    c = capacity(t, b, case.order)[2]
    return {"log_t": t, "log_b": b, "capacity_bits": c, "points": len(rows),
            "noise_first": first, "noise_last": int(rows[-1]["noise_base"]), "log_corroborated_points": len(logged)}


def report_archive(source, output, table="all"):
    manifest = json.loads((source / "manifest.json").read_text())
    require(manifest["format"] == "historical-fbt-v1", "Unknown historical data format")
    require([entry["case"] for entry in manifest["cases"]] == [asdict(c) for c in paper_cases()],
            "Historical manifest does not cover the complete matrix")
    tables = {4: [], 5: []}
    for case, entry in zip(paper_cases(), manifest["cases"]):
        if table != "all" and case.table != int(table):
            continue
        columns = ("samples key_switches lut_levels_inferred lut_s total_s lut_stddev_s total_stddev_s"
                   if case.table == 4 else
                   "log_t log_b capacity_bits points noise_first noise_last log_corroborated_points")
        result = {"p": case.p, "order": case.order, "method": LABELS[case.method], "ring_dim": case.ring,
                  "status": "available", **dict.fromkeys(columns.split(), ""), "source_log": ""}
        if "unavailable" in entry:
            result["status"] = entry["unavailable"]
        else:
            text, config, log_name = load(entry, source, case)
            target = next(row for row in read_csv(REFERENCE / f"table{case.table}.csv")
                          if int(row["p"]) == case.p and int(row["order"]) == case.order and row["method"] == case.method)
            result.update(timing(text, config, case, target) if case.table == 4 else
                          precision(entry, source, text, case))
            result["source_log"] = log_name
        tables[case.table].append(result)
    # Validate every selected input before writing any tables.
    for number, rows in tables.items():
        if rows:
            write_table(output / f"table{number}", rows)
    available = sum(row["status"] == "available" for rows in tables.values() for row in rows)
    total = sum(map(len, tables.values()))
    print(f"Wrote historical tables to {output}; {available}/{total} rows available. No FHE binary was run.")
