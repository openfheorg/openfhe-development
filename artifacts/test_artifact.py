"""Fast regression tests. Synthetic logs stay in temporary test directories."""
import csv
from dataclasses import asdict
import io
import json
import math
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import reproduce as r
from theory import capacity, lut_values, threshold


def synthetic_log(case):
    """Parser fixture, not a benchmark measurement."""
    args = dict(arg[2:].split("=", 1) for arg in r.command(case, Path("fixture"))[1:] if "=" in arg)
    config = {"mode": args["mode"], "method": case.method,
              "implementation": "BKSS_NEW" if case.method == "BKSS" else case.method,
              "p": case.p, "order": case.order, "ring_dim": case.ring, "slots": case.slots,
              "sf": 59, "eval_exp_degree": 58, "scaling": "FIXEDMANUAL", "key_dist": "SPARSE_TERNARY",
              "unsafe": int(case.unsafe), "level_budget": args["level-budget"],
              "warmups": int(case.table == 4), "measured_runs": 5 if case.table == 4 else 1}
    log = "CONFIG " + " ".join(f"{k}={v}" for k, v in config.items()) + "\nCSV_BEGIN\n"
    log += "run,warmup,noise_base,max_error,key_switches,lut_levels,total_ms,lut_ms,input_noise,lut_noise\n"
    for i, base in enumerate([10] * 6 if case.table == 4 else r.noise_bases(case)):
        log += f"{i if case.table == 4 else 0},{int(case.table == 4 and i == 0)},{base},0,28,5,1000,100,-35,-31\n"
    return log + "CSV_END\n"


class TheoryTests(unittest.TestCase):
    def test_all_table3_values(self):
        for row in r.read_csv(r.REFERENCE / "table3.csv"):
            values = lut_values(row["lut"], int(row["p"]))
            for n in range(1, 6):
                self.assertAlmostEqual(threshold(values, n, "SPARSE_THI"), float(row[f"n{n}"]), delta=0.005)

    def test_all_table5_thresholds_and_capacity(self):
        for row in r.read_csv(r.REFERENCE / "table5.csv"):
            n = int(row["order"])
            t = threshold(lut_values("ID", int(row["p"])), n, row["method"], True)
            # Table 5 truncates several thresholds (e.g. -8.397... is printed
            # as -8.39); preserve the formulas instead of fitting printed digits.
            self.assertAlmostEqual(t, float(row["log_t"]), delta=0.01)
            c = capacity(t, float(row["log_b"]), n)[2]
            self.assertAlmostEqual(c, float(row["capacity_bits"]), delta=0.015)

    def test_bkss_model_unchanged(self):
        for p in (16, 256):
            v = lut_values("ID", p)
            self.assertEqual(threshold(v, 1, "BKSS", True), threshold(v, 1, "BKSS_NEW", True))
            self.assertEqual(threshold(v, 1, "BKSS", True), threshold(v, 1, "AKP", True))

    def test_noise_floor_estimator(self):
        rows = [{"input_noise": -35, "lut_noise": -32}, {"input_noise": -34, "lut_noise": -31},
                {"input_noise": -20, "lut_noise": -12}]
        self.assertEqual(r.bound(rows), -31)


class WorkflowTests(unittest.TestCase):
    def test_exact_matrix(self):
        t4, t5 = r.paper_cases("4"), r.paper_cases("5")
        self.assertEqual((len(t4), len(t5)), (15, 15))
        self.assertEqual(len({case.id for case in t4 + t5}), 30)
        self.assertEqual(sum(c.unsafe for c in t4), 2)
        self.assertFalse(any(c.unsafe for c in t5))
        self.assertEqual({c.ring for c in t5 if c.p == 16 and c.method == "SPARSE_THI" and c.order >= 3}, {131072})
        self.assertTrue(all(c.slots == c.ring for c in t4 + t5))
        self.assertTrue(all("--method=BKSS" in r.command(c, Path("fbt")) for c in t4 + t5 if c.method == "BKSS"))
        self.assertEqual(r.noise_bases(t5[0]), list(range(24, 54)))
        self.assertEqual(r.noise_bases(t5[-1]), list(range(24, 50)))
        self.assertEqual(len(r.count_cases()), 15)
        self.assertTrue(all(c.ring == 256 and c.slots == 256 and c.table == 0 for c in r.count_cases()))
        self.assertEqual(len(r.smoke_cases()), 24)
        self.assertTrue(all(c.ring <= 256 and c.unsafe for c in r.smoke_cases()))

    def test_parser_complete(self):
        for case in r.paper_cases():
            self.assertTrue(r.parse_log(synthetic_log(case), case)[1])

    def test_reject_corruption(self):
        case = r.paper_cases("4")[1]
        log = synthetic_log(case)
        corruptions = [log.replace("CSV_END\n", ""), log + log,
                       log.replace("implementation=BKSS_NEW", "implementation=BKSS_LEGACY"),
                       log.replace("sf=59", "sf=50"), log.replace("ring_dim=65536", "ring_dim=256"),
                       log.replace("0,0,28,5", "0,1,28,5"), log.replace("1000,100", "nan,100"),
                       log.replace("1,0,10", "1,1,10")]
        for corrupt in corruptions:
            with self.assertRaises((ValueError, KeyError)):
                r.parse_log(corrupt, case)

    def test_complete_report_and_missing_rows(self):
        with tempfile.TemporaryDirectory() as directory:
            raw, output = Path(directory) / "raw", Path(directory) / "report"
            raw.mkdir()
            cases = r.paper_cases()
            for case in cases:
                log = raw / (case.id + ".log")
                log.write_text(synthetic_log(case))
                meta = {"case": asdict(case), "log_sha256": r.sha256(log), "returncode": 0,
                        "environment": {"source_sha256": "synthetic-fixture", "binary_sha256": "synthetic-fixture"}}
                (raw / (case.id + ".json")).write_text(json.dumps(meta))
            with patch("figures.experimental_phase"):
                r.report(raw, output, "all")
            self.assertEqual(len(r.read_csv(output / "table4.csv")), 15)
            self.assertEqual(len(r.read_csv(output / "table5.csv")), 15)
            (raw / (cases[-1].id + ".log")).unlink()
            with self.assertRaises(FileNotFoundError):
                r.report(raw, output, "all")

    def test_run_defaults_to_plan_without_binary(self):
        proc = subprocess.run([sys.executable, str(Path(r.__file__)), "run", "--binary=/does/not/exist"],
                              capture_output=True, text=True, check=True, cwd="/tmp")
        self.assertIn("NOT executed", proc.stdout)
        self.assertEqual(proc.stdout.count("taskset"), 30)


class ArchivedDataTests(unittest.TestCase):
    source = r.ROOT / "artifacts/results/archived"

    def test_complete_archived_tables(self):
        from archived_report import report_archive
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            report_archive(self.source, output)
            t4, t5 = r.read_csv(output / "table4.csv"), r.read_csv(output / "table5.csv")
            self.assertEqual((len(t4), len(t5)), (15, 15))
            self.assertNotIn("lut_ratio_to_paper", t4[0])
            self.assertNotIn("bound_delta", t5[0])
            self.assertNotIn("capacity_delta", t5[0])
            self.assertEqual(sum(row["status"] == "available" for row in t4), 15)
            self.assertEqual(sum(row["status"] == "available" for row in t5), 15)
            self.assertAlmostEqual(float(t4[0]["lut_s"]), 0.72956)
            self.assertAlmostEqual(float(t4[0]["total_s"]), 12.47029)
            order5 = next(row for row in t5 if row["p"] == "16" and row["order"] == "5")
            self.assertAlmostEqual(float(order5["log_b"]), -29.779)
            self.assertEqual((order5["noise_first"], order5["noise_last"]), ("24", "53"))
            self.assertEqual((order5["points"], order5["log_corroborated_points"]), ("30", "30"))
            for row in t5:
                if row["status"] == "available":
                    self.assertTrue(math.isfinite(float(row["log_b"])))
                    expected = capacity(float(row["log_t"]), float(row["log_b"]), int(row["order"]))[2]
                    self.assertAlmostEqual(float(row["capacity_bits"]), expected)
            for row in t4:
                if row["status"] == "available":
                    self.assertEqual(row["samples"], "5")

    def test_corrupt_files_and_wrong_settings_rejected(self):
        from archived_report import report_archive
        with tempfile.TemporaryDirectory() as directory:
            source, output = Path(directory) / "raw", Path(directory) / "report"
            shutil.copytree(self.source, source)
            manifest = json.loads((source / "manifest.json").read_text())
            entry = next(entry for entry in manifest["cases"] if "files" in entry)
            name = next(iter(entry["files"]))
            log = source / name
            log.write_text(log.read_text().replace("sf=59", "sf=50"))
            with self.assertRaisesRegex(ValueError, "checksum"):
                report_archive(source, output)
            entry["files"][name] = r.sha256(log)
            (source / "manifest.json").write_text(json.dumps(manifest))
            with self.assertRaisesRegex(ValueError, "wrong sf"):
                report_archive(source, output)
            self.assertFalse(output.exists())

    def test_archive_report_needs_no_binary(self):
        with tempfile.TemporaryDirectory() as directory:
            result = subprocess.run([sys.executable, str(Path(r.__file__)), "archived-report",
                                     "--binary=/does/not/exist", "--output=" + directory],
                                    cwd=directory, capture_output=True, text=True, check=True)
            self.assertIn("No FHE binary was run", result.stdout)


if __name__ == "__main__":
    unittest.main()
