# Historical raw measurements

This directory contains the authors' original measurements, copied byte-for-byte
from the private research experiment archive (commit-time source directory:
`openfhe-development-private/experiments/generated`). They are **historical
measurements, not fresh runs of the current branch**. Build and hardware
provenance was not recorded in the private archive, so it is reported as unknown
in `manifest.json` rather than inferred from the paper.

## Coverage

`manifest.json` lists all 30 paper cases (the `Case` objects used by
`artifacts/reproduce.py`), 15 for Table 4 (timing) and 15 for Table 5
(noise capacity), with a SHA-256 checksum for every bundled file:

| Paper item | Files | Format |
| --- | --- | --- |
| Table 4 | `benchmark-runs/*.log` | one warm-up + five measured runs per case |
| Table 5 | `*-id-p*-ring_*-SPARSE_TERNARY-FIXEDMANUAL-lvlb3_2.log` | one precision point per noise base |

Two Table 4 log files (`real-fullpack-ring65536-lvlb3_2-method-akp25-p16-order1.log`
and `...-method-mixedconstraints-p16-order1.log`) were updated in the private
archive after `manifest.json` was generated; their manifest checksums were
corrected to match the files, which are unchanged. The unit tests pin the
resulting averages.

## Using this directory

```bash
python3 artifacts/reproduce.py archived-report
```

The command verifies every checksum in `manifest.json`, rejects malformed or
misconfigured logs, and regenerates Table 4, Table 5, `phase-data.csv` and
`figure1.png` under `artifacts/results/archived-report/` without running any FHE
code. It is the fast way to inspect the numbers that the paper reports before
running the expensive `run --execute` matrix.

These files are reference data. For an independently measured reproduction use
`artifacts/reproduce.py run --table=4 --execute` and
`artifacts/reproduce.py run --table=5 --execute`, then
`artifacts/reproduce.py report`; see `AEC.md` and the top-level `README.md`.
