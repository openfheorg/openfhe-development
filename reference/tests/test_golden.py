"""Golden artifacts exist, parse, and are not stale; the serialized U round-trips to
the recomputed dense_U to <2^-100 (so the C++ fixture is trustworthy)."""
import json
import os

import mpmath
import pytest

from ci_ckks import linalg_mp as la
from ci_ckks.ci_embedding import dense_U
from ci_ckks.golden import GOLDEN_NS, build_all
from ci_ckks.precision import THRESHOLD, from_decimal

GOLDEN_DIR = os.path.join(os.path.dirname(__file__), "..", "golden")


def test_golden_present_and_not_stale():
    for name, obj in build_all().items():
        path = os.path.join(GOLDEN_DIR, name)
        assert os.path.exists(path), "missing golden %s (run tools/gen_golden.py)" % name
        with open(path) as f:
            on_disk = f.read().strip()
        assert on_disk == json.dumps(obj, indent=2, sort_keys=True).strip(), \
            "stale golden %s (run tools/gen_golden.py)" % name


@pytest.mark.parametrize("N", GOLDEN_NS)
def test_golden_U_roundtrips(N):
    with open(os.path.join(GOLDEN_DIR, "ci_dense_U_N%d.json" % N)) as f:
        g = json.load(f)
    Ug = mpmath.matrix(N, N)
    for r in range(N):
        for c in range(N):
            Ug[r, c] = from_decimal(g["U"][r][c])
    assert la.max_abs_diff(Ug, dense_U(N)) < THRESHOLD


@pytest.mark.parametrize("N", GOLDEN_NS)
def test_golden_oracle_recovers_message(N):
    with open(os.path.join(GOLDEN_DIR, "ci_oracle_vectors_N%d.json" % N)) as f:
        g = json.load(f)
    msg = [from_decimal(x) for x in g["msg"]]
    out = [from_decimal(x) for x in g["out"]]
    assert la.max_abs_vec(out, msg) < mpmath.mpf(2) ** -15
