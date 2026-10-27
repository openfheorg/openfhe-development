#!/usr/bin/env python3
"""CI entrypoint: re-run the Phase-0 acceptance checks (A0.1-A0.4) against the committed
golden JSON, and confirm the golden files are not stale. No file writes.

  python3 tools/verify_golden.py --check
"""
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import mpmath  # noqa: E402

from ci_ckks import linalg_mp as la  # noqa: E402
from ci_ckks.ci_embedding import dense_U  # noqa: E402
from ci_ckks.factorization_restrict import derive_A_dense  # noqa: E402
from ci_ckks.factorization_dct import derive_B_dense  # noqa: E402
from ci_ckks.golden import GOLDEN_NS  # noqa: E402
from ci_ckks.precision import THRESHOLD, from_decimal  # noqa: E402

GOLDEN_DIR = os.path.join(os.path.dirname(__file__), "..", "golden")


def _load(name):
    with open(os.path.join(GOLDEN_DIR, name)) as f:
        return json.load(f)


def main():
    ok = True
    # A0.1 / A0.2: derivations reproduce U and agree; and match the golden dense_U.
    for N in GOLDEN_NS:
        U = dense_U(N)
        A = derive_A_dense(N)
        B = derive_B_dense(N)
        dA = la.max_abs_diff(A, U)
        dB = la.max_abs_diff(B, U)
        dAB = la.max_abs_diff(A, B)
        g = _load("ci_dense_U_N%d.json" % N)
        Ug = mpmath.matrix(N, N)
        for r in range(N):
            for c in range(N):
                Ug[r, c] = from_decimal(g["U"][r][c])
        dg = la.max_abs_diff(U, Ug)
        passed = max(dA, dB, dAB, dg) < THRESHOLD
        ok = ok and passed
        print("N=%-3d  |A-U|=%s |B-U|=%s |A-B|=%s |golden-U|=%s  %s"
              % (N, mpmath.nstr(dA, 2), mpmath.nstr(dB, 2), mpmath.nstr(dAB, 2),
                 mpmath.nstr(dg, 2), "OK" if passed else "FAIL"))

    # Golden drift gate: recompute every artifact in-memory and compare to disk.
    from ci_ckks.golden import build_all
    for name, obj in build_all().items():
        path = os.path.join(GOLDEN_DIR, name)
        expect = json.dumps(obj, indent=2, sort_keys=True).strip()
        if not os.path.exists(path):
            print("DRIFT missing:", name); ok = False; continue
        with open(path) as f:
            if f.read().strip() != expect:
                print("DRIFT:", name); ok = False

    print("verify_golden:", "OK" if ok else "FAILED")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
