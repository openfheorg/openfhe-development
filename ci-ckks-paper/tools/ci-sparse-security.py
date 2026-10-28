#!/usr/bin/env python3
"""Security of the sparse-encapsulation ephemeral secret (item 3.1 of PLAN_PHASE2.md).

The sparse-secret switching key of SPARSE_ENCAPSULATED is an RLWE sample under the ephemeral secret s' modulo
q0 * P' (OpenFHE, 64-bit build, no composite scaling: q0 = 60 bits, P' = two 33-bit primes, log q ~ 126). For CI the
ring has rank N = 65536 and s' has h nonzero ternary CI-basis coordinates, so the attack instance is LWE with
n = 65536, a ternary secret of Hamming weight h, Gaussian error sigma = 3.19.

The malb/lattice-estimator (needs SageMath) could not be installed on ICELAKE (download of external code was not
permitted in the harness), so this script evaluates a SUBSET of its attacks with its formulas:
  * primal uSVP, 2016 estimate (ADPS16 / AGVW17): sqrt(b) * sigma <= delta(b)^(2b - d) * Vol^(1/d), with
    Bai-Galbraith scaling of the secret part (nu = sigma / sigma_s) and "drop and solve" (guess zeta coordinates
    to be zero, success probability C(n - zeta, h) / C(n, h)); the estimator's usvp/bdd + zeta guessing;
  * meet-in-the-middle on the secret alone (Odlyzko split; rounding hash on a few samples).
The minimum over a subset of attacks is an UPPER bound on what the full estimator reports: if a value here is
below 128 bits, the full estimator is below 128 bits as well.
BKZ cost models: core-SVP 0.292 b (ADPS16 classical; the HE-standard tables), and BDGL16 with 8d tours
(0.292 b + 16.4 + log2(8 d), lattice-estimator RC.BDGL16).

Usage: python3 ci-sparse-security.py   (prints the calibration and one table; ~20 s)
"""
import math

SIGMA = 3.19


def log2_binom(n, k):
    return (math.lgamma(n + 1) - math.lgamma(k + 1) - math.lgamma(n - k + 1)) / math.log(2)


def log2_delta(b):
    return math.log2(((b / (2 * math.pi * math.e)) * (math.pi * b) ** (1.0 / b)) ** (1.0 / (2 * (b - 1))))


def cost(b, d, model):
    if model == "core":
        return 0.292 * b
    return 0.292 * b + 16.4 + math.log2(8 * d)


def usvp_beta(n, logq, sigma_s, mmax):
    """Smallest BKZ block size b (and d) for which the 2016 uSVP condition holds for some m <= mmax."""
    lognu = max(0.0, math.log2(SIGMA / sigma_s))  # Bai-Galbraith scaling; no scaling for a dense ternary secret
    lo, hi = 40, min(60000, (n + mmax) // 2)

    def ok(b):
        ld = log2_delta(b)
        lhs = 0.5 * math.log2(b) + math.log2(SIGMA)
        # RHS(m) = (2b - d) ld + (m logq + n lognu) / d, d = m + n + 1; scan m (concave in m), coarse then fine
        best, bestd, bm = -1e300, None, None
        step = max(1, mmax // 400)
        cand = list(range(step, mmax + 1, step))
        for _ in range(3):
            for m in cand:
                d = m + n + 1
                if d <= b:
                    continue
                r = (2 * b - d) * ld + (m * logq + n * lognu) / d
                if r > best:
                    best, bestd, bm = r, d, m
            if bm is None:
                return False, None
            step = max(1, step // 20)
            cand = range(max(1, bm - 20 * step), min(mmax, bm + 20 * step) + 1, step)
        return best >= lhs, bestd

    if not ok(hi)[0]:
        return None, None
    while hi - lo > 1:
        mid = (lo + hi) // 2
        if ok(mid)[0]:
            hi = mid
        else:
            lo = mid
    return hi, ok(hi)[1]


def primal_drop(n, logq, h, model, mmax=None):
    """min over zeta of uSVP cost in dimension n - zeta (sparse, BG-scaled) / P[all h nonzeros survive]."""
    mmax = mmax or n
    best = (1e9, None)
    zetas = sorted(set([0] + [n - k for k in (256, 384, 512, 768, 1024, 1536, 2048, 3072, 4096, 6144, 8192,
                                               12288, 16384, 24576, 32768, 49152) if k < n]))
    for z in zetas:
        n1 = n - z
        if n1 < h:
            continue
        sigma_s = math.sqrt(h / n1)
        b, d = usvp_beta(n1, logq, sigma_s, mmax)
        if b is None:
            continue
        logp = log2_binom(n - z, h) - log2_binom(n, h)
        c = cost(b, d, model) - logp
        if c < best[0]:
            best = (c, (n1, b, d, -logp))
    return best


def dense(n, logq, model):
    b, d = usvp_beta(n, logq, math.sqrt(2.0 / 3.0), n)
    return cost(b, d, model), b, d


def mitm(n, h):
    """Odlyzko MITM on a weight-h ternary secret: split the coordinates in halves, h/2 nonzeros in each (probability
    C(n/2,h/2)^2 / C(n,h)), lists of C(n/2, h/2) 2^(h/2) entries, rounding hash on a few samples (q / sigma ~ 2^123,
    so 2 samples filter all false matches). Returns log2 of the expected list entries built (time ~ memory)."""
    half = h // 2
    logL = log2_binom(n // 2, half) + half
    logp = 2 * log2_binom(n // 2, half) - log2_binom(n, h)
    return logL + 1 - logp, logL, -logp, log2_binom(n, h) + h


def main():
    print("calibration: dense ternary secret (HE standard 128-bit bounds, classical)")
    for n, logq in ((4096, 109), (8192, 218), (65536, 1747)):
        for model in ("core", "bdgl16"):
            c, b, d = dense(n, logq, model)
            print(f"  n={n:6d} logq={logq:5d} {model:7s}: {c:6.1f} bits (beta {b}, d {d})")
    n = 65536
    print("\nsparse ephemeral secret, n = 65536 (CI rank), sigma = 3.19")
    print("h  | logq | primal+drop core-SVP (n', beta, guess bits) | primal+drop BDGL16 | MITM time (list, split) | #secrets")
    for h in (16, 24, 32, 64):
        for logq in (126,):
            c1, i1 = primal_drop(n, logq, h, "core")
            c2, i2 = primal_drop(n, logq, h, "bdgl16")
            t, L, sp, ns = mitm(n, h)
            print(f"{h:3d} | {logq} | {c1:6.1f} ({i1[0]}, {i1[1]}, {i1[3]:.1f}) | {c2:6.1f} ({i2[0]}, {i2[1]}, "
                  f"{i2[3]:.1f}) | {t:6.1f} ({L:.1f}, {sp:.2f}) | {ns:.1f}")
    # std, for reference: power-basis weight 32 in rank 65536 (same LWE dimension as CI here)


if __name__ == "__main__":
    main()
