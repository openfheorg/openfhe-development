"""D0.4 — analytic noise / precision predictor in the canonical-embedding l2 framework.

Kim-Song use the canonical embedding norm ||a||_2^can = ||tau(a)||_2 = ||U @ coeffs||_2.
Because the CI basis image is orthogonal with column norms
    w = [N, 2N, 2N, ..., 2N]            (||tau(1)||^2 = N, ||tau(X^i+X^-i)||^2 = 2N),
we have ||a||_2^can^2 = sum_i w_i * coeffs_i^2. The 1:2 asymmetry of w_0 vs w_i is the
basis asymmetry the whole pipeline must respect (CIBasisScale). [The plan's "N/2 vs N"
is the same ratio under a tau scaled by 1/sqrt(2); the values here match the paper's
explicit toy example and OpenFHE.]

This module gives (a) the encode/decode rounding precision used as the A0.4 textbook
sanity, and (b) a coarse bootstrap-stage predictor for the golden file. The full
Kim-Song Appendix-A homomorphic variances (V_enc/V_err/V_key/V_rs/V_mult/V_q) are wired
and calibrated in Phase 1, where A1.3 tests them against measured homomorphic noise.
"""
import mpmath

from .precision import pi
from .bootstrap_oracle import scaled_mod


def basis_weights(N):
    """Kim-Song §4.1 canonical-embedding squared norms of the Z-basis images."""
    return [mpmath.mpf(N)] + [mpmath.mpf(2 * N)] * (N - 1)


def canonical_norm_sq(coeffs, N):
    w = basis_weights(N)
    return sum(w[i] * coeffs[i] ** 2 for i in range(N))


def predict_encode_decode_rms(N, Delta):
    """Expected per-slot RMS error of decode(encode(x)) from coefficient rounding.

    Ecd rounds Delta*U^{-1}@x; per-coeff rounding error ~ U(-1/2,1/2), var 1/12.
    Decoded error e = U @ delta / Delta, E||e||^2 = (sum_i w_i)/12 / Delta^2, and
    sum_i w_i = N + (N-1)*2N = 2N^2 - N. Per-slot RMS = sqrt(E||e||^2 / N)."""
    sum_w = mpmath.mpf(2) * N * N - N
    e_norm_sq = sum_w / 12 / (Delta ** 2)
    return mpmath.sqrt(e_norm_sq / N)


def predict_evalmod_max_error(q0, msg_bound, arcsine=False, samples=129):
    """Max |m - scaled_mod(m,q0)| over |m|<=msg_bound (the cleartext EvalMod error)."""
    worst = mpmath.mpf(0)
    for k in range(samples):
        m = -msg_bound + 2 * msg_bound * mpmath.mpf(k) / (samples - 1)
        err = abs(m - scaled_mod(m, q0, arcsine))
        if err > worst:
            worst = err
    return worst


def predict_bootstrap_output_bits(N, Delta, q0, msg_bound, arcsine=False):
    """Coarse predicted recovered mantissa bits: dominated (in cleartext) by the larger
    of the encode/decode rounding error and the EvalMod approximation error, relative to
    the message scale. Refined with homomorphic variances in Phase 1."""
    enc_rms = predict_encode_decode_rms(N, Delta)
    evalmod = predict_evalmod_max_error(q0, msg_bound, arcsine) / Delta
    err = max(enc_rms, evalmod)
    if err <= 0:
        return mpmath.inf
    return -mpmath.log(err, 2)
