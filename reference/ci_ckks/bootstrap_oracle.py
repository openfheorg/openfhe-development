"""D0.4 — the cleartext bootstrap oracle.

Encode/Decode follow Kim-Song §4.1 exactly (verified against their toy example
n/2=2, Delta=64, x=(1.1,2.3) -> 109-27Y):
    Ecd(x, Delta) = round(Delta * U^{-1} @ x)        (integer coefficient vector)
    Dcd(coeffs)   = U @ coeffs                        (real slot vector)

Native CI bootstrap pipeline (rank-N throughout, plan §4):
    ModRaise:  raised = coeffs + q0 * I,  I integer, ||I||_inf <= K
    CI-CtS:    move coefficients into slots  (homomorphically the encode matrix U^{-1};
               in cleartext VALUES the slots then hold `raised` coefficient-wise)
    EvalMod:   slot-wise approx (x mod q0) via scaled sine (+ optional arcsine corr.)
    CI-StC:    move slots back to coefficients
    decode:    Dcd(.) / Delta  ~ original message
EvalMod is the only stage that loses precision in cleartext (the linear transforms are
exact here); ModRaise overflow cancels because sin(2*pi*(m+q0*I)/q0)=sin(2*pi*m/q0).
"""
import random

import mpmath

from .ci_embedding import dense_U, dense_U_inv_closed
from .precision import pi
from . import linalg_mp as la

_U_CACHE = {}
_UINV_CACHE = {}


def _U(N):
    if N not in _U_CACHE:
        _U_CACHE[N] = dense_U(N)
    return _U_CACHE[N]


def _Uinv(N):
    if N not in _UINV_CACHE:
        _UINV_CACHE[N] = dense_U_inv_closed(N)
    return _UINV_CACHE[N]


def encode(msg, N, Delta):
    """Ecd: integer coefficient vector = round(Delta * U^{-1} @ msg)."""
    scaled = la.matvec(_Uinv(N), [Delta * m for m in msg])
    return [mpmath.nint(c) for c in scaled]


def decode(coeffs, N, Delta):
    """Dcd: real slot vector = (U @ coeffs) / Delta."""
    return [s / Delta for s in la.matvec(_U(N), coeffs)]


def scaled_mod(t, q0, arcsine=False):
    """Approximate (t mod q0) centered in (-q0/2, q0/2] via the scaled sine
    s(t) = (q0/2pi) sin(2pi t/q0). With arcsine correction (Lee et al. / Han-Ki) the
    sin-distortion is inverted ONCE: (q0/2pi) arcsin((2pi/q0) s) = (t mod q0) exactly
    for |2pi t/q0| < pi/2 (cleartext). The homomorphic version approximates sin & arcsin
    by polynomials; this oracle uses exact mpmath sin/arcsin."""
    two_pi = 2 * pi()
    s = (q0 / two_pi) * mpmath.sin(two_pi * t / q0)
    if arcsine:
        s = (q0 / two_pi) * mpmath.asin(two_pi * s / q0)
    return s


def mod_raise(coeffs, q0, K, seed):
    rng = random.Random(seed)
    I = [rng.randint(-K, K) for _ in coeffs]
    raised = [coeffs[i] + q0 * I[i] for i in range(len(coeffs))]
    return raised, I


def oracle_bootstrap(N, msg, q0, Delta, K, seed, arcsine=False):
    """Full cleartext trace. Returns a dict of every intermediate vector."""
    coeffs = encode(msg, N, Delta)
    raised, I = mod_raise(coeffs, q0, K, seed)
    after_cts = list(raised)                       # slots now hold the coefficients
    after_evalmod = [scaled_mod(t, q0, arcsine) for t in after_cts]
    after_stc = list(after_evalmod)                # back to coefficient layout
    out = decode(after_stc, N, Delta)
    return {
        "N": N, "q0": q0, "Delta": Delta, "K": K, "seed": seed,
        "arcsine": arcsine,
        "msg": msg, "coeffs": coeffs, "I": I, "raised": raised,
        "after_cts": after_cts, "after_evalmod": after_evalmod,
        "after_stc": after_stc, "out": out,
    }


def cts_dense_vs_factorization_gap(N, vec):
    """A0.4 component: the CtS transform via dense U vs via the staged factorization
    must agree to <2^-100 (re-exercises A0.1 inside the oracle context)."""
    from .factorization_restrict import ci_decode_A
    from .factorization_dct import ci_decode_B
    U = dense_U(N)
    dense = la.matvec(U, vec)
    fa = ci_decode_A(vec, N)
    fb = ci_decode_B(vec, N)
    return max(la.max_abs_vec(dense, fa), la.max_abs_vec(dense, fb))
