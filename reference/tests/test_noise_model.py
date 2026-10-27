"""A0.4 — the analytic precision predictor matches the textbook leveled-CKKS sanity:
predicted encode/decode RMS error matches the empirically measured RMS within 0.5 bits,
across N. A negative test confirms the basis weights [N,2N] are load-bearing."""
import random

import mpmath
import pytest

from ci_ckks import linalg_mp as la
from ci_ckks.bootstrap_oracle import decode, encode
from ci_ckks.noise_model import (
    basis_weights, predict_encode_decode_rms, predict_evalmod_max_error,
)

NS = [8, 16, 32]


def _empirical_encode_decode_rms(N, Delta, trials, seed):
    rng = random.Random(seed)
    acc = mpmath.mpf(0)
    count = 0
    for _ in range(trials):
        msg = [mpmath.mpf(rng.uniform(-1, 1)) for _ in range(N)]
        err = la.max_abs_vec  # not used; compute full RMS below
        back = decode(encode(msg, N, Delta), N, Delta)
        for a, b in zip(back, msg):
            acc += (a - b) ** 2
            count += 1
    return mpmath.sqrt(acc / count)


@pytest.mark.parametrize("N", NS)
def test_encode_decode_rms_within_half_bit(N):  # A0.4 sanity
    Delta = mpmath.mpf(2) ** 30
    predicted = predict_encode_decode_rms(N, Delta)
    empirical = _empirical_encode_decode_rms(N, Delta, trials=60, seed=1234 + N)
    # |log2(predicted) - log2(empirical)| < 0.5 bits
    assert abs(mpmath.log(predicted, 2) - mpmath.log(empirical, 2)) < mpmath.mpf("0.5")


@pytest.mark.parametrize("N", NS)
def test_factor_two_is_in_the_formula(N):
    """Deterministic guard that the basis factor-2 is encoded: the correct prediction
    (sum_w = 2N^2 - N) must differ from a 'forgot the factor 2' model (sum_w = N^2) by
    the ~sqrt(2) ratio sqrt((2N-1)/N), proving the asymmetry is in the model."""
    Delta = mpmath.mpf(2) ** 30
    correct = predict_encode_decode_rms(N, Delta)
    no_factor2 = mpmath.sqrt((mpmath.mpf(N) * N) / 12 / (Delta ** 2) / N)
    ratio = correct / no_factor2
    expected = mpmath.sqrt((2 * mpmath.mpf(N) - 1) / N)  # in (1.32, 1.42)
    assert abs(ratio - expected) < mpmath.mpf("1e-30")
    assert ratio > mpmath.mpf("1.3")


def test_basis_weights_shape():
    w = basis_weights(8)
    assert w[0] == 8 and all(x == 16 for x in w[1:])


def test_arcsine_reduces_evalmod_error():
    q0 = mpmath.mpf(2) ** 50
    bound = q0 / mpmath.mpf(2) ** 12  # message well inside the interval
    e0 = predict_evalmod_max_error(q0, bound, arcsine=False)
    e1 = predict_evalmod_max_error(q0, bound, arcsine=True)
    assert e1 < e0 / mpmath.mpf(2) ** 20  # arcsin correction makes cleartext near-exact
