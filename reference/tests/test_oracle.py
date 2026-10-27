"""A0.4 (part) — the cleartext bootstrap oracle is self-consistent: ModRaise overflow
is removed by EvalMod, the round-trip recovers the message, and the CtS transform via
dense U agrees with both staged factorizations to <2^-100."""
import mpmath
import pytest

from ci_ckks import linalg_mp as la
from ci_ckks.bootstrap_oracle import (
    cts_dense_vs_factorization_gap, decode, encode, oracle_bootstrap, scaled_mod,
)
from ci_ckks.precision import THRESHOLD

NS = [4, 8, 16, 32]


@pytest.mark.parametrize("N", NS)
def test_encode_decode_matches_kim_song(N):
    # Round-trip with a scale factor recovers the message to ~1/Delta.
    Delta = mpmath.mpf(2) ** 50
    msg = [mpmath.sin(mpmath.mpf(i + 1)) for i in range(N)]
    back = decode(encode(msg, N, Delta), N, Delta)
    assert la.max_abs_vec(back, msg) < mpmath.mpf(2) ** -30


def test_kim_song_toy_example():
    # Paper §4.1: n/2=2 slots, Delta=64, x=(1.1,2.3) -> m(Y)=109-27Y.
    c = encode([mpmath.mpf("1.1"), mpmath.mpf("2.3")], 2, mpmath.mpf(64))
    assert [int(c[0]), int(c[1])] == [109, -27]
    back = decode(c, 2, mpmath.mpf(64))
    assert abs(back[0] - mpmath.mpf("1.1065")) < mpmath.mpf("1e-3")
    assert abs(back[1] - mpmath.mpf("2.2997")) < mpmath.mpf("1e-3")


@pytest.mark.parametrize("N", NS)
def test_cts_dense_vs_factorization(N):  # A0.4
    vec = [mpmath.cos(mpmath.mpf(5 * (i + 1))) for i in range(N)]
    assert cts_dense_vs_factorization_gap(N, vec) < THRESHOLD


@pytest.mark.parametrize("N", NS)
def test_modraise_overflow_removed_and_roundtrip(N):
    Delta = mpmath.mpf(2) ** 40
    q0 = mpmath.mpf(2) ** 55
    # small messages so |coeffs| << q0 (EvalMod regime)
    msg = [mpmath.mpf(1) / 1000 * mpmath.sin(mpmath.mpf(i + 1)) for i in range(N)]
    tr = oracle_bootstrap(N, msg, q0, Delta, K=3, seed=20260614, arcsine=True)
    # EvalMod removed the q0*I overflow: after_evalmod ~ coeffs
    assert la.max_abs_vec(tr["after_evalmod"], [mpmath.mpf(c) for c in tr["coeffs"]]) < mpmath.mpf(2) ** 20
    # end-to-end recovers the message
    assert la.max_abs_vec(tr["out"], msg) < mpmath.mpf(2) ** -15


def test_scaled_mod_kills_period():
    q0 = mpmath.mpf(2) ** 50
    m = mpmath.mpf(12345)
    for I in (-3, -1, 0, 2, 5):
        assert abs(scaled_mod(m + q0 * I, q0) - scaled_mod(m, q0)) < mpmath.mpf(2) ** -20 * q0
