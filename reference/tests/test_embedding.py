"""A0.3 — U is invertible (U U^{-1}=I to <2^-100), the closed-form inverse matches
the numeric inverse, columns are orthogonal with the [N,2N,...] norms, encode/decode
round-trips exactly (exercising the b_0 / constant slot), and the basis asymmetry is
real (zeroing the u_0 factor breaks the round-trip)."""
import mpmath
import pytest

from ci_ckks import linalg_mp as la
from ci_ckks.ci_embedding import (
    column_norm_sq, dense_U, dense_U_inv_closed, rot_group, slot_perm_g5,
)
from ci_ckks.precision import THRESHOLD

NS = [2, 4, 8, 16, 32]


@pytest.mark.parametrize("N", NS)
def test_columns_orthogonal_with_expected_norms(N):
    U = dense_U(N)
    G = la.transpose(U) * U  # U^T U should be diag(N, 2N, ..., 2N)
    w = column_norm_sq(N)
    for i in range(N):
        for j in range(N):
            expected = w[i] if i == j else mpmath.mpf(0)
            assert abs(G[i, j] - expected) < THRESHOLD


@pytest.mark.parametrize("N", NS)
def test_U_times_Uinv_is_identity(N):
    U = dense_U(N)
    Uinv = la.inv(U)
    I = la.eye(N)
    assert la.max_abs_diff(U * Uinv, I) < THRESHOLD
    assert la.max_abs_diff(Uinv * U, I) < THRESHOLD


@pytest.mark.parametrize("N", NS)
def test_closed_form_inverse_matches_numeric(N):
    U = dense_U(N)
    assert la.max_abs_diff(dense_U_inv_closed(N), la.inv(U)) < THRESHOLD


@pytest.mark.parametrize("N", NS)
def test_encode_decode_roundtrip_exercises_b0(N):
    # Real coefficient vector with a deliberately nonzero constant (b_0) term.
    coeffs = [mpmath.mpf(1) / 3] + [mpmath.cos(mpmath.mpf(7 * (i + 1))) for i in range(N - 1)]
    U = dense_U(N)
    Uinv = dense_U_inv_closed(N)
    slots = la.matvec(U, coeffs)                  # decode
    back = la.matvec(Uinv, slots)                 # encode
    assert la.max_abs_vec(back, coeffs) < THRESHOLD


@pytest.mark.parametrize("N", NS)
def test_b0_asymmetry_is_load_bearing(N):
    """Negative test: if the u_0 column norm is (wrongly) set to 2N like the others,
    the round-trip must break — proving the asymmetry is actually guarded."""
    U = dense_U(N)
    wrong = mpmath.matrix(N, N)
    for i in range(N):
        s = 1 / mpmath.mpf(2 * N)  # WRONG for i==0 (should be 1/N)
        for j in range(N):
            wrong[i, j] = s * U[j, i]
    coeffs = [mpmath.mpf(1)] + [mpmath.mpf(0)] * (N - 1)  # pure constant
    back = la.matvec(wrong, la.matvec(U, coeffs))
    assert la.max_abs_vec(back, coeffs) > mpmath.mpf(1) / 4  # grossly wrong


@pytest.mark.parametrize("N", NS)
def test_slot_perm_and_rot_group(N):
    rg = rot_group(N)
    assert rg[0] == 1 and rg[1] == 5 % (4 * N)
    assert len(set(rg)) == N  # 5 has order N mod 4N
    P = slot_perm_g5(N)
    assert sorted(P) == list(range(N))
    assert P[0] == 0  # 5^0 = 1 -> 4*0+1
