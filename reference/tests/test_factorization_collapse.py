"""The recursive REAL CI-DCT/DST factorization reproduces dense_U to <2^-100 (the spec
for the C++ level-collapsed CI real-DFT), and the DST companion matches 2 sin(theta_s c)."""
import mpmath
import pytest

from ci_ckks import linalg_mp as la
from ci_ckks.ci_embedding import dense_U
from ci_ckks.factorization_collapse import ci_dct, ci_dct_dense, ci_dst, count_stages
from ci_ckks.precision import THRESHOLD, cos, pi, sin

NS = [2, 4, 8, 16, 32, 64]


@pytest.mark.parametrize("N", NS)
def test_recursive_ci_dct_reproduces_U(N):
    assert la.max_abs_diff(ci_dct_dense(N), dense_U(N)) < THRESHOLD


@pytest.mark.parametrize("N", NS)
def test_ci_dst_matches_definition(N):
    # y[s] = sum_c 2 sin(theta_s c) a[c]
    a = [mpmath.cos(mpmath.mpf(3 * (i + 1))) for i in range(N)]
    y = ci_dst(a, N)
    for s in range(N):
        th = pi() * (4 * s + 1) / (2 * N)
        ref = sum(2 * sin(th * c) * a[c] for c in range(N))
        assert abs(y[s] - ref) < THRESHOLD


@pytest.mark.parametrize("N", NS)
def test_stage_count(N):
    assert count_stages(N) == N.bit_length() - 1


def _halve_col0(M):
    n = M.rows
    R = mpmath.matrix(n, n)
    for r in range(n):
        for c in range(n):
            R[r, c] = M[r, c] * (mpmath.mpf("0.5") if c == 0 else 1)
    return R


@pytest.mark.parametrize("N", [4, 16, 64, 256])
def test_two_stage_StC_and_CtS(N):
    """The 4-matrix 2-stage forms (with the DC fold = halve column 0 of the IN matrices)
    reconstruct U (StC) and U^{-1} (CtS) to <2^-100 -- the exact C++ multi-stage recipe."""
    from ci_ckks.ci_embedding import dense_U, dense_U_inv_closed
    from ci_ckks.factorization_collapse import two_stage_matrices
    nsub = 1 << ((N.bit_length() - 1) // 2)
    Mfci, Mfsi, Mfco, Mfso = two_stage_matrices(N, nsub)
    Mfci, Mfsi = _halve_col0(Mfci), _halve_col0(Mfsi)
    # StC: U = M_fc_out @ M_fc_in_dc + M_fs_out @ M_fs_in_dc
    assert la.max_abs_diff(Mfco * Mfci + Mfso * Mfsi, dense_U(N)) < THRESHOLD
    # CtS: U^{-1} = D @ U^T, U^T = M_fc_in_dc^T @ M_fc_out^T + M_fs_in_dc^T @ M_fs_out^T
    UT = la.transpose(Mfci) * la.transpose(Mfco) + la.transpose(Mfsi) * la.transpose(Mfso)
    D = mpmath.matrix(N, N)
    w = [N] + [2 * N] * (N - 1)
    for i in range(N):
        D[i, i] = 1 / mpmath.mpf(w[i])
    assert la.max_abs_diff(D * UT, dense_U_inv_closed(N)) < THRESHOLD
