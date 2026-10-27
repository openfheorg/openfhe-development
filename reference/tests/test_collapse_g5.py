"""The g=5-rotation-ALIGNED collapsed CI real-DFT (the genuine iso-precision fix) reconstructs
the CI decode U to 2^-100, is genuinely sparse under g=5 (the property the stride factorization
LACKS), and gives an exact CtS/StC round-trip. This is the validated C++ spec for the collapsed
native CI bootstrap; see reference/ci_ckks/collapse_g5.py.
"""
import mpmath
import pytest

from ci_ckks import linalg_mp as la
from ci_ckks.ci_embedding import column_norm_sq, dense_U, dense_U_inv_closed
from ci_ckks.collapse_g5 import (count_g5_diagonals, decoding_fat_levels_g5,
                                  reconstruct_U_from_fats)
from ci_ckks.factorization_collapse import two_stage_matrices
from ci_ckks.precision import THRESHOLD

# (N, level_budget) with level_budget | log2(N)
CASES = [(8, 3), (16, 2), (16, 4), (64, 2), (64, 3), (64, 6), (256, 2), (256, 4)]


@pytest.mark.parametrize("N,lb", CASES)
def test_collapse_reconstructs_U(N, lb):
    fats, _ = decoding_fat_levels_g5(N, lb)
    assert la.max_abs_diff(reconstruct_U_from_fats(fats, N), dense_U(N)) < THRESHOLD


@pytest.mark.parametrize("N,lb", CASES)
def test_levels_are_g5_sparse(N, lb):
    """Each fat level has <= numRotations = 2^(layersCollapse+1)-1 g5 diagonals -- the genuine
    O(sqrt N)-per-level sparsity. (Single-level would be N.)"""
    fats, layers = decoding_fat_levels_g5(N, lb)
    num_rotations = (1 << (layers + 1)) - 1
    for s, f in enumerate(fats):
        d = count_g5_diagonals(f)
        assert d <= num_rotations, f"level {s}: {d} g5-diagonals > numRotations {num_rotations}"
    # and strictly sparser than the dense single-level transform for non-trivial collapse
    if layers < (N.bit_length() - 1):
        assert num_rotations < N


@pytest.mark.parametrize("N,lb", [(16, 2), (64, 2), (256, 2)])
def test_ctS_stC_round_trip_is_identity(N, lb):
    """StC (= U) and CtS (= U^{-1} = diag(1/w) U^T, built from the SAME fats by transposition)
    compose to the identity to 2^-100 -- so the collapsed bootstrap refreshes exactly."""
    fats, _ = decoding_fat_levels_g5(N, lb)
    U = reconstruct_U_from_fats(fats, N)
    w = column_norm_sq(N)
    Uinv = mpmath.matrix(N, N)
    for a in range(N):
        for b in range(N):
            Uinv[a, b] = U[b, a] / w[a]          # (diag(1/w) U^T)[a,b]
    assert la.max_abs_diff(Uinv, dense_U_inv_closed(N)) < THRESHOLD
    assert la.max_abs_diff(U * Uinv, mpmath.eye(N)) < THRESHOLD


@pytest.mark.parametrize("N", [16, 64, 256])
def test_g5_aligned_beats_stride_sparsity(N):
    """Contrast: the STRIDE-decimation 2-stage factorization (factorization_collapse) is DENSE
    under g=5 (~N diagonals/stage) -- which is why the first C++ level-collapse port did not
    speed up or improve precision. The g5-aligned collapse is sparse. This test documents the
    discriminating property that motivated the rewrite."""
    nsub = 1 << ((N.bit_length() - 1) // 2)
    Mfci, Mfsi, Mfco, Mfso = two_stage_matrices(N, nsub)
    # The stride IN stage (Mfci/Mfsi) is DENSE under g=5 (~N nonzero g5 diagonals) -- so the
    # stride two-stage spends single-level cost on its first stage (the OUT stage Mfco/Mfso is
    # sparse, but the IN stage dominates). This is why that port did not speed up / improve precision.
    stride_diags = count_g5_diagonals(Mfci)
    assert stride_diags >= N, f"expected stride IN stage dense under g5 (~N), got {stride_diags}"
    # g5-aligned (lb=2) is sparse
    fats, layers = decoding_fat_levels_g5(N, 2)
    g5_diags = max(count_g5_diagonals(f) for f in fats)
    assert g5_diags <= (1 << (layers + 1)) - 1
    assert g5_diags < stride_diags
