"""A0.1 / A0.2 — both independent derivations reproduce dense_U, and agree with each
other and the Chebyshev witness, all to <2^-100."""
import mpmath
import pytest

from ci_ckks import linalg_mp as la
from ci_ckks.ci_embedding import dense_U
from ci_ckks.factorization_dct import derive_B_dense, dense_U_chebyshev
from ci_ckks.factorization_restrict import derive_A_dense, fft_special_stages
from ci_ckks.precision import THRESHOLD

NS = [2, 4, 8, 16, 32, 64]


@pytest.mark.parametrize("N", NS)
def test_derivation_A_reproduces_U(N):  # A0.1 (A)
    assert la.max_abs_diff(derive_A_dense(N), dense_U(N)) < THRESHOLD


@pytest.mark.parametrize("N", NS)
def test_derivation_B_reproduces_U(N):  # A0.1 (B)
    assert la.max_abs_diff(derive_B_dense(N), dense_U(N)) < THRESHOLD


@pytest.mark.parametrize("N", NS)
def test_A_and_B_agree(N):              # A0.2
    assert la.max_abs_diff(derive_A_dense(N), derive_B_dense(N)) < THRESHOLD


@pytest.mark.parametrize("N", NS)
def test_chebyshev_witness(N):          # independent third check of dense_U
    assert la.max_abs_diff(dense_U_chebyshev(N), dense_U(N)) < THRESHOLD


@pytest.mark.parametrize("N", NS)
def test_A_stages_are_sparse(N):        # butterfly stages have few diagonals
    for s in fft_special_stages(N):
        if s.kind == "diag":
            assert s.num_diagonals() <= 3
