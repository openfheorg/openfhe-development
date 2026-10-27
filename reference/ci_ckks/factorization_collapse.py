"""Level-collapse foundation: an exact RECURSIVE REAL factorization of the CI decode U.

The single-level homomorphic CtS/StC accumulates key-switch noise at one level (the C++
precision bottleneck). The fix is a multi-stage transform with rescaling between stages,
which requires factoring U into sparse REAL stages. Unlike the complex DFT, a real DCT
does not factor into purely-real radix-2 stages without a DST companion -- so the CI
real-DFT factors as a COUPLED DCT/DST recursion (the real-FFT structure). This module
establishes that factorization and validates it to 2^-100; it is the spec the C++
level-collapsed CI real-DFT (g=5 rotation basis, per-stage rescaling) is built on.

Definitions (theta_s = pi(4s+1)/(2N)):
  CI-DCT_N(a)[s] = sum_c U_N[s][c] a[c],  U_N[s][0]=1, U_N[s][c]=2 cos(theta_s c)  (c>=1)
  CI-DST_N(a)[s] = sum_c 2 sin(theta_s c) a[c]
Decimation on c (even c=2c', odd c=2c'+1), using 2cos(2 theta_s c' + theta_s) and
2sin(2 theta_s c' + theta_s) and theta_{s+N/2} = theta_s + pi:
  dct[s]      = E[s] + (cos th_s * C[s] - sin th_s * S[s])
  dct[s+N/2]  = E[s] - (cos th_s * C[s] - sin th_s * S[s])
  dst[s]      = SE[s] + (cos th_s * SO[s] + sin th_s * CO[s])
  dst[s+N/2]  = SE[s] - (cos th_s * SO[s] + sin th_s * CO[s])
where E=CI-DCT(a_even), C=CI-DCT(a_odd), S=CI-DST(a_odd), SE=CI-DST(a_even),
SO=CI-DST(a_odd), CO=CI-DCT(a_odd) at half size. log2(N) real butterfly stages, each a
sum of a few real (cos/sin/+-1) diagonals -- collapsible into lvlb fat stages.
"""
import mpmath

from .precision import cos, pi, sin


def _theta(N, s):
    return pi() * (4 * s + 1) / (2 * N)


def _fc(a, N):
    """FC_N(a)[s] = sum_c 2 cos(theta_s c) a[c]  (uniform factor 2, incl. c=0)."""
    if N == 1:
        return [2 * a[0]]  # 2 cos(0) a[0]
    half = N // 2
    a_even = [a[2 * c] for c in range(half)]
    a_odd = [a[2 * c + 1] for c in range(half)]
    FCe = _fc(a_even, half)
    FCo = _fc(a_odd, half)
    FSo = _fs(a_odd, half)
    x = [mpmath.mpf(0)] * N
    for s in range(half):
        th = _theta(N, s)
        odd = cos(th) * FCo[s] - sin(th) * FSo[s]
        x[s] = FCe[s] + odd
        x[s + half] = FCe[s] - odd
    return x


def _fs(a, N):
    """FS_N(a)[s] = sum_c 2 sin(theta_s c) a[c]."""
    if N == 1:
        return [mpmath.mpf(0)]  # 2 sin(0) a[0] = 0
    half = N // 2
    a_even = [a[2 * c] for c in range(half)]
    a_odd = [a[2 * c + 1] for c in range(half)]
    FSe = _fs(a_even, half)
    FSo = _fs(a_odd, half)
    FCo = _fc(a_odd, half)
    y = [mpmath.mpf(0)] * N
    for s in range(half):
        th = _theta(N, s)
        odd = cos(th) * FSo[s] + sin(th) * FCo[s]
        y[s] = FSe[s] + odd
        y[s + half] = FSe[s] - odd
    return y


def ci_dct(a, N):
    """CI decode x[s] = sum_c U_N[s][c] a[c] = FC_N(a)[s] - a[0] (remove the doubled DC)."""
    fc = _fc(a, N)
    return [fc[s] - a[0] for s in range(N)]


def ci_dst(a, N):
    """CI sine transform y[s] = sum_c 2 sin(theta_s c) a[c] = FS_N(a)[s]."""
    return _fs(a, N)


def ci_dct_dense(N):
    """Dense matrix of the recursive CI-DCT (should equal dense_U)."""
    cols = []
    for c in range(N):
        e = [mpmath.mpf(1) if k == c else mpmath.mpf(0) for k in range(N)]
        cols.append(ci_dct(e, N))
    M = mpmath.matrix(N, N)
    for c in range(N):
        for r in range(N):
            M[r, c] = cols[c][r]
    return M


def count_stages(N):
    """Number of real butterfly stages = log2(N) (radix-2); collapsible into lvlb fat
    stages, each merging log2(N)/lvlb consecutive stages."""
    return N.bit_length() - 1


# ---- Two-fat-stage decomposition for the homomorphic multi-stage port -----------------
# U = (M_fc_out @ M_fc_in + M_fs_out @ M_fs_in) - J, J[s][0]=1, where:
#   stage 1 (M_fc_in, M_fs_in): a -> (FC_inter, FS_inter), the nsub independent size-(N/nsub)
#           FC/FS transforms of the coefficient subvectors (block-sparse);
#   stage 2 (M_fc_out, M_fs_out): (FC_inter, FS_inter) -> FC_N(a) (the combine butterflies).
# Homomorphically: FC_inter=LT(v,M_fc_in); FS_inter=LT(v,M_fs_in); rescale; then
#   out = LT(FC_inter,M_fc_out) + LT(FS_inter,M_fs_out) - DC; rescale. Two rescaled levels.

def _stage1(a, N, nsub):
    target = N // nsub
    fc_inter = [mpmath.mpf(0)] * N
    fs_inter = [mpmath.mpf(0)] * N

    def rec(av, n, offset):
        if n == target:
            fc = _fc(av, n)
            fs = _fs(av, n)
            for p in range(n):
                fc_inter[offset + p] = fc[p]
                fs_inter[offset + p] = fs[p]
            return
        half = n // 2
        rec(av[0::2], half, offset)
        rec(av[1::2], half, offset + half)

    rec(a, N, 0)
    return fc_inter, fs_inter


def _stage2(fc_inter, fs_inter, N, nsub):
    target = N // nsub

    def rec(n, offset):
        if n == target:
            return (list(fc_inter[offset:offset + n]), list(fs_inter[offset:offset + n]))
        half = n // 2
        FCe, FSe = rec(half, offset)
        FCo, FSo = rec(half, offset + half)
        fc = [mpmath.mpf(0)] * n
        fs = [mpmath.mpf(0)] * n
        for s in range(half):
            th = _theta(n, s)
            oddc = cos(th) * FCo[s] - sin(th) * FSo[s]
            fc[s] = FCe[s] + oddc
            fc[s + half] = FCe[s] - oddc
            odds = cos(th) * FSo[s] + sin(th) * FCo[s]
            fs[s] = FSe[s] + odds
            fs[s + half] = FSe[s] - odds
        return fc, fs

    return rec(N, 0)  # (FC_N, FS_N)


def two_stage_matrices(N, nsub):
    """Materialize (M_fc_in, M_fs_in, M_fc_out, M_fs_out) as N x N mpmath matrices."""
    def mat_from(fn, dim_in):
        cols = []
        for c in range(dim_in):
            e = [mpmath.mpf(1) if k == c else mpmath.mpf(0) for k in range(dim_in)]
            cols.append(fn(e))
        M = mpmath.matrix(N, dim_in)
        for c in range(dim_in):
            col = cols[c]
            for r in range(N):
                M[r, c] = col[r]
        return M

    M_fc_in = mat_from(lambda e: _stage1(e, N, nsub)[0], N)
    M_fs_in = mat_from(lambda e: _stage1(e, N, nsub)[1], N)
    M_fc_out = mat_from(lambda e: _stage2(e, [mpmath.mpf(0)] * N, N, nsub)[0], N)
    M_fs_out = mat_from(lambda e: _stage2([mpmath.mpf(0)] * N, e, N, nsub)[0], N)
    return M_fc_in, M_fs_in, M_fc_out, M_fs_out
