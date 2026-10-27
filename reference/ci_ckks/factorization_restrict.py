"""Derivation A — restriction of OpenFHE's complex special-FFT to the CI subspace.

We mirror OpenFHE `DiscreteFourierTransform::FFTSpecial(cyclOrder=4N)` EXACTLY as a
product of sparse butterfly stages, whose assembled dense matrix is
    W[s][c] = exp(2*pi*i * c * 5^s / (4N))           (slot order = g5 cyclic).
The CI decode is the restriction of W to the conjugation-fixed subspace (conjugation
X->X^{-1} acts as the identity on R), which on the real input is the real part with the
b_0 column un-doubled, followed by reordering g5 -> natural slot order:
    (U @ coeffs)[t] = Re( ( W @ (Dscale @ coeffs) )[ Q[t] ] ),   Q = inverse_perm(P),
    Dscale = diag(1, 2, 2, ..., 2)   (CIBasisScale: const column 1, rest 2).
This reproduces dense_U exactly (verified to <2^-100).
"""
import mpmath

from .ci_embedding import inverse_perm, rot_group, slot_perm_g5
from .precision import exp_i, pi
from .stages_common import Stage, materialize_op_as_diag_stage


def ksi_pow(idx, M):
    return exp_i(2 * pi() * (idx % M) / M)


def _bitreverse_perm(n):
    # OpenFHE BitReverse: out[bitrev(i)] = in[i] over log2(n) bits.
    bits = n.bit_length() - 1
    return [int(format(i, "0{}b".format(bits))[::-1], 2) for i in range(n)]


def fft_special_decode(vals, M):
    """Exact port of OpenFHE FFTSpecial (decode). vals length n (power of two)."""
    n = len(vals)
    v = list(vals)
    # BitReverse
    perm = _bitreverse_perm(n)
    out = [None] * n
    for i in range(n):
        out[perm[i]] = v[i]
    v = out
    rg = rot_group(M // 4)  # rotGroup[j] = 5^j mod M, j=0..M/4-1 (>= n entries)
    length = 2
    while length <= n:
        lenh = length >> 1
        lenq = length << 2
        gap = M // lenq
        i = 0
        while i < n:
            for j in range(lenh):
                idx = (rg[j] % lenq) * gap
                u = v[i + j]
                w = v[i + j + lenh] * ksi_pow(idx, M)
                v[i + j] = u + w
                v[i + j + lenh] = u - w
            i += length
        length <<= 1
    return v


def fft_special_stages(N):
    """FFTSpecial @ M=4N as explicit sparse Stages (bitrev + one stage per len)."""
    M = 4 * N
    stages = [Stage(N, "perm", perm=_bitreverse_perm(N), label="bitrev")]
    rg = rot_group(N)
    length = 2
    while length <= N:
        lenh = length >> 1
        lenq = length << 2
        gap = M // lenq

        def make_op(length=length, lenh=lenh, lenq=lenq, gap=gap):
            def op(vec):
                v = list(vec)
                i = 0
                while i < N:
                    for j in range(lenh):
                        idx = (rg[j] % lenq) * gap
                        u = v[i + j]
                        w = v[i + j + lenh] * ksi_pow(idx, M)
                        v[i + j] = u + w
                        v[i + j + lenh] = u - w
                    i += length
                return v
            return op

        st, _ = materialize_op_as_diag_stage(make_op(), N, label="butterfly_len%d" % length)
        stages.append(st)
        length <<= 1
    return stages


def basis_scale(N):
    """Dscale = diag(1, 2, 2, ..., 2) (CIBasisScale on the coefficient index)."""
    return [mpmath.mpf(1)] + [mpmath.mpf(2)] * (N - 1)


def ci_decode_A(coeffs, N):
    """CI decode (slots = U @ coeffs) via Derivation A. Real in, real out."""
    Q = inverse_perm(slot_perm_g5(N))
    Ds = basis_scale(N)
    y = [Ds[c] * coeffs[c] for c in range(N)]
    z = fft_special_decode(y, 4 * N)            # complex, g5 slot order
    return [mpmath.re(z[Q[t]]) for t in range(N)]  # real, natural slot order


def ci_decode_A_via_stages(coeffs, N):
    """Same, but routed through the materialized Stage objects (validates the stages)."""
    from .stages_common import apply_stages
    Q = inverse_perm(slot_perm_g5(N))
    Ds = basis_scale(N)
    y = [Ds[c] * coeffs[c] for c in range(N)]
    z = apply_stages(fft_special_stages(N), y)
    return [mpmath.re(z[Q[t]]) for t in range(N)]


def derive_A_dense(N):
    """Dense matrix of the Derivation-A CI decode (should equal dense_U)."""
    cols = []
    for c in range(N):
        e = [mpmath.mpf(1) if k == c else mpmath.mpf(0) for k in range(N)]
        cols.append(ci_decode_A(e, N))
    Ucheck = mpmath.matrix(N, N)
    for c in range(N):
        for r in range(N):
            Ucheck[r, c] = cols[c][r]
    return Ucheck
