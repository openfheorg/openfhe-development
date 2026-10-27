"""Derivation B — an INDEPENDENT fast factorization of the CI decode, plus a Chebyshev
analytic witness. Deliberately shares NO code path with Derivation A (no rotGroup, no
ksiPows, no FFTSpecial) so it is a genuine cross-check (plan risk R3).

Construction. Work with the complex matrix V_N[s][c] = w^{(4s+1)c}, w = exp(2*pi*i/(4N)),
natural slot order. The CI decode is U[s][c] = scale_c * Re(V_N[s][c]) with
scale = (1,2,2,...,2) (no permutation: V uses the natural node 4s+1 directly).

V_N is computed by a radix-2 split on the COEFFICIENT index (even/odd), derived from
scratch:
    z[s]        = Ze[s'] + t_s * Zo[s']
    z[s+N/2]    = Ze[s'] - t_s * Zo[s']           s' = s mod (N/2), s in [0,N/2)
where Ze = V_{N/2} @ y_even, Zo = V_{N/2} @ y_odd, and the twiddle t_s = w^{4s+1}.
Base case N=1: V_1 @ y = y.

Independent witness: 2cos(c*theta) = 2*T_c(cos theta) (Chebyshev-1), cos theta_s = xi_s/2,
giving U[s][c] = scale_c * T_c(xi_s/2) via the T-recurrence — an O(N^2) check with no FFT.
"""
import mpmath

from .ci_embedding import ci_nodes
from .precision import exp_i, pi


def basis_scale(N):
    return [mpmath.mpf(1)] + [mpmath.mpf(2)] * (N - 1)


def _apply_V(y, N, w_base):
    """z = V_N @ y, where V_N[s][c] = exp(2*pi*i*(4s+1)c/(4N)); w_base = exp(2*pi*i/(4N))
    is the 4N-th root for the CURRENT level (halved as N halves)."""
    if N == 1:
        return [y[0]]
    half = N // 2
    y_even = [y[2 * c] for c in range(half)]
    y_odd = [y[2 * c + 1] for c in range(half)]
    # Child root is exp(2*pi*i/(4*half)) = exp(2*pi*i/(2N)) = w_base**2.
    w_child = w_base * w_base
    Ze = _apply_V(y_even, half, w_child)
    Zo = _apply_V(y_odd, half, w_child)
    z = [mpmath.mpc(0)] * N
    for s in range(half):
        t = w_base ** (4 * s + 1)          # w^{4s+1}
        a = Ze[s]
        b = t * Zo[s]
        z[s] = a + b
        z[s + half] = a - b
    return z


def ci_decode_B(coeffs, N):
    """CI decode via Derivation B. Real in, real out."""
    Ds = basis_scale(N)
    y = [Ds[c] * coeffs[c] for c in range(N)]
    w = exp_i(2 * pi() / (4 * N))
    z = _apply_V(y, N, w)
    return [mpmath.re(z[s]) for s in range(N)]


def derive_B_dense(N):
    cols = []
    for c in range(N):
        e = [mpmath.mpf(1) if k == c else mpmath.mpf(0) for k in range(N)]
        cols.append(ci_decode_B(e, N))
    Ucheck = mpmath.matrix(N, N)
    for c in range(N):
        for r in range(N):
            Ucheck[r, c] = cols[c][r]
    return Ucheck


def dense_U_chebyshev(N):
    """Independent analytic witness of dense_U: U[s][c] = scale_c * T_c(xi_s/2)."""
    xi = ci_nodes(N)
    Ds = basis_scale(N)
    U = mpmath.matrix(N, N)
    for s in range(N):
        x = xi[s] / 2  # = cos(theta_s)
        T_prev, T_cur = mpmath.mpf(1), x  # T_0, T_1
        U[s, 0] = Ds[0] * T_prev
        if N > 1:
            U[s, 1] = Ds[1] * T_cur
        for c in range(2, N):
            T_next = 2 * x * T_cur - T_prev
            T_prev, T_cur = T_cur, T_next
            U[s, c] = Ds[c] * T_cur
    return U
