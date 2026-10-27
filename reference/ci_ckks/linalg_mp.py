"""Minimal high-precision linear algebra over mpmath matrices (no numpy)."""
import mpmath


def zeros(n, m=None):
    return mpmath.matrix(n, n if m is None else m)


def eye(n):
    return mpmath.eye(n)


def matmul(A, B):
    return A * B


def matvec(A, v):
    """A (mpmath.matrix n x m) times v (list/column) -> list of length n."""
    n, m = A.rows, A.cols
    out = [mpmath.mpf(0)] * n
    for i in range(n):
        acc = mpmath.mpf(0)
        for j in range(m):
            acc = acc + A[i, j] * v[j]
        out[i] = acc
    return out


def conj_transpose(A):
    n, m = A.rows, A.cols
    C = mpmath.matrix(m, n)
    for i in range(n):
        for j in range(m):
            C[j, i] = mpmath.conj(A[i, j])
    return C


def transpose(A):
    n, m = A.rows, A.cols
    C = mpmath.matrix(m, n)
    for i in range(n):
        for j in range(m):
            C[j, i] = A[i, j]
    return C


def inv(A):
    """General inverse via mpmath LU solve, column by column. Works for real/complex."""
    n = A.rows
    Ainv = mpmath.matrix(n, n)
    for k in range(n):
        b = mpmath.matrix(n, 1)
        b[k, 0] = mpmath.mpf(1)
        x = mpmath.lu_solve(A, b)
        for i in range(n):
            Ainv[i, k] = x[i]
    return Ainv


def max_abs_diff(A, B):
    """max_{i,j} |A[i,j] - B[i,j]|. Robust, dimension-independent bug detector:
    <= the operator 2-norm, and any real bug produces O(1) entries."""
    n, m = A.rows, A.cols
    worst = mpmath.mpf(0)
    for i in range(n):
        for j in range(m):
            d = abs(A[i, j] - B[i, j])
            if d > worst:
                worst = d
    return worst


def max_abs_vec(u, v):
    worst = mpmath.mpf(0)
    for a, b in zip(u, v):
        d = abs(a - b)
        if d > worst:
            worst = d
    return worst


def op_norm_2(M):
    """Spectral norm = sqrt(max eigenvalue of M^H M). For reporting; the gating
    assertions use max_abs_diff (stricter per-entry, no eig fragility)."""
    MhM = conj_transpose(M) * M
    # Hermitianize to kill roundoff asymmetry before the symmetric eig solver.
    n = MhM.rows
    H = mpmath.matrix(n, n)
    for i in range(n):
        for j in range(n):
            H[i, j] = (MhM[i, j] + mpmath.conj(MhM[j, i])) / 2
    try:
        evals = mpmath.eigsy(H, eigvals_only=True) if _is_real(H) else mpmath.eighe(H, eigvals_only=True)
        return mpmath.sqrt(max(abs(e) for e in evals))
    except Exception:
        # Power iteration fallback on M^H M.
        v = mpmath.matrix([mpmath.mpf(1)] * n)
        for _ in range(200):
            w = H * v
            nrm = mpmath.sqrt(sum(abs(x) ** 2 for x in w))
            if nrm == 0:
                return mpmath.mpf(0)
            v = w / nrm
        return mpmath.sqrt(abs((conj_transpose(v) * (H * v))[0, 0]))


def _is_real(M):
    for i in range(M.rows):
        for j in range(M.cols):
            if abs(mpmath.im(M[i, j])) > mpmath.mpf(2) ** -200:
                return False
    return True
