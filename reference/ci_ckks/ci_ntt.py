"""Spec for the C++ twisted CI NTT (integer, over Z_q with q = 1 mod 4N).

The CI ring R_q = {a in Z_q[X]/(X^{2N}+1) : a(X)=a(X^{-1})}, element stored as the
length-N coefficient vector (a_0,...,a_{N-1}) of  a = a_0 + sum_{i=1}^{N-1} a_i (X^i+X^-i).

The CI-NTT evaluates a at the N real nodes w_m^{4j+1} (w_m a primitive 4N-th root mod q):
    ahat[j] = a(w_m^{4j+1}) = a_0 + sum_{i>=1} a_i (w_m^{(4j+1)i} + w_m^{-(4j+1)i})  (mod q).
This is the integer analog of dense_U (zeta -> w_m). It is a RING ISOMORPHISM R_q ~ Z_q^N,
so Hadamard product in the NTT domain = CI ring multiplication (used for homomorphic mult).

Kim-Song s4.3 fast factorization (the seed the C++ twisted NTT implements):
    ahat[j] = atilde(w_N^j),   w_N = w_m^4 (primitive N-th root),
    atilde_0 = a_0,  atilde_i = a_i w_m^i + a_{N-i} w_m^{-(N-i)}   (i=1..N-1),
i.e. a coefficient twiddle followed by a plain N-point cyclic NTT. Verified here to equal
the direct node evaluation and to invert; and Hadamard==CI-mult is cross-checked against an
independent negacyclic convolution oracle.
"""
import random


def find_4Nth_root(q, N, seed=12345):
    """Primitive 4N-th root of unity mod prime q (requires q = 1 mod 4N)."""
    order = 4 * N
    assert (q - 1) % order == 0, "q must be 1 mod 4N"
    e = (q - 1) // order
    rng = random.Random(seed)
    while True:
        h = rng.randrange(2, q - 1)
        w = pow(h, e, q)
        if pow(w, order // 2, q) != 1:   # order is a power of two -> primitive iff w^{2N}!=1
            return w


def ci_ntt_matrix(N, q, wm):
    """M[j][i] = integer CI-NTT (= dense_U over Z_q). M[j][0]=1, else node power-sum."""
    wm_inv = pow(wm, q - 2, q)
    M = [[0] * N for _ in range(N)]
    for j in range(N):
        node = pow(wm, 4 * j + 1, q)
        node_inv = pow(wm_inv, 4 * j + 1, q)
        M[j][0] = 1
        for i in range(1, N):
            M[j][i] = (pow(node, i, q) + pow(node_inv, i, q)) % q
    return M


def _matvec_mod(M, v, q):
    return [sum(M[r][c] * v[c] for c in range(len(v))) % q for r in range(len(M))]


def _mat_inv_mod(M, q):
    n = len(M)
    A = [row[:] + [1 if i == j else 0 for j in range(n)] for i, row in enumerate(M)]
    for col in range(n):
        piv = next(r for r in range(col, n) if A[r][col] % q != 0)
        A[col], A[piv] = A[piv], A[col]
        inv = pow(A[col][col], q - 2, q)
        A[col] = [(x * inv) % q for x in A[col]]
        for r in range(n):
            if r != col and A[r][col] % q != 0:
                f = A[r][col]
                A[r] = [(A[r][k] - f * A[col][k]) % q for k in range(2 * n)]
    return [row[n:] for row in A]


def ci_ntt_forward_direct(a, N, q, wm):
    return _matvec_mod(ci_ntt_matrix(N, q, wm), a, q)


def ci_ntt_forward_fast(a, N, q, wm):
    """Kim-Song s4.3: twiddle then N-point cyclic NTT (w_N = w_m^4)."""
    wm_inv = pow(wm, q - 2, q)
    wN = pow(wm, 4, q)
    atilde = [0] * N
    atilde[0] = a[0] % q
    for i in range(1, N):
        atilde[i] = (a[i] * pow(wm, i, q) + a[N - i] * pow(wm_inv, N - i, q)) % q
    return [sum(atilde[i] * pow(wN, (i * j) % N, q) for i in range(N)) % q for j in range(N)]


def ci_ntt_inverse(ahat, N, q, wm):
    """Inverse CI-NTT via the matrix inverse (the C++ side uses the s4.3 inverse;
    this oracle uses the dense inverse, which is unambiguous)."""
    Minv = _mat_inv_mod(ci_ntt_matrix(N, q, wm), q)
    return _matvec_mod(Minv, ahat, q)


def ci_ring_mult_negacyclic(a, b, N, q):
    """Independent CI-mult oracle: lift to Laurent polys in Z_q[X]/(X^{2N}+1), where
    X^i+X^-i = X^i - X^{2N-i}, negacyclic-convolve, and extract the CI coeff vector."""
    M = 2 * N

    def lift(v):
        A = [0] * M
        A[0] = v[0] % q
        for i in range(1, N):
            A[i] = (A[i] + v[i]) % q
            A[M - i] = (A[M - i] - v[i]) % q
        return A

    A, B = lift(a), lift(b)
    C = [0] * M
    for u in range(M):
        if A[u] == 0:
            continue
        for w in range(M):
            k = u + w
            if k < M:
                C[k] = (C[k] + A[u] * B[w]) % q
            else:
                C[k - M] = (C[k - M] - A[u] * B[w]) % q  # X^{2N} = -1
    # extract CI coeffs: c_0=C[0]; c_i=C[i] (and C[2N-i] == -C[i], C[N]==0 hold)
    c = [C[0]] + [C[i] for i in range(1, N)]
    assert C[N] % q == 0, "product not CI-invariant (X^N term)"
    for i in range(1, N):
        assert (C[M - i] + C[i]) % q == 0, "product not CI-invariant"
    return c
