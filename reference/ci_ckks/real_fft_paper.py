"""
Oracle for the real FFT factorization of the CI-CKKS DFT (Liu-Ma-Wang-Wang, ePrint 2026/2618, Sec. 3).

Slot order: g=5 cyclic order (position p <-> root zeta_{4N}^{5^p}), which is the order in which a CI
rotation by Galois element 5^k is a cyclic shift by k. V[p][j] = 1 (j=0), 2cos(pi*5^p*j/(2N)) (j>0).

Builds real factors F_1..F_l (l = log2 N) and diagonal S such that  S * F_l ... F_1 * V = Q,
Q a permutation (coefficient j lands at position pos[j]). Every F_i is real orthogonal and has
<= 7 nonzero cyclic diagonals in the g=5 order. Also reports diagonal counts after level collapse.
"""
import numpy as np, sys

def build(N):
    M = 4 * N
    zeta = lambda e: np.exp(2j * np.pi * (e % M) / M)
    p5 = [pow(5, j, M) for j in range(N)]
    # true-unit transforms T_i on the real representation; segments: ('R', r, start, len) / ('P', r, start, len)
    segs = [('R', 0, 0, N)]
    Ts, weights_in = [], None
    m = 1
    while m < N:
        L = N // (2 * m)
        T = np.zeros((N, N))
        new = []
        for (t, r, s, ln) in segs:
            if t == 'R' and r == 0:
                for j in range(L):
                    T[s + j, s + j] += 1; T[s + j, s + L + j] += 1
                    T[s + L + j, s + j] += 1; T[s + L + j, s + L + j] -= 1
                new += [('R', 0, s, L), ('R', m, s + L, L)]
            elif t == 'R':  # r == m/2 -> pair (r) at stage 2m
                for j in range(L):
                    w = zeta(-r * (p5[j + L] - p5[j]))
                    T[s + j, s + j] += 1; T[s + j, s + L + j] += w.real          # Re z_{2m,r}
                    T[s + L + j, s + L + j] += w.imag                            # Im z_{2m,r}
                new += [('P', r, s, L)]
            else:  # pair r, 1 <= r < m/2: Re at [s, s+2L), Im at [s+2L, s+4L)
                for j in range(L):
                    w = zeta(-r * (p5[j + L] - p5[j])); al, be = w.real, w.imag
                    a, b, c, d = s + j, s + L + j, s + 2 * L + j, s + 3 * L + j
                    # z_{2m,r} = (a+ic) + w(b+id)
                    T[s + j, a] += 1; T[s + j, b] += al; T[s + j, d] -= be
                    T[s + L + j, c] += 1; T[s + L + j, b] += be; T[s + L + j, d] += al
                    # z_{2m,m-r} = conj((a+ic) - w(b+id))
                    T[s + 2 * L + j, a] += 1; T[s + 2 * L + j, b] -= al; T[s + 2 * L + j, d] += be
                    T[s + 3 * L + j, c] -= 1; T[s + 3 * L + j, b] += be; T[s + 3 * L + j, d] += al
                new += [('P', r, s, L), ('P', m - r, s + 2 * L, L)]
        Ts.append(T); segs = new; m *= 2
    # final phase removal: coefficient r = Re(zeta^{-r} z_{N,r}) ; pairs give r and N-r
    Ph = np.zeros((N, N)); pos = {}
    for (t, r, s, ln) in segs:
        assert ln == 1
        if t == 'R':
            Ph[s, s] = zeta(-r).real; pos[r] = s
        else:
            th = np.pi * r / (2 * N)
            Ph[s, s] = np.cos(th); Ph[s, s + 1] = np.sin(th)          # coeff r
            Ph[s + 1, s] = np.sin(th); Ph[s + 1, s + 1] = -np.cos(th)  # coeff N-r
            pos[r] = s; pos[N - r] = s + 1
    return Ts, Ph, segs, pos, p5

def orthonormalize(N, Ts, Ph):
    """F_i = D_out T_i D_in^-1 / sqrt2 with D = 1 on real sub-vectors, sqrt2 on pair parts."""
    # recompute the segment types per stage to get D
    Ds = [np.ones(N)]
    segs = [('R', 0, 0, N)]; m = 1
    while m < N:
        L = N // (2 * m); new = []
        for (t, r, s, ln) in segs:
            if t == 'R' and r == 0: new += [('R', 0, s, L), ('R', m, s + L, L)]
            elif t == 'R': new += [('P', r, s, L)]
            else: new += [('P', r, s, L), ('P', m - r, s + 2 * L, L)]
        segs = new; m *= 2
        D = np.ones(N)
        for (t, r, s, ln) in segs:
            if t == 'P': D[s:s + 2 * ln] = np.sqrt(2)
        Ds.append(D)
    Fs = [np.diag(Ds[i + 1]) @ Ts[i] @ np.diag(1 / Ds[i]) / np.sqrt(2) for i in range(len(Ts))]
    # last layer: merge the phase (orthogonal on pair blocks; R(N/2) gets cos(pi/4) -> moved to S)
    PhO = Ph.copy()
    for i in range(N):
        if abs(Ph[i, i]) > 0 and np.count_nonzero(Ph[i]) == 1:
            PhO[i, i] = 1.0
    Fs[-1] = PhO @ Fs[-1]
    return Fs, Ds[-1]

def diag_offsets(A, tol=1e-12):
    N = A.shape[0]
    return sorted({(q - p) % N for p, q in zip(*np.nonzero(np.abs(A) > tol))})

def main(N, budgets=(1, 2, 3, 4)):
    l = int(np.log2(N))
    Ts, Ph, segs, pos, p5 = build(N)
    V = np.array([[1.0 if j == 0 else 2 * np.cos(np.pi * p5[p] * j / (2 * N)) for j in range(N)] for p in range(N)])
    C = Ph @ np.linalg.multi_dot(Ts[::-1]) if l > 1 else Ph @ Ts[0]
    Q = np.zeros((N, N))
    for j in range(N): Q[pos[j], j] = N
    err_true = np.abs(C @ V - Q).max()
    Fs, Dlast = orthonormalize(N, Ts, Ph)
    G = np.linalg.multi_dot(Fs[::-1]) if l > 1 else Fs[0]
    GV = G @ V
    # S: row scale making S*G*V a 0/1 permutation
    S = np.array([1.0 / GV[i, np.argmax(np.abs(GV[i]))] for i in range(N)])
    err_perm = np.abs(np.diag(S) @ GV - Q / N).max()
    orth = max(np.abs(F @ F.T - np.eye(N)).max() for F in Fs)
    print(f"N={N}: true-unit C*V = N*Q err {err_true:.1e} | S*F..F*V = Q err {err_perm:.1e} | max |F F^T - I| {orth:.1e}")
    print(f"   per-layer #diagonals: {[len(diag_offsets(F)) for F in Fs]}")
    print(f"   S distinct values * sqrt(2N): {sorted(set(np.round(S*np.sqrt(2*N), 9)))}")
    for lb in budgets:
        if lb > l: continue
        sizes = [l // lb + (1 if i < l % lb else 0) for i in range(lb)]
        # CtS applies F_1 first; group consecutive factors
        groups, k = [], 0
        for sz in sizes:
            P = np.eye(N)
            for F in Fs[k:k + sz]: P = F @ P
            groups.append(P); k += sz
        cnt = [len(diag_offsets(P)) for P in groups]
        print(f"   levelBudget {lb}: layer split {sizes} -> collapsed #diagonals {cnt}")
    return Fs, S, pos

if __name__ == "__main__":
    for N in [int(a) for a in sys.argv[1:]] or [8, 16, 64, 256]:
        main(N)
