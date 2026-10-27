"""Shared stage representation for the FFT-style factorizations.

A linear map on length-n vectors is written as a product of sparse *stages*. A stage
is either:
  - a permutation (kind='perm', `perm` a length-n list: out[perm[i]] = in[i]), or
  - a sum of generalized diagonals (kind='diag', `diags` = {offset: length-n vector}):
        out[k] = sum_off diags[off][k] * in[(k + off) mod n]

`apply_stages([S1, S2, ...], v)` applies S1 first, then S2, ...  (left-to-right),
matching how a homomorphic-DFT evaluator chains layers. `to_matrix` materializes a
stage so a product of stages can be compared densely to the target.

`materialize_op_as_diag_stage` converts any linear operator (e.g. one iteration of an
FFT butterfly loop) into a diagonal Stage by probing it with unit vectors — so the
stage diagonals are correct *by construction*, and their sparsity is then asserted.
"""
import mpmath


class Stage:
    def __init__(self, n, kind, perm=None, diags=None, label=""):
        self.n = n
        self.kind = kind
        self.perm = perm
        self.diags = diags or {}
        self.label = label

    def apply(self, v):
        n = self.n
        if self.kind == "perm":
            out = [mpmath.mpf(0)] * n
            for i in range(n):
                out[self.perm[i]] = v[i]
            return out
        out = [mpmath.mpc(0)] * n
        for off, d in self.diags.items():
            for k in range(n):
                out[k] = out[k] + d[k] * v[(k + off) % n]
        return out

    def to_matrix(self, complex_=True):
        n = self.n
        M = mpmath.matrix(n, n)
        if self.kind == "perm":
            for i in range(n):
                M[self.perm[i], i] = mpmath.mpf(1)
            return M
        for off, d in self.diags.items():
            for k in range(n):
                M[k, (k + off) % n] = d[k]
        return M

    def num_diagonals(self):
        return 0 if self.kind == "perm" else len(self.diags)


def apply_stages(stages, v):
    for s in stages:
        v = s.apply(v)
    return v


def stages_to_matrix(stages, n, complex_=True):
    """Dense matrix of the whole product (apply order left-to-right)."""
    M = mpmath.eye(n)
    cols = []
    for c in range(n):
        e = [mpmath.mpc(0)] * n
        e[c] = mpmath.mpc(1)
        col = apply_stages(stages, e)
        cols.append(col)
    out = mpmath.matrix(n, n)
    for c in range(n):
        for r in range(n):
            out[r, c] = cols[c][r]
    return out


def materialize_op_as_diag_stage(op, n, label="", tol=None):
    """Probe a linear operator `op(list)->list` with unit vectors, recover its matrix,
    and express it as a diagonal Stage. Returns (Stage, dense_matrix)."""
    if tol is None:
        tol = mpmath.mpf(2) ** -180
    M = mpmath.matrix(n, n)
    for c in range(n):
        e = [mpmath.mpc(0)] * n
        e[c] = mpmath.mpc(1)
        col = op(e)
        for r in range(n):
            M[r, c] = col[r]
    diags = {}
    for off in range(n):
        d = [M[k, (k + off) % n] for k in range(n)]
        if any(abs(x) > tol for x in d):
            diags[off] = d
    return Stage(n, "diag", diags=diags, label=label), M
