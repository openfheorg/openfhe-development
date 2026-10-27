"""g=5-rotation-ALIGNED collapsed FFT for the native CI bootstrap (the genuine fix).

This is the executable spec for the C++ `CoeffEncodingCollapseCI` / `CoeffDecodingCollapseCI`.
Unlike `factorization_collapse.py` (which decimates on the *coefficient* index -> stages that
are block-sparse in the STRIDE basis but DENSE under the g=5 rotation the homomorphic evaluator
runs in), this module reuses OpenFHE's exact complex `CoeffEncodingCollapse` structure, whose
per-level diagonals are sparse UNDER g=5 by construction (that is what makes the standard
hoisted-BSGS evaluator work). The CI decode is the REAL restriction of that complex special-FFT
(Derivation A, `factorization_restrict.py`); since a real DCT does not factor into real
single-channel radix-2 stages, the homomorphic transform is run as a TWO-CHANNEL (FC=Re, FS=Im)
computation through the same complex g=5-sparse stages.

Slot bases:
  - g5 order: slot k holds the value at node 5^k mod 4N (what CoeffEncodingCollapse uses).
  - natural order: slot t holds the value at node xi_t = 2cos(pi(4t+1)/2N) (what the CI ring's
    decode/applyCILT use). P = slot_perm_g5: g5 position k -> natural index t.

The C++ feeds applyCILT a per-level stage matrix in NATURAL basis (real & imag parts separately);
applyCILT's zero-skip then realizes the g5-sparsity automatically.
"""
import mpmath

from .ci_embedding import dense_U, dense_U_inv_closed, inverse_perm, rot_group, slot_perm_g5
from .precision import exp_i, pi


def ksi_pows(M):
    """pows[j] = exp(2 pi i j / M), j = 0..M (pows[M] == pows[0])."""
    return [exp_i(2 * pi() * j / M) for j in range(M + 1)]


def _select_layers(log_slots, level_budget):
    """Port of SelectLayers (ckksrns-utils.cpp:55-78): returns (layersCollapse, rowsCollapse,
    remCollapse)."""
    layers = -(-log_slots // level_budget)          # ceil
    rows = log_slots // layers
    rem = log_slots - rows * layers
    # OpenFHE folds the remainder into an extra collapsed row when rem != 0.
    return layers, rows, rem


def reduce_rotation(index, slots):
    return (slots + (index % slots)) % slots


def coeff_encoding_one_level(pows, rot_grp, flag_i):
    """Exact port of CoeffEncodingOneLevel (ckksrns-utils.cpp:437-477)."""
    I = mpmath.mpc(0, 1)
    neg_exp = mpmath.e ** (-pi() / 2 * I)
    dim = len(pows) - 1
    slots = len(rot_grp)
    log2slots = slots.bit_length() - 1
    coeff = [[mpmath.mpc(0)] * slots for _ in range(3 * log2slots)]
    m = slots
    while m > 1:
        s = (m.bit_length() - 1) - 1
        coeff0 = coeff[s]
        coeff1 = coeff[s + log2slots]
        coeff2 = coeff[s + 2 * log2slots]
        b = neg_exp if (flag_i and m == 2) else mpmath.mpc(1)
        k = 0
        while k < slots:
            lenq = m << 2
            lenh = m >> 1
            klenh = k + lenh
            for x in range(k, klenh):
                coeff2[x] = b
                coeff1[x] = b
            for j in range(lenh):
                w = b * pows[(lenq - (rot_grp[j] % lenq)) * (dim // lenq)]
                coeff1[klenh + j] = -w
                coeff0[klenh + j] = w
            k += m
        m >>= 1
    return coeff


def coeff_decoding_one_level(pows, rot_grp, flag_i):
    """Exact port of CoeffDecodingOneLevel (ckksrns-utils.cpp:479-519)."""
    I = mpmath.mpc(0, 1)
    pos_exp = mpmath.e ** (pi() / 2 * I)
    dim = len(pows) - 1
    slots = len(rot_grp)
    log2slots = slots.bit_length() - 1
    coeff = [[mpmath.mpc(0)] * slots for _ in range(3 * log2slots)]
    m = 2
    while m <= slots:
        s = (m.bit_length() - 1) - 1
        coeff0 = coeff[s]
        coeff1 = coeff[s + log2slots]
        coeff2 = coeff[s + 2 * log2slots]
        b = pos_exp if (flag_i and m == 2) else mpmath.mpc(1)
        k = 0
        while k < slots:
            lenq = m << 2
            lenh = m >> 1
            klenh = k + lenh
            for x in range(klenh, klenh + lenh):
                coeff0[x] = b
            for x in range(k, klenh):
                coeff1[x] = b
            for j in range(lenh):
                w = b * pows[(rot_grp[j] % lenq) * (dim // lenq)]
                coeff2[k + j] = w
                coeff1[k + j + lenh] = -w
            k += m
        m <<= 1
    return coeff


def _collapse(coeff1, slots, level_budget, log2slots, encoding):
    """Common collapse merge (ports CoeffEncodingCollapse:557-611 / CoeffDecodingCollapse).
    Returns coeff[s][u][k] (g5 order)."""
    layers, rows, rem = _select_layers(log2slots, level_budget)
    dim_collapse = level_budget
    flag_rem = 0 if rem == 0 else 1
    num_rot = (1 << (layers + 1)) - 1
    num_rot_rem = (1 << (rem + 1)) - 1

    coeff = [[[mpmath.mpc(0)] * slots for _ in range(num_rot)] for _ in range(dim_collapse)]
    if flag_rem:
        idx = 0 if encoding else dim_collapse - 1
        coeff[idx] = [[mpmath.mpc(0)] * slots for _ in range(num_rot_rem)]

    def merge_block(s, top, n_layers, nr):
        coeff[s][0] = list(coeff1[top])
        coeff[s][1] = list(coeff1[top + log2slots])
        coeff[s][2] = list(coeff1[top + 2 * log2slots])
        for l in range(1, n_layers):
            temp = coeff[s]
            coeff[s] = [[mpmath.mpc(0)] * slots for _ in range(nr)]
            shift = 1 << (top - l)
            for u in range((1 << (l + 1)) - 1):
                c_r = coeff1[top - l]
                c_n = coeff1[top - l + log2slots]
                c_l = coeff1[top - l + 2 * log2slots]
                for k in range(slots):
                    coeff[s][2 * u][k] += c_r[k] * temp[u][reduce_rotation(k - shift, slots)]
                    coeff[s][2 * u + 1][k] += c_n[k] * temp[u][k]
                    coeff[s][2 * u + 2][k] += c_l[k] * temp[u][reduce_rotation(k + shift, slots)]

    if encoding:
        if layers:
            for s in range(dim_collapse - 1, flag_rem - 1, -1):
                top = log2slots - (dim_collapse - 1 - s) * layers - 1
                merge_block(s, top, layers, num_rot)
        if flag_rem and rem:
            top = log2slots - (dim_collapse - 1) * layers - 1  # s = 0
            merge_block(0, top, rem, num_rot_rem)
    else:
        if layers:
            smax = dim_collapse - flag_rem
            for s in range(0, smax):
                top = s * layers + (rem if flag_rem else 0)
                merge_block(s, top + layers - 1, layers, num_rot)
        if flag_rem and rem:
            merge_block(dim_collapse - 1, rem - 1, rem, num_rot_rem)
    return coeff


def coeff_encoding_collapse(pows, rot_grp, level_budget):
    slots = len(rot_grp)
    log2slots = slots.bit_length() - 1
    coeff1 = coeff_encoding_one_level(pows, rot_grp, False)
    return _collapse(coeff1, slots, level_budget, log2slots, encoding=True)


def coeff_decoding_collapse(pows, rot_grp, level_budget):
    slots = len(rot_grp)
    log2slots = slots.bit_length() - 1
    coeff1 = coeff_decoding_one_level(pows, rot_grp, False)
    return _collapse(coeff1, slots, level_budget, log2slots, encoding=False)


# ---- stage matrices (g5 basis) from the collapse, using the evaluator's offset/scale ----

def _params(slots, level_budget):
    log2slots = slots.bit_length() - 1
    layers, rows, rem = _select_layers(log2slots, level_budget)
    num_rot = (1 << (layers + 1)) - 1
    num_rot_rem = (1 << (rem + 1)) - 1
    return layers, rem, num_rot, num_rot_rem


def stage_matrices_g5(coeff, slots, level_budget, encoding):
    """Build per-level dense stage matrices S_s in g5-slot basis, applying the evaluator's
    rotation offsets (EvalCoeffsToSlots:2273-2288): diagonal ij at level s carries cyclic
    offset scale*(ij - offset)."""
    layers, rem, num_rot, num_rot_rem = _params(slots, level_budget)
    flag_rem = 0 if rem == 0 else 1
    mats = []  # in APPLY order (first applied first)
    # encoding evaluator applies s = lvlb-1 .. stop(=0 if rem else loop to >stop); we build a
    # flat apply-ordered list of (s, scale, num_rotations_for_level).
    order = []
    if encoding:
        stop = 0 if flag_rem else -1
        for s in range(level_budget - 1, stop, -1):
            scale = 1 << ((s - flag_rem) * layers + rem)
            order.append((s, scale, num_rot))
        if flag_rem:
            order.append((0, 1, num_rot_rem))
    else:
        smax = level_budget - flag_rem
        for s in range(0, smax):
            scale = 1 << (s * layers)
            order.append((s, scale, num_rot))
        if flag_rem:
            order.append((level_budget - 1, 1 << (smax * layers), num_rot_rem))

    for (s, scale, nr) in order:
        offset = (nr + 1) // 2 - 1
        M = mpmath.matrix(slots, slots)
        for ij in range(nr):
            off = (scale * (ij - offset))
            for a in range(slots):
                b = reduce_rotation(a + off, slots)
                M[a, b] += coeff[s][ij][a]
        mats.append(M)
    return mats


def _apply_mat(M, v):
    n = M.rows
    out = [mpmath.mpc(0)] * n
    for a in range(n):
        acc = mpmath.mpc(0)
        for b in range(n):
            acc += M[a, b] * v[b]
        out[a] = acc
    return out


def product_g5(mats):
    """Dense matrix of the whole product, apply order (mats[0] first)."""
    n = mats[0].rows
    cols = []
    for c in range(n):
        e = [mpmath.mpc(1) if k == c else mpmath.mpc(0) for k in range(n)]
        for M in mats:
            e = _apply_mat(M, e)
        cols.append(e)
    out = mpmath.matrix(n, n)
    for c in range(n):
        for r in range(n):
            out[r, c] = cols[c][r]
    return out


def to_natural_basis(Mg5, N):
    """Conjugate a g5-basis matrix to natural CI slot basis: S_nat = Pm * Mg5 * Pm^T,
    where Pm maps g5 position k -> natural index P[k]."""
    P = slot_perm_g5(N)
    S = mpmath.matrix(N, N)
    for k in range(N):
        for l in range(N):
            S[P[k], P[l]] = Mg5[k, l]
    return S


# ---- high-level API: the validated g5-sparse collapsed CI real-DFT spec ------------------

def decoding_fat_levels_g5(N, level_budget):
    """lb g5-basis fat-stage matrices (apply order, fat 0 applied first), formed by composing
    layersCollapse=log2(N)/lb consecutive single-layer g5-sparse stages. Requires
    level_budget | log2(N) (no remainder). Each fat level is sparse under the g=5 cyclic
    rotation -- count_g5_diagonals returns <= numRotations = 2^(layersCollapse+1)-1."""
    log2 = N.bit_length() - 1
    if log2 % level_budget != 0:
        raise ValueError("level_budget must divide log2(N) (no-remainder collapse)")
    layers = log2 // level_budget
    raw = stage_matrices_g5(coeff_decoding_collapse(ksi_pows(4 * N), rot_group(N), log2),
                            N, log2, encoding=False)
    fats = []
    for s in range(level_budget):
        grp = raw[s * layers:(s + 1) * layers]
        M = grp[0]
        for g in grp[1:]:
            M = g * M          # grp[0] applied first -> later stages multiply on the left
        fats.append(M)
    return fats, layers


def count_g5_diagonals(M, tol=None):
    """Number of nonzero generalized diagonals of M under the cyclic (g=5) rotation."""
    if tol is None:
        tol = mpmath.mpf(2) ** -100
    n = M.rows
    cnt = 0
    for off in range(n):
        if any(abs(M[a, (a + off) % n]) > tol for a in range(n)):
            cnt += 1
    return cnt


def reconstruct_U_from_fats(fats, N):
    """U[t][c] = Dscale[c] * Re( prod_g5[Q[t]][br[c]] ), prod = compose(fats). Validated == dense_U."""
    prod = fats[0]
    for f in fats[1:]:
        prod = f * prod
    Q = inverse_perm(slot_perm_g5(N))
    br = _bitrev(N)
    Dsc = [mpmath.mpf(1)] + [mpmath.mpf(2)] * (N - 1)
    U = mpmath.matrix(N, N)
    for t in range(N):
        for c in range(N):
            U[t, c] = Dsc[c] * mpmath.re(prod[Q[t], br[c]])
    return U


def _bitrev(N):
    bits = N.bit_length() - 1
    return [int(format(i, "0{}b".format(bits))[::-1], 2) for i in range(N)]
