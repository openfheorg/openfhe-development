"""D0.5 — build the golden JSON artifacts (decimal strings, >=80 sig-figs) that the
C++ GoogleTests load as fixtures. Builders are shared by tools/gen_golden.py (writes)
and tools/verify_golden.py (recomputes and diffs)."""
import mpmath

from .precision import MP_PREC_BITS, to_decimal_str
from .ci_embedding import (
    bit_reverse_perm, column_norm_sq, dense_U, dense_U_inv_closed, inverse_perm,
    ci_nodes, rot_group, slot_perm_g5,
)
from .factorization_restrict import fft_special_stages
from .bootstrap_oracle import oracle_bootstrap
from .noise_model import predict_encode_decode_rms, predict_evalmod_max_error

GEN_VERSION = "phase0-v1"
GOLDEN_NS = [4, 8, 16]


def _header(N, kind, node_order="natural_4jp1", seed=None):
    return {
        "schema": "ci-ckks/%s/v1" % kind,
        "generator_version": GEN_VERSION,
        "mp_prec_bits": MP_PREC_BITS,
        "N": N, "m": 4 * N,
        "node_order": node_order,
        "rng_seed": seed,
    }


def _mat(M):
    return [[to_decimal_str(M[r, c]) for c in range(M.cols)] for r in range(M.rows)]


def build_dense_U(N):
    obj = _header(N, "dense_u")
    obj["U"] = _mat(dense_U(N))
    obj["U_inv"] = _mat(dense_U_inv_closed(N))
    obj["nodes"] = [to_decimal_str(x) for x in ci_nodes(N)]
    obj["column_norm_sq"] = [to_decimal_str(x) for x in column_norm_sq(N)]
    return obj


def build_slot_order(N):
    obj = _header(N, "slot_order")
    P = slot_perm_g5(N)
    Q = bit_reverse_perm(N)
    obj.update({
        "rot_group": rot_group(N),
        "P": P, "P_inv": inverse_perm(P),
        "Q_bitreverse": Q, "Q_inv": inverse_perm(Q),
    })
    return obj


def build_stages(N):
    obj = _header(N, "stages", node_order="g5_cyclic")
    obj["note"] = ("Complex FFTSpecial@4N butterfly stages (Derivation A). CI real "
                   "decode = restrict: out[t] = Re((W @ (Dscale @ coeffs))[Q[t]]), "
                   "Dscale=diag(1,2,..,2), Q=inverse_perm(P).")
    obj["basis_scale"] = [to_decimal_str(mpmath.mpf(1) if i == 0 else mpmath.mpf(2))
                          for i in range(N)]
    obj["restrict_perm_Q"] = inverse_perm(slot_perm_g5(N))
    stages = []
    for s in fft_special_stages(N):
        if s.kind == "perm":
            stages.append({"kind": "perm", "label": s.label, "perm": s.perm})
        else:
            stages.append({
                "kind": "diag", "label": s.label,
                "offsets": sorted(s.diags.keys()),
                "diagonals": {str(off): [to_decimal_str(x) for x in s.diags[off]]
                              for off in sorted(s.diags.keys())},
            })
    obj["stages"] = stages
    return obj


def build_oracle_vectors(N, seed=20260614):
    Delta = mpmath.mpf(2) ** 40
    q0 = mpmath.mpf(2) ** 55
    rng = mpmath.mp
    msg = [mpmath.mpf(1) / 1000 * mpmath.cos(mpmath.mpf(3 * (i + 1))) for i in range(N)]
    tr = oracle_bootstrap(N, msg, q0, Delta, K=3, seed=seed, arcsine=True)
    obj = _header(N, "oracle_vectors", seed=seed)
    obj.update({
        "Delta": to_decimal_str(Delta), "q0": to_decimal_str(q0), "K": 3, "arcsine": True,
        "msg": [to_decimal_str(x) for x in msg],
        "coeffs": [to_decimal_str(x) for x in tr["coeffs"]],
        "I": tr["I"],
        "raised": [to_decimal_str(x) for x in tr["raised"]],
        "after_cts": [to_decimal_str(x) for x in tr["after_cts"]],
        "after_evalmod": [to_decimal_str(x) for x in tr["after_evalmod"]],
        "after_stc": [to_decimal_str(x) for x in tr["after_stc"]],
        "out": [to_decimal_str(x) for x in tr["out"]],
    })
    return obj


def build_noise_prediction(N):
    Delta = mpmath.mpf(2) ** 40
    q0 = mpmath.mpf(2) ** 55
    bound = q0 / mpmath.mpf(2) ** 16
    obj = _header(N, "noise_prediction")
    obj.update({
        "Delta": to_decimal_str(Delta), "q0": to_decimal_str(q0),
        "encode_decode_rms": to_decimal_str(predict_encode_decode_rms(N, Delta)),
        "evalmod_max_error_no_arcsine": to_decimal_str(predict_evalmod_max_error(q0, bound, False)),
        "evalmod_max_error_arcsine": to_decimal_str(predict_evalmod_max_error(q0, bound, True)),
    })
    return obj


def build_all():
    out = {}
    for N in GOLDEN_NS:
        out["ci_dense_U_N%d.json" % N] = build_dense_U(N)
        out["ci_slot_order_N%d.json" % N] = build_slot_order(N)
        out["ci_stages_N%d.json" % N] = build_stages(N)
        out["ci_oracle_vectors_N%d.json" % N] = build_oracle_vectors(N)
        out["ci_noise_prediction_N%d.json" % N] = build_noise_prediction(N)
    return out
