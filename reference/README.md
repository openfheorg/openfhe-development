# `reference/` — Phase-0 cleartext oracle (library-agnostic)

The high-precision (mpmath, 256-bit) source of truth for native conjugate-invariant
(real) CKKS bootstrapping. Everything in the C++ phases is verified against the golden
artifacts emitted here. See `../.task` for the full plan and `§4` of it for the math
contract.

**IRON RULE:** no `numpy`/`scipy` in the math path — float64 (53-bit) would silently
break the `2^-100` correctness contract. Only `mpmath` + the standard library.

## Layout
```
ci_ckks/                package (importable in CPython and `sage -python`)
  precision.py          256-bit context, shared constructors, JSON (de)serialization
  linalg_mp.py          mpmath matrix ops (matmul, inv, op-norm, max_abs_diff)
  ci_embedding.py       D0.1: dense_U, nodes, rot_group(g=5), slot perm P, basis norms
  stages_common.py      Stage type + ApplyStages engine          (Phase-0 C1)
  collapse.py           CCS19/Bossuat level-collapse              (Phase-0 C1)
  factorization_restrict.py  Derivation A (restrict complex FFTSpecial@4N)  (C1)
  factorization_dct.py       Derivation B (independent fast-DCT)            (C1)
  noise_model.py        D0.4: Kim-Song App.A variance predictor  (Phase-0 C1)
  bootstrap_oracle.py   D0.4: ModRaise->CtS->EvalMod->StC oracle  (Phase-0 C1)
golden/                 D0.5: emitted JSON (decimal strings, >=80 sig-figs)
tools/                  gen_golden.py / verify_golden.py
tests/                  pytest: A0.1-A0.4
```

## Run
```bash
cd reference
python3 -m pip install -r requirements.txt
python3 -m pytest -q                 # A0.* acceptance
python3 tools/verify_golden.py --check   # golden drift gate (no file writes)
```

## Acceptance (plan §7)
- **A0.1** `max|ApplyStages(A) - dense_U| < 2^-100` and same for B.
- **A0.2** `max|ApplyStages(A) - ApplyStages(B)| < 2^-100` (two independent derivations agree).
- **A0.3** `U U^{-1}=I` and encode/decode round-trip `< 2^-100`; basis asymmetry guarded. *(passing)*
- **A0.4** oracle dense-vs-factorization agree `< 2^-100`; predicted precision matches a
  textbook leveled-CKKS case within 0.5 bit.

## Conventions pinned for the C++ side
- Slot orderings recorded three ways with inverses: natural `4j+1`, g5-cyclic `5^k`,
  OpenFHE `bitrev∘g5`. Derivation A relationship: **U(natural) = 2·Re(W@4N) with
  column-0 halved, rows permuted by P**, where `W[s][c]=exp(2πi·c·5^s/4N)` is what
  OpenFHE `FFTSpecial(cyclOrder=4N)` computes.
- Diagonals keyed by signed rotation offset under g=5; apply semantics
  `out[k] = Σ_off diag[off][k] · in[(k+off) mod N]`.
