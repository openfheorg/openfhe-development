# Native CI-CKKS bootstrapping in OpenFHE: review of the June 2026 fork and the paper-based rework

Branch: `ci-ckks-fft-v1.6.1` (OpenFHE v1.6.1 + reapplied `ci-ckks-2026` + this work).
Paper: Liu, Ma, Wang, Wang, "Efficient (Functional) Bootstrapping for CKKS over the Conjugate-Invariant
Ring", ePrint 2026/2618.

## 1. Where the existing implementation fell short

| # | Issue in `ci-ckks-2026` | Evidence | Effect |
|---|---|---|---|
| 1 | CtS/StC "collapsed" path multiplies OpenFHE's **complex** FFT stages into dense N x N "fat" matrices and evaluates them as **two real channels** (Re, Im) | `CICollapseNatFats`, `twoChannel` | 4 real linear transforms per level after the first; O(N^2) precompute memory (~140-275 GB at N=2^16, per its own report); only valid when the level budget divides log2 N |
| 2 | Default path (budget 1) is a dense BSGS over all N diagonals | `applyCILT` | O(N) plaintext multiplications and N stored diagonals; baby steps always 2^ceil(logN/2) even for sparse levels |
| 3 | CI encode/decode are dense O(N^2) loops with a `cos` per entry | `ckkspackedencoding.cpp` | Diagonal build took ~100 s at N=4096; hours at 2^16 |
| 4 | Twisted CI NTT: generic iterative NTT without Shoup constants, fresh allocations, and a **mutex lock on every** `IsCIModulus` check | `ci-transform.cpp` | ~3x slower than the standard negacyclic NTT; every multiplication/rescale/key switch pays it |
| 5 | FLEXIBLEAUTO unusable: the per-level rescale loop `while (deg > 1) ModReduceInPlace` never ends (ModReduce is a no-op there) | measured hang | Forced FIXEDMANUAL, which costs extra precision for CI because CI primes must be q = 1 mod 4N (twice the spacing of standard primes, so larger scale mismatch) |
| 6 | Only UNIFORM_TERNARY secrets (sparse encapsulation rejected) | explicit throw | Deeper EvalMod (K=648), larger modulus, lower precision |
| 7 | Precision diagnosis attributed the 4-7 bit floor to "intrinsic CI ring geometry" | NATIVE_CI_BOOTSTRAP_REPORT.md | Not intrinsic: with correct scaling CI matches std at small N and is within ~1-2 bits at larger N (Section 3) |
| 8 | (Port to v1.6.1) v1.6 folds the ModRaise overflow bound K into the CtS matrix; the fork assumed v1.5's convention | smoke test: -125 bits | Fixed by folding 1/K into scaleEnc |

## 2. What was changed

**Paper tricks applied (ePrint 2026/2618, Section 3):**
- Real FFT factorization of the CI DFT in the g=5 slot order (`math/ci-realfft`): conjugate-pair
  compensation, (Re, Im) replacement of each pair, the 2x2 / diagonal / 4x4 real butterflies, the final
  phase rotation and the diagonal S. Every factor is real orthogonal with at most 7 cyclic diagonals;
  `S * F_l ... F_1 * V` is a 0/1 permutation (validated in `reference/ci_ckks/real_fft_paper.py` and C++).
- Level collapsing of consecutive factors into the level budget, computed directly in cyclic-diagonal form
  (O(N log N) memory; no dense N x N). StC uses the transposed factors (orthogonality), so no second
  factorization is needed. Any budget works (no `lvlb | log2 N` restriction), and enc/dec budgets may differ.
- Single real channel: one real linear transform per level instead of four.
- BSGS per collapsed level over the actual nonzero-offset window (stride h, circular window [t0, t0+span)),
  hoisted baby steps, ratio n1 ~ 2 sqrt(span); Galois keys generated for exactly these shifts.

**Additional fixes needed to make it work and fast in OpenFHE:**
- v1.6.1 port: 1/K folded into the CI CtS scale (v1.6 moved K into the CtS matrix).
- O(N log N) CI encode/decode via the same real FFT (was dense O(N^2)).
- Twisted CI NTT rebuilt on OpenFHE's optimized negacyclic NTT (psi = wm^2, folded Shoup twists),
  eval vector kept in bit-reversed order (automorphism map adjusted), lock-free modulus registry.
  2.7x faster than the fork's NTT at N=2^16, within 1.2x of the standard NTT.
- FLEXIBLEAUTO support in the CI bootstrap (internal rescale like the std path).
- SPARSE_ENCAPSULATED support: CI-registered sparse-KS primes, switching keys, and the K=28 sine table
  (a weight-h CI key acts like a weight-2h power-basis key).
- Removed the dense two-channel collapse and its env switches.
