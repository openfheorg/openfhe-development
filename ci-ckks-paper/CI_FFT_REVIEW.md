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

## 3. Results (ICELAKE: Xeon Platinum 8360Y, single thread unless noted)

Workload: N real values in [-1, 1]. "CI" = one native CI ciphertext with N real slots. "std" = standard
CKKS at the same ring dimension N with N/2 slots, so N real values need **two separate bootstraps**.
Driver: `benchmark/src/ci-fft-boot.cpp`. Times are warm bootstraps (median of 2 after one cold run).

### 3.1 N = 2^16, 128-bit (HEStd_128_classic), FLEXIBLEAUTO, firstMod 60

| Secret, scaleMod | Budget | CI (65,536 reals) | std x2 (65,536 reals) | Speedup | RMS bits CI / std | Max bits CI / std | log2 Q + log2 P | Keys CI / std | Peak RSS CI / std |
|---|---|---|---|---|---|---|---|---|---|
| SPARSE_ENCAPSULATED, 55 | {3,3} | 29.6 s | 2 x 24.9 = 49.7 s | **1.68x** | 18.25 / 18.23 | 14.8 / 15.4 | 1050 + 420 | 79 / 51 | 14.0 / 8.1 GB |
| SPARSE_ENCAPSULATED, 55 | {4,4} | 26.3 s | 2 x 23.0 = 45.9 s | **1.74x** | 18.24 / 18.23 | 15.2 / 15.8 | 1160 + 420 | 70 / 76 | 11.4 / 9.1 GB |
| UNIFORM_TERNARY, 52 | {3,3} | 46.1 s | 2 x 45.5 = 91.0 s | **1.97x** | 7.2 / 9.7 | 4.3 / 7.6 | 1204 + 480 | 77 / 49 | 16.2 / 9.4 GB |

CI stage split at {4,4} (encapsulated): CtS 13.6 s, EvalMod 7.6 s, StC 4.4 s. Budget {5,5} exceeds the
128-bit modulus bound at this scale. The uniform rows are a poor-precision configuration for both
schemes (shown for the cost trend: CI's single EvalMod replaces four).

### 3.2 Before vs after at N = 4096 (insecure toy size, FIXEDMANUAL, uniform, 8 threads, same driver)

| Build | Budget | Warm boot | us / real slot | Max / RMS bits | Galois keys | Peak RSS |
|---|---|---|---|---|---|---|
| `ci-ckks-2026` (v1.5.1) CI | {3,3} | 3.78 s | 922 | 10.5 / 12.9 | 126 | 3.0 GB |
| this branch CI | {3,3} | 0.36 s | 89 | 12.2 / 14.1 | 47 | 0.57 GB |
| v1.5.1 std | {3,3} | 0.53 s (2048 reals) | 261 | 12.3 / 14.2 | 54 | 0.48 GB |
| v1.6.1 std | {3,3} | 0.34 s (2048 reals) | 164 | 12.4 / 14.2 | 52 | 0.47 GB |

The old fork was 3.5x slower than std per real slot; the new path is ~10x faster than the old fork and
1.8x faster than std per real slot. At N = 2^16 the old fork cannot run (dense N x N stage matrices).

### 3.3 Precision findings
- With correct scaling, CI and std have the same RMS precision at N = 2^16 (Table 3.1). Max error is
  0.5-0.6 bit lower for CI (max over twice as many slots plus sqrt(2) noise factors of the real embedding).
- Under FIXEDMANUAL, CI loses ~3 bits from N = 2^13 on: CI primes must be q = 1 mod 4N, so they sit
  twice as far from 2^p and the fixed-scale mismatch shows up one ring size earlier than for std
  (`benchmark/src/ci-noise-probe.cpp`). Use FLEXIBLEAUTO for CI.
- Lower correction factors help both schemes (about 1 bit per step down to the minimum allowed value
  firstMod - scaleMod, measured at 2^15 and 2^16; `PHASE2_LOG.md` item 0.2). The CI default is OpenFHE's fit at
  the complex-equivalent slot count N/2 minus one (7 at 2^16, std 8), which gives CI the RMS of std at defaults.

## 4. Remaining gaps and next steps
1. **CtS is half the CI time.** A collapsed real level has ~2^(k+2) diagonals vs 2^(k+1) for a complex
   level (each real output mixes Re and Im inputs). Options: better butterfly layout, per-level BSGS
   tuning, double hoisting, accumulating giant steps in the extended basis.
2. **Sparse encapsulation precision.** A weight-32 CI key acts like a weight-64 power-basis key, so CI uses
   the K=28 sine table where std uses K=16. A CI-specific K~23 table would recover some bits.
3. **CI ring overhead.** CI NTT is within 1.2x of the standard NTT; CI EvalMod still ~1.2x std per op.
4. **Modulus registry keyed by prime** (pre-existing design): a CI and a std context in one process
   that share a prime would conflict. Key it by (prime, ring) or attach the flag to the params.
5. **First bootstrap builds the diagonals lazily** (~70 s at 2^16); move to EvalBootstrapSetup.
6. **Not done:** the paper's functional bootstrapping (CI-AKP with radial correction, CI-Hermite),
   StC-first ordering, multi-thread tuning.

## 5. Other CI-CKKS work found
Upstream `openfheorg/openfhe-development` main and dev (v1.6.1) have no CI-CKKS. Stale 2023 feature
branches `cickks`, `cickks2`, `cickks2-instrumented*` (Caesar, Andrey Kim; based on v1.1) contain a CI
ring and a dense single-level (`isLTBootstrap`) CI bootstrap only, changing CKKS globally rather than
behind an option.

## 6. Reproduce
Tools in `ci-ckks-paper/tools/` (sync to ICELAKE, tmux-guarded jobs, result table). Example:
`OMP_NUM_THREADS=1 build/bin/benchmark/ci-fft-boot ci 16 4 4 55 60 1 2 fa 0 encap`
(args: scheme logN lbEnc lbDec scaleMod firstMod secure reps scaling corr secret). `CI_BOOT_TIMING=1`
prints the per-level BSGS plan and stage times.

## 7. Review of this work (second pass, 2026-10-27)
Checked against the paper (Sections 3, 4.2, 5.1-5.2) and the code on the branch.

Matches the paper: g=5 slot order, phase compensation, (Re, Im) replacement with the sqrt(2) norm scaling and the
1/sqrt(2) per-layer factor, 2x2 / diagonal / 4x4 butterflies, final 2x2 phase rotation merged into F_l, S with
1/sqrt(N) at coefficient 0 and 1/sqrt(2N) elsewhere, orthogonality used for StC (transposes), level collapsing
in diagonal form, BSGS over the arithmetic progression of each collapsed level, EvalMod on one real ciphertext,
permutation kept between CtS and StC. Per-layer diagonal counts [2, 3, 6, ..., 6, 7] agree with Lemma 4.
Differences that are not defects: our level split assigns remainder layers to the first groups (fewer
diagonals; the paper puts the short product last); any budget is allowed, not only powers of two.

Issues found (all addressed in `PLAN_PHASE2.md`, phase 0 unless noted):
1. `REAL_CI` with `BTSlotsEncoding = true` would run the standard StC-first path on CI data (no guard).
2. The CI correction-factor default change (`cfSlots = N/2`) is harmful and must be reverted. It moves the CI
   default at 2^16 (FLEXIBLEAUTO, CtS-first fit) from 7 to 8; measured with the committed code: CI RMS drops
   from 18.24 to 17.23 bits and min precision from 15.0 to 13.9 (std, which uses 8, is unchanged at 18.24).
   Table 3.1 was produced before this change and stands. Phase 0.2 of the plan reverts it and sweeps the
   correction factor for both schemes. (Done in phase 0.2: reverted; the new CI default is 7 at 2^16.)
3. `GetCIRealLevels` is cached twice (scaled for evaluation, unit-scaled for keygen).
4. The `CISparseMul` drop threshold is absolute; keygen and evaluation must agree on the sparsity pattern.
5. Diagonal plaintexts are built lazily inside a const `EvalBootstrap` (first call 70 s at 2^16; not safe under
   concurrent bootstraps) (phase 2.4).
6. Section 4 item 2 above is mis-stated: CI and std have equal RMS precision; the K = 28 table costs EvalMod
   degree (48 vs 36), it does not cost precision. The fix is a weight-16 CI ephemeral key (phase 3.1).
7. The chain is 1580 bits (P = 420) versus the paper's 1064; this, not the transforms, is the likely main
   reason for the 2x absolute gap to the paper's 12.6 s. Both schemes are affected equally (phase 1).
8. Hygiene: env switches, `std::cerr` and debug globals in library code; `EvalBootstrapKeyMapIndices` not
   CI-aware; a mid-file `#include` in the CI unit tests (phase 6).
Per-stage comparison at N = 2^16 (128-bit, 1 thread, FLEXIBLEAUTO, encapsulated; std via `-DBOOTSTRAPTIMING`,
warm run):

| Budget | Stage | std (32,768 reals) | CI (65,536 reals) | CI / std | CI / std per real |
|---|---|---|---|---|---|
| {4,4} | CtS | 8.26 s | 13.57 s | 1.64 | 0.82 |
| {4,4} | EvalMod (std runs it twice) | 12.02 s | 7.74 s | 0.64 | 0.32 |
| {4,4} | StC | 2.35 s | 4.42 s | 1.88 | 0.94 |
| {3,3} | CtS | 10.13 s | 15.83 s | 1.56 | 0.78 |
| {3,3} | EvalMod | 10.91 s | 7.17 s | 0.66 | 0.33 |
| {3,3} | StC | 3.11 s | 5.44 s | 1.75 | 0.88 |

So the linear transforms cost 1.6-1.9x std's at the same N. The inherent cost of the real factorization is
about 2x the plaintext multiplications and sqrt(2)x the rotations of the complex one, i.e. roughly 1.5-1.7x,
so CtS is close to the inherent bound and StC has ~0.2-0.3x of implementation slack. Per real slot CI is
already cheaper than std in every stage. The CI output ends with one fewer tower but std's output is left at
noise degree 2 (rescale pending), so the usable depth after bootstrapping is the same.

No correctness defect was found in the transform itself: 24/24 CI tests, 1191/1191 CKKS tests, 184/184 core
tests pass, and precision matches std at 2^16.
