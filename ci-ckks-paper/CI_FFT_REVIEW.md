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
  hoisted baby steps, n1 chosen per level by a cost model (exact baby/giant counts, giant = 5.2-5.8 babies by
  key-switching digit count; item 2.2); Galois keys generated for exactly these shifts.

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
  firstMod - scaleMod, measured at 2^15 and 2^16; `PHASE2_LOG.md` item 0.2).
- (Phase 3.R, WSL.) The per-op noise of CI at N equals std's at 2N (fresh, mult, rotate, double angle: within 0.1
  bit; std at the same N is 1.0 bit better), so CI has no ring-noise penalty at an equal real count, the paper's
  comparison. The K = 28 sine table costs no precision (K = 16/28 swap: RMS within 0.02 bits). Gap to the paper's
  20.55 bits (StC-first, max error): CI 2^16 19.69-19.85, i.e. about 0.4 bits CI-specific (source open) plus about
  0.3-0.45 bits of OpenFHE-vs-Lattigo design shared with std; CtS-first loses another 1.2-1.6 bits; META-BTS
  closes it (37 bits). See `PHASE2_LOG.md` 3.R. The CI default is OpenFHE's fit at
  the complex-equivalent slot count N/2 minus one (7 at 2^16, std 8), which gives CI the RMS of std at defaults.

## 4. Remaining gaps and next steps
1. **CtS is half the CI time.** A collapsed real level has ~2^(k+2) diagonals vs 2^(k+1) for a complex
   level (each real output mixes Re and Im inputs). Options: better butterfly layout, per-level BSGS
   tuning, double hoisting, accumulating giant steps in the extended basis.
   (Phase 2.1: per-level op counts added (`CI_BOOT_TIMING=1`, `[LT]` lines for CI and std). Two excess giant-step
   costs were fixed: the CI giant step now ModDowns only element 1 in the extended basis, as std's Horner step,
   and the BSGS window is aligned so the block at offset 0 needs no rotation. CI {4,3} 25.98 -> 23.75 s; at {4,4}
   CI CtS / StC went from 1.67x / 1.89x std's to 1.42x / 1.59x. Plaintext mults equal the diagonal count; the rest
   of the gap is the 1.88x diagonal count and 10 vs 4 giant steps per transform. See `PHASE2_LOG.md` 2.1.)
   (Phase 2.2: n1 per level now minimizes babies + rho(D) giants by exact counts after window alignment, rho =
   5.2-5.8 from the measured per-op costs. The 30-31-diagonal levels of CtS budget 5 drop from 3 giants to 1:
   CI {5,3} 23.6 -> 22.34 s, now CI's best budget (same as std's); CI/2xstd 1.96x, CtS / StC 1.42x / 1.53x std's
   at {5,3}. Budget-4 plans were already optimal. See `PHASE2_LOG.md` 2.2.)
   (Phase 2.3: the layer split per level now comes from a model search (diagonals x towers, 2.2 BSGS plans) instead
   of the even split. The first k layers have 2^k diagonals, a k-layer range further in about 2^(k+2), so the best
   splits are uneven. At 2^16 StC lb 3 is [7,5,4] (was [6,5,5]): CI {5,3} 22.34 -> 22.15 s, StC 4.64 -> 4.47 s
   (1.47x std's), 6 fewer keys; {4,4} -0.85 s with +31 keys. See `PHASE2_LOG.md` 2.3.)
2. **Sparse encapsulation EvalMod cost (not precision).** A weight-32 CI key acts like a weight-64
   power-basis key, so CI uses the K = 28 sine table (Chebyshev degree 48) where std uses K = 16 (degree 36).
   Precision is not affected: CI and std have the same RMS (18.24 / 18.23 bits, Table 3.1). Both tables have
   the same depth (7, plus R = 3 double-angle steps), so the chain does not change either. The cost is the
   larger Paterson-Stockmeyer evaluation (k, m) = (7, 3) vs (6, 3). Measured at 2^16 {4,4} (1 thread, item
   0.5, temporary switch): CI EvalMod 7.81 s with K = 28 vs 6.82 s with K = 16 (-1.0 s, -13%), total
   26.66 -> 25.56 s (-4%), RMS 18.23 bits in both runs. The fix is a weight-16 CI ephemeral key so that K = 16
   is sound (phase 3.1, subject to the security estimate).
   (Phase 3.1: rejected. A weight-16 CI key, n = 65536 at log q0 P' = 126, falls below 128 bits: MITM on the
   secret 2^116, primal drop-and-solve 129.8 bits; weight 32 has 213 bits. CI keeps weight 32 and K = 28, as the
   paper does (ephemeral weight 32 on the CI ring). See `PHASE2_LOG.md` 3.1.)
   (Phase 3.3, WSL 2^16 {5,3}: CI EvalMod is 60-61 us per real slot, std 188-193 us CtS-first (two calls) and
   91-94 us StC-first (one call): CI / std 0.31-0.33x and 0.64-0.66x. Per call CI is 1.24-1.33x std, about 1.15x
   from the K = 28 table and 1.10x from the CI ring. See `PHASE2_LOG.md` 3.3.)
3. **CI ring overhead.** CI NTT is within 1.2x of the standard NTT; CI EvalMod still ~1.2x std per op.
   (Phase 4.1, WSL: the CI NTT is now the NTT modulo X^N - wm^N of the fold g_i = a_i - wm^N a_{N-i}, fused into
   the first CT / last GS stage as raw-word loops in `NumberTheoreticTransformNat`; round trip 1.04-1.05x the
   standard NTT at 2^16 (was 1.19-1.20x), bit-exact; ModUp/ModDown -8%, CI bootstrap about -2%. See
   `PHASE2_LOG.md` 4.1.)
   (Phase 4.2, WSL 2^16, 21/11/4 towers, `benchmark/src/ci-op-cost.cpp`: CI/std per op is 1.02-1.06x for EvalMult,
   relinearization, rescale, rotation, ModUp and ModDown, and equal for the NTT-free ops; nothing above 1.1x. The
   CI/std bootstrap stage ratios come from op counts. See `PHASE2_LOG.md` 4.2.)
   (Phase 4.R, WSL 2^16 {5,3}: CI EvalMod per call is 1.23x std's (was 1.30x), so per real slot 0.31x std
   CtS-first and 0.61x std StC-first; the rest is the K = 28 table (floor 0.57x). CI 11.37 s vs std 11.27 s
   CtS-first (1.98x). See `PHASE2_LOG.md` 4.R.)
4. **Modulus registry keyed by prime** (pre-existing design): a CI and a std context in one process
   that share a prime would conflict. Key it by (prime, ring) or attach the flag to the params.
5. **First bootstrap builds the diagonals lazily** (~70 s at 2^16); move to EvalBootstrapSetup.
   (Done in phase 2.4: `EvalBootstrapSetup` encodes them, in parallel; the first bootstrap is warm.)
6. **Not done:** the paper's functional bootstrapping (CI-AKP with radial correction, CI-Hermite),
   StC-first ordering, multi-thread tuning. (StC-first done in phase 2.5: `BTSlotsEncoding = true` gives the CI
   StC-first bootstrap; at 2^16 {5,3} it is 2.1% faster (StC -9.4%) and 1.2 bits more precise (max error) with
   corr 12; std's real-data StC-first runs EvalMod once and is 27% faster than std CtS-first, so CI/2xstd is 1.53x
   with both StC-first vs 2.05x with both CtS-first. See `PHASE2_LOG.md` 2.5.)
   (Phase 2 review 2.R, WSL 2^16 {5,3}: CI/std stage ratios CtS 1.44x, StC 1.51x, below the diagonal ratios 1.83x /
   1.68x; StC-first cuts CI StC by 9% / 30% / 42% at 2 / 3 / 5 levels after, at 7.3-8.2 ms per diagonal vs std
   CtS-first 8.9-13.3 ms. Both orderings stay supported. See `PHASE2_LOG.md` 2.R.)

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
diagonals; the paper puts the short product last; since item 2.3 the split comes from a cost-model table); any budget is allowed, not only powers of two.

Issues found (all addressed in `PLAN_PHASE2.md`, phase 0 unless noted):
1. `REAL_CI` with `BTSlotsEncoding = true` would run the standard StC-first path on CI data (no guard).
   (Phase 0.1: guarded with a throw. Phase 2.5: replaced by a native CI StC-first branch in `EvalBootstrap`.)
2. The CI correction-factor default change (`cfSlots = N/2`) is harmful and must be reverted. It moves the CI
   default at 2^16 (FLEXIBLEAUTO, CtS-first fit) from 7 to 8; measured with the committed code: CI RMS drops
   from 18.24 to 17.23 bits and min precision from 15.0 to 13.9 (std, which uses 8, is unchanged at 18.24).
   Table 3.1 was produced before this change and stands. Phase 0.2 of the plan reverts it and sweeps the
   correction factor for both schemes. (Done in phase 0.2: reverted; the new CI default is 7 at 2^16.)
3. `GetCIRealLevels` is cached twice (scaled for evaluation, unit-scaled for keygen). (Done in phase 0.3:
   one unscaled entry per (N, lbEnc, lbDec), scalars applied at encode time; peak RSS 11.39 -> 11.19 GB at 2^16.)
4. The `CISparseMul` drop threshold is absolute; keygen and evaluation must agree on the sparsity pattern.
   (Done in phase 0.4: relative threshold 1e-13 x the largest entry; `EvalBootstrap` throws if its rotation
   set differs from the keygen Galois set; holds at 2^12..2^16 for {2,2}, {3,3}, {4,4}.)
5. Diagonal plaintexts are built lazily inside a const `EvalBootstrap` (first call 70 s at 2^16; not safe under
   concurrent bootstraps) (phase 2.4). (Done in phase 2.4: `EvalBootstrapSetup` and `EvalBootstrapPrecompute`
   encode all CI diagonals (parallel, extended Q_l P basis, towers from the chain model); `EvalBootstrap` only
   reads them and encodes a level locally only if its store does not match. WSL, 2^16 {5,3}, 1 thread: first
   bootstrap 35.5 -> 18.0 s (warm 16.5 s), setup +18.5 s (2.9x faster on 8 threads at 2^15); warm time, keys and
   peak RSS (13.54 GB) unchanged. See `PHASE2_LOG.md` 2.4.)
6. Section 4 item 2 above is mis-stated: CI and std have equal RMS precision; the K = 28 table costs EvalMod
   degree (48 vs 36), it does not cost precision. The fix is a weight-16 CI ephemeral key (phase 3.1).
   (Done in phase 0.5: section 4 item 2 rewritten as a cost item; the K = 28 table costs 1.0 s of 7.8 s CI
   EvalMod at 2^16 {4,4}, about 4% of the CI bootstrap, at the same depth and RMS.)
7. The chain is 1580 bits (P = 420) versus the paper's 1064; this, not the transforms, is the likely main
   reason for the 2x absolute gap to the paper's 12.6 s. Both schemes are affected equally (phase 1).
   (Phase 1.1-1.2: not confirmed. At N = 2^16 the time depends on the tower counts, not on log QP: dnum 3 is
   the fastest valid dnum, and 50-59-bit primes cost the same time. Mixed per-stage primes would not lower
   log QP in OpenFHE, because P is sized to the largest digit. Uniform 59/60 primes give +3.3 bits for CI at
   the same time. See `PHASE2_LOG.md` 1.1 and 1.2.)
   (Phase 1.3: with 59/60 primes the fastest budgets are CI {4,3} (25.97 s, -1.2% vs {4,4}) and std {5,3}
   (22.0 s, -6%). At each scheme's best budget CI/2xstd is 1.69x, not the 1.78x of equal {4,4} budgets. {5,5} is
   valid at 128-bit with dnum 4, but it is slower for both schemes.)
   (Phase 1.R: done, hypothesis refuted. log QP <= 1100 is reachable at 128-bit only with budget {2,2},
   55/56-bit primes and dnum 9 (log QP 1060 / 1076). That set is 2.3x slower for CI (59 s) and 2.1x for std
   (45-46 s) than the best sets, and at the same Q dnum 3 (log QP 1300) is faster than dnum 9. New baseline:
   59/60, CI {4,3} 25.98 s vs std {5,3} 21.86 s, 1.68x; CI is 2.06x the paper's 12.6 s (about 1.8x at equal
   clock) and 2.0 bits below its 20.55-bit max-error precision. The remaining gap is the linear transforms
   (18.0 of 25.98 s, phase 2) and EvalMod scale bookkeeping (~2.7 s, item 1.2), not the chain length.)
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
