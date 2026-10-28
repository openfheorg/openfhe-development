# Phase 2 plan: close the remaining gaps of the native CI-CKKS real-FFT bootstrap

Branch: `ci-ckks-fft-v1.6.1` (continue on it). Scope excludes the paper's functional bootstrapping.
Progress is tracked by the checkboxes below; the harness ticks `[x]` when an item is done and appends its
results to `ci-ckks-paper/PHASE2_LOG.md`. `[~]` marks an item deferred with a stated reason.

## Execution rules (apply to every item)
- **Code lives on WSL** in `/home/caesar/development/projects/za-real-ckks-boot-fft/openfhe-development`.
  Edit and commit there. **Never build, run benchmarks or run tests on WSL** (it must not be loaded).
- **All builds, benchmarks and tests run on ICELAKE** (`ssh -o BatchMode=yes ICE-Lake`, tree at
  `~/ci-ckks-fft/openfhe-development`, build dir `build`; `build-bt` = same with `-DBOOTSTRAPTIMING`).
  Push source with `ci-ckks-paper/tools/sync.sh` (it never deletes `build*/` dirs on ICELAKE).
- **Guard every remote job**: `cd ~/ci-ckks-fft && ./guard.sh NAME 'cmd'` (tmux; log in `logs/NAME.log`,
  exit code in `logs/NAME.rc`). Poll for the `.rc` file; an SSH drop must not kill a job.
- ICELAKE is shared: builds with `-j 32`; timing runs with `OMP_NUM_THREADS=1` (unless the item is about
  threads), one timing run at a time, never during a build.
- Unit tests run only in item 6.5 (they are slow).
- One commit per item (code + this checkbox + log entry), message ending with the Co-Authored-By line.

Baseline to beat (N = 2^16, 128-bit, 1 thread, FLEXIBLEAUTO, sparse encapsulation, budget {4,4}):
CI 26.4-26.7 s for 65,536 reals (CtS 13.7 / EvalMod 7.8 / StC 4.4), two std bootstraps 2 x 23.2 = 46.5 s (std
stages CtS 8.36 / EvalMod 12.2 / StC 2.38 per bootstrap), speedup 1.74-1.76x, RMS 18.2 bits both (re-measured in
0.R; 0.2 measured CI 26.3 s, std 45.9 s, 1.74x). Paper (Lattigo, Xeon Gold 6248R,
1 core, log QP = 1064): CI 12.6 s, 20.5 bits. Default correction factors: CI 7, std 8 (item 0.2); `corr` = 5
(no correction, the minimum for firstMod 60 / scaleMod 55) gives CI 20.2 / std 21.2 bits RMS at the same time.
Key switching: OpenFHE default dnum 3 (alpha 7, log P 420) is the fastest dnum valid at 128-bit for both schemes;
dnum 2 exceeds the 1747-bit bound, dnum 4 ties, dnum 5-7 are slower (item 1.1).
Prime sizes (item 1.2): time depends on tower counts, not prime bits; uniform FLEXIBLEAUTO 59/60 with corr 4 (CI) /
5 (std) is valid at 128-bit (log QP 1660) and gives CI RMS 21.6 / min 17.9-18.7 bits, std 22.7 / 19.9-20.3 bits
at the baseline's time; use it in item 1.3. The paper's 20.55 bits is max error (our `prec_bits_min`; baseline CI
15.0). Mixed per-stage primes would not lower time or log QP in OpenFHE, so no per-stage scale was built.
FIXEDMANUAL is 10% (CI) / 16% (std) faster, all in EvalMod (FLEXIBLEAUTO's scale-adjust rescales), but loses 3-7 bits RMS.
Budgets (item 1.3, 59/60): best CI {4,3} 25.97 s (log QP 1601; {4,4} 26.28 s, within 1.2%), best std {5,3} 22.0 s
(-6% vs {4,4}); at each scheme's best budget CI/2xstd is 1.69x (1.78x at equal {4,4}). {5,4}/{5,5} need dnum 4 at
128-bit; {5,5} is slower for both. RMS does not depend on the budget. Compare at each scheme's best budget from here on.
Driver `benchmark/src/ci-fft-boot.cpp` (args: scheme logN lbEnc lbDec scaleMod firstMod secure reps scaling corr secret [stcfirst] [dnum] [after]). Baseline commands (run at every phase review):

    OMP_NUM_THREADS=1 build/bin/benchmark/ci-fft-boot ci  16 4 4 55 60 1 2 fa 0 encap
    OMP_NUM_THREADS=1 build/bin/benchmark/ci-fft-boot std 16 4 4 55 60 1 2 fa 0 encap

## Phase 0: review fixes
- [x] **0.1** Throw (or route to the CtS-first CI path) when `REAL_CI` and `BTSlotsEncoding` are both set.
  Why: `EvalBootstrap` dispatches to `EvalBootstrapStCFirst`, which has no CI branch. Done when: guarded with
  a clear message (test added in 6.4).
- [x] **0.2** Revert the CI correction-factor change (`cfSlots = N/2` in `EvalBootstrapSetup`), then sweep corr
  in {5,...,9} at 2^16 (128-bit, 1 thread, encap, {4,4}) for CI and std. Why: measured, it moves the CI default
  from 7 to 8 and costs 1 bit RMS (18.24 -> 17.23). Done when: CI default chosen from data (keep std's OpenFHE
  default unless the data is overwhelming), and the baseline commands re-run.
- [x] **0.3** Store unscaled levels once; apply `scaleEnc`/`scaleDec` as per-level scalars at encode time.
  Why: `GetCIRealLevels` caches a second full copy keyed on (1.0, 1.0) for keygen. Done when: one cache entry
  per (N, lbEnc, lbDec); peak RSS at 2^16 {4,4} re-measured.
- [x] **0.4** Relative drop threshold in `CISparseMul` (1e-13 x max entry) and an assertion that the keygen
  Galois set equals the evaluator's rotation set. Done when: the assertion holds at 2^12..2^16 for budgets
  {2,2},{3,3},{4,4}.
- [x] **0.5** Fix `CI_FFT_REVIEW.md` section 4 item 2: it is an EvalMod *cost* item (degree 48 vs 36), not a
  precision item (RMS is equal). Done when: report updated.
- [x] **0.6** `.gitignore` the PDF copies under `ci-ckks-paper/`. (Done in commit 85e4166b.)
- [x] **0.R** Phase 0 review: build on ICELAKE, run the baseline commands, log the numbers.

## Phase 1: parameter leanness (both schemes; biggest absolute lever)
Our chain is log Q + log P = 1160 + 420 = 1580 bits; the paper's is 1064. Key-switching cost grows with the
number of QP limbs, so this is likely most of the 2x absolute gap to the paper (26.3 s vs 12.6 s).
- [x] **1.1** Sweep `SetNumLargeDigits` (dnum) in {3, 4, 5, 6} at 2^16 for CI and std; record log P, key size,
  time, precision (add a driver argument for dnum).
- [x] **1.2** Per-stage prime sizes as in the paper (EvalMod ~60-bit, StC ~40-bit, 3 usable levels after
  bootstrap): evaluate FIXEDMANUAL with mixed prime sizes vs FLEXIBLEAUTO uniform 55 (OpenFHE has no
  per-stage scale; only build one if the numbers show it pays). Record log QP, time, precision.
- [x] **1.3** Budget sweep with the best parameters from 1.1-1.2: {4,3}, {5,3}, {5,4}, {5,5} for CI and std
  (CtS budget first in OpenFHE's order; the paper's best is StC 3 + CtS 4).
- [ ] **1.R** Phase 1 review. Done when: a 128-bit parameter set with log QP <= ~1100 is found (or the reason it
  cannot be is recorded), both schemes re-measured, CI/2xstd ratio and absolute CI time vs the paper's 12.6 s
  logged. Update the baseline commands in this file if the parameters change.

## Phase 2: linear-transform cost (gap 1)
Measured at 2^16 (same N, warm, 1 thread): CI CtS = 1.64x std CtS ({4,4}), CI StC = 1.88x std StC, CI EvalMod
= 0.64x (std runs EvalMod twice). The real factorization inherently needs ~2x the plaintext multiplications
and ~sqrt(2)x the rotations of the complex one (~1.5-1.7x), so CtS is near the bound and StC has slack.
- [ ] **2.1** Instrument: count key switches and plaintext multiplications per level (CI) and in std's
  `EvalCoeffsToSlots` at the same N; compare with 2*sqrt(#diagonals) + #diagonals. Any excess is a bug to fix
  before tuning.
- [ ] **2.2** Per-level BSGS ratio from a cost model (hoisted baby rotation vs giant rotation at that level's
  limb count) instead of the global 2.0; verify at 2^16.
- [ ] **2.3** Uneven layer splits: search splits (e.g. [6,5,5] vs [7,5,4] vs [5,6,5]) with a (diagonals x limbs)
  cost model; measure the top 3 at 2^16.
- [ ] **2.4** Precompute the diagonal plaintexts in `EvalBootstrapSetup` (remove the ~70 s cold run and the write
  into the precom from a const `EvalBootstrap`; parallel encodes at setup; extended QlP form as now).
- [ ] **2.5** StC-first CI variant (the paper's ordering): CI branch in `EvalBootstrapStCFirst` (StC at the
  bottom of the chain, ModRaise, CtS, EvalMod); compare time, precision and output level with CtS-first.
- [ ] **2.R** Phase 2 review. Done when: at the same N, CI CtS <= 1.5x std CtS and CI StC <= 1.5x std StC (or the
  excess is accounted for by the diagonal count), and StC-first CI StC is below std's CtS-first StC.

## Phase 3: EvalMod and sparse encapsulation (gap 2, a cost item)
- [ ] **3.1** CI ephemeral sparse key with weight 16 in the CI basis (L1 norm ~32 in the power basis) and the
  K = 16 (degree 36) sine table, like std. Run the lattice estimator on ICELAKE for (N = 65536, log q ~ 126,
  ternary weight 16) and record the security level; if below 128 bits, keep weight 32 and record why.
- [ ] **3.2** META-BTS (`numIterations = 2`) for CI and std at 2^16: check that the CI branch works with the
  iteration wrapper; compare precision and time with the paper's 20.5 bits.
- [ ] **3.3** Log CI and std EvalMod time per real slot side by side.
- [ ] **3.R** Phase 3 review. Done when: CI EvalMod degree equals std's for the same secret distribution (or the
  security reason it cannot is recorded), and the precision gap to the paper is explained or closed.

## Phase 4: CI ring overhead (gap 3)
- [ ] **4.1** Raw-word Shoup twist loops for the CI NTT (move the twisted NTT next to
  `NumberTheoreticTransformNat` for word access). Target: CI NTT round trip within 1.05x of the standard NTT
  (now 1.19x at 2^16); validate with `benchmark/src/ci-ntt-check.cpp` (bit-exact vs reference).
- [ ] **4.2** Measure CI vs std per-op cost (EvalMult, rotation, rescale) at 2^16; fix anything above 1.1x.
- [ ] **4.R** Phase 4 review. Done when: CI EvalMod time per real slot <= 0.55x std's.

## Phase 5: multi-thread scaling
- [ ] **5.1** Measure 1/4/8/16 threads for CI and std at 2^16.
- [ ] **5.2** If CI scales worse: parallelize the sparse BSGS baby-step accumulation (per-thread partial sums in
  the extended basis, reduce once per giant block).
- [ ] **5.R** Phase 5 review. Done when: CI/std speedup at 16 threads is within 10% of the single-thread one.

## Phase 6: engineering (last)
- [ ] **6.1** Ring type as a property of the element parameters (or a (modulus, N)-keyed registry) instead of the
  global modulus-keyed registry; a CI and a std context sharing a prime in one process must not conflict.
- [ ] **6.2** Remove env switches (`CI_BSGS_RATIO`, `CI_BOOT_TIMING`), `std::cerr` prints and `g_CIDbg*` debug
  globals from library code; expose timing through `BOOTSTRAPTIMING`.
- [ ] **6.3** `EvalBootstrapKeyMapIndices` CI-aware; CI context and bootstrap-key serialization test.
- [ ] **6.4** Unit tests: StC-first CI (if built), encapsulated CI at two budgets, keygen/evaluator key-set
  equality, CI + `BTSlotsEncoding` guard; move the mid-file `#include` in `UnitTestCKKSrnsCI.cpp` to the top;
  clang-format the touched files.
- [ ] **6.5** Final run on ICELAKE: `pke_tests`, `core_tests`, `binfhe_tests`; final benchmark table (1 and 16
  threads) in `CI_FFT_REVIEW.md`; remove the `openfhe-ci2026-orig` worktree (WSL) and stale ICELAKE build dirs
  other than `build`.
