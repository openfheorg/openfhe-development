# Phase 2 plan: close the remaining gaps of the native CI-CKKS real-FFT bootstrap

Branch: `ci-ckks-fft-v1.6.1` (continue on it). Execution: ICELAKE only (ssh `ICE-Lake`, dir
`~/ci-ckks-fft/openfhe-development`), every job tmux-guarded via `ci-ckks-paper/tools/guard.sh`, source synced
from WSL with `tools/sync.sh`. Unit tests run once at the end of each phase, not during. Scope excludes the
paper's functional bootstrapping.

Baseline to beat (N = 2^16, 128-bit, 1 thread, FLEXIBLEAUTO, sparse encapsulation, budget {4,4}):
CI 26.3 s for 65,536 reals (CtS 13.6 / EvalMod 7.6 / StC 4.4), two std bootstraps 45.9 s, speedup 1.74x,
RMS 18.2 bits both. Paper (Lattigo, Xeon Gold 6248R, 1 core, log QP = 1064): CI 12.6 s, 20.5 bits.
Driver: `benchmark/src/ci-fft-boot.cpp` (args: scheme logN lbEnc lbDec scaleMod firstMod secure reps scaling
corr secret). Every phase ends with the same two commands so results stay comparable:

    OMP_NUM_THREADS=1 build/bin/benchmark/ci-fft-boot ci  16 4 4 55 60 1 2 fa 0 encap
    OMP_NUM_THREADS=1 build/bin/benchmark/ci-fft-boot std 16 4 4 55 60 1 2 fa 0 encap

## Phase 0: review fixes (small, do first)
| # | Item | Why | Done when |
|---|---|---|---|
| 0.1 | Throw (or route to the CtS-first path) when `REAL_CI` and `BTSlotsEncoding` are both set | `EvalBootstrap` dispatches to `EvalBootstrapStCFirst`, which has no CI branch and would run the complex transforms on CI data | unit test expects a throw |
| 0.2 | Validate or revert the CI correction-factor change (`cfSlots = N/2` in `EvalBootstrapSetup`) | committed without measurement; at 2^16 it leaves the default at 11, at 2^13 it moves it 12 -> 13 while the sweep showed lower factors are better for both schemes | sweep corr in {6,...,11} at 2^16 for CI and std; set the CI default from data |
| 0.3 | Store unscaled levels once; apply `scaleEnc`/`scaleDec` as per-level scalars | `GetCIRealLevels` caches a second full copy keyed on (1.0, 1.0) for keygen (~0.7 GB at 2^16) | one cache entry per (N, lbEnc, lbDec) |
| 0.4 | Relative drop threshold in `CISparseMul` (1e-13 x max entry) | absolute threshold could change the sparsity pattern, and keygen and evaluation must agree on it | keygen key set == evaluator key set, asserted |
| 0.5 | Fix report wording: gap 2 is an EvalMod *cost* item, not a precision item | measured RMS precision is equal (18.24 vs 18.23) | report updated |
| 0.6 | `.gitignore` the PDF copies under `ci-ckks-paper/` | untracked binaries in the tree | clean `git status` |

## Phase 1: parameter leanness (both schemes, biggest absolute win, keeps the comparison fair)
Our chain is log Q + log P = 1160 + 420 = 1580 bits; the paper runs at 1064. Key switching cost grows with the
number of QP limbs, so this alone is likely most of the 2x absolute gap to the paper (26.3 s vs 12.6 s).
1. Sweep `SetNumLargeDigits` (dnum) in {3, 4, 5, 6} at 2^16 for CI and std; record log P, key size, time.
2. Per-stage prime sizes as in the paper: EvalMod primes ~60 bits, StC primes ~40 bits, 3 usable levels after
   bootstrap (OpenFHE has no per-stage scale yet: evaluate FIXEDMANUAL with mixed prime sizes vs
   FLEXIBLEAUTO uniform 55; a per-stage scale schedule is an engineering item if it pays).
3. Re-run the budget sweep after 1-2: {4,3}, {5,3}, {5,4}, {5,5} (CtS budget first in OpenFHE's order; the
   paper's best is StC 3 + CtS 4). {5,5} exceeded the 128-bit modulus bound at 1580 bits and should fit after.
Done when: a parameter set with log QP <= ~1100 at 128-bit is found and both schemes are re-measured; report
the new CI/2xstd ratio and the absolute CI time against the paper's 12.6 s.

## Phase 2: CoeffsToSlots cost (gap 1)
CtS is 52% of the CI bootstrap. Part of that is inherent to the real factorization: a collapsed group of k full
real layers has about 2^(k+2) cyclic diagonals versus 2^(k+1) for the complex factorization (BSGS makes the
rotation count ~sqrt(2) worse and plaintext multiplications 2x worse). The paper has the same shape (CtS is
66% of its 12.6 s). The items below attack the implementation part.
1. Instrument: count key switches and plaintext multiplications per level (CI) and compare with std's
   `EvalCoeffsToSlots` at the same N; compare both to the theoretical 2*sqrt(#diagonals) + #diagonals.
   Any excess is a bug to fix before tuning.
2. Per-level BSGS ratio: `CI_BSGS_RATIO` is a global 2.0. Choose n1 per level from a cost model
   (hoisted baby rotation vs giant rotation at that level's limb count), verify on ICELAKE at 2^16.
3. Uneven layer splits: the first two real layers have 2 and 3 diagonals, later layers 6-7. Search splits
   (e.g. [6,5,5] vs [7,5,4] vs [5,6,5]) with a (diagonals x limbs) cost model, then measure the top 3.
4. Precompute the diagonal plaintexts in `EvalBootstrapSetup` (gap 5): removes the ~70 s cold run, removes the
   write into the precom from a const `EvalBootstrap` (a data race under concurrent bootstraps), and lets the
   encodes run in parallel at setup. Store in extended (QlP) form as now.
5. StC-first CI variant (gap 6, paper's ordering): add a CI branch to `EvalBootstrapStCFirst`: StC on the input
   at the bottom of the chain (few limbs, ~free), ModRaise, CtS, EvalMod; output at a higher level. Expected:
   StC 4.4 s -> ~1 s and more usable levels after bootstrap for the same chain.
Done when: CI CtS+StC per real slot is within 1.3x of std's CtS+StC per real slot, or the excess is shown to be
the inherent diagonal count.

## Phase 3: EvalMod and sparse encapsulation (gap 2, reframed)
1. The CI ephemeral key uses `GetSparseKSHammingWeight()` = 32 nonzeros in the CI basis, i.e. L1 norm ~64 in
   the power basis, so it needs the K = 28 (degree 48) sine table; std uses weight 32 with the K = 16
   (degree 36) table. Generate the CI ephemeral key with weight 16 and use the K = 16 table.
   Security check: the sparse key only protects the bottom modulus plus the two sparse-KS primes
   (log q ~ 60 + 66 bits at N = 2^16); run the lattice estimator for (N = 65536, log q = 126, ternary
   weight 16) and record the result in the report (expected far above 128 bits).
2. META-BTS (`numIterations = 2`) for both schemes: check that the CI branch works with the iteration wrapper in
   `EvalBootstrap`, then compare precision and time with the paper's 20.5 bits.
3. Report std and CI EvalMod time per real slot side by side (std does two EvalMods per bootstrap in the fully
   packed case; CI does one).
Done when: CI EvalMod degree equals std's for the same secret distribution, and the precision gap to the paper
is explained (OpenFHE sine approximation vs Lattigo's) or closed.

## Phase 4: CI ring overhead (gap 3)
1. The twist passes of the CI NTT are two `ModMulFastConst` per element through the `NativeInteger` API and do
   not vectorize; OpenFHE's NTT works on raw words. Move the twisted NTT next to `NumberTheoreticTransformNat`
   (friend access to the word values) and write the twist as raw-word Shoup loops.
   Target: CI NTT round trip within 1.05x of the standard NTT (now 1.19x at 2^16).
2. Measure CI vs std per-op cost (EvalMult, rotation, rescale) at 2^16 with `ci-noise-probe`-style timing;
   anything above 1.1x is a target.
Done when: EvalMod time per real slot for CI <= 0.55x std's (it is one EvalMod vs two).

## Phase 5: multi-thread scaling (gap 6)
1. Measure 1/4/8/16 threads for CI and std at 2^16; CI uses the same OMP-over-limbs parallelism as std, but the
   sparse BSGS inner loop is serial over baby steps.
2. If CI scales worse than std: parallelize the baby-step accumulation (per-thread partial sums in the extended
   basis, reduce once per giant block).
Done when: CI/std speedup at 16 threads is within 10% of the single-thread speedup.

## Phase 6: engineering (last)
1. Ring type as a property of the element parameters (or (modulus, N) keyed registry) instead of a global
   modulus-keyed registry (gap 4): a CI and a std context sharing a prime in one process must not conflict.
2. Remove env switches (`CI_BSGS_RATIO`, `CI_BOOT_TIMING`), the `std::cerr` prints and the `g_CIDbg*` debug
   globals from library code; expose timing through the existing `BOOTSTRAPTIMING` path.
3. `EvalBootstrapKeyMapIndices` CI-aware (serialization of CI bootstrapping keys); CI context serialization test.
4. Unit tests: StC-first CI (if built), encapsulated CI at two budgets, keygen/evaluator key-set equality,
   CI + BTSlotsEncoding guard. Move the mid-file `#include` in `UnitTestCKKSrnsCI.cpp` to the top; clang-format.
5. Final full run: `pke_tests`, `core_tests`, `binfhe_tests`; final benchmark table (1 and 16 threads) in the
   report; remove the `openfhe-ci2026-orig` worktree.

## Order and delegation
Phase 0 -> 1 -> 2 -> 3 -> 4 -> 5 -> 6. Phases 1 and 3.1 are independent and can run in parallel on ICELAKE if
the machine is idle (single-thread timing runs must not overlap with builds). Each phase: quick-and-dirty
implementation, measure, then optimize, then clean up. Commit per phase on this branch.
