# Phase 2 plan: close the remaining gaps of the native CI-CKKS real-FFT bootstrap

Branch: `ci-ckks-fft-v1.6.1` (continue on it). Scope excludes the paper's functional bootstrapping.
Progress is tracked by the checkboxes below; the harness ticks `[x]` when an item is done and appends its
results to `ci-ckks-paper/PHASE2_LOG.md`. `[~]` marks an item deferred with a stated reason.

**PAUSE AFTER PHASE 2 (user, 2026-10-28):** the user needs this laptop for another task. Items 2.5 and 2.R run as
usual. An executor of any item from 3.1 on must do nothing (no edits, no jobs, no commits) and return status "blocked"
with the summary "paused by the user after phase 2". A plan adapter consulted on such an item must choose "defer"
without editing the plan. This note is removed when the user resumes the work.

## Execution rules (apply to every item)
**Host change (2026-10-28, user request): from item 2.4 on, all builds, benchmarks and tests run on this WSL VM. Nothing
runs on ICELAKE (not even a read-only ssh) unless the user is told first; harness agents treat it as off limits.** Items 0.1-2.3 ran on ICELAKE; their numbers are not comparable with WSL numbers. The old ICELAKE rules are
kept at the end of this section for reference.
- **Code lives on WSL** in `/home/caesar/development/projects/za-real-ckks-boot-fft/openfhe-development`. Edit and
  commit there.
- **Every build, benchmark and test goes through the guard**, never directly in a shell:
  `ci-ckks-paper/tools/wsl-guard.sh NAME MEM_GB 'command'` (cwd = repo root; log `~/ci-ckks-wsl/logs/NAME.log`; exit
  status in `NAME.rc`; `killed:oom-kill` if the job hit its memory cap; `refused:mem` if there was not enough free
  memory to start). Wait with `ci-ckks-paper/tools/wsl-wait.sh NAME [timeout_s]`. Jobs survive VS Code/terminal
  resets (systemd user manager), not a VM restart.
- **Do not kill or starve the VM.** All guarded jobs share `cickks.slice`: 20 GB in total (raised from 16 GB by the user on 2026-10-28;
  this overrides any 16 GB figure in the harness prompt), no swap, 14 of 20 CPU threads, OOM-kill priority 1000. Each job also has its own cap (`MEM_GB`, peak RSS + about 1 GB) and runs at nice 10. Peak RSS: CI 2^16 about
  11-15 GB, std 2^16 about 8-9 GB, 2^15 about half, 2^12 under 1 GB. So only one 2^16 job runs at a time, and no build
  runs beside it; concurrent jobs only while their `MEM_GB` sum is at most 19. In practice VS Code and Claude use about
  16-17 GB of the VM's 31 GB, so a job can get about 14-16 GB; the guard refuses a job if free memory < `MEM_GB` + 2. A killed or refused job is answered by a
  smaller N or budget, or by lowering memory in the code, never by raising the slice limit.
- **Build dirs:** `build-wsl` (Release, benchmarks, no unit tests, no examples) and `build-wsl-bt` (the same with
  `-DCMAKE_CXX_FLAGS=-DBOOTSTRAPTIMING`, for std stage times). Build only the needed targets, `-j 8`, `MEM_GB` 12. Leave
  the old `build` dir alone. Item 6.5 turns on `BUILD_UNITTESTS` in `build-wsl` and builds tests with `-j 4`.
- **Timing:** `OMP_NUM_THREADS=1` (unless the item is about threads), one timing job at a time, never during a build.
  The i7-12700H laptop CPU has turbo and thermal variation: interleave A/B runs (before/after, CI/std) in one guarded
  job, `reps` 3 for final numbers, medians. The laptop may sleep: a timing job that spans a sleep (an outlier
  rep, or wall time in the log much longer than setup + reps) is discarded and rerun, never reported. The first WSL item (2.4) first measures and logs the **WSL baseline** at
  HEAD with the header commands (with `build-wsl` paths); later items compare against WSL numbers only.
- Unit tests run only in item 6.5 (they are slow).
- **Development-time rules (2026-10-28).** Aim for at most about 45 minutes per item.
  - *Screen cheap, confirm once.* N = 2^12-2^14 (insecure) for correctness checks; N = 2^15, or 2^16 with `reps` 1,
    for screening candidates. Only the final 1-3 candidates get the full 2^16, `reps` 3 timing.
  - *Parallel only where memory allows.* Small-N correctness runs may run concurrently with each other (sum of
    `MEM_GB` at most 15). 2^16 runs are always alone.
  - *A/B in one job*, interleaved, as above.
  - *Minimal rebuilds.* Build only the targets the item needs; batch code fixes before rebuilding.
  - *Phase reviews reuse numbers.* A phase review (x.R) reruns the baseline once per scheme (`reps` 3) only if code
    changed since the last item's final timing run; otherwise it cites that run.
  - Item 2.4 adds the precomputed diagonals to CI memory: measure it and keep CI 2^16 under a 19 GB job cap (and within free memory) (if it
    does not fit, precompute per level lazily or at a smaller N, and log it).
- One commit per item (code + this checkbox + log entry), message ending with the Co-Authored-By line.
- *Old ICELAKE rules (items 0.1-2.3, for reference only):* builds and runs on ICELAKE (`ssh -o BatchMode=yes
  ICE-Lake`, `~/ci-ckks-fft/openfhe-development`, dirs `build` and `build-bt`), source pushed with
  `ci-ckks-paper/tools/sync.sh`, jobs guarded with `~/ci-ckks-fft/guard.sh`.

**WSL baseline to beat (item 2.4; compare WSL items only with this).** Same settings as below, `build-wsl` (CI) and
`build-wsl-bt` (std, for stage times), one interleaved job, reps 3, warm medians: CI {5,3} 16.37 s (CtS 6.99 / EvalMod
5.34 / StC 3.62; RMS 21.55 / min 18.15 bits; 102 keys; peak RSS 13.55 GB), std {5,3} 16.25 s (5.16 / 8.44 / 2.32;
22.73 / 19.21 bits; 7.66 GB); 2 x 16.25 / 16.37 = 1.99x; stage ratios CtS 1.36x, EvalMod 0.63x, StC 1.56x. Equal
budget {4,4}: CI 17.48 s (8.37 / 6.30 / 2.68), std 18.23 s (6.11 / 9.92 / 1.87), 2.09x. The laptop takes ~26% less time
per bootstrap than ICELAKE and its run-to-run spread is up to ~15% (thermal): use interleaved A/B pairs. Since item 2.4 the CI
diagonals are encoded in `EvalBootstrapSetup` (1 thread: 18.5 s at 2^16 {5,3}; parallel), so the first CI bootstrap
is warm (18.0 vs 16.5 s; it was 35.5 s) and `setup+keygen_s` is ~18 s larger; warm time, keys and RSS unchanged.

ICELAKE baseline (item 2.3, reference only; N = 2^16, 128-bit, 1 thread, FLEXIBLEAUTO 59/60, sparse encapsulation, dnum 3, 2 levels
after, each scheme at its best budget, reps 3): both schemes' best budget is {5,3}. CI {5,3} corr 4: 22.15 s for
65,536 reals (CtS 9.63 / EvalMod 7.47 / StC 4.47), RMS 21.55 / min 18.37 bits, 102 keys, peak RSS 13.55 GB; std {5,3}
corr 5: 21.85 s (CtS 6.78 / EvalMod 11.57 / StC 3.04), RMS 22.75 / min 19.50 bits, log QP 1660; speedup
2 x 21.85 / 22.15 = 1.97x; stage ratios at {5,3} CtS 1.42x, EvalMod 0.65x, StC 1.47x. Equal-budget reference {4,4}:
CI 23.11-23.18 s (11.01 / 8.20 / 3.37; 92 keys, 12.56 GB), std 23.54 s (8.03 / 12.74 / 2.32), 2.03x; stage ratios
CtS 1.37x, EvalMod 0.64x, StC 1.45x. CI {4,3}: 23.05 s. [Item 2.2, even layer split: CI {5,3} 22.34 s (StC 4.64,
108 keys), 1.96x; {4,4} CI 23.98 s (11.48 / 8.19 / 3.73; 61 keys, 10.42 GB), ratios 1.43x / 0.64x / 1.61x; CI {4,3}
23.58 s. Item 2.1: CI {4,3} 23.75 s, std {5,3} 21.89 s, 1.84x. Item 1.R, before the 2.1 giant-step fixes: CI {4,3}
25.98 s, std {5,3} 21.86 s, 1.68x; {4,4} CI 26.31 s, std 23.40 s, stage ratios 1.67x / 0.64x / 1.89x.]
Paper (Lattigo, Xeon Gold 6248R, 1 core, log QP = 1064): CI 12.6 s, 20.55 bits max error; our CI is 1.76x slower
(about 1.54x at equal turbo clock) and about 2 bits less precise. Phase-0 baseline (55/60, {4,4}, default corr): CI 26.4-26.7 s, std 2 x 23.2 = 46.5 s, 1.74-1.76x, RMS 18.2
bits. Default correction factors: CI 7, std 8 (item 0.2); `corr` = 5
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
log QP <= 1100 (item 1.R): only {2,2} with 55-bit primes (56 for CI) and dnum 9 (P = 2 towers) reaches it (log QP
1060 / 1076, valid at 128-bit), but CI takes 56.6-59.4 s and std 45.0-46.1 s (2.3x / 2.1x the best sets) at CI RMS
20.2 bits, and dnum 3 at the same Q (log QP 1300) is faster. log QP is not a time lever in OpenFHE; not adopted.
Linear transforms (item 2.1): `CI_BOOT_TIMING=1` also prints one `[LT]` line per BSGS level for CI and std (diagonals,
towers, baby/giant rotations, ModUps, ModDowns, plaintext mults, adds, and the time of each). Plaintext mults equal the
diagonal count; CI giant steps now ModDown only element 1 (as std's Horner step) and the BSGS window is aligned so the
block at offset 0 needs no rotation (CI -8.6% at {4,3}). The remaining gap is 1.88x plaintext mults (inherent) and
10 vs 4 giant steps per transform; plaintext mult + add is 36% of CI CtS and 53% of CI StC.
BSGS split (item 2.2): n1 per level minimizes babies + rho(D) giants by exact counts after window alignment
(`CIPlanBsgsMinCost`, `math/ci-realfft.h`); rho = giant/baby cost = 5.2-5.8 from the 2.1 per-op times, set by the
key-switching digit count D (towers cancel). It removes 2 of 3 giants in the 30-31-diagonal lb-5 levels: CI {5,3}
23.6 -> 22.34 s, {5,4} -5.8%; lb-4 plans unchanged; +11 keys at {5,3}. `CI_BSGS_RATIO=2` gives the old plan.
Layer split (item 2.3): `CIDefaultLayerSplit` (`ckksrns-fhe.cpp`) takes the split of the FFT layers over the levels
from a table of model-best splits at 2^12..2^16 (`tools/ci-split-search.cpp`, diagonals x towers with the 2.2 BSGS
plans), even split elsewhere. At 2^16: StC lb 3 [7,5,4] (was [6,5,5]), lb 4 [6,4,3,3]; CtS lb 4 [5,3,4,4]; CtS lb 3
and lb 5 keep the even split (already model-best). CI {5,3} 22.34 -> 22.15 s and -6 keys; {4,4} -0.85 s but +31 keys;
{4,3} 23.50 -> 23.05 s. `CI_SPLIT_ENC` / `CI_SPLIT_DEC` = "n0,n1,..." force a split (layer order, F_1 first).
StC-first (item 2.5): `EvalBootstrapSetup(..., BTSlotsEncoding = true)` now gives the CI StC-first bootstrap (CI
branch of `EvalBootstrap`: StC on the input at lbDec + 2 towers, ModRaise, CtS, EvalMod; driver `stcfirst` 1 encrypts
the input at that level). It needs corr 12 (CI) / 13 (std) at 59/60, not 4 / 5. WSL 2^16 {5,3}, interleaved: CI
11.92 -> 11.67 s (-2.1%; only StC changes, 2.56 -> 2.32 s, one tower less per StC level with 2 levels after; the
gain grows with the levels after), RMS / min 21.56 / 18.48 -> 21.92 / 19.71 bits, same chain, keys (102) and usable
levels. Std's real-data StC-first runs EvalMod once instead of twice: std 12.21 -> 8.90 s, so CI/2xstd is 2.05x for
CtS-first but 1.53x with both StC-first (this session's CPU ran ~27% faster than in the 2.4 baseline; use pairs).
Driver `benchmark/src/ci-fft-boot.cpp` (args: scheme logN lbEnc lbDec scaleMod firstMod secure reps scaling corr secret [stcfirst] [dnum] [after]; the RESULT line also has `bootsetup_s`, EvalBootstrapSetup alone, since item 2.4). Baseline commands (run at every phase review; on WSL inside one `wsl-guard.sh` job, MEM_GB 15, CI and std interleaved):

    CI_BOOT_TIMING=1 OMP_NUM_THREADS=1 build-wsl/bin/benchmark/ci-fft-boot ci  16 5 3 59 60 1 3 fa 4 encap
    OMP_NUM_THREADS=1 build-wsl-bt/bin/benchmark/ci-fft-boot std 16 5 3 59 60 1 3 fa 5 encap
    # equal-budget reference for per-stage ratios (CI stages: CI_BOOT_TIMING=1; std stages: build-wsl-bt binary):
    CI_BOOT_TIMING=1 OMP_NUM_THREADS=1 build-wsl/bin/benchmark/ci-fft-boot ci  16 4 4 59 60 1 3 fa 4 encap
    OMP_NUM_THREADS=1 build-wsl-bt/bin/benchmark/ci-fft-boot std 16 4 4 59 60 1 3 fa 5 encap
    # StC-first pair (item 2.5; std StC-first is std's fastest real-data bootstrap):
    CI_BOOT_TIMING=1 OMP_NUM_THREADS=1 build-wsl/bin/benchmark/ci-fft-boot ci  16 5 3 59 60 1 3 fa 12 encap 1
    OMP_NUM_THREADS=1 build-wsl-bt/bin/benchmark/ci-fft-boot std 16 5 3 59 60 1 3 fa 13 encap 1

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
(Item 1.R: refuted. Time follows towers per key switch and diagonals per level, not log QP; see the log.)
- [x] **1.1** Sweep `SetNumLargeDigits` (dnum) in {3, 4, 5, 6} at 2^16 for CI and std; record log P, key size,
  time, precision (add a driver argument for dnum).
- [x] **1.2** Per-stage prime sizes as in the paper (EvalMod ~60-bit, StC ~40-bit, 3 usable levels after
  bootstrap): evaluate FIXEDMANUAL with mixed prime sizes vs FLEXIBLEAUTO uniform 55 (OpenFHE has no
  per-stage scale; only build one if the numbers show it pays). Record log QP, time, precision.
- [x] **1.3** Budget sweep with the best parameters from 1.1-1.2: {4,3}, {5,3}, {5,4}, {5,5} for CI and std
  (CtS budget first in OpenFHE's order; the paper's best is StC 3 + CtS 4).
- [x] **1.R** Phase 1 review. Done when: a 128-bit parameter set with log QP <= ~1100 is found (or the reason it
  cannot be is recorded), both schemes re-measured, CI/2xstd ratio and absolute CI time vs the paper's 12.6 s
  logged. Update the baseline commands in this file if the parameters change.

## Phase 2: linear-transform cost (gap 1)
Measured at 2^16 (same N, warm, 1 thread): CI CtS = 1.64x std CtS ({4,4}), CI StC = 1.88x std StC, CI EvalMod
= 0.64x (std runs EvalMod twice). The real factorization inherently needs ~2x the plaintext multiplications
and ~sqrt(2)x the rotations of the complex one (~1.5-1.7x), so CtS is near the bound and StC has slack.
- [x] **2.1** Instrument: count key switches and plaintext multiplications per level (CI) and in std's
  `EvalCoeffsToSlots` at the same N; compare with 2*sqrt(#diagonals) + #diagonals. Any excess is a bug to fix
  before tuning.
- [x] **2.2** Per-level BSGS ratio from a cost model (hoisted baby rotation vs giant rotation at that level's
  limb count) instead of the global 2.0; verify at 2^16.
- [x] **2.3** Uneven layer splits: search splits (e.g. [6,5,5] vs [7,5,4] vs [5,6,5]) with a (diagonals x limbs)
  cost model; measure the top 3 at 2^16.
- [x] **2.4** Precompute the diagonal plaintexts in `EvalBootstrapSetup` (remove the ~70 s cold run and the write
  into the precom from a const `EvalBootstrap`; parallel encodes at setup; extended QlP form as now).
- [x] **2.5** StC-first CI variant (the paper's ordering): CI branch in `EvalBootstrapStCFirst` (StC at the
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
