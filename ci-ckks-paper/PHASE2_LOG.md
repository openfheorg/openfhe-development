# Phase 2 execution log

One entry per plan item (newest last): item ID, date, what changed, commands run on ICELAKE, results, commit.

## 0.1 Guard REAL_CI against the StC-first (BTSlotsEncoding) path (2026-10-27)

**Change.** The CI bootstrap exists only in the CtS-first `EvalBootstrap`; `EvalBootstrapStCFirst` has no CI
branch, so `REAL_CI` with `BTSlotsEncoding = true` would have run the complex StC-first pipeline on CI data.
Chose "throw" (routing to CtS-first silently would ignore the caller's request; a CI StC-first branch is item 2.5).
- `EvalBootstrapSetup`: throws when `BTSlotsEncoding && REAL_CI` (before any precomputation is stored).
- `EvalBootstrapStCFirst`: throws at entry for `REAL_CI` ciphertexts. This also covers the dispatch from
  `EvalBootstrap` through a precomputation that has `BTSlotsEncoding = true` from another source
  (e.g. deserialized) and direct calls of `EvalBootstrapStCFirst`.
- `EvalFEFuncBootstrapSetup`: throws for `REAL_CI` (it forces `BTSlotsEncoding = true` and runs StC-first).
- Header doc of `EvalBootstrapSetup` notes the restriction.
- Driver `benchmark/src/ci-fft-boot.cpp`: optional 12th argument `stcfirst` (0 = CtS-first, default;
  1 = setup with `BTSlotsEncoding = true`; 2 = call `EvalBootstrapStCFirst` directly). Defaults unchanged,
  so the baseline commands are unaffected. The unit test for the guard is item 6.4.

**Commands (ICELAKE, `~/ci-ckks-fft`).**

    ./guard.sh p01_build "cd openfhe-development/build && cmake --build . --target ci-fft-boot -j 32"
    ./guard.sh p01_guard "cd openfhe-development && for a in 'ci 0' 'ci 1' 'ci 2' 'std 1'; do set -- $a; \
      OMP_NUM_THREADS=1 build/bin/benchmark/ci-fft-boot $1 12 3 3 59 60 0 1 fm 0 uniform $2; done"

**Results** (N = 2^12, insecure, FIXEDMANUAL, uniform, {3,3}, 1 thread; a correctness check, not a timing run):

| Run | Outcome |
|---|---|
| `ci ... 0` (CtS-first) | bootstraps as before: RMS 14.12 bits, min 12.17 bits, 47 Galois keys, output level 20 |
| `ci ... 1` (setup with BTSlotsEncoding) | throws in `EvalBootstrapSetup`: "BTSlotsEncoding (StC-first bootstrapping) is not supported for the REAL_CI data type; use BTSlotsEncoding = false (CtS-first native CI bootstrapping)." |
| `ci ... 2` (direct `EvalBootstrapStCFirst`) | throws in `EvalBootstrapStCFirst`: "EvalBootstrapStCFirst (BTSlotsEncoding) is not supported for the REAL_CI data type; ..." |
| `std ... 1` | passes setup and the guard and enters std StC-first (it then stops with OpenFHE's own "Not enough levels to perform Bootstrapping", because the driver encrypts at the CtS-first level); std is not blocked by the guard |

**Conclusion.** `REAL_CI` + `BTSlotsEncoding` now fails early with a clear message at setup, and every other
route into the StC-first code with CI data is blocked at its entry. CtS-first CI output is unchanged
(RMS 14.12 bits at 2^12, as in `CI_FFT_REVIEW.md` table 3.2). Item 2.5 removes the `EvalBootstrapStCFirst`
guard if it adds a CI StC-first branch.

## 0.2 Revert the CI correction-factor change; sweep the correction factor (2026-10-27)

**Change.**
- `EvalBootstrapSetup` (`ckksrns-fhe.cpp`): removed `cfSlots = N/2`. The FIXED* branch is back to OpenFHE's fit
  with the actual slot count (CI not measured there). The FLEXIBLE* branch now uses this CI default, based
  on the data below: OpenFHE's fit at the complex-equivalent slot count N/2, minus 1, clamped to [7, 14].
  This gives 7 at 2^16 (the same as the plain revert) and 7 at 2^15 (the plain revert gives 8). std is
  unchanged (8 at 2^15 and 2^16).
- Driver: the RESULT line also prints `corrEff` (the factor actually used, `GetCKKSBootCorrectionFactor()`).

**Commands (ICELAKE, `~/ci-ckks-fft`).**

    ./guard.sh p02_build "cd openfhe-development/build && cmake --build . --target ci-fft-boot -j 32"
    ./guard.sh p02_sweep "cd openfhe-development && for s in ci std; do for c in 5 6 7 8 9; do \
      OMP_NUM_THREADS=1 build/bin/benchmark/ci-fft-boot $s 16 4 4 55 60 1 1 fa $c encap; done; done"
    # side checks (insecure: 2^15 and the uniform-secret chain are not 128-bit with this chain)
    ./guard.sh p02_sweep3 "cd openfhe-development && for a in 'ci 15 6 encap' ... 'std 16 8 uniform'; do set -- $a; \
      OMP_NUM_THREADS=1 build/bin/benchmark/ci-fft-boot $1 $2 4 4 55 60 0 1 fa $3 $4; done"
    ./guard.sh p02_build2 "cd openfhe-development/build && cmake --build . --target ci-fft-boot -j 32"
    ./guard.sh p02_base "cd openfhe-development && <the two baseline commands> && \
      OMP_NUM_THREADS=1 build/bin/benchmark/ci-fft-boot {ci,std} 15 4 4 55 60 0 1 fa 0 encap"

(`p02_sweep2` was the same as `p02_sweep3` with secure=1. Every run threw "ring dimension does not comply with HE
standards", so it gave no data.)

**Results 1: main sweep** (2^16, 128-bit, FLEXIBLEAUTO, encap, {4,4}, 1 thread, reps 1). The reverted code is
used, so the default factor is not involved. The bits are RMS / min.

| corr | CI RMS | CI min | CI warm s | std RMS | std min | std warm s |
|---|---|---|---|---|---|---|
| 5 | **20.22** | 17.06 | 26.37 | **21.21** | 18.76 | 23.24 |
| 6 | 19.23 | 15.79 | 26.56 | 20.24 | 17.37 | 23.19 |
| 7 | 18.23 | 14.88 | 26.63 | 19.22 | 16.82 | 23.19 |
| 8 | 17.24 | 13.88 | 26.48 | 18.24 | 15.74 | 23.12 |
| 9 | 16.24 | 12.86 | 26.61 | 17.23 | 14.66 | 23.07 |

**Results 2: side checks** (insecure, otherwise the same; RMS bits).

| config | CI c=5 | CI c=6 | CI c=7 | CI c=8 | std c=5 | std c=6 | std c=7 | std c=8 |
|---|---|---|---|---|---|---|---|---|
| 2^15 encap | - | 22.98 | 22.00 | 20.99 | - | - | 23.39 | 22.38 |
| 2^16 uniform | 13.87 | 12.85 | 11.77 | 10.89 | 15.57 | 14.46 | 13.52 | 12.53 |

**Results 3: baseline commands after the change** (reps 2; `corr` = 0, which means the default).

| Run | corrEff | warm median s | RMS bits | min bits | Galois keys | setup+keygen s | peak RSS GB |
|---|---|---|---|---|---|---|---|
| `ci 16 4 4 55 60 1 2 fa 0 encap` | 7 | 26.31 | 18.23 | 14.61 | 70 | 35.2 | 11.39 |
| `std 16 4 4 55 60 1 2 fa 0 encap` | 8 | 22.96 (x2 = 45.92) | 18.23 | 15.69 | 76 | 43.2 | 9.08 |
| `ci 15 ... 0 1 fa 0 encap` (insecure) | 7 | 11.91 | 22.00 | 18.97 | 64 | 15.9 | 5.09 |
| `std 15 ... 0 1 fa 0 encap` (insecure) | 8 | 10.70 | 22.39 | 19.99 | 78 | 21.3 | 4.55 |

The speedup is 45.92 / 26.31 = 1.75x and RMS is 18.23 bits for both. The plan's baseline (26.3 s, 45.9 s,
1.74x, 18.2 bits) stands.

**Conclusions.**
- The precision of both schemes falls by about 1.0 bit for each step up in the correction factor. This holds
  across the whole range at 2^16 encap, at 2^15 and with the uniform secret. The best value is the minimum
  allowed value, `corr = deg = firstMod - scaleMod = 5` (no correction). A lower value throws in
  `EvalBootstrap`. In this regime the noise amplification dominates, not the EvalMod approximation error.
  The correction factor does not change the time (spread < 1%).
- At an equal factor, CI is 1.0 bit below std at 2^16 encap, 1.4 bits at 2^15 encap and 1.7 bits at 2^16 uniform.
  With one step less, CI is within 0.0 / 0.4 / 0.6-0.8 bits of std. That is the basis for the CI default:
  "std fit at N/2 complex slots, minus 1". The reverted `cfSlots` rule did the opposite: it raised CI to 8 at
  2^16 and cost 1 bit.
- std keeps OpenFHE's default. The +3 bits at corr = 5 are consistent, but they were measured only with one
  chain shape (deg = 5). OpenFHE's fit was made for a different deg. Changing the upstream default is outside
  this item.
- The defaults stay in the baseline commands, so the comparison is CI 7 vs std 8, at equal precision (18.23).
  For precision tables, `corr 5` for both schemes gives CI 20.2 / std 21.2 bits RMS at the same time. Phase 1
  changes the prime sizes (and thus deg), so it should re-check this.

## 0.3 One unscaled cache of the CI real-FFT levels; bootstrap scalars applied at encode time (2026-10-27)

**Change** (`src/pke/lib/scheme/ckksrns/ckksrns-fhe.cpp`, CI code only).
- `CIBuildRealLevels(N, lbEnc, lbDec)` no longer takes `scaleEnc` / `scaleDec`. The stored levels hold only
  the fixed constants: N/sqrt(2N) (CtS) and sqrt(2N) (StC), spread evenly over the levels, and the sigma
  row/column scale on the outermost level.
- `GetCIRealLevels(N, lbEnc, lbDec)`: the cache key is now (N, lbEnc, lbDec). Before, it was
  (N, lbEnc, lbDec, scaleEnc, scaleDec). Keygen (`CIRealFFTGaloisElements`, which used (1.0, 1.0)) and
  evaluation now share one entry. Before, each held a full copy.
- `applyReal(..., scale)` computes the per-level scalar `CIRealLevelScalar(scale, #levels) = scale^(1/#levels)`.
  `applyCISparse(..., sc)` multiplies each diagonal value by `sc` when it encodes the plaintext. The product
  over the levels is the same as before: pow(scale * c0, 1/r) = pow(scale, 1/r) * pow(c0, 1/r), up to
  rounding. The sparsity pattern is unchanged, because the scalars were applied after `CISparseMul` before too.
- The dense {1,1} path (`applyCILT`) was not cached and is unchanged. std is unchanged.

**Commands (ICELAKE, `~/ci-ckks-fft`).**

    # before (binary built from 611b54ba in item 0.2)
    ./guard.sh p03_before "cd openfhe-development && CI_BOOT_TIMING=1 OMP_NUM_THREADS=1 \
      build/bin/benchmark/ci-fft-boot ci 16 4 4 55 60 1 2 fa 0 encap"
    ci-ckks-paper/tools/sync.sh   # (on WSL)
    ./guard.sh p03_build "cd openfhe-development/build && cmake --build . --target ci-fft-boot -j 32"
    ./guard.sh p03_after "cd openfhe-development && CI_BOOT_TIMING=1 OMP_NUM_THREADS=1 \
      build/bin/benchmark/ci-fft-boot ci 16 4 4 55 60 1 2 fa 0 encap && \
      OMP_NUM_THREADS=1 build/bin/benchmark/ci-fft-boot ci 12 3 3 59 60 0 1 fm 0 uniform"

**Results** (CI baseline command: 2^16, 128-bit, FLEXIBLEAUTO, encap, {4,4}, 1 thread, reps 2).

| Run | peak RSS GB | warm median s | CtS / EvalMod / StC s (warm) | RMS bits | min bits | Galois keys | setup+keygen s |
|---|---|---|---|---|---|---|---|
| before (two cache entries) | 11.39 | 26.42 | 13.72 / 7.73 / 4.41 | 18.22 | 15.02 | 70 | 35.3 |
| after (one cache entry) | **11.19** | 26.42 | 13.73 / 7.74 / 4.39 | 18.23 | 14.97 | 70 | 35.8 |

The per-level diagonal counts (`CI_BOOT_TIMING`) are enc 16/62/62/63 and dec 63/62/62/16, so 406 diagonals
in total. One copy of the levels is 406 x 65,536 x 8 B = 213 MB (0.20 GiB). This equals the measured drop
of 0.20 in peak RSS.

Correctness check at 2^12 (insecure, FIXEDMANUAL, uniform, {3,3}; real-FFT path): RMS 14.23 bits, min
12.34 bits, 47 Galois keys. Item 0.1 measured 14.12 / 12.17 / 47. The input vector is fixed (seed 2026),
but the keys and the encryption noise are random, so a variation of about 0.1-0.2 bits is expected. At 2^16
the before/after RMS agree to 0.01 bit.

**Conclusion.** There is one unscaled cache entry per (N, lbEnc, lbDec). Peak RSS at 2^16 {4,4} falls from
11.39 to 11.19 GB, which is exactly one copy of the levels. Time, precision and the Galois key set are
unchanged. The baseline numbers in the plan header stand.

## 0.4 Relative drop threshold in `CISparseMul`; keygen/evaluator Galois-set assertion (2026-10-27)

**Change.**
- `CISparseMul` (`src/core/lib/math/ci-realfft.cpp`): a diagonal of C = A * B is dropped when its max |entry|
  is <= 1e-13 x the largest entry of C. Before, the rule was max |entry| < 1e-13 (absolute). The header
  comment states the rule.
- `CIRealFFTGaloisElements` (keygen, `ckksrns-fhe.cpp`): the set is now derived from the nonzero diagonals.
  For each offset k = h * (t0 + n1 * j + i) it adds the baby shift h * i (i > 0) and the giant shift
  h * (t0 + n1 * j) (when nonzero). Before, it added all baby shifts 1..n1-1 and all giant blocks, used or not.
- `EvalBootstrap` (CI real-FFT path): `applyCISparse` records the Galois element of every rotation that it
  performs (baby rotations of used residue classes, giant rotations of non-empty blocks). After StC, the
  recorded set is compared with `CIRealFFTGaloisElements(N, lbEnc, lbDec)`. If they differ,
  `OPENFHE_THROW` reports the two sizes and the counts "used but not generated" / "generated but unused".
  The check runs at each bootstrap (cost: one pass over the cached level keys). With `CI_BOOT_TIMING=1` it
  prints `[CI-BT] Galois check: R rotations == keygen set`. A mismatch can come from, for example, a
  different `CI_BSGS_RATIO` at keygen and at evaluation.
- New tool `ci-ckks-paper/tools/ci-sparse-margin.cpp` (standalone, links only `ci-realfft.cpp`): for every
  intermediate level product, it prints the smallest kept and the largest dropped diagonal max relative to the
  largest entry, and the number of diagonals on which the absolute and relative rules disagree.

**Commands (ICELAKE, `~/ci-ckks-fft`).**

    ci-ckks-paper/tools/sync.sh   # (on WSL)
    ./guard.sh p04_margin "cd openfhe-development && g++ -O2 -std=c++17 -Isrc/core/include \
      ci-ckks-paper/tools/ci-sparse-margin.cpp src/core/lib/math/ci-realfft.cpp -o ../scratch/ci-sparse-margin \
      && ../scratch/ci-sparse-margin"
    # before (binary from adf8752e), then after the -j 32 build; 2^16 is 128-bit, 2^12..2^15 insecure
    ./guard.sh p04_before "cd openfhe-development && for n in 12 13 14 15 16; do s=0; [ \$n = 16 ] && s=1; \
      for b in 2 3 4; do OMP_NUM_THREADS=8 build/bin/benchmark/ci-fft-boot ci \$n \$b \$b 55 60 \$s 0 fa 0 encap; done; done"
    ./guard.sh p04_build "cd openfhe-development/build && cmake --build . --target ci-fft-boot -j 32"
    ./guard.sh p04_after "<same loop as p04_before, with CI_BOOT_TIMING=1>"
    ./guard.sh p04_base "cd openfhe-development && CI_BOOT_TIMING=1 OMP_NUM_THREADS=1 \
      build/bin/benchmark/ci-fft-boot ci 16 4 4 55 60 1 2 fa 0 encap"

The sweep is a correctness check, not a timing run (8 threads, reps 0: only the first bootstrap, which builds
the plaintexts). ICELAKE had other users' load during the sweep (load average 3-9).

**Results 1: drop-threshold margin** (`ci-sparse-margin`, all intermediate products of the level split).

| logN | {2,2} diags | {3,3} diags | {4,4} diags | min kept / largest entry | max dropped / largest | abs vs rel disagree |
|---|---|---|---|---|---|---|
| 12 | 64/255 | 16/62/63 | 8/30/30/31 | 0.356 / 0.364 / 0.395 | 0 | 0 |
| 13 | 128/255 | 32/62/63 | 16/30/30/31 | 0.356 / 0.364 / 0.395 | 0 | 0 |
| 14 | 128/511 | 32/126/63 | 16/62/30/31 | 0.356 / 0.364 / 0.395 | 0 | 0 |
| 15 | 256/511 | 32/126/127 | 16/62/62/31 | 0.356 / 0.364 / 0.395 | 0 | 0 |
| 16 | 256/1023 | 64/126/127 | 16/62/62/63 | 0.354 / 0.364 / 0.364 | 0 | 0 |

No product creates a diagonal that is zero up to round-off: every diagonal that appears has a max entry of at
least 0.35 x the largest entry, and no diagonal is dropped by either rule. The library `CISparseMul` gave the
same pattern as the tool at every step (no MISMATCH line). So the relative rule does not change the levels
today. It makes the rule independent of the scale of the factors (for example if a scalar is folded into the
factors before the product), and the margin between kept (>= 0.35) and dropped (<= 1e-13) is about 12 orders.

**Results 2: Galois-set assertion** (CI, FLEXIBLEAUTO 55/60, encap, first bootstrap; keys = automorphism key
map size, which includes the 2 encapsulation keys; RMS bits of the first bootstrap).

| logN | budget | keys before | keys after | rotations == keygen set | RMS before | RMS after |
|---|---|---|---|---|---|---|
| 12 | {2,2} | 58 | 58 | 56 | 18.44 | 18.43 |
| 12 | {3,3} | 49 | 49 | 47 | 18.47 | 18.53 |
| 12 | {4,4} | 46 | 46 | 44 | 18.48 | 18.50 |
| 13 | {2,2} | 67 | 67 | 65 | 19.41 | 19.43 |
| 13 | {3,3} | 54 | 54 | 52 | 19.41 | 19.43 |
| 13 | {4,4} | 48 | 48 | 46 | 19.43 | 19.42 |
| 14 | {2,2} | 85 | 85 | 83 | 19.24 | 19.23 |
| 14 | {3,3} | 65 | 65 | 63 | 19.21 | 19.23 |
| 14 | {4,4} | 56 | 56 | 54 | 19.23 | 19.25 |
| 15 | {2,2} | 96 | 96 | 94 | 22.24 | 22.26 |
| 15 | {3,3} | 74 | 74 | 72 | 22.12 | 22.10 |
| 15 | {4,4} | 64 | 64 | 62 | 22.00 | 22.00 |
| 16 (128-bit) | {2,2} | 118 | 118 | 116 | 18.23 | 18.24 |
| 16 (128-bit) | {3,3} | 79 | 79 | 77 | 18.24 | 18.23 |
| 16 (128-bit) | {4,4} | 70 | 70 | 68 | 18.24 | 18.23 |

The assertion holds in all 15 configurations (all 15 runs printed the check line and a RESULT line, rc = 0).
The key counts are unchanged, so the old keygen also generated no unused keys: every baby residue class and
every giant block of these levels holds a nonzero diagonal. First-bootstrap times are within the noise of
the shared machine (2^16 {4,4}: 17.9 s before, 18.9 s after, 8 threads; the 1-thread run below shows no change).
Peak RSS at 2^16: {2,2} 32.8 GB, {3,3} 13.4 GB, {4,4} 11.0 GB (8 threads, reps 0).

**Results 3: CI baseline command** (`ci 16 4 4 55 60 1 2 fa 0 encap`, 1 thread, reps 2).

| Run | warm median s | CtS / EvalMod / StC s (warm) | RMS bits | min bits | Galois keys | setup+keygen s | peak RSS GB |
|---|---|---|---|---|---|---|---|
| 0.3 (adf8752e) | 26.42 | 13.73 / 7.74 / 4.39 | 18.23 | 14.97 | 70 | 35.8 | 11.19 |
| 0.4 | 26.55 | 13.76 / 7.80 / 4.42 and 13.58 / 7.81 / 4.42 | 18.23 | 14.58 | 70 | 35.7 | 11.19 |

The median of 2 reps is the larger rep. The difference (+0.5%) is within noise; the load average was about 9
during the run.

**Conclusion.** `CISparseMul` now uses a scale-invariant drop rule. On the actual factors it gives the same
pattern as the absolute rule, with a margin of about 12 orders of magnitude. Keygen derives the Galois set
from the nonzero diagonals, and `EvalBootstrap` checks at each call that its rotations are exactly that set.
The check holds at 2^12..2^16 for {2,2}, {3,3}, {4,4}. The key counts, precision, time and memory are
unchanged, so the baseline numbers in the plan header stand. A negative test (forced mismatch) belongs to
the key-set unit test of item 6.4.
