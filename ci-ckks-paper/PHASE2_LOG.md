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

## 0.5 Review section 4 item 2 restated as an EvalMod cost item (2026-10-27)

**Change.** `CI_FFT_REVIEW.md` section 4 item 2 said that sparse encapsulation costs CI precision and that a
K ~ 23 table would recover bits. That is wrong: CI and std have the same RMS at 2^16 (18.24 / 18.23 bits,
Table 3.1). The item now describes a cost: CI uses the K = 28 sine table (degree 48) because a weight-32 CI
key acts like a weight-64 power-basis key, while std uses K = 16 (degree 36). Section 7 issue 6 is marked done.
No library code changed in this commit.

**Code facts (from the source).**
- `g_coefficientsSparse` has 49 coefficients (degree 48), `g_coefficientsSparseEncapsulated` has 37 (degree 36).
- `GetDepthByDegree`: degrees 28..59 all have depth 7, so both tables have depth 7 + R_SPARSE = 3 = 10.
  `GetModDepthInternal` already budgets the degree-48 table for every sparse secret, so the chain does not
  change. The CI depth is 20 with either table.
- `ComputeDegreesPS`: (k, m) = (6, 3) for degree 36 and (7, 3) for degree 48 (one more power T_k, and
  longer leaf linear sums).

**Measurement (quick, temporary).** To give the cost a number, a temporary env switch `CI_SINE_K16` made the
CI path use K = 16 (both `GetModRaiseOverflowBound` and the coefficient table). It was reverted before this
commit, and ICELAKE was rebuilt from the committed source. K = 16 with this key is a cost probe only; whether
it is sound (overflow probability, security of a weight-16 CI key) is item 3.1.

**Commands (ICELAKE, `~/ci-ckks-fft`).**

    ci-ckks-paper/tools/sync.sh   # (on WSL, with the temporary switch)
    ./guard.sh p05_build "cd openfhe-development/build && make -j 32 ci-fft-boot"
    ./guard.sh p05_time "cd openfhe-development && export OMP_NUM_THREADS=1 CI_BOOT_TIMING=1; \
      echo === K28; /usr/bin/time -v build/bin/benchmark/ci-fft-boot ci 16 4 4 55 60 1 2 fa 0 encap; \
      echo === K16; CI_SINE_K16=1 /usr/bin/time -v build/bin/benchmark/ci-fft-boot ci 16 4 4 55 60 1 2 fa 0 encap"
    # switch reverted on WSL, ci-ckks-paper/tools/sync.sh, then:
    ./guard.sh p05_rebuild "cd openfhe-development/build && make -j 32 ci-fft-boot"   # rc 0, SYNCED_FROM c733491d 0

**Results** (CI, 2^16, 128-bit, encap, {4,4}, FLEXIBLEAUTO 55/60, 1 thread, reps 2; load average about 4-5).

| Sine table | EvalMod s (cold / warm / warm) | CtS / StC s (warm) | warm median s | RMS bits | min bits | depth | log2 Q + P | peak RSS GB |
|---|---|---|---|---|---|---|---|---|
| K = 28, degree 48 (current) | 7.89 / 7.83 / 7.79 | 13.82 / 4.45 and 13.51 / 4.41 | 26.66 | 18.23 | 14.82 | 20 | 1160 + 420 | 11.19 |
| K = 16, degree 36 (probe) | 6.83 / 6.82 / 6.82 | 13.76 / 4.41 and 13.58 / 4.39 | 25.56 | 18.23 | 14.76 | 20 | 1160 + 420 | 11.19 |

The degree-48 table costs 1.0 s of CI EvalMod (13%) and 1.1 s of the whole bootstrap (4%). CtS, StC, depth,
modulus, keys (70) and memory are the same. RMS is the same, so the larger table does not cost precision.

**Conclusion.** The report now states the gap correctly: it is a cost of about 1 s (4% of the CI bootstrap)
at 2^16 {4,4}, at the same depth and precision. This bounds what item 3.1 can gain: about 1 s of the 26.7 s.
For reference, with K = 16 the CI EvalMod (6.82 s for 65,536 reals) is 0.28x two std EvalMods (2 x 12.0 s).
The baseline numbers in the plan header are unchanged.

## 0.R Phase 0 review: build and baseline on ICELAKE (2026-10-27)

**State.** Source synced from commit 8dbcae45 (the end of phase 0; items 0.1-0.6 done; `SYNCED_FROM 8dbcae45 0`).
No code changed in this item.

**Commands (ICELAKE, `~/ci-ckks-fft`).**

    ci-ckks-paper/tools/sync.sh   # (on WSL)
    ./guard.sh p0R_build "cd openfhe-development/build && cmake --build . -j 32 && \
      cd ../build-bt && cmake --build . --target ci-fft-boot -j 32"                       # rc 0, no warnings
    ./guard.sh p0R_base "cd openfhe-development && export OMP_NUM_THREADS=1; \
      CI_BOOT_TIMING=1 /usr/bin/time -v build/bin/benchmark/ci-fft-boot ci 16 4 4 55 60 1 2 fa 0 encap && \
      /usr/bin/time -v build/bin/benchmark/ci-fft-boot std 16 4 4 55 60 1 2 fa 0 encap && \
      build-bt/bin/benchmark/ci-fft-boot std 16 4 4 55 60 1 2 fa 0 encap"
    # p0R_base2: the same three runs in the order std, std (build-bt), ci, after the machine was quiet again

`build` (all targets: the libraries and all benchmarks; unit tests are not configured there) and `build-bt`
(`-DBOOTSTRAPTIMING`, target `ci-fft-boot`) both built with rc 0.

**Interference in the first timing job.** During `p0R_base`, another user's 50-core job started while the std
runs were in progress (load average 5 -> 22 -> 46). The CI run finished before that (load 5-8). The std runs
are invalid: warm median 29.37 s, which is more than the first (cold) bootstrap at 23.49 s, and the `build-bt`
std stages were 12.7 / 15.8 / 4.2 s. I waited until the load average was below 8 (about 30 minutes) and ran
`p0R_base2`. Its load average was 2.9-5.9 for the whole job. Only the std numbers of `p0R_base` are discarded.

**Results 1: baseline commands** (N = 2^16, 128-bit, FLEXIBLEAUTO 55/60, encap, {4,4}, 1 thread, reps 2;
depth 20, log2 Q + P = 1160 + 420 for both).

| Run | corrEff | first (cold) s | warm median s | RMS bits | min bits | p99 bits | Galois keys | setup+keygen s | peak RSS GB | output level / towers |
|---|---|---|---|---|---|---|---|---|---|---|
| ci (`p0R_base`) | 7 | 46.91 | 26.44 | 18.24 | 15.03 | 16.41 | 70 | 35.7 | 11.19 | 18 / 3 |
| ci (`p0R_base2`) | 7 | 47.06 | 26.73 | 18.23 | 14.72 | 16.42 | 70 | 35.5 | 11.19 | 18 / 3 |
| std (`p0R_base2`) | 8 | 23.41 | 23.23 | 18.23 | 15.41 | 16.77 | 76 | 43.4 | 9.08 | 17 / 4 |
| std, `build-bt` (`p0R_base2`) | 8 | 23.72 | 23.34 | 18.24 | 15.32 | 16.77 | 76 | 43.2 | 9.08 | 17 / 4 |

Two std bootstraps: 2 x 23.23 = 46.46 s. Speedup (two std / one CI): 46.46 / 26.44 = 1.76x and
46.46 / 26.73 = 1.74x. Time per real slot: CI 403-408 us, std 709 us. `/usr/bin/time -v`: peak RSS
11.73 GB (CI) and 9.52 GB (std) in decimal kB (the driver prints GiB); wall time 2:18 (CI) and 1:55 (std).

**Results 2: per-stage times, warm runs** (CI from `CI_BOOT_TIMING`, std from `-DBOOTSTRAPTIMING`; s).

| Stage | std, per bootstrap (3 runs) | CI (`p0R_base`, 2 warm) | CI (`p0R_base2`, 2 warm) | CI / std (one CI vs one std) |
|---|---|---|---|---|
| CtS | 8.49 / 8.36 / 8.33 | 13.73 / 13.52 | 13.85 / 13.63 | 1.63 |
| EvalMod | 12.30 / 12.15 / 12.18 | 7.76 / 7.76 | 7.86 / 7.85 | 0.64 |
| StC | 2.46 / 2.38 / 2.37 | 4.39 / 4.40 | 4.45 / 4.47 | 1.86 |

(Ratios use the medians: std 8.36 / 12.18 / 2.38, CI 13.68 / 7.81 / 4.42.) CI per-level times (warm,
`p0R_base2`): CtS levels 0-3 = 1.60 / 4.10 / 3.92 / 3.76 s (16 / 62 / 62 / 63 diagonals, 20 -> 17 towers);
StC levels 0-3 = 1.46 / 1.33 / 1.21 / 0.39 s (63 / 62 / 62 / 16 diagonals, 7 -> 4 towers). The Galois check
of item 0.4 printed "68 rotations == keygen set" at every bootstrap.

The first CI bootstrap costs 47 s, 20.5 s more than a warm one: CtS 26.6 s and StC 11.7-11.9 s cold, EvalMod
unchanged. This is the diagonal-plaintext encoding that item 2.4 moves to setup. std has no such cold cost
(first 23.4 s, warm 23.2 s).

**Comparison with the plan's baseline (item 0.2 measurement).**

| Quantity | plan header (0.2) | 0.R |
|---|---|---|
| CI warm median | 26.3 s | 26.44 / 26.73 s |
| CI CtS / EvalMod / StC | 13.6 / 7.6 / 4.4 s | 13.7 / 7.8 / 4.4 s |
| two std bootstraps | 45.9 s | 46.5 s |
| std CtS / EvalMod / StC | 8.26 / 12.0 / 2.35 s | 8.36 / 12.18 / 2.38 s |
| speedup | 1.74x | 1.74-1.76x |
| RMS bits | 18.2 / 18.2 | 18.23-18.24 / 18.23-18.24 |
| Galois keys CI / std | 70 / 76 | 70 / 76 |
| peak RSS CI / std | 11.39 / 9.08 GB | 11.19 / 9.08 GB (item 0.3) |

**Conclusions.**
- Phase 0 is complete. Both trees build on ICELAKE from the phase-0 head, and the baseline commands run with
  the expected keys, depth, modulus and precision.
- The numbers are within 1-2% of the item-0.2 baseline. All runs after 0.2 put the CI bootstrap at
  26.4-26.7 s (0.3: 26.42, 0.4: 26.55, 0.5: 26.66, here 26.44 / 26.73). The 26.3 s of 0.2 was at the low end,
  and the difference is machine noise, not a code change. The plan header now gives the 0.R numbers.
- Phase 0 did not change speed: none of 0.1-0.5 changed the transforms or EvalMod. It did change the CI
  default correction factor (kept at 7 at 2^16; 0.2), CI peak RSS (-0.20 GB; 0.3), and keygen/evaluator
  consistency (0.4).
- The gaps for the next phases are unchanged: CI CtS = 1.63x std CtS and CI StC = 1.86x std StC (phase 2);
  absolute CI time 26.4-26.7 s vs the paper's 12.6 s with log QP 1580 vs 1064 (phase 1).

## 1.1 Sweep of the number of key-switching digits (dnum) at 2^16 (2026-10-27)

**Change.** `benchmark/src/ci-fft-boot.cpp` takes an optional 13th argument `dnum` (0 = OpenFHE default, which is
3 here) and calls `SetNumLargeDigits(dnum)`. The RESULT line also prints `dnum` and `alpha` (towers per digit, as
OpenFHE computed them), `towersP`, `keyMB` (the size of one rotation key) and `keysGB` (all switching keys: the
automorphism map, which also holds the two sparse-encapsulation keys, plus the relinearization key). Key sizes
count N x 8 bytes per tower, so they are the in-memory sizes. The baseline commands are unchanged (no 13th
argument means dnum 3). No library code changed.

**Commands (ICELAKE, `~/ci-ckks-fft`, source `SYNCED_FROM 9b07eecf` + this driver change).**

    ci-ckks-paper/tools/sync.sh   # (on WSL)
    ./guard.sh p11_build    "cd openfhe-development/build    && cmake --build . --target ci-fft-boot -j 32"   # rc 0
    ./guard.sh p11_build_bt "cd openfhe-development/build-bt && cmake --build . --target ci-fft-boot -j 32"   # rc 0
    ./guard.sh p11_smoke "..."   # 2^12 insecure {3,3} with `ci 12 3 3 55 60 0 1 fa 0 encap 0 $d`, and one std run
    # p11_sweep, then p11_sweep2 (the same loop again, without d = 2):
    ./guard.sh p11_sweep "cd openfhe-development && export OMP_NUM_THREADS=1; for d in 2 3 4 5 6 7; do \
      CI_BOOT_TIMING=1 build/bin/benchmark/ci-fft-boot ci 16 4 4 55 60 1 2 fa 0 encap 0 \$d; \
      build-bt/bin/benchmark/ci-fft-boot std 16 4 4 55 60 1 2 fa 0 encap 0 \$d; done"
    ./guard.sh p11_std3 "cd openfhe-development && export OMP_NUM_THREADS=1; \
      build-bt/bin/benchmark/ci-fft-boot std 16 4 4 55 60 1 2 fa 0 encap 0 3"      # rerun of an outlier
    ./guard.sh p11_dnum2 "cd openfhe-development && export OMP_NUM_THREADS=1 && \
      CI_BOOT_TIMING=1 build/bin/benchmark/ci-fft-boot ci 16 4 4 55 60 0 2 fa 0 encap 0 2 && \
      build-bt/bin/benchmark/ci-fft-boot std 16 4 4 55 60 0 2 fa 0 encap 0 2"     # dnum 2, security check off
    ./guard.sh p11_dnum2ci "..."  # the ci run of p11_dnum2 again (load rose to 20 during the first one)

All jobs ended with rc 0. The jobs before `p11_dnum2` ran in an earlier session that the host restart killed
before it could log them. The loops above are reconstructed from the command lines that the aborted runs echo
in `p11_sweep.log` and from the RESULT fields. The logs are in `~/ci-ckks-fft/logs/p11_*.log`. CI ran from
`build` (with `CI_BOOT_TIMING=1`). std ran from `build-bt` (`-DBOOTSTRAPTIMING`, per-stage times). Item 0.R showed
that the two std binaries agree within 0.5%.

**Smoke test** (`p11_smoke`, 2^12, insecure, {3,3}, 19 Q towers). The argument reaches OpenFHE: default -> dnum 3
(alpha 7, log P 420), dnum 2 -> alpha 10, log P 600, std dnum 5 -> alpha 4. dnum 6 and 21 throw OpenFHE's
"Can't appropriately distribute 19 towers into 6 (21) digits". OpenFHE rejects a dnum when alpha =
ceil(towers / dnum) leaves the last digit empty (towers <= alpha x (dnum - 1)). RMS stayed at 18.4-18.5 bits (CI).

**dnum 2 at 128-bit is not possible with this chain.** In `p11_sweep`, dnum 2 threw in
`ParamsGenCKKSRNSInternal` (ckksrns-parametergeneration.cpp l.154): "The specified ring dimension (65536) does
not comply with HE standards recommendation (131072)". At 2^16 the 21 Q towers split into 2 digits of alpha 11,
so P has 11 x 60 = 660 bits and log QP = 1160 + 660 = 1820. The HEStd_128_classic bound for ternary secrets at
N = 2^16 is 1747 bits (`stdlatticeparms.cpp` l.186), so OpenFHE asks for N = 2^17. The failure is the 128-bit
bound, as expected. `p11_dnum2` and `p11_dnum2ci` then ran dnum 2 with the security check off (`secure` = 0, same
N and the same moduli) to measure its time.

**Which runs count.** `p11_sweep` (15:41-16:06) had load 3-28 from other users. Its dnum 6 pair ran at load 28
and is invalid (CI 30.88 s, std 27.90 s). `p11_sweep2` (to 16:39) had load 1-8 except during std dnum 3: load
went from 2.6 to 25.9 during that run and its warm median was 27.53 s, more than the cold first bootstrap
(24.35 s). That run was redone as `p11_std3` (17:35, load 0.6-1.4): 23.17 s. The table uses `p11_sweep2` with
`p11_std3` for std dnum 3, and `p11_dnum2ci` (load 2.8-3.1) and the std run of `p11_dnum2` (load 10-20,
per-stage times stable over its 3 bootstraps) for dnum 2.

**Results 1: time, key size, precision** (N = 2^16, FLEXIBLEAUTO 55/60, encap, {4,4}, 1 thread, reps 2; depth
20, 21 Q towers, log2 Q = 1160 for all; warm median of 2 bootstraps).

| dnum | alpha = towers P | log P | log QP | 128-bit | one key MB | all keys GB CI / std | CI s | std s | 2 x std / CI | peak RSS GB CI / std | setup+keygen s CI / std | RMS bits CI / std |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 2 | 11 | 660 | 1820 | no (> 1747) | 64 | 4.38 / 4.75 | 28.61 | 24.24 | 1.69x | 10.72 / 8.09 | 28.2 / 37.3 | 18.24 / 18.22 |
| **3** (default) | 7 | 420 | 1580 | yes | 84 | 5.75 / 6.24 | **26.76** | **23.17** | 1.73x | 11.19 / 9.08 | 35.6 / 43.4 | 18.24 / 18.23 |
| 4 | 6 | 360 | 1520 | yes | 108 | 7.39 / 8.02 | 26.76 | 23.42 | 1.75x | 12.62 / 10.75 | 45.0 / 52.5 | 18.23 / 18.24 |
| 5 | 5 | 300 | 1460 | yes | 130 | 8.89 / 9.65 | 27.09 | 23.78 | 1.76x | 13.90 / 12.26 | 53.3 / 60.9 | 18.23 / 18.23 |
| 6 | 4 | 240 | 1400 | yes | 150 | 10.26 / 11.14 | 28.33 | 25.50 | 1.80x | 15.05 / 13.63 | 61.3 / 68.8 | 18.23 / 18.22 |
| 7 | 3 | 180 | 1340 | yes | 168 | 11.49 / 12.47 | 29.90 | 26.65 | 1.78x | 16.09 / 14.88 | 68.5 / 76.0 | 18.22 / 18.23 |

One key is dnum x 2 x (21 + alpha) towers x 2^16 x 8 B (84 MB = 3 x 2 x 28 x 0.5 MB). Galois keys: CI 70, std 76
at every dnum. Precision does not depend on dnum: RMS 18.22-18.24 bits, min 14.77-15.12 (CI) and 15.46-15.77
(std), p99 16.39-16.42 (CI) and 16.74-16.78 (std). The Galois check of item 0.4 printed "68 rotations ==
keygen set" at every CI bootstrap. `p11_sweep` gave the same picture where its load was low: CI 27.58 / 26.95 /
27.12 / - / 29.70 s and std 23.69 / 23.51 / 24.16 / - / 26.54 s for dnum 3 / 4 / 5 / 6 / 7.

**Results 2: per-stage times, warm** (CI: mean of the 2 warm bootstraps, `CI_BOOT_TIMING`; std: median of the 3
bootstraps, `-DBOOTSTRAPTIMING`; s).

| dnum | CI CtS | CI EvalMod | CI StC | std CtS | std EvalMod | std StC | CtS CI / std | StC CI / std |
|---|---|---|---|---|---|---|---|---|
| 2 | 13.95 | 8.17 | 5.87 | 8.10 | 12.58 | 3.11 | 1.72 | 1.89 |
| 3 | 13.75 | 7.84 | 4.44 | 8.27 | 12.12 | 2.35 | 1.66 | 1.89 |
| 4 | 13.88 | 7.85 | 4.40 | 8.56 | 12.05 | 2.33 | 1.62 | 1.89 |
| 5 | 14.23 | 7.91 | 4.20 | 8.77 | 12.22 | 2.26 | 1.62 | 1.86 |
| 6 | 15.38 | 8.11 | 4.06 | 9.80 | 12.68 | 2.26 | 1.57 | 1.80 |
| 7 | 16.66 | 8.46 | 3.91 | 10.76 | 13.10 | 2.19 | 1.55 | 1.79 |

The stages move in opposite directions. A hybrid key switch costs about (number of active digits) x (towers
of Q + towers of P) for ModUp and the key product, plus towers of P x towers of Q for ModDown. CtS runs at 20 -> 17
Q towers, where all digits are active. More digits make it slower (CI +2.9 s, std +2.5 s from dnum 3 to 7), and
fewer digits do not make it faster (dnum 2: CI +0.2 s, std -0.17 s). StC runs at 7 -> 4 Q towers, where only one
or two digits are active and the P towers are most of the basis. A smaller P makes it faster (CI -0.53 s from
dnum 3 to 7), and the 11 P towers of dnum 2 make it slower (CI +1.43 s, std +0.76 s). EvalMod is in the middle
and has its minimum at dnum 3-4.

**Conclusions.**
- Keep OpenFHE's default dnum 3 for both schemes. It is the fastest dnum that is valid at 128-bit: CI 26.76 s,
  std 23.17 s. dnum 4 has the same time within noise (CI 26.76 s, std +1%), but it costs +1.6-1.8 GB of keys and
  +1.4-1.7 GB peak RSS. dnum 5-7 are 1-12% (CI) and 3-15% (std) slower. The baseline commands and numbers in the plan header do not
  change.
- A higher dnum shortens log QP to 1340 bits at dnum 7, but the bootstrap gets slower. Shrinking log P is not
  the lever for the gap to the paper (1580 vs 1064 bits, 26.8 s vs 12.6 s). The extra bits are in log Q
  (1160 bits, 21 towers), which is item 1.2. A shorter Q also cuts the number of towers in every stage.
- dnum 2 would be 1.9 s (CI) and 1.1 s (std) slower than dnum 3 even if it were secure, because its large P
  makes StC and EvalMod slower. It becomes valid at 128-bit with one Q tower less (20 towers: log Q 1105 +
  log P 600 = 1705 <= 1747). When item 1.2 or 1.3 changes the chain, re-check dnum at the new tower count
  (log P = 60 x ceil(towers / dnum)) with the 13th driver argument. The trade-off above (CtS wants few digits,
  StC wants a small P) stays the same.
- The CI/2xstd ratio is 1.73-1.80x at every valid dnum. dnum does not change the CI advantage. The per-stage
  ratios (CtS 1.55-1.66x, StC 1.79-1.89x) also change little. Gap 1 (phase 2) is independent of dnum.

## 1.2 Prime sizes: per-stage (paper) vs uniform, FIXEDMANUAL vs FLEXIBLEAUTO at 2^16 (2026-10-27)

**Change.** `benchmark/src/ci-fft-boot.cpp` takes an optional 14th argument `after` (levels left for the
application after the bootstrap; default 2, the paper uses 3). The RESULT line also prints `after` and `towersQ`,
and a new line `chain Q bits (q0 first): ... | P bits: ...` lists the bit size of every Q and P prime. The
baseline commands are unchanged. No library code changed: the per-stage scale was not built (see "Decision").

**What OpenFHE can express.** FIXEDMANUAL and FLEXIBLE* both make every Q prime `scaleMod` bits except q0
(`firstMod`). A paper-style chain (EvalMod 60-bit, StC 40-bit, CtS 56-bit) needs two things that do not exist:
per-level prime sizes in `ParamsGenCKKSRNSInternal`, and a scale manager. FLEXIBLEAUTO's scale recursion
Delta' = Delta^2 / q_l diverges when q_l is far from Delta (2^56 entering 60-bit EvalMod primes: 2^52, 2^44,
2^28, ...). FIXEDMANUAL assumes q_l = Delta. A Lattigo-style manager (diagonals encoded at the dropped prime,
EvalMod at its own 2^60 scale) is a large change. The item says to build it only if the numbers show that it
pays. The runs below measure each of the three possible gains (time, log QP, precision) with what OpenFHE has.

**Commands (ICELAKE, `~/ci-ckks-fft`, source `SYNCED_FROM 500eeaa8` + this driver change).**

    ci-ckks-paper/tools/sync.sh   # (on WSL)
    ./guard.sh p12_build "cd openfhe-development/build && cmake --build . --target ci-fft-boot -j 32 && \
      cd ../build-bt && cmake --build . --target ci-fft-boot -j 32"                          # rc 0
    ./guard.sh p12_smoke "..."    # 2^12 insecure {3,3}, 4 threads: fa 59/60, fm 55/60, fm 59/60, fa 45/60 corr 15,
                                  # fa 59/60 after 3; ci and std; all rc 0
    # p12_sweep.sh "sm fm sc corr dnum after" ...: for each config, one ci run then one std run, 1 thread:
    #   CI_BOOT_TIMING=1 build/bin/benchmark/ci-fft-boot ci 16 4 4 $sm $fm 1 2 $sc $corr encap 0 $dnum $after
    #   build-bt/bin/benchmark/ci-fft-boot std 16 4 4 $sm $fm 1 2 $sc $corr encap 0 $dnum $after
    ./guard.sh p12_sweepA "./p12_sweep.sh '59 60 fa 0 0 2' '55 60 fa 0 0 2' '59 60 fa 5 0 2' '50 60 fa 10 0 2' \
      '45 60 fa 15 0 2' '55 60 fm 0 0 2' '59 60 fm 0 0 2'"                                   # rc 0
    ./guard.sh p12_sweepB "./p12_sweep.sh '59 60 fa 4 0 2' '59 60 fa 3 0 2' '59 60 fa 2 0 2' '55 60 fa 0 0 2' \
      '59 60 fa 0 0 2' '59 60 fa 5 0 3' '59 60 fa 5 4 3' '55 60 fa 0 0 3'"                   # rc 0
    # p12_ab.sh: clean A/B, reps 3, order ci55 ci59 std55 std59 ci59 ci55 std59 std55:
    #   ci  16 4 4 55 60 1 3 fa 0 encap   vs   ci  16 4 4 59 60 1 3 fa 4 encap
    #   std 16 4 4 55 60 1 3 fa 0 encap   vs   std 16 4 4 59 60 1 3 fa 5 encap
    ./guard.sh p12_ab ./p12_ab.sh                                                             # rc 0

Logs: `~/ci-ckks-fft/logs/p12_*.log`; the scripts are `~/ci-ckks-fft/p12_sweep.sh` and `p12_ab.sh`. Load was
1-6 except during the first two configs of `p12_sweepA` (load 13-22) and the `59 60 fa 5 4 3` pair of
`p12_sweepB` (load 6-15); those times are marked "loaded" and not used for time conclusions. `corr` 0 means the
default (CI 7, std 8 for FLEXIBLEAUTO; 7 for both under FIXEDMANUAL). With `scaleMod` < 55 the minimum correction
`firstMod - scaleMod` is above the default, so those runs pass that minimum. `59 60 fa 5 0 3` threw "The specified
ring dimension (65536) does not comply with HE standards recommendation (131072)" for both schemes (see below).

**Results 1: clean A/B, uniform 55 (baseline) vs uniform 59** (2^16, 128-bit, FLEXIBLEAUTO, encap, {4,4}, 1 thread;
two runs of reps 3 each; warm median per run; per-stage times are the mean of the two runs).

| scheme | scaleMod / firstMod | corr | log Q / log P / log QP | warm s (run 1, run 2) | CtS | EvalMod | StC | RMS bits | min bits (= paper's metric) | p99 bits |
|---|---|---|---|---|---|---|---|---|---|---|
| CI | 55 / 60 (baseline) | 7 | 1160 / 420 / 1580 | 26.68, 26.40 | 13.74 | 7.84 | 4.43 | 18.22, 18.23 | 15.06, 14.67 | 16.40 |
| CI | **59 / 60** | **4** | 1240 / 420 / 1660 | 26.31, 26.63 | 13.34 | 8.21 | 4.35 | **21.58, 21.56** | **18.69, 17.88** | 19.85 |
| std | 55 / 60 (baseline) | 8 | 1160 / 420 / 1580 | 23.35, 23.09 | 8.29 | 12.12 | 2.36 | 18.22, 18.24 | 15.71, 15.59 | 16.76 |
| std | **59 / 60** | **5** | 1240 / 420 / 1660 | 23.46, 23.37 | 7.97 | 12.69 | 2.30 | **22.75, 22.74** | **20.34, 19.88** | 21.33 |

Uniform 59-bit primes are valid at 128-bit (1660 <= 1747) with the same 21 Q + 7 P towers. They give +3.3 bits RMS
and +3.4 bits max-error precision (CI) and +4.5 / +4.5 bits (std) at the same time (CI -0.3%, std +0.9%, both
within noise). CI/2xstd: 1.75x (55) and 1.77x (59). EvalMod is 0.4 s (CI) and 0.6 s (std) slower at 59 bits and
CtS 0.3-0.4 s faster; the sums cancel. Galois keys (70 / 76), key memory (5.75 / 6.24 GB) and peak RSS (11.19 /
9.08 GB) do not change.

**Results 2: correction factor at uniform 59/60** (FLEXIBLEAUTO, `p12_sweepA`/`B`, reps 2; the minimum is
`firstMod - scaleMod` = 1).

| corr | CI RMS | CI min | std RMS | std min | CI warm s | std warm s |
|---|---|---|---|---|---|---|
| 2 | 18.71 | 16.83 | 17.69 | 15.94 | 26.51 | 24.27 |
| 3 | 20.67 | 18.60 | 19.69 | 17.92 | 26.86 | 23.88 |
| **4** | **21.56** | 18.31 | 21.66 | 19.86 | 27.17 | 23.54 |
| **5** | 20.73 | 17.64 | **22.75** | **20.11** | 26.55 | 23.51 |
| 7 / 8 (default) | 18.73 | 15.17-15.27 | 19.97 | 17.21-17.22 | 26.99 (loaded), 28.07 (loaded) | 23.97, 24.01 |

With 59-bit primes the correction factor has an optimum: CI 4 and std 5. Above it, each step costs ~1 bit (as
in item 0.2). Below it, the sine approximation error grows and precision drops 1-2 bits per step. By max error
the CI optimum is 3-4 (18.60 / 18.31 bits). At its optimum CI is 1.2 bits RMS below std (21.56 vs 22.75), the
same gap as in item 0.2. The default fit (7 / 8) depends on N and the slot count only, so at 59/60 it is 3 steps
too high for both schemes. At 55/60 the optimum lies below the allowed minimum (5), which is why item 0.2 found
that the lowest value is best.

**Results 3: smaller uniform primes** (FLEXIBLEAUTO, `firstMod` 60, `corr` = `firstMod - scaleMod`, reps 2;
`p12_sweepA`, load 1-3).

| scaleMod | towers Q + P | log Q / log P / log QP | CI s | std s | CI CtS / EvalMod / StC | std CtS / EvalMod / StC | CI RMS / min | std RMS / min |
|---|---|---|---|---|---|---|---|---|
| 59 (corr 5) | 21 + 7 | 1240 / 420 / 1660 | 26.55 | 23.51 | 13.34 / 8.17 / 4.36 | 8.00 / 12.74 / 2.30 | 20.73 / 17.64 | 22.75 / 20.11 |
| 55 (corr 7, `p12_sweepB`) | 21 + 7 | 1160 / 420 / 1580 | 26.52 | 23.67 | 13.68 / 7.83 / 4.42 | 8.48 / 12.30 / 2.43 | 18.23 / 15.05 | 18.23 / 15.58 |
| 50 (corr 10) | 21 + 7 | 1060 / 420 / 1480 | 26.54 | 23.29 | 13.66 / 7.80 / 4.42 | 8.32 / 12.15 / 2.37 | 6.29 / 3.27 | 10.10 / 7.46 |
| 45 (corr 15) | 21 + 6 | 960 / 360 / 1320 | 25.59 | 22.42 | 13.20 / 7.61 / 4.08 | 8.02 / 11.78 / 2.18 | -2.80 / -6.03 | 0.94 / -1.55 |

- **Time does not depend on the prime bit size.** RNS words are 64-bit, so a 50-bit prime costs the same as a
  59-bit one. 59, 55 and 50 bits give the same total time within 0.4 s (CI 26.52-26.55 s, std 23.29-23.67 s);
  per stage, 59 bits moves 0.3-0.6 s from CtS to EvalMod. Only the number of P towers moves the total time. OpenFHE sizes P to the largest digit: towersP = ceil(maxDigitBits / 60), plus one when the margin
  is below 4 bits (`rns-cryptoparameters.cpp`). At 45 bits the largest digit is 60 + 6 x 45 = 330 bits, so P has 6
  towers instead of 7, and the bootstrap is 0.95 s (CI, -3.6%) and 0.88 s (std, -3.8%) faster.
- **Precision collapses below 55 bits.** Every stage (EvalMod included) runs at the uniform scale, and the
  minimum correction grows as the scale shrinks. 50-bit primes give 6.3 (CI) and 10.1 (std) bits RMS; 45-bit
  primes give no precision.

**Results 4: FIXEDMANUAL vs FLEXIBLEAUTO** (`p12_sweepA`, load 3-5, reps 2, default corr 7 for both under FM).

| scheme | sc | scaleMod | warm s | CtS | EvalMod | StC | RMS / min bits |
|---|---|---|---|---|---|---|---|
| CI | fa | 55 | 26.52 | 13.68 | 7.83 | 4.42 | 18.23 / 15.05 |
| CI | fm | 55 | 23.92 | 13.73 | 5.08 | 4.42 | 11.34 / 7.44 |
| CI | fm | 59 | 23.85 | 13.42 | 5.23 | 4.41 | 14.77 / 10.05 |
| std | fa | 55 | 23.67 | 8.48 | 12.30 | 2.43 | 18.23 / 15.58 |
| std | fm | 55 | 19.86 | 8.49 | 8.50 | 2.36 | 13.27 / 11.14 |
| std | fm | 59 | 19.92 | 8.21 | 8.78 | 2.35 | 17.03 / 14.86 |

FIXEDMANUAL is 2.6 s (CI, -10%) and 3.8 s (std, -16%) faster, all of it in EvalMod (CI -35%, std -31%). Under
FLEXIBLE*, `AdjustLevelsAndDepthInPlace` (`ckksrns-leveledshe.cpp`) runs `EvalMultCore` and a rescale for every
addition of two ciphertexts at different levels, and the Paterson-Stockmeyer sine evaluation has many such
additions. FIXEDMANUAL only drops towers there. FIXEDMANUAL loses 6.9 bits (CI) and 5.0 bits (std) of RMS at 55
against FLEXIBLEAUTO 55/60, and 4.0 / 2.9 bits at 59 against FLEXIBLEAUTO 59/60 at its default corr (18.73 /
19.97). It assumes every prime is exactly 2^scaleMod, and the resulting scale error is multiplied by
the q0 x I term that EvalMod removes. CI likely loses more because its primes (q = 1 mod 4N) are spaced twice
as far apart (not checked). So FIXEDMANUAL is not usable as is, but its EvalMod shows that ~2.7 s (CI) and ~3.8 s (std) per
bootstrap are scale bookkeeping, not arithmetic that EvalMod needs. Under FIXEDMANUAL CI/2xstd falls to 1.66x,
because std pays the overhead twice.

**Results 5: three levels after the bootstrap (the paper's Base 60 + 40 x 3)** (`p12_sweepB`).

| scheme | chain | dnum | towers Q + P | log Q / log P / log QP | warm s | vs after 2 | RMS / min |
|---|---|---|---|---|---|---|---|
| CI | 55/60, after 3 | 3 (alpha 8) | 22 + 8 | 1215 / 480 / 1695 | 29.06 | +2.54 s (+9.6%) | 18.23 / 15.02 |
| std | 55/60, after 3 | 3 (alpha 8) | 22 + 8 | 1215 / 480 / 1695 | 25.28 | +1.61 s (+6.8%) | 18.23 / 15.83 |
| CI | 59/60, after 3, corr 5 | 4 (alpha 6) | 22 + 6 | 1299 / 360 / 1659 | 30.81 (loaded) | - | 20.72 / 17.33 |
| std | 59/60, after 3, corr 5 | 4 (alpha 6) | 22 + 6 | 1299 / 360 / 1659 | 26.28 (loaded) | - | 22.73 / 19.57 |

One more level adds one Q tower, and at dnum 3 also one P tower (alpha 7 -> 8). With 59-bit primes and dnum 3
the chain is 1299 + 480 = 1779 bits > 1747, and OpenFHE throws at 128-bit. dnum 4 (6 P towers, 1659 bits) is
valid; its time was measured under load and is only an upper bound.

**Decision: the per-stage scale is not built.** The three possible gains of mixed prime sizes in OpenFHE:
- *Time:* none. Time depends on the tower counts, not on the prime sizes (Results 3). A paper-style chain puts
  7 x 60-bit EvalMod primes into one dnum-3 digit (420 bits), so OpenFHE's P grows from 7 to 8 towers and the
  bootstrap gets slower. P can only shrink when every digit has small primes, and small primes destroy
  precision (Results 3).
- *log QP:* none. In our level structure (q0 60, 2 x 40 after, StC 4 x 40, EvalMod 10 x 60, CtS 4 x 56) Q is
  1124 bits. Its digits are 300 / 420 / 404 bits, so P = 8 x 60 = 480 and log QP = 1604, which is more than the
  baseline's 1580. A smaller log QP also does not make anything faster at N = 2^16. Item 1.1 showed that the
  dnum it would allow (2) is slower.
- *Precision:* uniform 59/60 already gives large EvalMod primes. It gains +3.3 (CI) / +4.5 (std) bits RMS at the
  same time and stays valid at 128-bit (Results 1).

**Conclusions.**
- Best parameters for item 1.3: FLEXIBLEAUTO, `scaleMod` 59, `firstMod` 60, `corr` 4 (CI) / 5 (std), dnum 3, i.e.
  `ci 16 4 4 59 60 1 2 fa 4 encap` and `std 16 4 4 59 60 1 2 fa 5 encap`. They give CI 26.3-26.6 s, RMS 21.6 bits,
  min 17.9-18.7 bits; std 23.4 s, RMS 22.7 bits, min 19.9-20.3 bits. The time equals the baseline's. The
  baseline commands in the plan are unchanged (item 1.R decides whether to switch).
- Precision metric: the paper's "Prec. 20.55 bits" is -log2 of the max error, which is `prec_bits_min` here,
  not `rms_bits`. On that metric the baseline CI is 14.7-15.1 bits (5.5 bits below the paper), and 59/60 corr 4
  closes it to 17.9-18.7 bits (about 2 bits below).
- log QP <= ~1100 (item 1.R) is not reachable with useful precision in OpenFHE's level structure. 21 Q + 7 P
  towers at 1100 bits would mean ~39-bit primes on average, and 50-bit primes already lose 8-12 bits RMS. The paper's chain is
  shorter mainly in towers (EvalMod 8 vs 10 levels, StC 3 vs 4, P 3 vs 7). Its own table is also not
  self-consistent: the listed columns of the 3+4 row sum to 60 + 120 + 120 + 480 + 224 + 180 = 1184 bits, and the
  stated 1064 (and 1008 / 952 / 952 for the other rows) equals that sum without the StC column. Either way it
  is a tower count of 19-22, not ours of 28.
- New lever, not covered by the plan: FLEXIBLEAUTO's level/scale adjustments cost ~2.7 s of 7.8 s CI EvalMod and
  ~3.8 s of 12.3 s std EvalMod (Results 4). An EvalMod that keeps the scale exact without the extra rescales,
  for example by encoding the Chebyshev/PS constants at the scale that makes the operands of each addition
  match (as Lattigo does), or FIXEDMANUAL with the actual primes folded into those constants, could keep
  FLEXIBLEAUTO's precision at FIXEDMANUAL's speed. Suggested as a phase 3 item. It would shorten the CI
  bootstrap by ~10% and lower CI/2xstd to ~1.66x.

## 1.3 Level-budget sweep with the item 1.1-1.2 parameters at 2^16 (2026-10-27)

**Change.** None in the source tree. The runs use the existing driver arguments (lbEnc lbDec ... dnum) with the
item 1.2 parameters: FLEXIBLEAUTO, `scaleMod` 59, `firstMod` 60, `corr` 4 (CI) / 5 (std), encap, 2 levels after
the bootstrap. The budget is {CtS, StC} in OpenFHE's order, so the paper's best "StC 3 + CtS 4" is {4,3}.
After the VM restart ICELAKE had no 1.3 jobs or logs, so the item started from the beginning.

**Commands (ICELAKE, `~/ci-ckks-fft`, source `SYNCED_FROM a817ecc7`).**

    ci-ckks-paper/tools/sync.sh   # (on WSL)
    ./guard.sh p13_build "cd openfhe-development/build && cmake --build . --target ci-fft-boot -j 32 && \
      cd ../build-bt && cmake --build . --target ci-fft-boot -j 32"                              # rc 0
    ./guard.sh p13_smoke "cd openfhe-development && export OMP_NUM_THREADS=4; for b in \"4 3\" \"5 3\" \"5 4\" \"5 5\"; do \
      set -- \$b; CI_BOOT_TIMING=1 build/bin/benchmark/ci-fft-boot ci 12 \$1 \$2 59 60 0 1 fa 4 encap; echo ci rc=\$?; \
      build/bin/benchmark/ci-fft-boot std 12 \$1 \$2 59 60 0 1 fa 5 encap; echo std rc=\$?; done"                     # rc 0
    # p13_sweep.sh "lbEnc lbDec dnum reps" ...: per config one ci run, then one std run, 1 thread:
    #   CI_BOOT_TIMING=1 build/bin/benchmark/ci-fft-boot ci 16 $1 $2 59 60 1 $4 fa 4 encap 0 $3
    #   build-bt/bin/benchmark/ci-fft-boot std 16 $1 $2 59 60 1 $4 fa 5 encap 0 $3
    ./guard.sh p13_sweepA "./p13_sweep.sh '5 4 3 1' '5 5 3 1' '4 4 0 2' '4 3 0 2' '5 3 0 2' '5 4 4 2' '5 5 4 2' \
      '4 4 4 2'"                                                                                   # rc 0
    # p13_ab.sh: clean A/B, reps 3, 1 thread, the same command lines; order
    #   ci{4,4} std{4,4} ci{4,3} std{5,3} ci{5,3} std{4,3} ci{5,4}d4 std{5,4}d4, then the same list reversed
    ./guard.sh p13_ab ./p13_ab.sh                                                                  # rc 0

Logs: `~/ci-ckks-fft/logs/p13_*.log`; scripts `~/ci-ckks-fft/p13_sweep.sh` and `p13_ab.sh`. `p13_sweepA`
(19:35-20:01) ran at load 1-5, except at the end of the CI {5,3} run (load 9.4). In `p13_ab` (20:02-20:44)
another user's job raised the load to 18-21 between 20:13 and 20:21. The first-pass std {4,3}, CI {5,4} and std
{5,4} runs were affected. They are marked "loaded" below and are not used for conclusions. The second pass ran
at load 1-8.

Note on `reps`: the driver's "warm median" is `times[reps / 2]` of the sorted warm times. With reps 2 it is the
slower of the two warm bootstraps. This is why the reps-2 sweep reads 0.2-0.4 s (CI) higher than the reps-3 A/B.
Use the A/B for comparisons between budgets.

**Smoke test** (`p13_smoke`, 2^12, insecure). All four budgets bootstrap for both schemes (rc 0). The Galois
check of item 0.4 holds (CI rotations 60 / 59 / 50 / 42 == keygen set). RMS: CI 18.80 bits, std 19.69 bits at
every budget. At 2^12 the precision does not depend on the budget.

**128-bit validity with 59/60 primes.** A budget level costs one Q tower. log P = 60 x ceil(towers / dnum) for
dnum 3, plus one P tower when the largest digit is within 4 bits of the P size (item 1.2).

| budget | towers Q | log Q | dnum 3: log P / log QP | dnum 4: log P / log QP | valid at dnum 3 |
|---|---|---|---|---|---|
| {4,3} | 20 | 1181 | 420 / 1601 | - | yes |
| {4,4}, {5,3} | 21 | 1240 | 420 / 1660 | 360 / 1600 | yes |
| {5,4} | 22 | 1299 | 480 / 1779 | 360 / 1659 | no (> 1747) |
| {5,5} | 23 | 1358 | 480 / 1838 | 360 / 1718 | no (> 1747) |

`p13_sweepA` confirms this. At dnum 3 both {5,4} and {5,5} throw "The specified ring dimension (65536) does not
comply with HE standards recommendation (131072)" for both schemes (rc 134). They run at dnum 4. dnum 2 is also not
valid at {4,3}: alpha 10 gives P = 600 bits and log QP = 1781.

**Results 1: time** (2^16, 128-bit, 1 thread; warm median in s. A/B = `p13_ab` pass 1, pass 2 (reps 3); sweep =
`p13_sweepA` (reps 2, slower of 2)).

| budget | dnum | log QP | CI A/B | CI sweep | std A/B | std sweep | CI best estimate | std best estimate | 2 x std / CI at this budget |
|---|---|---|---|---|---|---|---|---|---|
| {4,4} (ref) | 3 | 1660 | 26.33, 26.24 | 26.70 | 23.48, 23.37 | 23.37 | 26.28 | 23.42 | 1.78x |
| **{4,3}** | 3 | 1601 | **26.04, 25.90** | 26.29 | 23.41 (loaded), 22.83 | 22.86 | **25.97** | 22.85 | 1.76x |
| {5,3} | 3 | 1660 | 26.22, 26.01 | 26.57 | **21.89, 22.16** | **21.88** | 26.12 | **22.0** | 1.69x |
| {5,4} | 4 | 1659 | 26.89 (loaded), 26.01 | 26.19 | 22.74, 22.77 | 22.80 | 26.0-26.2 | 22.76 | 1.75x |
| {5,5} | 4 | 1718 | - | 27.71 | - | 24.36 | 27.7 | 24.4 | 1.76x |
| {4,4} | 4 | 1600 | - | 26.70 | - | 23.66 | 26.7 | 23.7 | 1.77x |

- **CI is flat.** {4,3}, {5,3} and {5,4} (dnum 4) are within 0.3 s of each other. They are 0.2-0.3 s (about 1%)
  faster than {4,4}, and the run-to-run spread is 0.1-0.2 s. {4,3} (the paper's choice) is the fastest by a small
  margin: 25.97 s, -1.2% vs {4,4}. {5,5} needs 23 towers and dnum 4 and is 4-5% slower.
- **std gains more.** {5,3} is the best std budget: 22.0 s, -6% vs {4,4} (23.42 s). {5,4} (dnum 4) and {4,3}
  are -2.4% to -2.8%. {5,5} is +4%.
- **CI/2xstd falls when both schemes use their best budget.** CI {4,3} 25.97 s vs 2 x std {5,3} 44.0 s gives
  **1.69x**. At the equal budget {4,4} it is 1.78x. The tuned std gains 1.4 s per bootstrap and pays it twice.

**Results 2: per-stage times, warm** (CI: mean of the warm bootstraps of the clean A/B runs; std: median of the
bootstraps of the clean runs; `p13_sweepA` for {5,5} and {4,4} dnum 4; s).

| budget | dnum | CI CtS | CI EvalMod | CI StC | std CtS | std EvalMod | std StC | CtS CI / std | StC CI / std |
|---|---|---|---|---|---|---|---|---|---|
| {4,4} | 3 | 13.28 | 8.16 | 4.33 | 7.97 | 12.70 | 2.30 | 1.67 | 1.88 |
| {4,3} | 3 | 12.68 | 7.45 | 5.27 | 7.78 | 11.62 | 3.05 | 1.63 | 1.73 |
| {5,3} | 3 | 12.30 | 7.70 | 5.59 | 6.89 | 11.63 | 3.08 | 1.79 | 1.81 |
| {5,4} | 4 | 12.94 | 8.17 | 4.27 | 7.36 | 12.61 | 2.27 | 1.76 | 1.88 |
| {5,5} | 4 | 13.93 | 8.95 | 4.05 | 7.89 | 13.84 | 2.07 | 1.77 | 1.96 |
| {4,4} | 4 | 13.53 | 8.17 | 4.27 | 8.21 | 12.67 | 2.27 | 1.65 | 1.88 |

CI per level (first warm bootstrap of the `p13_sweepA` run; diagonals / towers / s):

| budget | CtS levels | StC levels |
|---|---|---|
| {4,4} | 16/20/1.68, 62/19/4.07, 62/18/3.81, 63/17/3.66 | 63/7/1.44, 62/6/1.31, 62/5/1.19, 16/4/0.39 |
| {4,3} | 16/19/1.60, 62/18/3.93, 62/17/3.66, 63/16/3.51 | 127/6/2.22, 126/5/2.02, 64/4/1.02 |
| {5,3} | 16/20/1.73, 30/19/2.86, 30/18/2.71, 30/17/2.61, 31/16/2.54 | 127/6/2.29, 126/5/2.12, 64/4/1.11 |
| {5,4} d4 | 16/21/1.92, 30/20/3.08, 30/19/2.93, 30/18/2.43, 31/17/2.39 | 63/7/1.58, 62/6/1.20, 62/5/1.07, 16/4/0.35 |
| {5,5} d4 | 16/22/1.99, 30/21/3.21, 30/20/3.05, 30/19/2.93, 31/18/2.50 | 31/8/1.14, 30/7/1.02, 30/6/0.75, 30/5/0.68, 16/4/0.35 |

Where the time goes (vs {4,4}, both at dnum 3):
- **StC 3 levels**: the 16 layers split 6/5/5, so the levels have 127 / 126 / 64 diagonals instead of
  63 / 62 / 62 / 16. CI StC is +0.94 s ({4,3}) and +1.26 s ({5,3}); std StC is +0.75-0.78 s. The relative cost is
  about the same for both schemes (+22-29% CI, +33% std).
- **One level less below EvalMod**: EvalMod and everything above it run with one tower less. CI EvalMod is
  -0.71 s at {4,3} and -0.46 s at {5,3}; std EvalMod is -1.08 s at both. std's EvalMod is 1.6x CI's, so it gains
  more from each tower that is removed.
- **CtS 5 levels**: 16 / 30 / 30 / 30 / 31 diagonals instead of 16 / 62 / 62 / 63. CI CtS is -0.98 s; std CtS is
  -1.08 s, which is relatively twice as much (-14% vs -7%). At {4,3} the 4 CtS levels run with one tower less: CI
  -0.60 s, std -0.19 s.
- **dnum 4** ({5,4}, {5,5}) makes CtS slower (as in item 1.1), so the 5-level CtS gain shrinks to -0.34 s
  for CI. {5,5} adds 2 towers to every stage, and the cheaper StC (-0.28 s CI) does not cover them.

Net per bootstrap: CI {4,3} -0.37 s, {5,3} -0.18 s; std {5,3} -1.37 s. The real StC transform has 2x std's
diagonals at every StC budget (127 vs about 64 at 3 levels). That is why an StC level less costs CI more in
absolute terms, while the EvalMod and CtS savings are about the same for both schemes. Item 2.3 (uneven
splits) can reduce the 127/126-diagonal StC levels.

**Results 3: precision, keys, memory** (clean runs; CI keys and RSS include the cached diagonal plaintexts).

| budget | dnum | CI RMS | CI min (all runs) | std RMS | std min (all runs) | Galois keys CI / std | keys GB CI / std | peak RSS GB CI / std | setup+keygen s CI / std |
|---|---|---|---|---|---|---|---|---|---|
| {4,4} | 3 | 21.55-21.56 | 18.24, 18.61, 18.66 | 22.74-22.75 | 19.80, 20.04, 20.09 | 70 / 76 | 5.75 / 6.24 | 11.19 / 9.08 | 36.4 / 44.5 |
| {4,3} | 3 | 21.56 | 18.13, 18.34, 18.53 | 22.74-22.75 | 20.04, 20.09, 20.21 | 101 / 78 | 7.99 / 6.17 | 14.08 / 9.41 | 50.6 / 46.2 |
| {5,3} | 3 | 21.56 | 18.41, 18.43, 18.48 | 22.74-22.75 | 19.39, 20.09, 20.23 | 95 / 61 | 7.80 / 5.01 | 12.96 / 7.66 | 49.4 / 37.8 |
| {5,4} | 4 | 21.55 | 17.05, 18.46, 18.29 | 22.72-22.73 | 19.42, 18.21, 18.88 | 82 / 61 | 8.97 / 6.68 | 13.29 / 8.83 | 55.6 / 45.0 |
| {5,5} | 4 | 21.55 | 16.91 | 22.74 | 19.63 | 61 / 38 | 6.91 / 4.31 | 10.88 / 6.32 | 42.8 / 30.4 |

- **RMS does not depend on the budget** (CI 21.55-21.56, std 22.72-22.75 bits). The bootstrap error comes from
  EvalMod and the scale, not from the linear transforms.
- **Max error (`prec_bits_min`, the paper's metric)** varies by 0.5-1.5 bits from run to run at the same budget.
  It shows no clear budget trend. The two lowest CI values ({5,4} 17.05, {5,5} 16.91) are single runs, and the
  {5,4} reruns gave 18.29-18.46.
- **CI keys grow at StC budget 3.** The 127-diagonal StC levels need 99 (instead of 68) rotations. That is +2.2 GB of keys
  and +2.9 GB peak RSS at {4,3} (14.08 GB), and setup + keygen goes from 36 to 51 s. std's key set does not grow at StC 3
  (78 vs 76), and at {5,3} it shrinks to 61. The item 0.4 Galois check held at every CI bootstrap (68 / 99 / 93 /
  80 / 59 rotations == keygen set).

**Conclusions.**
- Best budgets with the 1.1-1.2 parameters (FLEXIBLEAUTO 59/60, corr 4 / 5, dnum 3 where valid): **CI {4,3}**
  (25.97 s, log QP 1601, RMS 21.56, min 18.1-18.5 bits) and **std {5,3}** (22.0 s, log QP 1660, RMS 22.74, min
  19.4-20.2 bits). For CI the gain over {4,4} is only 1.2% and costs +2.9 GB peak RSS. {4,4} (26.28 s, 11.19 GB)
  is within 0.3 s, so either budget is a reasonable CI default. The paper's best ordering (StC 3 + CtS 4) is also
  the fastest here, but by a much smaller margin.
- The speedup at each scheme's best budget is **1.69x** (CI {4,3} 25.97 s vs 2 x std {5,3} 22.0 s). At the
  equal budget {4,4} it is 1.78x, which overstates the CI advantage by 0.09x. Phase 2 (CI StC at 1.7-1.9x std's
  StC) is where CI must gain this back. Item 1.R should compare at each scheme's best budget.
- {5,4} and {5,5} need dnum 4 at 128-bit with 59-bit primes, and {5,5} is slower for both schemes. log QP stays at
  1601-1718. The budget does not bring log QP near the paper's ~1100 (item 1.R).
- The baseline commands in the plan header are unchanged. Item 1.R decides whether to switch to 59/60 and the
  new budgets:

      OMP_NUM_THREADS=1 build/bin/benchmark/ci-fft-boot ci  16 4 3 59 60 1 3 fa 4 encap
      OMP_NUM_THREADS=1 build/bin/benchmark/ci-fft-boot std 16 5 3 59 60 1 3 fa 5 encap
