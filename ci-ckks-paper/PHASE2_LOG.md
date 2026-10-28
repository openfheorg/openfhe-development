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

## 1.R Phase 1 review: new baseline, the log QP <= 1100 question, and the gap to the paper (2026-10-27)

**State.** Source synced from 89b7cd5c (the end of items 1.1-1.3; `SYNCED_FROM 89b7cd5c 0`). No source code changed
in this item. After the VM restart ICELAKE had no 1.R jobs or logs (its last logs were `p13_*`), so the item
started from the beginning. Two helper scripts were added on ICELAKE only: `~/ci-ckks-fft/p1R_chk.sh` prints the
chain of a configuration and stops after 40 s; `~/ci-ckks-fft/p1R_run.sh` runs configurations at 2^16, 128-bit,
FLEXIBLEAUTO `sm`/60, encap, 1 thread, 2 levels after (CI from `build` with `CI_BOOT_TIMING=1`, std from `build-bt`).

**Commands (ICELAKE, `~/ci-ckks-fft`).**

    ci-ckks-paper/tools/sync.sh   # (on WSL)
    ./guard.sh p1R_build "cd openfhe-development/build && cmake --build . --target ci-fft-boot -j 32 && \
      cd ../build-bt && cmake --build . --target ci-fft-boot -j 32"                                    # rc 0
    # p1R_chk.sh "scheme lbEnc lbDec sm corr dnum": ci-fft-boot $1 16 $2 $3 $4 60 1 0 fa $5 encap 0 $6 (timeout 40)
    ./guard.sh p1R_chk "./p1R_chk.sh 'ci 2 2 55 5 9' 'ci 2 2 56 4 9' 'ci 2 2 57 3 9' 'ci 2 2 55 5 6' 'ci 3 2 55 5 9' \
      'ci 2 3 55 5 9' 'ci 2 2 59 4 9' 'ci 3 3 55 5 9' 'std 2 2 55 5 9' 'ci 2 2 55 5 3'"                 # rc 0
    # p1R_run.sh "scheme lbEnc lbDec sm corr dnum reps":
    #   CI_BOOT_TIMING=1 build/bin/benchmark/ci-fft-boot ci 16 $2 $3 $4 60 1 $7 fa $5 encap 0 $6
    #   build-bt/bin/benchmark/ci-fft-boot std 16 $2 $3 $4 60 1 $7 fa $5 encap 0 $6
    ./guard.sh p1R_base "./p1R_run.sh 'ci 4 3 59 4 0 3' 'std 5 3 59 5 0 3' 'ci 4 4 59 4 0 3' 'std 4 4 59 5 0 3'"  # rc 0
    ./guard.sh p1R_low  "./p1R_run.sh 'ci 2 2 55 5 9 2' 'std 2 2 55 5 9 2' 'ci 2 2 55 5 3 2' 'std 2 2 55 5 3 2' \
      'ci 2 2 56 4 9 2' 'std 2 2 56 4 9 2'"                                                              # rc 0
    ./guard.sh p1R_low2 "./p1R_run.sh 'ci 2 2 55 5 9 2' 'ci 2 2 55 5 3 2' 'std 2 2 55 5 3 2' 'ci 2 2 56 4 9 2' \
      'std 2 2 56 4 9 2' 'std 2 2 55 5 9 2'"                                                             # rc 0

Logs: `~/ci-ckks-fft/logs/p1R_*.log`. `p1R_base` (20:55-21:05) ran at load 0.6-2.9. In `p1R_low`, another user's
test jobs raised the load to 18-28 between about 21:20 and 21:38. Its CI {2,2} dnum 3, std {2,2} dnum 3, CI 56
dnum 9 and std 56 dnum 9 runs are marked "loaded" and not used. `p1R_low2` (21:39-22:12) repeated them at load 1-8.

**Results 1: new baseline, both schemes re-measured** (`p1R_base`; 2^16, 128-bit, FLEXIBLEAUTO 59/60, encap, dnum 3,
2 levels after, 1 thread, reps 3; stage times are the warm bootstraps: CI `CI_BOOT_TIMING`, std `-DBOOTSTRAPTIMING`).

| scheme, budget | corr | towers Q + P | log Q / P / QP | warm median s | CtS | EvalMod | StC | RMS bits | min bits | Galois keys | keys GB | peak RSS GB | setup+keygen s | cold first s |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| **CI {4,3}** (best) | 4 | 20 + 7 | 1181 / 420 / 1601 | **25.98** | 12.65-12.80 | 7.46 | 5.28-5.29 | 21.57 | 18.50 | 101 | 7.99 | 14.08 | 50.6 | 50.0 |
| **std {5,3}** (best) | 5 | 21 + 7 | 1240 / 420 / 1660 | **21.86** | 6.78-6.90 | 11.57 | 3.04-3.05 | 22.74 | 19.73 | 61 | 5.01 | 7.66 | 37.4 | 22.0 |
| CI {4,4} | 4 | 21 + 7 | 1240 / 420 / 1660 | 26.31 | 13.22-13.40 | 8.16 | 4.34 | 21.55 | 18.55 | 70 | 5.75 | 11.19 | 36.3 | 46.9 |
| std {4,4} | 5 | 21 + 7 | 1240 / 420 / 1660 | 23.40 | 7.96-7.97 | 12.68 | 2.29-2.30 | 22.75 | 19.95 | 76 | 6.24 | 9.08 | 44.5 | 23.7 |

- Speedup at each scheme's best budget: 2 x 21.86 / 25.98 = **1.68x** (item 1.3: 1.69x). At the equal budget {4,4}:
  2 x 23.40 / 26.31 = 1.78x (item 1.3: 1.78x).
- All values agree with items 1.2-1.3 within 0.1-0.2 s. The item 0.4 Galois check printed "99 rotations ==
  keygen set" ({4,3}) and "68 rotations == keygen set" ({4,4}) at every CI bootstrap.
- Per-stage ratios at {4,4} (one CI vs one std): CtS 1.67x, EvalMod 0.64x, StC 1.89x. At the best budgets:
  CtS 1.87x, EvalMod 0.64x, StC 1.74x. Of the 25.98 s CI bootstrap, the linear transforms take 18.0 s (69%).

**Results 2: log QP <= ~1100 at 128-bit.**

Which chains can reach it. In OpenFHE log P = 60 x towersP, and towersP is set by the largest digit (the digit
that holds q0) plus a 4-bit margin. So P >= 120 bits (2 towers), and only with alpha <= 2, which needs dnum >= 9
at 17 towers. log Q must then be <= ~980 bits. The Q towers are q0 + 2 after + 10 EvalMod + lbEnc + lbDec, and
primes below 55 bits lose 8-12 bits of precision (item 1.2). At 55 bits, 17 towers give 940 bits, so the budget
can only be {2,2} (or {3,1} / {1,3}, which are even slower). `p1R_chk` confirms the arithmetic:

| scheme, budget | scaleMod | dnum | towers Q + P | log Q / P / QP (sum of the rounded prime bits) | 128-bit |
|---|---|---|---|---|---|
| ci / std {2,2} | 55 | 9 (alpha 2) | 17 + 2 | 940 / 120 / **1060** | yes |
| ci {2,2} | 56 | 9 | 17 + 2 | 956 / 120 / **1076** | yes |
| std {2,2} | 56 | 9 | 17 + 3 | 956 / 180 / 1136 | yes (std's q0 q1 digit has >= 117 bits, less than the 4-bit margin below 120, so P gets 3 towers) |
| ci {2,2} | 57 | 9 | 17 + 3 | 972 / 180 / 1152 | yes |
| ci {2,2} | 59 | 9 | 17 + 3 | 1004 / 180 / 1184 | yes |
| ci {2,2} | 55 | 6 (alpha 3) | 17 + 3 | 940 / 180 / 1120 | yes |
| ci {3,2}, {2,3} | 55 | 9 | 18 + 2 | 995 / 120 / 1115 | yes |
| ci {2,2} | 55 | 3 (alpha 6) | 17 + 6 | 940 / 360 / 1300 | yes |
| ci {3,3} | 55 | 9 | - | - | throws: 19 towers do not fill 9 digits of alpha 3 |

So a 128-bit parameter set with log QP <= 1100 exists: **{2,2}, 55/60 (or 56/60 for CI), dnum 9**. Its cost
(`p1R_low` clean runs and `p1R_low2`; reps 2, so the warm median is the slower of the 2 warm bootstraps):

| scheme | scaleMod / corr | dnum | log QP | warm s (runs) | CtS | EvalMod | StC | RMS | min | keys / GB | peak RSS GB | setup+keygen s | cold first s |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| CI | 55 / 5 | 9 | **1060** | 59.16, 59.38 | 38.6-41.0 | 7.45-7.69 | 9.68-10.12 | 20.16 | 15.26, 15.76 | 118 / 19.7 | 40.09 | 121-132 | 145-159 |
| std | 55 / 5 | 9 | **1060** | 46.10, 45.05 | 27.0-28.1 | 11.52-11.84 | 5.94-6.20 | 21.14-21.15 | 17.60, 17.93 | 131 / 21.9 | 33.17 | 161-164 | 46 |
| CI | 56 / 4 | 9 | **1076** | 56.59 (67.75 loaded) | 38.4-38.8 | 7.40 | 9.71 | 20.22-20.23 | 16.69, 16.76 | 118 / 19.7 | 40.09 | 121 | 142 |
| std | 56 / 4 | 9 | 1136 | 48.01 (48.29 loaded) | 28.5 | 12.08 | 6.81 | 21.64 | 19.68, 19.76 | 131 / 23.0 | 35.15 | 170 | 49 |
| CI | 55 / 5 | 3 | 1300 | 54.99 (59.58 loaded) | 34.4-34.9 | 6.50 | 13.15 | 20.24-20.25 | 16.93, 17.24 | 118 / 7.95 | 33.57 | 55 | 167 |
| std | 55 / 5 | 3 | 1300 | 42.15, 42.16 | 22.9-23.6 | 10.08-10.13 | 7.93-8.18 | 21.20 | 18.59, 18.60 | 131 / 8.83 | 23.30 | 101 | 42 |

CI per level at {2,2} (warm): CtS 256 diagonals at 16 towers (11.1 s) and 1023 diagonals at 15 towers (29.5 s);
StC 1023 diagonals at 5 towers (8.1 s) and 256 at 4 towers (2.0 s). The Galois check printed "116 rotations ==
keygen set" at every CI bootstrap.

- The log QP <= 1100 set is **2.3x slower for CI** (59.4 s vs 25.98 s) and **2.1x slower for std** (45.0-46.1 s
  vs 21.86 s) than the best 1601/1660-bit sets. Two budget levels of 8 FFT layers each give 256 + 1023 CI
  diagonals per transform, and CtS grows from 12.7 s to 40 s. The speedup falls to 2 x 45.05 / 59.38 = 1.52x
  (1.56x in `p1R_low`), because the transforms (where CI costs 1.4-1.6x std) now dominate EvalMod (where CI
  costs 0.65x).
- It also costs precision: CI RMS 20.2 bits and min 15.3-16.8 bits, against 21.6 / 18.5 bits for CI {4,3}
  59/60. 55-56-bit primes allow only corr >= 4-5, and their min precision is 1.7-3.2 bits lower.
- At the same Q, dnum 9 (log QP 1060) is **slower** than dnum 3 (log QP 1300): CI 59.4 vs 55.0 s (+8%), std
  45.0-46.1 vs 42.2 s (+7-9%). Shrinking P by adding digits makes CtS slower (CI 38.6-41.0 vs 34.4-34.9 s), as
  in item 1.1. EvalMod is also slower (7.5 vs 6.5 s), and only StC gains (9.7 vs 13.2 s). Keys grow 2.5x
  (19.7 vs 7.95 GB).
- Conclusion: log QP <= 1100 is reachable at 128-bit, but it is not a speed lever in OpenFHE at N = 2^16. Time
  follows the number of towers per key switch and the number of diagonals per level, not log QP. The set is
  not adopted.

**Results 3: our chain vs the paper's.** Paper row "StC 3 + CtS 4" (Lattigo; its stated log QP 1064 equals the sum
below without the StC column, see item 1.2) against our new CI baseline {4,3} 59/60.

| part | paper: towers x bits | ours (CI {4,3}): towers x bits | difference (bits) | what it would take in OpenFHE |
|---|---|---|---|---|
| q0 | 1 x 60 | 1 x 60 | 0 | - |
| levels after the bootstrap | 3 x 40 = 120 | 2 x 59 = 118 | -2 | (paper keeps one more level) |
| StC | 3 x 40 = 120 | 3 x 59 = 177 | +57 | per-stage scale (item 1.2: not built; no time gain) |
| EvalMod | 8 x 60 = 480 | 10 x 59 = 590 | +110 | a sine evaluation 2 levels shallower (OpenFHE: Chebyshev depth 7 + 3 double-angle steps) |
| CtS | 4 x 56 = 224 | 4 x 59 = 236 | +12 | - |
| P | 3 x 60 = 180 | 7 x 60 = 420 | +240 | alpha <= 3 (dnum >= 7): slower in item 1.1 (+12% CI at {4,4}) |
| total | 1184 (stated 1064) | 1601 | +417 | |
| towers Q + P | 19 + 3 = 22 | 20 + 7 = 27 | +5 | |

**Results 4: absolute CI time vs the paper.**

| | paper (Lattigo, Xeon Gold 6248R, 1 core) | ours (OpenFHE, Xeon Platinum 8360Y, 1 thread) | ratio |
|---|---|---|---|
| CI bootstrap, 65,536 reals | 12.6 s | 25.98 s (best budget {4,3}) | 2.06x |
| log QP | 1064 (1184 with StC) | 1601 | 1.50x (1.35x) |
| towers Q + P | 22 | 27 | 1.23x |
| precision, max error (`prec_bits_min`) | 20.55 bits | 18.50 bits (18.1-18.5 over items 1.3 and 1.R) | -2.05 bits |
| max single-core turbo (Intel spec) | 4.0 GHz | 3.5 GHz | 1.14x |

At equal clock the gap is about 2.06 / 1.14 = 1.8x. Phase 1 started from CI 26.4-26.7 s (RMS 18.2, min 14.7-15.1
bits). It gained 0.4-0.7 s (2%) in time, 3.3 bits RMS and 3.0-3.8 bits min precision. The CI/2xstd ratio, when each
scheme uses its best budget, went from 1.74-1.76x (equal {4,4}, 55/60) to 1.68x. Most of that drop is std
gaining more from its best budget (item 1.3).

**Conclusions.**
- Phase 1 is complete. The parameters do not close the 2x gap to the paper. log Q and log P are not where the
  time goes: every lever that shortens the chain in OpenFHE (more digits, smaller primes, smaller budgets)
  either costs time or costs precision. The phase-1 hypothesis in the plan ("the 1580 vs 1064-bit chain is likely
  most of the 2x gap") is refuted. CI_FFT_REVIEW.md issue 7 is updated.
- The remaining gap is in the computation itself. The linear transforms take 18.0 of the 25.98 s CI bootstrap
  (CI CtS 1.67x and StC 1.89x std's at {4,4}), which is phase 2. EvalMod spends ~2.7 s in FLEXIBLEAUTO
  scale-adjustment rescales (item 1.2) and ~1.0 s in the K = 28 sine table (item 0.5, phase 3.1). The 5 extra
  towers (27 vs 22) cost every key switch about 1.2x.
- New baseline (plan header updated): FLEXIBLEAUTO 59/60, dnum 3, encap, each scheme at its best budget, reps 3:

      OMP_NUM_THREADS=1 build/bin/benchmark/ci-fft-boot ci  16 4 3 59 60 1 3 fa 4 encap
      OMP_NUM_THREADS=1 build/bin/benchmark/ci-fft-boot std 16 5 3 59 60 1 3 fa 5 encap

  Per-stage CI/std ratios (phase 2 targets) use the equal-budget pair `ci 16 4 4 59 60 1 3 fa 4 encap` and
  `std 16 4 4 59 60 1 3 fa 5 encap`. CI stages come from `CI_BOOT_TIMING=1`, std stages from the `build-bt`
  binary.
- Suggestion for the plan adapter (not added to the plan): item 1.2's EvalMod lever. An exact-scale EvalMod
  without the FLEXIBLEAUTO adjustment rescales would save ~2.7 s (CI) and ~3.8 s (std) per bootstrap. It
  needs a phase 3 item.

## 2.1 Op counts per linear-transform level, CI vs std; two excess giant-step costs fixed (2026-10-27)

**State.** After the VM restart ICELAKE had no 2.1 jobs or logs (its last logs were `p1R_*`), so the item started
from the beginning. Source synced from b2f43d5b plus the working-tree change (`SYNCED_FROM b2f43d5b 1`); the
committed code is the code of the last sync (`p21_build3`, `p21_final`).

**What changed** (`src/pke/lib/scheme/ckksrns/ckksrns-fhe.cpp` only):
1. **Instrumentation.** With `CI_BOOT_TIMING=1`, every BSGS level of the CI transforms (`applyCISparse`) and of
   std's `EvalCoeffsToSlots` / `EvalSlotsToCoeffs` prints one `[LT]` line: diagonals, towers Ql+P, rotations
   (hoisted baby + giant), the identity extension, ModUps (digit decompositions), ModDowns (polynomials QlP -> Ql;
   a `KeySwitchDown` counts 2), extended-basis plaintext multiplications and additions, and the time of each
   class. Counters live in a file-local `LTStats` (`LTRun`, `LTLevel`); `EvalMultExt`, `EvalAddExtInPlace` and
   `EvalHornerGiantRotate` count themselves. Without the variable nothing is counted or printed (std from
   `build-bt` printed no `[LT]` line). Serial runs only: std's parallel baby loops are timed as a whole.
2. **Bug fix 1: giant step in the extended basis.** The CI giant step did a full `KeySwitchDown` of the block sum
   (2 ModDowns), rotated element 0 in Ql, then ModUp + key switch of element 1; the block at offset 0 paid one
   more ModDown (`KeySwitchDownFirstElement`). std's Horner giant (`EvalHornerGiantRotate`) ModDowns only element 1
   and rotates element 0 in QlP. CI now calls `EvalHornerGiantRotate` with the CI Galois element, the CI map
   (`PrecomputeAutoMapCI`) and that element's key, and adds the block at offset 0 to the accumulator in QlP. One
   `KeySwitchDown` ends the level. The same change is made in the dense budget-{1,1} path (`applyCILT`).
3. **Bug fix 2: window alignment.** `CIPlanBsgs` started the BSGS window at the first nonzero offset (for a
   centred level, offset -31). No giant block then started at offset 0, so all n2 blocks were rotated. The window
   start now moves back by r < n1 positions, so that offset 0 starts a block. That block needs no rotation: n2 - 1
   giants instead of n2. This is skipped when 0 is outside the window or the longer window would wrap around Z_T.
   Keygen (`CIRealFFTGaloisElements`) takes the plan from the same function; the item 0.4 Galois check held in
   every run.

**Commands (ICELAKE, `~/ci-ckks-fft`).** Helper scripts on ICELAKE only: `p21_run.sh "mode scheme logN lbEnc lbDec corr
reps secure"` runs `CI_BOOT_TIMING=1 build/bin/benchmark/ci-fft-boot $2 $3 $4 $5 59 60 $8 $7 fa $6 encap 0 0`, 1 thread
(mode 0 = item 2.1 code; mode 1 = pre-2.1 code through the temporary switches `CI_GIANT_OLD` + `CI_BSGS_NOALIGN`;
mode 2 = fix 1 only). `p21_final.sh` runs the committed code (switches removed). In `p21_ab` (first build, before fix
2 existed) "0" was fix 1 only and "1" was pre-2.1.

    ci-ckks-paper/tools/sync.sh   # (on WSL; three times: instrumentation + fix 1, + fix 2, final cleanup)
    ./guard.sh p21_build  "cd openfhe-development/build && cmake --build . --target ci-fft-boot -j 32 && \
      cd ../build-bt && cmake --build . --target ci-fft-boot -j 32"                                    # rc 0, no warnings
    ./guard.sh p21_smoke  "./p21_run.sh '0 ci 12 3 3 4 2 0' '1 ci 12 3 3 4 2 0' '0 std 12 3 3 5 2 0' \
      '0 ci 10 1 1 4 2 0' '0 ci 11 1 1 4 2 0'"                                                          # rc 0
    ./guard.sh p21_ab     "./p21_run.sh '0 ci 16 4 4 4 3 1' '1 ci 16 4 4 4 3 1' '0 std 16 4 4 5 3 1' \
      '0 ci 16 4 3 4 3 1' '1 ci 16 4 3 4 3 1' '0 std 16 5 3 5 3 1'"                                     # rc 0
    ./guard.sh p21_build2 "cd openfhe-development/build && cmake --build . --target ci-fft-boot -j 32"  # rc 0
    ./guard.sh p21_smoke2 "./p21_run.sh '0 ci 12 3 3 4 2 0' '2 ci 12 3 3 4 2 0' '1 ci 12 3 3 4 2 0' \
      '0 ci 12 2 2 4 2 0' '1 ci 12 2 2 4 2 0' '0 ci 13 4 3 4 2 0' '1 ci 13 4 3 4 2 0'"                  # rc 0
    ./guard.sh p21_ab2    "./p21_run.sh '0 ci 16 4 4 4 3 1' '2 ci 16 4 4 4 3 1' '1 ci 16 4 4 4 3 1' \
      '0 ci 16 4 3 4 3 1' '2 ci 16 4 3 4 3 1' '1 ci 16 4 3 4 3 1' '1 ci 16 4 3 4 3 1' '2 ci 16 4 3 4 3 1' \
      '0 ci 16 4 3 4 3 1' '1 ci 16 4 4 4 3 1' '2 ci 16 4 4 4 3 1' '0 ci 16 4 4 4 3 1'"                  # rc 0
    ./guard.sh p21_build3 "<same as p21_build>"                                                         # rc 0, no warnings
    ./guard.sh p21_final  ./p21_final.sh   # 2^12 ci/std {3,3}, 2^10 ci {1,1}, then the four plan baseline commands  # rc 0

Logs: `~/ci-ckks-fft/logs/p21_*.log`. Load average 1-6 in all timing runs, except one pre-2.1 {4,3} run in `p21_ab` that
started at 14.6; it is not used (its repeat in `p21_ab2` gives the same 25.92-26.01 s).

**Results 1: op counts per level** (2^16, 128-bit, FLEXIBLEAUTO 59/60, encap, equal budget {4,4}; warm bootstrap).
CtS level 0 is applied first. "rot" = baby + giant rotations; "2 sqrt(d)" is the item's reference; pt = plaintext
multiplications; t = level time in s (`p21_final` for CI 2.1, `p21_ab2` first mode-1 run for pre-2.1, `p21_ab` for std).

| transform, level | towers Ql+P | diags d | 2 sqrt(d) | rot pre-2.1 | rot 2.1 | ModUp pre / 2.1 | ModDown polys pre / 2.1 | pt | t pre-2.1 | t 2.1 |
|---|---|---|---|---|---|---|---|---|---|---|
| CI CtS 0 | 20+7 | 16 | 8.0 | 7+1 | 7+1 | 2 / 2 | 5 / 3 | 16 | 1.569 | 1.411 |
| CI CtS 1 | 19+7 | 62 | 15.7 | 15+4 | 15+3 | 5 / 4 | 10 / 5 | 62 | 3.981 | 3.377 |
| CI CtS 2 | 18+7 | 62 | 15.7 | 15+4 | 15+3 | 5 / 4 | 10 / 5 | 62 | 3.811 | 3.232 |
| CI CtS 3 | 17+7 | 63 | 15.9 | 15+4 | 15+3 | 5 / 4 | 10 / 5 | 63 | 3.670 | 3.118 |
| CI StC 0-2 | 7..5+7 | 63, 62, 62 | 15.7-15.9 | 15+4 | 15+3 | 5 / 4 | 10 / 5 | d | 1.425, 1.297, 1.185 | 1.197, 1.096, 0.987 |
| CI StC 3 | 4+7 | 16 | 8.0 | 7+1 | 7+1 | 2 / 2 | 5 / 3 | 16 | 0.385 | 0.332 |
| std CtS 0 | 20+7 | 31 | 11.1 | 15+0 | (same) | 1 | 2 | 31 | 1.856 | |
| std CtS 1, 2 | 19, 18+7 | 31 | 11.1 | 15+1 | | 2 | 3 | 31 | 2.052, 1.986 | |
| std CtS 3 | 17+7 | 15 | 7.7 | 7+2 (1 + the slot-order delta) | | 3 | 4 | 15 | 1.427 | |
| std StC 0-2 | 7..5+7 | 31 | 11.1 | 15+1 | | 2 | 3 | 31 | 0.696, 0.645, 0.586 | |
| std StC 3 | 4+7 | 15 | 7.7 | 7+1 (delta) | | 2 | 3 | 15 | 0.313 | |

Totals per transform ({4,4}):

| | rot (baby + giant) | sum 2 sqrt(d) | ModUp | ModDown polys | pt mult = sum d | t CtS (LT sum) | t StC (LT sum) |
|---|---|---|---|---|---|---|---|
| CI pre-2.1, per transform | 52 + 13 = 65 | 55.4 | 17 | 35 | 203 | 13.03 | 4.29 |
| CI 2.1, per transform | 52 + 10 = 62 | 55.4 | 14 | 18 | 203 | 11.14 | 3.61 |
| std, per transform | 52 + 4 = 56 | 41.2 | 8 | 12 | 108 | 7.32 | 2.24 |
| CI 2.1 / std | 1.11x | 1.34x | 1.75x | 1.50x | 1.88x | 1.52x | 1.61x |

- **Plaintext multiplications equal the diagonal count in every level** (CI and std). No zero diagonal is
  multiplied and no diagonal is used twice. CI levels have 2x std's diagonals (62-63 vs 31), as the real
  factorization requires.
- **Rotations follow the BSGS plan.** CI with ratio 2 uses n1 = 16 for 62-63 diagonals: 15 baby + 3 giant = 18
  against 2 sqrt(d) = 15.7. std's OpenFHE plan uses 15 babies + 1 giant for 31 diagonals (16 vs 11.1). The extra
  rotations over 2 sqrt(d) are cheap hoisted babies in both schemes; the baby/giant split is item 2.2. The giant
  step that was not needed (window not aligned to offset 0) was an excess and is fixed (fix 2).
- **ModDowns were an excess.** Before 2.1 a CI level with g giants did 2g + 2 (+1 when one block sat at offset 0)
  ModDowns; std's pattern is g + 2. After fix 1 and fix 2 CI does g + 2, with one giant fewer: 5 instead of 10 per
  62-diagonal level.
- **Per-op cost is the same in both schemes** at the same towers (19+7, {4,4} CtS level 1): plaintext
  multiplication 16.8 ms (CI) / 16.7 ms (std); hoisted baby rotation 57 / 57 ms; ModUp 188 / 167 ms; ModDown
  67 / 60 ms per polynomial. The ~10% on ModUp/ModDown is the CI NTT (item 4.1).

**Results 2: time, A/B on the same binary** (warm median of 3, 1 thread; two runs per mode in `p21_ab2`, one
in `p21_final` for 2.1):

| CI budget | pre-2.1 (mode 1) | fix 1 only (mode 2) | 2.1 (mode 0, `p21_ab2`) | 2.1 committed (`p21_final`) | change | Galois keys | peak RSS GB |
|---|---|---|---|---|---|---|---|
| {4,3} | 25.98, 26.01 (1.R: 25.98) | 24.34, 24.58 | 23.81, 23.71 | **23.75** | -8.6% | 101 -> 100 | 14.08 -> 13.97 |
| {4,4} | 26.41, 27.08 (load 4.2) (1.R: 26.31) | 25.17, 25.61 | 24.00, 23.70 | **23.84** | -9.4% vs 26.31 | 70 -> 61 | 11.19 -> 10.42 |

| stage, warm s | CI {4,3} pre-2.1 | CI {4,3} 2.1 | CI {4,4} pre-2.1 | CI {4,4} 2.1 | std {5,3} | std {4,4} |
|---|---|---|---|---|---|---|
| CtS | 12.67-12.70 | 10.96 | 13.28 | 11.39 | 6.80 | 8.02 |
| EvalMod | 7.45 | 7.46 | 8.18 | 8.17 | 11.58 | 12.74 |
| StC | 5.30 | 4.76 | 4.37 | 3.69 | 3.04 | 2.32 |
| total (warm median) | 25.98-26.01 | 23.75 | 26.41 | 23.84 | 21.89 | 23.55 |

(CI stages from `CI_BOOT_TIMING`, std stages from `build-bt`; std from `p21_final`, which matches 1.R within 0.7%.)

- Precision is unchanged: CI RMS 21.55-21.57 bits in every mode (1.R: 21.55-21.57), min 17.5-18.8 bits (the
  usual run-to-run spread; pre-2.1 runs 18.3-18.6). At 2^12 {3,3} and {2,2} the pre-2.1 and 2.1 runs give the
  same RMS 18.80 / min 17.18 bits; at 2^13 {4,3} 19.71 / 18.02-18.03 bits. The dense {1,1} path runs (2^10:
  RMS 16.59 / min 15.10 bits; 2^11: 17.83 / 16.33 bits); it has no A/B, but it now uses the same giant routine.
- Fix 1 saves 1.4-1.7 s at {4,3} and 0.7-1.9 s at {4,4}; fix 2 saves another 0.5-0.9 s at {4,3} and 1.2-1.9 s at
  {4,4} ({4,4} has 6 levels that gain a block at offset 0, {4,3} has 5; the 64-diagonal StC level was already aligned). The Galois key set
  changes with the giant offsets: {4,4} 70 -> 61 keys (5.75 -> 5.01 GB), {4,3} 101 -> 100; at 2^12 {3,3}
  49 -> 44, at 2^13 {4,3} 67 -> 68.
- New ratios. At each scheme's best budget: CI {4,3} 23.75 s vs std {5,3} 21.89 s, **2 x 21.89 / 23.75 = 1.84x**
  (1.R: 1.68x). At equal {4,4}: 2 x 23.55 / 23.84 = 1.98x (1.R: 1.78x). Per-stage CI/std at {4,4}: CtS
  11.39 / 8.02 = **1.42x** (1.R: 1.67x), EvalMod 0.64x, StC 3.69 / 2.32 = **1.59x** (1.R: 1.89x). Against the paper
  (12.6 s) CI is now 1.89x (1.R: 2.06x).
- CI {4,4} (23.84 s) is now within 0.4% of {4,3} (23.75 s) with 61 instead of 100 keys (5.0 vs 7.9 GB) and 10.4
  instead of 14.0 GB peak RSS.

**Results 3: where the CI transform time goes now** ({4,4}, LT sums, s):

| class | CI CtS | std CtS | CI/std | CI StC | std StC | CI/std |
|---|---|---|---|---|---|---|
| ModUp | 2.54 | 1.28 | 1.97x | 0.40 | 0.20 | 2.0x |
| hoisted baby rotations | 2.88 | 2.93 | 0.98x | 0.67 | 0.67 | 1.0x |
| giant key switch + automorphisms | 0.47 | 0.18 | 2.5x | 0.10 | 0.04 | 2.6x |
| ModDown | 1.17 | 0.71 | 1.66x | 0.52 | 0.31 | 1.7x |
| plaintext mult | 3.30 | 1.80 | 1.84x | 1.59 | 0.85 | 1.88x |
| extended add | 0.78 | 0.42 | 1.86x | 0.33 | 0.17 | 1.9x |
| total | 11.14 | 7.32 | 1.52x | 3.61 | 2.24 | 1.61x |

**Conclusions.**
- Against "2 sqrt(d) + d", the CI transforms had two excess costs, both in the giant steps: an extra ModDown per
  giant block (element 0 taken down to Ql in every block) and one unneeded giant rotation per level (window not
  aligned to offset 0). Both are fixed. Now plaintext multiplications = d exactly, rotations = 15 + 3 for 62-63
  diagonals (2 sqrt(d) = 15.7; the split is item 2.2's tuning), and ModUp / ModDown follow std's pattern (g + 1
  ModUps, g + 2 ModDowns for g giants). CI is 8.6-9.4% faster, and CI CtS/StC went from 1.67x / 1.89x std's to
  1.42x / 1.59x at {4,4}.
- The remaining CI/std transform gap is the diagonal count (1.88x plaintext multiplications, inherent) and more
  giant steps (CI 10 vs std 4 per transform: more diagonals per level with the same n1 = 16). This is what items
  2.2 (baby/giant split) and 2.3 (layer splits) can tune.
- Plaintext multiplication plus extended addition is 36% of CI CtS and 53% of CI StC (std: 30% / 46%). One
  extended-basis multiplication of a 26-tower ciphertext takes 16.7 ms at 2^16, about 4.9 ns per coefficient
  product. That is memory traffic, not arithmetic: `EvalMultExt` copies the plaintext polynomial, clones the
  ciphertext, then multiplies, and `EvalAddExtInPlace` makes another pass. Suggestion for the plan adapter (not
  added to the plan): a phase 2 item for a fused extended-basis multiply-accumulate (acc += ct * pt per tower, no
  copy, no clone). It is shared with std, but CI has 1.9x the multiplications, so it shrinks the CI/std ratio.
- Suggestion for the plan adapter: CI {4,4} now ties CI {4,3} in time with 39% fewer keys and 3.5 GB less
  memory; item 2.R could re-pick CI's baseline budget. The baseline commands are unchanged in this item.

## 2.2 Per-level BSGS split from a cost model (2026-10-28)

**State.** After the VM restart ICELAKE had no 2.2 jobs or logs (its last logs were `p21_*`), so the item started
from the beginning. The committed code is the code of the last sync (`p22_build3`, `p22_final`; `SYNCED_FROM 00f4cb19 4`).

**What changed.**
1. **Planner moved to core** (`src/core/include/math/ci-realfft.h`, `src/core/lib/math/ci-realfft.cpp`):
   `CIBsgsPlan` now also reports `babies` and `giants` (the rotations the level performs after window
   alignment). `CIPlanBsgsN1` builds the aligned plan for a given n1, `CIPlanBsgsRatio` is the old rule
   n1 = ceil(ratio sqrt(span)), and `CIPlanBsgsMinCost` tries every n1 in [1, span] and keeps the one with the
   smallest `babies + giantCost * giants` (exact counts, ties to the smaller n1).
2. **Cost model** `CIBsgsGiantCost(digits)`: cost of one giant step over one hoisted baby rotation, from the item 2.1
   `[LT]` per-op times (ms per QlP tower at 2^16): baby 0.63 D + 0.40, giant = ModUp 2.35 D + key switch and
   automorphisms (= a baby) + ModDown of one polynomial 2.45 + one extended add 0.15, with D = key-switching digits
   of the level input. The tower count cancels, so the ratio depends on D only: 5.81 (D = 1), 5.40 (D = 2), 5.21
   (D = 3). The fixed rule n1 = 2 sqrt(span) is the continuous optimum for a ratio of 4.
3. **Per-level input** (`ckksrns-fhe.cpp`): `CIBsgsLevelDigits` gives the Q towers and digits of every CtS / StC
   level from the chain shape (CtS level s: L0 - (1 + s) towers; StC level s: L0 - (lbEnc + modDepth + s);
   D = min(dnum, ceil(Ql / alpha))). Keygen (`CIRealFFTGaloisElements`) and `EvalBootstrap` both plan from these
   numbers, not from the runtime ciphertext, so their rotation sets agree by construction; the item 0.4 Galois check
   held in every run. With `CI_BOOT_TIMING=1` the `[CI-BT] level` line prints n1, babies, giants, digits and the
   runtime vs modelled towers: 0 mismatches in 156 levels at 2^12-2^14 (encapsulated and uniform secrets, budgets
   {2,2}..{5,5}, `p22_build2`) and 484 levels at 2^16 (`p22_ab`, `p22_final`, dnum 3 and 4) after the StC formula
   was corrected (first smoke `p22_smoke`: StC model one tower low).
4. `CI_BSGS_RATIO=r` still forces the fixed rule (r = 2 gives the pre-2.2 plan); used for the A/B below and to
   be removed in item 6.2 with the other switches.
5. New tool `ci-ckks-paper/tools/ci-bsgs-plan.cpp` (standalone, links `ci-realfft.cpp`): for 2^12..2^16 and budgets
   2..5 prints every level's window, the ratio-2 plan and the cost-model plan for D = 1..3 with modelled costs.

**Commands (ICELAKE, `~/ci-ckks-fft`).** Helper scripts on ICELAKE only: `p22_run.sh "mode scheme logN lbEnc lbDec
corr reps secure [dnum]"` runs `CI_BOOT_TIMING=1 build/bin/benchmark/ci-fft-boot $2 $3 $4 $5 59 60 $8 $7 fa $6 encap 0
${9:-0}` with 1 thread (mode 0 = cost model, mode 1 = `CI_BSGS_RATIO=2`, the pre-2.2 plan). `p22_final.sh` runs the
committed code: 2^12 {3,3} and {5,5}, 2^10 {1,1}, then CI {5,3}, std {5,3} (build-bt), CI {4,3}, CI {4,4}, std {4,4}
(build-bt) at 2^16, 128-bit, reps 3.

    ci-ckks-paper/tools/sync.sh   # (on WSL; four times)
    ./guard.sh p22_plan   "cd openfhe-development && g++ -O2 -std=c++17 -Isrc/core/include ci-ckks-paper/tools/ci-bsgs-plan.cpp \
      src/core/lib/math/ci-realfft.cpp -o ../scratch/ci-bsgs-plan && ../scratch/ci-bsgs-plan 12 16 sweep"  # rc 0
    ./guard.sh p22_build  "<cmake --build build --target ci-fft-boot -j 32>"   # compile error (shadowed name), fixed; the
                          # rebuild succeeded but its `exit` skipped the .rc file (log: Built target ci-fft-boot)
    ./guard.sh p22_smoke  "./p22_run.sh '0 ci 12 3 3 4 2 0' '1 ci 12 3 3 4 2 0' '0 ci 12 4 4 4 2 0' '1 ci 12 4 4 4 2 0' \
      '0 ci 12 5 5 4 2 0' '0 ci 12 2 2 4 2 0' '0 ci 13 4 3 4 2 0' '0 ci 14 5 3 4 2 0' '0 ci 15 3 3 4 2 0' '0 ci 10 1 1 4 2 0' \
      && <ci 12 4 4 ... uniform>"                                                                       # rc 0
    ./guard.sh p22_build2 "<build ci-fft-boot -j 32> && ./p22_run.sh '0 ci 12 3 3 4 2 0' '0 ci 12 4 4 4 2 0' \
      '0 ci 12 5 5 4 2 0' '0 ci 12 2 2 4 2 0' '0 ci 14 5 3 4 2 0' && <ci 12 4 4 uniform> && <ci 13 5 3 uniform>"  # rc 0
    ./guard.sh p22_ab     "./p22_run.sh '0 ci 16 4 3 4 3 1' '1 ci 16 4 3 4 3 1' '0 ci 16 5 3 4 3 1' '1 ci 16 5 3 4 3 1' \
      '0 ci 16 4 4 4 3 1' '0 ci 16 5 4 4 3 1 4' '1 ci 16 5 4 4 3 1 4' '1 ci 16 5 3 4 3 1' '0 ci 16 5 3 4 3 1' \
      '1 ci 16 4 3 4 3 1' '0 ci 16 4 3 4 3 1'"                                                          # rc 0
    ./guard.sh p22_build3 "<build ci-fft-boot -j 32 in build and build-bt>"                            # rc 0, no warnings
    ./guard.sh p22_final  ./p22_final.sh                                                               # rc 0

Logs: `~/ci-ckks-fft/logs/p22_*.log`. Load average 1-5 in `p22_ab` (another user's test jobs ran at the start), 0.7-1.3
in `p22_final`.

**Results 1: plans** (`ci-bsgs-plan`, N = 2^16; b/g = baby / giant rotations; cost in hoisted-baby units at the
level's D; CtS at 2^16 has D = 3, StC D = 1 for alpha 7).

| budget | level(s) | diags / span | ratio-2 plan n1, b/g | cost-model plan n1, b/g | modelled rotation cost |
|---|---|---|---|---|---|
| lb 4 (all levels) | CtS / StC | 16 / 16, 62-63 / 63-64 | 8, 7/1; 16, 15/3 | same | same |
| lb 3 | CtS 1, 2 / StC 0, 1 | 126-127 / 132-133 | 23, 22/5 | 32, 31/3 (StC 1 at D = 3: 21, 20/5) | -3.0% (D 3), -5.1% (D 1) |
| lb 3 | CtS 0 / StC 2 | 64 / 64 | 16, 15/3 | same | same |
| lb 5 | CtS 1-4 / StC 0-3 | 30-31 / 37-40 | 11-12, 10-11/3 | 15-16, 14-15/1 | -21% to -28% |
| lb 2 | 256 / 1023 diags | 256 / 1024 | 32, 31/7; 64, 63/15 | 37, 36/6; 74, 73/13 | -0.3% to -1.1% |

The lb-5 windows hold 30-31 diagonals spread over 37-40 positions, so 2 sqrt(span) = 12 gives 4 blocks (3 giants);
n1 = 15-16 covers the window in 2 aligned blocks, one of them at offset 0 (1 giant). At 2^12..2^15 the same happens
for the 30-31-diagonal levels of lb 4 and 5, and for the 8-diagonal levels (n1 6 -> 8, no giant).
The {4,4} plan at 2^16 is unchanged.

**Results 2: A/B at 2^16** (128-bit, 1 thread, warm median of 3, two runs per mode in `p22_ab`, `p22_final` for the
committed code; CI stages from `CI_BOOT_TIMING`, warm medians).

| CI budget | plan | warm s | CtS | EvalMod | StC | Galois keys | keys GB | peak RSS GB | RMS / min bits |
|---|---|---|---|---|---|---|---|---|---|
| {5,3} | ratio 2 (pre-2.2) | 23.73, 23.49 | 10.94, 10.84 | 7.47 | 4.74, 4.63 | 97 | 7.96 | 13.10 | 21.56 / 18.37-18.46 |
| {5,3} | cost model | 22.41, 22.34; **22.34** (final) | 9.71, 9.65; 9.64 | 7.47 | 4.65, 4.63; 4.64 | 108 | 8.86 | 14.10 | 21.56 / 17.99-18.58 |
| {4,3} | ratio 2 | 23.79, 24.17 (2.1: 23.75) | 10.95, 11.22 | 7.49-7.56 | 4.74, 4.80 | 100 | 7.91 | 13.97 | 21.56 / 18.16-18.37 |
| {4,3} | cost model | 23.79, 23.48; 23.58 (final) | 10.94, 10.88; 10.91 | 7.44-7.50 | 4.68, 4.61; 4.64 | 110 | 8.70 | 14.76 | 21.56-21.57 / 18.24-18.43 |
| {5,4} dnum 4 | ratio 2 | 24.87 | 12.24 | 8.26 | 3.69 | 83 | 9.08 | 13.37 | 21.54 / 17.48 |
| {5,4} dnum 4 | cost model | 23.44 | 10.77 | 8.30 | 3.77 | 86 | 9.41 | 13.80 | 21.56 / 17.96 |
| {4,4} | unchanged plan | 23.93; 23.98 (final) (2.1: 23.84) | 11.46, 11.48 | 8.18 | 3.69, 3.73 | 61 | 5.01 | 10.42 | 21.56 / 18.35-18.47 |

Per level ({5,3} CtS, 19..16 + 7 towers, D = 3): ratio 2 does 10-11 babies + 3 giants, the cost model 15 + 1. The
measured rotation cost of a level (ModUp + baby + giant + ModDown) drops from 1.80 / 1.73 / 1.65 / 1.63 s to
1.48 / 1.43 / 1.36 / 1.30 s (-0.29 to -0.33 s per level, 1.28 s for CtS). The model predicts 5.4 baby units x
57 ms = 0.31 s per level. At {4,3} StC levels 0-1 (6, 5 + 7 towers, D = 1) the model predicts 2.6 units x 13 ms =
0.035 s; measured 0.735 -> 0.715 s and 0.678 -> 0.648 s rotation cost (-0.02 to -0.03 s), within run-to-run noise
of the total.

**Results 3: new baseline** (`p22_final`, committed code, load 0.7-1.3):

| | warm s | CtS | EvalMod | StC | keys | RMS / min bits |
|---|---|---|---|---|---|---|
| CI {5,3} corr 4 | **22.34** | 9.64 | 7.47 | 4.64 | 108 (8.86 GB), peak RSS 14.10 GB | 21.56 / 18.06 |
| std {5,3} corr 5 | **21.85** | 6.78 | 11.57 | 3.04 | 61 | 22.75 / 19.50 |
| CI {4,3} | 23.58 | 10.91 | 7.47 | 4.64 | 110 | 21.56 / 18.24 |
| CI {4,4} | 23.98 | 11.48 | 8.19 | 3.73 | 61 (5.01 GB), 10.42 GB | 21.56 / 18.35 |
| std {4,4} | 23.54 | 8.03 | 12.74 | 2.32 | 76 | 22.75 / 20.24 |

- CI's best budget is now {5,3}, the same as std's: **2 x 21.85 / 22.34 = 1.96x** (2.1: 1.84x with CI {4,3}).
  Against the paper's 12.6 s, CI is 1.77x (2.1: 1.89x).
- Stage ratios at the equal budget {5,3}: CtS 9.64 / 6.78 = 1.42x, EvalMod 0.65x, StC 4.64 / 3.04 = 1.53x. At
  {4,4}: CtS 1.43x, EvalMod 0.64x, StC 1.61x (unchanged plan).
- Precision does not change with the plan (RMS 21.56 bits in every CI run; min error in the usual 17.5-18.6 band).

**Conclusions.**
- The giant/baby cost ratio is 5.2-5.8 at every level of the 2^16 chain: it depends on the key-switching digit
  count, not on the tower count, because baby, ModUp and ModDown all scale with the QlP towers. So "per-level"
  changes little through the ratio itself; what matters is choosing n1 by exact counts after window alignment.
  The old rule n1 = ceil(2 sqrt(span)) was badly off for the lb-5 levels (sparse windows of 30 diagonals in 37-40
  positions: 3 giants where 1 suffices) and for span-8 levels; for the dense 63-64-diagonal levels of lb 4 it was
  already optimal.
- At 2^16 the model saves 1.3-1.4 s (-5.5% to -5.8%) at CtS budget 5 ({5,3}, {5,4}) and nothing measurable at
  {4,3} / {4,4}. CI {5,3} (22.34 s) replaces {4,3} as CI's best budget; CI/2xstd is 1.96x.
- Cost: the time-optimal plans use more baby keys. {5,3}: 97 -> 108 keys (+0.9 GB keys, +1.0 GB peak RSS);
  {4,3}: 100 -> 110 keys (+0.8 GB) for a gain of about 0.03 s. The model ignores key memory. Suggestion for the plan
  adapter (not added to the plan): a key-aware tie-break (count only keys not already used by another level with the
  same stride h) if memory matters; and item 2.3 should use `CIPlanBsgsMinCost` counts (not 2 sqrt(d)) in its
  (diagonals x limbs) cost model, since the window shape decides the giant count.
- The baseline commands change to CI {5,3} (same budget as std).

## 2.3 Uneven layer splits from a (diagonals x towers) cost model (2026-10-28)

**State.** An earlier executor of 2.3 was cut off (authentication failure, about 01:40) after writing the env probe
and the search tool and running `p23_search`, `p23_search2`, `p23_build` and `p23_ab` on ICELAKE (all rc 0; ICELAKE
was synced from the WSL tree with those two changes, `SYNCED_FROM d2cfdadc 2`, before the build). Those runs are
reused below. This session added the default split table, rebuilt and ran `p23_search3`, `p23_smoke`, `p23_final`.

**What changed.**
1. `CIBuildRealLevels` (`ckksrns-fhe.cpp`) takes the split of the l = log2 N FFT layers over the levels from
   `CIDefaultLayerSplit(l, lb, enc)`: a table of the model-best splits (layer order, F_1 first) at l = 12..16 and
   lb = 3..5 (StC lb 3..4), and the even split (larger parts first, the old rule) for any other (l, lb). CtS level s
   is part s; StC level s is the transpose of part lb-1-s. Keygen and the evaluator both build their levels through
   `GetCIRealLevels`, so their rotation sets agree (the item 0.4 Galois check held in every run).
2. `CI_SPLIT_ENC` / `CI_SPLIT_DEC` = "n0,n1,..." force a split (A/B switch; throws unless lb positive parts sum to
   l). To be removed in item 6.2 with the other switches.
3. New tool `ci-ckks-paper/tools/ci-split-search.cpp` (standalone, links `ci-realfft.cpp`). For every composition of
   the l layers into lb parts it builds each level's numeric product (`CISparseMul`, as `CIBuildRealLevels`; ranges
   above 1100 diagonals are skipped), plans it with `CIPlanBsgsMinCost` at the level's digits (item 2.2), and costs
   it as (Ql + P) towers x [(g+1) ModUp 2.35 D + (b+g) key switch (0.63 D + 0.40) + (g+2) ModDown 2.45 + d ptMult
   0.646 + (d+g) add 0.15] ms (item 2.1 per-op times at 2^16), with Ql and D from the chain shape as
   `CIBsgsLevelDigits`. It prints the default split, the top K and their Galois shifts.
   The first version (`p23_search`) counted diagonals from the sumset of the layers' offsets; that overcounts
   (adjacent layers cancel exactly: e.g. a middle 3-layer range has 30 numeric vs 36 symbolic diagonals, 15 of 18
   ranges differed) and gave wrong rankings, so the tool now uses numeric products (`p23_search2`).

**Commands (ICELAKE, `~/ci-ckks-fft`).** Helper scripts on ICELAKE only: `p23_search.sh B...` builds the tool into
`../scratch` and runs `ci-split-search 16 lbEnc lbDec 10` per budget; `p23_run.sh "enc:dec:logN:lbEnc:lbDec:reps:secure[:dnum]"`
runs `CI_BOOT_TIMING=1 OMP_NUM_THREADS=1 build/bin/benchmark/ci-fft-boot ci logN lbEnc lbDec 59 60 secure reps fa 4
encap 0 [dnum]` with `CI_SPLIT_ENC=enc` / `CI_SPLIT_DEC=dec` ("-" = default) under `/usr/bin/time`.

    # earlier executor (env probe + tool, even split still the default)
    ./guard.sh p23_search  "./p23_search.sh 5x3 4x4 4x3 3x3"            # rc 0, symbolic counts (discarded)
    ./guard.sh p23_search2 "./p23_search.sh 5x3 4x4 4x3 3x3 5x4"        # rc 0, numeric counts
    ./guard.sh p23_build   "<cmake --build build --target ci-fft-boot -j 32>"   # Built target (no .rc written)
    ./guard.sh p23_ab      "./p23_run.sh -:-:12:3:3:2:0 5,4,3:6,3,3:12:3:3:2:0 -:-:12:5:3:2:0 4,2,2,2,2:5,4,3:12:5:3:2:0 \
      -:-:16:5:3:3:1 -:7,5,4:16:5:3:3:1 5,2,3,3,3:7,5,4:16:5:3:3:1 -:7,4,5:16:5:3:3:1 -:-:16:5:3:3:1 -:7,5,4:16:5:3:3:1 \
      -:-:16:4:4:3:1 5,3,4,4:6,4,3,3:16:4:4:3:1 -:-:16:4:3:3:1 5,3,4,4:7,5,4:16:4:3:3:1"          # rc 0
    # this session
    ./guard.sh p23_search3 ./p23_search3.sh   # ci-split-search at logN 12..15, budgets 3x3 4x4 5x3 4x3; rc 0
    ci-ckks-paper/tools/sync.sh               # (WSL) SYNCED_FROM d2cfdadc 3
    ./guard.sh p23_build2 "<cmake --build build --target ci-fft-boot -j 32>"  # Built target, no warnings (the
                          # command's `exit` skipped the .rc); p23_build3 = same no-op rebuild, rc 0
    ./guard.sh p23_smoke ./p23_smoke.sh       # 14 runs at 2^12..2^15, insecure, reps 2; rc 0
    ./guard.sh p23_final ./p23_final.sh       # 2^16, 128-bit, reps 3, interleaved new/old; rc 0
    #   p23_final.sh: ./p23_run.sh -:-:16:5:3:3:1 -:6,5,5:16:5:3:3:1 -:-:16:4:4:3:1 4,4,4,4:4,4,4,4:16:4:4:3:1 \
    #     -:6,5,5:16:5:3:3:1 -:-:16:5:3:3:1 4,4,4,4:4,4,4,4:16:4:4:3:1 -:-:16:4:4:3:1 -:-:16:4:3:3:1

Load average: `p23_ab` 0.5-1.1 for the first 2^16 pair, then another user's jobs raised it to 7.6-18 (01:16-01:30;
the {5,3} pass 2 and the {4,4} default run are affected) and back to 1.0-2.6. `p23_final` 0.8-4.4 (one of those
cores is the run itself); the second old-split {5,3} run (08:01) is disturbed (CtS 10.10 s, EvalMod 7.69 s).

**Results 1: model search at 2^16** (`p23_search2`; parts in layer order, F_1 first; model time of the transform).
Range diagonal counts: the first k layers have 2^k diagonals; a k-layer range in the middle has 2^(k+2) - 2; the last
k layers 2^(k+2) - 1. So the first part can take 1-2 more layers than the others at the same cost.

| transform, lb | even split (model s, rank) | model #1 | #2 | #3 |
|---|---|---|---|---|
| CtS lb 5 ({5,3}) | [4,3,3,3,3] 9.49 s, rank 1 | = even | [5,2,3,3,3] +0.03 | [5,3,2,3,3] +0.06 |
| CtS lb 4 ({4,4}) | [4,4,4,4] 11.30 s, rank 7 | [5,3,4,4] -0.44 | [5,4,3,4] -0.40 | [6,3,3,4] -0.35 |
| CtS lb 3 ({3,3}) | [6,5,5] 13.64 s, rank 1 | = even | [7,4,5] +0.04 | [7,5,4] +0.13 |
| StC lb 3 (any CtS budget) | [6,5,5] 4.95 s, rank 3 | [7,5,4] -0.14 | [7,4,5] -0.07 | [6,5,5] 0 |
| StC lb 4 | [4,4,4,4] 3.89 s, rank 11 | [6,4,3,3] -0.38 | [6,3,4,3] -0.34 | [6,3,3,4] -0.32 |

The best split of one transform does not depend on the other transform's budget (the StC towers do not depend on
lbEnc; CtS towers shift uniformly with lbDec). The plan's example [5,6,5] is #10 for StC lb 3 (+1.09 s: a middle
6-layer range has 254 diagonals). At 2^12..2^15 (`p23_search3`) the even split is model-best only at l = 13 CtS lb 3
and lb 4; elsewhere the model gains 0.06-0.87 model-s (the table in `CIDefaultLayerSplit` lists them).

**Results 2: top-3 A/B at 2^16** (128-bit, 1 thread, reps 3; warm median; stage times are medians of the 3 warm
bootstraps from `CI_BOOT_TIMING`; "old" = the pre-2.3 even split). `p23_ab` ran on the old binary with env splits;
`p23_final` on the new binary (default = model split, old via env).

| budget | CtS split | StC split | run | warm s | CtS | EvalMod | StC | keys (GB) | peak RSS GB | RMS / min bits |
|---|---|---|---|---|---|---|---|---|---|---|
| {5,3} | even | [6,5,5] old | ab p1 / final p1 | 22.31 / 22.35 | 9.64 / 9.64 | 7.47 | 4.63 / 4.64 | 108 (8.86) | 14.10 | 21.56 / 18.48-18.52 |
| {5,3} | even | [6,5,5] old | ab p2 (load 10-14) / final p2 (disturbed) | 22.56 / 23.22 | 9.74 / 10.10 | 7.53 / 7.69 | 4.70 / 4.87 | 108 | 14.10 | 21.56 / 18.25-18.53 |
| {5,3} | even | **[7,5,4]** #1 | ab p1, p2 (load 10-14) | 22.21, 22.40 | 9.65, 9.73 | 7.47, 7.50 | 4.50, 4.54 | 102 (8.37) | 13.55 | 21.55-21.56 / 17.97-18.43 |
| {5,3} | even | **[7,5,4]** new default | final p1, p2 | **22.15**, 22.18 | 9.63, 9.65 | 7.47, 7.48 | 4.47, 4.49 | 102 (8.37) | 13.55 | 21.55-21.57 / 18.37-18.54 |
| {5,3} | even | [7,4,5] #2 | ab (load 7.6-10) | 22.52 | 9.70 | 7.54 | 4.58 | 105 (8.62) | 13.83 | 21.56 / 18.44 |
| {5,3} | [5,2,3,3,3] #2 | [7,5,4] | ab (load rose to 7.6) | 22.56 | 9.78 | 7.49 | 4.81 | 106 (8.70) | 13.91 | 21.57 / 18.73 |
| {4,4} | [4,4,4,4] | [4,4,4,4] old | final p1, p2 | 24.03, 23.89 | 11.51, 11.41 | 8.20, 8.17 | 3.73, 3.72 | 61 (5.01) | 10.42 | 21.55 / 18.19-18.49 |
| {4,4} | **[5,3,4,4]** | **[6,4,3,3]** new | final p1, p2 | **23.18, 23.11** | 11.02, 10.99 | 8.20, 8.16 | 3.37, 3.38 | 92 (7.55) | 12.56 | 21.56 / 18.30-18.68 |
| {4,4} | [5,3,4,4] | [6,4,3,3] | ab (load 18 -> 2.6) | 23.00 | 10.96 | 8.12 | 3.34 | 92 | 12.56 | 21.55 / 18.22 |
| {4,3} | [4,4,4,4] | [6,5,5] old | ab | 23.50 | 10.89 | 7.44 | 4.61 | 110 (8.70) | 14.76 | 21.56 / 18.58 |
| {4,3} | **[5,3,4,4]** | **[7,5,4]** new | ab / final | 23.00 / **23.05** | 10.46 / 10.53 | 7.46 / 7.49 | 4.50 / 4.48 | 99 (7.83) | 13.63 | 21.56-21.57 / 17.98-18.45 |

(The {4,4} old-split run in `p23_ab`, 24.77 s at load 10-18, is not used.) Setup + keygen: {5,3} 55.7 -> 52.6 s,
{4,4} 31.9 -> 47.4 s. The cold first bootstrap is unchanged (42-45 s).

**Model vs measured** (stage change, s):

| change | model | measured |
|---|---|---|
| {5,3} StC [6,5,5] -> [7,5,4] | -0.14 | -0.16 (4.64 -> 4.48) |
| {5,3} StC [6,5,5] -> [7,4,5] | -0.07 | -0.05 to -0.12 (under load) |
| {4,4} CtS [4,4,4,4] -> [5,3,4,4] | -0.44 | -0.46 (11.46 -> 11.00) |
| {4,4} StC [4,4,4,4] -> [6,4,3,3] | -0.38 | -0.35 (3.73 -> 3.38) |
| {4,3} CtS [4,4,4,4] -> [5,3,4,4] | -0.43 | -0.43 (10.89 -> 10.46) |
| {4,3} StC [6,5,5] -> [7,5,4] | -0.14 | -0.11 (4.61 -> 4.50) |

**Results 3: correctness at 2^12..2^15** (`p23_smoke`, new defaults, insecure, reps 2; the Galois check held in all
42 bootstraps). RMS / min bits are the same as with the old split: 2^12 18.80 / 17.18 ({3,3}, {4,4} new and old,
{5,3}, {4,3}), 2^13 19.71 / 18.03, 2^14 20.71 / 18.90-18.95, 2^15 21.64-21.65 / 19.58-19.69. Keys at 2^12: {3,3}
44 -> 64, {4,4} 55 -> 62.

**Conclusions.**
- The (diagonals x towers) model with the 2.2 BSGS counts predicts the stage change of every measured split within
  0.03 s. The even split was already model-best for CtS lb 5 and lb 3 at 2^16, so CI's best budget {5,3} only gains
  in StC: [7,5,4] puts the 4 cheap last layers (63 diagonals) at the level with the most towers. CI {5,3} 22.34 ->
  22.15 s (-0.9%; final pass 1: 22.15 vs 22.35 interleaved), 108 -> 102 keys, peak RSS 14.10 -> 13.55 GB. New
  baseline: 2 x 21.85 / 22.15 = 1.97x; at {5,3} StC is 4.47 / 3.04 = 1.47x std's (was 1.53x), CtS 1.42x.
- At budget 4 the gain is larger (CtS -0.46 s, StC -0.35 s): {4,4} 23.98 -> 23.15 s (2.03x std {4,4}; CtS 1.37x,
  StC 1.45x), {4,3} 23.50 -> 23.05 s. The cost is keys: the {4,4} split has 92 instead of 61 keys (+2.5 GB, +2.1 GB
  peak RSS, keygen +15 s). {5,3} stays CI's best budget.
- The #2 and #3 splits measured as the model ranks them ([7,4,5] between [7,5,4] and [6,5,5]; [5,2,3,3,3] no gain).
- The table is static (computed offline for the chain shape lbEnc + 10 + lbDec + 2 + 1, dnum 3, alpha 7). A
  different chain could move the optimum; `CI_SPLIT_ENC/DEC` override it. Suggestion (not added to the plan): if key
  memory matters, a key-aware tie-break in the search (the {4,4} split trades 31 keys for 0.8 s).

## 2.4 Precompute the CI diagonal plaintexts in EvalBootstrapSetup; WSL baseline (2026-10-28)

First item on the WSL VM (i7-12700H laptop, `build-wsl` / `build-wsl-bt`, all jobs through
`ci-ckks-paper/tools/wsl-guard.sh`). Nothing ran on ICELAKE. ICELAKE numbers (items 0.1-2.3) are not comparable with
the numbers below.

**WSL baseline at HEAD (b09005e7 = code of fbb0ad1a, item 2.3), measured before any change.** Header commands with
`build-wsl` paths; std from `build-wsl-bt` (same code with `-DBOOTSTRAPTIMING`, for the std stage times). One guarded
job, CI and std interleaved, 2^16, 128-bit, 1 thread, reps 3; warm medians; stage times are medians of the 3 warm
bootstraps (`CI_BOOT_TIMING=1` for CI, `BOOTSTRAPTIMING` for std).

    wsl-guard.sh p24_build_bt 12 'cmake --build build-wsl-bt --target ci-fft-boot -j 8'     # rc 0 (build-wsl was built at HEAD before)
    wsl-guard.sh p24_base 15 'for a in "build-wsl/... ci 16 5 3" "build-wsl-bt/... std 16 5 3" "build-wsl/... ci 16 4 4" \
        "build-wsl-bt/... std 16 4 4"; do CI_BOOT_TIMING=1 OMP_NUM_THREADS=1 $bin $scheme 16 $lbE $lbD 59 60 1 3 fa $corr encap; done'
        # corr 4 (CI) / 5 (std); rc 0, load 0.6-2.5

| scheme {budget} | warm s | CtS | EvalMod | StC | first s | setup+keygen s | keys (GB) | peak RSS GB | RMS / min bits |
|---|---|---|---|---|---|---|---|---|---|
| CI {5,3} | **16.37** | 6.99 | 5.34 | 3.62 | 39.02 | 44.98 | 102 (8.37) | 13.55 | 21.55 / 18.15 |
| std {5,3} | **16.25** | 5.16 | 8.44 | 2.32 | 17.54 | 35.06 | 61 (5.01) | 7.66 | 22.73 / 19.21 |
| CI {4,4} | 17.48 | 8.37 | 6.30 | 2.68 | 36.20 | 47.13 | 92 (7.55) | 12.56 | 21.55 / 18.27 |
| std {4,4} | 18.23 | 6.11 | 9.92 | 1.87 | 17.64 | 42.65 | 76 (6.24) | 9.08 | 22.74 / 19.95 |

WSL baseline: CI/2xstd at each scheme's best budget {5,3} = 2 x 16.25 / 16.37 = **1.99x** (ICELAKE 1.97x); stage
ratios CtS 1.36x, EvalMod 0.63x, StC 1.56x. Equal budget {4,4}: 2 x 18.23 / 17.48 = 2.09x (ICELAKE 2.03x); CtS 1.37x,
EvalMod 0.64x, StC 1.43x. The laptop takes about 26% less time per bootstrap than ICELAKE (CI {5,3} 16.4 vs 22.15 s) and
noisier: in `p24_ab` below the same binary gave 16.5 and 18.9 s warm medians 4 minutes apart (thermal / turbo), so
only interleaved A/B pairs in one job are comparable. The cold first CI bootstrap was 39.0 s, 22.7 s above warm:
the diagonal encodes that this item moves to setup.

**What changed** (`src/pke/lib/scheme/ckksrns/ckksrns-fhe.cpp`, driver).
1. `EvalBootstrapSetup` (with `precompute = true`, the default) and `EvalBootstrapPrecompute` now encode all CI
   CtS / StC diagonal plaintexts: new `CIBootstrapPrecompute` fills `m_U0hatTPreFFT` / `m_U0PreFFT` (one store per
   real-FFT level, budget > 1) or `m_U0hatTPre` / `m_U0Pre` (dense budget {1,1}). Before, `EvalBootstrapSetup`
   returned early for `REAL_CI` and the const `EvalBootstrap` wrote the plaintexts into the precom on its first
   call (not safe under concurrent bootstraps; `EvalBootstrapPrecompute` ran the complex std precompute on CI).
2. The encodes keep the extended Q_l P form of the lazy path. The tower count of every level comes from the chain
   shape (`CIBsgsLevelDigits`, the model keygen already uses, item 2.2); the basis is the first `towers` Q moduli plus
   P (`CIParamsQlP`, the basis `KeySwitchExt` builds) and the level is |Q| - towers (as `ModRaiseInPlace` sets it).
   The BSGS layout and pre-rotation are unchanged (`CIEncodeSparseLevel`, `CIEncodeDenseLevel`, factored out of the
   old evaluator lambdas). The CI scalars scaleEnc / scaleDec come from one helper (`CIBootScales`) in setup and
   evaluation.
3. Encodes run in parallel at setup (`omp parallel for` over the diagonals of a level, dense: over giant blocks;
   `OpenFHEParallelControls` thread limit). The CI encode path (`CIRealFFTEncode`, CI NTT registry) is thread safe
   (mutex-guarded plan cache, lock-free registry lookups).
4. `EvalBootstrap` only reads the stores. If a store does not match the level input (size, plaintext level and
   tower count: `CIStoreMatches`), e.g. after `EvalBootstrapSetup(..., precompute = false)`, the level is encoded
   into a local vector for that call only. `CI_BOOT_TIMING=1` prints `local diagonal encodes: <n> levels`; it was 0
   in every run below.
5. Driver `ci-fft-boot`: the RESULT line also prints `bootsetup_s` (EvalBootstrapSetup alone; `setup+keygen_s`
   still includes it).

**Commands.** `OLD` = a copy of the HEAD `build-wsl` binary and libraries (`~/ci-ckks-wsl/head-fbb0ad1a`, run with
`LD_LIBRARY_PATH`), `NEW` = `build-wsl/bin/benchmark/ci-fft-boot` after the change.

    wsl-guard.sh p24_build 12 'cmake --build build-wsl --target ci-fft-boot -j 8'    # rc 0, no warnings
    wsl-guard.sh p24_smoke 9 'for cfg in "12 1 1" "12 2 2" "12 3 3" "12 4 4" "12 5 3" "13 4 4" "14 5 3" "15 5 3" "15 4 4";
        do for v in old new; do CI_BOOT_TIMING=1 OMP_NUM_THREADS=1 $v ci $logN $lbE $lbD 59 60 0 2 fa 4 encap; done; done'  # rc 0
    wsl-guard.sh p24_ab 15 'old, new, old, new: CI_BOOT_TIMING=1 OMP_NUM_THREADS=1 $v ci 16 5 3 59 60 1 3 fa 4 encap;
        then old, new: CI_BOOT_TIMING=1 OMP_NUM_THREADS=8 $v ci 15 5 3 59 60 0 1 fa 4 encap'   # rc 0, load 2.0-4.6
    wsl-guard.sh p24_build_bt2 12 'cmake --build build-wsl-bt --target ci-fft-boot -j 8'  # rc 0 (bt dir at the new code)
    wsl-guard.sh p24_build3 12 "<both build-wsl and build-wsl-bt, ci-fft-boot, -j 8>"     # rc 0 after a line-wrap-only edit

**Results 1: correctness at 2^12..2^15** (`p24_smoke`, insecure, reps 2, 1 thread). Old and new give the same
precision, keys and peak RSS in all 9 configurations ({1,1}, {2,2}, {3,3}, {4,4}, {5,3} at 2^12; {4,4} at 2^13;
{5,3} at 2^14; {5,3}, {4,4} at 2^15). The Galois check held and no level was encoded locally in any bootstrap.

| N, budget | old first / warm s | new bootsetup / first / warm s | RMS / min bits old, new | peak RSS GB |
|---|---|---|---|---|
| 2^12 {1,1} (dense) | 19.87 / 5.77 | 14.93 / 5.30 / 5.63 | 18.80 / 17.18, same | 4.88 |
| 2^12 {5,3} | 1.21 / 0.79 | 0.37 / 0.73 / 0.71 | 18.80 / 17.18, same | 0.48 |
| 2^13 {4,4} | 2.15 / 1.40 | 0.96 / 1.33 / 1.64 | 19.71 / 18.02, 19.71 / 18.04 | 1.18 |
| 2^14 {5,3} | 5.88 / 3.30 | 2.68 / 3.11 / 3.39 | 20.71 / 18.89, 20.71 / 18.91 | 2.37 |
| 2^15 {5,3} | 14.28 / 7.64 | 7.40 / 7.56 / 7.84 | 21.64 / 19.71, 21.65 / 19.68 | 5.89 / 5.88 |
| 2^15 {4,4} | 14.71 / 7.78 | 6.94 / 7.63 / 7.65 | 21.64 / 19.57, 21.65 / 19.62 | 5.66 |

**Results 2: 2^16 A/B** (`p24_ab`, 128-bit, CI {5,3}, 1 thread, reps 3, interleaved old/new/old/new; stage times
are the medians of the 3 warm bootstraps; "cold extra" = the first bootstrap's CtS + StC minus the warm ones).

| run | setup+keygen s | bootsetup s | first s | warm s | first CtS / StC | warm CtS / EvalMod / StC | RMS / min | peak RSS GB |
|---|---|---|---|---|---|---|---|---|
| old pass 1 | 44.30 | - | 35.51 | 17.32 | 15.76 / 13.50 (cold extra 17.8 s) | 7.85 / 5.38 / 3.66 | 21.56 / 18.17 | 13.55 |
| new pass 1 | 62.67 | 18.49 | **18.04** | 16.53 | 8.01 / 3.67 | 7.06 / 5.63 / 3.77 | 21.55 / 18.24 | 13.54 |
| old pass 2 | 45.88 | - | 35.35 | 19.46 | 15.73 / 13.32 (cold extra 17.0 s) | 8.10 / 6.81 / 4.00 | 21.56 / 18.22 | 13.55 |
| new pass 2 | 75.99 | 20.95 | **19.60** | 18.86 | 9.46 / 3.69 | 7.83 / 5.81 / 3.67 | 21.55 / 18.08 | 13.54 |

Pass 2 ran hotter (old warm +2.1 s, new +2.3 s, new keygen +12 s at the same code); compare within a pass. No job
spanned a laptop sleep: every run's wall time in the logs (2.2-2.6 min per 2^16 run) matches setup + first + reps. Keys 102
(8.37 GB) and the Galois check (100 rotations) are unchanged.

**Results 3: parallel setup encodes** (`p24_ab` tail, 2^15 {5,3}, insecure, 8 threads, reps 1): old setup+keygen
7.20 s, first 16.39 s, warm 7.16 s (the lazy encode in the first bootstrap is serial: 9.2 s extra); new
bootsetup 2.52 s (1 thread: 7.40 s, `p24_smoke`; 2.9x on 8 threads of this 6P+8E CPU), setup+keygen 10.41 s,
first 7.30 s, warm 6.87 s. Time to the first bootstrapped result: 23.6 -> 17.7 s.

**Conclusions.**
- The cold first bootstrap is gone: at 2^16 {5,3} the first bootstrap now takes 18.0 s against a 16.5 s warm median
  (old: 35.5 s against 17.3 s). The remaining ~1 s first-call excess is ordinary warm-up (std shows the same: 17.5
  vs 16.3 s). The encode work moved into `EvalBootstrapSetup`: 18.5 s at 1 thread (old cold extra 17.0-17.8 s, plus
  the level products, which keygen built before), 2.9x faster on 8 threads.
- Warm time, precision, keys and memory are unchanged: peak RSS 13.54 vs 13.55 GB at 2^16 {5,3} (the stores held the
  same plaintexts after the first bootstrap before), inside the 15 GB the jobs requested (job cap now 19 GB). The plaintexts are
  about 454 diagonals at {5,3} (137 CtS at 23-27 towers, 317 StC at 11-13 towers, Q_l + P).
- `EvalBootstrap` no longer writes into the precom; it is read-only and so safe for concurrent bootstraps on one
  context. `EvalBootstrapPrecompute` (the documented deserialize-then-recompute flow) now builds the CI stores too.
- The "~70 s cold run" in the plan was an early ICELAKE number (before items 0.3-2.3); at HEAD it was 22.7 s on WSL
  (39.0 - 16.4 s) and 20-23 s on ICELAKE.

## 2.5 StC-first CI bootstrap (the paper's ordering) (2026-10-28)

All builds and runs on the WSL VM (i7-12700H) through `ci-ckks-paper/tools/wsl-guard.sh`; nothing ran on ICELAKE.
Compare only with WSL numbers. The CPU ran about 27% faster in this session than in item 2.4 (CI CtS-first {5,3} warm
11.9 s here, 16.4 s in the 2.4 WSL baseline; same binary code path), so only the interleaved pairs below are
comparable with each other.

**What changed.**
1. `src/pke/lib/scheme/ckksrns/ckksrns-fhe.cpp`: `EvalBootstrapSetup(..., BTSlotsEncoding = true)` is now allowed for
   `REAL_CI` (the item 0.1 throw is removed) and selects the StC-first CI bootstrap. It is evaluated by the CI branch of
   `EvalBootstrap` (flag `ciStcFirst`): the input is dropped to the StC input level, cd (lbDec + 2) towers (the same
   level and the same FLEXIBLEAUTO scale fix-up as std's `EvalBootstrapStCFirst`), CI StC (scaleDec x U, the CtS-first
   StC levels and stores) runs on it, then correction-factor adjust, ModRaise, x pre/N, CI CtS (scaleEnc), EvalMod
   (one real ciphertext), x scalar, x 2^correction. There is no StC after EvalMod; the output has noise scale degree 2
   (FLEXIBLEAUTO), as std StC-first. The scalars are those of CtS-first (the q0 I overflow meets only scaleEnc).
2. `CIBsgsLevelDigits(..., stcFirst)`: StC level s of the StC-first chain has cd (lbDec + 2 - s) (+1 FLEXIBLEAUTOEXT)
   towers; keygen (`EvalBootstrapKeyGen`, from the precom's `BTSlotsEncoding`), the setup encodes
   (`CIBootstrapPrecompute`) and the evaluator use it, so the stores and Galois sets match by construction (checked:
   every runtime tower count equals the model, the Galois check held, 0 local encodes, in every run below).
3. `EvalBootstrapStCFirst` on `REAL_CI` forwards to `EvalBootstrap` when the precom was set up with
   `BTSlotsEncoding = true` and throws otherwise (a CtS-first precom has the wrong StC towers and keys);
   `EvalBootstrap` no longer dispatches CI to `EvalBootstrapStCFirst`. Header comments updated.
4. Default correction factor for CI StC-first: std's StC-first fit without CI's "-1" (CI and std have the same
   precision at an equal correction factor in StC-first, results 2). The measured best at 59/60 is higher (below).
5. Driver `ci-fft-boot`: `stcfirst` 1 encrypts the input with lbDec + 2 towers (level depth - lbDec - 1), the StC
   input level (before, std StC-first could not run from the driver: "Not enough levels"); the output line prints
   the input level / towers and the output level / towers / noise scale degree; RESULT has `stcfirst`.
6. `tools/ci-split-search.cpp`: optional last argument `stcFirst` (StC level s at lbDec + 2 - s towers).

**Commands** (`B` = `build-wsl/bin/benchmark/ci-fft-boot`, `T` = `build-wsl-bt/...`, 1 thread, encap, FLEXIBLEAUTO 59/60):

    wsl-guard.sh p25_build 12 'cmake --build build-wsl --target ci-fft-boot -j 8 && cmake --build build-wsl-bt --target ci-fft-boot -j 8
        && g++ -O2 -std=c++17 -Isrc/core/include ci-ckks-paper/tools/ci-split-search.cpp src/core/lib/math/ci-realfft.cpp -o ~/ci-ckks-wsl/tools/ci-split-search'  # rc 0
    wsl-guard.sh p25_split 3 'ci-split-search 16 5 {2,3,4} 6 2 10 7 3 7 1; ci-split-search 16 5 3 4 2 10 7 3 7 0'   # rc 0
    wsl-guard.sh p25_smoke 9 'CI_BOOT_TIMING=1 $B ci {12 1 1, 12 2 2, 12 3 3, 12 4 4, 12 5 3, 13 4 4, 14 5 3, 15 5 3, 15 4 4} 59 60 0 2 fa 4 encap {0,1};
        $B ci 12 3 3 ... {fa 0 uniform, fm 0 encap} {0,1}; $B std 14 5 3 ... fa 5 encap {0,1}; $B ci 12 3 3 ... fa 4 encap 2'   # rc 0
    wsl-guard.sh p25_corr15 8 '$B {ci,std} 15 5 3 59 60 0 2 fa corr encap 1, corr 6..12 (+ CtS-first refs ci corr 4, std corr 5)'  # rc 0 (*)
    wsl-guard.sh p25_corr15b 8 '... corr 13..17'                                                                        # rc 0
    wsl-guard.sh p25_build2 12 '<both build dirs, ci-fft-boot, -j 8>'     # rc 0, after the default-corr change (item 4 above)
    wsl-guard.sh p25_ab 15 'CI_BOOT_TIMING=1: $B ci 16 5 3 59 60 1 3 fa 4 encap 0; $B ci ... fa 12 encap 1; $T std ... fa 5 encap 0;
        $T std ... fa 13 encap 1; $B ci ... fa 13 encap 1; $T std ... fa 12 encap 1'                                 # rc 0
    wsl-guard.sh p25_ab2 15 '$B ci ... 12 encap 1; $B ci ... 4 encap 0; (again); $T std ... 13 encap 1; $T std ... 5 encap 0'  # rc 0
    wsl-guard.sh p25_extra 7 '$B ci 12 1 1 59 60 0 2 fa 12 encap 1; $B ci 12 3 3 59 60 0 2 fa 0 encap 1; ci-split-search 16 5 3 1 {2,3,5} 10 7 3 7 {0,1}'

(*) `p25_corr15` spanned a laptop sleep (55 min wall, 9.4 min CPU, uptime advanced 10 min); its precision numbers
are valid, its times are not used. `p25_ab` / `p25_ab2`: wall time equals the uptime advance (494 / 510 s), no sleep.
(`p25_build_head`, a first build, compiled a partial edit of this item; it is not used.)

**Results 1: correctness at 2^12..2^15** (`p25_smoke`, insecure, reps 2). StC-first runs at every budget, including
the dense {1,1}, with the uniform secret and with FIXEDMANUAL; std StC-first runs from the driver. The CtS-first path
is unchanged (RMS / min equal to `p24_smoke` within run-to-run noise: 2^13 {4,4} 19.71 / 18.03, 2^15 {5,3}
21.64 / 19.45, {4,4} 21.64 / 19.58). Keys and Galois sets are the same for both orders at every budget here (all StC
levels have one key-switching digit in both chains). `stcfirst` 2 (EvalBootstrapStCFirst on a CtS-first setup)
throws as intended. At the CtS-first correction factor (corr 4 CI, 5 std) StC-first gives only 6.69 bits RMS (CI, every
N) and 8.68 (std): the correction factor has to be retuned (results 2).

| 2^12, insecure | CtS-first RMS / min | StC-first RMS / min | note |
|---|---|---|---|
| CI {3,3} uniform, default corr | 20.11 / 18.25 | 22.61 / 19.69 | |
| CI {3,3} FIXEDMANUAL, default corr | 19.46 / 17.52 | 22.29 / 20.45 | |
| CI {3,3} encap (CtS-first corr 4, StC-first default 13) | 18.80 / 17.18 | 24.68 / 23.26 | `p25_extra` |
| CI {1,1} dense encap (corr 4 / 12) | 18.80 / 17.18 | 22.68 / 21.23 | `p25_extra` |

**Results 2: correction factor for StC-first** (2^15 {5,3}, insecure, reps 2). In StC-first the sine argument is the
message itself (coefficient = slot value after StC), about sqrt(N) larger than the CtS-first coefficients, so the
message must be shrunk by 2^correction much more. Up to corr 12 the sine's cubic error dominates (+2 bits per step,
the same for CI and std, independent of N); above it the EvalMod/key-switching noise, amplified by 2^correction, takes
over (-1 bit per step). CtS-first references: CI corr 4 21.65 / 19.70, std corr 5 22.51 / 20.50.

| corr | 6 | 7 | 8 | 9 | 10 | 11 | 12 | 13 | 14 | 15 | 16 | 17 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| CI RMS | 10.68 | 12.68 | 14.68 | 16.68 | 18.68 | 20.68 | **22.48** | 22.46 | 21.50 | 20.49 | 19.48 | 18.50 |
| CI min | 9.28 | 11.28 | 13.28 | 15.28 | 17.28 | 19.20 | **20.65** | 20.38 | 19.51 | 18.25 | 17.37 | 16.39 |
| std RMS | 10.69 | 12.69 | 14.69 | 16.69 | 18.69 | 20.68 | 22.58 | **22.91** | 21.97 | 20.98 | 19.99 | 18.98 |
| std min | 9.28 | 11.28 | 13.28 | 15.28 | 17.28 | 19.23 | 20.67 | **20.90** | 19.91 | 18.91 | 17.91 | 16.87 |

The OpenFHE StC-first default (std fit) gives 11 at 2^16 and 13 at 2^12 for both schemes (CI default changed from
10 to 11 at 2^16 by item 4 above); at 59/60 the best is 12 (CI) / 13 (std) at 2^16 (results 3). The driver passes it.

**Results 3: 2^16 A/B** (128-bit, {5,3}, reps 3, two interleaved passes; warm medians; stage times are medians of the 3
warm bootstraps, CI from `CI_BOOT_TIMING`, std from `build-wsl-bt`; std "CtS" includes the conjugate add).

| run (job, order) | warm s | CtS | EvalMod | StC | RMS / min bits | keys | peak RSS GB | in towers -> out towers (nsd) |
|---|---|---|---|---|---|---|---|---|
| CI CtS-first corr 4 (ab 1) | 11.92 | 5.21 | 3.91 | 2.56 | 21.55 / 18.25 | 102 | 13.54 | 2 -> 3 (1) |
| CI StC-first corr 12 (ab 2) | 12.35 | 5.78 | 3.95 | 2.33 | 21.92 / 19.73 | 102 | 13.39 | 5 -> 7 (2) |
| CI StC-first corr 13 (ab 5) | 13.75 | 6.32 | 4.66 | 2.98 | 21.21 / 19.19 | 102 | 13.39 | 5 -> 7 (2) |
| CI StC-first corr 12 (ab2 1) | 11.67 | 5.37 | 3.98 | 2.32 | 21.91 / 19.71 | 102 | 13.39 | 5 -> 7 (2) |
| CI CtS-first corr 4 (ab2 2) | 12.05 | 5.15 | 4.09 | 2.58 | 21.56 / 18.48 | 102 | 13.54 | 2 -> 3 (1) |
| CI StC-first corr 12 (ab2 3) | 11.47 | 5.33 | 3.89 | 2.28 | 21.92 / 19.50 | 102 | 13.39 | 5 -> 7 (2) |
| CI CtS-first corr 4 (ab2 4) | 11.75 | 5.09 | 3.90 | 2.50 | 21.56 / 18.55 | 102 | 13.54 | 2 -> 3 (1) |
| std CtS-first corr 5 (ab 3) | 12.36 | 3.89 | 6.22 | 1.93 | 22.75 / 19.79 | 61 | 7.66 | 2 -> 4 (2) |
| std StC-first corr 13 (ab 4) | 9.01 | 3.44 | 3.40 | 1.92 | 22.92 / 20.83 | 61 | 7.58 | 5 -> 7 (2) |
| std StC-first corr 12 (ab 6) | 8.35 | 3.51 | 3.00 | 1.56 | 22.57 / 20.74 | 61 | 7.58 | 5 -> 7 (2) |
| std StC-first corr 13 (ab2 5) | 8.80 | 3.72 | 3.22 | 1.58 | 22.91 / 20.83 | 61 | 7.58 | 5 -> 7 (2) |
| std CtS-first corr 5 (ab2 6) | 12.06 | 3.75 | 6.31 | 1.75 | 22.75 / 18.99 | 61 | 7.66 | 2 -> 4 (2) |

Summary (medians of the runs above; CI StC-first at its best corr 12):

| | CI CtS-first | CI StC-first | std CtS-first | std StC-first (corr 13) |
|---|---|---|---|---|
| warm s | 11.92 | **11.67** (-2.1%) | 12.21 | **8.90** (-27%) |
| StC stage s | 2.56 | **2.32** (-9.4%) | 1.75-1.93 | 1.58-1.92 |
| RMS / min bits | 21.56 / 18.48 | **21.92 / 19.71** | 22.75 / 18.99-19.79 | 22.91 / 20.83 |
| CI / 2 x std (same order) | 2 x 12.21 / 11.92 = 2.05x | 2 x 8.90 / 11.67 = **1.53x** | | |

**Conclusions.**
- The CI StC-first bootstrap works at every budget and both secrets; keygen, setup stores and the evaluator agree on
  the new StC tower counts. Same chain (21 Q towers, log QP 1660), same keys (102), peak RSS -0.15 GB.
- Time: StC-first saves only its StC cost difference, 0.24 s at 2^16 {5,3} (StC 2.56 -> 2.32 s, -9.4%; CtS and
  EvalMod do the same work in both orders), so the warm bootstrap is 2.1% faster (11.92 -> 11.67 s). The reason is
  the chain shape: with 2 levels after the bootstrap, CtS-first StC already runs near the bottom (6 / 5 / 4 Q towers)
  and StC-first moves it down by only one tower (5 / 4 / 3). The split model gives the same -8.5% for StC and shows
  the gain grows with the levels left after the bootstrap: StC 4.82 -> 4.41 (after 2), 5.22 -> 4.41 (after 3, the
  paper's setting, -16%), 6.83 -> 4.41 model-s (after 5, -35%; CtS-first StC there needs 2 digits). The StC split
  [7,5,4] stays model-best in the StC-first chain (lbDec 3), so `CIDefaultLayerSplit` is unchanged.
- Output level: StC-first returns lbDec = 3 towers more (7 with a pending rescale, i.e. 6, vs 3) but needs lbDec + 2 = 5
  towers at its input instead of 2, so the levels usable between two bootstraps are the same (1 here) at the same
  chain. StC-first therefore does not shorten the chain; it only makes StC cheaper and, since StC consumes the
  application's levels, the saving grows with them.
- Precision: StC-first is more precise once its correction factor is retuned (12 for CI, 13 for std at 59/60, vs 4 / 5
  for CtS-first): CI RMS 21.56 -> 21.92 bits, min 18.48 -> 19.71 bits at 2^16 (+1.2 bits max error; the paper's
  20.55 bits is 0.8 bits away now). The gain is larger at small N (2^12 {3,3}: +5.9 bits RMS).
- Std's real-data bootstrap has the same option, and it matters more there: OpenFHE's std StC-first for `REAL` data
  evaluates EvalMod on one ciphertext (CtS-first full packing evaluates it twice, real and imaginary parts), so std
  StC-first is 27% faster than std CtS-first (8.90 vs 12.21 s; EvalMod 3.2 vs 6.3 s) at better precision. Against
  that baseline CI/2xstd drops from 2.05x to **1.53x** (std StC-first corr 12: 8.35 s, 1.43x). A fair CI vs std
  comparison for real data should use std StC-first. Suggested for 2.R: report both orders; the 2.R target "StC-first
  CI StC below std's CtS-first StC" is not met (2.32 vs 1.75-1.93 s; CI has 1.88x the diagonals, item 2.1).
- Suggested (not added to the plan): with StC-first the best CI budget may move (lbDec costs only bottom towers);
  {5,4} needs dnum 4 at 128-bit (item 1.3).

## 2.R Phase 2 review (2026-10-28) -- NOT DONE: the StC-first criterion is not met (attempt 1)

All runs on the WSL VM (i7-12700H) through `ci-ckks-paper/tools/wsl-guard.sh`; nothing ran on ICELAKE. No code changed
since item 2.5 (HEAD 61a83a1a; `build-wsl` / `build-wsl-bt` were built from this source, no file under `src/` or
`benchmark/` is newer than the libraries), so nothing was rebuilt. Compare only the pairs inside one job.
No job spanned a laptop sleep: in every job the wall time of each run equals its `/proc/uptime` advance and
setup + first + 3 reps.

**Commands** (`B` = `build-wsl/bin/benchmark/ci-fft-boot`, `T` = `build-wsl-bt/bin/benchmark/ci-fft-boot`; every run
`CI_BOOT_TIMING=1 OMP_NUM_THREADS=1`, so CI and std both print `[LT]` lines; FLEXIBLEAUTO 59/60, encap, reps 3):

    wsl-guard.sh p2R_base 15 '$B ci 16 5 3 59 60 1 3 fa 4 encap; $T std 16 5 3 59 60 1 3 fa 5 encap;
        $B ci 16 5 3 59 60 1 3 fa 12 encap 1; $T std 16 5 3 59 60 1 3 fa 13 encap 1;
        $B ci 16 4 4 59 60 1 3 fa 4 encap; $T std 16 4 4 59 60 1 3 fa 5 encap'            # rc 0, load 0.2-1.1
    wsl-guard.sh p2R_after3 15 '... {std CtS-first, CI StC-first, CI CtS-first, std StC-first} 16 5 3 59 60 1 3 fa corr encap o 4 3'
        # killed:oom-kill in the 2nd run (CI, dnum 4: 102 keys x 112 MB = 11.4 GB of keys); std CtS-first finished
    wsl-guard.sh p2R_after3b 16 '$T std 16 5 3 59 60 0 3 fa 5 encap 0 3 3; $B ci ... fa 12 encap 1 3 3;
        $B ci ... fa 4 encap 0 3 3; $T std ... fa 13 encap 1 3 3'                            # rc 0
    wsl-guard.sh p2R_after5 17 '$T std 16 5 3 59 60 0 3 fa 5 encap 0 3 5; $B ci ... fa 12 encap 1 3 5;
        $B ci ... fa 4 encap 0 3 5'                                                           # rc 0, CI peak RSS 15.77 GB
    wsl-guard.sh p2R_smoke 7 '$B ci {12 1 1, 12 3 3, 13 4 4, 14 5 3} 59 60 0 1 fa {4 encap 0, 12 (13 at {3,3}) encap 1};
        $B ci 12 3 3 59 60 0 1 fa 0 uniform {0,1}'                                           # rc 0

After the OOM kill the 3-levels-after runs use dnum 3 with the security check off (`secure` 0; log QP 1779 at 3 levels
after, 1897 at 5, over the 1747-bit 128-bit bound; dnum 4 is valid at 3 levels after but CI needs more than 15 GB).
Both schemes run on the same chain in each pair, so the stage comparison is fair; the times are not 128-bit times.

**Results 1: baseline at HEAD** (`p2R_base`, 2^16, 128-bit, 2 levels after; warm medians; stage times are medians of
the 3 warm bootstraps; std stages from `BOOTSTRAPTIMING`, std "CtS" includes the conjugate add).

| run | warm s | CtS | EvalMod | StC | RMS / min bits | keys | peak RSS GB |
|---|---|---|---|---|---|---|---|
| CI {5,3} CtS-first corr 4 | **11.99** | 5.16 | 4.02 | 2.55 | 21.57 / 18.05 | 102 | 13.54 |
| std {5,3} CtS-first corr 5 | **11.63** | 3.59 | 6.17 | 1.69 | 22.75 / 19.24 | 61 | 7.66 |
| CI {5,3} StC-first corr 12 | **11.62** | 5.35 | 3.95 | 2.32 | 21.91 / 19.85 | 102 | 13.39 |
| std {5,3} StC-first corr 13 | **8.43** | 3.59 | 3.06 | 1.53 | 22.90 / 20.88 | 61 | 7.58 |
| CI {4,4} CtS-first corr 4 | 13.16 | 5.85 | 4.37 | 2.15 | 21.57 / 18.55 | 92 | 12.56 |
| std {4,4} CtS-first corr 5 | 12.79 | 4.50 | 6.80 | 1.27 | 22.74 / 19.46 | 76 | 9.08 |

| pair | CI / 2 x std | CtS ratio | EvalMod ratio | StC ratio |
|---|---|---|---|---|
| {5,3} CtS-first | 2 x 11.63 / 11.99 = **1.94x** | 1.44x | 0.65x | 1.51x |
| {5,3} StC-first | 2 x 8.43 / 11.62 = **1.45x** | 1.49x | 1.29x | 1.52x |
| {4,4} CtS-first | 2 x 12.79 / 13.16 = 1.94x | 1.30x | 0.64x | 1.69x |
| CI StC-first vs std CtS-first | 2 x 11.63 / 11.62 = 2.00x | | | 2.32 / 1.69 = 1.37x |

Both CI orderings build, run and give the expected precision (user note of 2026-10-28): CtS-first 21.57 / 18.05 bits,
StC-first 21.91 / 19.85 bits (item 2.5: 21.56 / 18.48 and 21.92 / 19.71); `p2R_smoke` (2^12..2^14, insecure,
reps 1) runs both orders at {1,1} (dense), {3,3}, {4,4}, {5,3} and with the uniform secret: CtS-first / StC-first RMS
18.80 / 22.68 ({1,1}), 18.80 / 24.68 ({3,3}), 19.71 / 22.67 (2^13 {4,4}), 20.71 / 22.48 (2^14 {5,3}), uniform {3,3}
20.13 / 23.32 bits; the Galois check held (sparse budgets) and no level was encoded at run time in any bootstrap.

**Results 2: criterion 1, CI CtS and StC vs std at the same N, accounted for by the diagonal count** (`[LT]` lines,
`p2R_base`; diagonals = plaintext mults; LT time = sum of the per-level warm medians).

| stage, budget | CI diags | std diags | diag ratio | CI / std LT s | LT ratio | stage ratio |
|---|---|---|---|---|---|---|
| CtS {5,3} | 137 (16, 30, 30, 30, 31) | 75 (15 x 5) | 1.83x | 4.93 / 3.19 | 1.54x | **1.44x** |
| StC {5,3} | 317 (63, 126, 128) | 189 (63 x 3) | 1.68x | 2.52 / 1.66 | 1.52x | **1.51x** |
| CtS {4,4} | 187 (32, 30, 62, 63) | 108 (31, 31, 31, 15) | 1.73x | 5.71 / 3.94 | 1.45x | **1.30x** |
| StC {4,4} | 187 (31, 30, 62, 64) | 108 (31, 31, 31, 15) | 1.73x | 2.11 / 1.23 | 1.71x | **1.69x** |

CtS is below 1.5x at both budgets. StC is 1.51x ({5,3}) and 1.69x ({4,4}), above 1.5x but below the diagonal ratio
(1.68x / 1.73x), so the excess is the diagonal count. Levels of the same shape cost the same in both schemes:
StC level 0 at {5,3} (63 diagonals, 6 + 7 towers, 15 baby + 3 giant) CI 0.622 s vs std 0.594 s (1.05x); CtS level 1
at {4,4} (30 vs 31 diagonals, 19 + 7 towers, 15 + 1) CI 1.105 vs std 1.102 s (1.00x); {4,4} StC level 0 (31
diagonals, 7 + 7) CI 0.39-0.57 s (2 of 4 reps 0.39 s, thermal) vs std 0.39 s. The CI per-op cost is at std's; the
remaining stage ratio is the real factorization's extra diagonals (item 2.1). **Criterion 1 is met.**

**Results 3: criterion 2, CI StC-first StC vs std CtS-first StC** (2^16 {5,3}; StC stage medians, LT sums in brackets).

| levels after | chain (Q + P towers, log QP) | CI StC-first StC | std CtS-first StC | ratio | CI CtS-first StC | StC-first gain |
|---|---|---|---|---|---|---|
| 2 (`p2R_base`, 128-bit) | 21 + 7, 1660 | 2.32 (2.30) | 1.69 (1.66) | **1.37x** | 2.55 (2.52) | -9% |
| 3 (`p2R_after3b`, dnum 3, insecure) | 22 + 8, 1779 | 2.54 (2.52) | 2.02 (1.98) | **1.27x** | 3.62 (3.49) | -30% |
| 5 (`p2R_after5`, dnum 3, insecure) | 24 + 8, 1897 | 2.59 (2.56) | 2.51 (2.49) | **1.03x** | 4.43 (4.55) | -42% |
| 3, dnum 4, 128-bit (`p2R_after3`) | 22 + 6, 1659 | (OOM-killed) | 2.57 | | | |

Other stages of these runs (warm s): after 3: std CtS-first 12.71 (3.79 / 6.59 / 2.02), CI StC-first 13.98
(6.59 / 4.82 / 2.54), CI CtS-first 15.42 (5.85 / 5.24 / 3.62; noisy, EvalMod reps 4.4-6.3), std StC-first 9.17
(3.87 / 3.32 / 1.70); after 5: std CtS-first 15.52 (4.20 / 8.24 / 2.51), CI StC-first 15.23 (6.90 / 5.66 / 2.59),
CI CtS-first 18.77 (7.74 / 6.36 / 4.43). Precision is the same as at 2 levels after (CI 21.92 / 19.8 StC-first,
21.57 / 18.3 CtS-first; std CtS-first 22.75 / 19.9-20.3, StC-first 22.91 / 20.8).

CI StC-first StC runs at fixed towers (lbDec + 2 = 5 / 4 / 3 Q + P), whatever the levels after; std CtS-first StC runs
at after + lbDec + 1 = after + 4 down to after + 2 Q towers. So StC-first moves the CI StC down by (after - 1) towers per
level, but CI StC still has 317 diagonals against std's 189 (1.68x). Measured, the ratio falls from 1.37x (2 after) to
1.27x (3 after, the paper's setting) and 1.03x (5 after); by extrapolation (std StC +0.25 s per level, CI StC-first
+0 s at constant P) CI StC-first StC drops below std CtS-first StC only from about 6 levels after the bootstrap.
**Criterion 2 ("StC-first CI StC is below std's CtS-first StC") is not met at 2, 3 or 5 levels after.** At the
plan's settings it can only be reached by fewer CI StC diagonals (a different factorization, not a phase 2 lever) or
by comparing at 6 or more levels after the bootstrap.

**Conclusions.**
- Phase 2 results on WSL at HEAD (2^16 {5,3}, 128-bit): CI 11.99 s vs std 11.63 s CtS-first (1.94x), CI 11.62 s vs
  std 8.43 s StC-first (1.45x, std's real-data StC-first evaluates EvalMod once). Stage ratios CtS 1.44x, StC 1.51x
  (diagonal ratio 1.83x / 1.68x), EvalMod 0.65x. Item 2.4 WSL baseline (CI 16.37 s; this session took 27% less time, as in
  item 2.5): 1.99x; CtS 1.36x, StC 1.56x.
- Criterion 1 is met (CtS <= 1.5x; StC excess = diagonal count; same-shape levels cost 1.00-1.05x std).
- Criterion 2 is not met; the item is not ticked. Suggested plan revision: state criterion 2 as "accounted for by
  the diagonal count" like criterion 1 (CI StC-first StC per diagonal 2.32 s / 317 = 7.3 ms vs std CtS-first
  1.69 s / 189 = 8.9 ms), or as "StC-first CI StC below CI CtS-first StC, with the gain growing with the levels after"
  (measured: -9% / -30% / -42% at 2 / 3 / 5 levels after), or move the comparison to >= 6 levels after.
- Memory: CI at dnum 4 does not fit a 15 GB job (keys 112 MB each); 3 levels after at 128-bit with 59-bit primes needs
  dnum 4 (item 1.2), so 128-bit runs with 3 levels after need a job cap of about 17-18 GB for CI.

**Plan adapter (2026-10-28, after attempt 1).** Criterion 2 of 2.R is revised in `PLAN_PHASE2.md`, not the code. As
written it compared 317 CI StC diagonals with std's 189 at the plan's chain (2 levels after), where std's CtS-first
StC already runs at 6..4 Q towers, so it measured the real factorization's diagonal count (item 2.1: inherent to the
real FFT) rather than what the ordering changes. The ordering's effect is the tower count of CI StC, and that is
what the revised criterion checks: StC-first CI StC below CtS-first CI StC at 2, 3 and 5 levels after with a growing
gain (measured -9% / -30% / -42%), and per-diagonal cost at or below std's CtS-first StC (2.32 s / 317 = 7.3 ms vs
1.69 s / 189 = 8.9 ms at 2 after; 8.0 vs 10.7 ms at 3; 8.2 vs 13.3 ms at 5). Left open, outside phase 2: the
original comparison at >= 6 levels after (17-18 GB CI job at 2^16, or a different, smaller-diagonal factorization).
Attempt 2 reuses the runs above; no new job is needed.

## 2.R Phase 2 review -- DONE (attempt 2, 2026-10-28)

Attempt 2 is a paperwork pass against the revised criteria in `PLAN_PHASE2.md` (commit 939e4cef). No code changed since
item 2.5 (`git diff --stat 61a83a1a HEAD` lists only `PLAN_PHASE2.md` and `PHASE2_LOG.md`), so the attempt-1 runs
`p2R_base`, `p2R_after3b`, `p2R_after5` and `p2R_smoke` (all rc 0, on WSL through `wsl-guard.sh`, no sleep inside a
job) are reused. No build and no job ran in this attempt; nothing ran on ICELAKE. The numbers below were re-derived
from the logs in `~/ci-ckks-wsl/logs/` (stage time = median of the 3 warm bootstraps; plaintext mults = sum of
`ptMult` over the StC `[LT]` levels of one bootstrap; per diagonal = stage median / plaintext mults).

**Criterion 1: CI CtS <= 1.5x std CtS, CI StC <= 1.5x std StC, or the excess is the diagonal count** (2^16, 128-bit,
2 levels after, `p2R_base`). Met.

| stage, budget | CI / std stage s | stage ratio | diagonal ratio | same-shape level CI / std |
|---|---|---|---|---|
| CtS {5,3} | 5.16 / 3.59 | **1.44x** <= 1.5x | 137 / 75 = 1.83x | |
| CtS {4,4} | 5.85 / 4.50 | **1.30x** <= 1.5x | 187 / 108 = 1.73x | level 1: 1.105 / 1.102 s = 1.00x |
| StC {5,3} | 2.55 / 1.69 | **1.51x** < 1.68x | 317 / 189 = 1.68x | level 0: 0.622 / 0.594 s = 1.05x |
| StC {4,4} | 2.15 / 1.27 | **1.69x** < 1.73x | 187 / 108 = 1.73x | |

**Criterion 2: StC-first pays for CI StC** (2^16 {5,3}; StC stage medians in s; per-diagonal in ms). Met: StC-first CI
StC is below CtS-first CI StC at every chain, the gain grows with the levels after, and per diagonal StC-first CI StC
costs less than std's CtS-first StC at every chain.

| levels after (run, chain) | CI StC-first StC | CI CtS-first StC | StC-first gain | CI StC-first per diag (/317) | std CtS-first StC | std per diag (/189) |
|---|---|---|---|---|---|---|
| 2 (`p2R_base`, 21 + 7, 128-bit) | 2.32 | 2.55 | **-9%** | **7.30** | 1.69 | 8.94 |
| 3 (`p2R_after3b`, 22 + 8, dnum 3, insecure) | 2.54 | 3.62 | **-30%** | **8.02** | 2.02 | 10.66 |
| 5 (`p2R_after5`, 24 + 8, dnum 3, insecure) | 2.59 | 4.43 | **-42%** | **8.16** | 2.51 | 13.29 |

The 3- and 5-levels-after rows are same-chain stage comparisons at dnum 3 with the security check off (log QP 1779 /
1897 > 1747); they are not 128-bit times. The `[LT]` sum for CI CtS-first StC at 5 after is 4.38 s (the attempt-1
table gave 4.55); the stage median 4.43 s is the same in both readings and the conclusion does not change.

**Criterion 3: both CI orderings build, run and give the expected precision.** Met.

| run | CtS-first RMS / min bits | StC-first RMS / min bits |
|---|---|---|
| 2^16 {5,3}, 128-bit (`p2R_base`; item 2.5: 21.56 / 18.48, 21.92 / 19.71) | 21.57 / 18.05 | 21.91 / 19.85 |
| 2^16 {5,3}, 3 after (`p2R_after3b`) | 21.57 / 18.34 | 21.92 / 19.81 |
| 2^16 {5,3}, 5 after (`p2R_after5`) | 21.56 / 18.32 | 21.92 / 19.85 |
| 2^12 {1,1} dense (`p2R_smoke`) | 18.80 / 17.18 | 22.68 / 21.24 |
| 2^12 {3,3} | 18.80 / 17.18 | 24.68 / 23.27 |
| 2^13 {4,4} | 19.71 / 18.03 | 22.67 / 21.17 |
| 2^14 {5,3} | 20.71 / 18.89 | 22.48 / 20.53 |
| 2^12 {3,3} uniform secret | 20.13 / 18.21 | 23.32 / 18.89 |

The Galois check held at every bootstrap of the four jobs (44 checks, no mismatch), and no level was encoded at run
time (`local diagonal encodes: 0 levels` in every bootstrap).

**Phase 2 result (WSL, HEAD, 2^16 {5,3}, 128-bit, 2 levels after):** CI 11.99 s vs std 11.63 s CtS-first
(2 x std / CI = 1.94x); CI 11.62 s vs std 8.43 s StC-first (1.45x). Stage ratios CtS 1.44x, StC 1.51x, EvalMod 0.65x.

**Open, carried out of phase 2:**
- The original criterion 2 (StC-first CI StC below std's CtS-first StC): measured 1.37x / 1.27x / 1.03x at 2 / 3 / 5
  levels after; the crossover is at about 6 levels after, which at 2^16 needs a 17-18 GB CI job, or a factorization
  with fewer CI StC diagonals (317 against std's 189).
- 3 levels after (the paper's setting) at 128-bit with 59-bit primes needs dnum 4; CI then needs a job cap of about
  17-18 GB (dnum 4 was OOM-killed at 15 GB in `p2R_after3`).

## 3.1 CI ephemeral sparse key of weight 16 -- DONE: weight 16 is below 128 bits, weight 32 kept (2026-10-28)

**Host:** ICELAKE for every job of this item (host file `ICELAKE`, read before each job; load average 1.0-1.1, no
other heavy user). No build, benchmark or test ran; no library code changed. Nothing ran on WSL.

**Question.** A weight-h CI ephemeral key (h nonzero ternary CI-basis coordinates) acts like a weight-2h power-basis
key, so CI uses the K = 28 sine table (degree 48) with h = 32, where std uses K = 16 (degree 36). Item 0.5 measured
what K = 16 would save: 1.0 s of CI EvalMod (-13%), about 4% of the CI bootstrap. K = 16 is sound for CI only with a
weight-16 CI key (power-basis L1 ~32, the overflow distribution std's K = 16 table was made for). The item asks
whether that key is 128-bit secure.

**Attack instance.** The sparse-secret switching key (`KeySwitchGenSparse`) is an RLWE sample under the ephemeral
secret s' modulo q0 * P'. With the plan's chain (64-bit build, no composite scaling) q0 is 60 bits and P' is two
33-bit primes (`ckksrns-cryptoparameters.cpp`, `auxBitsPlain` = 66), so log q = 126. For CI the ring has rank
N = 65536 and the attacker works in the CI basis: LWE with n = 65536, ternary secret of Hamming weight h,
Gaussian error sigma = 3.19. (The paper, ePrint 2026/2618 Section 6, also uses an ephemeral key of Hamming
weight 32 on the CI ring, with hwt(s) = ||s||_1 in its rank-N representation.)

**Estimator.** The malb/lattice-estimator needs SageMath, which is not on ICELAKE (no `sage`, no conda). Installing
it (micromamba + conda-forge `sage` + `git clone` of the estimator into `~/ci-ckks-fft/estimator`) was refused by the
harness permission check (download and execution of external code), so it did not run. In its place,
`ci-ckks-paper/tools/ci-sparse-security.py` (new, pure Python) evaluates a subset of the estimator's attacks with
its formulas: primal uSVP (2016 estimate) with Bai-Galbraith scaling of the secret and "drop and solve" (guess
zeta coordinates to be zero; success probability C(n - zeta, h) / C(n, h)), and the meet-in-the-middle attack on the
secret alone (Odlyzko split into two halves of n/2 coordinates with h/2 nonzeros each; rounding hash, as q / sigma
~ 2^123 lets 2 samples remove all false matches). The minimum over a subset of attacks is an upper bound on what
the full estimator reports, so a value below 128 bits here is below 128 bits for the full estimator as well.
BKZ cost: core-SVP (0.292 b) and BDGL16 with 8d tours (0.292 b + 16.4 + log2(8 d), lattice-estimator
`RC.BDGL16`). The BDGL16 model reproduces the HE-standard 128-bit bounds for dense ternary secrets
(127.9 / 128.3 / 130.4 bits at (4096, 109) / (8192, 218) / (65536, 1747)), so it is the calibrated column.

**Commands (ICELAKE, `~/ci-ckks-fft`).**

    ci-ckks-paper/tools/sync.sh   # on WSL; SYNCED_FROM 8980bf05 1 (the new script, uncommitted)
    ./guard.sh p31_sec "python3 openfhe-development/ci-ckks-paper/tools/ci-sparse-security.py"
    # runs 1 and 2: rc 1 (two script bugs in the block-size search bounds, fixed on WSL and re-synced);
    # run 3: rc 0, 12:39, about 20 s

**Results** (`p31_sec.log`, run 3; n = 65536, log q = 126, sigma = 3.19; bits of security = log2 of the attack cost).

| CI weight h (power-basis L1) | primal + drop, core-SVP (n', b, guess bits) | primal + drop, BDGL16 | MITM time (log2 list, split bits) | log2 #secrets | sine table it allows |
|---|---|---|---|---|---|
| **16** (~32) | 98.7 (1536, 41, 86.8) | 129.8 | **116.0** (112.7, 2.35) | 227.7 | K = 16 (std's) |
| 24 (~48) | 141.5 (2048, 73, 120.2) | 172.9 | 166.8 (163.2, 2.63) | 329.0 | none (would need K ~ 20) |
| **32** (~64), current | 181.7 (2048, 73, 160.3) | 213.0 | 215.6 (211.7, 2.84) | 426.3 | K = 28 |
| 64 (~128) | 330.8 (3072, 162, 283.5) | 362.7 | 398.6 (394.3, 3.33) | 792.0 | -- |

Std's weight-32 key in rank 65536 is the same LWE instance as the CI weight-32 row: 213 / 216 bits.

**Conclusions.**
- **Weight 16 is below 128 bits.** The meet-in-the-middle attack on the secret alone costs 2^116.0 list entries
  (two lists of 2^112.7 entries, 2^2.35 repetitions for the 8/8 split). This is a time count, as in the HE
  standard; it needs 2^112.7 memory, but a 128-bit claim counts time. The primal drop-and-solve attack is at
  129.8 bits (BDGL16) with only 87 bits of guessing and a BKZ-41 reduction in dimension 1536, so the hybrid
  attacks of the full estimator (guessing combined with MITM or lattice reduction) can only go lower. Each MITM
  list entry costs a few 126-bit additions (about 2^7 bit operations), which still leaves it at about 2^123, below
  128 bits.
- **Weight 32 is kept** (CI and std alike: 213 bits primal, 216 bits MITM, both far above 128). CI keeps the K = 28
  table (degree 48). The cost of that is the item 0.5 measurement: about 1.0 s of CI EvalMod, 4% of the CI bootstrap
  at 2^16 {4,4} (ICELAKE). No library code changed, so all baseline numbers and commands stand.
- **Not done, possible later:** a weight-24 CI key (power-basis L1 ~48) is secure by this subset (141.5 core-SVP,
  166.8 MITM; the full estimator must confirm it) but no sine table exists for it. It would need a new
  Chebyshev table for K ~ 20 (between degree 36 and 48; at most about half of the 1.0 s) and a failure-probability
  check of the overflow bound. A different encapsulation modulus does not help: log q = 126 is already the
  smallest (q0 60 bits + P' 66 bits), and the 116-bit MITM does not depend on q.
- The official lattice-estimator still has not run. Its result can only be lower than the values above, so the
  decision (weight 16 rejected) does not depend on it. It would be needed to certify weight 24.

## 3.2 META-BTS (`numIterations = 2`) for CI and std -- DONE (2026-10-28)

**Hosts.** Two attempts. The first attempt ran its 2^16 timing job on ICELAKE (job `p32_final`, rc 0) and was cut off
by an account usage limit before it logged or committed. The user then forbade ICELAKE for this item ("no runs in
ICELAKE no matter what"), so this attempt ran everything on WSL (host file `WSL`, read before each job) and did not
connect to ICELAKE. The ICELAKE numbers below are from the first attempt's job as recorded by the orchestrator
(labelled "ICELAKE, item 3.2 earlier attempt"); they are compared only with each other, never with WSL numbers.

**Code (from the first attempt, reviewed and kept).**
- `ckksrns-fhe.cpp`, `EvalBootstrap` iteration path (`numIterations > 1`): the two `ModReduceInternalInPlace`
  calls after the inner bootstraps (initial and error bootstrap) now go through `rescaleOutput`, which rescales a
  `REAL_CI` result only if its noise degree is above 1. The native CI bootstrap already returns degree 1, so the
  old unconditional rescale dropped one tower too many: the error ciphertext ended at 1 tower and its `ModRaise`
  threw. Std ciphertexts are rescaled as before (std code path unchanged). Both CI orderings take this path
  (StC-first CI goes through the CI branch of `EvalBootstrap`).
- Driver `benchmark/src/ci-fft-boot.cpp`: new optional args 15 `iters` (1 or 2) and 16 `metaprec` (the META-BTS
  precision argument in bits; 0 = floor of the min precision of the first bootstrap, which then runs with 1
  iteration, as in OpenFHE's iterative-ckks-bootstrapping example). The depth gets `iters - 1` more levels. The
  RESULT line adds `iters`, `metaprec` and `passthrough` (1 if `EvalBootstrap` returned a clone of its input because
  the output would not have more towers; it was 0 in every run).
- At 128-bit, 2^16 {5,3}, 2 levels after, the extra level needs dnum 4: depth 21 with dnum 3 gives log QP 1779 >
  1747 (the item 1.3 limit); dnum 4 gives 1299 + 360 = 1659.

**Commands (WSL, repo root, all `ci-ckks-paper/tools/wsl-guard.sh`; `$B` = `build-wsl/bin/benchmark/ci-fft-boot`;
args after the budget: scaleMod firstMod secure reps scaling corr secret stcfirst dnum after iters metaprec).**

    wsl-guard.sh p32_build 12 'cmake --build build-wsl --target ci-fft-boot -j 8'                  # rc 0
    wsl-guard.sh p32_smoke 8 'for {12 2 2, 13 3 3, 14 5 3} x {ci,std} x {CtS-first corr 4/5, StC-first corr 12/13}
        x iters {1,2}: OMP_NUM_THREADS=4 $B $s $cfg 59 60 0 2 fa $corr encap $st 0 2 $it 0'      # rc 0, 24 runs
    wsl-guard.sh p32_metaprec 6 '$B {ci 12 StC-first, std 13 StC-first, std 5 CtS-first} 13 3 3 59 60 0 2 fa
        $corr encap $st 0 2 2 {8,12,16,20,24}'                                                     # rc 0
    wsl-guard.sh p32_fm 6 'same three, fm (FIXEDMANUAL), iters/metaprec {1/0, 2/8, 2/16}'          # rc 0
    wsl-guard.sh p32_wsl16 19 'two passes: OMP_NUM_THREADS=1 $B ci 16 5 3 59 60 1 3 fa 4 encap 0 0 2 1 0;
        OMP_NUM_THREADS=1 $B ci 16 5 3 59 60 1 3 fa 4 encap 0 4 2 2 19'                            # rc 0
    wsl-guard.sh p32_wsl16b 19 '(the same job again)'                                              # rc 0

ICELAKE (first attempt, `p32_final`, one guarded job, load 2-3, 2^16 {5,3}, 128-bit, 1 thread, reps 3, 59/60
FLEXIBLEAUTO, encap, 2 levels after; 2-iteration runs at dnum 4).

**Results 1: 2^16, 128-bit, ICELAKE (item 3.2 earlier attempt; same-host comparison).**

| Ordering | Scheme | 1 iter: time / RMS / min bits | 2 iters (metaprec): time / RMS / min bits | time ratio |
|---|---|---|---|---|
| CtS-first | CI (corr 4) | 22.14 s / 21.54 / 18.24 | 48.20 s / 40.17 / 36.95 (19) | 2.18x |
| CtS-first | std (corr 5) | 21.88 s / 22.75 / 20.43 | 47.91 s / 40.97 / 38.01 (19) | 2.19x |
| StC-first | CI (corr 12) | 21.69 s / 21.92 / 19.84 | 46.14 s / 40.42 / 37.34 (20) | 2.13x |
| StC-first | std (corr 13) | 15.63 s / 22.91 / 20.83 | 33.37 s / 31.08 / 28.95 (20) | 2.13x |

**Results 2: 2^16, 128-bit, WSL (this attempt; CI CtS-first, 1 vs 2 iterations interleaved in one job).**

| Job / pass | 1 iter (dnum 3): warm / RMS / min | 2 iters (dnum 4, metaprec 19): warm / RMS / min | ratio | load avg |
|---|---|---|---|---|
| p32_wsl16 pass 1 | 12.63 s / 21.56 / 18.65 | 32.29 s / 40.18 / 37.18 | 2.56x | 1.9-2.9 |
| p32_wsl16 pass 2 | 43.18 s / 21.56 / 18.58 (discarded) | 27.10 s / 40.17 / 37.04 (discarded) | -- | up to 8.5 |
| p32_wsl16b pass 1 | 15.39 s / 21.56 / 18.51 | 49.32 s / 40.17 / 37.33 | 3.20x | 4.4-5.2 |
| p32_wsl16b pass 2 | 16.19 s / 21.57 / 18.11 | 49.17 s / 40.17 / 37.07 | 3.04x | 4.4-5.2 |

Peak RSS: 13.54 GB (1 iter), 16.37 GB (2 iters, 11.16 GB of keys at dnum 4); both fit the WSL slice. No run spanned a
sleep (wall time = setup + first + reps in every run). The VM was shared with other processes this session (load
average 2-8.5 from other Claude/VS Code processes), and the 2-iteration run (16.4 GB, larger dnum-4 keys) slowed
down more than the 1-iteration run under that load, so the WSL time ratios (2.56-3.20x) are not clean: pass 2 of
`p32_wsl16` is discarded (the 1-iteration run took 3.4x its pass-1 time), and the quiet ICELAKE ratio (2.13-2.19x)
is the reference for time. Precision is the same on both hosts and in every pass: CI CtS-first 2 iterations
40.17-40.18 bits RMS, 36.95-37.33 bits min.

**Results 3: correctness at small N (WSL, insecure, `p32_smoke`, 4 threads, reps 2; RMS / min bits).**

| N, budget | CI CtS 1 / 2 iters | CI StC 1 / 2 iters | std CtS 1 / 2 iters | std StC 1 / 2 iters |
|---|---|---|---|---|
| 2^12 {2,2} | 18.80/17.18 -> 35.48/33.78 | 22.68/21.28 -> 40.34/39.50 | 19.69/17.95 -> 37.94/36.34 | 24.69/23.25 -> 33.12/31.10 |
| 2^13 {3,3} | 19.71/18.03 -> 35.12/33.82 | 22.67/21.14 -> 41.65/39.96 | 20.81/19.15 -> 39.23/37.41 | 24.68/23.27 -> 32.63/30.62 |
| 2^14 {5,3} | 20.71/18.90 -> 40.34/38.26 | 22.49/20.56 -> 42.04/40.53 | 21.70/19.91 -> 40.90/39.42 | 24.38/22.41 -> 32.19/30.21 |

All 24 runs: rc 0, passthrough 0. The CI META-BTS works in both orderings at every N.

**Results 4: the META-BTS precision argument (WSL, 2^13 {3,3}, insecure, `p32_metaprec` / `p32_fm`; RMS / min bits).**

| metaprec | CI StC-first (corr 12) | std StC-first (corr 13) | std CtS-first (corr 5) |
|---|---|---|---|
| 8 | 33.69 / 31.60 | 32.60 / 30.72 | 39.11 / 35.11 |
| 12 | 37.68 / 35.60 | 32.68 / 30.66 | 43.13 / 39.67 |
| 16 | 41.62 / 39.68 | 32.64 / 30.79 | 44.33 / 42.22 |
| 20 | 41.71 / 40.15 | 32.64 / 30.57 | 37.24 / 35.44 |
| 24 | 36.91 / 35.53 | 32.60 / 30.59 | 29.24 / 27.44 |
| FIXEDMANUAL, 8 / 16 | 29.02 / 27.70, 37.02 / 35.70 | 31.29 / 29.50, 32.98 / 30.96 | 32.94 / 30.93, 40.98 / 38.93 |

**Conclusions.**
- **CI works with META-BTS in both orderings** (2^12-2^16), after the fix above. At 2^16, 128-bit, 2 iterations
  give CI 40.2-40.4 bits RMS and 37.0-37.3 bits min (max error), against the paper's 20.55 bits max error: about
  16.5 bits more. The cost is one more level (dnum 4 at 128-bit) and 2.13-2.18x the time of one iteration
  (ICELAKE; 46.1-48.2 s against the paper's 12.6 s for one bootstrap). With 1 iteration CI is 2.3 bits (CtS-first,
  min 18.2-18.6) or 0.7 bits (StC-first, min 19.8) below the paper; META-BTS is not needed to reach 20.5 bits, it is
  the option when the application needs much more.
- **CI and std give the same META-BTS precision for CtS-first** (40.2 vs 41.0 bits RMS) at the same time ratio.
- **Std StC-first reaches only ~31 bits.** The result does not depend on the precision argument (30.6-30.8 bits min
  for metaprec 8 to 24) or on the scaling technique (FIXEDMANUAL gives the same floor), while CI StC-first and std
  CtS-first follow the expected curve (rise with metaprec until the scaled error overflows the EvalMod range). A
  floor that does not move with metaprec means std's StC-first bootstrap of the error ciphertext has an error
  proportional to the error's magnitude (about 8 bits relative, against about 23 bits for a fresh input), so the
  second iteration gains only ~8 bits. It is specific to OpenFHE's std StC-first path for real data
  (`EvalBootstrapStCFirst`, single EvalMod on the real part after a conjugate add); the CI StC-first path does not
  show it. Root cause not pinned down (time-boxed); it does not affect CI.
- **The automatic precision argument is not optimal.** `metaprec` = floor(min bits of one bootstrap) (the OpenFHE
  example's rule) puts the scaled error near the EvalMod range limit: at 2^13 std CtS-first gives 39.2 bits RMS at
  19 but 44.3 at 16; CI StC-first is flat for 16-20. About 3 bits below the one-bootstrap min is the better
  choice; the 2^16 numbers above use the automatic rule (19 / 20), so they are conservative by up to ~2-4 bits.
- No baseline numbers or commands change (1-iteration paths are unchanged; the driver defaults are iters 1).

## 3.3 EvalMod time per real slot, CI and std side by side -- DONE (2026-10-28)

**Host.** WSL only (i7-12700H laptop VM). The host file said `WSL` before every job; nothing ran on ICELAKE (user:
"no runs in ICELAKE no matter what"). Compare these numbers only with WSL numbers.

**What changed.** No library or driver code. New tool `ci-ckks-paper/tools/evalmod-per-slot.py LOG...`: it reads
guarded-job logs of `ci-fft-boot` runs (CI EvalMod from the `[CI-BT] EvalMod` lines of `CI_BOOT_TIMING=1`, std
EvalMod from "Approximate modular reduction time" of the `build-wsl-bt` binary), drops the first (cold) bootstrap,
takes the median of the warm ones and prints, per run: real slots per bootstrap (CI N = 65536, std N/2 = 32768),
EvalMod calls per bootstrap (CI 1; std CtS-first 2, real and imaginary part; std StC-first 1), EvalMod s, us per real
slot, s per call, share of the bootstrap; then, for every CI run, the ratio to the nearest std run of each ordering
in the same log. Runs need a `=== ... ci-fft-boot ...` header line (the `r()` wrapper below).

**Commands** (WSL, repo root, `ci-ckks-paper/tools/wsl-guard.sh`; `B` = `build-wsl/bin/benchmark/ci-fft-boot`, `T` =
`build-wsl-bt/bin/benchmark/ci-fft-boot`, `E` = `env CI_BOOT_TIMING=1 OMP_NUM_THREADS=1`; 2^16 {5,3}, 128-bit, reps 3,
FLEXIBLEAUTO 59/60, encap, dnum 3, 2 levels after; `r()` echoes `=== time uptime cmd`, `uptime`, runs, `=== end`):

    wsl-guard.sh p33_build 12 'cmake --build build-wsl --target ci-fft-boot -j 8 && cmake --build build-wsl-bt --target ci-fft-boot -j 8'  # rc 0
    wsl-guard.sh p33_smoke 4 '$T std 14 5 3 59 {60,61} 0 3 fa 5 encap; CI_BOOT_TIMING=1 $B ci 14 5 3 59 60 0 3 fa 4 encap'           # rc 0 (*)
    wsl-guard.sh p33_em16 15 'pass 1: r $E $B ci ... fa 4 encap 0; r $E $T std ... fa 5 encap 0; r $E $B ci ... fa 12 encap 1;
        r $E $T std ... fa 13 encap 1; pass 2: the same four in reverse order'                                                  # rc 0
    wsl-guard.sh p33_em16b 15 'r $E $T std ... 13 encap 1; r $E $B ci ... 12 encap 1; r $E $T std ... 5 encap 0; r $E $B ci ... 4 encap 0;
        then the same four in reverse order'                                                                                    # rc 0
    python3 -I ci-ckks-paper/tools/evalmod-per-slot.py ~/ci-ckks-wsl/logs/{p33_em16,p33_em16b,p2R_base}.log

(*) `p33_smoke` tried std with firstMod 61 to give std the K = 28 sine table (OpenFHE uses it for the weight-64
encapsulation key when firstMod > 60) for a same-polynomial comparison; OpenFHE refuses primes above 60 bits
("LastPrime(): Requested bit length 61 exceeds maximum allowed length 60"), so that comparison is not possible
without a code switch (not done; item 0.5's switch measured the K = 28 cost on CI instead, see conclusions).

No run spanned a sleep (uptime advance = wall time for every run). All 32 CI bootstraps: Galois check held, 0 local
encodes. Precision as in 2.R (CI CtS-first RMS 21.55-21.57 / min 18.24-18.40; CI StC-first 21.91-21.92 /
19.69-19.83; std CtS-first 22.74-22.76 / 19.61-19.84; std StC-first 22.90-22.91 / 20.69-20.77 bits). Keys 102 / 61,
peak RSS 13.39-13.54 / 7.58-7.66 GB.

**Timing noise.** The laptop ran in two speed states during these jobs. A run is either at the 2.R reference speed
(warm bootstrap within 3% of `p2R_base`) or 1.15-1.9x slower in *every* stage uniformly (e.g. std StC-first in
`p33_em16b`: decode / encode / EvalMod 2.0-2.5 / 4.6-5.3 / 3.9-4.5 s against 1.5-1.7 / 3.4-3.7 / 2.9-3.0 s in
`p2R_base`). This fits the hybrid CPU (P-cores and E-cores; WSL does not pin a vCPU to a core type) and thermal
throttling; other users' load was 4.2-6.7 in pass 1 of `p33_em16` and 1.0-1.8 afterwards. Neighbouring runs can
be in different states, so a single adjacent CI/std pair can be off by up to 1.6x. The tables therefore give (1) the
runs at reference speed, (2) all runs, (3) the per-call ratio over all 16 neighbour pairs, (4) the calm 2.R job
re-read with the tool (same host and binaries' code paths: item 3.2 changed only the 2-iteration path).

**Results 1: runs at reference speed** (warm within 3% of `p2R_base`; `p33_em16b` #1-#3 are adjacent in one job).

| run | real slots | EvalMod calls | EvalMod s | **us / real slot** | s / call | share of bootstrap | bootstrap s |
|---|---|---|---|---|---|---|---|
| CI CtS-first corr 4 (em16b #3) | 65536 | 1 | 3.929 | **59.9** | 3.929 | 33% | 11.82 |
| CI StC-first corr 12 (em16b #1) | 65536 | 1 | 3.966 | **60.5** | 3.966 | 34% | 11.70 |
| std CtS-first corr 5 (em16b #2) | 32768 | 2 | 6.325 | **193.0** | 3.163 | 54% | 11.81 |
| std StC-first corr 13 (em16 #4) | 32768 | 1 | 2.985 | **91.1** | 2.985 | 36% | 8.21 |

| CI / std, per real slot | vs std CtS-first | vs std StC-first |
|---|---|---|
| CI CtS-first | **0.311x** (adjacent, em16b) | **0.658x** (across jobs) |
| CI StC-first | **0.314x** (adjacent, em16b) | **0.664x** (across jobs) |
| per EvalMod call (CI / std) | 1.24-1.25x | 1.32-1.33x |

**Results 2: all runs** (`p33_em16`, `p33_em16b`; warm medians; "x ref" = warm bootstrap / the same config in `p2R_base`).

| job #, run | EvalMod s | us / real slot | s / call | share | bootstrap s | x ref |
|---|---|---|---|---|---|---|
| em16 0 CI CtS-first | 7.369 | 112.4 | 7.369 | 32% | 22.78 | 1.90 |
| em16 1 std CtS-first | 11.686 | 356.6 | 5.843 | 52% | 22.49 | 1.93 |
| em16 2 CI StC-first | 5.820 | 88.8 | 5.820 | 34% | 17.29 | 1.49 |
| em16 3 std StC-first | 3.659 | 111.7 | 3.659 | 38% | 9.74 | 1.16 |
| em16 4 std StC-first | 2.985 | 91.1 | 2.985 | 36% | 8.21 | 0.97 |
| em16 5 CI StC-first | 4.689 | 71.6 | 4.689 | 34% | 13.60 | 1.17 |
| em16 6 std CtS-first | 7.899 | 241.1 | 3.950 | 54% | 14.72 | 1.27 |
| em16 7 CI CtS-first | 5.482 | 83.6 | 5.482 | 34% | 16.18 | 1.35 |
| em16b 0 std StC-first | 4.421 | 134.9 | 4.421 | 38% | 11.67 | 1.38 |
| em16b 1 CI StC-first | 3.966 | 60.5 | 3.966 | 34% | 11.70 | 1.01 |
| em16b 2 std CtS-first | 6.325 | 193.0 | 3.163 | 54% | 11.81 | 1.02 |
| em16b 3 CI CtS-first | 3.929 | 59.9 | 3.929 | 33% | 11.82 | 0.99 |
| em16b 4 CI CtS-first | 4.621 | 70.5 | 4.621 | 34% | 13.71 | 1.14 |
| em16b 5 std CtS-first | 7.975 | 243.4 | 3.987 | 54% | 14.83 | 1.28 |
| em16b 6 CI StC-first | 5.162 | 78.8 | 5.162 | 33% | 15.70 | 1.35 |
| em16b 7 std StC-first | 4.083 | 124.6 | 4.083 | 35% | 11.51 | 1.37 |

**Results 3: neighbour pairs** (each CI run with the nearest std run of each ordering; the tool's second table).
Per call CI / std over all 16 pairs: 0.89-2.01x, median **1.26x**. Per real slot vs std CtS-first (8 pairs):
0.25-0.35x, median **0.31x**. Vs std StC-first (8 pairs): 0.44-1.01x (too noisy to use alone; its expected value
is per call / 2, results 4).

**Results 4: 2.R job re-read with the tool** (`p2R_base`, WSL, one calm interleaved job, load 0.2-1.1).

| run | EvalMod s | us / real slot | s / call | share |
|---|---|---|---|---|
| CI CtS-first {5,3} | 4.016 | 61.3 | 4.016 | 34% |
| std CtS-first {5,3} | 6.173 | 188.4 | 3.087 | 53% |
| CI StC-first {5,3} | 3.947 | 60.2 | 3.947 | 34% |
| std StC-first {5,3} | 3.063 | 93.5 | 3.063 | 36% |
| CI CtS-first {4,4} | 4.365 | 66.6 | 4.365 | 33% |
| std CtS-first {4,4} | 6.796 | 207.4 | 3.398 | 53% |

CI / std per real slot: {5,3} CtS-first pair 0.325x, StC-first pair 0.644x, CI CtS-first vs std StC-first 0.656x,
CI StC-first vs std CtS-first 0.320x; {4,4} CtS-first pair 0.321x. Per call 1.28-1.31x.

**Summary (WSL, 2^16 {5,3}, 128-bit, 1 thread).**

| | CI CtS-first | CI StC-first | std CtS-first | std StC-first |
|---|---|---|---|---|
| real slots per bootstrap | 65536 | 65536 | 32768 | 32768 |
| EvalMod calls per bootstrap (degree) | 1 (K = 28, deg 48) | 1 (K = 28) | 2 (K = 16, deg 36) | 1 (K = 16) |
| EvalMod s | 3.93-4.02 | 3.95-3.97 | 6.17-6.33 | 2.99-3.06 |
| **EvalMod us per real slot** | **60-61** | **60-61** | **188-193** | **91-94** |
| CI / std per real slot | 0.31-0.33x vs CtS-first; 0.64-0.66x vs StC-first | same | | |
| EvalMod share of the bootstrap | 33-34% | 34% | 52-54% | 36% |

**Conclusions.**
- Per real slot CI EvalMod costs **0.31-0.33x** std CtS-first's and **0.64-0.66x** std StC-first's. The two CI
  orderings run the same EvalMod (60-61 us per real slot). Std's per-call EvalMod time is the same in both orderings
  (2.99-3.16 s); the 2x between them is the call count.
- The ratios follow from one number, the per-call ratio CI / std = **1.24-1.33x** (median of all pairs 1.26x):
  CI does one call for 65536 reals, std CtS-first two calls for 32768, std StC-first one call for 32768, so per real
  slot CI / std = per-call / 4 and per-call / 2. Both EvalMods start at the same level (after a 5-level CtS from 21
  towers), so the per-call excess is per-op cost, not towers.
- The per-call excess has two known parts: the K = 28 sine table (Paterson-Stockmeyer (7,3) vs (6,3), same depth),
  which item 0.5 measured as 13% of CI EvalMod (ICELAKE, {4,4}; a ratio within that host, used here as a fraction:
  CI with K = 16 would be about 1.26 x 0.87 = 1.10x std per call), and the CI ring overhead, the remaining ~1.10x
  (`CI_FFT_REVIEW.md` section 4 item 3: ~1.2x per op). Item 3.1 keeps K = 28 (weight 16 is below 128 bits).
- Against the phase-4 target "CI EvalMod time per real slot <= 0.55x std's" (4.R): met against std CtS-first
  (0.31-0.33x), not against std StC-first (0.64-0.66x). With K = 28 fixed, even a CI per-op cost equal to std's
  gives about 1.15 / 2 = 0.57x against std StC-first, so 4.R as written can only be met against std StC-first if CI
  ops become cheaper than std's. Suggested for the plan adapter: state which std ordering 4.R compares with
  (CtS-first: met now; StC-first: about 0.57x is the K = 28 floor).
- Std StC-first is the cheaper std EvalMod per real data value (one call instead of two), which is why CI/2xstd
  drops from ~1.95x to ~1.45x when both run StC-first (2.R); in EvalMod alone CI still saves 34-36% per real slot.
- No baseline numbers or commands change. The WSL timing noise of this session (two speed states, up to 1.9x) is
  logged above; later WSL items should check each run's "x ref" before using single pairs.

## 3.R Phase 3 review -- DONE (2026-10-28)

**Host.** WSL only (i7-12700H laptop VM). The host file said `WSL` before every job; nothing ran on ICELAKE (user:
"no runs in ICELAKE no matter what"). All numbers in this entry are precision numbers (bits), which do not depend on
the host or the thread count; no timing is reported.

**What changed.** Nothing is committed in the library or the drivers. Two temporary probes were built, used and
reverted (`git checkout`), and `build-wsl` was rebuilt from the committed source afterwards (`p3R_rebuild`, rc 0):
- `CI_PROBE_SINE_K=16|28` in `ckksrns-fhe.cpp` forced the SPARSE_ENCAPSULATED sine table (the overflow bound K in
  `GetModRaiseOverflowBound`, which is folded into the CtS matrices, and the Chebyshev coefficients) for CI and std
  alike, in all three EvalMod sites (CI branch, std CtS-first, std StC-first).
- `ci-noise-probe.cpp` printed the RMS of the imaginary part of std slots. It is always exactly 0 (OpenFHE's
  real-data decode drops it), so it measured nothing and was dropped.

**Commands** (WSL, repo root, `ci-ckks-paper/tools/wsl-guard.sh`; `B` = `build-wsl/bin/benchmark/ci-fft-boot`; args
after the budget: scaleMod firstMod secure reps scaling corr secret stcfirst; precision runs use 8 threads):

    wsl-guard.sh p3R_build 12 'cmake --build build-wsl --target ci-fft-boot -j 8'          # with the K probe; rc 0
    wsl-guard.sh p3R_k15 10 'bash ~/ci-ckks-wsl/scripts/p3R_k15.sh'                         # rc 0
      # two passes, OMP_NUM_THREADS=8, for (ci corr 4 CtS-first, std 5 CtS-first, ci 12 StC-first, std 13 StC-first)
      # x K in {28, 16}: CI_PROBE_SINE_K=$K $B $s 15 5 3 59 60 0 3 fa $corr encap $stcfirst
    wsl-guard.sh p3R_build2 12 'cmake --build build-wsl --target ci-noise-probe -j 8'      # rc 0
    wsl-guard.sh p3R_noise 8 'OMP_NUM_THREADS=8; for n in 14 15 16 (+ std 17); for s in ci std:
        build-wsl/bin/benchmark/ci-noise-probe $s $n 59 fa'                                # rc 0
    wsl-guard.sh p3R_eqreal 8 'bash ~/ci-ckks-wsl/scripts/p3R_eqreal.sh'                    # rc 0
      # n in {13, 14}: $B ci n 5 3 59 60 0 3 fa 12 encap 1; std n+1 ... 13 encap 1; std n ... 13 encap 1;
      #                $B ci n ... fa 4 encap 0;      std n+1 ... 5 encap 0;  std n ... 5 encap 0
    wsl-guard.sh p3R_std17 18 'OMP_NUM_THREADS=8 $B std 17 5 3 59 60 1 2 fa 13 encap 1'    # killed:oom-kill at 18 GB
    git checkout src/pke/lib/scheme/ckksrns/ckksrns-fhe.cpp benchmark/src/ci-noise-probe.cpp
    wsl-guard.sh p3R_rebuild 12 'cmake --build build-wsl --target ci-fft-boot ci-noise-probe -j 8'   # rc 0

The other numbers in this entry come from existing logs at the same code: `p33_em16`, `p33_em16b` (item 3.3: 2^16
{5,3}, 128-bit, reps 3) and `p2R_base` (item 2.R). Item 3.3 changed no code, so no baseline was rerun (plan rule
"phase reviews reuse numbers").

### Criterion 1: CI EvalMod degree vs std's for the same secret distribution

| ephemeral key (sparse encapsulation) | power-basis L1 of the overflow sum | sine table (degree) | security (item 3.1) |
|---|---|---|---|
| std, weight 32 (firstMod <= 60) | 32 | K = 16 (36) | 213 / 216 bits |
| std, weight 64 (firstMod > 60) | 64 | K = 28 (48) | -- |
| **CI, weight 32 in the CI basis (used)** | ~64 (b_i b_j = b_{i+j} + b_{abs(i-j)}) | K = 28 (48) | 213 / 216 bits |
| CI, weight 16 in the CI basis | ~32 | K = 16 (36) would be sound | **116 bits (MITM): rejected** |

- **For the same overflow distribution the degree is equal.** OpenFHE gives std the same K = 28, degree-48 table
  when its overflow sum has L1 64 (`UsesLargeSparseKey`, weight 64). For the same LWE secret (weight 32, rank
  65536, the paper's choice too) CI needs degree 48 where std uses 36, because a CI-basis product doubles the
  overflow's L1. To get std's degree 36, CI would need weight 16, and item 3.1 showed that weight 16 has only
  2^116 security. This is the security reason the criterion allows, and it is recorded.
- **The larger table costs time, not precision** (new: item 0.5 checked this only at 55/60, where noise limits the
  precision). `p3R_k15`, 2^15 {5,3}, 59/60, insecure, reps 3, two passes (RMS / min bits):

| run | K = 28 (degree 48) | K = 16 (degree 36) |
|---|---|---|
| CI CtS-first corr 4 | 21.65 / 19.64, 21.65 / 19.66 | 21.64 / 19.61, 21.64 / 19.50 |
| CI StC-first corr 12 | 22.47 / 20.58, 22.48 / 20.57 | 22.48 / 20.64, 22.47 / 20.49 |
| std CtS-first corr 5 | 22.52 / 20.34, 22.51 / 20.53 | 22.51 / 20.43, 22.50 / 20.16 |
| std StC-first corr 13 | 22.91 / 20.82, 22.92 / 20.91 | 22.93 / 20.91, 22.93 / 20.86 |

  RMS changes by at most 0.02 bits. min moves by up to 0.3 bits in both directions, which is the run-to-run spread.
  The precision gap between CI and std therefore does not come from the sine table.
- *Note for the plan adapter (estimate, not measured).* The CI overflow sum with L1 ~64 has sigma = sqrt(64/12) =
  2.31. K = 16 is 6.9 sigma, which gives a Gaussian tail of about 2^-38 per coefficient and 2^-22 per 2^16
  bootstrap. With L1 32 the sum is bounded by 16, so std never overflows K = 16. K = 28 gives about 2^-94 per
  bootstrap. A weight-32 CI key with the K = 16 table (about -1 s of EvalMod, item 0.5) would therefore fail about
  once per 4 million bootstraps. That is a correctness trade-off, not a security one, and it is not adopted.

### Criterion 2: the precision gap to the paper

The paper (ePrint 2026/2618, Table 2) reports Prec = -log2 of the max error (our `prec_bits_min`) for 65536
uniform reals in [-1, 1] with its StC-first bootstrap: CI 20.49-20.68 bits over its four factorizations, 20.55 at
3+4. Its "via standard CKKS" baseline puts the same 65536 reals in a ring of dimension 2N = 2^17 and gets
20.17-20.57 bits, so in the paper CI and std are equal to within 0.4 bits.

**Ours, 2^16 {5,3}, 128-bit (items 2.R and 3.3, same code):**

| ordering | CI RMS / min | std (2^16, 32768 reals) RMS / min | gap of CI min to the paper's 20.55 |
|---|---|---|---|
| CtS-first (OpenFHE default) | 21.55-21.57 / 18.05-18.40 | 22.74-22.76 / 19.61-19.84 | -2.15 to -2.50 |
| StC-first (the paper's ordering) | 21.91-21.92 / 19.69-19.85 | 22.90-22.91 / 20.69-20.77 | **-0.70 to -0.86** |
| META-BTS, 2 iterations (item 3.2) | 40.17-40.42 / 36.95-37.34 | | **+16.4 to +16.8** |

**Per-operation noise: CI at N equals std at 2N** (`p3R_noise`, UNIFORM_TERNARY, depth 8, 59-bit FLEXIBLEAUTO,
uniform reals, RMS bits of the real part).

| ring | reals | fresh | mult + rescale | rotate | 6 chained double angles |
|---|---|---|---|---|---|
| CI 2^14 | 16384 | 42.13 | 41.94 | 42.03 | 35.39 |
| std 2^14 | 8192 | 43.12 | 42.91 | 43.01 | 36.55 |
| CI 2^15 | 32768 | 41.13 | 40.93 | 41.05 | 34.44 |
| std 2^15 | 16384 | 42.11 | 41.91 | 42.06 | 35.49 |
| CI 2^16 | 65536 | 40.12 | 39.91 | 40.00 | 33.22 |
| std 2^16 | 32768 | 41.12 | 40.91 | 41.06 | 34.48 |
| std 2^17 | 65536 | 40.13 | 39.91 | 40.09 | 33.32 |

At the same N, every CI operation has 1.0 bit more noise per real slot than std. The real subring of rank N
evaluates a power-basis polynomial of length 2N, so its slot noise is the noise of std at 2N (within 0.1 bit
here). At the same number of reals, which is the paper's comparison, the noise is the same. So the noise of the CI
ring itself costs nothing against the paper's baseline. It only matters when CI is compared with std at the same N,
as in our plan's CI/std tables.

**Bootstrap precision at the same number of reals** (`p3R_eqreal` and `p3R_k15` at 2^13-2^15, insecure, reps 3;
the std 2^16 rows are from `p33_em16`/`p33_em16b`, 128-bit; RMS / min bits).

| reals | CI StC-first (corr 12) | std StC-first at 2N (corr 13) | CI CtS-first (corr 4) | std CtS-first at 2N (corr 5) |
|---|---|---|---|---|
| 8192 | CI 2^13: 22.67 / 21.14 | std 2^14: 24.37-24.38 / 22.42-22.45 | 19.71 / 18.03 | 21.70 / 19.89-19.90 |
| 16384 | CI 2^14: 22.49 / 20.54 | std 2^15: 22.91-22.93 / 20.82-21.04 | 20.71 / 18.92 | 22.50-22.52 / 20.16-20.53 |
| 32768 | CI 2^15: 22.47-22.48 / 20.49-20.64 | std 2^16: 22.90-22.91 / 20.69-20.77 | 21.64-21.65 / 19.50-19.66 | 22.74-22.76 / 19.61-19.84 |
| 65536 | CI 2^16: 21.91-21.92 / 19.69-19.85 | std 2^17: not measured (OOM, below) | 21.55-21.57 / 18.05-18.40 | -- |

The two std 2^13 runs (4096 reals) gave StC-first 24.68 / 23.26 and CtS-first 20.81 / 19.15. The std 2^17 bootstrap
(`p3R_std17`, 128-bit, 8 threads) was killed at its 18 GB cap during setup. The WSL slice cannot run it, and
ICELAKE is excluded, so the 65536-real std row is open.

**Accounting for the gap** (paper's ordering, max error, 2^16):
1. **Ordering: 1.2-1.6 bits, and only for the default CtS-first.** The paper's 20.55 bits is a StC-first number.
   CI CtS-first is 2.15-2.50 bits below the paper and CI StC-first 0.70-0.86 bits (item 2.5: StC-first +1.2 bits
   min at the same chain and time). Both orderings stay supported.
2. **Sine table: 0 bits** (criterion 1 table: K = 16 and K = 28 give the same RMS within 0.02 bits).
3. **Ring noise: 0 bits against the paper's comparison.** CI at N has std's per-op noise at 2N. The 1.0-bit
   CI/std RMS gap at the same N (21.92 vs 22.91 StC-first) is the 2x slot noise of twice as many reals per ring.
4. **CI vs std in OpenFHE at the same number of reals: about 0.4 bits RMS** (StC-first: 0.43-0.44 at 16384 and
   32768 reals; min 0.05-0.50). The paper sees no gap (+0.02 to +0.4 bits for CI). This part is specific to our
   CI bootstrap. Its source is not pinned down. The sine table and the per-op ring noise are ruled out. The
   remaining candidate is the rounding and rescale noise of the 1.9x more plaintext diagonals in CI CtS/StC
   (item 2.1). In CtS-first the gap is 1.1 bits at equal reals (21.65 vs 22.75 at 32768), where StC runs after
   EvalMod at the bottom of the chain. At 8192 reals (2^13/2^14) the gap is 1.7 bits. At that size, std's precision
   rises by 1.5 bits from 2^15 to 2^14 at a fixed corr, which marks a different noise regime and is not used here.
5. **The rest, about 0.3-0.45 bits (0.70-0.86 minus 4), comes from the library's bootstrap design, not from CI.**
   OpenFHE's std StC-first with 32768 reals at 2^16 (20.69-20.77 min) is at the paper's level. With 65536 reals in a
   ring of 2^17 (the paper's baseline) its per-op noise matches CI 2^16 (table above), so by item 4 it would reach
   about 20.1-20.3 bits, 0.3-0.45 below Lattigo's 20.55. That inference stands until the std 2^17 run above can
   be done. The design differences are: one 59/60 FLEXIBLEAUTO scale with a 2^12 correction shrink and a
   degree-48 Chebyshev sine with 3 double angles (OpenFHE), against per-stage scales (60-bit EvalMod, 40-bit
   StC/base) and Lattigo's cosine EvalMod (paper Table 1).
6. **Closed when needed:** META-BTS (2 iterations, item 3.2) gives CI 36.95-37.34 bits min at 2^16, 16.4-16.8 bits
   above the paper, at 2.13-2.18x the time of one bootstrap (ICELAKE ratio) and one more level (dnum 4 at 128-bit).

**Conclusions.**
- Criterion 1 is met through its security clause. CI and std use the same EvalMod degree for the same overflow
  distribution (degree 48 at power-basis L1 64). For the same weight-32 LWE secret, CI needs degree 48 against
  std's 36, and the only way to equalize, a weight-16 CI key, has 2^116 security (item 3.1). The larger table costs
  no precision (new: checked at 59/60), and its cost is about 1 s of EvalMod (item 0.5).
- Criterion 2 is met: the gap is explained, and META-BTS closes it. At the paper's ordering the gap is 0.70-0.86
  bits, made of about 0.4 bits of CI-specific bootstrap error (source open; table and ring noise excluded) and
  about 0.3-0.45 bits of OpenFHE-vs-Lattigo bootstrap design, which std shares. In the default CtS-first ordering
  another 1.2-1.6 bits are lost to the ordering. The 1.0-bit CI/std gap at the same N in our tables is the CI
  ring's per-op noise at twice the reals, and it vanishes at the paper's equal-reals comparison.
- No baseline numbers or commands change, and no code changed (both probes reverted; `build-wsl` rebuilt from
  HEAD). Open for later, with no item in the plan: the std 2^17 bootstrap (65536 reals), which needs more than
  18 GB, so ICELAKE or a larger WSL slice, to confirm item 5; the source of the 0.4-bit CI-specific part; and a
  K = 16 table with the weight-32 CI key, which has a failure estimate of about 2^-22 per bootstrap.

## 4.1 Raw-word CI NTT, fold fused into the first/last butterfly stage -- DONE (WSL)

**Host.** The host file said `WSL` before every job. All jobs ran on WSL through `wsl-guard.sh`. Nothing ran on
ICELAKE. Jobs: `p41_build`, `p41_check`, `p41_buildab`, `p41_smoke`, `p41_ab16`, `p41_build3`, `p41_ab16b`,
`p41_build4`, `p41_check2`, `p41_buildf`, `p41_final`. All have rc 0. One more build (`p41_build4`, first try) was
`refused:mem` while `p41_ab16b` still ran. The guard did that, so the binary did not change during the job.

**What changed.**
- The CI transform is now the NTT modulo X^N - wm^N of the fold g_i = a_i - wm^N a_{N-i} (g_0 = a_0). At the CI
  nodes wm^{4j+1}, x^{-i} = -wm^N x^{N-i}. The CT tree of X^N - wm^N has node multipliers wm^{e_k} with e_1 = N/2,
  e_{2k} = e_k/2 and e_{2k+1} = e_k/2 + N, so OpenFHE's in-place CT/GS kernels run it unchanged with these tables.
  The output order is the same as before: position brev(j) holds the value at wm^{4j+1}. So the automorphism maps
  and all callers stay the same, and the output is bit-exact against `CIForwardTransformRef`.
- Forward: the fold is fused into the first CT stage (multiplier r = wm^{N/2}, r^2 = wm^N, r^4 = -1). For each
  index quadruple {j, h+j, h-j, N-j} (h = N/2) it computes U = r^2 a_{N-j}, V = r^2 a_{h+j}, P = a_j - U,
  R = a_{h-j} - V, rS = -r^3 (a_j + U), rQ = -r^3 (a_{h-j} + V), and writes P +- rQ and R +- rS. That is 4
  multiplications per quadruple, against 2 for a plain first stage. Before, the separate twist took 4 per pair.
  The outputs stay below 3q, the bound OpenFHE's deferred-reduction schedule assumes after one stage.
- Inverse: the unfold a_i = (g_i + r^2 g_{N-i}) / 2 and the 1/N scaling are fused into the last GS stage. The
  table entries [2] and [3] (the second-to-last stage) also carry mu = r c, with c = (2N)^{-1}. That costs nothing,
  and it saves one multiplication: 5 per quadruple, against 4 for OpenFHE's last stage plus the 1/N pass. Before,
  the inverse used 4 per pair plus the 1/N pass. The special indices are 0 and N/2 (no halving, a_h = g_h/(1 - r^2))
  and N/4 and 3N/4.
- In total the CI round trip costs about N + N/4 more multiplications than std's 16.5 N at 2^16. The old twist
  cost 4 N more, through `NativeInteger` calls that reduced every product fully.
- Code:
  - `NumberTheoreticTransformNat` (`transformnat.h` / `-impl.h`, which already has raw `m_value` access) gets
    `CIForwardTransformToBitReverseInPlace` and `CIInverseTransformFromBitReverseInPlace`.
  - The std kernels are split, with no change to their arithmetic: `ForwardTransformToBitReverseInPlace` calls the
    new private `ForwardStagesFrom(1, ...)`, and `InverseTransformFromBitReverseInPlace` calls
    `InverseStagesButLast` and then its own last stage.
  - `ci-transform.cpp` builds the new tables and drops the psi tables, the four N-length twist tables and their
    Shoup tables (peak RSS at 2^16 {5,3} 13.60 -> 13.43 GB).
- `benchmark/src/ci-ntt-check.cpp` was rewritten:
  - Bit-exactness against the reference at logN 2, 3, 4, 5, 10 and 12-16, with 50-bit (lazy CT schedule), 59-bit
    and 60-bit (non-lazy at large N) primes. Each case has 3 inputs, one of them all near q - 1, and checks
    forward, inverse and the round trip.
  - Timing (59-bit prime) of the new CI NTT, the previous CI NTT (copied into the check as `OldCI`) and the std
    negacyclic NTT, interleaved per rep. The medians of the per-rep times and of the per-rep ratios cancel the
    laptop's speed states.

**Commands** (WSL, repo root; host file `WSL` before each):

    wsl-guard.sh p41_build 12 'cmake --build build-wsl --target ci-ntt-check ci-fft-boot -j 8'
    wsl-guard.sh p41_check 3 'OMP_NUM_THREADS=1 build-wsl/bin/benchmark/ci-ntt-check 100 3'     # 6-mult inverse
    # temporary CI_NTT_OLD=1 switch in ci-transform.cpp (old twisted NTT), for the bootstrap A/B in one binary:
    wsl-guard.sh p41_buildab 12 'cmake --build build-wsl --target ci-ntt-check ci-fft-boot -j 8'
    wsl-guard.sh p41_smoke 6 'for old in 0 1; for cfg in {12 1 1, 12 3 3, 13 4 4, 14 5 3};
        for st in {4 encap 0, 12 encap 1}: CI_NTT_OLD=$old ci-fft-boot ci $cfg 59 60 0 1 fa $st'
    wsl-guard.sh p41_ab16 15 'ci-ntt-check 200 7; for old in 0 1 1 0:
        CI_NTT_OLD=$old CI_BOOT_TIMING=1 OMP_NUM_THREADS=1 ci-fft-boot ci 16 5 3 59 60 1 3 fa 4 encap'
    wsl-guard.sh p41_build3 12 'cmake --build build-wsl --target ci-ntt-check -j 8'           # per-rep interleave
    wsl-guard.sh p41_ab16b 15 'ci-ntt-check 200 7; for old in 0 1 0 1 0 1: (same CI run as p41_ab16)'
    # 5-mult inverse (mu = r c in rootInv[2], [3]):
    wsl-guard.sh p41_build4 12 'cmake --build build-wsl --target ci-ntt-check ci-fft-boot -j 8'
    wsl-guard.sh p41_check2 3 'OMP_NUM_THREADS=1 build-wsl/bin/benchmark/ci-ntt-check 200 7'
    # final code (temporary switch removed):
    wsl-guard.sh p41_buildf 12 'cmake --build build-wsl --target ci-ntt-check ci-fft-boot -j 8'
    wsl-guard.sh p41_final 15 'ci-ntt-check 200 7; ci-fft-boot ci {12 1 1, 12 3 3, 13 4 4, 14 5 3} 59 60 0 1 fa
        {4 encap 0, 12 encap 1}; CI_BOOT_TIMING=1 ci-fft-boot ci 16 5 3 59 60 1 1 fa {4 encap 0, 12 encap 1}'

**NTT round trip** (59-bit prime, 1 thread, medians of per-rep times, per-rep interleaved new/old/std; the ratio
column is the median of per-rep new/std ratios). Bit-exact (`all_match=1`) in every run, at every N and prime
width.

| logN | std us | new CI us | new / std | old CI / std | old / new | job |
|---|---|---|---|---|---|---|
| 16 | 1822 | 1905 | **1.041** (aggregate 1.046) | 1.192 | 1.137 | `p41_final` |
| 16 | 1748 | 1834 | **1.046** (aggregate 1.049) | 1.199 | 1.145 | `p41_check2` |
| 16 | 1290 | 1365 | 1.059 | 1.202 | 1.135 | `p41_ab16b`, 6-mult inverse |
| 15 | 616 | 645 | 1.043 | 1.201 | 1.147 | `p41_final` |
| 14 | 370 | 390 | 1.063 | 1.213 | 1.142 | `p41_final` |
| 13 | 121 | 129 | 1.065 | 1.230 | 1.155 | `p41_final` |
| 12 | 78.6 | 83.9 | 1.066 | 1.250 | 1.165 | `p41_final` |

The absolute times move by up to 40% between jobs (the laptop's speed states). Only the per-rep ratios compare.
At 2^12-2^14 the fixed cost of the fused stage is a larger share, so the ratio there is 1.06-1.07x. The target
(2^16) is met. The old CI NTT measures 1.19-1.20x std here, the "1.19x" in the plan.

**Bootstrap A/B** (CI {5,3}, 2^16, 128-bit, 1 thread, reps 3, CtS-first, one binary, `CI_NTT_OLD` 0/1, 6-mult
inverse version). The laptop changed speed state during both jobs: `ptMult` has no NTT inside, yet it moved by up
to 38% between passes. So the warm times below compare only within passes with equal `ptMult`. Sums of the `[LT]`
classes over the 4 reps of each pass:

| job / pass | NTT | warm median s | LT total | modUp | modDown | ptMult | modUp / ptMult | modDown / ptMult |
|---|---|---|---|---|---|---|---|---|
| `p41_ab16` 1 | new | 14.57 | 39.21 | 5.54 | 3.65 | 13.22 | 0.419 | 0.276 |
| `p41_ab16` 2 | old | 12.29 | 31.21 | 4.85 | 3.11 | 10.09 | 0.481 | 0.308 |
| `p41_ab16` 3 | old | 11.85 | 29.73 | 4.45 | 2.92 | 9.68 | 0.460 | 0.302 |
| `p41_ab16` 4 | new | 13.34 | 33.04 | 4.84 | 3.23 | 11.09 | 0.436 | 0.291 |
| `p41_ab16b` 1 | new | 15.27 | 39.29 | 5.48 | 3.64 | 13.35 | 0.410 | 0.273 |
| `p41_ab16b` 2 | old | 11.83 | 36.17 | 5.44 | 3.55 | 11.88 | 0.458 | 0.299 |
| `p41_ab16b` 3 | **new** | **11.59** | 29.95 | 4.35 | 2.82 | **9.72** | 0.448 | 0.290 |
| `p41_ab16b` 4 | **old** | **11.82** | 30.17 | 4.65 | 3.00 | **9.70** | 0.479 | 0.309 |
| `p41_ab16b` 5 | new | 13.80 | 35.31 | 4.94 | 3.29 | 11.79 | 0.419 | 0.279 |
| `p41_ab16b` 6 | old | 16.35 | 40.57 | 6.14 | 4.07 | 13.39 | 0.459 | 0.304 |

(LT sums include the first bootstrap of each pass; the warm median excludes it, so the two can disagree, e.g.
`p41_ab16b` pass 2.)

- In the calm pair (`p41_ab16b` passes 3-4, `ptMult` 9.72 vs 9.70 s) the bootstrap goes from 11.82 to 11.59 s
  (-2.0%). ModUp goes from 4.65 to 4.35 s (-6.5%) and ModDown from 3.00 to 2.82 s (-6.0%).
- Normalized by `ptMult` in all 10 passes, ModUp is 0.410-0.448 (new) against 0.458-0.481 (old), -9%, and
  ModDown is 0.273-0.291 against 0.299-0.309, -8%. Item 2.1 attributed "~10% of ModUp/ModDown" to the CI NTT,
  and most of that is now gone.
- Precision is unchanged: RMS 21.55-21.57 bits in every pass. The Galois check held in all passes. Peak RSS is
  13.43 GB (new) against 13.60 GB (old).
- The final 5-multiplication inverse saves about 1.3% more NTT time. No bootstrap A/B was run for it, because the
  effect is below this laptop's noise.

**Correctness of the final code** (`p41_final`):

| N, budget | CtS-first (corr 4) RMS / min bits | StC-first (corr 12) RMS / min bits |
|---|---|---|
| 2^12 {1,1} (dense) | 18.80 / 17.18 | 22.68 / 21.26 |
| 2^12 {3,3} | 18.80 / 17.18 | 22.68 / 21.28 |
| 2^13 {4,4} | 19.71 / 18.03 | 22.67 / 21.09 |
| 2^14 {5,3} | 20.71 / 18.89 | 22.48 / 20.47 |
| 2^16 {5,3}, 128-bit, reps 1 | 21.56 / 18.67 (11.70 s) | 21.91 / 19.82 (11.02 s) |

These match the old NTT (`p41_smoke`, same matrix, CI_NTT_OLD=1: identical RMS, min within the seed spread). At
2^16 they also match the 2.R / 2.5 numbers (21.56-21.57 / 21.91-21.92). Both orderings run. At 2^16 the Galois
check held and no diagonal was encoded at run time.

**Conclusions.**
- Done: the CI NTT round trip is 1.04-1.05x the standard NTT at 2^16 (two runs of the final code), down from 1.19-1.20x.
  It is bit-exact against the reference at all N and prime widths. In the bootstrap, ModUp/ModDown drop by about 8% and the
  whole bootstrap by about 2% (one calm pair; the other passes are within the laptop's speed states).
- The rest of the CI NTT overhead is about N + N/4 multiplications per round trip for the fold/unfold.
  The forward side is at its minimum for this factorization: each output pair needs a separate r^2 product.
- std arithmetic did not change. Its NTT kernels were only split into helpers. The std NTT timing in the check is
  the same code before and after, but no separate std before/after run was made.
- The baseline commands do not change. CI baseline times should drop by about 2% at the next phase review.
