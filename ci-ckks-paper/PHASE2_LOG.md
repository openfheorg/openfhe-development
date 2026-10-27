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
