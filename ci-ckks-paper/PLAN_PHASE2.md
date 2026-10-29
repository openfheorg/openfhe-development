# Phase 2 plan: close the remaining gaps of the native CI-CKKS real-FFT bootstrap

Branch: `ci-ckks-fft-v1.6.1` (continue on it). Scope excludes the paper's functional bootstrapping.
Progress is tracked by the checkboxes below; the harness ticks `[x]` when an item is done and appends its
results to `ci-ckks-paper/PHASE2_LOG.md`. `[~]` marks an item deferred with a stated reason.

## Execution rules (apply to every item)
**Run host is switchable (user, 2026-10-28).** The active host is the one word in the WSL file
`/home/caesar/ci-ckks-host`: `ICELAKE` or `WSL`. Executors read it before every job and start the job there; the user
may change it at any time. Items 0.1-2.3 ran on ICELAKE, 2.4-2.R on WSL; from 3.1 on, per the host file (ICELAKE on
2026-10-28). The WSL rules below apply when the host is WSL; the ICELAKE rules (kept at the end of this section) apply
when it is ICELAKE, with screening runs allowed concurrently there (at most 3 at 2^16, peaks under 50 GB). Numbers from
different hosts are never compared: every A/B runs in one job on one host, and an item re-measures the baseline on its
host when the last baseline for that host is older than the code.
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
  `-DCMAKE_CXX_FLAGS=-DBOOTSTRAPTIMING`, for stage times; since item 6.2 also CI's, `CI_BOOT_TIMING` is gone). Build only the needed targets, `-j 8`, `MEM_GB` 12. Leave
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
- *ICELAKE rules (when the host file says ICELAKE):* builds and runs on ICELAKE (`ssh -o BatchMode=yes
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
Phase 2 review (2.R) reference (`p2R_base`, WSL, HEAD after item 2.5, same settings, one interleaved job, reps 3):
CI {5,3} 11.99 s vs std {5,3} 11.63 s CtS-first (1.94x); CI 11.62 s vs std 8.43 s StC-first (corr 12 / 13; 1.45x);
stage ratios CtS 1.44x, StC 1.51x, EvalMod 0.65x. The clock varies by up to ~27% from session to session (this job
took 27% less time than the 2.4 baseline above), so later items compare only within one interleaved job.

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
Linear transforms (item 2.1): `CI_BOOT_TIMING=1` (since 6.2: `-DBOOTSTRAPTIMING -DBOOTSTRAPTIMING_LT`) also prints one `[LT]` line per BSGS level for CI and std (diagonals,
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
Sparse key (item 3.1, ICELAKE): a weight-16 CI ephemeral key (needed for std's K = 16 sine table) is below 128 bits
(n = 65536, log q0 P' = 126: MITM on the secret 2^116, primal drop-and-solve 129.8 bits;
`tools/ci-sparse-security.py`, a subset of the lattice-estimator's attacks; the estimator itself could not be
installed), so CI keeps weight 32 (213 bits) and the K = 28 table (about 1.0 s of EvalMod, item 0.5).
META-BTS (item 3.2): `EvalBootstrap(ct, 2, metaprec)` works for CI in both orderings (the iteration path no longer
rescales the CI result twice). 2^16 {5,3}, 128-bit (needs dnum 4 for the extra level): CI 40.2-40.4 bits RMS / 37.0-37.3
min at 2.13-2.18x the one-iteration time (ICELAKE: CtS-first 48.2 vs 22.1 s), std CtS-first 41.0 / 38.0; std
StC-first stops at ~31 bits (a floor of OpenFHE's std StC-first path, independent of metaprec). Driver args 15
`iters`, 16 `metaprec` (0 = floor of one bootstrap's min bits; ~3 bits lower is better).
EvalMod per real slot (item 3.3, WSL, `tools/evalmod-per-slot.py LOG`): CI 60-61 us (one call, 65536 reals, both
orderings), std CtS-first 188-193 us (two calls), std StC-first 91-94 us (one call, 32768 reals); CI / std 0.31-0.33x
vs CtS-first, 0.64-0.66x vs StC-first; per call CI / std 1.24-1.33x (K = 28 table ~1.15x, CI ring ~1.10x). The 4.R
target 0.55x is met against std CtS-first only; against std StC-first the K = 28 floor is about 0.57x.
Phase 3 review (item 3.R, WSL, precision only): the K = 28 table costs no precision (K = 16 vs 28 swap: RMS within
0.02 bits, CI and std, both orderings, 2^15 59/60); CI keeps degree 48 because a weight-16 CI key is insecure (3.1).
Per-op noise of CI at N equals std at 2N (`ci-noise-probe`, within 0.1 bit; 1.0 bit worse than std at the same N), so
the paper's equal-reals comparison has no ring-noise gap. Gap to the paper's 20.55 bits (max error, StC-first):
CI 2^16 19.69-19.85 (-0.70 to -0.86) = ~0.4 bits CI-specific (CI vs std at equal reals, 2^14/2^15 and 2^15/2^16;
source open) + ~0.3-0.45 bits OpenFHE-vs-Lattigo design shared with std (std 2^17 OOM on WSL, inferred); CtS-first
loses another 1.2-1.6 bits (ordering); META-BTS closes it (37 bits min).
CI NTT (item 4.1, WSL): the CI transform is the NTT modulo X^N - wm^N of the fold g_i = a_i - wm^N a_{N-i}, with the fold
fused into the first CT stage and the unfold + 1/N into the last GS stage (raw-word members of
`NumberTheoreticTransformNat`; same output order, bit-exact vs the reference). Round trip 1.04-1.05x std at 2^16 (was
1.19-1.20x; `ci-ntt-check`, per-rep interleaved); ModUp/ModDown -8%, CI bootstrap about -2% (calm pair 11.82 -> 11.59 s),
precision unchanged, peak RSS -0.17 GB. Baseline commands unchanged.
Per-op cost (item 4.2, WSL, `ci-op-cost`, 2^16, 21/11/4 towers, calibrated per iteration against a std NTT): CI/std
is 1.02-1.06x for mult, relin, rescale, rotate, ModUp, KeySwitchDown and 0.97-1.08x for the NTT-free ops; nothing above
1.1x, no fix needed. The CI/std stage ratios come from op counts, not per-op cost. Baseline commands unchanged.
Phase 4 review (4.R, WSL, `p4R_em16`, calm pair at HEAD after 4.2): CI {5,3} 11.37 s vs std 11.27 s CtS-first
(1.98x; CtS 1.46x, EvalMod 0.61x, StC 1.48x), CI StC-first 10.94 s; RMS unchanged. CI EvalMod per real slot 0.31x
std CtS-first (criterion met); 0.61x std StC-first (per call 1.23x, was 1.30x; K = 28 floor 0.57x, item 3.1).
Threads (item 5.1, WSL): CI and std both get about 2x at 4 threads (best CI 2.07x, std 2.19x; CI/2xstd 1.89x vs
2.01x at 1 thread). Above 4 threads the WSL VM gives no usable number (14-CPU slice quota, hybrid laptop, 2-4x run
spread; best 16-thread CI 2.20x / std 2.43x, in-process sweeps the reverse), so 5.R needs a stable 16-core host or a
narrower thread range. Driver env `CI_THREAD_SWEEP=1,4,8,16` (`CI_SWEEP_ROUNDS`) times one process at several
thread counts; `tools/thread-scaling.py LOG` tabulates.
Parallel CI BSGS (item 5.2, WSL): the CI sparse BSGS ran its baby rotations and plaintext products serially (std's
runs its baby rotations in parallel), so CI scaled worse at 4 threads (calm rounds: 1.98x vs std 2.13x; StC 1.68x vs
2.02x). Baby rotations now run in an `omp parallel for` and each giant block sums its products in per-thread partial
sums (extended basis, reduced once per block); 1 thread runs the old code. CI at 4 threads 6.10 -> 5.18 s (2.35x;
CtS 2.32x, StC 2.26x), CI/2xstd 2.14x at 4 threads vs 1.98x at 1 thread; precision unchanged. Baseline commands unchanged.
Phase 5 review (5.R, WSL, `p5R_sweep`/`p5R_sweep2`, HEAD after 5.2, in-process 1/4/14/16-thread sweeps): best times
CI 11.46 -> 3.85 s (2.98x) and std 11.86 -> 4.57 s (2.60x) at 16 threads, so CI/2xstd 2.07x at 1 thread -> 2.37x at 16
(calm-round medians: CI 2.97x, std 2.24x); before 5.2 CI was 9% behind std (5.1). Criterion met on calm-state estimates;
WSL throttles 16 threads at its 14-CPU quota and single-job medians swing either way, so 5.1-ICE (on hold) would confirm.
Baseline commands unchanged.
Item 6.1 (WSL): the ring type is now a property of the element parameters (`ElemParams::GetRingType()`, set at CI
context generation and copied into every derived parameter set; `PolyImpl::SwitchFormat` dispatches on it); the CI
table cache is keyed by (q, N) and fills itself on first use. A CI and a std context sharing primes work in one process
(`benchmark/src/ci-ring-conflict.cpp`). Precision unchanged; 2^16 CI time unchanged (11.353 vs 11.352 s in the
same-speed pair). Baseline commands unchanged.
Item 6.2 (WSL): `CI_BOOT_TIMING`, `CI_BSGS_RATIO`, `CI_SPLIT_ENC` / `CI_SPLIT_DEC`, the library `std::cerr` prints and
the `g_CIDbg*` debug globals are gone. CI stage times (`[CI-BT] CtS / EvalMod / StC`) now need a `-DBOOTSTRAPTIMING`
build (`build-wsl-bt`, ICELAKE `build-bt`), as std's; `-DBOOTSTRAPTIMING_LT` adds the per-level `[LT]` counters and
BSGS plans (serial only). Precision unchanged. The baseline commands below now run CI from `build-wsl-bt` too.
Item 6.3 (WSL): `EvalBootstrapKeyMapIndices` is CI-aware (same Galois set as `EvalBootstrapKeyGen`, through the shared
`FindCIBootstrapGaloisElements`; no conjugation key; sparse encapsulation keys M-4, M-2), so `SerializeEvalBootstrapKey`
/ `DeserializeEvalBootstrapKey` work for CI. Serialization test: `benchmark/src/ci-boot-serial.cpp` (save / load in
separate processes, `ci-ckks-paper/tools/serial-matrix.sh`) and unit tests `CIBootstrapKeySerialization_*`. Keygen
unchanged (2^16 {5,3}: 102 keys, RMS 21.56 / 21.91). Baseline commands unchanged.
Driver `benchmark/src/ci-fft-boot.cpp` (args: scheme logN lbEnc lbDec scaleMod firstMod secure reps scaling corr secret [stcfirst] [dnum] [after] [iters] [metaprec]; the RESULT line also has `bootsetup_s`, EvalBootstrapSetup alone, since item 2.4). Baseline commands (run at every phase review; on WSL inside one `wsl-guard.sh` job, MEM_GB 15, CI and std interleaved):

    # since item 6.2 both schemes' stage times come from the -DBOOTSTRAPTIMING build (build-wsl-bt; ICELAKE build-bt):
    # CI "[CI-BT] CtS / EvalMod / StC", std "Encoding / Approximate modular reduction / Decoding time"
    OMP_NUM_THREADS=1 build-wsl-bt/bin/benchmark/ci-fft-boot ci  16 5 3 59 60 1 3 fa 4 encap
    OMP_NUM_THREADS=1 build-wsl-bt/bin/benchmark/ci-fft-boot std 16 5 3 59 60 1 3 fa 5 encap
    # equal-budget reference for per-stage ratios:
    OMP_NUM_THREADS=1 build-wsl-bt/bin/benchmark/ci-fft-boot ci  16 4 4 59 60 1 3 fa 4 encap
    OMP_NUM_THREADS=1 build-wsl-bt/bin/benchmark/ci-fft-boot std 16 4 4 59 60 1 3 fa 5 encap
    # StC-first pair (item 2.5; std StC-first is std's fastest real-data bootstrap):
    OMP_NUM_THREADS=1 build-wsl-bt/bin/benchmark/ci-fft-boot ci  16 5 3 59 60 1 3 fa 12 encap 1
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
- [x] **2.R** Phase 2 review. Done when: (1) at the same N, CI CtS <= 1.5x std CtS and CI StC <= 1.5x std StC (or
  the excess is accounted for by the diagonal count); (2) the StC-first ordering pays for CI StC: at 2^16 {5,3},
  StC-first CI StC is below CtS-first CI StC at every measured chain (2, 3 and 5 levels after the bootstrap) with
  the gain growing with the levels after, and per diagonal (StC time / plaintext mults from the `[LT]` lines)
  StC-first CI StC costs no more than std's CtS-first StC; (3) both CI orderings build, run and give the expected
  precision (below). Attempt 2 reuses the attempt-1 runs (`p2R_base`, `p2R_after3b`, `p2R_after5`, `p2R_smoke`; no
  code changed): no new job unless a rerun is needed by the rules.
  *Revised 2026-10-28 (plan adapter, after attempt 1).* The original criterion 2, "StC-first CI StC below std's
  CtS-first StC", compares 317 CI diagonals with 189 std ones at a chain where std's CtS-first StC already runs at
  6..4 Q towers (2 levels after), so it tests the real factorization's diagonal count, not the ordering. Measured
  ratio 1.37x / 1.27x / 1.03x at 2 / 3 / 5 levels after; the crossover is at about 6 levels after, which at 2^16
  needs a 17-18 GB CI job (over the practical cap). Open, not a phase 2 lever: fewer CI StC diagonals (a different
  factorization) or the >= 6-levels-after measurement when memory allows; recorded in the log.
  **Both CI orderings must stay supported** (user, 2026-10-28): CtS-first (default) and StC-first
  (`BTSlotsEncoding`); StC-first is the base for CI functional bootstrapping later. No item may remove or
  disable either path; the review checks that both build, run and give the expected precision.

## Phase 3: EvalMod and sparse encapsulation (gap 2, a cost item)
- [x] **3.1** CI ephemeral sparse key with weight 16 in the CI basis (L1 norm ~32 in the power basis) and the
  K = 16 (degree 36) sine table, like std. Run the lattice estimator on ICELAKE for (N = 65536, log q ~ 126,
  ternary weight 16) and record the security level; if below 128 bits, keep weight 32 and record why.
- [x] **3.2** META-BTS (`numIterations = 2`) for CI and std at 2^16: check that the CI branch works with the
  iteration wrapper; compare precision and time with the paper's 20.5 bits.
- [x] **3.3** Log CI and std EvalMod time per real slot side by side.
- [x] **3.R** Phase 3 review. Done when: CI EvalMod degree equals std's for the same secret distribution (or the
  security reason it cannot is recorded), and the precision gap to the paper is explained or closed.

## Phase 4: CI ring overhead (gap 3)
- [x] **4.1** Raw-word Shoup twist loops for the CI NTT (move the twisted NTT next to
  `NumberTheoreticTransformNat` for word access). Target: CI NTT round trip within 1.05x of the standard NTT
  (now 1.19x at 2^16); validate with `benchmark/src/ci-ntt-check.cpp` (bit-exact vs reference).
- [x] **4.2** Measure CI vs std per-op cost (EvalMult, rotation, rescale) at 2^16; fix anything above 1.1x.
- [x] **4.R** Phase 4 review. Done when: CI EvalMod time per real slot <= 0.55x std's.

## Phase 5: multi-thread scaling
- [x] **5.1** Measure 1/4/8/16 threads for CI and std at 2^16.
  - [ ] **5.1-ICE** (ON HOLD, user 2026-10-28: rerun 5.1 on ICELAKE later; not in the harness queue; no executor or
    plan adapter may run or schedule it, and it does not block 5.2 or 5.R.) On WSL only 1-4 threads gave usable numbers
    (both schemes ~2x at 4 threads; 8-16 threads varied 2-4x between runs, see `PHASE2_LOG.md` 5.1). Rerun the same
    measurement on ICELAKE (16 free physical cores, stable clocks): 1/4/8/16 threads, CI and std, 2^16 {5,3}, both
    orderings, using the `CI_THREAD_SWEEP` driver option and `tools/thread-scaling.py`; then re-evaluate 5.2 and 5.R.
- [x] **5.2** If CI scales worse: parallelize the sparse BSGS baby-step accumulation (per-thread partial sums in
  the extended basis, reduce once per giant block).
- [x] **5.R** Phase 5 review. Done when: CI/std speedup at 16 threads is within 10% of the single-thread one.

## Phase 6: engineering (last)
- [x] **6.1** Ring type as a property of the element parameters (or a (modulus, N)-keyed registry) instead of the
  global modulus-keyed registry; a CI and a std context sharing a prime in one process must not conflict.
- [x] **6.2** Remove env switches (`CI_BSGS_RATIO`, `CI_BOOT_TIMING`), `std::cerr` prints and `g_CIDbg*` debug
  globals from library code; expose timing through `BOOTSTRAPTIMING`.
- [x] **6.3** `EvalBootstrapKeyMapIndices` CI-aware; CI context and bootstrap-key serialization test.
- [ ] **6.4** Unit tests: StC-first CI (required: both orderings, at two budgets), CtS-first CI, encapsulated CI at two budgets, keygen/evaluator key-set
  equality, CI + `BTSlotsEncoding` guard; move the mid-file `#include` in `UnitTestCKKSrnsCI.cpp` to the top;
  clang-format the touched files.
- [ ] **6.5** Final run on the active host (host file; ICELAKE only if the user set it): `pke_tests`, `core_tests`, `binfhe_tests`; final benchmark table (1 and 16
  threads) in `CI_FFT_REVIEW.md`; remove the `openfhe-ci2026-orig` worktree (WSL) and stale ICELAKE build dirs
  other than `build`.

## Phase 7: StC-first optimization (ON HOLD: record only)
**Do not start any item of this phase until the user says so.** It is not in the harness queue. An executor or plan
adapter must not run, schedule, merge or reword these items into earlier phases. Recorded 2026-10-28 from the
StC-first analysis below.

*Where StC-first stands* (WSL, 2^16 {5,3}, 128-bit, 1 thread, item 2.R): CI 11.62 s (CtS 5.35 / EvalMod 3.95 /
StC 2.32) against two std StC-first bootstraps 2 x 8.43 = 16.86 s (CtS 3.59 / EvalMod 3.06 / StC 1.53 each):
**1.45x** (2x is the ceiling). Per stage, one CI against one std: CtS 1.49x (137 vs 75 diagonals, 1.83x), StC 1.52x
(317 vs 189 diagonals, 1.68x), EvalMod 1.29x per call (K = 28 table about 13%, CI ring per-op cost about 10%,
partly removed by item 4.1). Per diagonal CI already matches std (same-shape levels 1.00-1.05x), so the linear
transform gap is the real-FFT diagonal count. Estimate: 7.1-7.3 together bring CI StC-first to about 1.6-1.7x; going
toward 2x needs 7.4.

- [ ] **7.1** Re-tune the linear transforms for StC-first. The budget sweep (1.3), the per-level BSGS split (2.2)
  and the layer split (2.3) were tuned for CtS-first. In StC-first, StC runs at the bottom of the chain on the
  minimum tower count (independent of the levels after), so a deeper StC (more levels, fewer diagonals per level)
  is cheap there, and the best CtS split also changes with the shorter chain. Sweep budgets for StC-first for CI
  and std (both at their own best), redo the BSGS and layer-split cost models with the StC-first tower counts.
  Expected: the largest single gain of this phase. Done when: best StC-first budget and splits for each scheme are
  found and the CI/2xstd StC-first ratio is reported at those settings.
- [ ] **7.2** Smaller EvalMod table for CI with a secure key. A weight-24 CI ephemeral key (power-basis L1 about
  48; item 3.1: 141.5 core-SVP and 166.8 MITM by the item's own estimates) with a new Chebyshev table for K about 20
  (degree between 36 and 48). Needs: the official lattice-estimator run to certify 128 bits, a failure-probability
  check of the overflow bound (K = 16 with weight 32 fails about 2^-22 per bootstrap, item 3.R, so it is not an
  option), and the precision check. Expected: up to about half of the ~1 s the K = 28 table costs.
- [ ] **7.3** Remaining CI per-op overhead (after items 4.1-4.2): any CI op still above about 1.05x std per op
  (EvalMult, rotation, rescale, ModUp/ModDown) in the StC-first bootstrap path. Expected: small (item 4.1 took the
  NTT round trip from 1.19x to 1.04-1.05x).
- [ ] **7.4** Fewer diagonals in the real FFT (research). The paper's real FFT has up to 7 cyclic diagonals per layer
  against about 3 for the complex FFT, which gives CI 1.7-1.8x std's diagonals per transform. Look for a
  factorization or level grouping with fewer diagonals (other butterfly arrangements, merging the phase
  compensation differently, radix choice, sharing diagonals between levels). This is the only lever that moves
  CI StC-first toward 2x. Done when: a factorization with fewer diagonals is found and measured, or the reason the
  count is a lower bound is written down.
- [ ] **7.R** Phase 7 review: CI/2xstd StC-first ratio at the best settings of both schemes, precision of both
  orderings, both orderings still supported.
