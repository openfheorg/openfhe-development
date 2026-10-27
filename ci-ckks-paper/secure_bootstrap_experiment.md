# Secure (128-bit) single-bootstrap: CI vs standard CKKS — brief report

**Setup (common):** FIXEDMANUAL (CI) / FLEXIBLEAUTO (std), level budget **{3,3}**, firstModSize=60,
scaleModSize=53, input = uniform reals in **[-1,1]**, encrypted at the most-depleted level (L−1, 2
towers), **no homomorphic ops**, then one `EvalBootstrap`. Latency is **end-to-end, excluding
context setup + key generation**; runs multi-threaded (`OMP_NUM_THREADS=4`, 23 GB cap to protect the
machine). Harness: `benchmark/src/ci-vs-std-secure-boot.cpp`.

**How precision is computed:** `precision_bits = −log2( maxᵢ | Re(decode(Dec(Boot(ct))))[i] − x[i] | )`
over all real slots — i.e. −log2 of the **worst-case absolute slot error** vs the input vector `x∈[-1,1]`.

## The headline constraint

A **128-bit-secure CI bootstrap at logN=16 cannot be run** here, for two independent reasons:
1. **Memory:** the CI collapsed transform materializes its stage matrices *densely* (O(N²)); at N=2¹⁶,
   {3,3}/{4,4} needs **~140–275 GB** (this machine: 16 GB free). (The "FFT-accelerated CI encode /
   sparse-diagonal" gap.)
2. **Secret support:** the CI bootstrap currently accepts **UNIFORM_TERNARY only** (SPARSE throws).

So the secure (logN=16, 128-bit) numbers below are **std only**; CI is shown at the largest feasible
ring (logN=12, **not** 128-bit) for an indicative same-ring comparison.

## Results

### A. Secure target — logN=16, N=2¹⁶, 128-bit (HEStd_128_classic), std CKKS only

| scheme · secret | slots | log2(QP) | multDepth | bootstrap levels (ModRaise / CtS / EvalMod / StC) | latency (1 boot) | throughput | precision |
|---|---|---|---|---|---|---|---|
| std · UNIFORM | 32768 (N/2) | 1226 | 22 | 0 / 3 / **14** / 3 | **17.85 s** | 545 µs/slot | **3.44 b** |
| std · SPARSE  | 32768 (N/2) | 1014 | 18 | 0 / 3 / **10** / 3 | **11.30 s** | 345 µs/slot | **11.71 b** |

*(ModRaise/ModUp lifts to the top modulus — 0 usable levels spent. CI · UNIFORM and CI · SPARSE: not
runnable at this ring — see constraint above.)*

### B. Indicative same-ring — logN=12, N=4096, **not 128-bit** (HEStd_NotSet), UNIFORM

| scheme | slots | log2(QP) | multDepth | latency (1 boot) | throughput | precision |
|---|---|---|---|---|---|---|
| **CI**  | 4096 (N)   | 1226 | 22 | **3.34 s** | 816 µs/slot | 5.56 b |
| std     | 2048 (N/2) | 1226 | 22 | **0.55 s** | 270 µs/slot | 8.83 b |

## Observations (brief)

- **Secret distribution matters more than expected (std, 2¹⁶):** SPARSE is both **faster (11.3 vs
  17.9 s)** and **more precise (11.7 vs 3.4 bits)** than UNIFORM — its EvalMod is shallower (10 vs 14
  levels, smaller overflow K=28 vs 512), dropping multDepth 22→18 and freeing modulus for precision.
- **Precision is low for *both* at 2¹⁶/128-bit** because the secure ceiling forces scaleMod≤53 (and
  `firstMod−scaleMod ≤ correctionFactor≈7`), so each limb carries few bits. A *good*-precision 128-bit
  bootstrap is essentially a **2¹⁷** computation (scaleMod=59); that was excluded per request.
- **Same-ring (2¹², insecure):** CI packs **2× the real slots** (4096 vs 2048) but is **~6× slower**
  (3.34 vs 0.55 s) and lower precision; per-slot throughput favors std ~3×. CI's cost is the dense
  diagonal build + the two-channel collapsed transform; std uses the optimized hoisted FFT.
- **Bootstrap level usage** (logN/N-independent, set by budget+secret): {3,3} ⇒ CtS=3, StC=3;
  EvalMod=14 (UNIFORM) or 10 (SPARSE); ModRaise spends 0 usable levels.

## Bottom line

At the requested **128-bit / logN=16** target, only **std** is runnable: **SPARSE ≈ 11.3 s / 11.7 bits**,
**UNIFORM ≈ 17.9 s / 3.4 bits** over 32768 real slots. **CI is blocked at this ring** (dense-diagonal
memory + UNIFORM-only); at a feasible smaller ring it trades 2× packing for ~6× higher latency. The
uniformly-low precision is the 2¹⁶-modulus squeeze (affects std too), separate from the deferred CI
coefficient-recovery issue.
