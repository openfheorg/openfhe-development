# Building OpenFHE for Best Performance

The default build configuration of OpenFHE favors portability and ease of installation, and its runtime performance is often well below what the same machine can deliver. This document lists the build options, compiler and runtime settings that close that gap, and the operating points where adding more hardware stops helping.

## Build configuration

Three CMake options and the choice of compiler have the largest effect.

* `WITH_NATIVEOPT` (default `OFF`) enables machine-specific code generation (`-march=native`). Turn it on whenever the binary runs on the machine that builds it. It is the single most valuable setting: the vectorized number-theoretic transforms and digit decompositions only reach their full width with it, and on a 36-core Xeon CKKS bootstrapping runs 1.5 to 2 times faster with it than without. Binaries built with it are not portable to other processor generations.
* `NATIVE_SIZE` (default `64`) is the word size of a native integers. With 64-bit words the moduli are limited to 60 bits, which every scheme works within by default. 128-bit words raise the limit to 121 bits and make every arithmetic operation slower. High-precision CKKS is not a reason to choose them: scaling factors above 60 bits are reached in a 64-bit build with the `COMPOSITESCALINGAUTO` and `COMPOSITESCALINGMANUAL` scaling techniques, several times faster than the same computation on 128-bit words. Choose 128 only for a configuration whose moduli must exceed 60 bits. `32` caps moduli at 28 bits and disables 128-bit intermediate arithmetic; it is a portability option for constrained targets, not a performance one.
* `WITH_OPENMP` (default `ON`) enables OpenMP multithreading. All threads are available by default; `OMP_NUM_THREADS` limits them. See "Multithreading" below for how many are useful.

**Compiler.** OpenFHE requires GNU C++ 9 or clang 10 at minimum; performance favors recent releases of either. On a 36-core Ice Lake Xeon, clang 18 runs the BGV, BFV and CKKS operations 25 to 35% faster than GCC 14 on one thread, and it scales better with thread count because LLVM's OpenMP runtime changes the size of its thread team far more cheaply than libgomp does. For `binfhe` the two compilers are within about 10% of each other. Older GCC releases fall further behind: on an 8-core i7-9700 desktop, GCC 11 is 20 to 35% slower than clang 15 on `binfhe` gates and 5 to 17% slower on CKKS bootstrapping. A recent clang is the recommendation where the choice exists; GCC 12 or later is a sound alternative.

A configuration that applies all of the above for a build that stays on one machine:

```
cmake -DWITH_NATIVEOPT=ON -DCMAKE_C_COMPILER=clang-18 -DCMAKE_CXX_COMPILER=clang++-18 ..
```

## FHEW and TFHE (the `binfhe` module)

The `binfhe` module runs its bootstrapping keys and the blind rotation and key switching that consume them on 32-bit words inside a 64-bit build, whenever the parameters allow it. A refresh key takes the 32-bit form when its bootstrapping modulus fits the 32-bit accumulator's headroom, a switching key when its key-switching modulus fits the same 28-bit bound; the two decisions are independent, and a key whose moduli do not fit is generated at the native width. All predefined parameter sets qualify with the exception of `LPF_STD256Q_4_AP`, whose 51-bit bootstrapping modulus keeps its refresh key at 64 bits while its switching key still converts. The conversion is automatic: `BTKeyGen` generates the keys directly in the narrow form (its `internal32` argument, `true` by default, turns this off), gate outputs are identical to the 64-bit computation, and resident key material is roughly halved.

This is faster than a `NATIVE_SIZE=32` build, because a 64-bit build keeps the 128-bit intermediate arithmetic that lets the inner products accumulate lazily and reduce once per output coefficient, which a 32-bit build cannot do. The recommended build for `binfhe` is therefore the default word size with machine-specific optimizations and a recent compiler, as in the command above. Custom parameter sets benefit from the same path when the bootstrapping modulus and the key-switching modulus are both at most 2^28.

### Bootstrapping method and thread count

The two bootstrapping methods are GINX, the OpenFHE implementation of the TFHE (CGGI) scheme, and LMKCDEY, an optimized variant of the FHEW (DM) scheme. They differ in how they respond to threads. Boolean gate latency for the default 128-bit parameter sets, as measured by the [`binfhe-paramsets`](../../benchmark/src/binfhe-paramsets.cpp) benchmark (two-input OR gate):

| method | Xeon, 1 thread | Xeon, 8 threads | Xeon, 36 threads | i7, 1 thread | i7, 8 threads | i7 turbo, 1 thread | i7 turbo, 8 threads |
|---|---|---|---|---|---|---|---|
| GINX (`STD128`) | 29 ms | 17 ms | 17 ms | 29 ms | 17 ms | 20 ms | 12 ms |
| LMKCDEY (`STD128_LMKCDEY`) | 28 ms | 22 ms | 22 ms | 29 ms | 21 ms | 19 ms | 15 ms |

This table and every measurement in this document come from two machines, both built with `WITH_NATIVEOPT=ON`: a two-socket Intel Xeon Platinum 8360Y (Ice Lake, 36 cores per socket, no SMT, 128 GB of memory) with clang 18, and an 8-core Intel Core i7-9700 desktop (64 GB) running Ubuntu with clang 15. Both hold every core at its base clock with turbo disabled, 2.4 GHz on the Xeon and 3.0 GHz on the i7, which makes the numbers repeatable from run to run; at these clocks the two machines are within about 10% of each other on one thread. A desktop or laptop at its turbo clock is correspondingly faster: with turbo enabled the same i7 runs one core at 4.7 GHz and takes about two thirds of the time on one thread, while at 8 threads its all-core clock settles near 3.8 to 4.2 GHz under load and the gain is 10 to 30%.

Use GINX when gates run multithreaded: from 8 threads on, it is 10 to 30% faster than LMKCDEY on every predefined set. Single-threaded, the two are within about 10% of each other on both machines, and which one leads depends on the set, so either serves. A single gate does not benefit from more than about 8 threads under any method, because the blind rotation parallelizes over the gadget digits of one ciphertext and there are only a handful of those; running many gates concurrently at the application level is the way to use a larger machine, with `OMP_NUM_THREADS` kept small so the per-gate teams do not oversubscribe the cores. Setting `OMP_NUM_THREADS=1` gives the same runtimes as a build with `WITH_OPENMP=OFF`.

## BGV, BFV and CKKS (the `pke` module)

The default configuration is within a modest factor of the best one for these schemes; `WITH_NATIVEOPT=ON` and the compiler choice above account for most of the difference. Beyond the build, the parameters and API patterns below decide how much work each operation does and how many threads it can use.

**Limbs set the parallel width.** Double-CRT operations parallelize over the RNS limbs of a polynomial, and the number of limbs is set by the multiplicative depth. A shallow context therefore has little for extra threads to do. Measured at ring dimension 2^14 with clang 18 on the Xeon, `EvalMult` runs 1.9 times faster on 8 threads than on one with 3 limbs, 2.6 times with 4 limbs and 3.3 times with 7 limbs, and 36 threads add nothing over 8 at this ring size. The limb count also sets the cost of every operation, since each limb needs its own NTT whenever a polynomial changes representation. For a given depth, wider limbs mean fewer of them: a scaling modulus close to the 60-bit ceiling of a 64-bit build reaches the same depth with fewer limbs, and therefore fewer NTTs, than a smaller one. Set the multiplicative depth to what the circuit needs and no more: every extra level is an extra limb in every operation that follows.

**Key switching.** A ciphertext multiplication ends with a relinearization and a rotation with an automorphism; both are key switches, and the key switch is the dominant cost of each operation. BGV and CKKS default to the `HYBRID` technique, BFV to `BV`. `HYBRID` splits the modulus into `numLargeDigits` digits (0, the default, uses 3 digits when the depth exceeds 3 and 2 otherwise): fewer digits mean fewer basis conversions per switch and less key material, at the price of a larger auxiliary modulus. `BV` decomposes into digits of `digitSize` bits, and the default of 0 uses one digit per limb, which is the fastest BV setting; smaller digits lower the noise added by a switch but multiply its work in proportion. At ring dimension 2^14 and depth 2 on one thread, BV with 10-bit digits costs 1.4 times HYBRID on multiplication and 2.2 times on rotation. Keep `numLargeDigits` as small as the security bound allows, and raise it only when a deep context fails that bound, since fewer digits enlarge the auxiliary modulus. Under `BV`, keep `digitSize` at 0 unless the noise budget requires smaller digits.

**Rotating one ciphertext several times.** When one ciphertext is rotated by several indices, call `EvalFastRotationPrecompute` once and `EvalFastRotation` for each index. The digit decomposition is the expensive half of a rotation and depends only on the ciphertext, not on the index, so the precomputation does it once for all of them; the library's own linear transforms and sums are built this way.

**API patterns that avoid work.**

* Multiply several pairs with `EvalMultNoRelin`, add the products, and call `Relinearize` once on the sum instead of relinearizing every product.
* `EvalSquare` costs less than `EvalMult` of a ciphertext with itself.
* The in-place variants (`EvalAddInPlace`, `EvalMultInPlace`, `ModReduceInPlace` and others) avoid a ciphertext copy per call.
* The `NoCheck` variants (`EvalAddInPlaceNoCheck`, `EvalMultNoRelinNoCheck`, `EvalMultNoCheck`) skip the per-call parameter validation; they assume both operands come from the same context at compatible levels, which an inner loop can guarantee once outside it.
* `Compress` and `LevelReduce` drop limbs a ciphertext no longer needs. Every later operation on it, and its serialized size, scale with the limbs it still carries, so reduce before long-lived storage, before transmission, and before a chain of operations that will not use the depth.

**CKKS bootstrapping.** Bootstrapping at ring dimension 2^16 is the operation that uses a large machine best: more than 5 times faster on 36 cores than on one, and about 13% faster still with the NUMA interleaving described below on a two-socket machine. Three parameters move its cost. The secret key distribution: use `SPARSE_ENCAPSULATED`. It makes the approximate modular reduction a polynomial of about half the degree that `UNIFORM_TERNARY` needs, which saves four levels, and in the table below the uniform configuration takes about twice the time for about 10 bits less precision. [CKKS_BOOTSTRAPPING.md](../../src/pke/examples/CKKS_BOOTSTRAPPING.md) recommends it for every flavor of CKKS bootstrapping; `UNIFORM_TERNARY` is for applications that must follow the security guidelines' uniform secrets. The level budget: a larger budget spends more levels on the linear transforms and runs each with fewer rotations, a smaller one keeps more levels for the application at the cost of bootstrapping time. Start from {4, 3} at full packing and {3, 3} at 2^12 slots: in the parameter search behind the benchmark's configurations, {4, 3} was the fastest budget at full packing, {3, 3} took about 15% longer and {2, 2} twice as long, and at 2^12 slots {3, 3} was a third faster than {2, 2}. Go below these only when the application needs the levels they cost. The third is the fold radix, `PARTIAL_SUM_RADIX`, described next.

**Rotation-key storage against runtime.** The `PARTIAL_SUM_RADIX` CMake variable (default 4, any power of two) sets the radix of the rotation-fold accumulations: the CKKS bootstrapping partial sums and the `EvalSum`, `EvalSumRows` and `EvalSumCols` family for all schemes. Each fold level shares one digit decomposition across up to radix-1 rotations, so a higher radix performs fewer digit decompositions, and for bootstrapping those are at the raised level where they are most expensive. The cost is more rotation keys to generate and store: radix 4 needs roughly 1.5 times the keys of radix 2 for the affected operations, and its non-power-of-two indices are not shared with other operations. Keep the default for speed, and build with `-DPARTIAL_SUM_RADIX=2` only when rotation-key storage matters more than runtime. Key generation, including the multiparty `MultiEvalSumKeyGen`, creates the keys matching the configured radix.

**ModRaise-first and SlotsToCoeffs-first bootstrapping.** The default variant, ModRaise-first, raises the modulus, moves the coefficients into the slots, evaluates the approximate modular reduction there and moves the result back to the coefficients. The SlotsToCoeffs-first variant, selected with `BTSlotsEncoding = true` in `EvalBootstrapSetup` and described in [CKKS_BOOTSTRAPPING.md](../../src/pke/examples/CKKS_BOOTSTRAPPING.md), applies the slots-to-coefficients transform first, while the ciphertext is at its lowest level and the transform is at its cheapest, then raises the modulus, moves the coefficients into the slots and evaluates the modular reduction on the message values themselves, so the closing transform disappears. It requires `HYBRID` key switching and, under `FIXEDMANUAL`, leaves the output at a different noise scale degree than ModRaise-first. Use SlotsToCoeffs-first for fully packed ciphertexts: it takes about 70% of the time of ModRaise-first at every thread count, and on the fully packed 2^16 rows it is also 1.4 to 5 bits more precise. The one cost is planning: the ciphertext passed to `EvalBootstrap` must still hold the levels of the slots-to-coefficients transform, the second entry of the level budget, whereas ModRaise-first can start from the last level. At sparse packing the transform is small, the saving drops below 10%, and either variant serves. The table below gives both variants for each configuration.

**Bootstrapping latency and precision.** The table below takes its rows from the [`ckks-bootstrapping`](../../benchmark/src/ckks-bootstrapping.cpp) benchmark, all with `FLEXIBLEAUTO` scaling and, except the last, `SPARSE_ENCAPSULATED` secrets. Each row carries the most levels after bootstrapping that fit the 128-bit security bound at its ring dimension with at most eight key-switching digits, with the level budget and digit count that were fastest there, and each row names its parameters. Precision is measured as the library's bootstrapping examples measure it: minus the base-2 logarithm of the mean absolute error over the slots after one bootstrap of random inputs in [-1, 1]. It depends on the parameters, not on the machine. The `UNIFORM_TERNARY` row is Set II of the [homomorphic encryption security guidelines](https://cic.iacr.org/p/1/4/26) (Table 5.8) with four levels after bootstrapping instead of five. The 2^17 configurations need more memory than the i7's 64 GB, so they have no i7 columns. Latency of one bootstrap:

| configuration | variant | precision | Xeon, 1 thread | Xeon, 36 threads | i7, 1 thread | i7, 8 threads | i7 turbo, 1 thread | i7 turbo, 8 threads |
|---|---|---|---|---|---|---|---|---|
| 2^16, 2^15 slots, {4, 3}, 56-bit, 5 digits, 5 levels after | ModRaise-first | 19.9 bits | 22.1 s | 4.0 s | 24.5 s | 7.2 s | 16.6 s | 6.3 s |
|  | SlotsToCoeffs-first | 21.3 bits | 15.3 s | 2.8 s | 16.8 s | 5.1 s | 11.4 s | 4.5 s |
| 2^16, 2^12 slots, {3, 3}, 59-bit, 6 digits, 7 levels after | ModRaise-first | 21.8 bits | 19.6 s | 3.1 s | 21.3 s | 6.1 s | 14.5 s | 5.4 s |
|  | SlotsToCoeffs-first | 21.3 bits | 17.8 s | 2.9 s | 19.4 s | 5.5 s | 13.1 s | 4.8 s |
| 2^16, 2^5 slots, {1, 1}, 59-bit, 6 digits, 11 levels after | ModRaise-first | 23.1 bits | 15.7 s | 2.3 s | 17.2 s | 4.7 s | 11.6 s | 4.0 s |
|  | SlotsToCoeffs-first | 23.5 bits | 14.5 s | 2.1 s | 16.0 s | 4.3 s | 10.7 s | 3.7 s |
| 2^17, 2^16 slots, {5, 4}, 59-bit, 5 levels after | ModRaise-first | 19.6 bits | 48.0 s | 8.6 s |  |  |  |  |
|  | SlotsToCoeffs-first | 19.3 bits | 33.7 s | 6.5 s |  |  |  |  |
| 2^17, 2^16 slots, {5, 4}, 59-bit, 15 levels after | ModRaise-first | 19.6 bits | 82.5 s | 13.7 s |  |  |  |  |
|  | SlotsToCoeffs-first | 19.3 bits | 52.0 s | 9.2 s |  |  |  |  |
| 2^16, 2^15 slots, {3, 3}, 58-bit, 9 digits, `UNIFORM_TERNARY`, 4 levels after | ModRaise-first | 10.2 bits | 44.2 s | 7.5 s | 49.3 s | 14.3 s | 33.3 s | 12.5 s |
|  | SlotsToCoeffs-first | 15.2 bits | 29.6 s | 5.1 s | 32.7 s | 9.6 s | 22.2 s | 8.5 s |

SlotsToCoeffs-first takes about 70% of the time of ModRaise-first on the fully packed rows, at every thread count on both machines. Its saving comes from running the slots-to-coefficients transform at the lowest level instead of the raised one, so it shrinks with that transform: under 10% at 2^12 and 2^5 slots. Fewer slots make the linear transforms cheaper but leave the modular reduction unchanged, and the levels they save go to the application: 2^12 slots carry 7 levels in about 90% of the full-packing time, 2^5 slots carry 11 levels in about 70%. Doubling the ring dimension slightly more than doubles the time at equal levels, and at 2^17 ten more levels cost 60 to 70% more. Precision is set mainly by the scaling modulus and the secret key distribution; the level budget, the digits and the levels after bootstrapping do not change it. That separates the two choices: pick the scaling modulus for the precision the application needs, then pick the budget, digits and levels for speed alone. At full packing with `SPARSE_ENCAPSULATED` secrets and one bootstrapping iteration, the mean precision is about 12 bits at a 50-bit scaling modulus, 16.5 bits at 54 bits and 20 bits from 56 bits up, so a scaling modulus above 56 bits adds no bootstrapping precision there. `UNIFORM_TERNARY` secrets need a modular reduction four levels deeper than sparse ones, so the Set II configuration takes about twice the time of the first row and gives about 10 bits less precision in ModRaise-first. Turbo gives one thread the full clock ratio, while at 8 threads, where the all-core clock is lower and the bootstrap is limited by memory traffic rather than by the core clock, it gains only about 12%.

**CKKS functional bootstrapping.** `EvalFBT` evaluates an arbitrary lookup table on small integers while bootstrapping (the [`ckks-functional-bootstrapping`](../../benchmark/src/ckks-functional-bootstrapping.cpp) benchmark). Time for one evaluation over a fully packed ciphertext with `SPARSE_ENCAPSULATED` secrets, for lookup tables of 1, 2, 4 and 8 bits, with the input modulus q chosen so that the failure probability per ciphertext stays below 2^-40, on the Xeon (the 18-thread column uses the cores of one socket; 36 threads add nothing over 18) and on the i7 with turbo enabled:

| technique | table (bits) | ring dimension | log q | level budget | `numLargeDigits` | Xeon, 1 thread | Xeon, 18 threads | i7 turbo, 1 thread | i7 turbo, 8 threads |
|---|---|---|---|---|---|---|---|---|---|
| `FIXEDMANUAL` | 1 (Boolean) | 2^15 | 33 | {3, 3} | 4 | 5.3 s | 1.3 s | 3.9 s | 1.5 s |
| `FIXEDMANUAL` | 2 | 2^15 | 32 | {2, 2} | 4 | 9.9 s | 2.7 s | 7.3 s | 3.1 s |
| `FIXEDMANUAL` | 4 | 2^16 | 38 | {4, 4} | 2 | 20.4 s | 3.9 s | 15.0 s | 6.0 s |
| `FIXEDMANUAL` | 8 | 2^16 | 46 | {3, 3} | 4 | 41.7 s | 7.4 s | 30.4 s | 12.5 s |
| `FLEXIBLEAUTO` | 1 (Boolean) | 2^15 | 24 | {3, 3} | 2 | 5.7 s | 1.4 s | 4.2 s | 1.7 s |
| `FLEXIBLEAUTO` | 2 | 2^15 | 24 | {3, 3} | 3 | 8.3 s | 1.8 s | 6.1 s | 2.4 s |
| `FLEXIBLEAUTO` | 4 | 2^15 | 27 | {3, 3} | 4 | 10.8 s | 2.3 s | 7.9 s | 2.9 s |
| `FLEXIBLEAUTO` | 8 | 2^16 | 35 | {3, 3} | 2 | 52.8 s | 8.9 s | 40.0 s | 15.0 s |

Choose the scaling technique by table size. `FLEXIBLEAUTO` is faster for 2-bit and 4-bit tables, and for 4 bits by a factor of two, because its smaller moduli fit that table at ring dimension 2^15 where `FIXEDMANUAL` needs 2^16. `FIXEDMANUAL` is faster for 1-bit and 8-bit tables, by 7% and 21% on one Xeon thread: there both techniques use the same ring dimension, and the smaller moduli of `FLEXIBLEAUTO` do not reduce the number of limbs. The ranking is the same in every column of the table.

Since one evaluation stops scaling at one socket, a two-socket machine delivers more evaluations per second running one stream per socket, each confined with `numactl --cpunodebind`, than one stream across both. On the Xeon, two concurrent 18-thread streams complete 1.5 times as many 8-bit `FIXEDMANUAL` evaluations per second as one 36-thread stream, and 1.8 times as many 4-bit `FLEXIBLEAUTO` evaluations, although each stream takes 10 to 25% longer than it does alone.

## Multithreading

OpenFHE parallelizes lower-level operations with OpenMP:

* Double-CRT operations, which implement BGV, BFV and CKKS, parallelize over the RNS limbs of a polynomial. The width of these regions is the number of limbs, so the benefit grows with the multiplicative depth: for BGV and CKKS the limb count is one or two more than the depth, for BFV it is proportional to it.
* CKKS bootstrapping and CKKS-to-FHEW scheme switching add higher-level parallel loops.
* The blind rotation in `binfhe` parallelizes over gadget digits, as described above.
* Key generation is parallel for all schemes.

**How many threads help** depends on the operation, not only on the machine. Operations on rings of dimension 2^15 or below saturate at about 8 threads, and so does a `binfhe` gate: for such workloads, set `OMP_NUM_THREADS` to about 8 and give the remaining cores to independent work at the application level, as described below. CKKS bootstrapping at ring dimension 2^16 keeps scaling: the first configuration of the bootstrapping table takes 22.1 s on one Xeon thread, 5.3 s on 8 and 4.0 s on 36. Beyond the saturation point extra threads are at best idle, and under libgomp (GCC) they cost time, because consecutive parallel regions of different widths make that runtime rebuild its thread team; LLVM's libomp (clang) is largely insensitive to this. `OMP_WAIT_POLICY` and `GOMP_SPINCOUNT` do not change the picture. Benchmark with a few thread counts to find the right `OMP_NUM_THREADS` for a given workload.

**Restricting a process to a set of cores.** `numactl --cpunodebind=<node>` and `taskset -c <cores>` confine a process to one socket or one group of cores. That keeps its threads and the memory they touch on the same socket, stops the scheduler from migrating threads across sockets between short parallel regions, isolates processes that share a machine, and makes measurements repeatable; a process whose thread count fits one socket should run on one socket. OpenFHE's own measurements use these tools. They restrict the whole process and leave the OpenMP runtime free to place threads within the mask, which is what OpenFHE needs.

Per-thread binding through `OMP_PROC_BIND` and `OMP_PLACES` is a different mechanism and should stay unset. It adds nothing measurable on top of a core set: on plain BGV, BFV and CKKS operations and on `binfhe` gates, `OMP_PROC_BIND=close` measures within 2% of unbound threads on both runtimes, and `spread` is 2 to 19% slower. On the operations that run nested parallel regions, CKKS bootstrapping and CKKS-to-FHEW scheme switching, it is harmful under both runtimes: forming a nested team narrows a thread's place partition, and once the initial thread's partition is a single core every team it creates afterwards is confined to that core, so a 36-thread bootstrap ends up on one core, 5 to 6 times slower or worse. If a binding is in force for other reasons, check the process with `grep Cpus_allowed_list /proc/<pid>/task/*/status`; every thread reporting the same single CPU means the partition has collapsed.

Hyperthreading reduces performance, so `OMP_NUM_THREADS` should not exceed the number of physical cores. On a shared or general-purpose machine, where background processes compete for cores, a value somewhat below the physical core count avoids context switching and cache thrashing.

At the application level, running independent operations on different ciphertexts in an OpenMP loop of your own scales close to linearly when the loop is at least as wide as the core count. OpenFHE does not use nested parallelism, so an outer application loop turns the library's inner loops into serial code; use it when the application loop is wider than the inner regions would be, and set `WITH_OPENMP=OFF` when another parallelization mechanism (pthreads, C++ threads, multiprocessing) manages the threads.

## Memory allocation policy

OpenFHE allocates and frees many large polynomial buffers, roughly 0.5 to 30 MB each. Under the default allocator policy, freed buffers of that size go back to the operating system immediately, and every subsequent allocation pays page faults to get them again. OpenFHE therefore tunes the allocator at library load to keep large freed buffers on the heap for reuse, which behaves like a memory pool and removes the page-fault churn. The `WITH_MALLOC_TUNING` CMake option (default `ON`) controls this; keep it on.

The trade-off is that a process's resident set size reflects its peak transient allocation rather than its steady-state working set: a process that runs `EvalBootstrap` and then idles keeps that peak footprint. If that matters, release the retained memory explicitly at a quiescent point:

```cpp
#include "utils/memory.h"
lbcrypto::AllocTrim();   // return free heap memory to the OS
```

Call it after a batch of large transient work has completed and before the process idles, not mid-computation, since the heap grows again on the next allocation. OpenFHE calls it on context teardown (`ReleaseAllContexts()`, `ClearStaticMapsAndVectors()`) and deliberately not after individual operations, because only the application knows when it has reached a low-footprint point.

## NUMA memory placement

On a multi-socket machine the Linux default is first-touch: a page lands on the memory of whichever node writes it first. OpenFHE's long-lived, read-mostly structures, evaluation and rotation keys and bootstrapping precomputation tables, are created once during setup, usually from one thread, so under first-touch they all land on one node and every worker on the other node reads them across the interconnect. OpenFHE sets an interleaved memory policy at library load to spread these pages across the nodes the process may use; on a dual-socket Xeon, CKKS bootstrapping at ring dimension 2^16 with 36 threads runs about 13% faster with it.

The policy is conservative:

* it does nothing unless the process may use more than one NUMA node, so single-socket machines are unaffected;
* it does nothing in single-threaded use, that is, builds with `WITH_OPENMP=OFF` or runs with `OMP_NUM_THREADS=1`;
* it never overrides a policy that is already set, so `numactl --membind=...`, `--interleave=...` and container or cpuset policies take precedence;
* it applies process-wide, like the allocator tuning, which matters when OpenFHE is embedded in a larger application.

Keep it enabled on multi-socket machines. To disable it, set `OPENFHE_NUMA_INTERLEAVE=0` in the environment at runtime, or build with `-DWITH_NUMA_INTERLEAVE=OFF` to compile it out. Non-Linux platforms are unaffected.

## Hardware acceleration backends

OpenFHE supports multiple hardware acceleration backends. The released one is based on the Intel HEXL library for Intel processors with AVX-512.

The Intel HEXL backend is optimized for processors with AVX512-IFMA, such as Intel Ice Lake Xeons. The IFMA instructions apply when the small moduli are below 50 bits; larger moduli fall back to slower instructions. This pulls against the advice above to use limbs close to 60 bits: under HEXL, moduli below 50 bits run on the fast instructions but need more limbs for the same depth. Which side wins depends on the workload, so measure a HEXL build with sub-50-bit moduli against the native build with wide limbs before committing to either. Build the HEXL variant with a recent clang, for example by exporting `CC=clang-18` and `CXX=clang++-18` before following the instructions at https://github.com/openfheorg/openfhe-hexl. HEXL requires 64-bit data, so `NATIVE_SIZE` must remain 64.
