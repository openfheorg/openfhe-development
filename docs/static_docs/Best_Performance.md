# Building OpenFHE for Best Performance

The default build configuration of OpenFHE favors portability and ease of installation, and its runtime performance is often well below what the same machine can deliver. This document lists the build options, compiler and runtime settings that close that gap, and the operating points where adding more hardware stops helping.

## Build configuration

Three CMake options and the choice of compiler have the largest effect.

* `WITH_NATIVEOPT` (default `OFF`) enables machine-specific code generation (`-march=native`). Turn it on whenever the binary runs on the machine that builds it. It is the single most valuable setting: the vectorized number-theoretic transforms and digit decompositions only reach their full width with it, and on a 36-core Xeon CKKS bootstrapping runs 1.5 to 2 times faster with it than without. Binaries built with it are not portable to other processor generations.
* `NATIVE_SIZE` (default `64`) is the word size of the native integers. 64 bits serves every scheme with moduli up to 60 bits, which covers all predefined parameter sets, and it is the right choice for the `binfhe` module as well (see below). `128` allows moduli up to 121 bits at a cost in arithmetic speed and is needed only for configurations that require such moduli. `32` caps moduli at 28 bits and disables 128-bit intermediate arithmetic; it is a portability option for constrained targets, not a performance one.
* `WITH_OPENMP` (default `ON`) enables OpenMP multithreading. All threads are available by default; `OMP_NUM_THREADS` limits them. See "Multithreading" below for how many are useful.

**Compiler.** OpenFHE requires GNU C++ 9 or clang 10 at minimum; performance favors recent releases of either. Measured on a 36-core Xeon with `WITH_NATIVEOPT=ON`, clang 18 runs the BGV, BFV and CKKS operations 25 to 35% faster than GCC 14 on one thread, and it scales better with thread count because LLVM's OpenMP runtime changes the size of its thread team far more cheaply than libgomp does. For `binfhe` the two compilers are within about 10% of each other. A recent clang is the recommendation where the choice exists; GCC 12 or later is a sound alternative.

A configuration that applies all of the above for a build that stays on one machine:

```
cmake -DWITH_NATIVEOPT=ON -DCMAKE_C_COMPILER=clang-18 -DCMAKE_CXX_COMPILER=clang++-18 ..
```

## FHEW and TFHE (the `binfhe` module)

The `binfhe` module runs its bootstrapping keys and the blind rotation and key switching that consume them on 32-bit words inside a 64-bit build, whenever the parameters allow it. A refresh key takes the 32-bit form when its bootstrapping modulus fits the 32-bit accumulator's headroom, a switching key when its key-switching modulus fits the same 28-bit bound; the two decisions are independent, and a key whose moduli do not fit is generated at the native width. All predefined parameter sets qualify with the exception of `LPF_STD256Q_4_AP`, whose 51-bit bootstrapping modulus keeps its refresh key at 64 bits while its switching key still converts. The conversion is automatic: `BTKeyGen` generates the keys directly in the narrow form (its `internal32` argument, `true` by default, turns this off), gate outputs are identical to the 64-bit computation, and resident key material is roughly halved.

This is faster than a `NATIVE_SIZE=32` build, because a 64-bit build keeps the 128-bit intermediate arithmetic that lets the inner products accumulate lazily and reduce once per output coefficient, which a 32-bit build cannot do. The recommended build for `binfhe` is therefore the default word size with machine-specific optimizations and a recent compiler, as in the command above. Custom parameter sets benefit from the same path when the bootstrapping modulus and the key-switching modulus are both at most 2^28.

### Bootstrapping method and thread count

The three bootstrapping methods differ in how they respond to threads. Boolean gate latency on the 36-core Xeon with clang 18 and `WITH_NATIVEOPT=ON`, for the default 128-bit parameter sets:

| method | 1 thread | 8 threads | 36 threads |
|---|---|---|---|
| GINX (`STD128`) | 29 ms | 17 ms | 17 ms |
| LMKCDEY (`STD128_LMKCDEY`) | 28 ms | 22 ms | 22 ms |
| AP (`STD128_AP`) | 40 ms | 27 ms | 27 ms |

Single-threaded, GINX and LMKCDEY are within about 10% of each other across the predefined sets, and which one leads depends on the set. From 8 threads on, GINX is 10 to 25% faster than LMKCDEY on every set. AP is the slowest and has the largest keys. A single gate does not benefit from more than about 8 threads under any method, because the blind rotation parallelizes over the gadget digits of one ciphertext and there are only a handful of those; running many gates concurrently at the application level is the way to use a larger machine, with `OMP_NUM_THREADS` kept small so the per-gate teams do not oversubscribe the cores. Setting `OMP_NUM_THREADS=1` gives the same runtimes as a build with `WITH_OPENMP=OFF`.

## BGV, BFV and CKKS (the `pke` module)

The default configuration is within a modest factor of the best one for these schemes; `WITH_NATIVEOPT=ON` and the compiler choice above account for most of the difference. Beyond the build, the parameters and API patterns below decide how much work each operation does and how many threads it can use.

**Limbs set the parallel width.** Double-CRT operations parallelize over the RNS limbs of a polynomial, and the number of limbs is set by the multiplicative depth: one or two more than the depth for BGV and CKKS, proportional to it for BFV. A shallow context therefore has little for extra threads to do. Measured at ring dimension 2^14 with clang 18 on the 36-core Xeon, `EvalMult` runs 1.9 times faster on 8 threads than on one with 3 limbs, 2.6 times with 4 limbs and 3.3 times with 7 limbs, and 36 threads add nothing over 8 at this ring size. The limb count also sets the cost of every operation, since each limb needs its own NTT whenever a polynomial changes representation. For a given depth, wider limbs mean fewer of them: a scaling modulus close to the 60-bit ceiling of a 64-bit build reaches the same depth with fewer limbs, and therefore fewer NTTs, than a smaller one.

**Key switching.** A ciphertext multiplication ends with a relinearization and a rotation with an automorphism; both are key switches, and the key switch is the dominant cost of each operation. BGV and CKKS default to the `HYBRID` technique, BFV to `BV`. `HYBRID` splits the modulus into `numLargeDigits` digits (0, the default, uses 3 digits when the depth exceeds 3 and 2 otherwise): fewer digits mean fewer basis conversions per switch and less key material, at the price of a larger auxiliary modulus. `BV` decomposes into digits of `digitSize` bits, and the default of 0 uses one digit per limb, which is the fastest BV setting; smaller digits lower the noise added by a switch but multiply its work in proportion. At ring dimension 2^14 and depth 2 on one thread, BV with 10-bit digits costs 1.4 times HYBRID on multiplication and 2.2 times on rotation.

**Rotating one ciphertext several times.** The digit decomposition is the expensive half of a rotation and depends only on the ciphertext, not on the index. `EvalFastRotationPrecompute` computes it once and `EvalFastRotation` reuses it for each index, which is how the library's own linear transforms and sums are built.

**API patterns that avoid work.**

* Multiply several pairs with `EvalMultNoRelin`, add the products, and call `Relinearize` once on the sum instead of relinearizing every product.
* `EvalSquare` costs less than `EvalMult` of a ciphertext with itself.
* The in-place variants (`EvalAddInPlace`, `EvalMultInPlace`, `ModReduceInPlace` and others) avoid a ciphertext copy per call.
* The `NoCheck` variants (`EvalAddInPlaceNoCheck`, `EvalMultNoRelinNoCheck`, `EvalMultNoCheck`) skip the per-call parameter validation; they assume both operands come from the same context at compatible levels, which an inner loop can guarantee once outside it.
* `Compress` and `LevelReduce` drop limbs a ciphertext no longer needs. Every later operation on it, and its serialized size, scale with the limbs it still carries, so reduce before long-lived storage, before transmission, and before a chain of operations that will not use the depth.

**CKKS bootstrapping.** Bootstrapping at ring dimension 2^16 is the operation that uses a large machine best: about 5.5 times faster on 36 cores than on one, and about 13% faster still with the NUMA interleaving described below on a two-socket machine. Three parameters move its cost. The secret key distribution: `SPARSE_TERNARY` and `SPARSE_ENCAPSULATED` make the approximate modular reduction a polynomial of about half the degree that `UNIFORM_TERNARY` needs, which saves levels and time. The level budget: a larger budget spends more levels on the coefficient-to-slot transforms and runs each with fewer rotations, a smaller one keeps more levels for the application at the cost of bootstrapping time. And the fold radix below.

**Rotation-key storage against runtime.** The `PARTIAL_SUM_RADIX` CMake variable (default 4, any power of two) sets the radix of the rotation-fold accumulations: the CKKS bootstrapping partial sums and the `EvalSum`, `EvalSumRows` and `EvalSumCols` family for all schemes. Each fold level shares one digit decomposition across up to radix-1 rotations, so a higher radix performs fewer digit decompositions, and for bootstrapping those are at the raised level where they are most expensive. The cost is more rotation keys to generate and store: radix 4 needs roughly 1.5 times the keys of radix 2 for the affected operations, and its non-power-of-two indices are not shared with other operations. Build with `-DPARTIAL_SUM_RADIX=2` when rotation-key storage matters more than runtime. Key generation, including the multiparty `MultiEvalSumKeyGen`, creates the keys matching the configured radix.

## Multithreading

OpenFHE parallelizes lower-level operations with OpenMP:

* Double-CRT operations, which implement BGV, BFV and CKKS, parallelize over the RNS limbs of a polynomial. The width of these regions is the number of limbs, so the benefit grows with the multiplicative depth: for BGV and CKKS the limb count is one or two more than the depth, for BFV it is proportional to it.
* CKKS bootstrapping and CKKS-to-FHEW scheme switching add higher-level parallel loops.
* The blind rotation in `binfhe` parallelizes over gadget digits, as described above.
* Key generation is parallel for all schemes.

**How many threads help** depends on the operation, not only on the machine. Operations on rings of dimension 2^15 or below saturate at about 8 threads; a `binfhe` gate saturates at about 8; CKKS bootstrapping at ring dimension 2^16 uses 36 cores well. Beyond the saturation point extra threads are at best idle, and under libgomp (GCC) they cost time, because consecutive parallel regions of different widths make that runtime rebuild its thread team; LLVM's libomp (clang) is largely insensitive to this. `OMP_WAIT_POLICY` and `GOMP_SPINCOUNT` do not change the picture. Benchmark with a few thread counts to find the right `OMP_NUM_THREADS` for a given workload.

**Restricting a process to a set of cores.** `numactl --cpunodebind=<node>` and `taskset -c <cores>` confine a process to one socket or one group of cores. That keeps its threads and the memory they touch on the same socket, stops the scheduler from migrating threads across sockets between short parallel regions, isolates processes that share a machine, and makes measurements repeatable; a process whose thread count fits one socket should run on one socket. OpenFHE's own measurements use these tools. They restrict the whole process and leave the OpenMP runtime free to place threads within the mask, which is what OpenFHE needs.

Per-thread binding through `OMP_PROC_BIND` and `OMP_PLACES` is a different mechanism and should stay unset. It adds nothing measurable on top of a core set: on plain BGV, BFV and CKKS operations and on `binfhe` gates, `OMP_PROC_BIND=close` measures within 2% of unbound threads on both runtimes, and `spread` is 2 to 19% slower. On the operations that run nested parallel regions, CKKS bootstrapping and CKKS-to-FHEW scheme switching, it is harmful under both runtimes: forming a nested team narrows a thread's place partition, and once the initial thread's partition is a single core every team it creates afterwards is confined to that core, so a 36-thread bootstrap ends up on one core, 5 to 6 times slower or worse. If a binding is in force for other reasons, check the process with `grep Cpus_allowed_list /proc/<pid>/task/*/status`; every thread reporting the same single CPU means the partition has collapsed.

Hyperthreading reduces performance, so `OMP_NUM_THREADS` should not exceed the number of physical cores. On a shared or general-purpose machine, where background processes compete for cores, a value somewhat below the physical core count avoids context switching and cache thrashing.

At the application level, running independent operations on different ciphertexts in an OpenMP loop of your own scales close to linearly when the loop is at least as wide as the core count. OpenFHE does not use nested parallelism, so an outer application loop turns the library's inner loops into serial code; use it when the application loop is wider than the inner regions would be, and set `WITH_OPENMP=OFF` when another parallelization mechanism (pthreads, C++ threads, multiprocessing) manages the threads.

## Memory allocation policy

OpenFHE allocates and frees many large polynomial buffers, roughly 0.5 to 30 MB each. Under the default allocator policy, freed buffers of that size go back to the operating system immediately, and every subsequent allocation pays page faults to get them again. OpenFHE therefore tunes the allocator at library load to keep large freed buffers on the heap for reuse, which behaves like a memory pool and removes the page-fault churn. The `WITH_MALLOC_TUNING` CMake option (default `ON`) controls this.

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

Set `OPENFHE_NUMA_INTERLEAVE=0` in the environment to disable it at runtime, or build with `-DWITH_NUMA_INTERLEAVE=OFF` to compile it out. Non-Linux platforms are unaffected.

## Hardware acceleration backends

OpenFHE supports multiple hardware acceleration backends. The released one is based on the Intel HEXL library for Intel processors with AVX-512.

The Intel HEXL backend is optimized for processors with AVX512-IFMA, such as Intel Ice Lake Xeons. The IFMA instructions apply when the small moduli are below 50 bits; larger moduli fall back to slower instructions. Build the HEXL variant with a recent clang, for example by exporting `CC=clang-18` and `CXX=clang++-18` before following the instructions at https://github.com/openfheorg/openfhe-hexl. HEXL requires 64-bit data, so `NATIVE_SIZE` must remain 64.
