# Building OpenFHE for Best Performance

The default build configuration of OpenFHE focuses on portability and ease of installation.
As a result, the runtime performace for the default configuration is often significantly worse than for the optimal configuration.

There are three important CMake flags that affect the runtime performance:
* `WITH_NATIVEOPT` allows the user to turn on/off machine-specific optimizations. By default, it is set to OFF for maximum portability of generated binaries.
* `NATIVE_SIZE` specifies the word size used internally for "small" integers. By default, it is set to 64. However, when used moduli are 28 bits or below,
it is more efficient to set it to 32.
* `WITH_OPENMP` allows the user to turn on multithreading using OpenMP. By default, it is set to ON, and all threads are available for OpenMP multithreading. The OMP_NUM_THREADS environment variable can be used to set the number of threads available in parallel regions.

The compiler used is also important. We recommend using more recent compiler versions to achieve the best runtime performance.

## Configuration specific to DM-like schemes, such as FHEW or TFHE

For STD128* modes of the schemes within the `binfhe` module with OpenMP parallelization disabled, we recommend using the following CMake command-line configuration:

```
cmake -DNATIVE_SIZE=32 -DWITH_NATIVEOPT=ON -DCMAKE_C_COMPILER=clang-12 -DCMAKE_CXX_COMPILER=clang++-12 -DWITH_OPENMP=OFF ..
```

This configuration was used to generate the runtimes for the table in [Demystifying Bootstrapping in Fully Homomorphic Encryption](https://eprint.iacr.org/2023/149).

If OpenMP parallelization is desired, the last command-line argument should be removed. If the number of OpenMP threads is set to 1 (single-threaded execution) using the `OMP_NUM_THREADS` environment variable, then runtimes will be roughly the same as for the mode when `WITH_OPENMP` is set to OFF.

Note that the use of a 32-bit word size is recommended for 'binfhe' because all STD128* configurations in OpenFHE use moduli no higher than 28 bits.

A later version of the clang compiler can also be used.

## Configuration specific to BGV-like schemes, such as BGV, BFV, and CKKS

Typically, the default configuration for schemes in the `pke` module is only to a small degree less performant than the optimal one (in contrast to DM-like schemes). Setting `WITH_NATIVEOPT` to ON may sometimes lead to a decrease in runtime (especially when using clang).

# Multithreading Configuration using OpenMP

OpenFHE uses loop parallelization via OpenMP to speed up some lower-level (mostly polynomial) operations. This loop parallelization gives the biggest improvement in the `pke` module and only provides modest speed-up in the `binfhe` module.

From a bird's eye view, the built-in OpenFHE loop parallelization is applied at the following levels:
* For many Double-CRT operations (used for BGV, BFV, and CKKS implemented using RNS in OpenFHE), loop parallelization over the number of RNS limbs is automatically applied. The biggest benefit is seen when the multiplicative depth is not small (in deeper computations). For BGV and CKKS, the number of RNS limbs is roughly the same as the multiplicative depth set by the user (it is 1 or 2 larger). In BFV, it gets more complicated, but the number of RNS limbs is still proportional to the multiplicative depth.
* A higher-level loop parallelization is employed for CKKS bootstrapping and scheme switching between CKKS and FHEW/TFHE.
* Loop parallelization is also used for all schemes during key generation (but this does not have effect on the online operations).

When developing C++ applications based on OpenFHE, it is advised to use OpenMP parallelization at the application level, e.g., when independent operations on multiple ciphertexts are performed, application-level OpenMP loop parallelization can be turned on. The scaling of performance with the number of cores in this setup can approach the "ideal" linear scaling if the dimension of the loop is comparable to the number of cores. Note that turning on OpenMP parallelization at the application level typically turns off the lower-level OpenMP loop parallelization (i.e., we do not use nested loop parallelization in OpenMP), so application-level loop parallelization should be used only when you know that the application loop dimension is higher than what is expected for built-in OpenFHE OpenMP loop parallization.

Within OpenFHE, the use of hyperthreading can lead to decreased performance so the `OMP_NUM_THREADS` environment variable should not be set higher than the number of physical cores.

If an alternative parallelization mechanism is used, e.g., pthreads, C++11 threads, or multiprocessing, OpenMP should be turned off by setting the `WITH_OPENMP` CMake flag to OFF.

# Accelerating OpenFHE using Specialized Hardware Backends #

OpenFHE supports multiple hardware acceleration backends. Currently, one such backend has been released based on the Intel HEXL library for Intel processors with AVX-512 support.

## Notes specific to the Intel HEXL backend

The Intel HEXL backend is optimized for processors with AVX512_IFMA support, e.g., Intel IceLake Xeon processors. Note that to take advantage of AVX512_IFMA optimizations, the
small moduli should be below 50 bits. If they are larger, slower instructions are used.

For best AVX512 acceleration, we recommend building the OpenFHE HEXL variant using a recent version of clang, i.e., 12 or later (exceptions for `binfhe` discussed below). This can be done using the environment variables `CC` and `CXX`. For instance,
the user can run
```
export CC=clang-12
export CXX=clang++-12
```
before following the build instructions at https://github.com/openfheorg/openfhe-hexl. Alternatively, the environment variables can be set in `bash_profile` or similar profile configuration file.

For DM-like schemes within the `binfhe` module, later versions of clang (with the exceptions of clang-14 and clang-15) produce the best performance. The Intel HEXL Library requires 64-bit data so `NATIVE_SIZE` can not be set to 32.
