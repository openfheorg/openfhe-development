# Building OpenFHE for Best Performance

The default build configuration of OpenFHE focuses on portability and ease of installation.
As a result, the runtime results for the default configuration are often significantly worse than for the optimal configuration.

There are two important CMake flags that affect the runtime performance:
* `WITH_NATIVEOPT` allows the user to turn on/off machine-specific optimizations. By default, it is set to OFF for maximum portability of generated binaries.
* `NATIVE_SIZE` specifies the word size used internally for "small" integers. By default, it is set to 64. However, when the moduli are below 28 bits,
it is more efficient to set it to 32.

A choice of compiler is also important. We recommend using more recent versions of compilers to achieve best performance results.

## Configuration specific to DM-like schemes, such as FHEW or TFHE

For STD128* modes of the schemes in the `binfhe` module when OpenMP parallelization is not used, we recommend using the following CMake command-line configuration:

```
cmake -DNATIVE_SIZE=32 -DWITH_NATIVEOPT=ON -DCMAKE_C_COMPILER=clang-12 -DCMAKE_CXX_COMPILER=clang++-12 -DWITH_OPENMP=OFF ..
```

This configuration was used to generate the runtimes for the table in [Demystifying Bootstrapping in Fully Homomorphic Encryption](https://eprint.iacr.org/2023/149)

If OMP parallelization is used, then the last command-line argument can be removed. Not that the use of 32-bit word size is recommended because all STD128* configurations in OpenFHE use moduli not higher than 28 bits.

A later version of the clang compiler can also be used.

## Configuration specific to BGV-like schemes, such as BGV, BFV, and CKKS

Typically the default configuration for the schemes in the `pke` module is only to a small degree less performant than the optimal one (in contrast to DM-like schemes). Turning on `WITH_NATIVEOPT` may sometimes lead to a decrease in runtime (especially in clang).

# Accelerating OpenFHE using Specialized Hardware Backends #

OpenFHE supports multiple hardware acceleration backends. Currently, one such backend has been released based the Intel HEXL library for Intel processors with AVX-512 support.

## Notes specific to the Intel HEXL backend

The Intel HEXL backend is optimized for processors with AVX512_IFMA support, e.g., Intel IceLake Xeon processors. Note that to take advantage of AVX512_IFMA optimizations, the
small moduli should be below 50 bits. If they are larger, slower instructions are used.

For best AVX512 acceleration, we recommend building the OpenFHE HEXL variant using a recent version of clang, i.e., 12 or later. This can be done using the environment variables `C` and `CXX`. For instance,
the user can run
```
export C = clang-12
export CXX = clang++-12
```
before following the build instructions at https://github.com/openfheorg/openfhe-hexl. Alternatively, the environment variables can be set in `bash_profile` or similar profile configuration file.
