10/20/2025: OpenFHE 1.4.2 (stable) is released

* Fixes a bug introduced by PR #1007 that affected large-depth scenarios for the `HPSPOVERLEVELED` mode of BFV (#1066)

The detailed list of changes is available at https://github.com/openfheorg/openfhe-development/issues?q=is%3Aissue+milestone%3A%22Release+1.4.2%22

10/14/2025: OpenFHE 1.4.1 (stable) is released

* Changes `convert` to `ConvertRLWEToCKKS` and `ConvertCKKSToRLWE` + other small API updates for functional CKKS bootstrapping (#1047)
* Removes the need for setting `LD_LIBRARY_PATH` when installing the library at a different location for user projects (#1050)
* Adds a new API for `EvalFastRotation` that does not requre specifying the cyclotomic order (#1051)
* Fixes several bugs

The detailed list of changes is available at https://github.com/openfheorg/openfhe-development/issues?q=is%3Aissue+milestone%3A%22Release+1.4.1%22

08/18/2025: OpenFHE 1.4.0 (development) is released

* Adds general functional bootstrapping using CKKS proposed in https://eprint.iacr.org/2024/1623 (#954)
* Enables the sparse-secret encapsulation mode from https://eprint.iacr.org/2022/024 for regular and functional CKKS bootstrapping (#1001)
* Adds optimized implementation (without checks) for selected homomorphic addition and multiplication operations (#991)
* Updates google submodules (#1036)
* Fixes several bugs

The detailed list of changes is available at https://github.com/openfheorg/openfhe-development/issues?q=is%3Aissue+milestone%3A%22Release+1.4.0%22

07/11/2025: OpenFHE 1.3.1 (stable) is released

* API change: Previously, const plaintexts were silently modified; the `const` qualifier now has to be removed in these cases; see #1046 for more details (#970)
* Updates the noise estimation models for BGV and BFV, making them slightly more conservative (roughly 1 extra bit is added for each multiplicative level) (#1004)
* Removes extra rotation indices in CKKS bootstrapping (#998)
* Fixes a bug with CKKS bootstrapping for N=2^17 (#996)
* Improves exception handling
* Fixes several other bugs

The detailed list of changes is available at https://github.com/openfheorg/openfhe-development/issues?q=is%3Aissue+milestone%3A%22Release+1.3.1%22

05/21/2025: OpenFHE 1.3.0 (development) is released

* Adds the composite scaling modes to CKKS based on https://eprint.iacr.org/2023/1462 (see https://github.com/openfheorg/openfhe-development/blob/main/src/pke/examples/COMPOSITE_SCALING.md for more details)
* Adds two-party interactive CKKS bootstrapping from https://eprint.iacr.org/2023/1203 (see https://github.com/openfheorg/openfhe-development/blob/main/src/pke/examples/INTERACTIVE_BOOTSTRAPPING.md for more details)
* Enables the complex-number arithmetic in CKKS (#964)
* Makes OpenFHE compatible with Emscripten 3.x and 4.x (see https://github.com/openfheorg/openfhe-wasm for more details)
* Adds a cleartext version of EvalChebyshevFunction (#959)
* Optimizes the hybrid key switching (#237)
* Fixes several bugs

The detailed list of changes is available at https://github.com/openfheorg/openfhe-development/issues?q=is%3Aissue+milestone%3A%22Release+1.3.0%22

03/21/2025: OpenFHE 1.2.4 (stable) is released

* Improves the support for STL threads (when OMP is disabled)
* Fixes the bugs identified in [CVE-2024-56430](https://nvd.nist.gov/vuln/detail/CVE-2024-56430)

The detailed list of changes is available at https://github.com/openfheorg/openfhe-development/issues?q=is%3Aissue+milestone%3A%22Release+1.2.4%22

10/30/2024: OpenFHE 1.2.3 (stable) is released

* Adds support for a custom PRNG implemented in an external library

The detailed list of changes is available at https://github.com/openfheorg/openfhe-development/issues?q=is%3Aissue+milestone%3A%22Release+1.2.3%22

10/28/2024: OpenFHE 1.2.2 (stable) is released

* Improves the runtime of inverse NTT (for clang++; #872)
* Extends the support of extended (RLWE) parameters in DM/CGGI (#867)
* Includes several bug fixes

The detailed list of changes is available at https://github.com/openfheorg/openfhe-development/issues?q=is%3Aissue+milestone%3A%22Release+1.2.2%22

09/10/2024: OpenFHE 1.2.1 (stable) is released

* Fixes compilation issues with g++ 14 and clang++ 18 (#822, #835)
* Fixes the parameter estimation bug for HRA-secure PRE when ring dimension is not set by the user (#827)
* Includes several other bug fixes

The detailed list of changes is available at https://github.com/openfheorg/openfhe-development/issues?q=is%3Aissue+milestone%3A%22Release+1.2.1%22

06/25/2024: OpenFHE 1.2.0 (stable) is released

* Updates the lattice parameters tables to support the ring dimension of 2^{16} and 2^{17} for ternary and Gaussian secrets (#806)
* Adds application specifications validator for BGV, BFV, and CKKS (#710)
* Updates the parameter sets for CGGI/DM/LMKCDEY; adds low-probability-of-failure parameter sets (below 2^{-120}) (#673)
* Adds several optimizations for BFV, including support for modulus switching during computation (#682, #715, #731)
* Fixes parameter estimation bugs for BGV, BFV, and CKKS (insecure configurations were possible for scenarios with hybrid key switching) (#785, #786)
* Includes several fixes related to handling the map of automorphism keys for various EvalSum*KeyGen operations (#756, #773, #783, #797)
* Add support for selective serialization/deserialization of automorphism/rotation keys (#775)
* Updates the HRA-Secure BGV PRE implementation based on https://eprint.iacr.org/2024/681 (#767)
* Includes many other bug fixes

The detailed list of changes is available at https://github.com/openfheorg/openfhe-development/issues?q=is%3Aissue+milestone%3A%22Release+1.2.0%22

03/08/2024: OpenFHE 1.1.4 (stable) is released

* Fixes a bug affecting the Google C++ Transpiler code generation (#701)
* Adds serialization backwards compatibility down to 1.0.4 for the JSON encoding (#571)
* Shows more information when an exception is thrown (#702)

The detailed list of changes is available at https://github.com/openfheorg/openfhe-development/issues?q=is%3Aissue+milestone%3A%22Release+1.1.4%22

03/04/2024: OpenFHE 1.1.3 (stable) is released

* One internal map is now used for all rotation keys, which reduces memory footprint and key generation time for BGV-like schemes (#546)
* New mechanism for OpenFHE exceptions is added; the old one is still available, but will be removed in a later major release (#668)
* Low-level optimizations for polynomial arithmetic (minor efficiency improvements for BGV-like schemes)
* Scheme switching code improvements; note that the API for scheme switching has changed! (#631)
* Improves runtime for systems with a large number of threads/cores (#617)
* Fast rotations are now fully operations in BFV (#569)
* Includes fixes for 18 bugs

The detailed list of changes is available at https://github.com/openfheorg/openfhe-development/issues?q=is%3Aissue+milestone%3A%22Release+1.1.3%22

12/16/2023: OpenFHE 1.1.2 (stable) is released

* Improves the performance of secret-key encryption and key generation for all schemes (#598)
* Improves the efficiency of X(N)OR gates for FHEW/TFHE (#578)
* Adds an article explaining how to configure OpenFHE for best performance (#549)
* Includes 18 bug fixes

The detailed list of changes is available at https://github.com/openfheorg/openfhe-development/issues?q=is%3Aissue+milestone%3A%22Release+1.1.2%22

08/23/2023: OpenFHE 1.1.1 (development) is released

* Fixes the CMake files (binfhe module is now a dependency for the pke module) [#525, #538]
* Fixes a bug in EvalChebyshevFunction (#530)
* Adds documentation for threshold FHE (#457)
* Includes several other bug fixes

The detailed list of changes is available at https://github.com/openfheorg/openfhe-development/pulls?q=is%3Apr+milestone%3A%22Release+1.1.1%22

07/28/2023: OpenFHE 1.1.0 (development) is released

* Adds scheme switching between CKKS and FHEW/TFHE
* Adds comparison and (arg)min evaluation in CKKS via scheme switching to FHEW/FHEW
* Implements a new FHEW/TFHE bootstrapping method proposed in https://eprint.iacr.org/2022/198 (EUROCRYPT'23)
* Adds support for multi-input Boolean gates
* Adds a parameter selection tool for FHEW/TFHE based on the lattice estimator (see https://github.com/openfheorg/openfhe-lattice-estimator)
* Implements interactive CKKS bootstrapping based on threshold FHE
* Includes many optimizations for all FHE schemes, e.g., FHEW/TFHE bootstrapping is now 2x faster (takes 26 ms on a commodity laptop)
* Improves the Hardware Abstraction Layer
* Many bug fixes and documentation changes

The detailed list of changes is available at https://github.com/openfheorg/openfhe-development/pulls?q=is%3Apr+milestone%3A%22Release+1.1.0%22

06/19/2023: OpenFHE 1.0.4 (stable) is released

* Optimizes hybrid key switching (#377)
* Several bugfixes for BFV (#422, #432)
* Several bugfixes for CKKS (#424, #436)
* Adds security work factors for the ring dimension of 64K (#439)
* Fixes examples for FHEW/TFHE (#335, #357)
* Adds support for gcc/g++ 13 (#430)
* Other bugfixes and small documentation changes

03/17/2023: OpenFHE 1.0.3 (stable) is released

* Corrects the noise estimation for BGV/BFV multiparty scenarios (#273)
* Adjusts the logic when trying to bootstrap CKKS ciphertexts with remaining levels (#305)
* Adds exception handling for several reported issues
* Fixes several examples
* Includes several documentation fixes

The detailed list is available at https://github.com/openfheorg/openfhe-development/pulls?q=is%3Apr+is%3Aclosed+milestone%3A%22Release+1.0.3%22

12/23/2022: OpenFHE 1.0.2 (stable) is released

* Fixes several compilation errors affecting selected environments
* Includes several documentation fixes

11/30/2022: OpenFHE 1.0.1 (stable) is released

* Fixed the serialization bug affecting DM/CGGI schemes (binfhe module)
* Added support for the Emscripten compiler (for WebAssembly compilation)

11/03/2022: OpenFHE 1.0.0 (development) is released

* Doubles the precision of CKKS bootstrapping
* Adds support for evaluating arbitrary smooth functions, including logistic function, sine, cosine, and division
* Implements recommendations for INDCPA^D secure implemementation of CKKS proposed in https://eprint.iacr.org/2022/816 (CRYPTO'22)
* Adds a new security mode for threshold FHE
* Fixes many bugs

10/17/2022: OpenFHE 0.9.5 (development) is released

* Improves precision of CKKS bootstrapping
* Fixes a building error in MacOS
* Includes other small bug fixes

10/05/2022: OpenFHE 0.9.4 (development) is released

* Fixes build errors for NATIVE_SIZE=32
* Includes other small bug fixes

09/16/2022: OpenFHE 0.9.3 (development) is released

* Fixes build errors in MinGW
* Fixes a compilation error with g++ 12
* Includes fixes for the Proxy Re-Encryption functionality

08/18/2022: OpenFHE 0.9.2 (development) is released

* Fixes a compilation error for some versions of MacOS
* Fixes a problem with docker configuration
* Includes bug fixes from PALISADE v1.11.7
* Adds support for RISC-V architecture
* Small optimizations for some of the CKKS operations

07/21/2022: OpenFHE 0.9.1 (development) is released

* Fixes a compilation error for NATIVE_SIZE=128 in MacOS
* Fixes small bugs

07/19/2022: OpenFHE 0.9.0 (development) is released

Includes all prior FHE functionality of PALISADE. Also adds the following new features:
* New BGV and BFV RNS variants proposed in https://eprint.iacr.org/2021/204
* A new CKKS RNS variant variant proposed in https://eprint.iacr.org/2020/1118
* A full RNS implementation of CKKS bootstrapping
* Adds support for multiple hardware acceleration backends using a Hardware Abstraction Layer feature
* Large-precision comparison and other algorithms proposed in https://eprint.iacr.org/2021/1337

**Note**: OpenFHE stems off of PALISADE. Refer to the following for [PALISADE release notes](https://gitlab.com/palisade/palisade-development/-/blob/master/Release_Notes.md)
