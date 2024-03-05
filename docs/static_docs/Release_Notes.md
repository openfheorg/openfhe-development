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
