08/22/2021: PALISADE v1.11.4 (stable) is released in the palisade-release repo
* Fixes WebAssembly compilation for new versions of Emscripten (2.0.23+)
* Integrates HEXL v1.2.0 improvements (additional acceleration)
* Adds support for Gaussian sampling with standard deviations between 2^32 and 2^59
* Fixes several minor bugs

05/28/2021: PALISADE v1.11.3 (stable) is released in the palisade-release repo
* Includes all changes from development releases v1.11.0, v1.11.1, and v1.11.2

05/26/2021: PALISADE v1.11.2 (development) is released
* Adds initial Intel HEXL library integration
* Adds support for web assembly
* Fixes some bugs for the scenarios with multiple cryptocontexts

05/04/2021: PALISADE v1.11.1 (development) is released
* Fixes some bugs related to serialization

03/31/2021: PALISADE v1.11.0 (development) is released

* The abe module is moved to https://gitlab.com/palisade/palisade-abe
* The signature module is moved to https://gitlab.com/palisade/palisade-signature
* Adds high-precision CKKS (supports the scaling factor of up to 119 bits in size)
* Removes old code (Stehle-Steinfeld scheme and prior Matrix functionality)
* Applies optimizations for NTT, and hybrid key switching in BGVrns and CKKS
* Simplifies the PALISADE installation (gitmodules are now updated automatically)
* Adds a Dockerfile for PALISADE
* Fixes many bugs reported by the PALISADE community

12/08/2020: PALISADE v1.10.6 (stable) is released

* Patches CKKS against the Li-Micciancio attack
* Complex-number arithmetic is no longer supported in CKKS
* Fixes a bug in the 128-bit mathematical backend
* Fixes a rarely occuring exception in the Gaussian sampling procedure

10/01/2020: PALISADE v1.10.5 (stable) is released

* Fixes a lattice parameter selection bug for an edge case (for leveled HE schemes)
* Fixes a compilation error in Apple clang 12 (XCode 12)

09/21/2020: PALISADE v1.10.4 (stable) is released

* Includes all changes from development releases v1.10.0-v1.10.3
* Fixes some bugs in BGVrns
* Improves error handling

08/25/2020: PALISADE v1.10.3 (development) is released

* Fixes a bug in BFVrns for larger plaintext moduli
* Fixes bugs in FHEW/TFHE
* Fixes bugs affecting the 32-bit and 64-bit native integer backends
* Improves error handling
* Includes minor documentation cleanup

07/11/2020: PALISADE v1.10.2 (development) is released

* Fixes a bug affecting some threshold FHE scenarios
* Adds more validation to CMake flags
* Includes minor documentation cleanup

06/26/2020: PALISADE v1.10.1 (development) is released

* Fixes a bug affecting some clang environments
* Fixes a bug related to the BUILD_BENCHMARKS CMake flag

06/18/2020: PALISADE v1.10.0 (development) is released

* Adds a usable, full RNS variant of BGV (as a more efficient alternative to BFV RNS variants for integer arithmetic)
* Adds a fully functional threshold FHE capability to BGV, BFV, and CKKS to support multi-party computations
* Adds an automated rescaling mode to the approximate rescaling RNS variant of CKKS
* Improves the performance of both CKKS RNS variants
* Improves the performance of both BFV RNS variants
* Makes NTL completely optional for all environments (no quad-precision floats are needed anymore)
* Improves the support for clang in Linux
* Simplifies the CMake procedure for building PALISADE
* Fixes many bugs reported by the PALISADE community

04/24/2020: PALISADE v1.9.2 (stable) is released in the palisade-release repo

* Includes all changes from development releases v1.8.0, v1.9.0, and v1.9.1
* Fixes a bug in BFVrnsB
* Fixes a bug with CSPRNG in some multi-threaded environments

03/03/2020: PALISADE v1.9.1 (development) is released

* Fixes the performance issue with Ubuntu
* Improves the runtime of inverse Number Theoretic Transform for all supported systems

02/29/2020: PALISADE v1.9.0 (development) is released

* Adds multiple low-level optimizations, including improved Number Theoretic Transform
* Adds a CMake install package for PALISADE
* Improves the security and performance of the PRE implementations for BFV, BGV, and CKKS homomorphic encryption schemes
* Updates selected parameter sets for FHEW to reduce the probability of decryption error
* Includes multiple bug fixes for the issues reported by the PALISADE community

01/30/2020: PALISADE v1.8.0 (development) is released

* Adds the Gama-Izabachene-Nguyen-Xie (GINX) bootstrapping to the FHEW implementation
* Includes other FHEW optimizations: now the bootstrapping key size is 20x times smaller and runtime about 2.5x faster
* Adds XOR and XNOR gates to FHEW

01/22/2020: PALISADE v1.7.4 (stable) is released in the palisade-release repo

* includes all changes from development releases v1.7.a to v1.7.d

01/15/2020: PALISADE v1.7.d (development) is released

* Replaces the Mersenne Twister PRNG Engine with a cryptographically secure BLAKE2-based PRNG
* Fixes a PRNG bug affecting environments where multithreading is done not using OpenMP

12/26/2019: PALISADE v1.7.c (development) is released

* Fixes a bug affecting applications using the PALISADE serialization capability
* Changes the installation paths for header files and library binary files

12/19/2019: PALISADE v1.7.b (development) is released

* Simplifies the development of applications using PALISADE (only one header file is now needed for most applications)
* Changes the folder hierarchy of the library header files

11/15/2019: PALISADE v1.7.a (development) is released

* Adds an optimized implementation of the CKKS scheme for approximate (real-number) homomorphic encryption. The implementation features automated rescaling/modswitching and hybrid key switching.
* Adds an optimized implementation of the FHEW scheme for Boolean-circuit homomorphic encryption, supporting standard HE parameters. Performs bootstrapping for each binary gate, and hence supports the evaluation of arbitrary Boolean circuits.
* Adds the ring dimension as an option when generating crypto contexts for BFV variants.
* Improves the noise growth of the BEHZ variant of BFV (referred to as the BFVrnsB scheme in PALISADE).
* Fixes several bugs.

9/12/2019: PALISADE v1.6.0 is released

* Significantly simplifies/automates the PALISADE build/installation process. Now we use CMake.
* Serialization/deserialization is now much faster (by 3x to 10x). Both binary and JSON formats are supported.
* By default, PALISADE compiles w/o external dependencies in Linux and Windows, i.e., NTL/GMP is now optional for these OSes.
* The performance in Windows is now as fast as in Linux (4x to 7x times faster than previously).
* Applies several low-level optimizations, and fixes some bugs.

3/20/2019: PALISADE v1.5.0 is released

* Fixes the vulnerability found in https://eprint.iacr.org/2017/785 (PKC'19) for the PRE schemes based on BGV/BFV
* Adds PRE modes for BGV/BFV that are secure under honest re-reencryption attacks (recommended security for practical use)
* Adds support for splitting lattice trapdoor sampling into offline and online phases (used by digital signatures, IBE, and ABE constructions)
* Fixes bugs related to the multi-threaded mode of operation

02/11/2018: PALISADE v1.4.1 is released

Fixes a bug affecting the IBE and CP-ABE implementations (some unit tests for IBE/CP-ABE were entering in an infinite loop in about 10% of the runs).

12/31/2018: PALISADE v1.4.0 is released

* Adds the Gentry-Peikert-Vaikuntanathan (GPV) digital signature scheme
* Adds the GPV identity-based encryption scheme
* Adds the Zhang-Zhang ciphertext-policy attribute-based encryption scheme
* Includes Genise-Micciancio (Eurocrypt'18) lattice trapdoor sampling algorithms and their improvements/generalizations
* Fixes bugs that were brought to our attention

11/26/2018: PALISADE v1.3.1 is released

* Improves performance of BFVrns
* Improves performance of Number Theoretic Transform
* Fixes a bug affecting the demo-cross-correlation demo
* Fixes other bugs that were brought to our attention

10/17/2018: PALISADE v1.3.0 is released

* Added support for the security levels/tables specified by the HomorphicEncryption.org security standard to all variants of the BFV scheme
* Optimized the packed encoding (batching)
* Simplified the signatures of classes and methods at multiple layers
* Fixed bugs that were brought to our attention

6/15/2018: PALISADE v1.2 is released

PALISADE v1.2 provides several important advancements and improvements to the library.  Most notably, we provide:

* The Bajard-Eynard-Hasan-Zucca RNS variant of the BFV scheme is added to the library
* The implementation of the Halevi-Polyakov-Shoup RNS variant of the BFV scheme is significantly improved
* Large multiplicative depths (up to 100 and higher) for both RNS variants are now supported.
* Several low-level optimizations, e.g., in Number Theoretic Transform and NTL multiprecision math backend, are implemented.
* Multiple improvements in plaintext encodings.
* Software engineering improvements: extended batteries of unit tests, cleaner design of the matrix class, better CryptoContext wrapper, etc.
* Fixes for bugs which have been brought to our attention.

1/29/2018: PALISADE v1.1.1 is released

PALISADE v1.1.1 includes bug fixes and minor optimizations:

* Fixes minor bugs in NativeInteger and multiprecision backends (BigInteger)
* Deals properly with a low-probability rounding error in BFVrns
* Fixes a compilation error on some CentOS systems
* Improves the performance of NativeInteger
* Fixes a couple of other minor bugs

12/29/2017: PALISADE v1.1 is released

PALISADE v1.1  includes the following new capabilities, library enhancements, and optimizations:

* New efficient homomorphic scheme: BFVrns
* Newly supported homomorphic operations for multi-depth computations
* Type checking, type safety, and improved error handling
* Faster/more capable Gaussian sampling
* NTL integration as a new option for the multiprecision arithmetic backend
* And more...

07/15/2017: PALISADE v1.0 is released
