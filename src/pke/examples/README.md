OpenFHE Lattice Cryptography Library - Examples
=============================================

[License Information](License.md)

Document Description
===================
This document describes the examples included with the OpenFHE lattice crypto library.

Examples Directory Description
==========================

Directory Objective
-------------------
This directory contains examples that, when linked with the library, demonstrate the capabilities of the system

File Listing
------------

*Example programs*

- [advanced-ckks-bootstrapping.cpp](advanced-ckks-bootstrapping.cpp): an example showing CKKS bootstrapping for a ciphertext with sparse packing
- [advanced-real-numbers.cpp](advanced-real-numbers.cpp): shows several advanced examples of approximate homomorphic encryption using CKKS
- [advanced-real-numbers-128.cpp](advanced-real-numbers-128.cpp): shows several advanced examples of approximate homomorphic encryption using high-precision CKKS
- [ckks-noise-flooding.cpp](ckks-noise-flooding.cpp): demonstrates use of experimental feature NOISE_FLOODING_DECRYPT mode in CKKS, which enhances security
- [depth-bfvrns.cpp](depth-bfvrns.cpp): demonstrates use of the BFVrns scheme for basic homomorphic encryption
- [depth-bfvrns-behz.cpp](depth-bfvrns-behz.cpp): demonstrates use of the BEHZ BFV variant for basic homomorphic encryption
- [depth-bgvrns.cpp](depth-bgvrns.cpp): demonstrates use of the BGVrns scheme for basic homomorphic encryption
- [function-evaluation.cpp](function-evaluation.cpp): demonstrates the evaluation of a non-polynomial function using a Chebyshev approximation using CKKS
- [inner-product.cpp](inner-product.cpp): demonstrates the evaluation of inner product using CKKS and BFV
- [interactive-bootstrapping.cpp](interactive-bootstrapping.cpp): two examples of $2$-party interactive bootstrapping (the second one is with Chebyshev interpolation)
- [iterative-ckks-bootstrapping.cpp](iterative-ckks-bootstrapping.cpp): demonstrates how to run multiple iterations of CKKS bootstrapping to improve precision
- [iterative-ckks-bootstrapping-composite-scaling.cpp](iterative-ckks-bootstrapping-composite-scaling.cpp): double-precision CKKS bootstrapping in the CKKS composite scaling mode
- [linearwsum-evaluation.cpp](linearwsum-evaluation.cpp): demonstrates the evaluation of a linear weighted sum using CKKS
- [polynomial-evaluation.cpp](polynomial-evaluation.cpp): demonstrates an evaluation of a polynomial (power series) using CKKS
- [polynomial-evaluation-high-precision-composite-scaling.cpp](polynomial-evaluation-high-precision-composite-scaling.cpp): high-precision (80-bit scaling factor) power series evaluation in the CKKS composite scaling mode
- [pre-buffer.cpp](pre-buffer.cpp): demonstrates use of OpenFHE for encryption, re-encryption and decryption of packed vector of binary data
- [pre-hra-secure.cpp](pre-hra-secure.cpp): shows examples of HRA-secure PRE based on BGV
- [rotation.cpp](rotation.cpp): demonstrates use of EvalRotate for different schemes
- [scheme-switching.cpp](scheme-switching.cpp): demonstrates several use cases for switching between CKKS and FHEW ciphertexts
- [scheme-switching-serial.cpp](scheme-switching-serial.cpp): provides an example of CKKS <-> FHEW scheme switching with serialization
- [simple-ckks-bootstrapping.cpp](simple-ckks-bootstrapping.cpp): simple example showing CKKS bootstrapping for a ciphertext with full packing
- [simple-ckks-bootstrapping-composite-scaling.cpp](simple-ckks-bootstrapping-composite-scaling.cpp): single-precision CKKS bootstrapping in the CKKS composite scaling mode
- [simple-complex-numbers.cpp.cpp](simple-complex-numbers.cpp): leveled FHE and bootstrapping examples for CKKS over complex numbers
- [simple-integers.cpp](simple-integers.cpp): simple example showing homomorphic additions, multiplications, and rotations for vectors of integers using BFVrns
- [simple-integers-bgvrns.cpp](simple-integers-bgvrns.cpp): simple example showing homomorphic additions, multiplications, and rotations for vectors of integers using BGV
- [simple-integers-serial.cpp](simple-integers-serial.cpp): simple example showing typical serialization/deserialization calls for a prototype computing homomorphic additions, multiplications, and rotations for vectors of integers using BFVrns
- [simple-integers-serial-bgvrns.cpp](simple-integers-serial-bgvrns.cpp): simple example showing typical serialization/deserialization calls for a prototype computing homomorphic additions, multiplications, and rotations for vectors of integers using BGV
- [simple-real-numbers.cpp](simple-real-numbers): simple example showing homomorphic additions, multiplications, and rotations for vectors of real numbers using CKKS
- [simple-real-numbers-composite-scaling.cpp](simple-real-numbers-composite-scaling.cpp): basic CKKS arithmetic in the CKKS composite scaling mode
- [simple-real-numbers-serial.cpp](simple-real-numbers-serial.cpp): simple example showing typical serialization/deserialization calls for a prototype computing homomorphic additions, multiplications, and rotations for vectors of integers using CKKS
- [tckks-interactive-mp-bootstrapping.cpp](tckks-interactive-mp-bootstrapping.cpp): an example of $n$-party interactive bootstrapping
- [tckks-interactive-mp-bootstrapping-Chebyshev.cpp](tckks-interactive-mp-bootstrapping-Chebyshev.cpp): an example of $n$-party interactive bootstrapping with Chebyshev interpolation
- [threshold-fhe.cpp](threshold-fhe.cpp): shows several examples of threshold FHE in BGV, BFV, and CKKS
- [threshold-fhe-5p.cpp](threshold-fhe-5p.cpp): shows example of threshold FHE with 5 parties in BFV

How To Link Your Own Project After Having OpenFHE Installed
===================
1. Check that you do not get error messages at the time of running "make install" for OpenFHE. You may need the admin rights to install.
2. Go to a new directory where you will keep "my_own_project.cpp" file.
3. Copy openfhe-development/CMakeLists.User.txt to the new directory and rename it to CMakeLists.txt.
4. Open CMakeLists.txt for editing and add a line to its end as suggested in the comments in CMakeLists.txt. Something like this:
```
    add_executable( test my_own_project.cpp)
```
5. ... and after that, execute commands that are very similar to the commands to build and run examples in OpenFHE:
```
    mkdir build
    cd build
    cmake ..
    make
    and, finally, run ./my_own_project
```

Generating Cryptocontext using GenCryptoContext()
===================
1. Pick the scheme you want to use. I chose CKKS for our tutorial example.
2. Include openfhe.h\
    **NOTE for OpenFHE contributors**\
    Instead of including openfhe.h, your code should include gen-cryptocontext.h and the header with the scheme-specific context generator (scheme/<scheme>/cryptocontext-<scheme>.h). Example:
```
    #include "scheme/ckks/cryptocontext-ckks.h"
    #include "gen-cryptocontext.h"
```
3. Create a parameter object to be passed to GenCryptoContext(). Its generic form would look like this: CCParams<GeneratorName> parameters where GeneratorName is the name of the class defined in cryptocontext-<scheme>.h. In our case it is CryptoContextCKKS and the line to add is
```
    CCParams<CryptoContextCKKS<Element>> parameters;
    // std::cout << parameters << std::endl;  // prints all parameter values
```
4. Adjust the parameters' values with set functions for CCParams<CryptoContextCKKS> as the object is created using default values from scheme/cryptocontextparams-defaults.h. The set functions can be found in scheme/cryptocontextparams-base.h. For example, we can set the multiplicative depth to be 1 as shown below.
```
    parameters.SetMultiplicativeDepth(1);
```
5. Call GenCryptoContext() to generate the cryptocontext.
```
    auto cryptoContext = GenCryptoContext(parameters);
```
6. Enable the features that we want to use. For example, if we want to perform an encrypted rotation, then we need encryption, key switching, and leveled somewhat homomorphic encryption (SHE) operations.
```
    cryptoContext->Enable(ENCRYPTION);
    cryptoContext->Enable(KEYSWITCH);
    cryptoContext->Enable(LEVELEDSHE);
```

Now your code should look like this:
```
    #include "openfhe.h
    ...........................................
    CCParams<CryptoContextCKKS> parameters;
    parameters.SetMultiplicativeDepth(1);
    parameters.SetScalingModSize(50);
    parameters.SetBatchSize(8);
    parameters.SetSecurityLevel(HEStd_NotSet);
    parameters.SetRingDim(16);

    auto cryptoContext = GenCryptoContext(parameters);

    cryptoContext->Enable(ENCRYPTION);
    cryptoContext->Enable(KEYSWITCH);
    cryptoContext->Enable(LEVELEDSHE);
    ...........................................
```

## Description of the CryptoContext parameters and their restrictions
Choosing the CryptoContext parameters is important for obtaining the best performance for your encrypted application, while maintaining the desired level of security. We strongly recommend that you specify the security level and have OpenFHE automatically select the other parameters, unless you are an expert in homomorphic encryption. If you would like to modify the parameters to understand how they affect noise growth and performance, we provide descriptions below.

The default values for all the parameters can be found in [gen-cryptocontext-params-defaults.h](../include/scheme/gen-cryptocontext-params-defaults.h)

If the set function is called for a parameter which is not available for the given scheme, then an exception will be thrown at run-time.

**PlaintextModulus ptModulus (BGV/BFV only)** - impacts noise growth and has to be set by user as it can not be zero. The set method is `SetPlaintextModulus`.

**uint32_t digitSize** - used in digit decomposition and impacts noise growth. The set method is `SetDigitSize`.

**float standardDeviation** - error distribution parameter (recommended for advanced users), used for Gaussian error generation. The set method is `SetStandardDeviation`.

**SecretKeyDist secretKeyDist** - secret key distribution: GAUSSIAN, UNIFORM_TERNARY, SPARSE_TERNARY. The set method is `SetSecretKeyDist`.

**uint32_t maxRelinSkDeg** - max relinearization degree of secret key polynomial (used for lazy relinearization). The set method is `SetMaxRelinSkDeg`.

**KeySwitchTechnique ksTech**:  BV or HYBRID. The set method is `SetKeySwitchTechnique`.
- For BV, we do not have extra modulus, so the security depends on ciphertext modulus Q
- For BV, we need digitSize - digit size in digit decomposition
- For HYBRID, we do have an extra modulus P, so the security depends on modulus P*Q
- For HYBRID, we need numLargeDigits - number of digits in digit decomposition

**ScalingTechnique scalTech (CKKS/BGV only)** - rescaling/modulus switching technique: FIXEDMANUAL, FIXEDAUTO, FLEXIBLEAUTO, FLEXIBLEAUTOEXT, COMPOSITESCALINGAUTO (CKKS only), COMPOSITESCALINGMANUAL (CKKS only). NORESCALE is not allowed (used for BFV internally). See https://eprint.iacr.org/2022/915 for additional details. The set method is `SetScalingTechnique`.

**uint32_t batchSize** - max batch size of messages to be packed in encoding (number of slots). The set method is `SetBatchSize`.

**ProxyReEncryptionMode PREMode** - PRE security mode IND-CPA, FIXED_NOISE_HRA. NOISE_FLOODING_HRA supported only in BGV for scaleTech=FIXEDMANUAL. The set method is `SetPREMode`.

**MultipartyMode multipartyMode (BFV/BGV only)** - multiparty security mode. The NOISE_FLOODING_MULTIPARTY mode adds extra noise and gives enhanced security compared to the FIXED_NOISE_MULTIPARTY mode. Not available for CKKS, but FIXED_NOISE_MULTIPARTY is used for CKKS internally. The set method is `SetMultipartyMode`.

**DecryptionNoiseMode decryptionNoiseMode (CKKS only)** - NOISE_FLOODING_DECRYPT mode is more secure (provable secure) than FIXED_NOISE_DECRYPT, but it requires executing all computations twice. The set method is `SetPREMode`.

**ExecutionMode executionMode (CKKS only)** - The execution mode is only used in NOISE_FLOODING_DECRYPT mode. The set method is `SetExecutionMode`.
- EXEC_NOISE_ESTIMATION - we estimate the noise we need to add to the actual computation to guarantee good security.
- EXEC_EVALUATION - we input our noise estimate and perform the desired secure encrypted computation.
- Although not available for BGV/BFV, EXEC_EVALUATION is used for these schemes internally.

**double noiseEstimate (CKKS only)** - This estimate is obtained from running the computation in EXEC_NOISE_ESTIMATION mode. It is only used in the NOISE_FLOODING_DECRYPT mode. The set method is `SetNoiseEstimate`.

**double desiredPrecision (CKKS only)** - desired precision for 128-bit CKKS. We use this value in NOISE_FLOODING_DECRYPT mode to determine the scaling factor. The set method is `SetDesiredPrecision`.

**uint32_t statisticalSecurity (BGV/CKKS only)** - statistical security of CKKS in NOISE_FLOODING_DECRYPT mode. This is the bound on the probability of success that any adversary can have. Specifically, they have a probability of success of at most 2^(-statisticalSecurity). Used for BGV when PREMode=NOISE_FLOODING_HRA and for CKKS when multipartyMode=NOISE_FLOODING_MULTIPARTY. The set method is `SetStatisticalSecurity`.

**uint32_t numAdversarialQueries (BGV/CKKS only)** - this is the number of adversarial queries a user is expecting for their application, which we use to ensure security of CKKS in NOISE_FLOODING_DECRYPT mode. Used for BGV when PREMode=NOISE_FLOODING_HRA and for CKKS when multipartyMode=NOISE_FLOODING_MULTIPARTY. The set method is `SetNumAdversarialQueries`.

**uint32_t thresholdNumOfParties (BGV/BFV only)** - number of parties in a threshold application, which is used for the bound on the joint secret key. The set method is `SetThresholdNumOfParties`.

**uint32_t firstModSize (CKKS/BGV only) and uint32_t scalingModSize** - are used to calculate ciphertext modulus. The ciphertext modulus should be seen as: Q = q_0 * q_1 * ... * q_n * q':
- q_0 is first prime, and it's number of bits is firstModSize
- q_i have same number of bits and is equal to scalingModSize
- the prime q' is not explicitly given, but it is used internally in CKKS and BGV schemes (in *EXT scaling methods)
- **firstModSize** is allowed for BGV with **scalTech = FIXEDMANUAL** only
- **scalingModSize** is allowed for BGV with **scalTech = FIXEDMANUAL** and **scalingModSize** must be < 60 for CKKS and NATIVEINT=64
- **firstModSize and scalingModSize** are not available for BGV if PREMode=NOISE_FLOODING_HRA.

The set method is `SetFirstModSize`.

**uint32_t numLargeDigits** - number of digits in HYBRID key switching (see KeySwitchTechnique). The set method is `SetNumLargeDigits`.

**uint32_t multiplicativeDepth** - the maximum number of multiplications (in a binary tree manner) we can perform before bootstrapping. Must be 0 for BGV if PREMode=NOISE_FLOODING_HRA. The set method is `SetMultiplicativeDepth`.

**SecurityLevel securityLevel** - We use the values from the security standard at http://homomorphicencryption.org/wp-content/uploads/2018/11/HomomorphicEncryptionStandardv1.1.pdf for ring dimensions up to 32K, and from https://cic.iacr.org/p/1/4/26/pdf for 64K and 128K. Given the ring dimension and security level, we have upper bound of possible highest modulus (Q for BV or P*Q for HYBRID). The set method is `SetSecurityLevel`.

**uint32_t ringDim** - ring dimension N of the scheme : the ring is Z_Q[x] / (X^N+1). Must be > 0 for BGV if PREMode=NOISE_FLOODING_HRA. The set method is `SetRingDim`.

**uint32_t evalAddCount (BGV/BFV only)** - maximum number of additions (used for setting noise). In BGV, it is the maximum number of additions at any level. The set method is `SetEvalAddCount`.

**EncryptionTechnique encryptionTechnique (BFV only)** - STANDARD or EXTENDED mode for BFV encryption; EXTENDED slightly reduces the size of Q (by few bits) but makes encryption somewhat slower (see https://eprint.iacr.org/2022/915 for details). Although not available for CKKS/BGV, STANDARD is used for these 2 schemes internally. The set method is `SetEncryptionTechnique`.

**MultiplicationTechnique multiplicationTechnique (BFV only)** - multiplication method in BFV: BEHZ, HPS, HPSPOVERQ, HPSPOVERLEVELED (see https://eprint.iacr.org/2022/915 for details). The set method is `SetMultiplicationTechnique`.

**uint32_t keySwitchCount (BGV/BFV only)** - maximum number of key switching operations (used for setting noise). The set method is `SetKeySwitchCount`.

**uint32_t PRENumHops (BGV only)** - number of hops supported for PRE in the provable HRA setting:
- used only with multipartyMode=NOISE_FLOODING_MULTIPARTY
- if PREMode=NOISE_FLOODING_HRA, then **PRENumHops** must be > 0

The set method is `SetPRENumHops`.

**COMPRESSION_LEVEL interactiveBootCompressionLevel (CKKS only)** - interactive multi-party bootstrapping parameter which sets the compression level in ciphertext to SLACK (has weaker security assumption, thus less efficient) or COMPACT (has stronger security assumption, thus more efficient).  The set method is `SetInteractiveBootCompressionLevel`.

**uint32_t registerWordSize (CKKS only)** - register word size for the CKKS composite scaling mode (should match the hardware architecture on which the FHE computation will be run). The word size should be between 20 and 64. The actual moduli are determined by evenly splitting the scaling factor into approximately equal moduli, which cannot be not higher than the register word size. The set method is `SetRegisterWordSize`.

**uint32_t compositeDegree (CKKS only)** - specifies how many words should be used to represent the CKKS scaling factor in the CKKS composite scaling mode. This setting is only used for the COMPOSITESCALINGMANUAL scaling techique. The supported values are 1, 2, 3, and 4. The set method is `SetCompositeDegree`.

**CKKSDataType ckksDataType (CKKS only)** - defines the CKKS data type: COMPLEX (for complex numbers) or REAL (for real numbers). If the mode is COMPLEX, dynamic noise estimation is disabled; and the user has to set the noise using SetNoiseEstimate if $IND-CPA^D$ security is desired. If the mode is REAL, the dynamic noise is estimated using the imaginary component (OpenFHE works the same way as in version below 1.3.0). The set method is `SetCKKSDataType`.
