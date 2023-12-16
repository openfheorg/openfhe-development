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
- [iterative-ckks-bootstrapping.cpp](iterative-ckks-bootstrapping.cpp): demonstrates how to run multiple iterations of CKKS bootstrapping to improve precision
- [linearwsum-evaluation.cpp](linearwsum-evaluation.cpp): demonstrates the evaluation of a linear weighted sum using CKKS
- [function-evaluation.cpp](function-evaluation.cpp): demonstrates the evaluation of a non-polynomial function using a Chebyshev approximation using CKKS
- [polynomial-evaluation.cpp](polynomial-evaluation.cpp): demonstrates an evaluation of a polynomial (power series) using CKKS
- [pre-buffer.cpp](pre-buffer.cpp): demonstrates use of OpenFHE for encryption, re-encryption and decryption of packed vector of binary data
- [rotation.cpp](rotation.cpp): demonstrates use of EvalRotate for different schemes
- [scheme-switching.cpp](scheme-switching.cpp): demonstrates several use cases for switching between CKKS and FHEW ciphertexts
- [simple-ckks-bootstrapping.cpp](simple-ckks-bootstrapping.cpp): simple example showing CKKS bootstrapping for a ciphertext with full packing
- [simple-integers.cpp](simple-integers.cpp): simple example showing homomorphic additions, multiplications, and rotations for vectors of integers using BFVrns
- [simple-integers-bgvrns.cpp](simple-integers-bgvrns.cpp): simple example showing homomorphic additions, multiplications, and rotations for vectors of integers using BGVrns
- [simple-integers-serial.cpp](simple-integers-serial.cpp): simple example showing typical serialization/deserialization calls for a prototype computing homomorphic additions, multiplications, and rotations for vectors of integers using BFVrns
- [simple-integers-serial-bgvrns.cpp](simple-integers-serial-bgvrns.cpp): simple example showing typical serialization/deserialization calls for a prototype computing homomorphic additions, multiplications, and rotations for vectors of integers using BGVrns
- [simple-real-numbers.cpp](simple-real-numbers): simple example showing homomorphic additions, multiplications, and rotations for vectors of real numbers using CKKS
- [simple-real-numbers-serial.cpp](simple-real-numbers-serial.cpp): simple example showing typical serialization/deserialization calls for a prototype computing homomorphic additions, multiplications, and rotations for vectors of integers using CKKS
- [threshold-fhe.cpp](threshold-fhe.cpp): shows several examples of threshold FHE in BGVrns, BFVrns, and CKKSrns
- [threshold-fhe-5p.cpp](threshold-fhe-5p.cpp): shows example of threshold FHE with 5 parties in BFVrns

How To Link Your Own Project After Having OpenFHE Installed
===================
1. Check that you do not get error messages at the time of running "make install" for OpenFHE. You may need the admin rights to install.
2. Go to a new directory where you will keep “my_own_project.cpp” file.
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

## Description of the CryptoContext parameters
Choosing the CryptoContext parameters is important for obtaining the best performance for your encrypted application, while maintaining the desired level of security. We strongly recommend that you specify the security level and have OpenFHE automatically select the other parameters, unless you are an expert in homomorphic encryption. If you would like to modify the parameters to understand how they affect noise growth and performance, we provide descriptions below.

The default values for all the parameters can be found in [gen-cryptocontext-params-defaults.h](../include/scheme/gen-cryptocontext-params-defaults.h)

**PlaintextModulus ptModulus** - plaintext modulus(for BGV/BFV), which impacts noise growth

**usint digitSize** - for BV key switching only (when KeySwitchTechnique = BV). We use digit size in digit decomposition, which impacts noise growth

**float standardDeviation** - used for Gaussian error generation

**SecretKeyDist secretKeyDist** - secret key distribution: GAUSSIAN, UNIFORM_TERNARY, etc.

**usint maxRelinSkDeg** - max relinearization degree of secret key polynomial (used for lazy relinearization)

**KeySwitchTechnique ksTech (BV or HYBRID currently)**:
- For BV we do not have extra modulus, so the security depends on ciphertext modulus Q
- For BV we need digitSize - digit size in digit decomposition
- For HYBRID we do have extra modulus P, so the security depends on modulus P*Q
- For HYBRID we need numLargeDigits - number of digits in digit decomposition

**ScalingTechnique scalTech (for CKKS/BGV)** - rescaling/modulus switching technique FLEXIBLEAUTOEXT, FIXEDMANUAL, FLEXIBLEAUTO, etc. see https://eprint.iacr.org/2022/915 for additional details

**usint batchSize** - max batch size of messages to be packed in encoding (number of slots)

**ProxyReEncryptionMode PREMode** - PRE security mode IND-CPA, FIXED_NOISE_HRA, etc

**MultipartyMode multipartyMode** - multiparty security mode in BFV/BGV. The NOISE_FLOODING_MULTIPARTY mode adds extra noise and gives enhanced security compared to the FIXED_NOISE_MULTIPARTY mode

**DecryptionNoiseMode decryptionNoiseMode** - decryption noise mode in CKKS. NOISE_FLOODING_DECRYPT mode is more secure than FIXED_NOISE_DECRYPT, but it requires executing all computations twice

**ExecutionMode executionMode** - execution mode in CKKS. The execution mode is only used in NOISE_FLOODING_DECRYPT mode:
- EXEC_NOISE_ESTIMATION - we estimate the noise we need to add to the actual computation to guarantee good security
- EXEC_EVALUATION - we input our noise estimate and perform the desired secure encrypted computation

**double noiseEstimate** -  noise estimate in CKKS. This estimate is obtained from running the computation in EXEC_NOISE_ESTIMATION mode. It is only used in NOISE_FLOODING_DECRYPT mode

**double desiredPrecision** - desired precision for 128-bit CKKS. We use this value in NOISE_FLOODING_DECRYPT mode to determine the scaling factor

**uint32_t statisticalSecurity** - statistical security of CKKS in NOISE_FLOODING_DECRYPT mode. This is the bound on the probability of success that any adversary can have. Specifically, they have a probability of success of at most 2^(-statisticalSecurity)

**uint32_t numAdversarialQueries** - this is the number of adversarial queries a user is expecting for their application, which we use to ensure security of CKKS in NOISE_FLOODING_DECRYPT mode

**usint firstModSize and usint scalingModSize** - are used to calculate ciphertext modulus. The ciphertext modulus should be seen as: Q = q_0 * q_1 * ... * q_n * q':
- q_0 is first prime, and it's number of bits is firstModSize
- q_i have same number of bits and is equal to scalingModSize
- the prime q' is not explicitly given, but it is used internally in CKKS and BGV schemes (in *EXT scaling methods)

**usint numLargeDigits** - number of digits in HYBRID key switching (see KeySwitchTechnique)

**usint multiplicativeDepth** - the maximum number of multiplication we can perform before bootstrapping

**SecurityLevel securityLevel** - We use the values from the security standard at http://homomorphicencryption.org/wp-content/uploads/2018/11/HomomorphicEncryptionStandardv1.1.pdf. For given ring dimension and security level we have upper bound of possible highest modulus (Q for BV or P*Q for HYBRID)

**usint ringDim** - ring dimension N of the scheme : the ring is Z_Q[x] / (X^N+1)

**usint evalAddCount** - number of additions (used for setting noise in BGV and BFV)

**usint keySwitchCount** - number of key switching operations (used for setting noise in BGV and BFV)

**usint multiHopModSize** - size of moduli used for PRE in the provable HRA setting

**EncryptionTechnique encryptionTechnique** - STANDARD or EXTENDED mode for BFV encryption; EXTENDED slightly reduces the size of Q (by few bits) but makes encryption somewhat slower (see https://eprint.iacr.org/2022/915 for details)

**MultiplicationTechnique multiplicationTechnique** - multiplication method in BFV: BEHZ, HPS, etc. (see https://eprint.iacr.org/2022/915 for details)
