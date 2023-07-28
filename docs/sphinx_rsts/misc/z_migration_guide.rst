How To Migrate A User Project From Palisade To OpenFHE
======================================================

This migration guide describes how to migrate user projects from Palisade to OpenFHE. The guide uses `src/pke/examples/simple-integers.cpp <https://github.com/openfheorg/openfhe-development/blob/main/src/pke/examples/simple-integers.cpp>`_ as an example.

Before making any changes to `simple-integers.cpp`:

- Install OpenFHE (see instructions `here <https://openfhe-development.readthedocs.io/en/latest/sphinx_rsts/intro/installation/installation.html>`_)

- Change the ``CMakeLists.txt`` for your project: replace all instances of **Palisade** and **PALISADE** with **OpenFHE**

Code changes (in `src/pke/examples/simple-integers.cpp`):

1. Generate CryptoContext (see instructions `here <https://github.com/openfheorg/openfhe-development/tree/main/src/pke/examples#generating-cryptocontext-using-gencryptocontext>`_).
You don’t need to set multiple arguments anymore to generate CryptoContext. A separate parameter object is required instead and every parameter in the object has a default value. So, set only those parameters that you want to change.
For this example, we changed two of them:

::

    // declare the parameter object
    CCParams<CryptoContextBFVRNS> parameters;
    // set the desired parameter values
    parameters.SetPlaintextModulus(65537);
    parameters.SetMultiplicativeDepth(2);

All parameter values can be seen by simply printing the parameter object:

::

    // print all parameters for CryptoContext
    std::cout << parameters << std::endl;

    And you get something similar to this line:
    scheme: BFVRNS; ptModulus: 65537; digitSize: 0; standardDeviation: 3.19; secretKeyDist: UNIFORM_TERNARY; maxRelinSkDeg: 2; ksTech: BV; scalTech: NORESCALE; batchSize: 0; firstModSize: 60; numLargeDigits: 0; multiplicativeDepth:2; scalingModSize: 60; securityLevel: HEStd_128_classic; ringDim: 0; evalAddCount: 0; keySwitchCount: 0; encryptionTechnique: STANDARD; multiplicationTechnique: HPSPOVERQLEVELED; multiHopModSize: 0; PREMode: INDCPA; multipartyMode: FIXED_NOISE_MULTIPARTY; executionMode: EXEC_EVALUATION; decryptionNoiseMode: FIXED_NOISE_DECRYPT; noiseEstimate: 0; desiredPrecision: 0; statisticalSecurity: 30; numAdversarialQueries: 1


The parameter object is created using a template and for BFV it should be

::

    CCParams<CryptoContextBFVRNS> parameters;

2. All other changes are mostly cosmetic as some types and functions were renamed:

- ``KeyPair<DCRTPoly>`` instead of ``LPKeyPair<DCRTPoly>``
- ``EvalRotateKeyGen()`` instead of ``EvalAtIndexKeyGen()``
- ``EvalRotate()`` instead of ``EvalAtIndex()``
- ``GetScheme()`` instead of ``GetEncryptionAlgorithm()``
- ``GetNoiseScaleDeg()`` instead of ``GetDepth()``

After you make all the changes mentioned above, you can link and run the example.

Palisade-OpenFHE type mappings and new parameter types
----------------------------------------------------------

.. list-table::
   :header-rows: 1

   * - In Palisade
     - In OpenFHE
   * - **Arguments to cryptoContext->Enable()**
     -
   * - ENCRYPTION
     - PKE
   * - PRE
     - PRE
   * - SHE
     - LEVELEDSHE
   * - ADVANCEDSHE
     - ADVANCEDSHE
   * - MULTIPARTY
     - MULTIPARTY
   * - FHE
     - FHE
   * - **MODE**
     - **SecretKeyDist**
   * - RLWE
     - GAUSSIAN
   * - OPTIMIZED
     - UNIFORM_TERNARY
   * - SPARSE
     - SPARSE_TERNARY
   * - **KeySwitchTechnique**
     - **KeySwitchTechnique**
   * - HYBRID
     - HYBRID
   * - BV
     - BV
   * - GHS
     - No longer supported
   * - **RescalingTechnique**
     - **ScalingTechnique**
   * - APPROXRESCALE
     - FIXEDMANUAL
   * - APPROXAUTO
     - FIXEDAUTO
   * - EXACTRESCALE
     - FLEXIBLEAUTO
   * -
     - FLEXIBLEAUTOEXT (new)
   * -
     - NORESCALE (new)
   * - **BFV CryptoContext Call**
     - **MultiplicationTechnique (BFV only)**
   * - genCryptoContextBFVrnsB
     - BEHZ
   * - genCryptoContextBFVrns
     - HPS
   * -
     - HPSPOVERQ (new)
   * -
     - HPSPOVERQLEVELED (new)


If your project includes serialization, then the following files should be included in addition to “openfhe.h”:

1. To serialize ciphertext:

::

    #include "ciphertext-ser.h"

2. To serialize cryptocontext:

::

    #include "cryptocontext-ser.h"

3. To serialize key(s):

::

    #include "key/key-ser.h"

4. … and the scheme-related serialization header file

- for CKKS

::

    #include "scheme/ckksrns/ckksrns-ser.h"
- for BGV

::

    #include "scheme/bgvrns/bgvrns-ser.h"
- for BFV

::

    #include "scheme/bfvrns/bfvrns-ser.h"

See the `code difference <https://github.com/openfheorg/migration/compare/dd717a0..a4629a8?diff=split>`_ in ``simple-integers.cpp`` before and after the migration.

**For advanced users:** see the `code difference <https://github.com/openfheorg/migration/compare/b25e60e..6b01291?diff=split>`_ in ``openfhe-genomic-examples`` before and after the migration.
