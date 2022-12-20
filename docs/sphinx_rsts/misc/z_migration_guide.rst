How To Migrate A User Project From Palisade To OpenFHE
====================================
This migration guide describes how to migrate user projects from Palisade to OpenFHE using `src/pke/examples/simple-integers.cpp <https://github.com/openfheorg/openfhe-development/blob/main/src/pke/examples/simple-integers.cpp>` as an example.

2 prerequisites for making any changes to simple-integers.cpp:
* install OpenFHE (see instructions `here <https://openfhe-development.readthedocs.io/en/latest/sphinx_rsts/intro/installation/installation.html>`)
* change the CMakeLists.User.txt (see instructions `here <https://github.com/openfheorg/openfhe-development/tree/main/src/pke/examples#how-to-link-your-own-project-after-having-openfhe-installed>`)

Code changes (in src/pke/examples/simple-integers.cpp):

1. Generate CryptoContext (see instructions `here <https://github.com/openfheorg/openfhe-development/tree/main/src/pke/examples#generating-cryptocontext-using-gencryptocontext>`).
You don’t need to set multiple arguments in order to generate CryptoContext anymore. A separate object with parameters is required instead with every parameter having a default value. Set only those parameters that you want to change.
For this example we changed 2 of them:

::

    CCParams<CryptoContextBFVRNS> parameters;
    parameters.SetPlaintextModulus(65537);
    parameters.SetMultiplicativeDepth(2);

All default values can be seen by simply printing the object.
The parameter object is created using a template and for BFV it should be

::

    CCParams<CryptoContextBGVRNS> parameters;

2. All other changes are mostly cosmetic as some functions are renamed. Use:
* KeyPair<DCRTPoly> instead of LPKeyPair<DCRTPoly>
* EvalRotateKeyGen() instead of EvalAtIndexKeyGen()
* EvalRotate() instead of EvalAtIndex()

After you make all the changes mentioned above, you can link and run the example.

Palisade-OpenFHE type mappings and new parameter types
-----------------------------

.. csv-table:: components
   :header: "Palisade", "OpenFHE"

   "Arguments to cryptoContext->Enable()"
   ^^^^^^^^^^^^^^^^^^^^^
   "ENCRYPTION","PKE"
   "PRE","PRE"
   "SHE","LEVELEDSHE"
   "LEVELEDSHE","LEVELEDSHE"
   "ADVANCEDSHE","ADVANCEDSHE"
   "MULTIPARTY","MULTIPARTY"
   "FHE","FHE"
   "MODE","SecretKeyDist"
   ^^^^^^^^^^^^^^^^^^^^^
   "RLWE","GAUSSIAN"
   "OPTIMIZED","UNIFORM_TERNARY"
   "SPARSE","SPARSE_TERNARY"
   "KeySwitchTechnique","KeySwitchTechnique"
   ^^^^^^^^^^^^^^^^^^^^^
   "HYBRID","HYBRID"
   "BV","BV"
   "GHS","No longer supported"
   "RescalingTechnique","ScalingTechnique"
   ^^^^^^^^^^^^^^^^^^^^^
   "APPROXRESCALE","FIXEDMANUAL"
   "APPROXAUTO","FIXEDAUTO"
   "EXACTRESCALE","FLEXIBLEAUTO"
   "","FLEXIBLEAUTOEXT (new)"
   "","NORESCALE (new)"
   "BFV CryptoContext Call","MultiplicationTechnique (BFV only)"
   ^^^^^^^^^^^^^^^^^^^^^
   "genCryptoContextBFVrnsB","BEHZ"
   "genCryptoContextBFVrns","HPS"
   "","HPSPOVERQ (new)"
   "","HPSPOVERQLEVELED (new)"


If your project includes serialization, then the following files are to be included in addition to “openfhe.h”:
1. To serialize ciphertext: #include "ciphertext-ser.h"
2. To serialize cryptocontext: #include "cryptocontext-ser.h"
3. To serialize key(s): #include "key/key-ser.h"
4. … and the scheme-related serialization header file
* for CKKS - #include "scheme/ckksrns/ckksrns-ser.h"
* for BGV - #include "scheme/bgvrns/bgvrns-ser.h"
* for BFV - #include "scheme/bfvrns/bfvrns-ser.h"

See the `difference <https://github.com/openfheorg/openfhe-development/compare/a98984b..e6151ad>` in simple-integers.cpp before and after the migration.

For advanced users: openfhe-genomic-examples before and after the migration
