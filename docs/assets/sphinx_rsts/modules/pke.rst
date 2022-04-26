General Public Key Encryption (PKE) documentation
=================================================

File Listings
-----------------------

`ciphertext.h <https://github.com/openfheorg/openfhe-development/tree/main/src/pke/include/ciphertext.h>`__

-  for the representation of ciphertext in OpenFHE

-  provides ``CiphertextImpl`` which is used to contain encrypted text

`ciphertext-ser.h <https://github.com/openfheorg/openfhe-development/tree/main/src/pke/include/ciphertext-ser.h>`__

-  exposes serialization methods for ciphertexts to `USCiLab -
   cereal <https://github.com/USCiLab/cereal>`__

-  must be included any time we need ciphertext serialization

`constants.h <https://github.com/openfheorg/openfhe-development/tree/main/src/pke/include/constants.h>`__

-  Contains the various constants used throughout the ``PKE`` module
   including:

   -  PKE Scheme Feature: Lists all features supported by PKE schemees.

      -  PKE (PKE)
      -  Keyswitch (KEYSWITCH)
      -  proxy-reencryption (PRE)
      -  Leveled Somewhat Homomorphic Encryption (LEVELED SHE)
      -  Advanced Somewhat Homomorphic Encryption (ADVANCEDSHE)
      -  Threshold FHE (MULTIPARTY)
      -  Fully Homomorphic Encryption (FHE)

   -  MODE

      -  Ring Learning with Error (RLWE)
      -  Optimized (OPTIMIZED)
      -  Sparse (sparse)

   -  Rescaling Technique

      -  Fixed Manual (FIXEDMANUAL)
      -  Fixed Auto (FIXEDAUTO)
      -  Flexible Auto (FLEXIBLEAUTO)
      -  No Rescaling (NORESCALE)

   -  Key Switch Technique

      -  BV (See `Fully Homomorphic Encryption from Ring-LWE and
         Security for Key Dependent Messages (BV
         Scheme) <https://www.wisdom.weizmann.ac.il/~zvikab/localpapers/IdealHom.pdf>`__)
      -  Hybrid (See `Homomorphic Evaluation of the AES
         Circuit <https://eprint.iacr.org/2012/099.pdf>`__)

   -  Encryption Technique

      -  Standard (STANDARD)
      -  P Over Q (POVERQ)

   -  Multiplication Technique

      -  Bajard-Eynard-Hasan-Zucca (BEHZ)
      -  Halevi-Polyakov-Shoup (HPS)
      -  Halevi-Polyakov-Shoup P over Q (HPSPOVERQ)
      -  Halevi-Polyakov-Shoup P over Q Leveled Multiplication
         (HPSPOVERQLEVELED)

`cryptocontextfactory.h <https://github.com/openfheorg/openfhe-development/tree/main/src/pke/include/cryptocontextfactory.h>`__

-  Generates new ``CryptoContexts`` from user parameters

`cryptocontextgen.h <https://github.com/openfheorg/openfhe-development/tree/main/src/pke/include/cryptocontextgen.h>`__

-  ``Cryptocontext`` generator for the various PKE schemes (notably
   ``BFV``, ``BGV``, and ``CKKS`` in their ``RNS`` forms)

`cryptocontext.h <https://github.com/openfheorg/openfhe-development/tree/main/src/pke/include/cryptocontext.h>`__

-  defines ``CryptoContextImpl``, which is used to access the OpenFHE
   library

-  all OpenFHE objects are created “within” a ``CryptoContext`` which
   acts like an object “manager”. Objects can only be used in the
   context they were created in

`cryptocontexthelper.h <https://github.com/openfheorg/openfhe-development/tree/main/src/pke/include/cryptocontexthelper.h>`__

-  provides helper functions to print out the parameter sets

`cryptocontextparametersets.h <https://github.com/openfheorg/openfhe-development/tree/main/src/pke/include/cryptocontextparametersets.h>`__

-  defines the parameter sets for ``CryptoContexts``

`cryptocontext-ser.h <https://github.com/openfheorg/openfhe-development/tree/main/src/pke/include/cryptocontext-ser.h>`__

-  exposes serialization methods for ``CryptoContext`` to `USCiLab -
   cereal <https://github.com/USCiLab/cereal>`__

-  must be included any time we need ``CryptoContext`` serialization

`cryptoobject.h <https://github.com/openfheorg/openfhe-development/tree/main/src/pke/include/cryptoobject.h>`__

-  comprises a ``context``, and ``keytag``:

   -  ``context``: ``CryptoContext`` this object belongs to
   -  ``keytag``: tag that is used to find the evaluation key needed for
      various operations

`gen-cryptocontext.h <https://github.com/openfheorg/openfhe-development/tree/main/src/pke/include/gen-cryptocontext.h>`__

-  Constructs ``CryptoContext`` based on the provided set of parameters

`globals.h <https://github.com/openfheorg/openfhe-development/tree/main/src/pke/include/globals.h>`__

-  Global value definitions

`metadata.h <https://github.com/openfheorg/openfhe-development/tree/main/src/pke/include/metadata.h>`__

-  metadata container and helper function definition

`metadata-ser.h <https://github.com/openfheorg/openfhe-development/tree/main/src/pke/include/metadata-ser.h>`__

-  exposes serialization methods for ``Metadata`` to `USCiLab -
   cereal <https://github.com/USCiLab/cereal>`__

-  must be included any time we need ``Metadata`` serialization

`openfhe.h <https://github.com/openfheorg/openfhe-development/tree/main/src/pke/include/openfhe.h>`__

-  top level for ease of import

PKE Generated Docs
--------------------------------

.. autodoxygenindex::
   :project: pke
