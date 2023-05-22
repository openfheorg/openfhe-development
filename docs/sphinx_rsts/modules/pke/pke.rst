General Public Key Encryption (PKE) documentation
=================================================

.. contents:: Page Contents
   :depth: 2
   :local:


File Listings
-----------------------

`Ciphertext (ciphertext.h) <https://github.com/openfheorg/openfhe-development/tree/main/src/pke/include/ciphertext.h>`__

-  for the representation of ciphertext in OpenFHE

-  provides ``CiphertextImpl`` which is used to contain encrypted text

`Ciphertext Serialization (ciphertext-ser.h) <https://github.com/openfheorg/openfhe-development/tree/main/src/pke/include/ciphertext-ser.h>`__

-  exposes serialization methods for ciphertexts to `USCiLab -
   cereal <https://github.com/USCiLab/cereal>`__

-  must be included any time we need ciphertext serialization

`Constants (constants.h) <https://github.com/openfheorg/openfhe-development/tree/main/src/pke/include/constants.h>`__

-  Contains the various constants used throughout the ``PKE`` module

`CryptoContext Factory (cryptocontextfactory.h) <https://github.com/openfheorg/openfhe-development/tree/main/src/pke/include/cryptocontextfactory.h>`__

-  Generates new ``CryptoContexts`` from user parameters

`CryptoContext (cryptocontext.h) <https://github.com/openfheorg/openfhe-development/tree/main/src/pke/include/cryptocontext.h>`__

-  defines ``CryptoContextImpl``, which is used to access the OpenFHE
   library

-  all OpenFHE objects are created “within” a ``CryptoContext`` which
   acts like an object “manager”. Objects can only be used in the
   context they were created in

`CryptoContext Serialization (cryptocontext-ser.h) <https://github.com/openfheorg/openfhe-development/tree/main/src/pke/include/cryptocontext-ser.h>`__

-  exposes serialization methods for ``CryptoContext`` to `USCiLab -
   cereal <https://github.com/USCiLab/cereal>`__

-  must be included any time we need ``CryptoContext`` serialization

`CryptoContext Object (cryptoobject.h) <https://github.com/openfheorg/openfhe-development/tree/main/src/pke/include/cryptoobject.h>`__

-  comprises a ``context``, and ``keytag``:

   -  ``context``: ``CryptoContext`` this object belongs to
   -  ``keytag``: tag that is used to find the evaluation key needed for
      various operations

`CryptoContext Generator (gen-cryptocontext.h) <https://github.com/openfheorg/openfhe-development/tree/main/src/pke/include/gen-cryptocontext.h>`__

-  Constructs ``CryptoContext`` based on the provided set of parameters

`Global Values (globals.h) <https://github.com/openfheorg/openfhe-development/tree/main/src/pke/include/globals.h>`__

-  Global value definitions

`Metadata Container (metadata.h) <https://github.com/openfheorg/openfhe-development/tree/main/src/pke/include/metadata.h>`__

-  metadata container and helper function definition

`Metadata Serialization (metadata-ser.h) <https://github.com/openfheorg/openfhe-development/tree/main/src/pke/include/metadata-ser.h>`__

-  exposes serialization methods for ``Metadata`` to `USCiLab -
   cereal <https://github.com/USCiLab/cereal>`__

-  must be included any time we need ``Metadata`` serialization

`OpenFHE Top-Level Include (openfhe.h) <https://github.com/openfheorg/openfhe-development/tree/main/src/pke/include/openfhe.h>`__

- Top-level ``#include`` for access to all capabilities
