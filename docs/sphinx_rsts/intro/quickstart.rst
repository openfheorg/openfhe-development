.. _quickstart:

Examples
====================================

OpenFHE provides the following examples which should provide the reader with a basic understanding of how to use the
library for various purposes.


.. contents:: Page Contents
   :local:


Boolean FHE
----------------------------

`Boolean Fully Homomorphic Encryption Examples <https://github.com/openfheorg/openfhe-development/tree/main/src/binfhe/examples>`_

At a high level:

-  `boolean.cpp: GINX (CGGI) Bootstrapping <https://github.com/openfheorg/openfhe-development/tree/main/src/binfhe/examples/boolean.cpp>`__:

   -  bootstrapping as described in `TFHE: Fast Fully Homomorphic
      Encryption over the Torus <https://eprint.iacr.org/2018/421>`__
      and in `Bootstrapping in FHEW-like
      Cryptosystems <https://eprint.iacr.org/2020/086.pdf>`__


-  `boolean-ap.cpp: AP (DM) Bootstrapping <https://github.com/openfheorg/openfhe-development/tree/main/src/binfhe/examples/boolean-ap.cpp>`__:

   -  bootstrapping as described in `FHEW: Bootstrapping Homomorphic
      Encryption in less than a
      second <https://eprint.iacr.org/2014/816.pdf>`__ and in
      `Bootstrapping in FHEW-like
      Cryptosystems <https://eprint.iacr.org/2020/086.pdf>`__

-  `boolean-lmkcdey.cpp: LMKCDEY Bootstrapping <https://github.com/openfheorg/openfhe-development/tree/main/src/binfhe/examples/boolean-lmkcdey.cpp>`__:

   -  bootstrapping as described in `Efficient FHEW Bootstrapping with Small Evaluation Keys, and
      Applications to Threshold Homomorphic Encryption <https://eprint.iacr.org/2022/198.pdf>`__

-  `boolean-serial-binary.cpp: Boolean Serialization <https://github.com/openfheorg/openfhe-development/tree/main/src/binfhe/examples/boolean-serial-binary.cpp>`_:

   - serializing ``CryptoContext``, various keys, and ciphertext to a file in binary format


-  `boolean-serial-json.cpp: Boolean Serialization - json <https://github.com/openfheorg/openfhe-development/tree/main/src/binfhe/examples/boolean-serial-json.cpp>`_:

   - serializing ``CryptoContext``, various keys, and ciphertext to a file in json format


-  `boolean-truth-tables.cpp: Boolean Truth Tables <https://github.com/openfheorg/openfhe-development/tree/main/src/binfhe/examples/boolean-truth-tables.cpp>`_:

   -  prints out the truth tables for all supported binary gates


-  `eval-decomp.cpp: Eval Decomposition <https://github.com/openfheorg/openfhe-development/tree/main/src/binfhe/examples/eval-decomp.cpp>`_:

   -  runs a homomorphic digit decomposition process on the input ciphertext


-  `eval-flooring.cpp: Eval Flooring <https://github.com/openfheorg/openfhe-development/tree/main/src/binfhe/examples/eval-flooring.cpp>`_:

   -  rounds down the input ciphertext by certain number of bits


-  `eval-function.cpp: Eval Function <https://github.com/openfheorg/openfhe-development/tree/main/src/binfhe/examples/eval-function.cpp>`_:

   -  evaluates a function *f: Z_p -> Z_p* on the input ciphertext


-  `eval-sign.cpp: Eval Sign <https://github.com/openfheorg/openfhe-development/tree/main/src/binfhe/examples/eval-sign.cpp>`_:

   -  evaluates the most-significant bit of the input ciphertext


Core
----------------------------

`Core OpenFHE Examples <https://github.com/openfheorg/openfhe-development/tree/main/src/core/examples>`_:

- `parallel.cpp <https://github.com/openfheorg/openfhe-development/blob/main/src/core/examples/parallel.cpp>`_:

  - provides an example of parallelization in ``OpenFHE`` with `OpenMP <https://www.openmp.org/>`_


- `sampling <https://github.com/openfheorg/openfhe-development/blob/main/src/core/examples/sampling.cpp>`_:

  - provides an example of doing integer Gaussian sampling using `OpenFHE samplers <https://github.com/openfheorg/openfhe-development/tree/main/src/core/include/math>`_.

  - For more information on sampling, read :ref:`sampling documentation <sampling>`


PKE - SIMD FHE
----------------------------

`SIMD Fully Homomorphic Encryption Examples <https://github.com/openfheorg/openfhe-development/tree/main/src/pke/examples>`_:

Basic Homomorphic Encryption
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Demonstrates basic homomorphic encryption using the various schemes:

- `BFVrns (depth-bfvrns.cpp) <https://github.com/openfheorg/openfhe-development/blob/main/src/pke/examples/depth-bfvrns.cpp>`_

- `BGVrns depth-bgvrns.cpp <https://github.com/openfheorg/openfhe-development/blob/main/src/pke/examples/depth-bgvrns.cpp>`_


Simple Mathematical Operations and Serialization
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Demonstrates the following mathematical operations on vectors of appropriate type (integers in the case of `BGV` and `BFV`, and real numbers in `CKKS`):

- homomorphic additions,
- homomorphic multiplications
- homomorphic rotations

Additionally, we include the variants detailing how to do serialization-deserialization.

**Schemes**:

- `Standard BGV-rns (simple-integers-bgvrns.cpp) <https://github.com/openfheorg/openfhe-development/blob/main/src/pke/examples/simple-integers-bgvrns.cpp>`_

- `BGV-rns with Serialization/Deserialization (simple-integers-serial-bgvrns.cpp) <https://github.com/openfheorg/openfhe-development/blob/main/src/pke/examples/simple-integers-serial-bgvrns.cpp>`_


- `Standard BFV-rns (simple-integers.cpp) <https://github.com/openfheorg/openfhe-development/blob/main/src/pke/examples/simple-integers.cpp>`_

- `BFV-rns with Serialization/Deserialization (simple-integers-serial.cpp) <https://github.com/openfheorg/openfhe-development/blob/main/src/pke/examples/simple-integers-serial.cpp>`_


- `Standard CKKS-rns (simple-real-numbers.cpp) <https://github.com/openfheorg/openfhe-development/blob/main/src/pke/examples/simple-real-numbers>`__:

- `CKKS-rns with Serialization/Deserialization (simple-real-numbers-serial.cpp) <https://github.com/openfheorg/openfhe-development/blob/main/src/pke/examples/simple-real-numbers-serial.cpp>`_

Advanced CKKS Usage
^^^^^^^^^^^^^^^^^^^^^^^^

Demonstates advanced operations on real-number vectors using ``CKKS``:

- High-precision CKKS
- Rescaling (automatic and manual)
- hybrid key-switching
- hoisting

**Formats**

-  `Standard-precision Advanced CKKS Examples (advanced-real-numbers.cpp) <https://github.com/openfheorg/openfhe-development/blob/main/src/pke/examples/advanced-real-numbers.cpp>`__:

-  `High-precision Advanced CKKS Examples (advanced-real-numbers.cpp) <https://github.com/openfheorg/openfhe-development/blob/main/src/pke/examples/advanced-real-numbers-128.cpp>`__:

-  `CKKS Bootstrapping with Full Packing (simple-ckks-bootstrapping.cpp) <https://github.com/openfheorg/openfhe-development/blob/main/src/pke/examples/simple-ckks-bootstrapping.cpp>`__:

-  `CKKS Bootstrapping with Sparse Packing (advanced-ckks-bootstrapping.cpp) <https://github.com/openfheorg/openfhe-development/blob/main/src/pke/examples/advanced-ckks-bootstrapping.cpp>`__:

Misc. Operations across Schemes
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

-  `rotation.cpp <https://github.com/openfheorg/openfhe-development/blob/main/src/pke/examples/rotation.cpp>`__:

   - demonstrates use of ``EvalRotate automorphism`` for different schemes


- `linearsum-evaluation <https://github.com/openfheorg/openfhe-development/blob/main/src/pke/examples/linearwsum-evaluation.cpp>`_:

  - demonstrates the process of taking the linear weighted sum of a vector of ciphertexts against a vector of plaintext data in the `CKKS` scheme


-  `polynomial-evaluation.cpp <https://github.com/openfheorg/openfhe-development/blob/main/src/pke/examples/polynomial-evaluation.cpp>`__:

   - demonstrates an evaluation of a polynomial (power series) using ``CKKS``

-  `pre-buffer.cpp <https://github.com/openfheorg/openfhe-development/blob/main/src/pke/examples/pre-buffer.cpp>`__:

   - demonstrates use of OpenFHE for encryption, re-encryption and decryption of packed vector of binary data


-  `threshold-fhe.cpp <https://github.com/openfheorg/openfhe-development/blob/main/src/pke/examples/threshold-fhe.cpp>`__:

   - shows several examples of threshold FHE in ``BGVrns``, ``BFVrns``, and ``CKKSrns``

-  `threshold-fhe-5p.cpp <https://github.com/openfheorg/openfhe-development/blob/main/src/pke/examples/threshold-fhe-5p.cpp>`__:

   - shows example of threshold FHE with 5 parties in ``BFVrns``
