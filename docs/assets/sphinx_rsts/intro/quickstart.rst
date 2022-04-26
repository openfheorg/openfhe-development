Examples
====================================

OpenFHE provides the following examples which should provide the reader with a basic understanding of how to use the
library for various purposes.

Binary FHE
----------------------------

`Binary Fully Homomorphic Encryption Examples <https://github.com/openfheorg/openfhe-development/tree/main/src/binfhe/examples>`_

At a high level:

-  `boolean.cpp: GINX Bootstrapping <https://github.com/openfheorg/openfhe-development/tree/main/src/binfhe/examples/boolean.cpp>`__:

   -  bootstrapping as described in `TFHE: Fast Fully Homomorphic
      Encryption over the Torus <https://eprint.iacr.org/2018/421>`__
      and in `Bootstrapping in FHEW-like
      Cryptosystems <https://eprint.iacr.org/2020/086.pdf>`__


-  `boolean-ap.cpp: AP Bootstrapping <https://github.com/openfheorg/openfhe-development/tree/main/src/binfhe/examples/boolean-ap.cpp>`__:

   -  bootstrapping as described in `FHEW: Bootstrapping Homomorphic
      Encryption in less than a
      second <https://eprint.iacr.org/2014/816.pdf>`__ and in
      `Bootstrapping in FHEW-like
      Cryptosystems <https://eprint.iacr.org/2020/086.pdf>`__


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

`Implementation core of the OpenFHE library <https://github.com/openfheorg/openfhe-development/tree/main/src/binfhe/examples>`_ Examples include:

- `parallel.cpp <https://github.com/openfheorg/openfhe-development/blob/main/src/core/examples/parallel.cpp>`_:

  - provides an example of parallelization in ``OpenFHE`` with `OpenMP <https://www.openmp.org/>`_


- `sampling <https://github.com/openfheorg/openfhe-development/blob/main/src/core/examples/sampling.cpp>`_:

  - provides an example of doing integer Gaussian sampling using `OpenFHE samplers <https://github.com/openfheorg/openfhe-development/tree/main/src/core/include/math>`_.

  - For more information on sampling, read `<https://openfhe-development.readthedocs.io/en/latest/assets/sphinx_rsts/modules/core/math/sampling.html>`_


Public-Key Encryption (PKE)
----------------------------

Generalized Fully Homomorphic Encryption

-  `advanced-real-numbers-128.cpp <https://github.com/openfheorg/openfhe-development/blob/main/src/pke/examples/advanced-real-numbers-128.cpp>`_:

   - demonstates the advanced operations on **high-precision** real number vectors using ``CKKS``:

     - High-precision CKKS
     - Rescaling (automatic and manual)
     - hybrid key-switching
     - hoisting

-  `advanced-real-numbers.cpp: Advanced examples of how to use the CKKS framework <https://github.com/openfheorg/openfhe-development/blob/main/src/pke/examples/advanced-real-numbers.cpp>`__:

   - demonstates the advanced operations on real number vectors using ``CKKS``:

     - Rescaling (automatic and manual)
     - hybrid key-switching
     - hoisting

-  `depth-bfvrns-b.cpp <https://github.com/openfheorg/openfhe-development/blob/main/src/pke/examples/depth-bfvrns-b.cpp>`__:

   - demonstrates use of the ``BFVrnsB`` scheme for basic homomorphic encryption

-  `depth-bfvrns.cpp <https://github.com/openfheorg/openfhe-development/blob/main/src/pke/examples/depth-bfvrns.cpp>`__:

   - demonstrates use of the ``BFVrns`` scheme for basic homomorphic encryption


-  `depth-bgvrns.cpp <https://github.com/openfheorg/openfhe-development/blob/main/src/pke/examples/depth-bgvrns.cpp>`__:

   - demonstrates use of the ``BGVrns`` scheme for basic homomorphic encryption


-  `evalatindex.cpp <https://github.com/openfheorg/openfhe-development/blob/main/src/pke/examples/evalatindex.cpp>`__:

   - demonstrates use of ``EvalAtIndex (rotation operation) AKA automorphism`` for different schemes and cyclotomic rings


- `linearsum_evaluation <https://github.com/openfheorg/openfhe-development/blob/main/src/pke/examples/linearwsum_evaluation.cpp>`_:

  - demonstrates the process of taking the linear weighted sum of a vector of ciphertexts against a vector of plaintext data in the `CKKS` scheme


-  `polynomial_evaluation.cpp <https://github.com/openfheorg/openfhe-development/blob/main/src/pke/examples/polynomial_evaluation.cpp>`__:

   - demonstrates an evaluation of a polynomial (power series) using ``CKKS``

-  `pre-buffer.cpp <https://github.com/openfheorg/openfhe-development/blob/main/src/pke/examples/pre-buffer.cpp>`__:

   - demonstrates use of OpenFHE for encryption, re-encryption and decryption of packed vector of binary data


-  `simple-integers-bgvrns.cpp <https://github.com/openfheorg/openfhe-development/blob/main/src/pke/examples/simple-integers-bgvrns.cpp>`__:

   - demonstates the following mathematical operations on vectors of integers using ``BGVrns``:

     - homomorphic additions,
     - homomorphic multiplications
     - homomorphic rotations


-  `simple-integers-serial-bgvrns.cpp <https://github.com/openfheorg/openfhe-development/blob/main/src/pke/examples/simple-integers-serial-bgvrns.cpp>`__:

   - demonstates the following mathematical operations on vectors of integers using ``BGVrns``:

     - homomorphic additions,
     - homomorphic multiplications
     - homomorphic rotations

   - Additionally demonstrates the typical serialization/deserialization calls


-  `simple-integers-serial.cpp <https://github.com/openfheorg/openfhe-development/blob/main/src/pke/examples/simple-integers-serial.cpp>`__:

   - demonstates the following mathematical operations on vectors of integers using ``BFVrns``:

     - homomorphic additions,
     - homomorphic multiplications
     - homomorphic rotations

   - Additionally demonstrates the typical serialization/deserialization calls

-  `simple-integers.cpp <https://github.com/openfheorg/openfhe-development/blob/main/src/pke/examples/simple-integers.cpp>`__:

   - demonstates the following mathematical operations on vectors of integers  using ``BFVrns``:

     - homomorphic additions,
     - homomorphic multiplications
     - homomorphic rotations

-  `simple-real-numbers-serial.cpp <https://github.com/openfheorg/openfhe-development/blob/main/src/pke/examples/simple-real-numbers-serial.cpp>`__:

   - demonstates the following mathematical operations on real number vectors using ``CKKS``:

     - homomorphic additions,
     - homomorphic multiplications
     - homomorphic rotations

   - Additionally demonstrates the typical serialization/deserialization calls


-  `simple-real-numbers.cpp <https://github.com/openfheorg/openfhe-development/blob/main/src/pke/examples/simple-real-numbers>`__:

   - demonstrates the following mathematical operations on real number vectors using ``CKKS``:

     - homomorphic additions,
     - homomorphic multiplications
     - homomorphic rotations

-  `threshold-fhe.cpp <https://github.com/openfheorg/openfhe-development/blob/main/src/pke/examples/threshold-fhe.cpp>`__:

   - shows several examples of threshold FHE in ``BGVrns``, ``BFVrns``, and ``CKKS``
