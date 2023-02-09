# BinFHE Examples

This folder contains various examples of the ways to use `binfhe`. For further details about these examples,
visit [BinFHE Examples Documentation](https://openfhe-development.readthedocs.io/en/latest/assets/sphinx_rsts/modules/binfhe.html).

At a high level:

- GINX Bootstrapping:
  - [`boolean.cpp`](https://github.com/openfheorg/openfhe-development/tree/main/src/binfhe/examples/boolean.cpp)
    - bootstrapping as described
      in [TFHE: Fast Fully Homomorphic Encryption over the Torus](https://eprint.iacr.org/2018/421) and
      in [Bootstrapping in FHEW-like Cryptosystems](https://eprint.iacr.org/2020/086.pdf)
  - [`boolean-pke.cpp`](https://github.com/openfheorg/openfhe-development/tree/main/src/binfhe/examples/pke/boolean-pke.cpp)
    - Public Key Encryption (PKE) version of the `boolean.cpp` example

- AP Bootstrapping:
  - [`boolean-ap.cpp`](https://github.com/openfheorg/openfhe-development/tree/main/src/binfhe/examples/boolean-ap.cpp)
    - bootstrapping as described
      in [FHEW: Bootstrapping Homomorphic Encryption in less than a second](https://eprint.iacr.org/2014/816.pdf) and
      in [Bootstrapping in FHEW-like Cryptosystems](https://eprint.iacr.org/2020/086.pdf)
  - [`boolean-ap-pke.cpp`](https://github.com/openfheorg/openfhe-development/tree/main/src/binfhe/examples/pke/boolean-ap-pke.cpp)
    - PKE version of the `boolean-ap.cpp` example

- Boolean Serialization - binary format:
    - [`boolean-serial-binary.cpp`](https://github.com/openfheorg/openfhe-development/tree/main/src/binfhe/examples/boolean-serial-binary.cpp)
    - [`boolean-serial-binary-pke.cpp`](https://github.com/openfheorg/openfhe-development/tree/main/src/binfhe/examples/pke/boolean-serial-binary-pke.cpp)
        - PKE version of the `boolean-serial-binary.cpp` example

- Boolean Serialization - json format:
    - [`boolean-serial-json.cpp`](https://github.com/openfheorg/openfhe-development/tree/main/src/binfhe/examples/boolean-serial-json.cpp)
    - [`boolean-serial-json-pke.cpp`](https://github.com/openfheorg/openfhe-development/tree/main/src/binfhe/examples/pke/boolean-serial-json-pke.cpp)
        - PKE version of the `boolean-serial-json.cpp` example

- Boolean Truth Tables:
    - [`boolean-truth-tables.cpp`](https://github.com/openfheorg/openfhe-development/tree/main/src/binfhe/examples/boolean-truth-tables.cpp)
        - prints out the truth tables for all supported binary gates
    - [`boolean-truth-tables-pke.cpp`](https://github.com/openfheorg/openfhe-development/tree/main/src/binfhe/examples/pke/boolean-truth-tables-pke.cpp)
        - PKE version of the `boolean-truth-tables-pke.cpp` example

Examples below are based on the functionalities described
in [Large-Precision Homomorphic Sign Evaluation using FHEW/TFHE Bootstrapping](https://eprint.iacr.org/2021/1337)

Note that for these advanced features, only GINX bootstrapping with 128-bit security (and toy security) is supported. To use these features, GenerateBinFHEContext needs to be called with at least two parameters: security parameter and whether arbitrary function evaluation is needed. For homomorphic sign evaluation and homomorphic digit decomposition, the large precision Q also needs to be specified. Please see the examples for details.

- [Eval Decomposition](https://github.com/openfheorg/openfhe-development/tree/main/src/binfhe/examples/eval-decomp.cpp): - `eval-decomp.cpp`
    - runs a homomorphic digit decomposition process on the input ciphertext

- Eval Flooring:
    - [`eval-flooring.cpp`](https://github.com/openfheorg/openfhe-development/tree/main/src/binfhe/examples/eval-flooring.cpp)
        - rounds down the input ciphertext by certain number of bits
    - [`eval-flooring-pke.cpp`](https://github.com/openfheorg/openfhe-development/tree/main/src/binfhe/examples/pke/eval-flooring-pke.cpp)
        - PKE version of the `eval-flooring.cpp` example

- Eval Function:
    - [`eval-function.cpp`](https://github.com/openfheorg/openfhe-development/tree/main/src/binfhe/examples/eval-function.cpp)
        - evaluates a function _f: Z<sub>p</sub> -> Z<sub>p</sub>_ on the input ciphertext
    - [`eval-function-pke.cpp`](https://github.com/openfheorg/openfhe-development/tree/main/src/binfhe/examples/pke/eval-function-pke.cpp)
        - PKE version of the `eval-function.cpp` example

- [Eval Sign](https://github.com/openfheorg/openfhe-development/tree/main/src/binfhe/examples/eval-sign.cpp): - `eval-sign.cpp`
    - evaluates the most-significant bit of the input ciphertext

- [Serialization for a larger precision scenario - binary format](https://github.com/openfheorg/openfhe-development/tree/main/src/binfhe/examples/boolean-serial-binary-dynamic-large-precision.cpp): - `boolean-serial-binary-dynamic-large-precision.cpp`

- [Serialization for a larger precision scenario - json format](https://github.com/openfheorg/openfhe-development/tree/main/src/binfhe/examples/boolean-serial-json-dynamic-large-precision.cpp): - `boolean-serial-json-dynamic-large-precision.cpp`
