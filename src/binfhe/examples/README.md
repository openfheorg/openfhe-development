# BinFHE Examples

This folder contains various examples of the ways to use `binfhe`. For further details about these examples, visit [BinFHE Examples Documentation](). At a high level:

- [GINX Bootstrapping](boolean.cpp): 
  - bootstrapping as described in [TFHE: Fast Fully Homomorphic Encryption over the Torus](https://eprint.iacr.org/2018/421) and in [Bootstrapping in FHEW-like Cryptosystems](https://eprint.iacr.org/2020/086.pdf)

- [AP Bootstrapping](boolean.cpp): 
  - bootstrapping as described in [FHEW: Bootstrapping Homomorphic Encryption in less than a second](https://eprint.iacr.org/2014/816.pdf) and in [Bootstrapping in FHEW-like Cryptosystems](https://eprint.iacr.org/2020/086.pdf)

- [Boolean Serialization - binary format](boolean-serial-binary.cpp)

- [Boolean Serialization - json format](boolean-serial-json.cpp)

- [Boolean Truth Tables](boolean-truth-tables.cpp)
  - prints out the truth tables for all supported binary gates 

Examples below are based on the functionalities described in [Large-Precision Homomorphic Sign Evaluation using FHEW/TFHE Bootstrapping](https://eprint.iacr.org/2021/1337)

- [Eval Decomposition](eval-decomp.cpp)
  - runs a homomorphic digit decomposition process on the input ciphertext

- [Eval Flooring](eval-flooring.cpp)
  - rounds down the input ciphertext by certain number of bits

- [Eval Function](eval-function.cpp)
  - evaluates a function _f: Z<sub>p</sub> -> Z<sub>p</sub>_ on the input ciphertext

- [Eval Sign](eval-sign.cpp)
  - evaluates the most-significant bit of the input ciphertext
