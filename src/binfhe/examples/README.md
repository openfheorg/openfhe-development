# BinFHE Examples

This folders contains various examples of the ways to use `binfhe`. For further details about these examples visit [BinFHE Examples Documentation](). At a high level:

- [Ginx Bootstrapping](boolean.cpp): 
  - bootstrapping as described in [FHEW: Bootstrapping Homomorphic Encryption in less than a second](https://eprint.iacr.org/2014/816.pdf)

- [AP Bootstrapping](boolean.cpp): 
  - bootstrapping as described in [Bootstrapping in FHEW-like Cryptosystems](https://eprint.iacr.org/2020/086.pdf)

- [Boolean Serialization - binary format](boolean-serial-binary.cpp)

- [Boolean Serialization - json format](boolean-serial-json.cpp)

- [Boolean Truth Tables](boolean-truth-tables.cpp)
  - prints out the truth tables for all supported binary gates

- [Eval Decomposition](eval-decomp.cpp)
  - Runs a digit decomposition

- [Eval Flooring](eval-flooring.cpp)
  - Rounding down an input ciphertext by some number of bits

- [Eval Function](eval-function.cpp)
  - Evaluate an input function that outputs in some ring Z$_p$

- [Eval Sign](eval-sign.cpp)
  - Evaluate the most-significant bit of the input number
