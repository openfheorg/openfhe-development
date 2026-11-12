# Troubleshooting

Symptoms, their usual causes and what to check. Messages are quoted from OpenFHE 1.6.

## Exceptions

An `OpenFHEException` derives from `std::exception`. Its message starts with the source file, line and function.

`Call EvalMultKeyGen() to have EvalMultKey available`
: No multiplication key exists for the key the ciphertext was encrypted with. Call `EvalMultKeyGen`, or deserialize
  the keys. In threshold FHE, encrypt with the joint public key.

`EvalAutomorphismKeys are not generated`
: No rotation keys exist. Call `EvalRotateKeyGen` with every index the computation uses.

`EvalKey for index [...] is not found` (CKKS), or just `map::at` (BFV)
: Rotation keys exist, but not for this index. Add the index to `EvalRotateKeyGen`. The number in the message is an
  internal automorphism index, not the rotation index.

`... operation has not been enabled. Enable(ADVANCEDSHE) must be called`
: Call `cc->Enable(...)` with the feature named in the message.

`The decryption failed because the approximation error is too high`
: CKKS only. The multiplicative depth was exceeded, or the ciphertext was decrypted with the wrong key.

`Too few towers to support ModReduce`
: BGV only. The multiplicative depth was exceeded.

`PlaintextModulus is not set`
: BFV and BGV need `SetPlaintextModulus`.

`(q-1)/m is an integer`, or `The modulus value ... must be prime`, followed by the process aborting
: The plaintext modulus does not suit packed encoding. Use a prime `t` with `t - 1` divisible by twice the ring
  dimension; see `bfv-bgv.md`.

`Input ciphertexts should be independant`
: A binfhe gate was called with the same ciphertext object for both inputs.

## Wrong results with no error

- **BFV values are garbage.** The multiplicative depth was exceeded, or the wrong secret key was used. BFV reports
  neither.
- **BFV or BGV values are off by a multiple of the plaintext modulus.** A value left the range
  `-(t-1)/2 ... (t-1)/2` and wrapped.
- **A CKKS function result is far off.** An input was outside the `[a, b]` interval given to the Chebyshev
  evaluation.
- **CKKS precision is poor.** The scaling mod size is too small for the depth.
- **A rotated BFV or BGV vector has zeros or values in unexpected slots.** Rotation wraps at half the ring dimension,
  not at the input length.
- **A rotated CKKS vector wraps at an unexpected place.** Rotation wraps at the batch size.
- **The decrypted vector is longer than the input.** Call `SetLength` on the plaintext.

To locate the fault, run the same computation in the clear and decrypt intermediate ciphertexts, comparing step by
step. Start with small inputs.

## It is slow or runs out of memory

- Build in Release mode.
- Print `cc->GetRingDimension()`. Cost grows with the ring dimension and with the depth. Lower the depth or the
  scaling mod size if the ring dimension is larger than expected.
- Generate only the rotation keys that are used; each key takes memory and time.
- Pack many values into one ciphertext and use rotations and sums, not one ciphertext per value.
- Multiplying by a plaintext is cheaper than multiplying by a ciphertext. Keep data that need not be secret in the
  clear.
- CKKS bootstrapping needs gigabytes of memory at secure parameters. Develop with the toy parameters in `ckks.md`,
  and reduce the number of slots where the application allows.
- OpenFHE uses OpenMP. Check that the thread count matches the cores available: `OMP_NUM_THREADS`.

## Build and link

- `find_package(OpenFHE)` fails: pass `-DCMAKE_PREFIX_PATH=<install prefix>` to CMake.
- The program does not find `libOPENFHE*.so` at run time: add `<install prefix>/lib` to `LD_LIBRARY_PATH`, or install
  OpenFHE to a system location.
- Compile with the flags from `OpenFHE_CXX_FLAGS`, as `template/CMakeLists.txt` does. They carry the settings the
  library was built with.
- Serialization functions are missing at compile or link time: include the `-ser.h` headers listed in
  `serialization.md`.
