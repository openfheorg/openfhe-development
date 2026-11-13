# Library follow-ups

Possible library changes that came up while writing the agent guides. Nothing here is implemented or decided. This file
is for maintainers and is not part of the guide.

## BFV fails silently in two cases

Observed on OpenFHE 1.6.1 (dev, 64-bit native size, math backend 4) with `CryptoContextBFVRNS`, plaintext modulus
65537 and multiplicative depth 1.

| Case | Observed |
|---|---|
| Three chained `EvalMult` calls (depth 3) | no exception; decrypts to -31290 where -7200 is correct |
| 1000 × 1000 | no exception; decrypts to 16945, the product modulo 65537 |

For comparison, CKKS with depth 2 on a depth-1 context threw at `Decrypt` ("approximation error is too high"), and
BGV (default `FLEXIBLEAUTOEXT`) with four chained squarings on a depth-2 context threw in `EvalMult` ("Too few towers
to support ModReduce").

### Exceeding the depth

This could be caught, approximately. BFV ciphertexts already count multiplications: `EvalMult` sets
`SetNoiseScaleDeg(max(...) + 1)` in `src/pke/lib/scheme/bfvrns/bfvrns-leveledshe.cpp`. `EvalMult` could compare that
counter with the configured multiplicative depth and throw.

Reasons for caution:

- The counter is a proxy. The real noise cannot be measured without the secret key, and the depth setting is a
  worst-case bound, so parameters usually have slack.
- Programs that go past their declared depth and still decrypt correctly today would start throwing.
- Additions and key switches also use up the noise budget, and BFV sizes its parameters from `evalAddCount` and
  `keySwitchCount` as well. A multiplication counter does not see those.

Options:

1. Throw in `EvalMult` when the counter passes the configured depth. This is a behaviour change and needs a release
   note and a regression test.
2. Emit a warning through `utils/diagnostic_output.h` instead of throwing, which keeps existing programs running.
3. Leave the library as is and only document the behaviour, which is the current state.

### Plaintext-modulus overflow

This cannot be detected. Wrapping modulo the plaintext modulus is the defined arithmetic of BFV. The evaluator sees
only ciphertexts, and the decrypted value is a valid residue. The application has to bound its values in the clear and
choose a large enough modulus.

## An invalid plaintext modulus aborts the process

Observed with `CryptoContextBFVRNS`, ring dimension 8192, inside a `try`/`catch (const std::exception&)` block.
`GenCryptoContext` and key generation succeed, and the first `MakePackedPlaintext` call ends the process with
`terminate called after throwing an instance of 'lbcrypto::OpenFHEException'`:

| Plaintext modulus | Message |
|---|---|
| 65539 (prime, not 1 modulo 2N) | `RootOfUnity(): ... satisfying the condition: (q-1)/m is an integer` |
| 65536 (not prime) | `SetParams_2n(): The modulus value is [65536]. It must be prime.` |

The exception does not reach the caller's handler. The parameter setup in `src/pke/lib/encoding/packedencoding.cpp` runs
inside `#pragma omp critical` sections, and an exception that leaves an OpenMP region ends the process, so that is the
likely cause; it has not been confirmed. Two possible improvements: make it catchable, and validate the modulus for
packed encoding in `GenCryptoContext`, where a plaintext modulus of zero is already rejected.

## Smaller findings

Observed on the same build.

- BFV: `EvalRotate` with an index that has no key, when keys for other indices exist, throws `map::at` from
  `std::map` with no OpenFHE message. CKKS reports `EvalKey for index [125] is not found` for rotation index 3, which
  names the automorphism index and not the index the caller passed.
- BFV: decrypting with a different secret key of the same context raises no error and returns garbage. CKKS throws
  "approximation error is too high" in the same situation.
- BFV: `KeyGen` and `EvalMultKeyGen` succeed on a context with only `PKE` enabled, without `KEYSWITCH` or
  `LEVELEDSHE`.
- CKKS: `EvalChebyshevFunction` with an input outside `[a, b]` raises no error. An input of 4 on `[-1, 1]` returned
  82.4 for `sqrt(x + 2)`. This cannot be detected under encryption; it is listed here because it is easy to hit.
- BFV: a 59-bit plaintext modulus, 576460752315482113 (prime, 1 modulo 2^18), is accepted at depth 1 and ring
  dimension 8192, and then every result is wrong with no error, including a plain `EvalSum`. Moduli of up to 51 bits
  gave correct results in the same test. If large moduli are unsupported, `GenCryptoContext` could reject them.
- `EvalSum(ct, n)` with `n` not a power of two sums the next power of two: `EvalSum(ct, 5)` returned the sum of eight
  slots.
- BGV proxy re-encryption in `NOISE_FLOODING_HRA` mode, set up as in `pre-hra-secure.cpp` but with plaintext modulus
  65537 instead of 2 (ring dimension 32768, 13 hops), throws `LastPrime(): overflow shrinking candidate` from
  `GenCryptoContext`. The message does not say which parameter to change.
