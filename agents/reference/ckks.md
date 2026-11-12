# CKKS

CKKS computes on vectors of real or complex numbers. Results are approximate. Read `../README.md` first.

## Parameters

```cpp
CCParams<CryptoContextCKKSRNS> parameters;
parameters.SetMultiplicativeDepth(depth);
parameters.SetScalingModSize(50);
parameters.SetBatchSize(slots);          // power of two, at most ring dimension / 2
parameters.SetSecurityLevel(HEORG24_128);
```

| Parameter | Default | Notes |
|---|---|---|
| Multiplicative depth | 1 | Set it from the computation; see below |
| Scaling mod size | 50 bits | Larger gives more precision and a larger ring dimension |
| First mod size | 60 bits | |
| Batch size | ring dimension / 2 | Rotations wrap around the batch size |
| Security level | `HEStd_128_classic` | Use `HEORG24_128` in new code |
| Scaling technique | `FLEXIBLEAUTOEXT` | Rescales automatically; keep it unless you know why not |
| Secret key distribution | `UNIFORM_TERNARY` | Use `HYBRID_TERNARY` with bootstrapping |

The library picks the ring dimension from the depth, the modulus sizes and the security level. With 50-bit scaling and
`HEORG24_128`:

| Depth | Ring dimension |
|---|---|
| 1 | 16384 |
| 5–10 | 32768 |
| 20 | 65536 |
| 30–40 | 131072 |

Run time and memory grow with both the ring dimension and the depth, so keep the depth as small as the computation
allows.

## Counting depth

| Operation | Levels used |
|---|---|
| Ciphertext × ciphertext | 1 |
| Ciphertext × plaintext or scalar | 1 |
| Addition, subtraction, with a ciphertext, plaintext or scalar | 0 |
| Rotation | 0 |
| `EvalPoly`, degree 4 | 3 |
| `EvalChebyshevFunction`, `EvalLogistic` and similar | see the table below |

Depth is the longest chain, so multiply in a balanced tree: `(a*b)*(c*d)` has depth 2, `((a*b)*c)*d` has depth 3.
Operands at different levels can be combined directly; the library aligns them.

`ciphertext->GetLevel()` returns the number of levels used so far.

## Plaintexts and scalars

```cpp
auto scaled  = cc->EvalMult(ct, 0.1);                               // scalar
auto shifted = cc->EvalAdd(ct, 0.25);
auto masked  = cc->EvalMult(ct, cc->MakeCKKSPackedPlaintext(w));    // per-slot weights, a std::vector<double>
```

Encoding a plaintext needs no key, so a server that holds only the context can build its own plaintexts, for example
model weights. Keep data that is not secret in the clear: a plaintext multiplication is cheaper than a ciphertext
multiplication, though it uses a level too.

## Rotations and sums

```cpp
cc->EvalRotateKeyGen(keys.secretKey, {1, -1, 2});   // one key per index
auto left  = cc->EvalRotate(ct, 1);                 // slot i takes the value of slot i+1
auto right = cc->EvalRotate(ct, -1);

cc->EvalSumKeyGen(keys.secretKey);
auto total = cc->EvalSum(ct, batchSize);            // every slot holds the sum
auto dot   = cc->EvalInnerProduct(ct1, ct2, batchSize);
```

`EvalSum` and `EvalInnerProduct` need `Enable(ADVANCEDSHE)`.

To sum blocks of a packed matrix, for example `m` features of `n` samples stored as slot `j*n + i`, fold with
rotations by the stride: add the ciphertext rotated by `n * m/2`, then by `n * m/4`, down to `n`. With the batch size
set to `n * m` (both powers of two), slot `i` then holds the sum over the features of sample `i`, using `log2(m)`
rotation keys.

## Non-polynomial functions

CKKS has only addition and multiplication. Other functions are evaluated as Chebyshev approximations over an interval
`[a, b]` that must contain every input value:

```cpp
auto y = cc->EvalLogistic(ct, a, b, degree);
auto z = cc->EvalChebyshevFunction([](double v) { return std::sqrt(v); }, ct, a, b, degree);
```

These functions need `Enable(ADVANCEDSHE)`. An input outside `[a, b]` gives a wrong result with no error. In a test, an
input of 4 on the interval `[-1, 1]` returned 82.4 where 2.45 was correct. Bound the inputs in the clear before choosing
the interval.

Depth used, by polynomial degree. On the interval `[-1, 1]` it is one less.

| Degree | Depth |
|---|---|
| 3–5 | 4 |
| 6–13 | 5 |
| 14–27 | 6 |
| 28–59 | 7 |
| 60–119 | 8 |
| 120–247 | 9 |

A wider interval needs a higher degree for the same accuracy. Maximum error of `EvalLogistic` measured over the
whole interval, with 50-bit scaling:

| Interval | Degree 5 | Degree 13 | Degree 27 | Degree 59 |
|---|---|---|---|---|
| `[-1, 1]` | 5e-6 | 7e-12 | 6e-12 | 6e-12 |
| `[-5, 5]` | 2e-2 | 2e-4 | 4e-8 | 1e-11 |
| `[-10, 10]` | 9e-2 | 8e-3 | 1e-4 | 5e-9 |

To save the level, scale the input into `[-1, 1]` in a multiplication the computation already performs, such as the
model weights, and pass a rescaled function: `EvalChebyshevFunction([B](double v) { return f(B * v); }, ct, -1, 1,
degree)`.

Comparisons, `max` and `sign` are not smooth and need high degrees. See `choosing-a-scheme.md` before building them in
CKKS.

## Bootstrapping

Bootstrapping refreshes a ciphertext that has run out of levels. It is expensive in time and memory. First check
whether a larger depth without bootstrapping is enough.

```cpp
CCParams<CryptoContextCKKSRNS> parameters;
SecretKeyDist secretKeyDist = HYBRID_TERNARY;
parameters.SetSecretKeyDist(secretKeyDist);
parameters.SetSecurityLevel(HEORG24_128);
parameters.SetScalingModSize(59);
parameters.SetFirstModSize(60);
parameters.SetScalingTechnique(FLEXIBLEAUTO);

std::vector<uint32_t> levelBudget = {4, 4};
uint32_t levelsAfterBootstrap     = 10;
uint32_t depth = levelsAfterBootstrap + FHECKKSRNS::GetBootstrapDepth(levelBudget, secretKeyDist);
parameters.SetMultiplicativeDepth(depth);

auto cc = GenCryptoContext(parameters);
cc->Enable(PKE);
cc->Enable(KEYSWITCH);
cc->Enable(LEVELEDSHE);
cc->Enable(ADVANCEDSHE);
cc->Enable(FHE);

cc->EvalBootstrapSetup(levelBudget, {0, 0}, numSlots);
auto keys = cc->KeyGen();
cc->EvalMultKeyGen(keys.secretKey);
cc->EvalBootstrapKeyGen(keys.secretKey, numSlots);

auto refreshed = cc->EvalBootstrap(ct);
```

- These settings are for the default 64-bit build. A 128-bit build uses different modulus sizes; see
  `simple-ckks-bootstrapping.cpp`.
- With these settings and `HEORG24_128` the ring dimension is 131072.
- Scale the values into `[-1, 1]` before bootstrapping.
- Use the same `numSlots` in the setup, the key generation and the encoding. Fewer slots is faster.
- With few slots the library lowers a level budget that is too large and prints a warning such as "level budget for
  encoding too large. Setting it to 3". The result is still correct. Pass the smaller budget to silence it.
- One of the levels left after bootstrapping is used by the next bootstrapping call.
- Generate the application's own rotation keys with `EvalRotateKeyGen` even when `EvalBootstrapKeyGen` already made a
  key for the same index.
- While developing, `SetSecurityLevel(HEStd_NotSet)` with `SetRingDim(1 << 12)` runs the same code in seconds. It is
  not secure.

## Reading results

```cpp
Plaintext result;
cc->Decrypt(keys.secretKey, ct, &result);
result->SetLength(n);
std::vector<double> values = result->GetRealPackedValue();
```

`result->GetLogPrecision()` estimates the precision in bits. Compare with a tolerance, never with `==`.

## Further topics

These are not covered here. Each has an example or a note in `src/pke/examples` of the source tree.

| Topic | Read |
|---|---|
| Bootstrapping variants, key sizes, failure probabilities | `CKKS_BOOTSTRAPPING.md` |
| Higher precision from two bootstrapping iterations | `iterative-ckks-bootstrapping.cpp` |
| Complex inputs | `simple-complex-numbers.cpp` |
| Lookup tables and functions through functional bootstrapping | `CKKS_FUNCTIONAL_BOOTSTRAPING.md` |
| Composite scaling for high precision on 64-bit builds | `COMPOSITE_SCALING.md` |
| Scaling techniques and hoisted rotations | `advanced-real-numbers.cpp` |
| Smooth function evaluation | `FUNCTION_EVALUATION.md` |
| Releasing bootstrapping memory | `ckks-release-memory.cpp` |
