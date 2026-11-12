# BFV and BGV

BFV and BGV compute exactly on vectors of integers modulo a plaintext modulus `t`. Read `../README.md` first.

Both schemes have the same interface. Start with BFV. The only difference to plan for is what happens when the depth
is exceeded: BFV returns wrong values silently, BGV throws.

## Parameters

```cpp
CCParams<CryptoContextBFVRNS> parameters;   // or CryptoContextBGVRNS
parameters.SetPlaintextModulus(65537);
parameters.SetMultiplicativeDepth(depth);
parameters.SetSecurityLevel(HEORG24_128);

CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);
cc->Enable(PKE);
cc->Enable(KEYSWITCH);
cc->Enable(LEVELEDSHE);
```

The plaintext modulus has no default and must be set. The default depth is 1 and the default security level is
`HEStd_128_classic`; use `HEORG24_128` in new code. `SetBatchSize` is not needed.

The library picks the ring dimension `N`, mainly from the depth. With `HEORG24_128`, BFV gave 8192 at depths 1 and 2
and 16384 at depths 4 and 8, for plaintext moduli from 17 to 50 bits, and BGV gave 16384 at depth 2. Read it back with
`cc->GetRingDimension()`.

## Choosing the plaintext modulus

For packed encoding, `t` must be a prime with `t - 1` divisible by `2N`. `N` is only known after `GenCryptoContext`,
so choose a prime of the form `k * 2^18 + 1`, which suits every ring dimension up to 131072, and check
`(t - 1) % (2 * cc->GetRingDimension()) == 0` before encoding.

| `t` | Size | Largest magnitude, `(t-1)/2` |
|---|---|---|
| 65537 | 17 bits | 32768; ring dimension up to 32768 only |
| 786433 | 20 bits | 393216 |
| 21495809 | 25 bits | about 10.7 million |
| 1074266113 | 31 bits | about 537 million |
| 1099512938497 | 41 bits | about 5.5e11 |
| 1125899915231233 | 51 bits | about 5.6e14 |

All of these were tested at depth 1. A 59-bit modulus, 576460752315482113, was accepted and then returned wrong
results with no error, so stay at or below the 51-bit entry. For another size, search upwards from the bound for the
first prime `k * 2^18 + 1`.

An unsuitable `t` is not rejected by `GenCryptoContext`. The first `MakePackedPlaintext` call then ends the process
with an uncaught `OpenFHEException` (`RootOfUnity(): ... (q-1)/m is an integer` or `The modulus value ... must be
prime`), even inside a `try` block. Because `N` depends on the depth, raising the depth can turn a working `t` into a
failing one.

Values are integers in the range `-(t-1)/2 ... (t-1)/2`, and negative inputs decrypt as negative. All arithmetic is
modulo `t`: a result outside the range wraps around with no error. With `t = 65537`, 1000 × 1000 decrypts to 16945.
Bound every intermediate value in the clear and choose `t` above twice that bound.

If the values do not fit even the largest modulus above, split them into digits, or run the computation under several
moduli and recombine with the Chinese remainder theorem. For real numbers use CKKS.

## Encoding and operations

```cpp
std::vector<int64_t> v = {1, 2, 3, 4, -5, 6, 7, 8};
auto ct = cc->Encrypt(keys.publicKey, cc->MakePackedPlaintext(v));

auto sum     = cc->EvalAdd(ct, ct);
auto product = cc->EvalMult(ct, ct);                             // needs EvalMultKeyGen
auto scaled  = cc->EvalMult(ct, cc->MakePackedPlaintext({2, 2, 2, 2, 2, 2, 2, 2}));

Plaintext result;
cc->Decrypt(keys.secretKey, product, &result);
result->SetLength(v.size());
std::vector<int64_t> values = result->GetPackedValue();
```

A ciphertext has `N` slots. A shorter vector is padded with zeros.

## Rotations

The `N` slots form two rows of `N/2`. `EvalRotate` rotates each row cyclically on its own; values do not move between
the rows.

```cpp
cc->EvalRotateKeyGen(keys.secretKey, {1, -1});
cc->EvalRotate(ct, 1);    // {1,2,3,4,-5,6,7,8} -> {2,3,4,-5,6,7,8,0,...}
cc->EvalRotate(ct, -1);   // {1,2,3,4,-5,6,7,8} -> {0,1,2,3,4,-5,6,7,8,...}
```

A positive index moves values towards slot 0. The rotation wraps at `N/2`, not at the length of the input. In the
example above the first value moves to slot `N/2 - 1`, not to slot 7. To rotate a short vector cyclically, repeat it
to fill the row, or combine two rotations with masks.

Because a short vector is padded with zeros, a left rotation shifts zeros in at its end. That is what a sliding
window needs: `ct + rot(ct, 1) + rot(ct, 2)` holds the sum of three neighbours in every slot whose window lies inside
the input.

## Sums

```cpp
cc->Enable(ADVANCEDSHE);
cc->EvalSumKeyGen(keys.secretKey);
auto total = cc->EvalSum(ct, n);     // n must be a power of two
```

Slot `i` of the result holds the sum of slots `i ... i+n-1`, so the total of the first `n` values is in slot 0. If `n`
is not a power of two it is rounded up: `EvalSum(ct, 5)` returned the sum of eight slots. Pad the input with zeros to
a power of two.

## Depth

Count the depth as the longest chain of ciphertext multiplications. Additions, rotations and `EvalSum` do not count
towards it: one multiplication followed by three rotations and an `EvalSum` over 64 slots was correct at depth 1.

Past the configured depth:

- BFV raises no error and decrypts to wrong values. Always test against the cleartext result.
- BGV throws from the failing operation: `ModReduceInternalInPlace(): Too few towers to support ModReduce`.

## Further topics

Examples in `src/pke/examples` of the source tree:

| Topic | Read |
|---|---|
| BFV basics | `simple-integers.cpp` |
| BGV basics | `simple-integers-bgvrns.cpp` |
| Deeper circuits | `depth-bfvrns.cpp`, `depth-bgvrns.cpp` |
| Inner product | `inner-product.cpp` |
| Rotations in each scheme | `rotation.cpp` |
