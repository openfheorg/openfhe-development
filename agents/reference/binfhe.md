# binfhe: Boolean circuits and small integers

The `binfhe` module implements FHEW/TFHE-style encryption. Each ciphertext holds one bit or one small integer, and
every gate bootstraps, so circuits can be arbitrarily deep. There is no packing: a gate handles one value at a time.
Read `../README.md` first.

Use it for Boolean logic, comparisons and lookup tables on small values. For arithmetic on many numbers, BFV, BGV or
CKKS is far faster.

## Boolean gates

```cpp
#include "binfhecontext.h"
using namespace lbcrypto;

auto cc = BinFHEContext();
cc.GenerateBinFHEContext(STD128);
auto sk = cc.KeyGen();
cc.BTKeyGen(sk);                       // bootstrapping keys, needed before any gate

auto a = cc.Encrypt(sk, 1);
auto b = cc.Encrypt(sk, 0);
auto c = cc.EvalBinGate(AND, a, b);
auto d = cc.EvalNOT(a);

LWEPlaintext result;
cc.Decrypt(sk, c, &result);
```

- The API differs from `pke`: the context is a value, not a pointer, and there is no `Enable` call.
- The types are `LWECiphertext`, `LWEPrivateKey` and `LWEPlaintext`, which is an integer.
- Two-input gates: `AND`, `OR`, `NAND`, `NOR`, `XOR`, `XNOR`. `EvalNOT` needs no bootstrapping.
- The two inputs of a gate must be different ciphertext objects. `EvalBinGate(AND, a, a)` throws "Input ciphertexts
  should be independant".
- The output of a gate or of `EvalNOT` can be used as the input of any number of later gates.
- `Encrypt(sk, ...)` is secret-key encryption. For public-key encryption, call `cc.BTKeyGen(sk, PUB_ENCRYPT)` and
  encrypt with `cc.GetPublicKey()`.

## Parameter sets

`GenerateBinFHEContext(set, method)` takes a parameter set and a bootstrapping method (`GINX`, the default, `AP`, or
`LMKCDEY`).

| Set | Use |
|---|---|
| `STD128`, `STD192`, `STD256` | more than 128, 192 and 256 bits of security against classical attacks |
| `STD128Q`, `STD192Q`, `STD256Q` | the same levels against quantum attacks |
| `STD128_3`, `STD128_4` and similar | gates with three or four inputs |
| `STD128_LMKCDEY`, `STD128_AP` and similar | sets tuned for the `LMKCDEY` or `AP` method; they work only with it |
| `LPF_STD128` and similar | the same security with a lower probability of failure |
| `TOY`, `MEDIUM` | testing only, not secure |

`STD128` is the usual choice. Each bootstrapping fails with a small probability, which the header lists per set:
2^-68 for `STD128` and 2^-132 for `LPF_STD128`. The full list is in `binfhe-constants.h`, installed under
`include/openfhe/binfhe`.

## Building a circuit

Multi-bit operations are built from gates, bit by bit. A comparator `a > b` for unsigned values, from the least
significant bit upwards:

```cpp
// a[i], b[i] are encrypted bits, least significant first
auto gt = cc.EvalBinGate(AND, a[0], cc.EvalNOT(b[0]));
for (size_t i = 1; i < bits; ++i) {
    auto here = cc.EvalBinGate(AND, a[i], cc.EvalNOT(b[i]));      // a[i] = 1 and b[i] = 0
    auto same = cc.EvalBinGate(XNOR, a[i], b[i]);
    gt        = cc.EvalBinGate(OR, here, cc.EvalBinGate(AND, same, gt));
}
```

This uses 4 gates per bit after the first.

Gates with three or four inputs (`AND3`, `OR3`, `MAJORITY`, `CMUX`, `AND4`, `OR4`) take a vector of ciphertexts and
need a `_3` or `_4` set and a matching plaintext modulus at encryption; follow `boolean-multi-input.cpp`.

## Small integers and lookup tables

A context generated for arbitrary function evaluation works on integers modulo a small `p`:

```cpp
auto cc = BinFHEContext();
cc.GenerateBinFHEContext(STD128, true, 12);          // arbitrary functions, 12-bit ciphertext modulus
auto sk = cc.KeyGen();
cc.BTKeyGen(sk);

int p = cc.GetMaxPlaintextSpace().ConvertToInt();    // 8 with these settings

auto f   = [](NativeInteger m, NativeInteger p1) -> NativeInteger { return (m * m) % p1; };
auto lut = cc.GenerateLUTviaFunction(f, p);

auto ct  = cc.Encrypt(sk, 5, LARGE_DIM, p);
auto out = cc.EvalFunc(ct, lut);

LWEPlaintext result;
cc.Decrypt(sk, out, &result, p);
```

Lookup tables and the large-precision functions below are not available in a build with `NATIVE_SIZE=32`; context
generation throws there. Boolean gates work in every build.

The plaintext space is small: 8 values here. Pass the same `p` to `Encrypt` and `Decrypt`. Larger integers have to be
split into digits by the application.

## Large-precision comparison

`EvalSign`, `EvalFloor` and `EvalDecomp` work on a larger ciphertext modulus `Q`:

```cpp
uint32_t logQ = 17;
auto cc = BinFHEContext();
cc.GenerateBinFHEContext(STD128, false, logQ, 0, GINX, false);
auto sk = cc.KeyGen();
cc.BTKeyGen(sk);
uint32_t Q = 1 << logQ;
int p      = cc.GetMaxPlaintextSpace().ConvertToInt() * (1 << (logQ - 12));   // 512 for logQ = 17

auto ct   = cc.Encrypt(sk, value, LARGE_DIM, p, Q);
auto sign = cc.EvalSign(ct);            // 1 if value >= p/2, else 0
cc.Decrypt(sk, sign, &result, 2);
```

In tests `logQ` of 17, 23 and 27 gave plaintext spaces of 512, 32768 and 524288; a larger `logQ` is slower.

## Cost

Every gate or lookup is a bootstrapping, so run time is proportional to the number of gates. Count the gates of the
circuit before choosing binfhe.

## Further topics

Examples in `src/binfhe/examples` of the source tree:

| Topic | Read |
|---|---|
| Gates | `boolean.cpp`, `boolean-truth-tables.cpp` |
| Other bootstrapping methods | `boolean-ap.cpp`, `boolean-lmkcdey.cpp` |
| Three and four-input gates | `boolean-multi-input.cpp` |
| Lookup tables | `eval-function.cpp` |
| Sign, floor, digit decomposition | `eval-sign.cpp`, `eval-flooring.cpp`, `eval-decomp.cpp` |
| Serialization | `boolean-serial-binary.cpp`, `boolean-serial-json.cpp` |
| Combining with CKKS | `src/pke/examples/scheme-switching.cpp`, `SCHEME_SWITCHING_CAPABILITY.md` |
