# Choosing a scheme

`../README.md` has the short table. This file covers the cases where the choice is not obvious.

## Start from the data and the operations

| Question | Points to |
|---|---|
| Are the values real numbers, and is a small error acceptable? | CKKS |
| Must the result be exact? | BFV or BGV, or binfhe |
| Do many values go through the same arithmetic? | BFV, BGV or CKKS; one ciphertext packs thousands of values |
| Is the logic branching, bit-level, or a table lookup on small values? | binfhe |
| Is the depth unknown or unbounded? | binfhe, or CKKS with bootstrapping |

## BFV or BGV

They offer the same operations on the same data, so start with BFV. BGV throws when the depth is exceeded, where BFV
returns wrong values silently, which can make BGV easier to debug. Compare run times on your own computation before
committing to one.

## Exact integers that do not fit the plaintext modulus

BFV and BGV work modulo a plaintext modulus that must also suit the ring dimension; see `bfv-bgv.md`. When
intermediate values are larger:

- split the values into digits and compute on the digits, or
- run the computation under several plaintext moduli and recombine in the clear, or
- use CKKS if an approximate result is acceptable. CKKS on integers gives values close to integers that the
  application rounds after decryption.

## Comparisons, max, sign, branching

Arithmetic schemes have no comparison operation. The options, from simplest to most involved:

1. Avoid it. Move the comparison to the party that decrypts, or restructure the computation so the comparison happens
   on cleartext.
2. If the data is bits or small integers and the circuit is small, use binfhe throughout; see `binfhe.md`.
3. In CKKS, approximate the step function with `EvalChebyshevFunction` over a known input interval. The result is a
   smooth approximation that is inaccurate near the threshold, and a sharper step needs a higher degree and more
   depth; see `ckks.md`.
4. Scheme switching: compute arithmetic in CKKS, switch to FHEW for the comparison, and switch back.
   `EvalCompareSchemeSwitching`, `EvalMinSchemeSwitching` and `EvalMaxSchemeSwitching` do this. The capability is
   marked experimental; see `SCHEME_SWITCHING_CAPABILITY.md` and `scheme-switching.cpp` in `src/pke/examples`.
5. CKKS functional bootstrapping evaluates lookup tables and sign on CKKS ciphertexts. It is also marked experimental;
   see `CKKS_FUNCTIONAL_BOOTSTRAPING.md`.

There is no encrypted `if`. Compute both branches and combine them with an encrypted selector bit `b`:
`b * x + (1 - b) * y`.

## Depth

A leveled computation, with the depth fixed in advance, is the simplest and fastest choice whenever the depth is known
and moderate. Bootstrapping removes the limit at a high cost in time and memory. Before adding it:

- rewrite multiplication chains as balanced trees,
- lower polynomial degrees,
- check whether the computation can be split so that a client decrypts and re-encrypts between stages.

## Who holds the key

| Setting | Use |
|---|---|
| One client encrypts and decrypts, a server computes | any scheme, with `serialization.md` |
| Several data owners, no one may decrypt alone | threshold FHE, `multiparty.md` |
| Data encrypted for one party must be handed to another | proxy re-encryption, `multiparty.md` |

FHE protects the data from the party that computes. It does not prove that the computation was done correctly, and a
decrypted result reveals what the result itself reveals. For CKKS, read `CKKS_NOISE_FLOODING.md` in
`src/pke/examples` before sharing decrypted results with a party that does not hold the key.
