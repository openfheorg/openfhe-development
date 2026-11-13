# Threshold FHE and proxy re-encryption

Read `../README.md` first, then the reference for the scheme the parties compute with.

## Threshold FHE

Several parties hold shares of the secret key. Anyone can encrypt to the joint public key and compute on the
ciphertexts, but decryption needs every party. It is supported for BFV, BGV and CKKS and needs `Enable(MULTIPARTY)`.

### Joint keys

Each party derives its key pair from the previous party's public key. The public key of the last party is the joint
public key.

```cpp
cc->Enable(PKE);
cc->Enable(KEYSWITCH);
cc->Enable(LEVELEDSHE);
cc->Enable(ADVANCEDSHE);
cc->Enable(MULTIPARTY);

auto kpA = cc->KeyGen();                             // party A
auto kpB = cc->MultipartyKeyGen(kpA.publicKey);      // party B; kpB.publicKey is the joint key

auto ct = cc->Encrypt(kpB.publicKey, plaintext);
```

### Joint multiplication key

Multiplication needs a key for the joint secret, built in rounds between the parties:

```cpp
auto multA   = cc->KeySwitchGen(kpA.secretKey, kpA.secretKey);                              // A
auto multB   = cc->MultiKeySwitchGen(kpB.secretKey, kpB.secretKey, multA);                  // B
auto multAB  = cc->MultiAddEvalKeys(multA, multB, kpB.publicKey->GetKeyTag());
auto multBAB = cc->MultiMultEvalKey(kpB.secretKey, multAB, kpB.publicKey->GetKeyTag());     // B
auto multAAB = cc->MultiMultEvalKey(kpA.secretKey, multAB, kpB.publicKey->GetKeyTag());     // A
cc->InsertEvalMultKey({cc->MultiAddEvalMultKeys(multAAB, multBAB, multAB->GetKeyTag())});
```

Rotation and summation keys are built the same way with `MultiEvalAtIndexKeyGen`, `MultiEvalSumKeyGen`,
`MultiAddEvalAutomorphismKeys` and `MultiAddEvalSumKeys`; see `threshold-fhe.cpp`.

### Decryption

Each party produces a partial decryption, and the parts are fused. Exactly one party uses the `Lead` call.

```cpp
auto partA = cc->MultipartyDecryptLead({ct}, kpA.secretKey);
auto partB = cc->MultipartyDecryptMain({ct}, kpB.secretKey);

Plaintext result;
cc->MultipartyDecryptFusion({partA[0], partB[0]}, &result);
result->SetLength(n);
```

### Rules

- Encrypt with the joint public key, the last party's. A ciphertext encrypted under one party's own key cannot be
  multiplied; `EvalMult` throws that no multiplication key exists for that key.
- A single party's `Decrypt` does not work on a joint ciphertext. In CKKS it throws "approximation error is too high".
- Every party must take part in every decryption. `ShareKeys` and `RecoverSharedKey` in `cryptocontext.h` support
  recovering the share of a party that drops out (threshold FHE with aborts).
- For BFV and BGV in production, set `parameters.SetMultipartyMode(NOISE_FLOODING_MULTIPARTY)`. The default,
  `FIXED_NOISE_MULTIPARTY`, adds less noise to the decryption shares and is weaker. For CKKS, read
  `CKKS_NOISE_FLOODING.md`.
- In a real deployment each step runs on a different machine, so the keys and partial decryptions are serialized
  between them; see `serialization.md`. A secret key share never leaves its owner.

## Proxy re-encryption

A proxy converts a ciphertext encrypted for Alice into one encrypted for Bob, without seeing the plaintext. It needs
a PRE mode in the parameters and `Enable(PRE)`.

```cpp
parameters.SetPREMode(INDCPA);          // before GenCryptoContext
auto cc = GenCryptoContext(parameters);
cc->Enable(PKE);
cc->Enable(KEYSWITCH);
cc->Enable(LEVELEDSHE);
cc->Enable(PRE);

auto alice = cc->KeyGen();
auto bob   = cc->KeyGen();

auto ct       = cc->Encrypt(alice.publicKey, plaintext);
auto reKey    = cc->ReKeyGen(alice.secretKey, bob.publicKey);   // made by Alice, given to the proxy
auto ctForBob = cc->ReEncrypt(ct, reKey);                       // done by the proxy

Plaintext result;
cc->Decrypt(bob.secretKey, ctForBob, &result);
```

Without `SetPREMode`, `ReKeyGen` throws "PRE is disabled (default = NOT_SET)" in CKKS and BGV. BFV accepts the
default, but set the mode there too.

| Mode | Supported in |
|---|---|
| `INDCPA` | BFV, BGV, CKKS |
| `FIXED_NOISE_HRA` | BGV |
| `NOISE_FLOODING_HRA` | BGV, with the extra settings below |

An unsupported combination throws in `GenCryptoContext`. The HRA modes protect against a stronger attacker than
`INDCPA`; `pre-hra-secure.cpp` explains the difference. Choose the mode deliberately.

`NOISE_FLOODING_HRA` needs all of these, and throws without any one of them:

```cpp
CCParams<CryptoContextBGVRNS> parameters;
parameters.SetPlaintextModulus(2);
parameters.SetPREMode(NOISE_FLOODING_HRA);
parameters.SetScalingTechnique(FIXEDMANUAL);
parameters.SetPRENumHops(numHops);          // number of re-encryptions to support, at least 1
parameters.SetMultiplicativeDepth(0);
parameters.SetRingDim(32768);               // must be set by hand
// do not call SetFirstModSize or SetScalingModSize
```

This was tested with plaintext modulus 2 and `MakeCoefPackedPlaintext`, as `pre-hra-secure.cpp` uses. The same setup
with plaintext modulus 65537 threw in `GenCryptoContext`. Start from that example, which also sets the statistical
security and the number of adversarial queries.

## Further topics

Examples in `src/pke/examples` of the source tree:

| Topic | Read |
|---|---|
| Two-party threshold FHE in BFV, BGV and CKKS | `threshold-fhe.cpp` |
| Five parties | `threshold-fhe-5p.cpp` |
| Threshold security modes | `docs/static_docs/Threshold_FHE.md` |
| Interactive bootstrapping between parties | `INTERACTIVE_BOOTSTRAPPING.md`, `interactive-bootstrapping.cpp` |
| Proxy re-encryption | `pre-buffer.cpp`, `pre-hra-secure.cpp` |
