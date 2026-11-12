# Serialization

Serialization moves crypto contexts, keys and ciphertexts between processes, for example between a client that holds
the secret key and a server that computes. Read `../README.md` first.

## Headers

`openfhe.h` does not include the serialization code. Add:

```cpp
#include "ciphertext-ser.h"
#include "cryptocontext-ser.h"
#include "key/key-ser.h"
#include "scheme/ckksrns/ckksrns-ser.h"   // or scheme/bfvrns/bfvrns-ser.h, scheme/bgvrns/bgvrns-ser.h
```

For binfhe, include `binfhecontext-ser.h`.

## Client: write

```cpp
Serial::SerializeToFile("cc.bin", cc, SerType::BINARY);
Serial::SerializeToFile("public.key", keys.publicKey, SerType::BINARY);
Serial::SerializeToFile("ct.bin", ciphertext, SerType::BINARY);

std::ofstream multKeys("mult.key", std::ios::out | std::ios::binary);
cc->SerializeEvalMultKey(multKeys, SerType::BINARY);

std::ofstream rotKeys("rot.key", std::ios::out | std::ios::binary);
cc->SerializeEvalAutomorphismKey(rotKeys, SerType::BINARY);
```

All of these functions, and the `Deserialize` ones below, return `false` on failure; check the result.
`Serial::Serialize(object, stream, SerType::BINARY)` writes to any `std::ostream`, for sending over a network.

`SerializeEvalMultKey(stream, type)` and `SerializeEvalAutomorphismKey(stream, type)` are static functions that write
the keys of every context in the process. To write the keys of one context or one key pair, pass the context or the
key tag as a third argument: `cc->SerializeEvalMultKey(stream, SerType::BINARY, cc)`.

The public key is needed only by a party that encrypts. A server that only computes does not need it.

## Server: read

```cpp
CryptoContext<DCRTPoly> cc;
Serial::DeserializeFromFile("cc.bin", cc, SerType::BINARY);

std::ifstream multKeys("mult.key", std::ios::in | std::ios::binary);
cc->DeserializeEvalMultKey(multKeys, SerType::BINARY);

std::ifstream rotKeys("rot.key", std::ios::in | std::ios::binary);
cc->DeserializeEvalAutomorphismKey(rotKeys, SerType::BINARY);

Ciphertext<DCRTPoly> ciphertext;
Serial::DeserializeFromFile("ct.bin", ciphertext, SerType::BINARY);
```

## Client: keep the secret key and decrypt later

A client that decrypts in a later run stores its secret key locally and reloads the context before it:

```cpp
Serial::SerializeToFile("secret.key", keys.secretKey, SerType::BINARY);     // first run; never leaves the client

CryptoContext<DCRTPoly> cc;                                                 // later run
Serial::DeserializeFromFile("cc.bin", cc, SerType::BINARY);
PrivateKey<DCRTPoly> secretKey;
Serial::DeserializeFromFile("secret.key", secretKey, SerType::BINARY);
Ciphertext<DCRTPoly> result;
Serial::DeserializeFromFile("result.bin", result, SerType::BINARY);

Plaintext plaintext;
cc->Decrypt(secretKey, result, &plaintext);
```

A public key is read the same way into a `PublicKey<DCRTPoly>`.

For a client and a server built from one project, add a second `add_executable` and `target_link_libraries` pair to
the template's `CMakeLists.txt`.

## Rules

- Deserialize the crypto context first, then the evaluation keys, then the ciphertexts.
- The server needs the context, the evaluation keys and the ciphertexts. It never needs the secret key; do not send
  it.
- A deserialized context keeps its enabled features. `Enable` does not have to be called again.
- Evaluation keys are stored in the context, not in a key object. Without `DeserializeEvalMultKey`, `EvalMult` throws
  that no multiplication key exists; the same holds for rotations and `DeserializeEvalAutomorphismKey`.
- Use `SerType::BINARY`. `SerType::JSON` is for inspection: in a test a JSON ciphertext was eight times the size of
  the binary one.
- Keep both sides on the same OpenFHE version and build configuration, such as the native integer size.
- When one process plays both roles, as in a test, call `cc->ClearEvalMultKeys()`,
  `cc->ClearEvalAutomorphismKeys()` and `CryptoContextFactory<DCRTPoly>::ReleaseAllContexts()` before deserializing,
  as the examples do. Otherwise the test reuses in-memory state and does not prove the round trip.
- Evaluation keys are large, megabytes each at ring dimension 16384 and growing with the ring dimension and depth.
  Generate only the rotation indices the computation uses.

## Further topics

Examples in the source tree:

| Topic | Read |
|---|---|
| CKKS client and server | `src/pke/examples/simple-real-numbers-serial.cpp` |
| BFV and BGV | `src/pke/examples/simple-integers-serial.cpp`, `simple-integers-serial-bgvrns.cpp` |
| CKKS bootstrapping keys | `src/pke/examples/ckks-bootstrap-keys-serial.cpp` |
| Smaller rotation keys at a reduced level | `src/pke/examples/ckks-bootstrapping-leveled-keys.cpp` |
| Scheme switching | `src/pke/examples/scheme-switching-serial.cpp` |
| binfhe | `src/binfhe/examples/boolean-serial-binary.cpp`, `boolean-serial-json.cpp` |
