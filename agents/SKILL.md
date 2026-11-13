---
name: openfhe
description: Build C++ applications with the OpenFHE homomorphic encryption library. Use when writing, debugging or reviewing code that computes on encrypted data with OpenFHE (BFV, BGV, CKKS, FHEW/TFHE binfhe, threshold FHE, proxy re-encryption), or when choosing an FHE scheme or its parameters.
---

# OpenFHE applications

Do not write OpenFHE code from memory. The parameter rules and several failure modes are not obvious, and some of
them produce wrong results with no error.

Read the guide in this directory first, then the reference file for the scheme in use:

1. [README.md](README.md) – the workflow, how to choose a scheme, and the rules that prevent most failures
2. [reference/](reference/) – one file per topic: [ckks.md](reference/ckks.md), [bfv-bgv.md](reference/bfv-bgv.md),
   [binfhe.md](reference/binfhe.md), [multiparty.md](reference/multiparty.md),
   [serialization.md](reference/serialization.md), [choosing-a-scheme.md](reference/choosing-a-scheme.md),
   [troubleshooting.md](reference/troubleshooting.md), [examples-index.md](reference/examples-index.md)
3. [template/](template/) – a CMake project with a starting program for CKKS, BFV and binfhe

Always finish by running the program on small inputs and comparing the decrypted result with the same computation in
the clear.
