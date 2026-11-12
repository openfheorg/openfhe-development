---
name: openfhe
description: Build C++ applications with the OpenFHE homomorphic encryption library. Use when writing, debugging or reviewing code that computes on encrypted data with OpenFHE (BFV, BGV, CKKS, FHEW/TFHE binfhe, threshold FHE, proxy re-encryption), or when choosing an FHE scheme or its parameters.
---

# OpenFHE applications

Do not write OpenFHE code from memory. The parameter rules and several failure modes are not obvious, and some of
them produce wrong results with no error.

Read the guide first, then the reference file for the scheme in use:

1. `${CLAUDE_PLUGIN_ROOT}/README.md` – the workflow, how to choose a scheme, and the rules that prevent most failures
2. `${CLAUDE_PLUGIN_ROOT}/reference/` – one file per topic: `ckks.md`, `bfv-bgv.md`, `binfhe.md`, `multiparty.md`,
   `serialization.md`, `choosing-a-scheme.md`, `troubleshooting.md`, `examples-index.md`
3. `${CLAUDE_PLUGIN_ROOT}/template/` – a CMake project and `main.cpp` to copy as the starting point

If those paths do not exist, this skill was installed without the plugin. The same files are in the `agents`
directory of the OpenFHE source tree (https://github.com/openfheorg/openfhe-development), and in
`<install prefix>/share/openfhe/agents` when OpenFHE installed them.

Always finish by running the program on small inputs and comparing the decrypted result with the same computation in
the clear.
