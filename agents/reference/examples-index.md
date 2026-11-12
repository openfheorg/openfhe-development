# Examples index

The example programs are in the OpenFHE source tree
(https://github.com/openfheorg/openfhe-development). Each is one self-contained program and a good starting point for
the task next to it. Paths are relative to the repository root.

## CKKS, in `src/pke/examples`

| Task | Example |
|---|---|
| Add, multiply and rotate real vectors | `simple-real-numbers.cpp` |
| Scaling techniques, key switching, hoisted rotations | `advanced-real-numbers.cpp` |
| Complex numbers | `simple-complex-numbers.cpp` |
| Polynomial evaluation | `polynomial-evaluation.cpp` |
| Logistic, square root and other smooth functions | `function-evaluation.cpp` |
| Weighted sum of ciphertexts | `linearwsum-evaluation.cpp` |
| Inner product | `inner-product.cpp` |
| Bootstrapping | `simple-ckks-bootstrapping.cpp` |
| Bootstrapping with few slots | `advanced-ckks-bootstrapping.cpp` |
| Bootstrapping with higher precision | `iterative-ckks-bootstrapping.cpp` |
| Lookup tables through functional bootstrapping | `functional-bootstrapping-ckks.cpp` |
| Smooth functions through functional bootstrapping | `FE-functional-bootstrapping-ckks.cpp` |
| Scaling factors above the word size | `simple-real-numbers-composite-scaling.cpp` |
| Noise flooding at decryption | `ckks-noise-flooding.cpp` |
| Releasing bootstrapping memory | `ckks-release-memory.cpp` |
| Smaller rotation keys at a reduced level | `ckks-bootstrapping-leveled-keys.cpp` |

## BFV and BGV, in `src/pke/examples`

| Task | Example |
|---|---|
| Add, multiply and rotate integer vectors, BFV | `simple-integers.cpp` |
| The same in BGV | `simple-integers-bgvrns.cpp` |
| Deeper multiplication chains | `depth-bfvrns.cpp`, `depth-bgvrns.cpp` |
| Rotations in every scheme | `rotation.cpp` |
| Inner product | `inner-product.cpp` |

## binfhe, in `src/binfhe/examples`

| Task | Example |
|---|---|
| Boolean gates | `boolean.cpp`, `boolean-truth-tables.cpp` |
| Gates with three or four inputs | `boolean-multi-input.cpp` |
| Other bootstrapping methods | `boolean-ap.cpp`, `boolean-lmkcdey.cpp` |
| Lookup table on a small integer | `eval-function.cpp` |
| Sign of a large-precision value | `eval-sign.cpp` |
| Floor and digit decomposition | `eval-flooring.cpp`, `eval-decomp.cpp` |

## Several parties, in `src/pke/examples`

| Task | Example |
|---|---|
| Threshold FHE with two parties, in BFV, BGV and CKKS | `threshold-fhe.cpp` |
| Threshold FHE with five parties | `threshold-fhe-5p.cpp` |
| Interactive bootstrapping | `interactive-bootstrapping.cpp`, `tckks-interactive-mp-bootstrapping.cpp` |
| Proxy re-encryption | `pre-buffer.cpp`, `pre-hra-secure.cpp` |

## Mixing schemes, in `src/pke/examples`

| Task | Example |
|---|---|
| Comparison, min and max by switching between CKKS and FHEW | `scheme-switching.cpp` |

## Serialization

| Task | Example |
|---|---|
| CKKS client and server | `src/pke/examples/simple-real-numbers-serial.cpp` |
| BFV, BGV | `src/pke/examples/simple-integers-serial.cpp`, `simple-integers-serial-bgvrns.cpp` |
| Bootstrapping keys | `src/pke/examples/ckks-bootstrap-keys-serial.cpp` |
| Scheme switching | `src/pke/examples/scheme-switching-serial.cpp` |
| binfhe | `src/binfhe/examples/boolean-serial-binary.cpp`, `boolean-serial-json.cpp` |

## Background notes, in `src/pke/examples`

`CKKS_BOOTSTRAPPING.md`, `CKKS_FUNCTIONAL_BOOTSTRAPING.md`, `CKKS_NOISE_FLOODING.md`, `COMPOSITE_SCALING.md`,
`FUNCTION_EVALUATION.md`, `INTERACTIVE_BOOTSTRAPPING.md`, `SCHEME_SWITCHING_CAPABILITY.md`.
