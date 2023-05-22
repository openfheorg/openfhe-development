# Misc. Utils

## Block Allocator

- Utility for allocating and freeing fixed blocks of memory memory.

- Prevents memory faults by using a heap

- Basically a custom memory management system.

## PRNG

- Our cryptographic hash function is based off of [Blake2b](https://blake2.net), which allows fast hashing.

- To define new `PRNG` engines, refer to [blake2engine.h](prng/blake2engine.h).

- Additionally, we refer users to [sampling-readme](https://openfhe-development.readthedocs.io/en/latest/assets/sphinx_rsts/modules/core/math/sampling.html) for more information about sampling in OpenFHE, as well as how to use these samplers.