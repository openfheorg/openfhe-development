# PRNG Engine(s)

Refer to our [readthedocs - PRNG Engine(s)](https://openfhe-development.readthedocs.io/en/latest/sphinx_rsts/modules/core/utils/prng.html) for more information.

Additionally, we refer users to [sampling documentation](https://openfhe-development.readthedocs.io/en/latest/sphinx_rsts/modules/core/math/sampling.html) for
more information about sampling in OpenFHE, as well as how to use these samplers.

## Blake2

- Our cryptographic hash function is based off of [Blake2b](https://blake2.net), which allows fast hashing.

## Using a custom PRNG Engine

To define new `PRNG` engines, refer to [blake2engine.h](blake2engine.h).
