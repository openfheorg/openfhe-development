Pseudorandom Number Generator (PRNG)
=====================================

Documentation for `core/include/utils/prng <https://github.com/openfheorg/openfhe-development/tree/main/src/core/include/utils/prng>`_

.. contents:: Core PRNG
   :depth: 2
   :local:
   :backlinks: none

Implemented PRNG hash function
-----------------------------

- Our cryptographic hash function which is based off of `Blake2b <https://blake2.net>`_, which allows fast hashing.

Using your own PRNG engine
-----------------------------------

To define new ``PRNG`` engines, refer to `blake2engine.h <https://github.com/openfheorg/openfhe-development/blob/main/src/core/include/utils/prng/blake2.h>`_.

Core PRNG Generated Docs
-------------------------------

.. autodoxygenindex::
   :project: core_utils_prng