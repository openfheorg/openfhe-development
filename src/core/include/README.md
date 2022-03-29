# Core Library Implementation

Contains the underlying primitives that are used in both `pke` and `binfhe`.

## Utils

Contains utilities for fast memory management, and generation of `PRNGs`

### Block Allocator

- Utility for allocating and freeing fixed blocks of memory memory.

- Prevents memory faults by using a heap

- Basically a custom memory management system.

### PRNG

- Our cryptographic hash function which is based off of [Blake2b](https://blake2.net), which allows fast hashing.

- To define new `PRNG` engines, refer to [blake2engine.h](prng/blake2engine.h).
