# OpenFHE

OpenFHE is a C++17 library for fully homomorphic encryption: BFV, BGV and CKKS
(`pke`), and FHEW/TFHE-style Boolean circuits (`binfhe`).

If you are writing an application that uses OpenFHE rather than changing the
library, read `agents/README.md` instead of this file.

## Layout

- `src/core` – math backends, lattice and polynomial layers, utilities
- `src/pke` – BFV, BGV, CKKS, threshold FHE, proxy re-encryption, scheme switching
- `src/binfhe` – DM, CGGI and LMKCDEY Boolean FHE
- `src/*/include`, `src/*/lib` – headers and sources
- `src/*/unittest` – GoogleTest suites
- `src/*/examples` – runnable examples, one program per file
- `benchmark` – Google Benchmark programs
- `docs` – Sphinx sources, published on Read the Docs
- `third-party` – git submodules; do not edit

## Build

```bash
mkdir build && cd build
cmake ..
make -j
```

Useful options: `-DCMAKE_BUILD_TYPE=Debug`, `-DBUILD_UNITTESTS`,
`-DBUILD_EXAMPLES`, `-DBUILD_BENCHMARKS`, `-DBUILD_EXTRAS`, `-DWITH_OPENMP`.
The full list is at the top of `CMakeLists.txt`.

Warnings are errors (`-Wall -Werror`). The code must build with both GCC and
Clang.

## Test

```bash
make testall                                        # core, pke and binfhe suites
unittest/pke_tests --gtest_filter='UTCKKSRNS*'      # one suite
```

A change to math or lattice code can behave differently per configuration. CI
runs these, and a change that could be affected should be checked against them
locally:

- `-DNATIVE_SIZE=64` (default), `32`, `128`
- `-DMATHBACKEND=4` (default), `2`, `6` (`6` also needs `-DWITH_NTL=ON` and is
  not available with `NATIVE_SIZE=128`)
- `-DWITH_TCM=ON`, `-DCMAKE_BUILD_TYPE=Debug`

Every bug fix needs a regression test in the matching `unittest` directory.

## Style

Formatting and lint run through pre-commit, which pins its own clang-format and
cpplint versions:

```bash
pre-commit run --files <changed files>
```

- Google C++ style with 4-space indentation and a 120-column limit.
- Classes, methods and enums are `CamelCase`; variables are `camelCase`; private
  and protected members are `m_camelCase`; constants and macros are `UPPER_CASE`.
- Include guards are named after the path from the repository root:
  `SRC_PKE_INCLUDE_CRYPTOCONTEXT_H_`.
- Public classes, methods and members carry Doxygen comments that state input
  constraints and the conditions that throw.
- Report errors with `OPENFHE_THROW` (`src/core/include/utils/exception.h`).
- Library code under `src/*/lib` and `src/*/include` must not write to
  `std::cout` or `std::cerr`; use `utils/diagnostic_output.h`. A pre-commit hook
  enforces this.
- An exception thrown inside an OpenMP region must be caught in that region;
  see `ThreadException` in `exception.h`.
- No manual `new`/`delete`.

## Contributing

- Branch from `dev` and open the pull request against `dev`.
- Each change needs a GitHub issue.
- Changes that break the existing public API are held for a major release;
  raise them with the maintainers first.

More detail: `docs/sphinx_rsts/contributing/`.
