# OpenFHE

OpenFHE is a C++17 library for fully homomorphic encryption: BFV, BGV and CKKS (`pke`), and FHEW/TFHE-style Boolean
circuits (`binfhe`).

If you are writing an application that uses OpenFHE rather than changing the library, read `agents/README.md` instead of
this file.

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

Useful switches, each `ON` or `OFF`: `-DBUILD_UNITTESTS=ON`, `-DBUILD_EXAMPLES=ON`, `-DBUILD_BENCHMARKS=ON`,
`-DBUILD_EXTRAS=ON`, `-DWITH_OPENMP=ON`. The build type is set with `-DCMAKE_BUILD_TYPE=Release` or `Debug`. The full
list is at the top of `CMakeLists.txt`.

Warnings are errors (`-Wall -Werror`). The code must build with both GCC and Clang.

## Test

```bash
make testall                                        # core, pke and binfhe suites
unittest/pke_tests --gtest_filter='UTCKKSRNS*'      # one suite
```

A change to math or lattice code can behave differently per configuration. CI runs these, and a change that could be
affected should be checked against them locally:

- `-DNATIVE_SIZE=64` (default), `32`, `128`
- `-DMATHBACKEND=4` (default), `2`, `6` (`6` also needs `-DWITH_NTL=ON` and is not available with `NATIVE_SIZE=128`)
- `-DWITH_TCM=ON`, `-DCMAKE_BUILD_TYPE=Debug`

Every bug fix needs a regression test in the matching `unittest` directory.

## Style

Formatting and lint run through pre-commit, which pins its own clang-format and cpplint versions:

```bash
pre-commit run --files <changed files>
```

- Google C++ style with 4-space indentation and a 120-column limit.
- Classes, methods and enums are `CamelCase`; variables are `camelCase`; private and protected members are
  `m_camelCase`; constants and macros are `UPPER_CASE`.
- Include guards are named after the path from the repository root: `SRC_PKE_INCLUDE_CRYPTOCONTEXT_H_`.
- Public classes, methods and members carry Doxygen comments that state input constraints and the conditions that throw.
- Report errors with `OPENFHE_THROW` (`src/core/include/utils/exception.h`).
- Library code under `src/*/lib` and `src/*/include` must not write to `std::cout` or `std::cerr`; use
  `utils/diagnostic_output.h`. A pre-commit hook enforces this.
- An exception thrown inside an OpenMP region must be caught in that region; see `ThreadException` in `exception.h`.
- No manual `new`/`delete`.

## Keeping agents/ current

`agents/` is a guide that teaches coding agents to write applications with OpenFHE. It names API functions, defaults,
exception messages and examples, so a library change can make it wrong. Update it in the same change when you:

- rename, remove or add a public function, parameter, enum value or feature;
- change a default, a parameter rule or which ring dimension is chosen;
- change the text of an exception or turn a silent failure into an error;
- add, rename or remove an example;
- change the OpenFHE version in `CMakeLists.txt`: set the same version in `agents/.claude-plugin/plugin.json`, and
  the major and minor version where `agents/README.md` names it.

How:

1. Run `agents/maint/update-agents-guide.sh`. It runs the checker and lists the guide files your changes may affect.
2. Edit those files. Keep them short and within 120 columns. Verify each statement you add or change by building and
   running a small program against the library; do not write from memory.
3. Behaviour the guide states is pinned by `src/pke/unittest/UnitTestAgentGuide.cpp` and
   `src/binfhe/unittest/UnitTestAgentGuide.cpp`. If one of those tests fails, the failure names the guide file to
   update; change the guide and the test together.
4. `agents/maint/check-agents-guide.sh` must pass. It runs as a pre-commit hook and in CI.
5. A pull request that changes `src/*/include` or `src/*/examples` without touching `agents/` gets a warning from the
   `guide-reminder` check. It does not block the merge; decide whether the guide needs an update.

## Contributing

- Branch from `dev` and open the pull request against `dev`.
- Each change needs a GitHub issue.
- Changes that break the existing public API are held for a major release; raise them with the maintainers first.

More detail: `docs/sphinx_rsts/contributing/`.
