# Reviewing a change to OpenFHE

This is for reviewing a change to the library itself: a pull request, a branch or a working tree. It lists what a
general review tends to miss in this code base. For an application written with OpenFHE, use `agents/README.md`.

## Where to read about OpenFHE

Understand the area before judging a change to it. The repository already explains most of it:

- `agents/README.md` and the files in `agents/reference` state how each scheme is expected to behave for an
  application: parameters, defaults, limits and the errors it should raise. A change that makes one of those
  statements false is a finding.
- The `README.md` files under `src`, such as `src/pke/include/scheme/README.md` and
  `src/pke/include/keyswitch/README.md`, describe the design of that directory.
- `src/pke/examples` and `src/binfhe/examples` show the intended use of the API; `agents/reference/examples-index.md`
  lists them by task.
- The unit tests of the changed files show which behaviour is already pinned.
- `docs/sphinx_rsts` holds the published documentation, including `docs/sphinx_rsts/intro/security.rst`.

## How to review

1. A review does not edit. Report the findings and change code only when asked to.
2. Find the whole change. Start with `git status --short`. For a branch or a pull request, compare with the branch it
   will be merged into, normally `dev`: `git diff origin/dev...HEAD`. Work that is not committed does not show there;
   read `git diff --cached` and `git diff` as well, and list new files with
   `git ls-files --others --exclude-standard`. Then read the callers and the tests of what the change touches, not
   only the changed lines.
3. Run `git diff --check` on the same ranges. Do not run `pre-commit` during a review: several of its hooks rewrite
   the files they check. The lint job in CI reports formatting.
4. Verify a finding before reporting it: build, run the affected test, or write a small program outside the repository
   that shows the behaviour. Say what you ran and what you could not run. Give a count, or say "never" or "all", only
   after measuring it.
5. Report a numbered list, most serious first. Give the file and line for each finding and mark it as confirmed
   (you reproduced it) or possible (state the condition under which it happens).
6. If the pull request has a description, compare it with the diff. Flag functions or behaviour it describes that the
   diff does not contain.

## What to check

### Logic

- Work out what the new code is meant to do, from the issue, the description and the tests, then check that it does
  that on every path: each scheme, scaling technique and key-switching method it can be reached with, not only the
  one the author tested.
- Find the existing code that does the same or a related job and compare. The new code must not contradict it: the
  same inputs handled differently, a different rounding or level convention, an invariant the rest of the library
  relies on (the format of a polynomial, the level and scaling factor of a ciphertext, the key tag) left broken.
- Check that code which depended on the old behaviour still holds: callers, the other schemes that share the
  function, serialization and the examples.
- Check what the new code needs to have happened first, such as a setup call or keys that must already exist. It
  should test for that and throw, or the Doxygen comment should state it. Check that the examples and tests call
  things in that order.
- If the change duplicates logic that already exists, say so and name the existing function.

### Build configurations

CI builds a pull request with `MATHBACKEND` 2, 4 and 6, and only the backend 4 build has `WITH_TCM=ON`. The `Debug`
builds and the other combinations run after the merge to `main`, so a change they could affect has to be built by
hand. `NATIVE_SIZE` can be 32, 64 or 128.

- Integer width. `NativeInteger` follows `NATIVE_SIZE`. Look for values assumed to fit `uint32_t` or `uint64_t`,
  narrowing conversions, shifts by the full width, and constants that do not fit 32 bits.
- Code under `src/core` that is specific to one math backend, or that only one backend exercises.
- A variable used only inside an assertion is unused in a release build, and warnings are errors.
- A test that asserts on heap usage is not stable with `WITH_TCM=ON`; it should skip itself there.

### C++

- The style rules in `AGENTS.md`: `OPENFHE_THROW`, no output to `std::cout` in library code, no manual `new`.
- Member initialisers in the order of declaration; GCC rejects the other order with `-Werror=reorder`.
- Every field initialised. A copy or an assignment keeps all of the state, including key tags, levels and scaling
  factors.
- Encapsulation kept: no member made public and no `const` dropped only to get past a compile error.
- A new template or overload is instantiated by a test or an example. Template code that nothing instantiates is not
  compiled, so its errors stay hidden.
- OpenMP. An exception thrown inside a parallel region is caught in that region (`ThreadException`). The value passed
  to `num_threads` is never zero: at run time zero means all threads, which ignores the limit the user set. Thread
  counts go through `OpenFHEParallelControls`.

### Public API and serialization

- A removed or renamed public function, a changed signature or a dropped overload breaks applications. It waits for a
  major release.
- A change to the fields a class saves changes the serialized format, so data written by an earlier release may no
  longer load. Point it out.
- Doxygen comments describe what the code does now: input constraints, what throws, and what is returned. Check them
  against the implementation, not against the intent.
- `agents/` is updated when the change calls for it; see "Keeping agents/ current" in `AGENTS.md`.

### Parameters and security

- A change to parameter generation, noise estimation or the tables in `src/core/lib/lattice/stdlatticeparms.cpp` can
  weaken security or correctness without failing a test. It needs a stated reason and a reference.

### Tests

- A bug fix has a regression test in the matching `unittest` directory, and the test fails without the fix.
- The test parameters can show the bug. The smallest ring dimension or slot count often cannot: a wrong rotation
  index can be invisible at 8 slots and plain at 64. Ask which configuration distinguishes the correct code from the
  broken code.
- Each overload is called directly by a test, not only reached through another one.

### Performance

- A performance claim comes with numbers measured before and after, on the same machine and configuration.
- No new copies of polynomials, ciphertexts or keys where a reference would do.
