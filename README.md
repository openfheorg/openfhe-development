# Sparse Hermite interpolation: paper artifact

This branch implements the methods and reproduction workflow for **Sparse Hermite
Interpolation Method for Discrete-CKKS Functional Bootstrapping**.

This is repo is cleaned copy of an internal experimental repo and is produced using Codex.

**Start with the quick checks. Full paper experiments require an explicit
`run --execute` command and a machine with enough memory.** The local migration
validation does not constitute a rerun of the paper's full benchmarks.

## What is reproduced

| Paper item | Command / source | Result |
| --- | --- | --- |
| Tables 1–2 | Analytical comparisons and definitions in the paper | No benchmark required |
| Table 3 | `python3 artifacts/reproduce.py theory` | `table3.csv`, `.md`, `.tex`: seven LUT/size rows, orders 1–5 |
| Table 4 | `run --table=4 --execute`, then `report --table=4` | Fifteen rows of measured LUT/total latency, key switches and levels |
| Table 5 | `run --table=5 --execute`, then `report --table=5` | Fifteen rows of theoretical threshold, measured noise floor and capacity |
| Figure 1 | Produced by the Table 5 report | `figure1.png`, `.pdf`, and `phase-data.csv` |
| Figures 2–3 | `python3 artifacts/reproduce.py theory` | Theoretical noise curves and the paired Sparse-THI/AKP interpolation surfaces |

`BKSS` in the scripts and reports selects **BKSS_NEW**, the optimized real-valued
BKSS implementation from Section 5.3. Its threshold and noise model are the same
as those of the original BKSS; it is not presented as a separate noise-cleaning
method. `BKSS_LEGACY` selects the original four-polynomial evaluator for checks.
`FULL_THI` is available for orders 1–3 and is labeled **CKKL** in Table 5.
The encrypted paper experiments use the centered identity LUT. AES S-box, MSB
and LSB are also included in the theoretical Table 3 calculation.

## Generate tables from the bundled measurements (no FHE build or long runs)

The [historical results](artifacts/results/archived/README.md) contain all 15 compatible
Table 4 timing cases and all 15 Table 5 noise cases copied byte-for-byte from the
research experiment archive. With the Python dependencies installed, run:

```bash
python3 artifacts/reproduce.py archived-report
python3 artifacts/reproduce.py theory
```

The first command regenerates CSV, Markdown and LaTeX tables in
`artifacts/results/archived-report/`; the second regenerates Table 3 and Figures
2–3. Both run without an FHE executable. Generated
[Table 4](artifacts/results/archived-report/table4.md) and
[Table 5](artifacts/results/archived-report/table5.md) are also bundled for reading.

All rows of Tables 4 and 5 are available.

## Dependencies and build

The paper used Debian 13, clang++ 19, an AMD Ryzen AI MAX+ 395 CPU, 128 GB RAM,
and one CPU thread. This artifact uses the branch's native arithmetic backend.
A Linux x86-64 machine is sufficient for the quick checks. Allow several GB for
source/build files and use a 128 GB machine for the full experiment matrix;
128 GB is the paper's machine capacity, not a measured minimum requirement.
No GPU or proprietary software is needed.

The build uses NATIVE_SIZE=64, MATHBACKEND=6, NTL/GMP, OpenMP, tcmalloc, Release
optimization, and native arithmetic. Python **3.10 or newer**, NumPy
**2.1.2**, and Matplotlib **3.10.7** are used for tables and figures. CMake 3.16+
is required. The OpenFHE submodule revisions are fixed by this repository.
The exact compiler, CMake options, libraries, CPU, source digest and binary
hashes are recorded alongside every run; retain them when submitting results.

Note that the original experiments are run with HEXL enabled. We refer the reader to openfhe-configurator to see how to enable HEXL. Note that you also need to enable `WITH_FBT_INSTRUMENTATION` for the cmake commands for openfhe-configurator.

From a clone of this branch, run:

```bash
# Debian 13 packages; system package installation needs administrator rights.
sudo apt-get update
sudo apt-get install -y build-essential git cmake clang-19 libomp-19-dev \
    libntl-dev libgmp-dev autoconf automake libtool pkg-config \
    python3 python3-venv util-linux

git submodule update --init --recursive
python3 -m venv artifacts/.venv
. artifacts/.venv/bin/activate
python3 -m pip install -r artifacts/requirements.txt

# Builds OpenFHE, the driver and unit-test binaries. Does not run experiments.
JOBS=4 bash artifacts/build.sh
```

The default build directory is `build-artifact/`. The script accepts a different
directory as its first argument. `CC` and `CXX` override the compiler; `JOBS`
controls build parallelism. The initial build needs internet access to obtain
submodules and Python packages. Once built, all experiment and report
commands work without network access.

For development on a machine without the paper's toolchain, for example:

```bash
CC=clang CXX=clang++ WITH_TCM=OFF \
    JOBS=4 bash artifacts/build.sh build-smoke
python3 artifacts/reproduce.py smoke \
    --binary=build-smoke/bin/examples/pke/fbt-benchmark \
    --output=artifacts/results/smoke-native
```

This alternative is suitable for correctness checks; its latencies must not be
presented as a matching hardware reproduction. The normal library build keeps
`WITH_FBT_INSTRUMENTATION` off unless explicitly requested.

## Quick validation (no full benchmark)

```bash
. artifacts/.venv/bin/activate
python3 -m unittest discover -s artifacts -p 'test_*.py'
OMP_NUM_THREADS=1 build-artifact/unittest/pke_tests \
    --gtest_filter='HermiteComparison.*:PaperInterpolation/*'
OMP_NUM_THREADS=1 build-artifact/unittest/core_tests \
    --gtest_filter='UTNTT.*:UTTransform.*:UTBinVect.*:UTPoly.*:UTDCRTPoly.*'
python3 artifacts/reproduce.py smoke
python3 artifacts/reproduce.py check-counts
python3 artifacts/reproduce.py theory
python3 artifacts/reproduce.py plan
```

`smoke` checks 24
small configurations at **N=256**, both packing modes, FULL_THI orders 1–3,
and Sparse-THI orders 1, 2, 3 and 5. Every decoded result must be exact.
These rings use `--unsafe`/`HEStd_NotSet` and are only for testing.
`check-counts` verifies all 15 Table 4 key-switch and level counts at N=256,
without running latency benchmarks at the paper's ring sizes.

## Reproduce the experimental tables on the experiment machine

This can take hours to reproduce. We also provide our raw data and you can use `python3 artifacts/reproduce.py archived-report`.

All rows use log2(scale)=59, EvalExp degree 58, SPARSE_TERNARY secrets, HYBRID
key switching, FIXEDMANUAL scaling, level budgets `{3,2}`, and full packing.
`slots=N` in the driver means N RLWE values, processed through two CKKS branches.
The total key-switch count in each raw row includes both branches; the Table 4
report divides it by two, as required by the paper.

| Matrix | p=16 | p=256 |
| --- | --- | --- |
| Table 4 | N=65536; AKP orders 1–3, BKSS order 1, Sparse-THI orders 1–3 and 5 | N=131072; AKP/Sparse-THI orders 1–3, BKSS order 1 |
| Table 5 / Figure 1 | N=65536, except Sparse-THI orders 3 and 5 use N=131072; additionally CKKL order 1 | N=131072; AKP/Sparse-THI orders 1–2, BKSS/CKKL order 1 |

The two starred Table 4 rows (p=16, Sparse-THI orders 3 and 5) explicitly disable
the security estimator, reproducing the paper's illustrative parameters. Table 5
uses the larger ring for those orders. As explained in the paper, the remaining
sparse-secret configurations follow historical security thresholds; a successful
run is not a new security assessment.

```bash
# Optional: select an otherwise idle logical CPU from `lscpu`.
# Without --cpu, the runner selects the first CPU allowed by the process affinity.
python3 artifacts/reproduce.py run --table=4 --execute \
    --output=artifacts/results/run
python3 artifacts/reproduce.py run --table=5 --execute \
    --output=artifacts/results/run

# Or run both tables in one command:
# python3 artifacts/reproduce.py run --table=all --execute

# Report generation reads logs only; missing inputs cause an error.
python3 artifacts/reproduce.py report --table=all \
    --input=artifacts/results/run --output=artifacts/results/report
```

Each Table 4 configuration generates one key/context setup, one warm-up FBT,
and five measured FBT runs. Setup, key generation, encryption and decryption are
outside the timing interval, matching the supplied research driver. `EvalLUT`
starts immediately after EvalExp and includes polynomial-power precomputation;
`Total` covers `EvalFBT`, including homomorphic encoding and decoding. Precision
runs decrypt intermediate states and must not be used for timing comparisons.
The runner pins each FHE process to one CPU and sets `OMP_NUM_THREADS=1`.

Table 5 sweeps noise bases 24–53 for p=16 and 24–49 for p=256. Base b injects
normalized real noise `2^(b-59)` immediately before EvalExp, with the existing
K=25 normalization. The bound estimator preserves the private script:
start with the first noise point, then maximize the output residual over points
with `log v < log v' + 1` and `log v < -25`. The theoretical threshold includes
the original full-packing correction of `-0.5/n`. Capacity follows equations
(4)–(5), with base-2 logs:

```text
log I = (log B + n log T - log n)/(n+1)
log output_at_I = log B + log(1+1/n)
capacity_bits = log I - log output_at_I
```

Full experiment wall time and peak memory have **not** been measured during the
migration. Table 4 alone contains about 51 minutes of timed FBT calls at the
paper's latencies, before setup/key-generation costs. Dense precision sweeps
are more expensive because of intermediate decryption. Reserve several hours
and record actual resource usage on the experiment machine.

## Source organization and reuse

- [hermite.h](src/core/include/math/hermite.h) and
  [hermite.cpp](src/core/lib/math/hermite.cpp): interpolation selection and
  coefficient generation. Existing calls still default to AKP.
- [ckksrns-fhe.cpp](src/pke/lib/scheme/ckksrns/ckksrns-fhe.cpp): explicit method
  routing, depth accounting and both packing paths. BKSS/BKSS_NEW currently
  require FIXEDMANUAL with composite degree 1. FULL_THI supports orders 1–3.
- [ckksrns-advancedshe.cpp](src/pke/lib/scheme/ckksrns/ckksrns-advancedshe.cpp):
  shared BSGS powers and the BKSS polynomial evaluator.
- [fbt-benchmark.cpp](src/pke/examples/fbt-benchmark.cpp): one configuration per
  process, verification, timing and precision modes. `--help` lists its options.
- [artifacts/reproduce.py](artifacts/reproduce.py),
  [theory.py](artifacts/theory.py), and [figures.py](artifacts/figures.py):
  experiment matrix, strict reporting, analytical models and plotting.

For example, generate a BKSS coefficient layout and use the same explicit method
in `GetFBTDepth`, `EvalFBTSetup` and `EvalFBT`:

```cpp
auto method = lbcrypto::DiscreteCKKSInterpolationMethod::BKSS_NEW;
auto coeffs = lbcrypto::GetHermiteTrigCoefficients(lut, p, 1, scale, method);
```

BKSS coefficients are packed evaluator data, not an ordinary polynomial for
`EvalPoly`. FULL_THI coefficients are an ordinary holomorphic polynomial and are
evaluated directly, without the `2*Re` reconstruction used by AKP/Sparse-THI.
`GetHermiteTrigCoefficientsFullTHIForComplexLUT` also accepts complex LUT values.
Use the paper's normalization `scale=p` and matching `postScaling=p` for integer
LUTs of magnitude at most p/2. FULL_THI uses the generic Paterson–Stockmeyer
evaluator; at p=256, the old test normalization `scale=32` caused incorrect
encrypted results, while `scale=256` passed for both centered and shifted LUTs.
Validate accuracy when changing the LUT range or normalization.
To explore a different matrix, create a separate `Case` list/output directory;
the published paper matrix is kept fixed for review.

The branch's native arithmetic and mainline optimizations are retained.
Matching operation counts is checked independently from matching wall-clock times. Local reference directories `ac-81/` and
`openfhe-development-private/` are preserved and ignored by Git; the artifact has
no runtime dependence on either directory.

---

OpenFHE - Open-Source Fully Homomorphic Encryption Library
=====================================

Fully Homomorphic Encryption (FHE) is a powerful cryptographic primitive that enables performing computations over encrypted data without having access to the secret key.
OpenFHE is an open-source FHE library that includes efficient implementations of all common FHE schemes:

- Brakerski/Fan-Vercauteren (BFV) scheme for integer arithmetic
- Brakerski-Gentry-Vaikuntanathan (BGV) scheme for integer arithmetic
- Cheon-Kim-Kim-Song (CKKS) scheme for real-number arithmetic (includes approximate bootstrapping)
- Ducas-Micciancio (DM/FHEW), Chillotti-Gama-Georgieva-Izabachene (CGGI/TFHE), and Lee-Micciancio-Kim-Choi-Deryabin-Eom-Yoo (LMKCDEY) schemes for evaluating Boolean circuits and arbitrary functions over larger plaintext spaces using lookup tables

OpenFHE also supports hybrid vectorized schemes, with the goal of enabling the FHEW/TFHE-like functional bootstrapping capability for schemes such as CKKS and BFV. In particular, OpenFHE supports

- Switching between CKKS and FHEW/TFHE to evaluate non-smooth functions, e.g., comparison, using (scalar) FHEW/TFHE functional bootstrapping
- Switching between RLWE (a scheme equivalent to the coefficient-encoded additive BFV scheme) and CKKS to evaluate arbitrary lookup tables over vectors of integers, e.g., modular reduction, comparison or S-box, using vectorized functional bootstrapping implemented in CKKS

OpenFHE also supports partial schemes, called schemelets, such as RLWE which is equivalent to the coefficient-encoded additive BFV scheme. In OpenFHE, the RLWE schemelet is the starting point for the vectorized functional bootstrapping capability, which allows the evaluation of arbitrary lookup tables over vectors of integers, e.g., modular reduction, comparison or Sbox, using CKKS in an intermediate step.

OpenFHE also includes the following multiparty extensions of FHE:

- Threshold FHE for BGV, BFV, and CKKS schemes
- Interactive bootstrapping for Threshold CKKS
- Proxy Re-Encryption for BGV, BFV, and CKKS schemes

OpenFHE supports any GNU C++ compiler version 9 or above and clang C++ compiler version 10 or above. To achieve the best runtime performance, we recommend following the
guidelines outlined in [building OpenFHE for best performance](https://github.com/openfheorg/openfhe-development/blob/main/docs/static_docs/Best_Performance.md).

## Links and Resources

- [OpenFHE documentation](https://openfhe-development.readthedocs.io/en/latest/)
- [Design paper for OpenFHE](https://eprint.iacr.org/2022/915)
- [OpenFHE website](https://openfhe.org)
- [Community forum for OpenFHE](https://openfhe.discourse.group/)
- [OpenFHE Release Notes](https://github.com/openfheorg/openfhe-development/blob/main/docs/static_docs/Release_Notes.md)
- [Quickstart](https://openfhe-development.readthedocs.io/en/latest/sphinx_rsts/intro/quickstart.html)
- [BSD 2-Clause License](LICENSE)
- [Contributing to OpenFHE](https://openfhe-development.readthedocs.io/en/latest/sphinx_rsts/contributing/contributing.html)
- [OpenFHE Governance](https://openfhe-development.readthedocs.io/en/latest/sphinx_rsts/misc/governance.html)
- [Openfhe-development Github Issues](https://github.com/openfheorg/openfhe-development/issues)
- To report security vulnerabilities, please email us at <contact@openfhe.org>

## Installation

Refer to our General Installation Information: [readthedocs](https://openfhe-development.readthedocs.io/en/latest/sphinx_rsts/intro/installation/installation.html) for more information

Or refer to the following for your specific operating system:

- [Linux](https://openfhe-development.readthedocs.io/en/latest/sphinx_rsts/intro/installation/linux.html)

- [MacOS](https://openfhe-development.readthedocs.io/en/latest/sphinx_rsts/intro/installation/macos.html)

- [Windows](https://openfhe-development.readthedocs.io/en/latest/sphinx_rsts/intro/installation/windows.html)

## Code Examples

To get familiar with the main API of OpenFHE, we recommend looking at the code of the following examples:

   1. FHE for arithmetic over integers (BFV):
       1. [Simple Code Example](src/pke/examples/simple-integers.cpp)
       2. [Simple Code Example with Serialization](src/pke/examples/simple-integers-serial.cpp)
   1. FHE for arithmetic over integers (BGV):
       1. [Simple Code Example](src/pke/examples/simple-integers-bgvrns.cpp)
       2. [Simple Code Example with Serialization](src/pke/examples/simple-integers-serial-bgvrns.cpp)
   1. FHE for arithmetic over real numbers (CKKS):
       1. [Simple Code Example](src/pke/examples/simple-real-numbers.cpp)
       2. [Advanced Code Example](src/pke/examples/advanced-real-numbers.cpp)
       3. [Advanced Code Example for High-Precision CKKS](src/pke/examples/advanced-real-numbers-128.cpp)
       4. [Arbitrary Smooth Function Evaluation](src/pke/examples/function-evaluation.cpp)
       5. [Simple CKKS Bootstrapping Example](src/pke/examples/simple-ckks-bootstrapping.cpp)
       6. [Advanced CKKS Bootstrapping Example](src/pke/examples/advanced-ckks-bootstrapping.cpp)
       7. [Double-Precision (Iterative) Bootstrapping Example](src/pke/examples/iterative-ckks-bootstrapping.cpp)
       8. [Basic CKKS Arithmetic in the CKKS Composite Scaling Mode](src/pke/examples/simple-real-numbers-composite-scaling.cpp)
   1. FHE for arithmetic over complex numbers (CKKS):
       1. [Leveled and Boostrapping Code Examples](src/pke/examples/simple-complex-numbers.cpp)
   1. FHE for Boolean circuits and larger plaintext spaces (FHEW/TFHE):
       1. [Simple Code Example with Symmetric Encryption](src/binfhe/examples/boolean.cpp)
       2. [Simple Code Example with PKE](src/binfhe/examples/pke/boolean-pke.cpp)
       3. [Evaluation of Multi-Input Gates](src/binfhe/examples/boolean-multi-input.cpp)
       4. [Code with JSON serialization](src/binfhe/examples/boolean-serial-json.cpp)
       5. [Code with Binary Serialization](src/binfhe/examples/boolean-serial-binary.cpp)
       6. [Large-Precision Comparison](src/binfhe/examples/eval-sign.cpp)
       7. [Small-Precison Arbitrary Function Evaluation](src/binfhe/examples/eval-function.cpp)
   1. Scheme Switching:
       1. [Examples with Scheme Switching between CKKS and FHEW/TFHE](src/pke/examples/scheme-switching.cpp)
   1. Functional Bootstrapping over integers (RLWE and CKKS):
       1. [Examples with Functional Bootstrapping using CKKS for lookup table evaluation, sign extraction and multivalue bootstrapping](src/pke/examples/functional-bootstrapping-ckks.cpp)
   1. Threshold FHE:
       1. [Code Example for BGV, BFV, and CKKS](src/pke/examples/threshold-fhe.cpp)
       1. [2-party Interactive Bootstrapping Examples](src/pke/examples/interactive-bootstrapping.cpp)
       1. [Simple n-party Interactive Bootstrapping Example](src/pke/examples/tckks-interactive-mp-bootstrapping.cpp)
       1. [n-party Interactive Bootstrapping after Chebyshev Approximation](src/pke/examples/tckks-interactive-mp-bootstrapping-Chebyshev.cpp)
       1. [Code Example for BFV with 5 parties](src/pke/examples/threshold-fhe-5p.cpp)

## Main API

- [PKE CryptoContext API (BGV/BFV/CKKS)](https://openfhe-development.readthedocs.io/en/latest/api/classlbcrypto_1_1CryptoContextImpl.html)
- [Description of CryptoContext Parameters for BGV, BFV, and CKKS](https://github.com/openfheorg/openfhe-development/blob/main/src/pke/examples#description-of-the-cryptocontext-parameters-and-their-restrictions)

- [BinFHE Context API (FHEW/TFHE)](https://openfhe-development.readthedocs.io/en/latest/api/classlbcrypto_1_1BinFHEContext.html)

## Code of Conduct

In the interest of fostering an open and welcoming environment, we as contributors and maintainers pledge to making
participation in our project and our community a harassment-free experience for everyone, regardless of age, body size,
disability, ethnicity, sex characteristics, gender identity and expression, level of experience, education,
socio-economic status, nationality, personal appearance, race, religion, or sexual identity and orientation.

OpenFHE is a community-driven open source project developed by a diverse group of
[contributors](https://openfhe-development.readthedocs.io/en/latest/sphinx_rsts/misc/contributors.html). The OpenFHE leadership has made a strong commitment to creating an open,
inclusive, and positive community. Please read our
[Code of Conduct](https://openfhe-development.readthedocs.io/en/latest/sphinx_rsts/misc/code_of_conduct.html?highlight=code%20of%20) for guidance on how to interact with others in a way that
makes our community thrive.

## Call for Contributions

We welcome all contributions including but not limited to:

- [reporting issues](https://github.com/openfheorg/openfhe-development/issues)
- addressing [bugs](https://github.com/openfheorg/openfhe-development/issues) big or small. We label issues to help you filter them to your skill level.
- documentation changes
- talks and seminars using OpenFHE

## How to Cite OpenFHE

To cite OpenFHE in academic papers, please use the following BibTeX entry (updated version)

```
@misc{OpenFHE,
      author = {Ahmad Al Badawi and Andreea Alexandru and Jack Bates and Flavio Bergamaschi and David Bruce Cousins and Saroja Erabelli and Nicholas Genise and Shai Halevi and Hamish Hunt and Andrey Kim and Yongwoo Lee and Zeyu Liu and Daniele Micciancio and Carlo Pascoe and Yuriy Polyakov and Ian Quah and Saraswathy R.V. and Kurt Rohloff and Jonathan Saylor and Dmitriy Suponitsky and Matthew Triplett and Vinod Vaikuntanathan and Vincent Zucca},
      title = {{OpenFHE}: Open-Source Fully Homomorphic Encryption Library},
      howpublished = {Cryptology ePrint Archive, Paper 2022/915},
      year = {2022},
      note = {\url{https://eprint.iacr.org/2022/915}},
      url = {https://eprint.iacr.org/2022/915}
}
```

or, alternatively (original WAHC@CCS'22 version),

```
@inproceedings{10.1145/3560827.3563379,
      author = {Al Badawi, Ahmad and Bates, Jack and Bergamaschi, Flavio and Cousins, David Bruce and Erabelli, Saroja and Genise, Nicholas and Halevi, Shai and Hunt, Hamish and Kim, Andrey and Lee, Yongwoo and Liu, Zeyu and Micciancio, Daniele and Quah, Ian and Polyakov, Yuriy and R.V., Saraswathy and Rohloff, Kurt and Saylor, Jonathan and Suponitsky, Dmitriy and Triplett, Matthew and Vaikuntanathan, Vinod and Zucca, Vincent},
      title = {OpenFHE: Open-Source Fully Homomorphic Encryption Library},
      year = {2022},
      publisher = {Association for Computing Machinery},
      address = {New York, NY, USA},
      url = {https://doi.org/10.1145/3560827.3563379},
      doi = {10.1145/3560827.3563379},
      booktitle = {Proceedings of the 10th Workshop on Encrypted Computing \& Applied Homomorphic Cryptography},
      pages = {53-63},
      numpages = {11},
      location = {Los Angeles, CA, USA},
      series = {WAHC'22}
}
```

## Acknowledgments ##

- Distribution Statement "A" (Approved for Public Release, Distribution Unlimited). This work is supported in part by DARPA through HR0011-21-9-0003 and HR0011-20-9-0102. The views, opinions, and/or findings expressed are those of the author(s) and should not be interpreted as representing the official views or policies of the Department of Defense or the U.S. Government.
- This research was funded, in part, by the Advanced Research Projects Agency for Health (ARPA-H). The views and conclusions contained in this document are those of the authors and should not be interpreted as representing the oﬃcial policies, either expressed or implied, of the U.S. Government.
