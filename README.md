OpenFHE - Open-Source Fully Homomorphic Encryption Library
=====================================

Fully Homomorphic Encryption (FHE) is a powerful cryptographic primitive that enables performing computations over encrypted data without having access to the secret key.
OpenFHE is an open-source FHE library that includes efficient implementations of all common FHE schemes:
  * Brakerski/Fan-Vercauteren (BFV) scheme for integer arithmetic
  * Brakerski-Gentry-Vaikuntanathan (BGV) scheme for integer arithmetic
  * Cheon-Kim-Kim-Song (CKKS) scheme for real-number arithmetic (includes approximate bootstrapping)
  * Ducas-Micciancio (DM) and Chillotti-Gama-Georgieva-Izabachene (CGGI) schemes for evaluating Boolean circuits and arbitrary functions over larger plaintext spaces using lookup tables

OpenFHE also includes the following multiparty extensions of FHE:
  * Threshold FHE for BGV, BFV, and CKKS schemes
  * Proxy Re-Encryption for BGV, BFV, and CKKS schemes

OpenFHE supports any GNU C++ compiler version 9 or above and clang C++ compiler version 10 or above.

## Links and Resources

 * [OpenFHE documentation](https://openfhe-development.readthedocs.io/en/latest/)
 * [Design paper for OpenFHE](https://eprint.iacr.org/2022/915)
 * [OpenFHE website](https://openfhe.org)
 * [Community forum for OpenFHE](https://openfhe.discourse.group/)
 * [OpenFHE Release Notes](https://github.com/openfheorg/openfhe-development/blob/main/docs/static_docs/Release_Notes.md)
 * [Quickstart](https://openfhe-development.readthedocs.io/en/latest/sphinx_rsts/intro/quickstart.html)
 * [BSD 2-Clause License](LICENSE)
 * [Contributing to OpenFHE](https://openfhe-development.readthedocs.io/en/latest/sphinx_rsts/contributing/contributing.html)
 * [OpenFHE Governance](https://openfhe-development.readthedocs.io/en/latest/sphinx_rsts/misc/governance.html)
 * [Openfhe-development Github Issues](https://github.com/openfheorg/openfhe-development/issues)
 * To report security vulnerabilities, please email us at contact@openfhe.org


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
       2. [Advanced Code Example for High-Precision CKKS](src/pke/examples/advanced-real-numbers-128.cpp)
       2. [Arbitrary Smooth Function Evaluation](src/pke/examples/function-evaluation.cpp)
       3. [Simple CKKS Bootstrapping Example](src/pke/examples/simple-ckks-bootstrapping.cpp)
       4. [Advanced CKKS Bootstrapping Example](src/pke/examples/advanced-ckks-bootstrapping.cpp)
       5. [Double-Precision (Iterative) Bootstrapping Example](src/pke/examples/iterative-ckks-bootstrapping.cpp)
   1. FHE for Boolean circuits and larger plaintext spaces (FHEW/TFHE):
       1. [Simple Code Example](src/binfhe/examples/boolean.cpp)
       2. [Code with JSON serialization](src/binfhe/examples/boolean-serial-json.cpp)
       3. [Code with Binary Serialization](src/binfhe/examples/boolean-serial-binary.cpp)
       4. [Large-Precision Comparison](src/binfhe/examples/eval-sign.cpp)
       4. [Small-Precison Arbitrary Function Evaluation](src/binfhe/examples/eval-function.cpp)
   1. Threshold FHE:
       1. [Code Example for BGV, BFV, and CKKS](src/pke/examples/threshold-fhe.cpp)
       1. [Code Example for BFV with 5 parties](src/pke/examples/threshold-fhe-5p.cpp)

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

To cite OpenFHE in academic papers, please use the following BibTeX entry.

```
@misc{OpenFHE,
      author = {Ahmad Al Badawi and Jack Bates and Flavio Bergamaschi and David Bruce Cousins and Saroja Erabelli and Nicholas Genise and Shai Halevi and Hamish Hunt and Andrey Kim and Yongwoo Lee and Zeyu Liu and Daniele Micciancio and Ian Quah and Yuriy Polyakov and Saraswathy R.V. and Kurt Rohloff and Jonathan Saylor and Dmitriy Suponitsky and Matthew Triplett and Vinod Vaikuntanathan and Vincent Zucca},
      title = {OpenFHE: Open-Source Fully Homomorphic Encryption Library},
      howpublished = {Cryptology ePrint Archive, Paper 2022/915},
      year = {2022},
      note = {\url{https://eprint.iacr.org/2022/915}},
      url = {https://eprint.iacr.org/2022/915}
}
```

## Acknowledgments ##

Distribution Statement "A" (Approved for Public Release, Distribution Unlimited). This work is supported in part by DARPA through HR0011-21-9-0003 and HR0011-20-9-0102. The views, opinions, and/or findings expressed are those of the author(s) and should not be interpreted as representing the official views or policies of the Department of Defense or the U.S. Government.
