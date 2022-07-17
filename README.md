OpenFHE - Open-Source Fully Homomorphic Encryption Library
=====================================

Fully Homomorphic Encryption (FHE) is a powerful cryptographic primitive that enables performing computations over encrypted data without having access to the secret key. 
OpenFHE is an open-source FHE library that includes efficient implementations of all common FHE schemes:
  * Brakerski/Fan-Vercauteren (BFV) scheme for integer arithmetic
  * Brakerski-Gentry-Vaikuntanathan (BGV) scheme for integer arithmetic
  * Cheon-Kim-Kim-Song (CKKS) scheme for real-number arithmetic (includes approximate bootstrapping)
  * Ducas-Micciancio (DM) and Chillotti-Gama-Georgieva-Izabachene (CGGI) schemes for Boolean circuit evaluation

OpenFHE also includes the following multiparty extensions of FHE: 
  * Threshold FHE for BGV, BFV, and CKKS schemes
  * Proxy Re-Encryption for BGV, BFV, and CKKS schemes

## Links and Resources

 * [OpenFHE documentation](https://openfhe-development.readthedocs.io/en/latest/)
 * [Design paper for OpenFHE](https://eprint.iacr.org/2022/915)
 * [OpenFHE website](https://openfhe.org)
 * [Community forum for OpenFHE](https://openfhe.discourse.group/)
 * [Quickstart](https://openfhe-development.readthedocs.io/en/latest/sphinx_rsts/intro/quickstart.html)
 * [BSD 2-Clause License](LICENSE)
 * [Contributing to OpenFHE](https://openfhe-development.readthedocs.io/en/latest/sphinx_rsts/contributing/contributing.html)
 * [Openfhe-development Github Issues](https://github.com/openfheorg/openfhe-development/issues)
 * To report security vulnerabilities, please email us at contact@openfhe.org


## Installation

Refer to our General Installation Information: [readthedocs](https://openfhe-development.readthedocs.io/en/latest/sphinx_rsts/intro/installation/installation.html) for more information

Or refer to the following for your specific operating system:

- [Linux](https://openfhe-development.readthedocs.io/en/latest/sphinx_rsts/intro/installation/linux.html)

- [MacOS](https://openfhe-development.readthedocs.io/en/latest/sphinx_rsts/intro/installation/macos.html)

- [Windows](https://openfhe-development.readthedocs.io/en/latest/sphinx_rsts/intro/installation/windows.html)


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
