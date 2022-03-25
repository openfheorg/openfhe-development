Welcome to PALISADE's documentation!
====================================

PALISADE
--------

OpenFHE is a general lattice cryptography library that currently includes efficient implementations of the following lattice cryptography capabilities:

- Fully Homomorphic Encryption (FHE)

  - Brakerski/Fan-Vercauteren (BFV) scheme for integer arithmetic

  - Brakerski-Gentry-Vaikuntanathan (BGV) scheme for integer arithmetic

  - Cheon-Kim-Kim-Song (CKKS) scheme for real-number arithmetic

  - Ducas-Micciancio (FHEW) and Chillotti-Gama-Georgieva-Izabachene (TFHE) schemes for Boolean circuit evaluation


- Multi-Party Extensions of FHE (to support multi-key FHE)

  - Threshold FHE for BGV, BFV, and CKKS schemes

  - Proxy Re-Encryption for BGV, BFV, and CKKS schemes

A major focus is on the usability of the schemes. For instance, all HE schemes with packing use the same common API, and are implemented using runtime polymorphism.

PALISADE implements efficient Residue Number System (RNS) algorithms to achieve high performance, e.g., PALISADE was used as the library for a winning genome-wide association studies solution at iDASH’18.

.. toctree::
   :maxdepth: 2
   :glob:
   :caption: Contents:

   assets/sphinx_rsts/intro/get_started.rst
   assets/sphinx_rsts/modules/modules.rst
   assets/sphinx_rsts/contributing/contributing.rst
   assets/sphinx_rsts/misc/*


Components
-------------

PALISADE is a cross-platform C++11 library supporting Linux, Windows, and macOS. The supported compilers are g++ v6.1 or later and clang++ v6.0 or later.

The library also includes unit tests and sample application demos.

The library is based on modular architecture with the following layers:

* Math operations layer supporting low-level modular arithmetic, number theoretic transforms, and integer sampling.  This layer is implemented to be portable to multiple hardware computation substrates.
* Lattice operations layer supporting lattice operations, ring algebra, and lattice trapdoor sampling.
* Crypto layer containing efficient implementations of lattice cryptography schemes.
* Encoding layer supporting multiple plaintext encodings for cryptographic schemes.

Important Notes
---------------

Note as of version 1.11, the following features have been moved to their own repositories in the PALISADE group.

* `Digital Signature <https://gitlab.com/palisade/palisade-signature/>`_
* `Identity-Based Encryption <https://gitlab.com/palisade/palisade-abe/>`_
* `Ciphertext-Policy Attribute-Based Encryption <https://gitlab.com/palisade/palisade-abe/>`_


All the research prototypes for Key-Policy Attributed-Based Encryption and Program Obfuscation have been moved to `Palisade-Trapdoor <https://gitlab.com/palisade/palisade-trapdoor/>`_

License
-----------

PALISADE is available under the BSD 2-clause license.

Additional Resources
----------------------

`PALISADE Webinars <https://www.youtube.com/channel/UC1qByOsQina1rpZ8AGl5TZw>`_


Indices and tables
==================
* :ref:`genindex`
* :ref:`search`
