Welcome to OpenFHE's documentation!
====================================

OpenFHE
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

OpenFHE implements efficient Residue Number System (RNS) algorithms to achieve high performance, e.g., OpenFHE (called PALISADE at the time) was used as the library for a winning genome-wide association studies solution at iDASH’18.

.. note:: For a quick introduction to OpenFHE, visit our :ref:`quickstart <quickstart>` page.

.. toctree::
   :maxdepth: 2
   :caption: Contents:

   .sphinx_rsts/intro/get_started.rst
   api/library_root.rst

..
   [COMMENT]: we separated the above TOC tree and the below to make them list at different depths.
   Meaning sub-sections in the get_started.rst will be listed, but sub-sections in any given
   /misc/ file will not appear

.. toctree::
   :maxdepth: 1
   :glob:

   .sphinx_rsts/contributing/contributing.rst
   .sphinx_rsts/misc/*

Components
-------------

OpenFHE is a cross-platform C++11 library supporting Linux, Windows, and macOS. The supported compilers are g++ v6.1 or later and clang++ v6.0 or later.

The library also includes unit tests and sample application demos.

The library is based on modular architecture with the following layers:

* Math operations layer supporting low-level modular arithmetic, number theoretic transforms, and integer sampling.  This layer is implemented to be portable to multiple hardware computation substrates.
* Lattice operations layer supporting lattice operations, ring algebra, and lattice trapdoor sampling.
* Crypto layer containing efficient implementations of lattice cryptography schemes.
* Encoding layer supporting multiple plaintext encodings for cryptographic schemes.

OpenFHE Extensions
-------------------

- `Intel HEXL Acceleration <https://github.com/openfheorg/openfhe-hexl>`_

License
-----------

OpenFHE is available under the BSD 2-clause license.

Additional Resources
----------------------

`OpenFHE/PALISADE Webinars <https://www.youtube.com/channel/UC1qByOsQina1rpZ8AGl5TZw>`_
