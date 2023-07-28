Welcome to OpenFHE's documentation!
====================================

OpenFHE
--------

Fully Homomorphic Encryption (FHE) is a powerful cryptographic primitive that enables performing computations over encrypted data without having access to the secret key.
OpenFHE is an open-source FHE library that includes efficient implementations of all common FHE schemes:
  - Brakerski/Fan-Vercauteren (BFV) scheme for integer arithmetic
  - Brakerski-Gentry-Vaikuntanathan (BGV) scheme for integer arithmetic
  - Cheon-Kim-Kim-Song (CKKS) scheme for real-number arithmetic (includes approximate bootstrapping)
  - Ducas-Micciancio (DM/FHEW) and Chillotti-Gama-Georgieva-Izabachene (CGGI/TFHE), and Lee-Micciancio-Kim-Choi-Deryabin-Eom-Yoo (LMKCDEY) schemes for evaluating Boolean circuits and arbitrary functions over larger plaintext spaces using lookup tables

OpenFHE also includes the following multiparty extensions of FHE:
  - Threshold FHE for BGV, BFV, and CKKS schemes
  - Proxy Re-Encryption for BGV, BFV, and CKKS schemes

OpenFHE also supports switching between CKKS and FHEW/TFHE to evaluate non-smooth functions, e.g., comparison, using FHEW/TFHE functional bootstrapping.

OpenFHE supports any GNU C++ compiler version 9 or above and clang C++ compiler version 10 or above.

A major focus is on the usability of the schemes. For instance, all HE schemes with packing use the same common API, and are implemented using runtime polymorphism.

OpenFHE implements efficient Residue Number System (RNS) algorithms to achieve high performance.

.. note:: For a quick introduction to OpenFHE, visit our :ref:`quickstart <quickstart>` page.

.. toctree::
   :maxdepth: 2
   :caption: Contents:


   sphinx_rsts/intro/get_started.rst
   sphinx_rsts/intro/quickstart.rst
   sphinx_rsts/intro/tutorials.rst
   sphinx_rsts/modules/modules.rst
   sphinx_rsts/intro/security.rst


..
   [COMMENT]: we separated the above TOC tree from the bottom in an attempt to split them up. For some
   reason the library root was parsing all of the modules and creating duplicates

.. toctree::
   :maxdepth: 2

   api/library_root.rst

..
   [COMMENT]: we separated the above TOC tree and the below to make them list at different depths.
   Meaning sub-sections in the get_started.rst will be listed, but sub-sections in any given
   /misc/ file will not appear

.. toctree::
   :maxdepth: 1
   :glob:

   sphinx_rsts/contributing/contributing.rst
   sphinx_rsts/misc/*

Components
-------------

OpenFHE is a cross-platform C++17 library supporting Linux, Windows, and macOS. The supported compilers are g++ v9 or later and clang++ v10 or later.

The library also includes unit tests and sample application demos.

The library is based on modular architecture with the following layers:

* Primitive math layer supporting low-level modular arithmetic, number theoretic transforms, and integer sampling.  This layer is implemented to be portable to multiple hardware computation substrates.
* Lattice/polynomial operations layer supporting lattice operations, ring algebra, and lattice trapdoor sampling.
* Crypto layer containing efficient implementations of FHE schemes.
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

.. toctree::
   :caption: Appendix

   genindex.rst
