Core Library Documentation
====================================

`Github Src <https://github.com/openfheorg/openfhe-development/tree/main/src/core>`_

Detailed below are the various components for the ``core`` module. These components are composed and used to construct the ``pke`` and ``binfhe`` modules. The ``core`` module consists of 3 primary components:

- **Lattice**:

  - Consists of the underlying implementation of lattice-based cryptography schemes.

- **Math**:

  - Code pertaining to the underlying math that is used e.g a matrix class (``MatrixStrassen``), number theory functions, etc.

- **Utilities**:

  - Utilities such as an underlying fast block allocator, and code for a hashing function (based off ``Blake2b``).

  .. note:: The PRNG function can be extended by including your own implementation so long as you follow the conventions followed.

.. autodoxygenindex::
   :project: core
