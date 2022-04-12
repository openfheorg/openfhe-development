PKE Key-Switching documentation
====================================

`Github Source <https://github.com/openfheorg/openfhe-development/tree/main/src/pke/include/keyswitch>`_:  This folder contains the header files of the key-switching methods present in``Open-FHE``.

The documentation is largely based on `Revisiting Homomorphic Encryption Schemes for Finite Fields <https://eprint.iacr.org/2021/204.pdf>`_

Intuition
---------

Let :math:`c_t` be a ciphertext :math:`c_t = (c_0, c_1) \in \mathbb{R}_Q^2`, which can be decrypted with  :math:`s_A`.

Key switching

- This feature is needed to compute automorphisms(rotations) of ciphertexts, or to relinearize ciphertexts


Key-Switching Class Inheritance
-----------------------

.. mermaid::

   graph BT
      Key[Keyswitch: Base Class] --> |Inherited by|KeyRNS[Keyswitch: RNS];
      KeyRNS[Keyswitch: RNS] --> |Inherited by|KeyBV[Keyswitch: BV];
      KeyRNS[Keyswitch: RNS] --> |Inherited by|KeyHybrid[Keyswitch: Hybrid];


File Listings
-----------------------

``Key-switch Base``

- Base class for Lattice-based cryptography(LBC) Somewhat Homomorphic Encryption(SHE) algorithms.

``Key-switch RNS``

- Abstract interface class for RNS LBC SHE algorithms

``Key-switch BV``

- Implements BV scheme from `Fully Homomorphic Encryption from Ring-LWE and Security for Key Dependent Messages (BV Scheme)]<https://www.wisdom.weizmann.ac.il/~zvikab/localpapers/IdealHom.pdf>`_
- Requires the computation of a quadratic number of NTTs.

``Key-switch Hybrid``

- Uses a mix of the GHS key-switching with the BV key-switching to produce more efficient key-switching.
- Was introduced in `Homomorphic Evaluation of the AES Circuit(GHS Scheme) <https://eprint.iacr.org/2012/099.pdf>`_
- GHS Keyswitching:

  - **Pros**: Smaller noise growth than BV and is more efficient as it only requires a linear number of NTTs
  - **Cons**: need to double dimension, N, or reduce size of ciphertext modulus, Q, by a factor of 2

PKE Key-Switching Generated Docs
--------------------------------

.. autodoxygenindex::
   :project: pke_keyswitch
