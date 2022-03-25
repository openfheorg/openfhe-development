PKE Key-Switching documentation
====================================

`Github Source <https://github.com/openfheorg/openfhe-development/tree/main/src/pke/include/keyswitch>`_:  This folder contains the header files of the key-switching methods present in ``Open-FHE``.

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
    - Inherits from [key-switch base](keyswitch-base.h)
    - Implements key switching for the

``Key-switch Hybrid``
    - Inherits from [key-switch base](keyswitch-base.h)
    - Implements

PKE Key-Switching Generated Docs
--------------------------------

.. autodoxygenindex::
   :project: pke_keyswitch
