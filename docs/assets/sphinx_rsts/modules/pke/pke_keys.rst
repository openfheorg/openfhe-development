PKE Keys documentation
====================================

`Github Source <https://github.com/openfheorg/openfhe-development/tree/main/src/pke/include/key>`_:  This folder contains the header files of the various keys that are defined within ``Open-FHE``.

Keys Class Inheritance
-----------------------

.. mermaid::

   graph BT
      Key[Key: Base Class] --> |Inherited by|EvalKeyImpl;
      EvalKeyImpl --> |Inherited by|EvalKeyRelinImpl;

Key Pair
--------

.. mermaid::

   graph BT
      PrivKey[Private Key] --> |container|KP(Key Pair);
      PubKey[Public Key] --> |container|KP(Key Pair);

File Listings
-----------------------

``All Key``
    - Top-level ``#include`` for access to all capabilities

``Eval Key``
    - Inherits from the base ``Key`` class.
    - Serves as base class for ``Eval Key Relin``

``Eval Key Relin``
    - Get and set relinearization elements
    - Get and set key switches for ``BinDCRT`` and ``DCRT``
    - Inherits from ``Eval Key``

``Key``
    - Base Key class

``Key Serialization``
    - Capabilities for serializing the keys using `Cereal <https://github.com/USCiLab/cereal>`__

``Key Pair``
    - Container for the ``private key`` and ``public key`` implementations

``Private Key``

``Public Key``

PKE Keys Generated Docs
-------------------------------

.. autodoxygenindex::
   :project: pke_key
