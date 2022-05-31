PKE Keys documentation
====================================

`Github Source <https://github.com/openfheorg/openfhe-development/tree/main/src/pke/include/key>`_:  This folder contains the header files of the various keys that are defined within ``Open-FHE``.


.. contents:: Page Contents
   :local:


File Listings
-------------

`All Key Top-Level Include (allkey.h) <https://github.com/openfheorg/openfhe-development/blob/main/src/pke/include/key/allkey.h>`_

- Top-level ``#include`` for access to all capabilities


Keys Class Inheritance
-----------------------

.. mermaid::

   graph BT
      Key[Key: Base Class] --> |Inherited by|EvalKeyImpl;
      EvalKeyImpl --> |Inherited by|EvalKeyRelinImpl;


Key Class File Listings
-----------------------

`Eval Key (evalkey.h) <https://github.com/openfheorg/openfhe-development/blob/main/src/pke/include/key/evalkey.h>`_

- Inherits from the base ``Key`` class.

- Serves as base class for ``Eval Key Relin``

`Eval Key Relin (evalkeyrelin.h) <https://github.com/openfheorg/openfhe-development/blob/main/src/pke/include/key/evalkeyrelin.h>`_

- Get and set relinearization elements

- Get and set key switches for ``BinDCRT`` and ``DCRT``

- Inherits from ``Eval Key``

`Key (key.h) <https://github.com/openfheorg/openfhe-development/blob/main/src/pke/include/key/key.h>`_

- Base Key class

`Key Serialization (key-ser.h) <https://github.com/openfheorg/openfhe-development/blob/main/src/pke/include/key/key-ser.h>`_

- Capabilities for serializing the keys using `Cereal <https://github.com/USCiLab/cereal>`__

Key Pair
--------

.. mermaid::

   graph BT
      PrivKey[Private Key] --> |container|KP(Key Pair);
      PubKey[Public Key] --> |container|KP(Key Pair);

Key Pair File Listings
-----------------------

`Key Pair (keypair.h) <https://github.com/openfheorg/openfhe-development/blob/main/src/pke/include/key/keypair.h>`_

- Container for the ``private key`` and ``public key`` implementations

`Private Key (privatekey.h) <https://github.com/openfheorg/openfhe-development/blob/main/src/pke/include/key/privatekey.h>`_

`Public Key (publickey.h) <https://github.com/openfheorg/openfhe-development/blob/main/src/pke/include/key/publickey.h>`_
