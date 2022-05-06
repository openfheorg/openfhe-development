Boolean FHE (BinFHE) documentation
====================================

.. contents:: Page Contents
   :local:

`Github Source <https://github.com/openfheorg/openfhe-development/tree/main/src/binfhe/examples>`_: Implements the following Boolean circuit evaluation schemes:

- `Ducas-Micciancio (FHEW) <https://eprint.iacr.org/2014/816.pdf>`_

- `Chillotti-Gama-Georgieva-Izabachene (TFHE)  <https://eprint.iacr.org/2018/421.pdf>`_

File Listings
-----------------------

`Boolean FHE CryptoContext Serialization (binfhecontext-ser.h) <https://github.com/openfheorg/openfhe-development/blob/main/src/binfhe/include/binfhecontext-ser.h>`_

- Adds serialization support to Boolean Circuit FHE

`Boolean FHE CryptoContext (binfhecontext.h) <https://github.com/openfheorg/openfhe-development/blob/main/src/binfhe/include/binfhecontext.h>`_

- CryptoContext for the boolean circuit FHE scheme.
- A CryptoContext is the primary object through which we interact with the various ``OpenFHE`` capabilities

.. note:: various parameter ``enum`` are also provided, primarily ``BINFHEPARAMSET`` and ``BINFHEOUTPUT`` which define the level of security, and type of ciphertext generated when the ``encrypt`` method is called.

`FHEW (fhew.h) <https://github.com/openfheorg/openfhe-development/blob/main/src/binfhe/include/fhew.h>`_

- The FHEW scheme (RingGSW accumulator) implementation
- The scheme is described in `Bootstrapping in FHEW-like Cryptosystems <https://eprint.iacr.org/2014/816>`_ from Daniele Micciancio and Yuriy Polyakov as published in Cryptology ePrint Archive, Report 2020/086
- The object containing the parameters for encoding. These parameters are kept and continually reused (can be modified) during the encoding of new values
- Defines the ``RingGSWAccumulatorScheme``: the ring GSW accumulator scheme described in the aforementioned paper.

`Learning with Error (lwe.h) <https://github.com/openfheorg/openfhe-development/blob/main/src/binfhe/include/lwe.h>`_

- LWE Encryption Scheme implementation
- The scheme described in `FHEW: Bootstrapping Homomorphic Encryption in less than a second <https://eprint.iacr.org/2014/816>`_ from Leo Ducas and Daniele Micciancio

`LWE Core (lwecore.h) <https://github.com/openfheorg/openfhe-development/blob/main/src/binfhe/include/lwecore.h>`_

- Main ring class for boolean FHE
- Defines the following:

  - ``LWECryptoParams``: stores parameters for use in the LWE scheme

  - ``LWE Ciphertext Impl``: the ciphertext implementation for `LWE`

  - ``LWEPrivateKeyImpl``: stores the LWE scheme secret key in a vector

  - ``LWESwitchingKey``: stores the LWE scheme switching key

`Ring Core (ringcore.h) <https://github.com/openfheorg/openfhe-development/blob/main/src/binfhe/include/ringcore.h>`_

- Main ring class for boolean FHE
- Defines the enum for the supported boolean gates:

  - ``OR``, ``XOR_FAST``, ``XOR``

  - ``AND``, ``NAND``

  - ``NOR``, ``XNOR_FAST``, ``XNOR``

- Defines the enums for the bin-FHE methods: ``AP`` and ``GINX``
- Defines the following:

  - ``RingGSWCiphertext``: two-dimensional vector of ring elements

  - ``RingGSWBTKey``: stores the refreshing key used in bootstrapping. Is a 3-d vector of ``RingGSW`` ciphertexts


Boolean FHE Generated Docs
--------------------------------

.. autodoxygenindex::
   :project: binfhe
   :allow-dot-graphs: