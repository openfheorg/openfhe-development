Boolean FHE (BinFHE) documentation
====================================

.. contents:: Page Contents
   :local:

`Github Source <https://github.com/openfheorg/openfhe-development/tree/main/src/binfhe/examples>`_: Implements the following Boolean circuit evaluation schemes:

- `Ducas-Micciancio (DM or FHEW) <https://eprint.iacr.org/2014/816.pdf>`_

- `Chillotti-Gama-Georgieva-Izabachene (CGGI or TFHE)  <https://eprint.iacr.org/2018/421.pdf>`_

File Listings
-----------------------

`Boolean FHE CryptoContext Serialization (binfhecontext-ser.h) <https://github.com/openfheorg/openfhe-development/blob/main/src/binfhe/include/binfhecontext-ser.h>`_

- Adds serialization support to Boolean Circuit FHE

`Boolean FHE CryptoContext (binfhecontext.h) <https://github.com/openfheorg/openfhe-development/blob/main/src/binfhe/include/binfhecontext.h>`_

- CryptoContext for the boolean circuit FHE scheme.
- A CryptoContext is the primary object through which we interact with the various ``OpenFHE`` capabilities

.. note:: various parameter ``enum`` are also provided
.. - ``BINFHEPARAMSET`` that defines the security level and parameters
.. - ``BINFHE_METHOD`` to choose the bootstrapping method: AP (DM/FHEW scheme) or GINX (CGGI/TFHE scheme)
.. - ``BINFHE_METHOD`` specifies whther fresh ciphertext should be bootstrapped.

`DM/CGGI Cryptosystem (binfhe-base-scheme) <https://github.com/openfheorg/openfhe-development/blob/main/src/binfhe/include/binfhe-base-scheme.h>`_

- The main cryptosystem implementation used for DM/CGGI schemes
- The scheme is described in `Bootstrapping in FHEW-like Cryptosystems <https://eprint.iacr.org/2020/086>`_ from Daniele Micciancio and Yuriy Polyakov as published in Cryptology ePrint Archive, Report 2020/086

`Parameters for DM/CGGI Cryptosystem (binfhe-base-params) <https://github.com/openfheorg/openfhe-development/blob/main/src/binfhe/include/binfhe-base-params.h>`_

- Stores the parameters for all cryptographic schemes, including LWE, RLWE, and RGSW

`Constants for DM/CGGI Cryptosystem (binfhe-base-params) <https://github.com/openfheorg/openfhe-development/blob/main/src/binfhe/include/binfhe-constants.h>`_

- Defines all options for ``BINFHEPARAMSET``, ``BINFHE_METHOD``, and ``BINFHE_METHOD`` enums

`LWE Ciphertext (lwe-ciphertext) <https://github.com/openfheorg/openfhe-development/blob/main/src/binfhe/include/lwe-ciphertext.h>`_

`LWE Crypto Parameters (lwe-cryptoparameters) <https://github.com/openfheorg/openfhe-development/blob/main/src/binfhe/include/lwe-cryptoparameters.h>`_

`LWE Switching Key (lwe-keyswitchkey) <https://github.com/openfheorg/openfhe-development/blob/main/src/binfhe/include/lwe-keyswitchkey.h>`_

`LWE Scheme (lwe-pke) <https://github.com/openfheorg/openfhe-development/blob/main/src/binfhe/include/lwe-pke.h>`_

`LWE Private Key (lwe-privatekey) <https://github.com/openfheorg/openfhe-development/blob/main/src/binfhe/include/lwe-privatekey.h>`_

`Parent RGSW Accumulator Scheme (rgsw-acc) <https://github.com/openfheorg/openfhe-development/blob/main/src/binfhe/include/rgsw-acc.h>`_

`CGGI RGSW Accumulator Scheme (rgsw-acc-cggi) <https://github.com/openfheorg/openfhe-development/blob/main/src/binfhe/include/rgsw-acc-cggi.h>`_

`DM RGSW Accumulator Scheme (rgsw-acc-dm) <https://github.com/openfheorg/openfhe-development/blob/main/src/binfhe/include/rgsw-acc-dm.h>`_

`RGSW Refreshing Key (rgsw-acckey) <https://github.com/openfheorg/openfhe-development/blob/main/src/binfhe/include/rgsw-acckey.h>`_

`RGSW Crypto Parameters (rgsw-cryptoparameters) <https://github.com/openfheorg/openfhe-development/blob/main/src/binfhe/include/rgsw-cryptoparameters.h>`_

`RGSW Evaluation Key/Ciphertext (rgsw-evalkey) <https://github.com/openfheorg/openfhe-development/blob/main/src/binfhe/include/rgsw-evalkey.h>`_

`RLWE Ciphertext (rlwe-ciphertext) <https://github.com/openfheorg/openfhe-development/blob/main/src/binfhe/include/rlwe-ciphertext.h>`_
