# Boolean FHE (BinFHE) documentation

Refer to our [OpenFHE-Readthedocs](https://openfhe-development.readthedocs.io/en/latest/assets/sphinx_rsts/modules/binfhe.html) for more information. This folder contains implementations of [Ducas-Micciancio (FHEW)](https://eprint.iacr.org/2014/816.pdf), and [Chillotti-Gama-Georgieva-Izabachene (TFHE)](https://eprint.iacr.org/2018/421.pdf)

## File Listings

[Binary FHE CryptoContext Serialization](binfhecontext-ser.h)

- Adds serialization support to Bollean Circuit FHE

[Binary FHE CryptoContext](binfhecontext.h)

- CryptoContext for the boolean circuit FHE scheme.
- A CryptoContext is the primary object through which we interact with the various `OpenFHE` capabilities

[FHEW](fhew.h)

- The FHEW scheme (RingGSW accumulator) implementation for both DM and CGGI schemes
- The schemes are described in [Bootstrapping in FHEW-like Cryptosystems](https://eprint.iacr.org/2014/816) from Daniele
  Micciancio and Yuriy Polyakov as published in Cryptology ePrint Archive, Report 2020/086

[LWE](lwe.h)

- LWE Encryption Scheme implementation
- The scheme described [FHEW: Bootstrapping Homomorphic Encryption in less than a second](https://eprint.iacr.org/2014/816) from Leo Ducas and Daniele Micciancio

[LWE Core](lwecore.h)

- Main LWE classes for boolean FHE

[Ring Core](ringcore.h)

- Main ring classes for boolean FHE
- Defines the enum for the supported binary gates:
- ``OR``, ``XOR_FAST``, ``XOR``
- ``AND``, ``NAND``
- ``NOR``, ``XNOR_FAST``, ``XNOR``
- Defines the enums for the bin-FHE methods: ``AP`` and ``GINX``
