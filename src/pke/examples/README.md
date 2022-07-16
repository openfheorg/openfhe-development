OpenFHE Lattice Cryptography Library - Examples
=============================================

[License Information](License.md)

Document Description
===================
This document describes the examples included with the OpenFHE lattice crypto library.

Examples Directory Description
==========================

Directory Objective
-------------------
This directory contains examples that, when linked with the library, demonstrate the capabilities of the system

File Listing
------------

*Example programs*

- [advanced-real-numbers.cpp](src/pke/examples/advanced-real-numbers.cpp): shows several advanced examples of approximate homomorphic encryption using CKKS
- [advanced-real-numbers-128.cpp](src/pke/examples/advanced-real-numbers-128.cpp): shows several advanced examples of approximate homomorphic encryption using high-precision CKKS
- [depth-bfvrns.cpp](src/pke/examples/depth-bfvrns.cpp): demonstrates use of the BFVrns scheme for basic homomorphic encryption
- [depth-bfvrns-behz.cpp](src/pke/examples/depth-bfvrns-behz.cpp): demonstrates use of the BEHZ BFV variant for basic homomorphic encryption
- [depth-bgvrns.cpp](src/pke/examples/depth-bgvrns.cpp): demonstrates use of the BGVrns scheme for basic homomorphic encryption
- [linearwsum-evaluation.cpp](src/pke/examples/linearwsum.cpp): demonstrates the evaluation of a linear weighted sum using CKKS
- [polynomial-evaluation.cpp](src/pke/examples/polynomial-evaluation.cpp): demonstrates an evaluation of a polynomial (power series) using CKKS
- [pre.cpp](src/pke/examples/pre.cpp): demonstrates use of proxy re-encryption across several schemes
- [pre-buffer.cpp](src/pke/examples/pre-buffer.cpp): demonstrates use of OpenFHE for encryption, re-encryption and decryption of packed vector of binary data
- [rotation.cpp](src/pke/examples/rotation.cpp): demonstrates use of EvalRotate for different schemes
- [simple-integers.cpp](src/pke/examples/simple-integers.cpp): simple example showing homomorphic additions, multiplications, and rotations for vectors of integers using BFVrns
- [simple-integers-bgvrns.cpp](src/pke/examples/simple-integers-bgvrns.cpp): simple example showing homomorphic additions, multiplications, and rotations for vectors of integers using BGVrns
- [simple-integers-serial.cpp](src/pke/examples/simple-integers-serial.cpp): simple example showing typical serialization/deserialization calls for a prototype computing homomorphic additions, multiplications, and rotations for vectors of integers using BFVrns
- [simple-integers-serial-bgvrns.cpp](src/pke/examples/simple-integers-serial-bgvrns.cpp): simple example showing typical serialization/deserialization calls for a prototype computing homomorphic additions, multiplications, and rotations for vectors of integers using BGVrns
- [simple-real-numbers.cpp](src/pke/examples/simple-real-numbers): simple example showing homomorphic additions, multiplications, and rotations for vectors of real numbers using CKKS
- [simple-real-numbers-serial.cpp](src/pke/examples/simple-real-numbers-serial.cpp): simple example showing typical serialization/deserialization calls for a prototype computing homomorphic additions, multiplications, and rotations for vectors of integers using CKKS
- [threshold-fhe.cpp](src/pke/examples/threshold-fhe.cpp): shows several examples of threshold FHE in BGVrns, BFVrns, and CKKSrns