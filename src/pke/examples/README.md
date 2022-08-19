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

- [advanced-ckks-bootstrapping.cpp](advanced-ckks-bootstrapping.cpp): an example showing CKKS bootstrapping for a ciphertext with sparse packing
- [advanced-real-numbers.cpp](advanced-real-numbers.cpp): shows several advanced examples of approximate homomorphic encryption using CKKS
- [advanced-real-numbers-128.cpp](advanced-real-numbers-128.cpp): shows several advanced examples of approximate homomorphic encryption using high-precision CKKS
- [depth-bfvrns.cpp](depth-bfvrns.cpp): demonstrates use of the BFVrns scheme for basic homomorphic encryption
- [depth-bfvrns-behz.cpp](depth-bfvrns-behz.cpp): demonstrates use of the BEHZ BFV variant for basic homomorphic encryption
- [depth-bgvrns.cpp](depth-bgvrns.cpp): demonstrates use of the BGVrns scheme for basic homomorphic encryption
- [linearwsum-evaluation.cpp](linearwsum.cpp): demonstrates the evaluation of a linear weighted sum using CKKS
- [polynomial-evaluation.cpp](polynomial-evaluation.cpp): demonstrates an evaluation of a polynomial (power series) using CKKS
- [pre-buffer.cpp](pre-buffer.cpp): demonstrates use of OpenFHE for encryption, re-encryption and decryption of packed vector of binary data
- [rotation.cpp](rotation.cpp): demonstrates use of EvalRotate for different schemes
- [simple-ckks-bootstrapping.cpp](simple-ckks-bootstrapping.cpp): simple example showing CKKS bootstrapping for a ciphertext with full packing
- [simple-integers.cpp](simple-integers.cpp): simple example showing homomorphic additions, multiplications, and rotations for vectors of integers using BFVrns
- [simple-integers-bgvrns.cpp](simple-integers-bgvrns.cpp): simple example showing homomorphic additions, multiplications, and rotations for vectors of integers using BGVrns
- [simple-integers-serial.cpp](simple-integers-serial.cpp): simple example showing typical serialization/deserialization calls for a prototype computing homomorphic additions, multiplications, and rotations for vectors of integers using BFVrns
- [simple-integers-serial-bgvrns.cpp](simple-integers-serial-bgvrns.cpp): simple example showing typical serialization/deserialization calls for a prototype computing homomorphic additions, multiplications, and rotations for vectors of integers using BGVrns
- [simple-real-numbers.cpp](simple-real-numbers): simple example showing homomorphic additions, multiplications, and rotations for vectors of real numbers using CKKS
- [simple-real-numbers-serial.cpp](simple-real-numbers-serial.cpp): simple example showing typical serialization/deserialization calls for a prototype computing homomorphic additions, multiplications, and rotations for vectors of integers using CKKS
- [threshold-fhe.cpp](threshold-fhe.cpp): shows several examples of threshold FHE in BGVrns, BFVrns, and CKKSrns
