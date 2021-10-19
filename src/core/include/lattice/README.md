PALISADE Lattice Cryptography Library
=====================================

[License Information](License.md)

Document Description
===================
This document is intended to describe the overall design, design considerations and structure of the lattice directory in the PALISADE lattice crypto library.

Lattice Directory Description
=============================

Directory Objective
-------------------
The files in the lattice directory support the lattice layer operations in the library.  The layer is used to represent polynomial rings
and support operations over polynomial rings.

This lattice layer is a middle layer in the library.
The lattice layer supports higher-level calls for operations on ring elements necessary for lattice cryptography.
The lattice layer is intended to make calls to lower layers that support math operations, such as modulus and ring arithmetic.

File Listing
------------

* Parameter classes files
  - [elemparams.h](elemparams.h): This header file is a simple class to contain ring element parameters.
  - [ilparams.h](ilparams.h), [ilparams.cpp](../../lib/lattice/ilparams.cpp): This pair of files represents a parameter class for the basic single-CRT lattice parameters.  This class inherits from the class in [elemparams.h](src/lib/lattice/elemparams.h).
  - [ildcrtparams.h](ildcrtparams.h): This file represents a parameter class for the more advanced and computationally efficient double-CRT lattice parameters.  This class inherits from the class in [ilparams.h](ilparams.h), [ilparams.cpp](../../lib/lattice/ilparams.cpp).
* Element classes files
  - [ilelement.h](ilelement.h): This file presents a basic interface class for elements from ideal lattices.
  - [poly.h](poly.h), [poly.cpp](../../lib/lattice/poly.cpp): These files present a basic class for Poly, elements from ideal lattices using a single-CRT representation.  This class inherits from the class in [ilelement.h](ilelement.h). This file also defines a NativePoly, which is simply a Poly using NativeInteger coefficients. A NativePoly is an important part of a DCRTPoly.
  - [dcrtpoly.h](dcrtpoly.h), [dcrtpoly.cpp](../../lib/lattice/dcrtpoly.cpp): These files present a basic class for DCRTPoly, elements from ideal lattices using a double-CRT representation.  This class inherits from the class in [ilelement.h](ilelement.h).
* Documentation files
  - [README.md](README.md): This file.



Directory Description
=====================

The primary objective of the code in this directory is to represent polynomial ring elements and manipulations on these elements.  The current implementations support polynomial rings that are of dimension a power of two (e.g. x^n + 1 where n is a power of 2).  A polynomial ring is defined as Rq := R/qR = Zq[X]/(f(X)), with f(X) a mononic irreducable polynomial of degree n, and q an integer modulus.

Support for arbitrary cyclotomic rings is also available but in experimental mode. The case of m = p and m = 2*p, where m is a cyclotomic order and p is a prime, have been tested relatively well. Other cases of m have not been tested.

The three main data classes in this layer are Poly, NativePoly and DCRTPoly.

A Poly is a single-CRT representation using BigInteger types as coefficients, and supporting a large modulus q.

A NativePoly is a single-CRT representation using NativeInteger types, which limites the size of the coefficients and the modulus q to 64 bits.

A DCRTPoly is a double-CRT representation.  In practice, this means that Poly uses a single large modulus q, while  DCRTPoly uses multiple smaller moduli.  Hence, Poly runs slower than DCRTPoly because DCRTPoly operations can be easier to fit into the native bitwidths of commodity processors.

Poly, NativePoly and DCRTPoly all implement the interface ILElement.  Any new ring polynomial classes should be built to conform to this interface.

The classes ILParams and ILDCRTParams contain parameters for the ring element representations.  In the case of Poly and NativePoly, this includes the order, modulus and root of unity.  In the case of DCRTPoly, this includes the order, double-CRT width, moduli and roots of unity.

ILParams and ILDCRTParams implement the interface ElemParams.  Any new parameter should be built to conform to this interface.

FORMAT
------
The coefficients of the polynomial ring, in their initial form, are just coefficients.
Translated into one of Poly or DCRTPoly, can be simply seen
as vector's representing polynomial ring elements.

We internally represent polynomial ring elements as being either in coefficient or evaluation format.  The initial or raw format, is noted as COEFFICIENT throughout the code. By applying the Chinese-Remainder-Transform (CRT), which is a Number Theoretic Transform (NTT)  and variant of the Discrete Fourier Transform (DFT), we convert the ring elements into the EVALUATION format. The EVALUATION format, with respect to multiplying two or more ring polynomials, allows us to do element-wise multiplication on the vectors.

Note that it is generally computationally less expensive to carry on all operations in the evaluation form.  However, the CRT and inverse CRT operations take O(nlogn) time using current best known algorithms, where n is the ring dimension.

ASSUMPTIONS
===========

* It is assumed that any scalar or vector operation such as multiplication, addition etc. done on one or more operations contain the same params.
  - Checks need to be added to the code to test the compatibility of parameters.
* Multiplication is currently only implemented in the EVALUATION format.
  - Code needs to be added to implement COEFFICIENT format multiplication, if desired.
