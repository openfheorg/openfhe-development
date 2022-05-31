Core Math Documentation
========================

.. contents:: Page Contents
   :local:
   :backlinks: entry

Math Backends
---------------

OpenFHE supports a number of mathematical backends for various usecases.
For more information refer to :doc:`math_backends`

Inheritance Diagram
---------------------

Let Gen. = Generator

.. mermaid::

   flowchart BT
       A[Distribution Generator] --> |Inherited by|B[Ternary Uniform Gen.];
       A[Distribution Generator] --> |Inherited by|C[Discrete Uniform Gen.];
       A[Distribution Generator] --> |Inherited by|D[Binary Uniform Gen.];
       A[Distribution Generator] --> |Inherited by|E[Discrete Gaussian Gen.];
       A[Distribution Generator] --> |Inherited by|F[Discrete Gaussian Generic Gen.];

File Listings
----------------

`Binary Uniform Generator (binaryuniformgenerator.h) <https://github.com/openfheorg/openfhe-development/blob/main/src/core/include/math/binaryuniformgenerator.h>`_

-  Generate ``Uniform`` distribution of binary values (mod 2)
-  Relies on built-in C++ generator for 32-bit unsigned integers defined
   in ``<random>``

`DFT Transform (dftransform.h) <https://github.com/openfheorg/openfhe-development/blob/main/src/core/include/math/dftransform.h>`_

-  Discrete Fourier Transform (FFT) code

`Discrete Gaussian Generator (discretegaussiangenerator.h) <https://github.com/openfheorg/openfhe-development/blob/main/src/core/include/math/discretegaussiangenerator.h>`_

-  Generate ``Gaussian`` distribution of discrete values.
-  Relies on built-in C++ generator for 32-bit unsigned integers defined
   in ``<random>``

`Discrete Gaussian Generator Generic (discretegaussiangeneratorgeneric.h) <https://github.com/openfheorg/openfhe-development/blob/main/src/core/include/math/discretegaussiangeneratorgeneric.h>`_

-  Implements the generic sampler by UCSD discussed in `Gaussian
   Sampling over the Integers: Efficient, Generic,
   Constant-Time <https://eprint.iacr.org/2017/259.pdf>`__
-  based heavily on Michael Walter’s original code.
-  2 different “Base Samplers”

   -  Peikert’s inversion method
   -  Knuth-Yao

-  Generic Sampler works independent from standard deviation of the
   distribution

   -  combines an array of aforementioned base samplers centered around
      0 to :math:`\frac{2^{b} - 1}{2^b}` through convolution

`Discrete Uniform Generator (discreteuniformgenerator.h) <https://github.com/openfheorg/openfhe-development/blob/main/src/core/include/math/discreteuniformgenerator.h>`_

-  Generate ``Uniform`` distribution of discrete values.
-  Relies on built-in C++ generator for 32-bit unsigned integers defined
   in ``<random>``

`Distr Gen (distrgen.h) <https://github.com/openfheorg/openfhe-development/blob/main/src/core/include/math/distrgen.h>`_

-  Basic noise generation functionality

`Distribution Generator (distributiongenerator.h) <https://github.com/openfheorg/openfhe-development/blob/main/src/core/include/math/distributiongenerator.h>`_

-  Base class for distribution generators

`Hardware Abstraction Layer (HAL) (hal.h) <https://github.com/openfheorg/openfhe-development/blob/main/src/core/include/math/hal.h>`_

-  Code to switch between math backends

`Matrix (matrix.h) <https://github.com/openfheorg/openfhe-development/blob/main/src/core/include/math/matrix.h>`_

-  Templated matrix implementation for SIMD-compatible matrix code

`Matrix Strassen (matrixstrassen.h) <https://github.com/openfheorg/openfhe-development/blob/main/src/core/include/math/matrixstrassen.h>`_

-  Matrix Strassen Operations

`Number Theory Functions (nbtheory.h) <https://github.com/openfheorg/openfhe-development/blob/main/src/core/include/math/nbtheory.h>`_

-  Number theory utilities
-  Check if two numbers are coprime
-  GCD of two numbers
-  Primality testing
-  witness function to test if a number is prime
-  Eulers Totient function phin(n)
-  Generator Algorithm

`Ternary Uniform Generator (ternaryuniformgenerator.h) <https://github.com/openfheorg/openfhe-development/blob/main/src/core/include/math/ternaryuniformgenerator.h>`_

-  Provides generation of uniform distribution of binary values
