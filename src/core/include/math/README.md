# OpenFHE Core Math

We provide a brief description below, but encourage readers to refer
to [Read The Docs - Core Math](https://openfhe-development.readthedocs.io/en/latest/assets/sphinx_rsts/modules/core/core_math.html)

# Math Backends

OpenFHE supports a number of mathematical backends for various usecases. For more information refer to [Math Backends](math_backends.md) or 
[Read The Docs - Core Math](https://openfhe-development.readthedocs.io/en/latest/assets/sphinx_rsts/modules/core/core_math.html)

# Inheritance Diagram

Let Gen. = Generator

```mermaid
flowchart BT
    A[Distribution Generator] --> |Inherited by|B[Ternary Uniform Gen.];
    A[Distribution Generator] --> |Inherited by|C[Discrete Uniform Gen.];
    A[Distribution Generator] --> |Inherited by|D[Binary Uniform Gen.];
    A[Distribution Generator] --> |Inherited by|E[Discrete Gaussian Gen.];
    A[Distribution Generator] --> |Inherited by|F[Discrete Gaussian Generic Gen.];
```

# File Listings

[Binary Uniform Generator](binaryuniformgenerator.h)

- Generate `Uniform` distribution of binary values (mod 2)
- Relies on built-in C++ generator for 32-bit unsigned integers defined in `<random>`

[DFT Transform](dftransform.h)

- Discrete Fourier Transform (FFT) code

[Discrete Gaussian Generator](discretegaussiangenerator.h)

- Generate `Gaussian` distribution of discrete values.
- Relies on built-in C++ generator for 32-bit unsigned integers defined in `<random>`

[Discrete Gaussian Generator Generic](discretegaussiangeneratorgeneric.h)

- Implements the generic sampler by UCSD discussed in [Gaussian Sampling over the Integers:
  Efficient, Generic, Constant-Time](https://eprint.iacr.org/2017/259.pdf)
- based heavily on Michael Walter's original code.
- Generic Sampler works independent from standard deviation of the distribution
  - combinaes an array of aforementioned base samplers centered around 0 to $\frac{2^{b} - 1}{2^b}$ through convolution
- 2 different "Base Samples"
  - Peikert's inversion method
  - Knuth-Yao

[Discrete Uniform Generator](discreteuniformgenerator.h)

- Generate `Uniform` distribution of discrete values.
- Relies on built-in C++ generator for 32-bit unsigned integers defined in `<random>`

[Distr Gen](distrgen.h)

- Basic noise generation functionality

[Distribution Generator](distributiongenerator.h)

- Base class for distribution generators

[Hardware Abstraction Layer (HAL)](hal.h)

- Code to switch between math backends

[Matrix](matrix.h)

- Templated matrix implementation for SIMD-compatible matrix code

[Matrix Strassen](matrixstrassen.h)

- Matrix Strassen Operations

[NB Theory](nbtheory.h)

- Number theory utilities
- Check if two numbers are coprime
- GCD of two numbers
- If a number, i, is prime
- witness function to test if a number is prime
- Eulers Totient function phin(n)
- Generator Algorithm

[Ternary Uniform Generator](ternaryuniformgenerator.h)

- Provides generation of uniform distribution of binary values