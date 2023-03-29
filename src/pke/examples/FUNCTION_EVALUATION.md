OpenFHE Lattice Cryptography Library - Arbitrary Smooth Function Evaluation
============================================================================

[License Information](License.md)

Document Description
===================
This document describes how to evaluate an arbitrary smooth function on a ciphertext in CKKS using [Chebyshev approximation](https://www.gnu.org/software/gsl/doc/html/cheb.html). The Chebyshev approximation is a method of approximating a smooth function using polynomials.

Example Description
==========================

The example for this code is located in [function-evaluation.cpp](function-evaluation.cpp). The file gives examples on how to run `EvalLogistic`, the logistic function $\frac{1}{1 + e^{-x}},$ and an arbitrary function using `EvalChebyshevFunction`. We use the square root function in our example for `EvalChebyshevFunction`.

Input Parameters
==========================
- `ciphertext`: This is the ciphertext we wish to operate on.
- `a`: This is the lower bound of underlying plaintext values we could have.
- `b`: This is the upper bound of underlying plaintext values we could have.
- `degree`: This is the polynomial degree of the Chebyshev approximation. A higher degree gives a more precise estimate, but takes longer to run.

How to Choose Multiplicative Depth
====================================
Each run of EvalChebyshevFunction requires a certain number of multiplications which depends on the input polynomial degree. We give a table below to map polynomial degrees to multiplicative depths.

| Degree        | Multiplicative Depth |
| ------------- |:--------------------:|
| 3-5           | 4                    |
| 6-13          | 5                    |
| 14-27         | 6                    |
| 28-59         | 7                    |
| 60-119        | 8                    |
| 120-247       | 9                    |
| 248-495       | 10                   |
| 496-1007      | 11                   |
| 1008-2031     | 12                   |

Note that if we use a range $(a, b) = (-1, 1),$ the multiplicative depth is 1 less than the depths listed in the table.
