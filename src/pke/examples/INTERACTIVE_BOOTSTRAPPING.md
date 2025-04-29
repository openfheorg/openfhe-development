OpenFHE Library - Interactive Bootstrapping
=====================================================================================================

OpenFHE provides two methods for interactive CKKS bootstrapping:
* The $n$-party method described in Appendix E of https://eprint.iacr.org/2023/1203. This method is an optimized version of the method originally proposed in https://eprint.iacr.org/2020/304 and https://arxiv.org/abs/2009.00349.
* The 2-party method proposed in Appendix D of https://eprint.iacr.org/2023/1203, which is based on the idea of distributed rounding.

The 2-party method is more efficient than the $n$-party method for the case when $n=2$. It requires only one extra RNS limb in contrast to 2-3 extra RNS limbs for the $n$-party bootstrapping for the FIXED* modes, and an exra RNS limb for both methods for the FLEXIBLE* modes of CKKS. Moreover, the computational and communication complexity of the $2$-party interactive bootstrapping is smaller than for the $n$-party method.

## Examples for the $2$-party interactive bootstrapping

- [interactive-bootstrapping.cpp](interactive-bootstrapping.cpp) shows two examples of $2$-party interactive bootstrapping: interactive bootstrapping without a computation and interactive bootstrapping together with a Chebyshev interpolation

## Examples for the $n$-party interactive bootstrapping

- [tckks-interactive-mp-bootstrapping.cpp](tckks-interactive-mp-bootstrapping.cpp): An example of $n$-party interactive bootstrapping by itself
- [tckks-interactive-mp-bootstrapping-Chebyshev.cpp](tckks-interactive-mp-bootstrapping-Chebyshev.cpp): An example of $n$-party interactive bootstrapping together with Chebyshev interpolation
