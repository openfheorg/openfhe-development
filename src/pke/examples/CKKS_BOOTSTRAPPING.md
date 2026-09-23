OpenFHE Library - CKKS Bootstrapping
=====================================================================================================

Bootstrapping is the process of refreshing a ciphertext's noise and increasing its multiplicative depth (modulus) to allow for further computations, enabling fully homomorphic encryption. In the CKKS scheme, this procedure is approximate. In OpenFHE, the implementation of CKKS bootstrapping builds on [https://eprint.iacr.org/2019/688](https://eprint.iacr.org/2019/688), [https://eprint.iacr.org/2018/1043](https://eprint.iacr.org/2018/1043), [https://eprint.iacr.org/2020/1203](https://eprint.iacr.org/2020/1203), [https://eprint.iacr.org/2022/1167](https://eprint.iacr.org/2022/1167).

## The Bootstrapping Pipeline
The bootstrapping procedure follows a modular framework consisting of four main stages.

The original method started with a modulus raising step, as follows:
1. **ModRaise** (Modulus Raising): The ciphertext $(c_0, c_1)\mod q$ is logically viewed as $(c_0, c_1)\mod Q$, for $Q >> q$. This process effectively changes the underlying plaintext from $m(X)$ to $m(X) + q\cdot I(X)$, where $I$ is an integer overflow. Note that the modulus $Q$ needs to be large enough to support the desired number of levels after bootstrapping, as well as the levels required for the bootstrapping procedure. Also note that the overflows are over the coefficients of the ciphertext.
2. **CoeffsToSlots** (Homomorphic Encoding): This step performs a linear transformation to move the coefficients of the ciphertext polynomials into slots, in order to enable the removal of the overflows. In OpenFHE, this is implemented using a matrix-vector multiplication approach (often using a FFT-like butterfly structure) to minimize the number of rotations. The baby-step/giant-step evaluation accumulates the giant steps in Horner form with a single giant-step stride, which also minimizes the number of distinct rotation keys that must be generated and stored. Note that this step is expensive since it happens at the largest modulus.
3. **EvalMod** (Approximate Modular Reduction): This is the core functional evaluation. To recover an encryption of the message $m$ without the overflow, we have to evaluate an approximate modular reduction function homomorphically, using a sine function approximation for small angles. To handle larger ranges of $I$ (determined by the parameter $K$ depending in turn on the secret key distribution), we employ $r$ iterations of the double-angle formula, which reduces the computational complexity at the expense of a higher multiplicative depth. The underlying trigonometric function is computed using Chebyshev series interpolation. See [https://eprint.iacr.org/2019/688](https://eprint.iacr.org/2019/688), [https://eprint.iacr.org/2018/1043](https://eprint.iacr.org/2018/1043), [https://eprint.iacr.org/2020/1203](https://eprint.iacr.org/2020/1203) for details.
4. **SlotsToCoeffs** (Homomorphic Decoding): This step is the inverse of the CoeffsToSlots step and returns the underlying message to the slots encoding, resulting in a refreshed ciphertext $(c_0', c_1')(\bmod Q')$.

This variant of CKKS bootstrapping is commonly known as "ModRaise-first". There is another folklore variant of CKKS bootstrapping, commonly known as "SlotsToCoeffs-first", which could be traced to [https://eprint.iacr.org/2020/1335.pdf](https://eprint.iacr.org/2020/1335.pdf).

In this version, the steps order is the following:
1. **SlotsToCoeffs** (Homomorphic Decoding): Same as before. Note that bootstrapping starts at a slightly higher ciphertext modulus $q' > q$ in order to allow the linear transformation to the coefficient encoding before the ciphertext is depleted.
1. **ModRaise** (Modulus Raising): Same as before, but logically, now both the message and the overflows are in the coefficient encoding.
2. **CoeffsToSlots** (Homomorphic Encoding): Same as before.
3. **EvalMod** (Approximate Modular Reduction): Same as before.

There are a few main differences between the two versions:
- In the SlotsToCoeffs-first version, the user needs to reserve a number of levels before calling bootstrapping, while in the ModRaise-first version, the bootstrapping can start on the last level (typically requiring an extra level for scale adjustement right before **ModRaise**).
- The SlotsToCoeffs-first version performs the SlotsToCoeff transform on a smaller modulus than the ModRaise-first version, leading to both runtime and memory reduction.
- In the case of full real packing, internally, the SlotsToCoeffs-first version requires a single ciphertext internally to store all information, while the ModRaise-first version requires using two ciphertexts internally (corresponding to the real and imaginary parts). In single-threaded computation, this makes the SlotsToCoeffs-first substantially faster than the ModRaise-first.
- The SlotsToCoeffs-first version has a slightly better precision than the ModRaise-first one.

## Secret Key Distribution
The secret key distribution (`SetSecretKeyDist`) determines the bound $K$ on the number of mod-raise overflows and hence the probability that bootstrapping fails (an overflow coefficient exceeding $K$ corrupts the output). The failure probabilities below are for fully packed ciphertexts ($N/2$ slots) and were computed with the Irwin-Hall model of Appendix A of the [Security Guidelines for Implementing Homomorphic Encryption](https://cic.iacr.org/p/1/4/26/pdf); halving the number of slots lowers them by one bit.

| Distribution | $K$ | $N = 2^{16}$ | $N = 2^{17}$ | Notes |
|---|---|---|---|---|
| `SPARSE_ENCAPSULATED` (recommended) | 16 | $2^{-138}$ | $2^{-137}$ | Hamming weight 32 for the key used in bootstrapping and 192 otherwise ([https://eprint.iacr.org/2022/024](https://eprint.iacr.org/2022/024)). For first moduli above 60 bits (composite scaling), Hamming weight 64 and $K = 28$ are used (failure probability below $2^{-142}$). |
| `UNIFORM_TERNARY` | 648 | $2^{-67}$ | $2^{-27}$ | Distribution recommended by the homomorphic encryption security guidelines; requires a larger multiplicative depth for bootstrapping. |
| `SPARSE_TERNARY` (not recommended) | 28 | $2^{-23}$ | $2^{-22}$ | Hamming weight 192, as in the original CKKS paper. |

`SPARSE_ENCAPSULATED` is recommended for all flavors of CKKS bootstrapping (ModRaise-first, SlotsToCoeffs-first, iterative, composite scaling, and functional bootstrapping), as it achieves a failure probability below $2^{-128}$ for all supported ring dimensions. `UNIFORM_TERNARY` can be used when uniform ternary secrets are required for compliance with the security guidelines; note the failure probability at $N = 2^{17}$. `SPARSE_TERNARY` is discouraged because of its high failure probability.

## OpenFHE functions
In order to perform bootstrapping, the user needs to run `Enable(FHE)` and call:
- `EvalBootstrapSetup` (and if precomputations are not enabled, call `EvalBootstrapPrecompute`) which performs all precomputations and stores the plaintexts necessary for the linear transforms for a specified number of CKKS slots.
- `EvalBootstrapKeyGen` which generates all the evaluation keys required by the bootstrap procedure.
- `EvalBootstrap` which applies the bootstrap procedure over a ciphertext.

Since the number of slots can significantly affect the performance of the bootstrapping procedure, OpenFHE allows generating and storing precomputations corresponding to different number of slots.

For the best precision, the input messages to CKKS bootstrapping should be scaled to [-1,1].

Apart from the CKKS bootstrapping variant (dictated by setting the flag `BTSlotsEncoding` in `EvalBootstrapSetup`), the user can control various parameters of bootstrapping, which can lead to different performance and/or precision profiles.
- The `levelBudget` (for the CoeffsToSlots and SlotsToCoeffs transformations) dictates how many levels these transformations should take; more levels imply fewer rotations.
- The `bsgsDim` is used for the "baby-step giant-step" method for linear transforms. It also affects the efficiency through the number of rotations, and the internal default logic selects it in a way that minimizes the runtime.
- The `levelsAvailableAfterBootstrap` dictates how many levels are required to remain after the last step of the bootstrapping.
- The `correctionFactor` provides an internal scaling to improve precision. The default values were heuristically computed based on the ring dimension, number of slots and rescaling type.

## Iterative Precision Refinement
The modular reduction in CKKS is inherently approximate. OpenFHE implements a two-iteration bootstrapping procedure as described in [https://eprint.iacr.org/2022/1167](https://eprint.iacr.org/2022/1167). Briefly, this extended procedure performs bootstrapping twice, one to extract the message along with the bootstrapping error and the second one to bootstrap this scaled error, which is then removed from the initially bootstrapped ciphertext.

The user needs to specify `numIterations=2` in `EvalBootstrap`. The user should also specify the `precision` argument of the same function, which should be the expected precision of a single bootstrapping round. There is a large band of values for the precision parameter that would lead to similar output precision, but the user is encouraged to verify this for each application. Moreover, the `correctionFactor` argument can be modified from the default value to lead to an increase of the output precision (but the output precision for non-default values of the correction factor should be experimentially checked by the user).

## Examples for CKKS bootstrapping
The CKKS bootstrapping procedure is an involved procedure, and the users are encouraged to check out the provided examples in order to familiarize themselves with the functionality and the effect of the various parameters.

Examples
- [simple-ckks-bootstrapping.cpp](simple-ckks-bootstrapping.cpp) shows how to perform CKKS bootstrapping for fully packed real inputs, both variants.
- [advanced-ckks-bootstrapping.cpp](advanced-ckks-bootstrapping.cpp) shows the effect of the number of slots on the CKKS bootstrapping performance (by default runs ModRaise-first variant).
- [iterative-ckks-bootstrapping.cpp](iterative-ckks-bootstrapping.cpp) shows the precision improvement that can be achieved using two iterations of bootstrapping for both variants, and discusses the effect of the correction factor.

Extras
- [ckks-bootstrap.cpp](ckks-bootstrap.cpp) shows how to perform the precomputations and key generation for multiple values of the number of CKKS slots (by default runs ModRaise-first variant).
- [ckks-bootstrap-precision.cpp](ckks-bootstrap-precision.cpp) shows the effect of the correction factor for both single- and double-iteration CKKS bootstrapping, for both variants.
