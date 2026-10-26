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

The modulus raise uses the OverModRaise technique of [https://cic.iacr.org/p/2/3/32](https://cic.iacr.org/p/2/3/32) ([https://eprint.iacr.org/2025/1298](https://eprint.iacr.org/2025/1298)): the ciphertext is raised to $Q \cdot E$, where $E$ is an extra level (a prime of the size of the scaling modulus, or the corresponding composite primes) that is not part of any key, and the normalization multiplication that precedes CoeffsToSlots (by the exact power of two $2^{-\deg}/N$, which brings the overflows into the range of the approximate modular reduction) is rescaled by $E$ instead of by a level of the chain. This saves one level in all flavors of CKKS bootstrapping, which `GetBootstrapDepth`, `GetFBTDepth` and `GetFEFBTDepth` account for. No key switching is performed before $E$ is dropped, so every key-dependent operation stays at the modulus $Q \cdot P$ the keys are generated for, and the security of the parameters is unaffected. Because the normalization shrinks the message, the two key switchings that used to precede it (the switch back from the sparse secret of `SPARSE_ENCAPSULATED`/`HYBRID_TERNARY`, and the partial sum of the coefficients for sparsely packed ciphertexts) are folded into the hoisted key switching of the first CoeffsToSlots layer, whose rounding noise is attenuated by the multiplication by the encoding matrix; for the encapsulated distributions, `EvalBootstrapKeyGen` therefore generates one additional (fused) rotation key per baby step of that layer.

ModRaise-first bootstrapping also scales the message down by $2^{-c}$, $c$ being the correction factor minus $\log_2(q_0/\Delta)$, before the modulus raise. This is a multiplication followed by a rescale, so the input needs one level above the bottom one. When $c = 0$, the step is skipped and the input may be at the bottom level; the fixed ratio between the scaling factors of the bottom and raised levels is folded into the SlotsToCoeffs matrix, which acts after the approximate modular reduction has removed the overflow (folding it into CoeffsToSlots would scale the overflow as well and break the integrality the modular reduction relies on). $c = 0$ needs $\log_2(q_0/\Delta)$ to reach the correction factor, so with the default factor, which is at least 6, it needs a first modulus at least $2^6$ times the scaling modulus; an explicit correction factor equal to $\log_2(q_0/\Delta)$ does it too. Composite scaling often has a large enough gap, but not always: the library's own composite-scaling examples do not. The shrink itself needs a rescale before the raise, so for $c > 0$ the level remains unless the caller applies it: the scaling by $2^{-c}$ (with $c$ given by `GetCKKSBootCorrection`) can be folded into the last multiplication before bootstrapping, whose own rescale then lands on the bottom level, and `EvalBootstrap(ct, 1, 0, true)` (`correctionApplied`) skips the step, scales the result back up by $2^c$ as usual and saves the level. This is available for a single iteration of the ModRaise-first variant in the 64-bit build; the StC-first variant carries the correction in the last SlotsToCoeffs rescale instead.

This variant of CKKS bootstrapping is commonly known as "ModRaise-first". There is another folklore variant of CKKS bootstrapping, commonly known as "SlotsToCoeffs-first", which can be traced to [https://eprint.iacr.org/2020/1335.pdf](https://eprint.iacr.org/2020/1335.pdf).

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
| `HYBRID_TERNARY` (recommended) | 16 | $2^{-138}$ | $2^{-137}$ | Uniform ternary secret for all operations except the modulus raise in bootstrapping, which uses a sparse secret of Hamming weight 32 obtained by sparse secret encapsulation, as for `SPARSE_ENCAPSULATED` (Hamming weight 64 and $K = 28$ for first moduli above 60 bits). Security is determined by the uniform ternary secret. |
| `UNIFORM_TERNARY` | 648 | $2^{-67}$ | $2^{-27}$ | Distribution recommended by the homomorphic encryption security guidelines; requires a larger multiplicative depth for bootstrapping. |
| `SPARSE_TERNARY` (not recommended) | 28 | $2^{-23}$ | $2^{-22}$ | Hamming weight 192, as in the original CKKS paper. |

`HYBRID_TERNARY` and `SPARSE_ENCAPSULATED` are recommended for all flavors of CKKS bootstrapping (ModRaise-first, SlotsToCoeffs-first, iterative, composite scaling, and functional bootstrapping), as they achieve a failure probability below $2^{-128}$ for all supported ring dimensions. `HYBRID_TERNARY` has the failure probability, depth and approximation polynomials of `SPARSE_ENCAPSULATED` with a uniform ternary main secret, so it should be chosen when uniform ternary secrets are required for compliance with the security guidelines. `UNIFORM_TERNARY` can also be used, but note its failure probability at $N = 2^{17}$ and its larger depth. `SPARSE_TERNARY` is discouraged because of its higher failure probability.

## OpenFHE functions
In order to perform bootstrapping, the user needs to run `Enable(FHE)` and call:
- `EvalBootstrapSetup` (and if precomputations are not enabled, call `EvalBootstrapPrecompute`) which performs all precomputations and stores the plaintexts necessary for the linear transforms for a specified number of CKKS slots.
- `EvalBootstrapKeyGen` which generates all the evaluation keys required by the bootstrap procedure.
- `EvalBootstrap` which applies the bootstrap procedure over a ciphertext. Its optional `correctionApplied` flag states that the caller has already scaled the input by $2^{-c}$, with $c$ given by `GetCKKSBootCorrection`, which saves the level the correction would otherwise cost (see above).

Since the number of slots can significantly affect the performance of the bootstrapping procedure, OpenFHE allows generating and storing precomputations corresponding to different number of slots.

The keys generated by `EvalBootstrapKeyGen` for a given number of slots (the rotation and conjugation keys, and for `SPARSE_ENCAPSULATED` and `HYBRID_TERNARY` also the keys that switch between the dense and the sparse secret, including the fused rotation keys of the first CoeffsToSlots layer) can be serialized with `SerializeEvalBootstrapKey` and deserialized with `DeserializeEvalBootstrapKey`. This lets bootstrapping run on a party that did not generate the keys. The relinearization key is serialized separately, with `SerializeEvalMultKey`. The deserializing party calls `EvalBootstrapSetup` with the same parameters before running `EvalBootstrap`.

The bootstrapping precomputations are cached in the CKKS scheme of the crypto context and can take a significant amount of memory. `ClearBootstrapPrecom` releases them for one crypto context, and `CryptoContextFactory<DCRTPoly>::ReleaseAllContexts` releases all registered crypto contexts together with their caches and evaluation keys.

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
- [simple-complex-numbers.cpp](simple-complex-numbers.cpp) shows CKKS bootstrapping for complex inputs.
- [ckks-bootstrap-keys-serial.cpp](ckks-bootstrap-keys-serial.cpp) shows how to serialize the bootstrapping keys and bootstrap on a crypto context that is deserialized from files.
- [ckks-release-memory.cpp](ckks-release-memory.cpp) shows how to release the memory held by the bootstrapping precomputations.
- The composite scaling versions of the single- and double-iteration bootstrapping examples are listed in [COMPOSITE_SCALING.md](COMPOSITE_SCALING.md), and the functional bootstrapping examples in [CKKS_FUNCTIONAL_BOOTSTRAPING.md](CKKS_FUNCTIONAL_BOOTSTRAPING.md).

Extras
- [ckks-bootstrap.cpp](../extras/ckks-bootstrap.cpp) shows how to perform the precomputations and key generation for multiple values of the number of CKKS slots (by default runs ModRaise-first variant).
- [ckks-bootstrapping-precision.cpp](../extras/ckks-bootstrapping-precision.cpp) shows the effect of the correction factor for both single- and double-iteration CKKS bootstrapping, for both variants.
