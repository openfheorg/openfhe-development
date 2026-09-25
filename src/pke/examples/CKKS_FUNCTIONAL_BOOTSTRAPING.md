OpenFHE Lattice Cryptography Library - CKKS-based Functional Bootstrapping
==========================================================================

[License Information](../../../LICENSE)

Document Description
====================
This document describes the two flavors of CKKS-based functional bootstrapping in OpenFHE and what capabilities are
currently supported for each of them:
- the evaluation of arbitrary lookup tables (LUT) over integers, based on
[Alexandru, Kim and Polyakov CRYPTO 2025](https://eprint.iacr.org/2024/1623.pdf) (section "Functionality" below);
- the evaluation of smooth functions over real numbers using Fourier extension, based on
[ePrint 2026/367](https://eprint.iacr.org/2026/367) (EUROCRYPT 2026) (section "Fourier-Extension Functional Bootstrapping" below).

Both are experimental functionalities.

Example Description
====================

The example file for the lookup table evaluation is located at [functional-bootstrapping-ckks.cpp](functional-bootstrapping-ckks.cpp). The file gives
examples on how to run:
- `ArbitraryLUT`, which applies a function specified as an LUT over an input ciphertext, for various values of the input and output bit-sizes;
- `MultiValueBootstrapping`, which applies different functions specified as LUTs over the same input ciphertext, reusing intermediate
computations; it also shows how to apply leveled computations after an LUT evaluation;
- `MultiPrecisionSign`, which evaluates the sign of a large value using digit decomposition, for various sizes of the digits.

The example file for the Fourier-extension functional bootstrapping is located at
[FE-functional-bootstrapping-ckks.cpp](FE-functional-bootstrapping-ckks.cpp). It refreshes one CKKS ciphertext and evaluates
three functions on it (the exponential over [-2, 2], the sigmoid over [-8, 8] and the tanh approximation of GELU over [-8, 8]),
sharing the function-independent part of the computation among them.


Functionality
=============

**RLWE schemelet**
We proposed a hybrid scheme that is similar in flavor to a vectorized FHEW scheme. Concretely, we consider the input and output
messages to be integers encoded in the RLWE (Ring LWE) scheme as coefficients, which is equivalent to the coefficient-encoded BFV scheme.
RLWE is additively homomorphic. For more homomomoprhic operations, we convert to CKKS.

We work with an RLWE scheme that assumes the plaintext modulus and the ciphertext modulus to be powers of two (not RNS-friendly). We
implemented this as a "schemelet", i.e., a thin layer of abstraction for multiprecision encryption, decryption, and conversion to the
(RNS) CKKS scheme.

The RLWE and CKKS schemes are compatible in the sense that they can share the same secret key (and implicitly ring dimension). This
makes the conversion between RLWE and CKKS to essentially be modulus switching.

A vector encoded in RLWE can have as many elements as the ring dimension. If this is the case (the number of elements is between half
the ring dimension and the ring dimension), this corresponds to a full complex packing in CKKS, where the complex slots are also
populated. Otherwise, real CKKS packing (full or sparse) is used.

Note that the message is encoded in the coefficients in the RLWE scheme, but when converted to CKKS, the coefficients are held in
the slots of the CKKS ciphertexts. To be able to apply CKKS leveled computations, we need to homomorphically transform from
the coefficient encoding to the slot encoding. When doing this via an FFT-like transform (instead of a linear transform), the
slots will be bit reversed in the CKKS ciphertext. When intermediate computations involving rotations are done in CKKS (see more
below), it is more efficient to apply bit reversal in the encoding and decoding of RLWE. The argument `bitReverse` in
`SchemeletRLWEMP::EncryptCoeff` and `SchemeletRLWEMP::DecryptCoeff` has this role.

**Functional Bootstrapping**
The full functionality is described in [[AKP25]](https://eprint.iacr.org/2024/1623.pdf).

First, the plaintext input and output bit-sizes for the desired function are set, which determine the depth of the computation. The
RLWE ciphertext modulus and CKKS scaling factor are also set in accordance to the desired precsion. Second, the trigonometric Hermite
Interpolation coefficients are computed for the function to be evaluated, based on a desired order of the interpolation (currently
supported orders are 1, 2, and 3). For non-Boolean functions or higher orders, this is done through `GetHermiteTrigCoefficients`, which
returns complex coefficients. For the first order and a Boolean function f, an optimized implementation is used, which requires the
(real and integer) coefficients to be set as [f(1), f(0) - f(1)]. For numeric accuracy in CKKS, the coefficients should be scaled
down such that their maximum magnitude is at most one. This scaling factor `scale` should be chosen to be an integer to incur a
small noise increase.

The desired number of levels that should remain after the function evaluation (for output precision) should be specified. Then, the
setup for the computation is called by `EvalFBTSetup` and the necessary keys are generated by calling `EvalBootstrapKeyGen`.

The RLWE input ciphertext needs to be converted to a CKKS ciphertext in order to commence the functional bootstrapping. This is done
by calling `SchemeletRLWEMP::ConvertRLWEToCKKS`. Then, `EvalFBT` is called to obtain a CKKS encrypting the coefficients of the function
evaluation output. Finally, to return to the exact RLWE scheme, `SchemeletRLWEMP::ConvertCKKSToRLWE` should be called.

Internally, `EvalFBT` performs the following steps: modulus raising, coefficient to slots transform (equivalent to homomorphic
encoding), complex exponential evaluation, computing powers of the complex exponential, power series evaluation of the
Hermite coefficients, slots to coefficients transform (equivalent to homomorphic decoding) and necessary scalings.

If one wants to apply an intermediate leveled computation on the CKKS slots, then the number of levels for this leveled computation
needs to be specified. If this intermediate computation requires rotations, then in order to apply the rotations over the natural
order in CKKS slots, the RLWE input needs to be bit reversed if multiple levels are used for encoding and decoding. Then
`EvalFBTNoDecoding` should be called, the intermediate computation applied and finally, `EvalHomDecoding` should be called.

The features that need to be enabled for CKKS functional bootstrapping are PKE, KEYSWITCH, LEVELEDSHE, ADVANCEDSHE and FHE.

**Multi-Value Bootstrapping**

When multiple functions need to be evaluated over the same input ciphertext, we can reuse the computations for functional
bootstrapping up to (including) the powers of the complex exponential. This can be called by `EvalMVBPrecompute`. Using the
ciphertexts obtained as such, one can then call `EvalMVB` once for every set of coefficients corresponding to a different
function. All these functions must be interpolated with the same shape (same plaintext modulus and `order`, which dictate
the size of the coefficient vector; for degree less than 5, the sparsity of the coefficients should also be identical) as
the coefficients passed to `EvalMVBPrecompute`, since those determine which powers of the complex exponential are precomputed.
As before, if intermediate CKKS leveled computations are required before converting back to RLWE, one
should call `EvalMVBNoDecoding` and `EvalHomDecoding`.

**Chain computations and Sign**

For certain computations, such as sign, we can support LUTs over larger inputs than direct functional bootstrapping for arbitrary
functions. In particular, we achieve this by performing homomorphic digit decomposition using functional bootstrapping for the
smaller digits, and process these smaller digits separately.

**Secret key distributions**

Functional bootstrapping is supported for sparse secret keys (SPARSE_TERNARY and SPARSE_ENCAPSULATED) and for
uniform ternary secret keys (UNIFORM_TERNARY). SPARSE_ENCAPSULATED is recommended, as it achieves a probability of
failure below 2^-128; SPARSE_TERNARY is discouraged.

The SPARSE_TERNARY distribution is the distribution used in the original CKKS paper [[CKKS17](https://eprint.iacr.org/2016/421.pdf)],
where the Hamming weight of the secret key is set to 192. For the set number of overflows in bootstrapping, K = 28, this
distribution leads to a larger probability of failure (about 2^-22 for 2^16 slots), so it should not be used in deployments.
Compared to SPARSE_ENCAPSULATED, choosing this distribution requires an extra level in the complex exponential approximation
to achieve correctness. This is the distribution used for the benchmarks in [[AKP25]](https://eprint.iacr.org/2024/1623.pdf).

The SPARSE_ENCAPSULATED distribution (described in [[BTH22]](https://eprint.iacr.org/2022/024.pdf)) uses a Hamming weight of 32
for the key used in (functional) bootstrapping and 192 for other operations. With the set number of overflows K = 16, this
distribution leads to a negligible probability of failure (below 2^-138 for N = 2^16 and 2^-137 for N = 2^17 with full
packing). Moreover, for all supported LUT sizes (up to 14 bits), the number of levels for the complex exponential
approximation is the same. The only caveat for the current implementation is that when the
scaling factor is very close to the first modulus size in CKKS (which happens for LUT of input bit-size 14), the noise introduced
by the extra key switching is larger. For a first modulus larger than 60 bits (which requires composite scaling in the 64-bit
build), the Hamming weight of the sparse key is 64 and the K = 28 approximation of SPARSE_TERNARY is used, which keeps the
probability of failure negligible (below 2^-142 for 2^16 slots) at the cost of the extra level mentioned above.

The UNIFORM_TERNARY distribution is the distribution recommended by the homomorphic encryption security guidelines and can be
used when uniform ternary secrets are required for compliance with them. It is handled in the same manner as in regular CKKS
bootstrapping: the number of overflows is bounded by K = 672 (probability of failure below 2^-73
for N = 2^16 and 2^-30 for N = 2^17 with full packing), and the complex exponential (or cosine, for the binary case) is
approximated by a degree-104 Chebyshev interpolation over [-672, 672] followed by six double-angle iterations (instead of degree
64/46 and two double-angle iterations for the sparse distributions). This increases the
multiplicative depth of functional bootstrapping by 5 levels. In addition, since the mod-raised message is scaled down by K
before the homomorphic encoding, larger scaling factors (roughly 5-9 more bits, depending on the parameters) are needed to
achieve the same output noise as for the sparse distributions.

**Scaling techniques**
All scaling techniques (FIXEDMANUAL, FIXEDAUTO, FLEXIBLEAUTO, FLEXIBLEAUTOEXT, COMPOSITESCALINGAUTO, and
COMPOSITESCALINGMANUAL) are supported. The FLEXIBLEAUTO, FLEXIBLEAUTOEXT, and COMPOSITESCALING* modes track the exact
level-specific scaling factors, which removes the scaling-factor drift of the FIXED* modes; hence they achieve smaller noise
for the same parameters (equivalently, correctness can be achieved with a smaller CKKS scaling factor). The noise of the
COMPOSITESCALING* modes is roughly the same as that of FLEXIBLEAUTO for the same parameters, and all secret key
distributions are supported in these modes.

**Current limitations**
- There is no automated selection of parameters and approximation orders. The user needs to choose appropriate RLWE and CKKS
cryptoparameters, trigonometric Hermite interpolation order and the scaling for the Hermite coefficients. These parameters
should guarantee correct decryption in RLWE (the error should not corrupt the message) in order to achieve
$\textsf{IND}-\textsf{CPA}^{D}$ security.
If the output is decrypted under CKKS, noise flooding should be applied in order to achieve $\textsf{IND}-\textsf{CPA}^{D}$
security.
- With a scaling factor fitting on native int size of 64 bits, LUTs up to 14 bits in size are supported. Larger scaling
factors (e.g., 90 bits) are supported with the COMPOSITESCALING* modes, which represent the scaling factor as a product
of several smaller primes.
- The current multiprecision sign evaluation implementation requires that the digit bit size divides the input bit size.
- In the COMPOSITESCALING* modes, the first modulus has to be at least one bit larger than the scaling factor (whose bit
length matches the RLWE ciphertext modulus), as required by the parameter generation for composite scaling.
- The 128-bit build (`NATIVE_SIZE == 128`) is not supported; `EvalFBTSetup` rejects it.
- MULTIPARTY is not supported.

Fourier-Extension Functional Bootstrapping
==========================================

**Overview**
The Fourier-extension functional bootstrapping (FE functional bootstrapping) refreshes a CKKS ciphertext and evaluates a
smooth real-valued function f on its slots in a single pass. Unlike the lookup table evaluation described above, it operates
directly on CKKS ciphertexts (no RLWE schemelet is involved), its inputs are real numbers rather than integers, and its output
is approximate.

The method replaces the approximate modular reduction of CKKS bootstrapping by a Fourier series of f. Every term of the series
is periodic, so the integer overflows introduced by modulus raising vanish when the series is evaluated, and the evaluation of
the series both removes the overflows and applies f. The name refers to how the series is obtained: f is approximated on the
message domain, which is half of the period of the series, and the approximation is free on the other half. Such a Fourier
extension converges much faster than a plain Fourier expansion of a non-periodic function.

Internally, `EvalFEFuncBootstrap` follows the SlotsToCoeffs-first variant of CKKS bootstrapping (see
[CKKS_BOOTSTRAPPING.md](CKKS_BOOTSTRAPPING.md)): SlotsToCoeffs transform, modulus raising, CoeffsToSlots transform, evaluation
of the complex exponential (Chebyshev interpolation followed by double-angle iterations), and evaluation of the Fourier series
over the powers of the complex exponential.

**Fourier coefficients**
The input message m has to lie in [-1/2, 1/2). A function f over [-B, B] is evaluated as g(m) = f(2Bm), and the
coefficient vector c = (c_0, c_1, ..., c_d) has to satisfy

$$g(m) \approx 2 \cdot \mathrm{Re}\left(\sum_{j=0}^{d} c_j e^{\pi i j m}\right), \quad m \in [-1/2, 1/2).$$

In other words, c_0 is half of the constant term of the series and c_j, for j > 0, are the one-sided coefficients of the
series (the conjugate terms are added internally). The output is always real-valued; with CKKSDataType COMPLEX, the imaginary
parts of the input slots are discarded, so CKKSDataType REAL should be used unless complex values are needed elsewhere in the
computation.

The coefficients are computed offline with the Python scripts in [fefbt-python](https://github.com/openfheorg/fefbt-python),
which take the target function f, the interval [-B, B] and the degree d, and print the coefficient vector as a C++
declaration together with the precision it achieves. The example contains the coefficient vectors for its three functions.

**OpenFHE functions**
The features that need to be enabled are PKE, KEYSWITCH, LEVELEDSHE, ADVANCEDSHE and FHE. Then:
- `FHECKKSRNS::GetFEFBTDepth` returns the multiplicative depth consumed by the FE functional bootstrapping for a given level
budget, coefficient vector and secret key distribution. The levels to be used after the bootstrapping should be added to it
when setting the multiplicative depth of the crypto context.
- `EvalFEFuncBootstrapSetup` performs the precomputations of the linear transforms for a given level budget and number of slots.
A level budget of {1, 1} uses a single linear transform for each of the SlotsToCoeffs and CoeffsToSlots steps.
- `EvalBootstrapKeyGen` (together with `EvalMultKeyGen`) generates the keys, as for regular CKKS bootstrapping.
- `EvalFEFuncBootstrap` refreshes a ciphertext and evaluates the function given by a coefficient vector.

As the SlotsToCoeffs transform is performed first, the input ciphertext has to have enough levels left for it: in the example,
the input is encoded at level `depth - (levelBudget[1] + 1)`. A ciphertext at a higher level is brought down to the required
level automatically.

When several functions need to be evaluated on the same input, the function-independent part of the computation (up to and
including the powers of the complex exponential), which dominates the cost, can be shared. `EvalFEFuncBootstrapPrecompute`
performs it and returns the powers, and `EvalFEFuncBootstrapWithPrecomp` evaluates the series of one function against them.
The coefficient vector passed to `EvalFEFuncBootstrapPrecompute` determines which powers are computed, so it should be that of
the longest series (of degree at least 5); the error message of `EvalFEFuncBootstrapWithPrecomp` reports the maximum degree
if a longer series is passed.

`EvalFEFuncBootstrapSetup`, `EvalBootstrapSetup` and `EvalFBTSetup` store their precomputations in the same entry for a given
number of slots, so a crypto context holds the precomputations of only one of them for each number of slots.

**Secret key distributions**
All three distributions are supported, and the probabilities of failure are those of the bound K on the mod-raise overflows
used for each of them (for full packing):
- SPARSE_ENCAPSULATED (recommended): K = 16, probability of failure below 2^-128. For a first modulus larger than 60 bits
(which requires composite scaling in the 64-bit build), the Hamming weight of the sparse key is 64 and K = 28 is used, which
keeps the probability of failure negligible.
- UNIFORM_TERNARY: K = 696, probability of failure below 2^-79 for N = 2^16 and 2^-33 for N = 2^17. It can be used when uniform
ternary secrets are required for compliance with the homomorphic encryption security guidelines, at the cost of a larger
multiplicative depth (9 double-angle iterations instead of 3-4).
- SPARSE_TERNARY (discouraged): K = 28, probability of failure about 2^-23 for N = 2^16.

**Scaling techniques and packing**
All scaling techniques (FIXEDMANUAL, FIXEDAUTO, FLEXIBLEAUTO, FLEXIBLEAUTOEXT, COMPOSITESCALINGAUTO, and
COMPOSITESCALINGMANUAL) are supported, for both full and sparse packing.

**Current limitations**
- The first modulus has to be exactly one bit larger than the scaling factor (`FirstModSize = ScalingModSize + 1`), since the
message is embedded into half of the period of the series; `EvalFEFuncBootstrap` and `EvalFEFuncBootstrapPrecompute`
throw otherwise.
- Only HYBRID key switching is supported.
- There is no correction factor and no iterative (Meta-BTS) mode, and there is no automated selection of the number of
Fourier coefficients: the user needs to choose it (and the domain [-B, B]) so that the approximation error of the series is
below the desired precision, for example using the precision reported by the coefficient generator.
- If the output is decrypted under CKKS, noise flooding should be applied in order to achieve $\textsf{IND}-\textsf{CPA}^{D}$
security.
- The 128-bit build (`NATIVE_SIZE == 128`) is not supported; `EvalFEFuncBootstrapSetup` rejects it.
