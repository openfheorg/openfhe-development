OpenFHE Lattice Cryptography Library - Scheme switching between CKKS and FHEW experimental capability
=====================================================================================================

[License Information](License.md)

Document Description
====================
This document describes how to use the scheme switching functionality to convert between CKKS and FHEW ciphertexts and perform intermediate
operations.

Example Description
====================

The example for this code is located in [scheme-switching.cpp](scheme-switching.cpp). The file gives examples on how to run:
- `EvalCKKStoFHEW`, which converts a CKKS ciphertext to FHEW ciphertexts;
- `EvalFHEWtoCKKS`, which converts FHEW ciphertexts to a CKKS ciphertext;
- how to combine the two with intermediate operations, for example the floor function or a polynomial;
- `EvalCompareSchemeSwitching `, which returns the result of the comparison between two CKKS ciphertexts via transformation to FHEW ciphertexts
and comparison;
- `EvalMinSchemeSwitching`, `EvalMinSchemeSwitchingAlt` and `EvalMaxSchemeSwitching`, `EvalMaxSchemeSwitchingAlt` respectively, which return
the min and argmin, respectively max and argmax, of a vector of reals packed inside a CKKS ciphertext, via iterated scheme switching.


Functionality
=============

**CKKS->FHEW**
We can transform a CKKS ciphertext (slot-packed and under public key encryption) into FHEW ciphertexts (symmetric key encryption), where
each FHEW ciphertext encrypts a slot of the CKKS ciphertext. The conversion is done by computing the scaled homomorphic decoding (via a
linear transform which can be precomputed), modulus switching, key switching, LWE extraction from RLWE, and another modulus switching.

The features that need to be enabled are PKE, KEYSWITCH, LEVELEDSHE and SCHEMESWITCH.

The user has to generate a CKKS cryptocontext and keys with the desired parameters, as well as to set up the FHEW cryptocontext and
private key through `EvalCKKStoFHEWSetup` and the automorphism keys and key switch hints through `EvalCKKStoFHEWKeyGen`. The setup is
completed by calling `EvalCKKStoFHEWPrecompute` which takes as argument the scale with which to multiply the decoding matrix, which
in most cases should be chosen by the user to be Q / (scFactor * p), where Q is the CKKS ciphertext modulus on level 0, scFactor is the
CKKS scaling factor for that level, and p is the desired FHEW plaintext modulus. If the scale is left to be the default value of 1, the
implicit FHEW plaintext modulus will be Q / scFactor, and the user should take this into account. Finally, the user can also divide
separately the messages by p, and input plaintexts in the unit circle, then scale only by Q / scFactor and recover the initial message
in FHEW.

After the setup and precomputation, the user should call `EvalCKKStoFHEW`. The number of slots to be converted is specified by the user,
otherwise it defaults to the number of slots specified in the CKKS scheme. Note that FHEW plaintexts are integers, so the messages from
CKKS will be rounded.

**FHEW->CKKS**
We can transform a number of FHEW ciphertexts (symmetric key encryption) into a CKKS ciphertext (public key encryption) encrypting in
its slots the input messages. The conversion is done by evaluating the FHEW decryption homomorphically (via a linear transform, which
cannot be precomputed because it depends on the ciphertexts), then computing the polynomial interpolation of the modular reduction
function (approximated via the sine function), and finally postprocessing the ciphertext to the appropriate message range.

The features that need to be enabled are PKE, KEYSWITCH, LEVELEDSHE, ADVANCEDSHE and SCHEMESWITCH.

The user has to generate a CKKS cryptocontext and keys with the desired parameters, as well as a FHEW cryptocontext and private key.
The setup also includes precomputing the necessary automorphism keys and CKKS encryption of the FHEW secret key, as well as other
information for switching from FHEW to CKKS, through `EvalFHEWtoCKKSSetup` and `EvalFHEWtoCKKSKeyGen`.

The conversion between FHEW to CKKS is called via `EvalFHEWtoCKKS`, where the user has to specify the number of ciphertexts to
convert into a single CKKS ciphertext, the FHEW plaintext modulus (by default 4), and if the output is not binary, the range for
postprocessing the CKKS ciphertext after the Chebyshev polynomial evaluation. The example `SwitchFHEWtoCKKS()` illustrates this aspect.

Importantly, for correct CKKS decryption, the messages have to be much smaller than the FHEW plaintext modulus used when encrypting in
FHEW. The reason for this is that the modular reduction approximation implemented works well around zero, so m/p should be very small.
(If this does not happen, only small messages will be converted correctly.) Moreover, since the postprocessing implies multiplying
by the FHEW plaintext modulus used, which can be large depending on the target application, some loss of precision is expected when the
message space is large.

**CKKS->FHEW->operation->CKKS**
With the previous two modules in place, we can also work with CKKS ciphertexts, convert them to FHEW, perform operations on them, and
then convert the result back to CKKS.

The user has to generate a CKKS cryptocontext and keys with the desired parameters, then call `EvalSchemeSwitchingSetup` and
`EvalSchemeSwitchingKeyGen`, which combine the setups for both conversions, then the precomputation for the CKKS to FHEW conversion
`EvalCKKStoFHEWPrecompute` as above or `EvalCompareSwitchPrecompute`, and the `BTKeyGen` for the desired intermediate FHEW computations.

After calling `EvalCKKStoFHEW`, the user then applies the desired functions on the FHEW ciphertexts. In the example
`FloorViaSchemeSwitching()` the function is generalized floor/shifted truncation, in the example `ComparisonViaSchemeSwitching()`
the function is comparison between two vectors, and in the example `FuncViaSchemeSwitching()` the function is specified and computed
through `GenerateLUTviaFunction`.

Finally, `EvalFHEWtoCKKS` should be called to switch back to CKKS, where the plaintext modulus of the output of the above function should
be specified (e.g., 4 for the output of comparison).

Recall that FHEW supports integers, while CKKS encodes real values. Therefore, a rounding is done during the conversion. For instance, to
correctly compare numbers that are very close to each other, the user has to scale the inputs with the desired precision. The example
`ComparisonViaSchemeSwitching()` shows how to do this via `EvalCompareSwitchPrecompute`.

Currently, the code does not support an arbitrary function to be applied to the intermediate FHEW ciphertexts if they have to be converted
back to CKKS. The reason is that (1) the current implementation of `GenerateLUTviaFunction` works only for the small decryption ciphertext
modulus q = 2048, which allows a plaintext modulus of at most p = 8 (`GetMaxPlaintextSpace()`) and (2) the current implementation of light
bootstrapping to convert FHEW ciphertexts to a CKKS ciphertext approximates correctly the modular function only arround zero, which requires
the messagee m << p. Instead of specifying directly the larger plaintext modulus in `EvalFHEWtoCKKS`, which is required to postprocess
the ciphertext obtained after the Chebyshev evaluation, one can supply the plaintext modulus as 4, which returns a ciphertext
encrypting $y=sin(2pi*x/p)$. Then, one can apply $arcsin(y)*p/(2pi)$. However, this also does not cover the whole initial message space,
since arcsin has codomain $[-pi/2, pi/2]$. This issue is exemplified in the example `FloorViaSchemeSwitching()`.

**FHEW->CKKS->operation->FHEW**
This functionality is the mirror of the above. The user should call `EvalSchemeSwitchingSetup`, `EvalSchemeSwitchingKeyGen`,
`EvalCKKStoFHEWPrecompute`, and generate the keys which are required for the intermediate CKKS computations. After calling `EvalFHEWtoCKKS`,
the user can then apply the desired functions on the CKKS ciphertext. In the example `PolyViaSchemeSwitching`, this intermediate function
involves rotations, multiplications and additions. Finally, `EvalCKKStoFHEW` should be called to switch back to FHEW (where the plaintext
modulus to be used in decryption was used to compute the scale in `EvalCKKStoFHEWPrecompute`).

**Iterated scheme switching: min/argmin and max/argmax**
We also support repeated scheme switching between CKKS and FHEW with intermediate computations in each scheme. One such example is
computing the minimum and argminimum, respectively the maximum and argmaximum, of a vector encrypted initially in a CKKS ciphertext.

The functionality is computed in a binary tree approach. First, the first half is compared to the second half of the vector: the
difference is computed in CKKS, then switched to FHEW where the signs of the difference are computed, and switched back to CKKS.
Second, using multiplication in CKKS, only half of the slots are selected to update the vector for the next iteration (the ones
corresponding to a negative difference for min and the ones corresponding to a positive difference for max), and the process repeats
until reaching a vector of length of one.

We provide two instantiation of the above intuition, `EvalMinSchemeSwitching` which performs more operations in CKKS and is exemplified
in `ArgminViaSchemeSwitching()`, and `EvalMinSchemeSwitchingAlt` which performs more operations in FHEW and is exemplified in
`ArgminViaSchemeSwitchingAlt()`.

For a good precision of the output, we require a large scaling factor and large first modsize in CKKS, as well as large ciphertext
modulus and plaintext modulus in FHEW. Note that because CKKS is an approximate scheme, performing more operations in CKKS can lead
to a decrease in precision.

The user should call `EvalSchemeSwitchingSetup`, then `EvalSchemeSwitchingKeyGen`, specifying whether the argmin/argmax should have a
one-hot encoding or not, as well as if the alternative computation method mentioned above should be used, then `EvalCompareSwitchPrecompute`
specifying if an additional scaling if desired. As mentioned above, the user can manually scale the inputs to [-0.5, 0.5], (such that
the difference of values is between [-1, 1]) in which case the precomputation does not need to have any scaling, and this is
exemplified in `ArgminViaSchemeSwitchingUnit()` and `ArgminViaSchemeSwitchingUnitAlt()`.

Finally, the user should call `EvalMinSchemeSwitching` or `EvalMinSchemeSwitchingAlt` to obtain the minimum value and the argmin, and
respectively, `EvalMaxSchemeSwitching` or `EvalMaxSchemeSwitchingAlt` to obtain the maximum value and the argmax.

**Current limitations**
- Scheme switching is currently supported only for CKKS and FHEW/TFHE.
- Switching from CKKS to FHEW is only supported for the first consecutive slots in the CKKS ciphertext.
- Switching to CKKS the result of an arbitrary function evaluation in FHEW is not yet supported. Only functions with binary outputs or small outputs with respect to the FHEW plaintext space are supported.
- Computing the min/max via scheme switching is only implemented for vectors of size a power of two.
- Large memory consumption for large number of slots (because of the linear transform required in the switching and that the keys are created with the maximum number of levels)
- Only GINX with uniform ternary secrets is currently supported for scheme switching.
