//==================================================================================
// BSD 2-Clause License
//
// Copyright (c) 2025, Duality Technologies Inc. and other contributors
//
// All rights reserved.
//
// Author TPOC: contact@openfhe.org
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
//    list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//==================================================================================

/*
  Examples for functional bootstrapping for RLWE ciphertexts using CKKS.
 */

#include "math/hermite.h"
#include "openfhe.h"
#include "schemelet/rlwe-mp.h"

#include <functional>

using namespace lbcrypto;

const BigInteger QBFVINIT(BigInteger(1) << 60);
const BigInteger QBFVINITLARGE(BigInteger(1) << 80);

void ArbitraryLUT(BigInteger QBFVInit, BigInteger PInput, BigInteger POutput, BigInteger Q, BigInteger Bigq,
                  uint64_t scaleTHI, size_t order, uint32_t numSlots, uint32_t ringDim,
                  std::function<int64_t(int64_t)> func);
void MultiValueBootstrapping(BigInteger QBFVInit, BigInteger PInput, BigInteger POutput, BigInteger Q, BigInteger Bigq,
                             uint64_t scaleTHI, size_t order, uint32_t numSlots, uint32_t ringDim,
                             uint32_t levelComputation);
void MultiPrecisionSign(BigInteger QBFVInit, BigInteger PInput, BigInteger PDigit, BigInteger Q, BigInteger Bigq,
                        uint64_t scaleTHI, uint64_t scaleStepTHI, size_t order, uint32_t numSlots, uint32_t ringDim);

int main() {
    std::cerr << "\n*1.* Compute the function (x % PInput - POutput / 2) % POutput." << std::endl << std::endl;
    // Boolean LUT
    std::cerr << "=====Boolean LUT order 1 sparsely packed=====" << std::endl << std::endl;
    ArbitraryLUT(QBFVINIT, BigInteger(2), BigInteger(2), (BigInteger(1) << 33), (BigInteger(1) << 33), 1, 1, 8, 4096,
                 [](int64_t x) { return (x % 2 - 2 / 2) % 2; });
    std::cerr << "=====Boolean LUT order 2 sparsely packed=====" << std::endl << std::endl;
    ArbitraryLUT(QBFVINIT, BigInteger(2), BigInteger(2), (BigInteger(1) << 33), (BigInteger(1) << 33), 1, 2, 8, 4096,
                 [](int64_t x) { return (x % 2 - 2 / 2) % 2; });
    std::cerr << "=====Boolean LUT order 1 fully packed=====" << std::endl << std::endl;
    ArbitraryLUT(QBFVINIT, BigInteger(2), BigInteger(2), (BigInteger(1) << 33), (BigInteger(1) << 33), 1, 1, 1024, 4096,
                 [](int64_t x) { return (x % 2 - 2 / 2) % 2; });
    // LUT with 8-bit input and 4-bit output
    std::cerr << "=====8-to-4 bit LUT order 1 sparsely packed=====" << std::endl << std::endl;
    ArbitraryLUT(QBFVINIT, BigInteger(256), BigInteger(16), (BigInteger(1) << 47), (BigInteger(1) << 47), 32, 1, 8,
                 4096, [](int64_t x) { return (x % 256 - 16 / 2) % 16; });

    std::cerr << "\n\n*2.* Compute multiple functions over the same ciphertext." << std::endl << std::endl;
    // Two LUTs with 8-bit input and 8-bit output and intermediate leveled computations
    std::cerr << "=====Multivalue bootstrapping for two 8-to-8 bit LUTs order 1 fully packed=====" << std::endl
              << std::endl;
    MultiValueBootstrapping(QBFVINIT, BigInteger(256), BigInteger(256), (BigInteger(1) << 47), (BigInteger(1) << 47),
                            32, 1, 256, 2048, 1);

    std::cerr << "\n\n*3.* Homomorphically evaluate the sign." << std::endl << std::endl;
    // Compute the sign of a 12-bit input using 1-bit and 4-bit digits
    // The following needs to hold true: log2(PInput) - log2(PDigit) = log2(Q) - log2(Bigq)
    std::cerr << "=====Sign evaluation of a 12-bit input using 1-bit digits order 1 sparsely packed=====" << std::endl
              << std::endl;
    MultiPrecisionSign(QBFVINIT, BigInteger(4096), BigInteger(2), (BigInteger(1) << 46), (BigInteger(1) << 35), 1, 1, 1,
                       32, 2048);
    std::cerr << "=====Sign evaluation of a 12-bit input using 4-bit digits order 1 fully packed=====" << std::endl
              << std::endl;
    MultiPrecisionSign(QBFVINIT, BigInteger(4096), BigInteger(16), (BigInteger(1) << 48), (BigInteger(1) << 40), 32, 8,
                       1, 64, 2048);
    std::cerr << "=====Sign evaluation of a 32-bit input using 8-bit digits order 1 fully packed=====" << std::endl
              << std::endl;
    MultiPrecisionSign(QBFVINITLARGE, BigInteger(1) << 32, BigInteger(256), BigInteger(1) << 71, BigInteger(1) << 47,
                       256, 32, 1, 64, 2048);

    return 0;
}

void ArbitraryLUT(BigInteger QBFVInit, BigInteger PInput, BigInteger POutput, BigInteger Q, BigInteger Bigq,
                  uint64_t scaleTHI, size_t order, uint32_t numSlots, uint32_t ringDim,
                  std::function<int64_t(int64_t)> func) {
    /* 1. Figure out whether sparse packing or full packing should be used.
     * numSlots represents the number of values to be encrypted in BFV.
     * If this number is the same as the ring dimension, then the CKKS slots is half.
     */
    bool flagSP       = (numSlots <= ringDim / 2);  // sparse packing
    auto numSlotsCKKS = flagSP ? numSlots : numSlots / 2;

    /* 2. Input */
    std::vector<int64_t> x = {
        (PInput.ConvertToInt<int64_t>() / 2), (PInput.ConvertToInt<int64_t>() / 2) + 1, 0, 3, 16, 33, 64,
        (PInput.ConvertToInt<int64_t>() - 1)};
    std::cerr << "First 8 elements of the input (repeated) up to size " << numSlots << ":" << std::endl;
    std::cerr << x << std::endl;
    if (x.size() < numSlots)
        x = Fill<int64_t>(x, numSlots);

    /* 3. The case of Boolean LUTs using the first order Trigonometric Hermite Interpolation
     * supports an optimized implementation.
     * In particular, it supports real coefficients as opposed to complex coefficients.
     * Therefore, we separate between this case and the general case.
     * There is no need to scale the coefficients in the Boolean case.
     * However, in the general case, it is recommended to scale down the Hermite
     * coefficients in order to bring their magnitude close to one. This scaling
     * is reverted later.
     */
    std::vector<int64_t> coeffint;
    std::vector<std::complex<double>> coeffcomp;
    bool binaryLUT = (PInput.ConvertToInt() == 2) && (order == 1);

    if (binaryLUT) {
        coeffint = {
            func(1),
            func(0) -
                func(1)};  // those are coefficients for [1, cos^2(pi x)], not [1, cos(2pi x)] as in the general case.
    }
    else {
        coeffcomp = GetHermiteTrigCoefficients(func, PInput.ConvertToInt(), order, scaleTHI);  // divided by 2
    }

    /* 4. Set up the cryptoparameters.
     * The scaling factor in CKKS should have the same bit length as the RLWE ciphertext modulus.
     * The number of levels to be reserved before and after the LUT evaluation should be specified.
    * The secret key distribution for CKKS should either be SPARSE_TERNARY or SPARSE_ENCAPSULATED.
    * The SPARSE_TERNARY distribution is for testing purposes as it gives a larger probability of
    * failure but less noise, while the SPARSE_ENCAPSULATED distribution gives a smaller probability
    * of failure at a cost of slightly more noise.
    */
    uint32_t dcrtBits                       = Bigq.GetMSB() - 1;
    uint32_t firstMod                       = Bigq.GetMSB() - 1;
    uint32_t levelsAvailableAfterBootstrap  = 0;
    uint32_t levelsAvailableBeforeBootstrap = 0;
    uint32_t dnum                           = 3;
    SecretKeyDist secretKeyDist             = SPARSE_ENCAPSULATED;
    std::vector<uint32_t> lvlb              = {3, 3};

    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetSecretKeyDist(secretKeyDist);
    parameters.SetSecurityLevel(HEStd_NotSet);
    parameters.SetScalingModSize(dcrtBits);
    parameters.SetScalingTechnique(FIXEDMANUAL);
    parameters.SetFirstModSize(firstMod);
    parameters.SetNumLargeDigits(dnum);
    parameters.SetBatchSize(numSlotsCKKS);
    parameters.SetRingDim(ringDim);
    uint32_t depth = levelsAvailableAfterBootstrap;

    if (binaryLUT)
        depth += FHECKKSRNS::GetFBTDepth(lvlb, coeffint, PInput, order, secretKeyDist);
    else
        depth += FHECKKSRNS::GetFBTDepth(lvlb, coeffcomp, PInput, order, secretKeyDist);

    parameters.SetMultiplicativeDepth(depth);

    auto cc = GenCryptoContext(parameters);
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE);
    cc->Enable(FHE);

    std::cout << "CKKS scheme is using ring dimension " << cc->GetRingDimension() << " and a multiplicative depth of "
              << depth << std::endl
              << std::endl;

    /* 5. Compute various moduli and scaling sizes, used for scheme conversions.
     * Then generate the setup parameters and necessary keys.
     */
    auto keyPair = cc->KeyGen();

    if (binaryLUT)
        cc->EvalFBTSetup(coeffint, numSlotsCKKS, PInput, POutput, Bigq, keyPair.publicKey, {0, 0}, lvlb,
                         levelsAvailableAfterBootstrap, 0, order);
    else
        cc->EvalFBTSetup(coeffcomp, numSlotsCKKS, PInput, POutput, Bigq, keyPair.publicKey, {0, 0}, lvlb,
                         levelsAvailableAfterBootstrap, 0, order);

    cc->EvalBootstrapKeyGen(keyPair.secretKey, numSlotsCKKS);
    cc->EvalMultKeyGen(keyPair.secretKey);

    /* 6. Perform encryption in the RLWE scheme, using a larger initial ciphertext modulus.
     * Switching the modulus to a smaller ciphertext modulus helps offset the encryption error.
     */
    auto ep = SchemeletRLWEMP::GetElementParams(keyPair.secretKey, depth - (levelsAvailableBeforeBootstrap > 0));

    auto ctxtBFV = SchemeletRLWEMP::EncryptCoeff(x, QBFVInit, PInput, keyPair.secretKey, ep);

    SchemeletRLWEMP::ModSwitch(ctxtBFV, Q, QBFVInit);

    /* 7. Convert from the RLWE ciphertext to a CKKS ciphertext (both use the same secret key).
    */
    auto ctxt = SchemeletRLWEMP::ConvertRLWEToCKKS(*cc, ctxtBFV, keyPair.publicKey, Bigq, numSlotsCKKS,
                                                   depth - (levelsAvailableBeforeBootstrap > 0));

    /* 8. Apply the LUT over the ciphertext.
    */
    Ciphertext<DCRTPoly> ctxtAfterFBT;
    if (binaryLUT)
        ctxtAfterFBT = cc->EvalFBT(ctxt, coeffint, PInput.GetMSB() - 1, ep->GetModulus(), scaleTHI, 0, order);
    else
        ctxtAfterFBT = cc->EvalFBT(ctxt, coeffcomp, PInput.GetMSB() - 1, ep->GetModulus(), scaleTHI, 0, order);

    /* 9. Convert the result back to RLWE.
    */
    auto polys = SchemeletRLWEMP::ConvertCKKSToRLWE(ctxtAfterFBT, Q);

    auto computed = SchemeletRLWEMP::DecryptCoeff(polys, Q, POutput, keyPair.secretKey, ep, numSlotsCKKS, numSlots);

    std::cerr << "First 8 elements of the obtained output % POutput: [";
    std::copy_n(computed.begin(), 8, std::ostream_iterator<int64_t>(std::cerr, " "));
    std::cerr << "]" << std::endl;

    auto exact(x);
    std::transform(x.begin(), x.end(), exact.begin(), [&](const int64_t& elem) {
        return (func(elem) > POutput.ConvertToDouble() / 2.) ? func(elem) - POutput.ConvertToInt() : func(elem);
    });

    std::transform(exact.begin(), exact.end(), computed.begin(), exact.begin(), std::minus<int64_t>());
    std::transform(exact.begin(), exact.end(), exact.begin(),
                   [&](const int64_t& elem) { return (std::abs(elem)) % (POutput.ConvertToInt()); });
    auto max_error_it = std::max_element(exact.begin(), exact.end());
    std::cerr << "Max absolute error obtained: " << *max_error_it << std::endl << std::endl;
}

void MultiValueBootstrapping(BigInteger QBFVInit, BigInteger PInput, BigInteger POutput, BigInteger Q, BigInteger Bigq,
                             uint64_t scaleTHI, size_t order, uint32_t numSlots, uint32_t ringDim,
                             uint32_t levelsComputation) {
    /* 1. Figure out whether sparse packing or full packing should be used.
     * numSlots represents the number of values to be encrypted in BFV.
     * If this number is the same as the ring dimension, then the CKKS slots is half.
     */
    bool flagSP       = (numSlots <= ringDim / 2);  // sparse packing
    auto numSlotsCKKS = flagSP ? numSlots : numSlots / 2;

    /* 2. Distinct functions to compute over the same input. */
    auto a     = PInput.ConvertToInt<int64_t>();
    auto b     = POutput.ConvertToInt<int64_t>();
    auto func1 = [a, b](int64_t x) -> int64_t {
        return (x % a - a / 2) % b;
    };

    auto func2 = [a, b](int64_t x) -> int64_t {
        return (x % a) % b;
    };

    /* 3. Input */
    std::vector<int64_t> x = {
        (PInput.ConvertToInt<int64_t>() / 2), (PInput.ConvertToInt<int64_t>() / 2) + 1, 0, 3, 16, 33, 64,
        (PInput.ConvertToInt<int64_t>() - 1)};
    std::cerr << "First 8 elements of the input (repeated) up to size " << numSlots << ":" << std::endl;
    std::cerr << x << std::endl;
    if (x.size() < numSlots)
        x = Fill<int64_t>(x, numSlots);

    /* 4. The case of Boolean LUTs using the first order Trigonometric Hermite Interpolation
     * supports an optimized implementation.
     * In particular, it supports real coefficients as opposed to complex coefficients.
     * Therefore, we separate between this case and the general case.
     * There is no need to scale the coefficients in the Boolean case.
     * However, in the general case, it is recommended to scale down the Hermite
     * coefficients in order to bring their magnitude close to one. This scaling
     * is reverted later.
     */
    std::vector<int64_t> coeffint1;
    std::vector<int64_t> coeffint2;
    std::vector<std::complex<double>> coeffcomp1;
    std::vector<std::complex<double>> coeffcomp2;
    bool binaryLUT = (PInput.ConvertToInt() == 2) && (order == 1);

    if (binaryLUT) {
        coeffint1 = {func1(1), func1(0) - func1(1)};
        coeffint2 = {func2(1), func2(0) - func2(1)};
    }
    else {
        coeffcomp1 = GetHermiteTrigCoefficients(func1, PInput.ConvertToInt(), order, scaleTHI);
        coeffcomp2 = GetHermiteTrigCoefficients(func2, PInput.ConvertToInt(), order, scaleTHI);
    }

    /* 5. Set up the cryptoparameters.
     * The scaling factor in CKKS should have the same bit length as the RLWE ciphertext modulus.
     * The number of levels to be reserved before and after the LUT evaluation should be specified.
     * The secret key distribution for CKKS should either be SPARSE_TERNARY or SPARSE_ENCAPSULATED.
     * The SPARSE_TERNARY distribution is for testing purposes as it gives a larger probability of
     * failure but less noise, while the SPARSE_ENCAPSULATED distribution gives a smaller probability
     * of failure at a cost of slightly more noise.
     */
    uint32_t dcrtBits                       = Bigq.GetMSB() - 1;
    uint32_t firstMod                       = Bigq.GetMSB() - 1;
    uint32_t levelsAvailableAfterBootstrap  = 0;
    uint32_t levelsAvailableBeforeBootstrap = 0;
    uint32_t dnum                           = 3;
    SecretKeyDist secretKeyDist             = SPARSE_TERNARY;
    std::vector<uint32_t> lvlb              = {3, 3};

    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetSecretKeyDist(secretKeyDist);
    parameters.SetSecurityLevel(HEStd_NotSet);
    parameters.SetScalingModSize(dcrtBits);
    parameters.SetScalingTechnique(FIXEDMANUAL);
    parameters.SetFirstModSize(firstMod);
    parameters.SetNumLargeDigits(dnum);
    parameters.SetBatchSize(numSlotsCKKS);
    parameters.SetRingDim(ringDim);
    uint32_t depth = levelsAvailableAfterBootstrap + levelsComputation;

    if (binaryLUT)
        depth += FHECKKSRNS::GetFBTDepth(lvlb, coeffint1, PInput, order, secretKeyDist);
    else
        depth += FHECKKSRNS::GetFBTDepth(lvlb, coeffcomp1, PInput, order, secretKeyDist);

    parameters.SetMultiplicativeDepth(depth);

    auto cc = GenCryptoContext(parameters);
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE);
    cc->Enable(FHE);

    std::cout << "CKKS scheme is using ring dimension " << cc->GetRingDimension() << " and a multiplicative depth of "
              << depth << std::endl
              << std::endl;

    /* 6. Compute various moduli and scaling sizes, used for scheme conversions.
     * Then generate the setup parameters and necessary keys.
     */
    auto keyPair = cc->KeyGen();

    if (binaryLUT)
        cc->EvalFBTSetup(coeffint1, numSlotsCKKS, PInput, POutput, Bigq, keyPair.publicKey, {0, 0}, lvlb,
                         levelsAvailableAfterBootstrap, levelsComputation, order);
    else
        cc->EvalFBTSetup(coeffcomp1, numSlotsCKKS, PInput, POutput, Bigq, keyPair.publicKey, {0, 0}, lvlb,
                         levelsAvailableAfterBootstrap, levelsComputation, order);

    cc->EvalBootstrapKeyGen(keyPair.secretKey, numSlotsCKKS);
    cc->EvalMultKeyGen(keyPair.secretKey);
    cc->EvalAtIndexKeyGen(keyPair.secretKey, std::vector<int32_t>({-2}));

    auto mask_real = Fill<double>({1, 1, 1, 1, 0, 0, 0, 0}, numSlots);

    // Note that the corresponding plaintext mask for full packing can be just real, as real times complex multiplies both real and imaginary parts
    Plaintext ptxt_mask = cc->MakeCKKSPackedPlaintext(
        Fill<double>({1, 1, 1, 1, 0, 0, 0, 0}, numSlotsCKKS), 1,
        depth - lvlb[1] - levelsAvailableAfterBootstrap - levelsComputation, nullptr, numSlotsCKKS);

    /* 7. When leveled computations (multiplications, rotations) are desired to be performed while in
     * slot-packed CKKS (before returning to RLWE coefficient packing), and the FFT method is used
     * for the homomorphic encoding and decoding during functional bootstrapping, the inputs in RLWE
     * should be encoded in a bit reversed order. This bit reverse order will be cancelled during
     * the homomorphic encoding, therefore the slots in CKKS will be in natural order.
     * Both the RLWE encryption and RLWE decryption should specify this flag.
     */
    bool flagBR = (lvlb[0] != 1 || lvlb[1] != 1);

    /* 8. Perform encryption in the RLWE scheme, using a larger initial ciphertext modulus.
     * Switching the modulus to a smaller ciphertext modulus helps offset the encryption error.
     */
    auto ep = SchemeletRLWEMP::GetElementParams(keyPair.secretKey, depth - (levelsAvailableBeforeBootstrap > 0));

    auto ctxtBFV = SchemeletRLWEMP::EncryptCoeff(x, QBFVInit, PInput, keyPair.secretKey, ep, flagBR);

    SchemeletRLWEMP::ModSwitch(ctxtBFV, Q, QBFVInit);

    /* 9. Convert from the RLWE ciphertext to a CKKS ciphertext (both use the same secret key).
    */
    auto ctxt = SchemeletRLWEMP::ConvertRLWEToCKKS(*cc, ctxtBFV, keyPair.publicKey, Bigq, numSlotsCKKS,
                                                   depth - (levelsAvailableBeforeBootstrap > 0));

    /* 10. Apply the LUTs over the ciphertext.
     * First, compute the complex exponential and its powers to reuse.
     * Second, apply multiple LUTs over these powers.
    */
    std::vector<Ciphertext<DCRTPoly>> complexExp;
    Ciphertext<DCRTPoly> ctxtAfterFBT1, ctxtAfterFBT2;

    auto exact(x);
    std::transform(x.begin(), x.end(), exact.begin(), [&](const int64_t& elem) {
        return (func1(elem) > POutput.ConvertToDouble() / 2.) ? func1(elem) - POutput.ConvertToInt() : func1(elem);
    });

    auto exact2(x);
    std::transform(x.begin(), x.end(), exact2.begin(), [&](const int64_t& elem) {
        return (func2(elem) > POutput.ConvertToDouble() / 2.) ? func2(elem) - POutput.ConvertToInt() : func2(elem);
    });

    if (binaryLUT) {
        auto complexExpPowers = cc->EvalMVBPrecompute(ctxt, coeffint1, PInput.GetMSB() - 1, ep->GetModulus(), order);

        ctxtAfterFBT1 =
            cc->EvalMVB(complexExpPowers, coeffint1, PInput.GetMSB() - 1, scaleTHI, levelsComputation, order);

        ctxtAfterFBT2 = cc->EvalMVBNoDecoding(complexExpPowers, coeffint2, PInput.GetMSB() - 1, order);

        // Apply a rotation
        ctxtAfterFBT2 = cc->EvalRotate(ctxtAfterFBT2, -2);
        exact2        = flagSP ? Rotate(exact2, -2) : RotateTwoHalves(exact2, -2);

        // Apply a multiplicative mask
        ctxtAfterFBT2 = cc->EvalMult(ctxtAfterFBT2, ptxt_mask);
        cc->ModReduceInPlace(ctxtAfterFBT2);

        std::transform(exact2.begin(), exact2.end(), mask_real.begin(), exact2.begin(), std::multiplies<double>());

        // Back to coefficient encoding
        ctxtAfterFBT2 = cc->EvalHomDecoding(ctxtAfterFBT2, scaleTHI, levelsComputation - 1);
    }
    else {
        auto complexExpPowers = cc->EvalMVBPrecompute(ctxt, coeffcomp1, PInput.GetMSB() - 1, ep->GetModulus(), order);

        ctxtAfterFBT1 =
            cc->EvalMVB(complexExpPowers, coeffcomp1, PInput.GetMSB() - 1, scaleTHI, levelsComputation, order);

        ctxtAfterFBT2 = cc->EvalMVBNoDecoding(complexExpPowers, coeffcomp2, PInput.GetMSB() - 1, order);

        // Apply a rotation
        ctxtAfterFBT2 = cc->EvalRotate(ctxtAfterFBT2, -2);
        exact2        = flagSP ? Rotate(exact2, -2) : RotateTwoHalves(exact2, -2);

        // Apply a multiplicative mask
        ctxtAfterFBT2 = cc->EvalMult(ctxtAfterFBT2, ptxt_mask);
        cc->ModReduceInPlace(ctxtAfterFBT2);

        std::transform(exact2.begin(), exact2.end(), mask_real.begin(), exact2.begin(), std::multiplies<double>());

        // Back to coefficient encoding

        ctxtAfterFBT2 = cc->EvalHomDecoding(ctxtAfterFBT2, scaleTHI, levelsComputation - 1);
    }

    auto polys = SchemeletRLWEMP::ConvertCKKSToRLWE(ctxtAfterFBT1, Q);

    /* 11. Convert the results back to RLWE.
    */
    auto computed =
        SchemeletRLWEMP::DecryptCoeff(polys, Q, POutput, keyPair.secretKey, ep, numSlotsCKKS, numSlots, flagBR);

    std::cerr << "First 8 elements of the obtained output = (input % PInput - POutput / 2) % POutput: [";
    std::copy_n(computed.begin(), 8, std::ostream_iterator<int64_t>(std::cerr, " "));
    std::cerr << "]" << std::endl;

    std::transform(exact.begin(), exact.end(), computed.begin(), exact.begin(), std::minus<int64_t>());
    std::transform(exact.begin(), exact.end(), exact.begin(),
                   [&](const int64_t& elem) { return (std::abs(elem)) % (POutput.ConvertToInt()); });
    auto max_error_it = std::max_element(exact.begin(), exact.end());
    std::cerr << "Max absolute error obtained in the first LUT: " << *max_error_it << std::endl << std::endl;

    polys = SchemeletRLWEMP::ConvertCKKSToRLWE(ctxtAfterFBT2, Q);

    computed = SchemeletRLWEMP::DecryptCoeff(polys, Q, POutput, keyPair.secretKey, ep, numSlotsCKKS, numSlots, flagBR);

    std::cerr << "First 8 elements of the obtained output = (input % PInput) % POutput, rotated by -2 and masked: [";
    std::copy_n(computed.begin(), 8, std::ostream_iterator<int64_t>(std::cerr, " "));
    std::cerr << "]" << std::endl;

    std::transform(exact2.begin(), exact2.end(), computed.begin(), exact2.begin(), std::minus<int64_t>());
    std::transform(exact2.begin(), exact2.end(), exact2.begin(),
                   [&](const int64_t& elem) { return (std::abs(elem)) % (POutput.ConvertToInt()); });
    max_error_it = std::max_element(exact2.begin(), exact2.end());
    std::cerr << "Max absolute error obtained in the second LUT: " << *max_error_it << std::endl << std::endl;
}

void MultiPrecisionSign(BigInteger QBFVInit, BigInteger PInput, BigInteger PDigit, BigInteger Q, BigInteger Bigq,
                        uint64_t scaleTHI, uint64_t scaleStepTHI, size_t order, uint32_t numSlots, uint32_t ringDim) {
    /* 1. Figure out whether sparse packing or full packing should be used.
     * numSlots represents the number of values to be encrypted in BFV.
     * If this number is the same as the ring dimension, then the CKKS slots is half.
     */
    bool flagSP       = (numSlots <= ringDim / 2);  // sparse packing
    auto numSlotsCKKS = flagSP ? numSlots : numSlots / 2;

    /* 2. Functions necessary for the sign evaluation. */
    auto a = PInput.ConvertToInt<int64_t>();
    auto b = PDigit.ConvertToInt<int64_t>();

    auto funcMod = [b](int64_t x) -> int64_t {
        return (x % b);
    };
    auto funcStep = [a, b](int64_t x) -> int64_t {
        return (x % a) >= (b / 2);
    };

    /* 3. Input. */
    std::vector<int64_t> x = {static_cast<int64_t>(PInput.ConvertToInt() / 2),
                              static_cast<int64_t>(PInput.ConvertToInt() / 2) + 1,
                              0,
                              3,
                              16,
                              33,
                              64,
                              static_cast<int64_t>(PInput.ConvertToInt() - 1)};
    std::cerr << "First 8 elements of the input (repeated) up to size " << numSlots << ":" << std::endl;
    std::cerr << x << std::endl;
    if (x.size() < numSlots)
        x = Fill<int64_t>(x, numSlots);

    auto exact(x);
    std::transform(x.begin(), x.end(), exact.begin(),
                   [&](const int64_t& elem) { return (elem >= PInput.ConvertToDouble() / 2.); });

    /* 4. The case of Boolean LUTs using the first order Trigonometric Hermite Interpolation
     * supports an optimized implementation.
     * In particular, it supports real coefficients as opposed to complex coefficients.
     * Therefore, we separate between this case and the general case.
     * There is no need to scale the coefficients in the Boolean case.
     * However, in the general case, it is recommended to scale down the Hermite
     * coefficients in order to bring their magnitude close to one. This scaling
     * is reverted later.
     */
    std::vector<int64_t> coeffintMod;
    std::vector<std::complex<double>> coeffcompMod;
    std::vector<std::complex<double>> coeffcompStep;
    bool binaryLUT = (PDigit.ConvertToInt() == 2) && (order == 1);

    if (binaryLUT) {
        coeffintMod = {funcMod(1), funcMod(0) - funcMod(1)};
    }
    else {
        coeffcompMod  = GetHermiteTrigCoefficients(funcMod, PDigit.ConvertToInt(), order, scaleTHI);  // divided by 2
        coeffcompStep = GetHermiteTrigCoefficients(funcStep, PDigit.ConvertToInt(), order,
                                                   scaleStepTHI);  // divided by 2
    }

    /* 5. Set up the cryptoparameters.
     * The scaling factor in CKKS should have the same bit length as the RLWE ciphertext modulus corresponding to the digit.
     * The number of levels to be reserved before and after the LUT evaluation should be specified.
     * The secret key distribution for CKKS should either be SPARSE_TERNARY or SPARSE_ENCAPSULATED.
     * The SPARSE_TERNARY distribution is for testing purposes as it gives a larger probability of
     * failure but less noise, while the SPARSE_ENCAPSULATED distribution gives a smaller probability
     * of failure at a cost of slightly more noise.
     */
    uint32_t dcrtBits                       = Bigq.GetMSB() - 1;
    uint32_t firstMod                       = Bigq.GetMSB() - 1;
    uint32_t levelsAvailableAfterBootstrap  = 0;
    uint32_t levelsAvailableBeforeBootstrap = 0;
    uint32_t dnum                           = 3;
    SecretKeyDist secretKeyDist             = SPARSE_ENCAPSULATED;
    std::vector<uint32_t> lvlb              = {3, 3};

    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetSecretKeyDist(secretKeyDist);
    parameters.SetSecurityLevel(HEStd_NotSet);
    parameters.SetScalingModSize(dcrtBits);
    parameters.SetScalingTechnique(FIXEDMANUAL);
    parameters.SetFirstModSize(firstMod);
    parameters.SetNumLargeDigits(dnum);
    parameters.SetBatchSize(numSlotsCKKS);
    parameters.SetRingDim(ringDim);

    uint32_t depth = levelsAvailableAfterBootstrap;

    if (binaryLUT)
        depth += FHECKKSRNS::GetFBTDepth(lvlb, coeffintMod, PDigit, order, secretKeyDist);
    else
        depth += FHECKKSRNS::GetFBTDepth(lvlb, coeffcompMod, PDigit, order, secretKeyDist);

    parameters.SetMultiplicativeDepth(depth);

    auto cc = GenCryptoContext(parameters);
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE);
    cc->Enable(FHE);

    auto keyPair = cc->KeyGen();

    std::cout << "CKKS scheme is using ring dimension " << cc->GetRingDimension() << " and a multiplicative depth of "
              << depth << std::endl
              << std::endl;

    /* 6. Compute various moduli and scaling sizes, used for scheme conversions.
     * Then generate the setup parameters and necessary keys.
     */
    cc->EvalMultKeyGen(keyPair.secretKey);

    if (binaryLUT)
        cc->EvalFBTSetup(coeffintMod, numSlotsCKKS, PDigit, PInput, Bigq, keyPair.publicKey, {0, 0}, lvlb,
                         levelsAvailableAfterBootstrap, 0, order);
    else
        cc->EvalFBTSetup(coeffcompMod, numSlotsCKKS, PDigit, PInput, Bigq, keyPair.publicKey, {0, 0}, lvlb,
                         levelsAvailableAfterBootstrap, 0, order);

    cc->EvalBootstrapKeyGen(keyPair.secretKey, numSlotsCKKS);

    /* 7. Perform encryption in the RLWE scheme, using a larger initial ciphertext modulus.
     * Switching the modulus to a smaller ciphertext modulus helps offset the encryption error.
     */
    auto ep = SchemeletRLWEMP::GetElementParams(keyPair.secretKey, depth - (levelsAvailableBeforeBootstrap > 0));

    auto ctxtBFV = SchemeletRLWEMP::EncryptCoeff(x, QBFVInit, PInput, keyPair.secretKey, ep);

    SchemeletRLWEMP::ModSwitch(ctxtBFV, Q, QBFVInit);
    uint32_t QBFVBits = Q.GetMSB() - 1;

    /* 8. Set up the sign loop parameters. */
    std::vector<int64_t> coeffint;
    std::vector<std::complex<double>> coeffcomp;
    if (binaryLUT)
        coeffint = coeffintMod;
    else
        coeffcomp = coeffcompMod;

    const bool checkeq2       = PDigit.ConvertToInt() == 2;
    const bool checkgt2       = PDigit.ConvertToInt() > 2;
    const uint32_t pDigitBits = PDigit.GetMSB() - 1;

    BigInteger QNew;
    BigInteger pOrig = PInput;

    bool step                = false;
    bool go                  = QBFVBits > dcrtBits;
    size_t levelsToDrop      = 0;
    uint32_t postScalingBits = 0;

    /* 9. Start the sign loop. For arbitrary digit size, pNew > 2, the last iteration needs
     * to evaluate step pNew not mod pNew.
     * Currently this only works when log(pNew) divides log(p).
    */
    while (go) {
        auto encryptedDigit = ctxtBFV;

        /* 9.1. Apply mod Bigq to extract the digit and convert it from RLWE to CKKS. */
        encryptedDigit[0].SwitchModulus(Bigq, 1, 0, 0);
        encryptedDigit[1].SwitchModulus(Bigq, 1, 0, 0);

        auto ctxt = SchemeletRLWEMP::ConvertRLWEToCKKS(*cc, encryptedDigit, keyPair.publicKey, Bigq, numSlotsCKKS,
                                                       depth - (levelsAvailableBeforeBootstrap > 0));

        /* 9.2 Bootstrap the digit.*/
        Ciphertext<DCRTPoly> ctxtAfterFBT;
        if (binaryLUT)
            ctxtAfterFBT = cc->EvalFBT(ctxt, coeffint, pDigitBits, ep->GetModulus(), scaleTHI * (1 << postScalingBits),
                                       levelsToDrop, order);
        else
            ctxtAfterFBT = cc->EvalFBT(ctxt, coeffcomp, pDigitBits, ep->GetModulus(), scaleTHI * (1 << postScalingBits),
                                       levelsToDrop, order);

        /* 9.3 Convert the result back to RLWE and update the
         * plaintext and ciphertext modulus of the ciphertext for the next iteration.
         */
        auto polys = SchemeletRLWEMP::ConvertCKKSToRLWE(ctxtAfterFBT, Q);

        if (!step) {
            /* 9.4 If not in the last iteration, subtract the digit from the ciphertext. */
            ctxtBFV[0] = ctxtBFV[0] - polys[0];
            ctxtBFV[1] = ctxtBFV[1] - polys[1];

            /* 9.5 Do modulus switching from Q to QNew for the RLWE ciphertext. */
            QNew       = Q >> pDigitBits;
            ctxtBFV[0] = ctxtBFV[0].MultiplyAndRound(QNew, Q);
            ctxtBFV[0].SwitchModulus(QNew, 1, 0, 0);
            ctxtBFV[1] = ctxtBFV[1].MultiplyAndRound(QNew, Q);
            ctxtBFV[1].SwitchModulus(QNew, 1, 0, 0);
            Q >>= pDigitBits;
            PInput >>= pDigitBits;
            QBFVBits -= pDigitBits;
            postScalingBits += pDigitBits;
        }
        else {
            /* 9.6 If in the last iteration, return the digit. */
            ctxtBFV[0] = std::move(polys[0]);
            ctxtBFV[1] = std::move(polys[1]);
        }

        /* 9.7 If in the last iteration, decrypt and assess correctness. */
        go = QBFVBits > dcrtBits;
        if (step || (checkeq2 && !go)) {
            auto computed =
                SchemeletRLWEMP::DecryptCoeff(ctxtBFV, Q, PInput, keyPair.secretKey, ep, numSlotsCKKS, numSlots);

            std::cerr << "First 8 elements of the obtained sign: [";
            std::copy_n(computed.begin(), 8, std::ostream_iterator<int64_t>(std::cerr, " "));
            std::cerr << "]" << std::endl;

            std::transform(exact.begin(), exact.end(), computed.begin(), exact.begin(), std::minus<int64_t>());
            std::transform(exact.begin(), exact.end(), exact.begin(),
                           [&](const int64_t& elem) { return (std::abs(elem)) % (pOrig.ConvertToInt()); });
            auto max_error_it = std::max_element(exact.begin(), exact.end());
            std::cerr << "\nMax absolute error obtained: " << *max_error_it << std::endl << std::endl;
        }

        /* 9.8 Determine whether it is the last iteration and if not, update the parameters for the next iteration. */
        if (checkgt2 && !go && !step) {
            if (!binaryLUT)
                coeffcomp = coeffcompStep;
            scaleTHI = scaleStepTHI;
            step     = true;
            go       = true;
            if (coeffcompMod.size() > 4 && GetMultiplicativeDepthByCoeffVector(coeffcompMod, true) >
                                               GetMultiplicativeDepthByCoeffVector(coeffcompStep, true)) {
                levelsToDrop = GetMultiplicativeDepthByCoeffVector(coeffcompMod, true) -
                               GetMultiplicativeDepthByCoeffVector(coeffcompStep, true);
            }
        }
    }
}
