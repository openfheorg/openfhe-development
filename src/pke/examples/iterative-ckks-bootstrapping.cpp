//==================================================================================
// BSD 2-Clause License
//
// Copyright (c) 2014-2022, NJIT, Duality Technologies Inc. and other contributors
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

Example for multiple iterations of CKKS bootstrapping to improve precision. Note that you need to run a
single iteration of bootstrapping first, to measure the precision. Then, you can input the measured
precision as a parameter to EvalBootstrap with multiple iterations. With 2 iterations, you can achieve
double the precision of a single bootstrapping.

* Source: Bae Y., Cheon J., Cho W., Kim J., and Kim T. META-BTS: Bootstrapping Precision
* Beyond the Limit. Cryptology ePrint Archive, Report
* 2022/1167. (https://eprint.iacr.org/2022/1167.pdf)

*/

#include <cmath>
#include <complex>
#include <cstdint>
#include <iostream>
#include <ostream>
#include <random>
#include <vector>

#include "openfhe.h"

using namespace lbcrypto;

void IterativeBootstrapExample();
void IterativeBootstrapStcExample();

int main(int argc, char* argv[]) {
    // We run the example with 8 slots and ring dimension 4096.
    IterativeBootstrapExample();
    IterativeBootstrapStcExample();
}

// CalculateApproximationError() calculates the precision number (or approximation error).
// The higher the precision, the less the error.
// As recomended in footnote 23 of Security Guidelines for Implementing Homomorphic Encryption
// (https://cic.iacr.org/p/1/4/26/pdf), precision bits are evaluated as the negative
// base 2 logarithm of the average L1 norm between results from standard (cleartext) calculation
// and those computed homomorphically.
double CalculateApproximationError(const std::vector<std::complex<double>>& result,
                                   const std::vector<std::complex<double>>& expectedResult) {
    if (result.size() != expectedResult.size())
        OPENFHE_THROW("Cannot compare vectors with different numbers of elements");

    // using the average
    double accError = 0;
    for (size_t i = 0; i < result.size(); ++i)
        accError += std::abs(result[i] - expectedResult[i]);
    return std::abs(std::log2(accError / result.size()));
}

void IterativeBootstrapExample() {
    std::cout << "***CKKS Bootstrapping Variant with ModRaise-first step***\n\n";
    // Step 1: Set CryptoContext
    CCParams<CryptoContextCKKSRNS> parameters;
    SecretKeyDist secretKeyDist = UNIFORM_TERNARY;
    parameters.SetSecretKeyDist(secretKeyDist);
    parameters.SetSecurityLevel(HEStd_NotSet);
    parameters.SetRingDim(1 << 12);

#if NATIVEINT == 128
    // Currently, only FIXEDMANUAL and FIXEDAUTO modes are supported for 128-bit CKKS bootstrapping.
    ScalingTechnique rescaleTech = FIXEDAUTO;
    uint32_t dcrtBits            = 78;
    uint32_t firstMod            = 89;
#else
    // All modes are supported for 64-bit CKKS bootstrapping.
    ScalingTechnique rescaleTech = FLEXIBLEAUTO;
    uint32_t dcrtBits            = 59;
    uint32_t firstMod            = 60;
#endif

    parameters.SetScalingModSize(dcrtBits);
    parameters.SetScalingTechnique(rescaleTech);
    parameters.SetFirstModSize(firstMod);

    // Here, we specify the number of iterations to run bootstrapping. Note that we currently only support 1 or 2 iterations.
    // Two iterations should give us approximately double the precision of one iteration.
    uint32_t numIterations = 2;

    std::vector<uint32_t> levelBudget = {3, 3};
    std::vector<uint32_t> bsgsDim     = {0, 0};

    uint32_t levelsAvailableAfterBootstrap = 10;
    uint32_t depth =
        levelsAvailableAfterBootstrap + FHECKKSRNS::GetBootstrapDepth(levelBudget, secretKeyDist) + (numIterations - 1);
    parameters.SetMultiplicativeDepth(depth);

    // Generate crypto context.
    CryptoContext<DCRTPoly> cryptoContext = GenCryptoContext(parameters);

    // Enable features that you wish to use. Note, we must enable FHE to use bootstrapping.
    cryptoContext->Enable(PKE);
    cryptoContext->Enable(KEYSWITCH);
    cryptoContext->Enable(LEVELEDSHE);
    cryptoContext->Enable(ADVANCEDSHE);
    cryptoContext->Enable(FHE);

    uint32_t ringDim = cryptoContext->GetRingDimension();
    std::cout << "CKKS scheme is using ring dimension " << ringDim << "\n\n";

    // Step 2: Precomputations for bootstrapping
    // We use a sparse packing.
    uint32_t numSlots = 8;
    cryptoContext->EvalBootstrapSetup(levelBudget, bsgsDim, numSlots);

    // Step 3: Key Generation
    auto keyPair = cryptoContext->KeyGen();
    cryptoContext->EvalMultKeyGen(keyPair.secretKey);
    // Generate bootstrapping keys.
    cryptoContext->EvalBootstrapKeyGen(keyPair.secretKey, numSlots);

    // Step 4: Encoding and encryption of inputs
    // Generate random input
    std::vector<double> x;
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_real_distribution<> dis(0.0, 2.0);
    for (uint32_t i = 0; i < numSlots; ++i) {
        x.push_back(dis(gen));
    }

    // Encoding as plaintexts
    // We specify the number of slots as numSlots to achieve a performance improvement.
    // We use the other default values of depth 1, levels 0, and no params.
    // Alternatively, you can also set batch size as a parameter in the CryptoContext as follows:
    // parameters.SetBatchSize(numSlots);
    // Here, we assume all ciphertexts in the cryptoContext will have numSlots slots.
    // We start with a depleted ciphertext that has used up all of its levels.
    Plaintext ptxt = cryptoContext->MakeCKKSPackedPlaintext(x, 1, depth - 1, nullptr, numSlots);
    ptxt->SetLength(numSlots);
    std::cout << "Input: " << ptxt;

    // Encrypt the encoded vectors
    Ciphertext<DCRTPoly> ciph = cryptoContext->Encrypt(keyPair.publicKey, ptxt);

    // Step 5: Measure the precision of a single bootstrapping operation.
    auto ciphertextAfter = cryptoContext->EvalBootstrap(ciph);

    Plaintext result;
    cryptoContext->Decrypt(keyPair.secretKey, ciphertextAfter, &result);
    result->SetLength(numSlots);
    uint32_t precision =
        std::floor(CalculateApproximationError(result->GetCKKSPackedValue(), ptxt->GetCKKSPackedValue()));
    std::cout << "Bootstrapping precision after 1 iteration: " << precision << "\n\n";
    // Set precision equal to empirically measured value after many test runs. One could add a buffer to reduce this value as below.
    precision -= 5;
    std::cout << "Precision input to 2 iteration: " << precision << "\n";

    // Step 6: Run bootstrapping with multiple iterations.
    auto ciphertextTwoIterations = cryptoContext->EvalBootstrap(ciph, numIterations, precision);

    Plaintext resultTwoIterations;
    cryptoContext->Decrypt(keyPair.secretKey, ciphertextTwoIterations, &resultTwoIterations);
    resultTwoIterations->SetLength(numSlots);
    auto actualResult = resultTwoIterations->GetCKKSPackedValue();

    std::cout << "Output after two iterations of bootstrapping: " << actualResult << "\n";
    double precisionMultipleIterations = CalculateApproximationError(actualResult, ptxt->GetCKKSPackedValue());

    // Output the precision of bootstrapping after two iterations. It should be approximately double the original precision.
    std::cout << "Bootstrapping precision after 2 iterations: " << precisionMultipleIterations << "\n";
    std::cout << "Number of levels remaining after 2 bootstrappings: "
              << depth - ciphertextTwoIterations->GetLevel() - (ciphertextTwoIterations->GetNoiseScaleDeg() - 1)
              << "\n\n";
}

void IterativeBootstrapStcExample() {
    std::cout << "***CKKS Bootstrapping Variant with SlotsToCoefficients-first step***\n\n";
    // Step 1: Set CryptoContext
    CCParams<CryptoContextCKKSRNS> parameters;
    SecretKeyDist secretKeyDist = UNIFORM_TERNARY;
    parameters.SetSecretKeyDist(secretKeyDist);
    parameters.SetSecurityLevel(HEStd_NotSet);
    parameters.SetRingDim(1 << 12);

#if NATIVEINT == 128
    // Currently, only FIXEDMANUAL and FIXEDAUTO modes are supported for 128-bit CKKS bootstrapping.
    ScalingTechnique rescaleTech = FIXEDAUTO;
    uint32_t dcrtBits            = 78;
    uint32_t firstMod            = 89;
#else
    // All modes are supported for 64-bit CKKS bootstrapping.
    ScalingTechnique rescaleTech = FLEXIBLEAUTO;
    uint32_t dcrtBits            = 59;
    uint32_t firstMod            = 60;
#endif

    parameters.SetScalingModSize(dcrtBits);
    parameters.SetScalingTechnique(rescaleTech);
    parameters.SetFirstModSize(firstMod);

    // Here, we specify the number of iterations to run bootstrapping. Note that we currently only support 1 or 2 iterations.
    // Two iterations should give us approximately double the precision of one iteration.
    uint32_t numIterations = 2;

    std::vector<uint32_t> levelBudget = {3, 3};
    std::vector<uint32_t> bsgsDim     = {0, 0};

    uint32_t levelsAvailableAfterBootstrap = 10 + levelBudget[1];
    uint32_t depth = levelsAvailableAfterBootstrap + FHECKKSRNS::GetBootstrapDepth(9, levelBudget, secretKeyDist);
    parameters.SetMultiplicativeDepth(depth);

    // Generate crypto context.
    CryptoContext<DCRTPoly> cryptoContext = GenCryptoContext(parameters);

    // Enable features that you wish to use. Note, we must enable FHE to use bootstrapping.
    cryptoContext->Enable(PKE);
    cryptoContext->Enable(KEYSWITCH);
    cryptoContext->Enable(LEVELEDSHE);
    cryptoContext->Enable(ADVANCEDSHE);
    cryptoContext->Enable(FHE);

    uint32_t ringDim = cryptoContext->GetRingDimension();
    std::cout << "CKKS scheme is using ring dimension " << ringDim << "\n\n";

    // Step 2: Precomputations for bootstrapping
    // We use a sparse packing and default correection factor for single iteration
    uint32_t numSlots = 8;
    cryptoContext->EvalBootstrapSetup(levelBudget, bsgsDim, numSlots, 0, true, true);

    // Step 3: Key Generation
    auto keyPair = cryptoContext->KeyGen();
    cryptoContext->EvalMultKeyGen(keyPair.secretKey);
    // Generate bootstrapping keys.
    cryptoContext->EvalBootstrapKeyGen(keyPair.secretKey, numSlots);

    // Step 4: Encoding and encryption of inputs
    // Generate random input
    std::vector<double> x;
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_real_distribution<> dis(0.0, 2.0);
    for (uint32_t i = 0; i < numSlots; ++i) {
        x.push_back(dis(gen));
    }

    // Encoding as plaintexts
    // We specify the number of slots as numSlots to achieve a performance improvement.
    // We use the other default values of depth 1, levels 0, and no params.
    // Alternatively, you can also set batch size as a parameter in the CryptoContext as follows:
    // parameters.SetBatchSize(numSlots);
    // Here, we assume all ciphertexts in the cryptoContext will have numSlots slots.
    // We start with a depleted ciphertext that has used up all of its levels.
    Plaintext ptxt = cryptoContext->MakeCKKSPackedPlaintext(x, 1, depth - 1 - levelBudget[1], nullptr, numSlots);
    ptxt->SetLength(numSlots);
    std::cout << "Input: " << ptxt;

    std::cout << "Correction factor used: " << cryptoContext->GetCKKSBootCorrectionFactor() << "\n";

    // Encrypt the encoded vectors
    Ciphertext<DCRTPoly> ciph = cryptoContext->Encrypt(keyPair.publicKey, ptxt);

    // Step 5: Measure the precision of a single bootstrapping operation.
    auto ciphertextAfter = cryptoContext->EvalBootstrap(ciph);

    Plaintext result;
    cryptoContext->Decrypt(keyPair.secretKey, ciphertextAfter, &result);
    result->SetLength(numSlots);
    uint32_t precision =
        std::floor(CalculateApproximationError(result->GetCKKSPackedValue(), ptxt->GetCKKSPackedValue()));
    std::cout << "Bootstrapping precision after 1 iteration: " << precision << "\n\n";

    // Set precision equal to empirically measured value after many test runs. One could add a buffer to reduce this value as below.
    precision -= 5;
    std::cout << "Precision input to 2nd iteration: " << precision << "\n";

    // Step 6: Run bootstrapping with multiple iterations.
    auto ciphertextTwoIterations = cryptoContext->EvalBootstrap(ciph, numIterations, precision);

    Plaintext resultTwoIterations;
    cryptoContext->Decrypt(keyPair.secretKey, ciphertextTwoIterations, &resultTwoIterations);
    resultTwoIterations->SetLength(numSlots);
    auto actualResult = resultTwoIterations->GetCKKSPackedValue();

    std::cout << "Output after two iterations of bootstrapping: " << actualResult << "\n";
    double precisionMultipleIterations = CalculateApproximationError(actualResult, ptxt->GetCKKSPackedValue());

    // Output the precision of bootstrapping after two iterations. It should be approximately double the original precision.
    std::cout << "Bootstrapping precision after 2 iterations: " << precisionMultipleIterations << "\n";
    std::cout << "Number of levels remaining after 2 bootstrappings: "
              << depth - ciphertextTwoIterations->GetLevel() - (ciphertextTwoIterations->GetNoiseScaleDeg() - 1)
              << "\n\n";

    //---------------------------------------------------------------------------------------------------------------------
    // When using EvalBootstrap for 2 iterations with STC first, it may be beneficial to scale down the default correction
    // factor to achieve a higher final precision. This behavior is specifically pronounced for sparse packing. As the
    // number of slots increases, the difference between the default correction factor and the best empirical correction
    // factor decreases. For full packing at full security for CKKS bootstrapping, this variant of CKKS bootstrapping
    // has better precision than the ModRaise-first variant without any change to the default correction factor.

    cryptoContext->SetCKKSBootCorrectionFactor(cryptoContext->GetCKKSBootCorrectionFactor() - 5);
    std::cout << "Correction factor used: " << cryptoContext->GetCKKSBootCorrectionFactor() << "\n";

    ciphertextAfter = cryptoContext->EvalBootstrap(ciph);
    cryptoContext->Decrypt(keyPair.secretKey, ciphertextAfter, &result);
    result->SetLength(numSlots);
    precision = std::floor(CalculateApproximationError(result->GetCKKSPackedValue(), ptxt->GetCKKSPackedValue()));
    std::cout << "Bootstrapping precision after 1 iteration: " << precision << "\n\n";

    // Set precision equal to empirically measured value after many test runs. One could add a buffer to reduce this value as below.
    precision -= 5;
    std::cout << "Precision input to 2nd iteration: " << precision << "\n";

    ciphertextTwoIterations = cryptoContext->EvalBootstrap(ciph, numIterations, precision);
    cryptoContext->Decrypt(keyPair.secretKey, ciphertextTwoIterations, &resultTwoIterations);
    actualResult = resultTwoIterations->GetCKKSPackedValue();

    std::cout << "Output after two iterations of bootstrapping: " << actualResult << "\n";
    precisionMultipleIterations = CalculateApproximationError(actualResult, ptxt->GetCKKSPackedValue());

    // Output the precision of bootstrapping after two iterations. It should be approximately double the original precision.
    std::cout << "Bootstrapping precision after 2 iterations: " << precisionMultipleIterations << "\n";
    std::cout << "Number of levels remaining after 2 bootstrappings: "
              << depth - ciphertextTwoIterations->GetLevel() - (ciphertextTwoIterations->GetNoiseScaleDeg() - 1)
              << "\n\n";
}
