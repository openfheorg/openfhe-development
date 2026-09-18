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

Use this script to find the correction factor, which gives the best precision for CKKS bootstrapping.
Specifically, we used this to choose the default correction factor for 64-bit FLEXIBLEAUTO and FLEXIBLEAUTOEXT.

*/

#include <algorithm>
#include <iostream>
#include <ostream>
#include <vector>

#include "openfhe.h"

#define DOUBLEITTR
#define STCBOOT

using namespace lbcrypto;

constexpr ScalingTechnique rescaleTech = FLEXIBLEAUTOEXT;
// constexpr ScalingTechnique rescaleTech = FIXEDMANUAL;

constexpr uint32_t ringdm = 1 << 12;

double MeasureBootstrapPrecision(uint32_t numSlots, uint32_t correctionFactor);
double MeasureStCFirstBootstrapPrecision(uint32_t numSlots, uint32_t correctionFactor);
std::vector<double> MeasureBootstrapDoubleIterPrecision(uint32_t numSlots, uint32_t correctionFactor);
std::vector<double> MeasureStCFirstBootstrapDoubleIterPrecision(uint32_t numSlots, uint32_t correctionFactor);

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

int main(int argc, char* argv[]) {
#if NATIVEINT == 64
    uint32_t numIterations         = 10;
    uint32_t minCorrectionFactor   = 5;
    uint32_t maxCorrectionFactor   = 15;
    std::vector<uint32_t> slotsVec = {1 << 3, 1 << 7, 1 << 9, 1 << 11};
    for (uint32_t numSlots : slotsVec) {
        for (uint32_t correctionFactor = minCorrectionFactor; correctionFactor <= maxCorrectionFactor;
             ++correctionFactor) {
            std::cout << "`=======================================================================" << std::endl;
            std::cout << "Number of slots: " << numSlots << "\n";
            std::cout << "Correction Factor: " << correctionFactor << "\n";

            double precision = 0.0;
    #ifdef DOUBLEITTR
            double precision2 = 0.0;
    #endif
            for (uint32_t i = 0; i < numIterations; ++i) {
    #ifdef DOUBLEITTR
        #ifdef STCBOOT
                auto precisionVec = MeasureStCFirstBootstrapDoubleIterPrecision(numSlots, correctionFactor);
        #else
                auto precisionVec = MeasureBootstrapDoubleIterPrecision(numSlots, correctionFactor);
        #endif
                precision += precisionVec[0];
                precision2 += precisionVec[1];
    #else
        #ifdef STCBOOT
                precision += MeasureStCFirstBootstrapPrecision(numSlots, correctionFactor);
        #else
                precision += MeasureBootstrapPrecision(numSlots, correctionFactor);
        #endif
    #endif
            }
            precision /= numIterations;
            std::cout << "Average initial precision over " << numIterations << " iterations: " << precision << "\n";
    #ifdef DOUBLEITTR
            precision2 /= numIterations;
            std::cout << "Average META-BTS precision over " << numIterations << " iterations: " << precision2 << "\n";
    #endif
            std::cout << "`=======================================================================" << std::endl;
        }
    }
#endif
}

double MeasureBootstrapPrecision(uint32_t numSlots, uint32_t correctionFactor) {
    CCParams<CryptoContextCKKSRNS> parameters;

    SecretKeyDist secretKeyDist = UNIFORM_TERNARY;
    parameters.SetSecretKeyDist(secretKeyDist);

    parameters.SetSecurityLevel(HEStd_NotSet);
    parameters.SetRingDim(ringdm);

    uint32_t dcrtBits = 59;
    uint32_t firstMod = 60;
    parameters.SetScalingModSize(dcrtBits);
    parameters.SetScalingTechnique(rescaleTech);
    parameters.SetFirstModSize(firstMod);

    std::vector<uint32_t> levelBudget      = {3, 3};
    uint32_t approxBootstrapDepth          = 9;
    std::vector<uint32_t> bsgsDim          = {0, 0};
    uint32_t levelsAvailableAfterBootstrap = 10;
    uint32_t depth =
        levelsAvailableAfterBootstrap + FHECKKSRNS::GetBootstrapDepth(approxBootstrapDepth, levelBudget, secretKeyDist);
    parameters.SetMultiplicativeDepth(depth);

    CryptoContext<DCRTPoly> cryptoContext = GenCryptoContext(parameters);

    cryptoContext->Enable(PKE);
    cryptoContext->Enable(KEYSWITCH);
    cryptoContext->Enable(LEVELEDSHE);
    cryptoContext->Enable(ADVANCEDSHE);
    cryptoContext->Enable(FHE);

    cryptoContext->EvalBootstrapSetup(levelBudget, bsgsDim, numSlots, correctionFactor);

    auto keyPair = cryptoContext->KeyGen();
    cryptoContext->EvalMultKeyGen(keyPair.secretKey);
    cryptoContext->EvalBootstrapKeyGen(keyPair.secretKey, numSlots);

    // Generate random input
    std::vector<double> x;
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_real_distribution<> dis(0.0, 1.0);
    for (size_t i = 0; i < numSlots; i++) {
        x.push_back(dis(gen));
    }

    Plaintext ptxt = cryptoContext->MakeCKKSPackedPlaintext(x, 1, depth - 1, nullptr, numSlots);
    ptxt->SetLength(numSlots);

    Ciphertext<DCRTPoly> ciph = cryptoContext->Encrypt(keyPair.publicKey, ptxt);

    auto ciphertextAfter = cryptoContext->EvalBootstrap(ciph);

    Plaintext result;
    cryptoContext->Decrypt(keyPair.secretKey, ciphertextAfter, &result);
    result->SetLength(numSlots);

    double precision = CalculateApproximationError(ptxt->GetCKKSPackedValue(), result->GetCKKSPackedValue());

    cryptoContext->ClearStaticMapsAndVectors();

    return precision;
}

double MeasureStCFirstBootstrapPrecision(uint32_t numSlots, uint32_t correctionFactor) {
    CCParams<CryptoContextCKKSRNS> parameters;

    SecretKeyDist secretKeyDist = UNIFORM_TERNARY;
    parameters.SetSecretKeyDist(secretKeyDist);

    parameters.SetSecurityLevel(HEStd_NotSet);
    parameters.SetRingDim(ringdm);

    uint32_t dcrtBits = 59;
    uint32_t firstMod = 60;
    parameters.SetScalingModSize(dcrtBits);
    parameters.SetScalingTechnique(rescaleTech);
    parameters.SetFirstModSize(firstMod);

    std::vector<uint32_t> levelBudget      = {3, 3};
    std::vector<uint32_t> bsgsDim          = {0, 0};
    uint32_t levelsAvailableAfterBootstrap = 10 + levelBudget[1];
    uint32_t depth = levelsAvailableAfterBootstrap + FHECKKSRNS::GetBootstrapDepth({levelBudget[0], 0}, secretKeyDist);
    parameters.SetMultiplicativeDepth(depth);

    CryptoContext<DCRTPoly> cryptoContext = GenCryptoContext(parameters);

    cryptoContext->Enable(PKE);
    cryptoContext->Enable(KEYSWITCH);
    cryptoContext->Enable(LEVELEDSHE);
    cryptoContext->Enable(ADVANCEDSHE);
    cryptoContext->Enable(FHE);

    cryptoContext->EvalBootstrapSetup(levelBudget, bsgsDim, numSlots, correctionFactor, true, true);

    auto keyPair = cryptoContext->KeyGen();
    cryptoContext->EvalMultKeyGen(keyPair.secretKey);
    cryptoContext->EvalBootstrapKeyGen(keyPair.secretKey, numSlots);

    // Generate random input
    std::vector<double> x;
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_real_distribution<> dis(0.0, 1.0);
    for (size_t i = 0; i < numSlots; i++) {
        x.push_back(dis(gen));
    }

    Plaintext ptxt = cryptoContext->MakeCKKSPackedPlaintext(x, 1, depth - 1 - levelBudget[1], nullptr, numSlots);
    ptxt->SetLength(numSlots);

    Ciphertext<DCRTPoly> ciph = cryptoContext->Encrypt(keyPair.publicKey, ptxt);

    auto ciphertextAfter = cryptoContext->EvalBootstrap(ciph);

    Plaintext result;
    cryptoContext->Decrypt(keyPair.secretKey, ciphertextAfter, &result);
    result->SetLength(numSlots);

    double precision = CalculateApproximationError(ptxt->GetCKKSPackedValue(), result->GetCKKSPackedValue());

    cryptoContext->ClearStaticMapsAndVectors();

    return precision;
}

std::vector<double> MeasureBootstrapDoubleIterPrecision(uint32_t numSlots, uint32_t correctionFactor) {
    CCParams<CryptoContextCKKSRNS> parameters;

    SecretKeyDist secretKeyDist = UNIFORM_TERNARY;
    parameters.SetSecretKeyDist(secretKeyDist);

    parameters.SetSecurityLevel(HEStd_NotSet);
    parameters.SetRingDim(ringdm);

    uint32_t dcrtBits = 59;
    uint32_t firstMod = 60;
    parameters.SetScalingModSize(dcrtBits);
    parameters.SetScalingTechnique(rescaleTech);
    parameters.SetFirstModSize(firstMod);

    std::vector<uint32_t> levelBudget      = {3, 3};
    uint32_t approxBootstrapDepth          = 9;
    std::vector<uint32_t> bsgsDim          = {0, 0};
    uint32_t levelsAvailableAfterBootstrap = 10;
    uint32_t depth =
        levelsAvailableAfterBootstrap + FHECKKSRNS::GetBootstrapDepth(approxBootstrapDepth, levelBudget, secretKeyDist);
    parameters.SetMultiplicativeDepth(depth);

    CryptoContext<DCRTPoly> cryptoContext = GenCryptoContext(parameters);

    cryptoContext->Enable(PKE);
    cryptoContext->Enable(KEYSWITCH);
    cryptoContext->Enable(LEVELEDSHE);
    cryptoContext->Enable(ADVANCEDSHE);
    cryptoContext->Enable(FHE);

    cryptoContext->EvalBootstrapSetup(levelBudget, bsgsDim, numSlots, correctionFactor);

    auto keyPair = cryptoContext->KeyGen();
    cryptoContext->EvalMultKeyGen(keyPair.secretKey);
    cryptoContext->EvalBootstrapKeyGen(keyPair.secretKey, numSlots);

    // Generate random input
    std::vector<double> x;
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_real_distribution<> dis(0.0, 2.0);
    for (size_t i = 0; i < numSlots; i++) {
        x.push_back(dis(gen));
    }

    Plaintext ptxt = cryptoContext->MakeCKKSPackedPlaintext(x, 1, depth - 1, nullptr, numSlots);
    ptxt->SetLength(numSlots);

    Ciphertext<DCRTPoly> ciph = cryptoContext->Encrypt(keyPair.publicKey, ptxt);

    auto ciphertextAfter = cryptoContext->EvalBootstrap(ciph);

    Plaintext result;
    cryptoContext->Decrypt(keyPair.secretKey, ciphertextAfter, &result);
    result->SetLength(numSlots);

    double precision = CalculateApproximationError(ptxt->GetCKKSPackedValue(), result->GetCKKSPackedValue());

    // Give buffer for precision to be lower than one measured result.
    const double precisionBuffer = 5;
    double precisionUsed         = std::floor(std::max(0.0, precision - precisionBuffer));

    // Add numIterations as a parameter.
    uint32_t numIterations       = 2;
    auto ciphertextTwoIterations = cryptoContext->EvalBootstrap(ciph, numIterations, precisionUsed);

    Plaintext resultTwoIterations;
    cryptoContext->Decrypt(keyPair.secretKey, ciphertextTwoIterations, &resultTwoIterations);
    resultTwoIterations->SetLength(numSlots);

    double precisionMultipleIterations =
        CalculateApproximationError(resultTwoIterations->GetCKKSPackedValue(), ptxt->GetCKKSPackedValue());

    cryptoContext->ClearStaticMapsAndVectors();

    return {precision, precisionMultipleIterations};
}

std::vector<double> MeasureStCFirstBootstrapDoubleIterPrecision(uint32_t numSlots, uint32_t correctionFactor) {
    CCParams<CryptoContextCKKSRNS> parameters;

    SecretKeyDist secretKeyDist = UNIFORM_TERNARY;
    parameters.SetSecretKeyDist(secretKeyDist);

    parameters.SetSecurityLevel(HEStd_NotSet);
    parameters.SetRingDim(ringdm);

    uint32_t dcrtBits = 59;
    uint32_t firstMod = 60;
    parameters.SetScalingModSize(dcrtBits);
    parameters.SetScalingTechnique(rescaleTech);
    parameters.SetFirstModSize(firstMod);

    std::vector<uint32_t> levelBudget      = {3, 3};
    uint32_t approxBootstrapDepth          = 9;
    std::vector<uint32_t> bsgsDim          = {0, 0};
    uint32_t levelsAvailableAfterBootstrap = 10;
    uint32_t depth =
        levelsAvailableAfterBootstrap + FHECKKSRNS::GetBootstrapDepth(approxBootstrapDepth, levelBudget, secretKeyDist);
    parameters.SetMultiplicativeDepth(depth);

    CryptoContext<DCRTPoly> cryptoContext = GenCryptoContext(parameters);

    cryptoContext->Enable(PKE);
    cryptoContext->Enable(KEYSWITCH);
    cryptoContext->Enable(LEVELEDSHE);
    cryptoContext->Enable(ADVANCEDSHE);
    cryptoContext->Enable(FHE);

    cryptoContext->EvalBootstrapSetup(levelBudget, bsgsDim, numSlots, correctionFactor, true, true);

    auto keyPair = cryptoContext->KeyGen();
    cryptoContext->EvalMultKeyGen(keyPair.secretKey);
    cryptoContext->EvalBootstrapKeyGen(keyPair.secretKey, numSlots);

    // Generate random input
    std::vector<double> x;
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_real_distribution<> dis(0.0, 2.0);
    for (size_t i = 0; i < numSlots; i++) {
        x.push_back(dis(gen));
    }

    Plaintext ptxt = cryptoContext->MakeCKKSPackedPlaintext(x, 1, depth - 1 - levelBudget[1], nullptr, numSlots);
    ptxt->SetLength(numSlots);

    Ciphertext<DCRTPoly> ciph = cryptoContext->Encrypt(keyPair.publicKey, ptxt);

    auto ciphertextAfter = cryptoContext->EvalBootstrap(ciph);

    Plaintext result;
    cryptoContext->Decrypt(keyPair.secretKey, ciphertextAfter, &result);
    result->SetLength(numSlots);

    double precision = CalculateApproximationError(ptxt->GetCKKSPackedValue(), result->GetCKKSPackedValue());

    // Give buffer for precision to be lower than one measured result.
    const double precisionBuffer = 5;
    double precisionUsed         = std::floor(std::max(0.0, precision - precisionBuffer));

    // Add numIterations as a parameter.
    uint32_t numIterations       = 2;
    auto ciphertextTwoIterations = cryptoContext->EvalBootstrap(ciph, numIterations, precisionUsed);

    Plaintext resultTwoIterations;
    cryptoContext->Decrypt(keyPair.secretKey, ciphertextTwoIterations, &resultTwoIterations);
    resultTwoIterations->SetLength(numSlots);

    double precisionMultipleIterations =
        CalculateApproximationError(resultTwoIterations->GetCKKSPackedValue(), ptxt->GetCKKSPackedValue());

    cryptoContext->ClearStaticMapsAndVectors();

    return {precision, precisionMultipleIterations};
}
