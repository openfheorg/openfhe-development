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

#define PROFILE

#include "openfhe.h"

using namespace lbcrypto;

double MeasureBootstrapPrecision(uint32_t numSlots, uint32_t correctionFactor);

double CalculateApproximationError(const std::vector<std::complex<double>>& result,
                                   const std::vector<std::complex<double>>& expectedResult) {
    if (result.size() != expectedResult.size())
        OPENFHE_THROW(config_error, "Cannot compare vectors with different numbers of elements");

    // using the Euclidean norm
    double avrg = 0;
    for (size_t i = 0; i < result.size(); ++i) {
        avrg += std::pow(std::abs(result[i].real() - expectedResult[i].real()), 2);
    }

    avrg = std::sqrt(avrg) / result.size();  // get the average
    return std::abs(std::log2(avrg));
}

int main(int argc, char* argv[]) {
#if NATIVEINT == 64
    size_t numIterations           = 10;
    size_t maxCorrectionFactor     = 15;
    std::vector<uint32_t> slotsVec = {1 << 3, 1 << 11};
    for (uint32_t numSlots : slotsVec) {
        for (size_t correctionFactor = 1; correctionFactor <= maxCorrectionFactor; correctionFactor++) {
            std::cout << "=======================================================================" << std::endl;
            std::cout << "Number of slots: " << numSlots << std::endl;
            std::cout << "Correction Factor: " << correctionFactor << std::endl;
            double precision = 0.0;
            for (size_t i = 0; i < numIterations; i++) {
                precision += MeasureBootstrapPrecision(numSlots, correctionFactor);
            }
            precision /= numIterations;
            std::cout << "Average precision over " << numIterations << " iterations: " << precision << std::endl;
            std::cout << "=======================================================================" << std::endl;
        }
    }
#endif
}

double MeasureBootstrapPrecision(uint32_t numSlots, uint32_t correctionFactor) {
    CCParams<CryptoContextCKKSRNS> parameters;

    SecretKeyDist secretKeyDist = UNIFORM_TERNARY;
    parameters.SetSecretKeyDist(secretKeyDist);

    parameters.SetSecurityLevel(HEStd_NotSet);
    parameters.SetRingDim(1 << 12);

    ScalingTechnique rescaleTech = FLEXIBLEAUTOEXT;
    usint dcrtBits               = 59;
    usint firstMod               = 60;
    parameters.SetScalingModSize(dcrtBits);
    parameters.SetScalingTechnique(rescaleTech);
    parameters.SetFirstModSize(firstMod);

    std::vector<uint32_t> levelBudget      = {3, 3};
    uint32_t approxBootstrapDepth          = 9;
    std::vector<uint32_t> bsgsDim          = {0, 0};
    uint32_t levelsAvailableAfterBootstrap = 10;
    usint depth =
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
    return precision;
}
