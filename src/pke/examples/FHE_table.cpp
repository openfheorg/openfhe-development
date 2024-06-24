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

Example for CKKS bootstrapping with full packing, modified from simple-ckks-bootstrapping.cpp provided by OpenFHE library.

*/

#define PROFILE

#include "openfhe.h"

using namespace lbcrypto;

void SimpleBootstrapExample(uint32_t ringDim, usint dcrtBits, usint firstMod, std::vector<uint32_t> levelBudget,
                            uint32_t levelsAvailableAfterBootstrap, uint32_t numDigits);
double CalculateApproximationError(const std::vector<std::complex<double>>& result,
                                   const std::vector<std::complex<double>>& expectedResult) {
    if (result.size() != expectedResult.size())
        OPENFHE_THROW(config_error, "Cannot compare vectors with different numbers of elements");

    // using the average
    double accError = 0;
    for (size_t i = 0; i < result.size(); ++i) {
        accError += std::abs(result[i].real() - expectedResult[i].real());
    }
    double avrg = accError / result.size();  // get the average
    return std::abs(std::log2(avrg));
}
int main(int argc, char* argv[]) {
    // SetII
    std::cout << "--------------------RNS-CKKS with Bootstrapping Set II--------------------" << std::endl;
    uint32_t ringDim                       = 1 << 16;
    usint dcrtBits                         = 58;
    usint firstMod                         = 60;
    std::vector<uint32_t> levelBudget      = {3, 3};
    uint32_t levelsAvailableAfterBootstrap = 5;
    uint32_t numDigits                     = 9;
    SimpleBootstrapExample(ringDim, dcrtBits, firstMod, levelBudget, levelsAvailableAfterBootstrap, numDigits);
}

void SimpleBootstrapExample(uint32_t ringDim, usint dcrtBits, usint firstMod, std::vector<uint32_t> levelBudget,
                            uint32_t levelsAvailableAfterBootstrap, uint32_t numDigits) {
    CCParams<CryptoContextCKKSRNS> parameters;
    // A. Specify main parameters
    /*  A1) Secret key distribution
    * The secret key distribution for CKKS should either be SPARSE_TERNARY or UNIFORM_TERNARY.
    * The SPARSE_TERNARY distribution was used in the original CKKS paper,
    * but in this example, we use UNIFORM_TERNARY because this is included in the homomorphic
    * encryption standard.
    */
    SecretKeyDist secretKeyDist = UNIFORM_TERNARY;
    parameters.SetSecretKeyDist(secretKeyDist);

    /*  A2) Desired security level based on FHE standards.
    * In this example, we use the "NotSet" option, so the example can run more quickly with
    * a smaller ring dimension. Note that this should be used only in
    * non-production environments, or by experts who understand the security
    * implications of their choices. In production-like environments, we recommend using
    * HEStd_128_classic, HEStd_192_classic, or HEStd_256_classic for 128-bit, 192-bit,
    * or 256-bit security, respectively. If you choose one of these as your security level,
    * you do not need to set the ring dimension.
    */
    parameters.SetSecurityLevel(HEStd_128_classic);
    parameters.SetRingDim(ringDim);

    /*  A3) Scaling parameters.
    * By default, we set the modulus sizes and rescaling technique to the following values
    * to obtain a good precision and performance tradeoff. We recommend keeping the parameters
    * below unless you are an FHE expert.
    */
    ScalingTechnique rescaleTech = FLEXIBLEAUTO;
    // usint dcrtBits               = 58;
    // usint firstMod               = 60;

    parameters.SetScalingModSize(dcrtBits);
    parameters.SetScalingTechnique(rescaleTech);
    parameters.SetFirstModSize(firstMod);

    parameters.SetNumLargeDigits(numDigits);
    parameters.SetKeySwitchTechnique(HYBRID);

    /*  A4) Multiplicative depth.
    * The goal of bootstrapping is to increase the number of available levels we have, or in other words,
    * to dynamically increase the multiplicative depth. However, the bootstrapping procedure itself
    * needs to consume a few levels to run. We compute the number of bootstrapping levels required
    * using GetBootstrapDepth, and add it to levelsAvailableAfterBootstrap to set our initial multiplicative
    * depth. We recommend using the input parameters below to get started.
    */

    usint depth = levelsAvailableAfterBootstrap + FHECKKSRNS::GetBootstrapDepth(levelBudget, secretKeyDist);
    std::cout << "Level consumption for SlotsToCoeffs: " << levelBudget[0] << std::endl;
    std::cout << "Level consumption for EvalMod: "
              << depth - levelsAvailableAfterBootstrap - levelBudget[0] - levelBudget[1] - 1 << std::endl;
    std::cout << "Level consumption for CoeffsToSlots: " << levelBudget[1] << std::endl;
    parameters.SetMultiplicativeDepth(depth);
    std::cout << "depth = " << depth << std::endl;
    CryptoContext<DCRTPoly> cryptoContext = GenCryptoContext(parameters);

    cryptoContext->Enable(PKE);
    cryptoContext->Enable(KEYSWITCH);
    cryptoContext->Enable(LEVELEDSHE);
    cryptoContext->Enable(ADVANCEDSHE);
    cryptoContext->Enable(FHE);

    // This is the maximum number of slots that can be used for full packing.
    usint numSlots = ringDim / 2;
    std::cout << "CKKS scheme is using ring dimension " << ringDim << std::endl;
    std::cout << "# of slots =  " << numSlots << std::endl << std::endl;

    std::cout << "CKKS scheme is using ring dimension " << ringDim << std::endl << std::endl;
    std::cout << "log Q " << cryptoContext->GetModulus().GetMSB() << std::endl << std::endl;
    const auto cryptoParamsCKKS =
        std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(cryptoContext->GetCryptoParameters());
    std::cout << "log P " << cryptoParamsCKKS->GetParamsP()->GetModulus().GetMSB() << std::endl << std::endl;
    std::cout << "log PQ " << cryptoParamsCKKS->GetParamsQP()->GetModulus().GetMSB() << std::endl << std::endl;

    cryptoContext->EvalBootstrapSetup(levelBudget);

    auto keyPair = cryptoContext->KeyGen();
    cryptoContext->EvalMultKeyGen(keyPair.secretKey);
    cryptoContext->EvalBootstrapKeyGen(keyPair.secretKey, numSlots);

    std::vector<double> x;
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_real_distribution<> dis(-1.0, 1.0);
    for (size_t i = 0; i < numSlots; i++) {
        x.push_back(dis(gen));
    }

    size_t encodedLength = x.size();

    Plaintext ptxt = cryptoContext->MakeCKKSPackedPlaintext(x, 1, depth - 1);

    ptxt->SetLength(encodedLength);

    Ciphertext<DCRTPoly> ciph = cryptoContext->Encrypt(keyPair.publicKey, ptxt);

    std::cout << "Initial number of levels remaining: " << depth - ciph->GetLevel() << std::endl;

    // Perform the bootstrapping operation. The goal is to increase the number of levels remaining
    // for HE computation.
    auto ciphertextAfter = cryptoContext->EvalBootstrap(ciph);

    std::cout << "Number of levels remaining after bootstrapping: " << depth - ciphertextAfter->GetLevel() << std::endl
              << std::endl;

    Plaintext result;
    cryptoContext->Decrypt(keyPair.secretKey, ciphertextAfter, &result);
    result->SetLength(encodedLength);
    // std::cout << "Output after bootstrapping \n\t" << result << std::endl;
    auto actualResult = result->GetCKKSPackedValue();
    double precision  = CalculateApproximationError(actualResult, ptxt->GetCKKSPackedValue());
    std::cout << "Real precision in bits: " << precision << std::endl;
}
