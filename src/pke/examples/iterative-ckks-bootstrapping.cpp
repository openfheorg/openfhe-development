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

#define PROFILE

#include "openfhe.h"

using namespace lbcrypto;

void IterativeBootstrapExample();

int main(int argc, char* argv[]) {
    // We run the example with 8 slots and ring dimension 4096.
    IterativeBootstrapExample();
}

// CalculateApproximationError() calculates the precision number (or approximation error).
// The higher the precision, the less the error.
double CalculateApproximationError(const std::vector<std::complex<double>>& result,
                                   const std::vector<std::complex<double>>& expectedResult) {
    if (result.size() != expectedResult.size())
        OPENFHE_THROW(config_error, "Cannot compare vectors with different numbers of elements");

    // using the infinity norm
    double maxError = 0;
    for (size_t i = 0; i < result.size(); ++i) {
        double error = std::abs(result[i].real() - expectedResult[i].real());
        if (maxError < error)
            maxError = error;
    }

    return std::abs(std::log2(maxError));
}

void IterativeBootstrapExample() {
    // Step 1: Set CryptoContext
    CCParams<CryptoContextCKKSRNS> parameters;
    SecretKeyDist secretKeyDist = UNIFORM_TERNARY;
    parameters.SetSecretKeyDist(secretKeyDist);
    parameters.SetSecurityLevel(HEStd_NotSet);
    parameters.SetRingDim(1 << 12);

#if NATIVEINT == 128 && !defined(__EMSCRIPTEN__)
    // Currently, only FIXEDMANUAL and FIXEDAUTO modes are supported for 128-bit CKKS bootstrapping.
    ScalingTechnique rescaleTech = FIXEDAUTO;
    usint dcrtBits               = 78;
    usint firstMod               = 89;
#else
    // All modes are supported for 64-bit CKKS bootstrapping.
    ScalingTechnique rescaleTech = FLEXIBLEAUTO;
    usint dcrtBits               = 59;
    usint firstMod               = 60;
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
    usint depth =
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

    usint ringDim = cryptoContext->GetRingDimension();
    std::cout << "CKKS scheme is using ring dimension " << ringDim << std::endl << std::endl;

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
    std::uniform_real_distribution<> dis(0.0, 1.0);
    for (size_t i = 0; i < numSlots; i++) {
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
    std::cout << "Input: " << ptxt << std::endl;

    // Encrypt the encoded vectors
    Ciphertext<DCRTPoly> ciph = cryptoContext->Encrypt(keyPair.publicKey, ptxt);

    // Step 5: Measure the precision of a single bootstrapping operation.
    auto ciphertextAfter = cryptoContext->EvalBootstrap(ciph);

    Plaintext result;
    cryptoContext->Decrypt(keyPair.secretKey, ciphertextAfter, &result);
    result->SetLength(numSlots);
    uint32_t precision =
        std::floor(CalculateApproximationError(result->GetCKKSPackedValue(), ptxt->GetCKKSPackedValue()));
    std::cout << "Bootstrapping precision after 1 iteration: " << precision << std::endl;

    // Set precision equal to empirically measured value after many test runs.
    precision = 17;
    std::cout << "Precision input to algorithm: " << precision << std::endl;

    // Step 6: Run bootstrapping with multiple iterations.
    auto ciphertextTwoIterations = cryptoContext->EvalBootstrap(ciph, numIterations, precision);

    Plaintext resultTwoIterations;
    cryptoContext->Decrypt(keyPair.secretKey, ciphertextTwoIterations, &resultTwoIterations);
    result->SetLength(numSlots);
    auto actualResult = resultTwoIterations->GetCKKSPackedValue();

    std::cout << "Output after two iterations of bootstrapping: " << actualResult << std::endl;
    double precisionMultipleIterations = CalculateApproximationError(actualResult, ptxt->GetCKKSPackedValue());

    // Output the precision of bootstrapping after two iterations. It should be approximately double the original precision.
    std::cout << "Bootstrapping precision after 2 iterations: " << precisionMultipleIterations << std::endl;
    std::cout << "Number of levels remaining after 2 bootstrappings: " << depth - ciphertextTwoIterations->GetLevel()
              << std::endl;
}
