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
  Example of polynomial evaluation using CKKS.
 */

#define PROFILE  // turns on the reporting of timing results

#include "openfhe.h"

using namespace lbcrypto;

int main(int argc, char* argv[]) {
    TimeVar t;

    double timeEvalLinearWSum(0.0);

    std::cout << "\n======EXAMPLE FOR EVAL LINEAR WEIGHTED SUM========\n" << std::endl;

    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetMultiplicativeDepth(1);
    parameters.SetScalingModSize(50);
    parameters.SetBatchSize(8);
    parameters.SetSecurityLevel(HEStd_NotSet);
    parameters.SetRingDim(2048);
    parameters.SetScalingTechnique(FLEXIBLEAUTO);
    parameters.SetFirstModSize(60);

    CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE);

    std::vector<std::vector<std::complex<double>>> input;

    input.push_back({0.5, 0.7, 0.9, 0.95, 0.93, 1.3});
    input.push_back({1.2, 1.7, -0.9, 0.85, -0.63, 2});
    input.push_back({0.5, 0, 1.9, 2.95, -3.93, 3.3});
    input.push_back({1.5, 0.7, 1.9, 2.95, -3.78, 3.3});
    input.push_back({0.5, 2.7, 1.9, 0.0, -3.43, 1.3});
    input.push_back({0.5, 0.7, -1.9, 2.95, 1.96, 0.0});
    input.push_back({0.0, 0.0, 1.0, 0.0, 0.0, 0.0});

    size_t encodedLength = input.size();

    std::vector<double> coefficients({0.15, 0.75, 1.25, 1, 0, 0.5, 0.5});

    auto keyPair = cc->KeyGen();

    std::cout << "Generating evaluation key for homomorphic multiplication...";
    cc->EvalMultKeyGen(keyPair.secretKey);
    std::cout << "Completed." << std::endl;

    std::vector<ConstCiphertext<DCRTPoly>> ciphertextVec;
    for (usint i = 0; i < encodedLength; ++i) {
        Plaintext plaintext = cc->MakeCKKSPackedPlaintext(input[i]);
        ciphertextVec.push_back(cc->Encrypt(keyPair.publicKey, plaintext));
    }

    TIC(t);

    auto result = cc->EvalLinearWSum(ciphertextVec, coefficients);

    timeEvalLinearWSum = TOC(t);

    std::vector<std::complex<double>> unencIP;
    for (usint i = 0; i < input[0].size(); ++i) {
        std::complex<double> x = 0;
        for (usint j = 0; j < encodedLength; ++j) {
            x += input[j][i] * coefficients[j];
        }
        unencIP.push_back(x);
    }

    Plaintext plaintextDec;

    cc->Decrypt(keyPair.secretKey, result, &plaintextDec);

    plaintextDec->SetLength(encodedLength);

    std::cout << std::setprecision(10) << std::endl;

    std::cout << "\n Result of evaluating a linear weighted sum with coefficients " << coefficients << " \n";
    std::cout << plaintextDec << std::endl;

    std::cout << "\n Expected result: " << unencIP << std::endl;

    std::cout << "\n Evaluation time: " << timeEvalLinearWSum << " ms" << std::endl;

    return 0;
}
