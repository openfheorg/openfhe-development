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

/**
 * Simple example for BFV and CKKS for inner product.
 */

#include <iostream>
#include "openfhe.h"
#include <vector>

using namespace lbcrypto;

template <class T>
T plainInnerProduct(std::vector<T> vec) {
    T res = 0.0;
    for (auto& el : vec) {
        res += (el * el);
    }
    return res;
}

bool innerProductBFV(std::vector<int64_t>& incomingVector) {
    int64_t expectedResult = plainInnerProduct(incomingVector);
    /////////////////////////////////////////////////////////
    // Crypto CryptoParams
    /////////////////////////////////////////////////////////
    CCParams<CryptoContextBFVRNS> parameters;
    parameters.SetPlaintextModulus(65537);
    parameters.SetMultiplicativeDepth(20);
    parameters.SetSecurityLevel(lbcrypto::HEStd_NotSet);
    parameters.SetRingDim(1 << 7);
    uint32_t batchSize = parameters.GetRingDim() / 2;

    /////////////////////////////////////////////////////////
    // Set crypto params and create context
    /////////////////////////////////////////////////////////
    lbcrypto::CryptoContext<lbcrypto::DCRTPoly> cc;
    cc = GenCryptoContext(parameters);

    // Enable the features that you wish to use.
    cc->Enable(PKE);
    cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE);

    KeyPair keys = cc->KeyGen();
    cc->EvalMultKeyGen(keys.secretKey);
    cc->EvalSumKeyGen(keys.secretKey);

    Plaintext plaintext1 = cc->MakePackedPlaintext(incomingVector);
    auto ct1             = cc->Encrypt(keys.publicKey, plaintext1);
    auto finalResult     = cc->EvalInnerProduct(ct1, ct1, batchSize);
    lbcrypto::Plaintext res;
    cc->Decrypt(keys.secretKey, finalResult, &res);
    auto final = res->GetPackedValue()[0];

    std::cout << "Expected Result: " << expectedResult << " Inner Product Result: " << final << std::endl;
    return expectedResult == final;
}

bool innerProductCKKS(const std::vector<double>& incomingVector) {
    double expectedResult                 = plainInnerProduct(incomingVector);
    lbcrypto::SecurityLevel securityLevel = lbcrypto::HEStd_NotSet;
    uint32_t dcrtBits                     = 59;
    uint32_t ringDim                      = 1 << 8;
    uint32_t batchSize                    = ringDim / 2;
    lbcrypto::CCParams<lbcrypto::CryptoContextCKKSRNS> parameters;
    uint32_t multDepth = 10;

    parameters.SetMultiplicativeDepth(multDepth);
    parameters.SetScalingModSize(dcrtBits);
    parameters.SetBatchSize(batchSize);
    parameters.SetSecurityLevel(securityLevel);
    parameters.SetRingDim(ringDim);

    lbcrypto::CryptoContext<lbcrypto::DCRTPoly> cc;
    cc = GenCryptoContext(parameters);

    cc->Enable(PKE);
    cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE);

    KeyPair keys = cc->KeyGen();
    cc->EvalMultKeyGen(keys.secretKey);
    cc->EvalSumKeyGen(keys.secretKey);

    Plaintext plaintext1 = cc->MakeCKKSPackedPlaintext(incomingVector);
    auto ct1             = cc->Encrypt(keys.publicKey, plaintext1);
    auto finalResult     = cc->EvalInnerProduct(ct1, ct1, batchSize);
    lbcrypto::Plaintext res;
    cc->Decrypt(keys.secretKey, finalResult, &res);
    res->SetLength(incomingVector.size());
    auto final = res->GetCKKSPackedValue()[0].real();
    std::cout << "Expected Result: " << expectedResult << " Inner Product Result: " << final << std::endl;
    return std::abs(expectedResult - final) <= 0.0001;
}

int main(int argc, char* argv[]) {
    std::vector<int64_t> vec = {1, 2, 3, 4, 5};
    bool bfvRes              = innerProductBFV(vec);
    std::cout << "BFV Inner Product Correct? " << (bfvRes ? "True" : "False") << std::endl;

    std::cout << "********************************************************************" << std::endl;
    std::vector<double> asDouble(vec.begin(), vec.end());
    for (size_t i = 0; i < asDouble.size(); i++) {
        asDouble[i] += (asDouble[i] / 100.0);
    }
    bool ckksRes = innerProductCKKS(asDouble);
    std::cout << "CKKS Inner Product Correct? " << (ckksRes ? "True" : "False") << std::endl;

    return 0;
}
