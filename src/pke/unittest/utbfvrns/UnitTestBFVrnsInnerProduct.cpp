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

#include "scheme/bfvrns/gen-cryptocontext-bfvrns.h"
#include "gen-cryptocontext.h"

#include <vector>
#include "gtest/gtest.h"

#include "utils/debug.h"

using namespace lbcrypto;

namespace {
class UTBFVRNS_INNERPRODUCT : public ::testing::Test {
protected:
    void SetUp() {}

    void TearDown() {
        CryptoContextFactory<DCRTPoly>::ReleaseAllContexts();
    }

public:
};

enum TEST_ESTIMATED_RESULT { SUCCESS, FAILURE };

}  // anonymous namespace

template <class T>
T plainInnerProduct(std::vector<T> vec) {
    T res = 0.0;
    for (auto& el : vec) {
        res += (el * el);
    }
    return res;
}

//================================================================================================

// declaration for Automorphism Test on BFVrns scheme with polynomial operation
// in power of 2 cyclotomics.
int64_t BFVrnsInnerProduct(const std::vector<int64_t> testVec) {
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

    KeyPair<DCRTPoly> keys = cc->KeyGen();
    cc->EvalMultKeyGen(keys.secretKey);
    cc->EvalSumKeyGen(keys.secretKey);

    Plaintext plaintext1 = cc->MakePackedPlaintext(testVec);
    auto ct1             = cc->Encrypt(keys.publicKey, plaintext1);
    auto finalResult     = cc->EvalInnerProduct(ct1, ct1, batchSize);
    lbcrypto::Plaintext res;
    cc->Decrypt(keys.secretKey, finalResult, &res);
    return res->GetPackedValue()[0];
}

TEST_F(UTBFVRNS_INNERPRODUCT, Test_BFVrns_INNERPRODUCT) {
    const std::vector<int64_t> testVec{1, 2, 3, 4, 5};
    auto innerProductHE = BFVrnsInnerProduct(testVec);

    int64_t expectedResult = plainInnerProduct(testVec);
    EXPECT_EQ(innerProductHE, expectedResult);
}
