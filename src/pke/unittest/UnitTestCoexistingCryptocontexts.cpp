//==================================================================================
// BSD 2-Clause License
//
// Copyright (c) 2014-2023, NJIT, Duality Technologies Inc. and other contributors
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
/***
 * Very qiuck unittest to verify that ringDim for the first cryptocontext is not overriden by
 * creation of another cryptocontext. This test's code should be as close to a regular user project
 * as possible
 */
#include "openfhe.h"
#include "UnitTestUtils.h"
#include "include/gtest/gtest.h"

using namespace lbcrypto;

class UTGENERAL_CRYPTOCONTEXTS : public ::testing::Test {
protected:
    virtual void SetUp() {}

    virtual void TearDown() {
        // Code here will be called immediately after each test
        // (right before the destructor).
        // TODO (dsuponit): do we need to remove keys before releasing all context?
        // CryptoContextImpl<Poly>::ClearEvalMultKeys();
        // CryptoContextImpl<Poly>::ClearEvalSumKeys();
        // CryptoContextImpl<DCRTPoly>::ClearEvalMultKeys();
        // CryptoContextImpl<DCRTPoly>::ClearEvalSumKeys();
        CryptoContextFactory<DCRTPoly>::ReleaseAllContexts();
    }
};

TEST_F(UTGENERAL_CRYPTOCONTEXTS, coexisting_ckks_cryptocontexts) {
    // Setup crypto context 1
    CCParams<CryptoContextCKKSRNS> parameters1;
    parameters1.SetMultiplicativeDepth(5);
    parameters1.SetScalingModSize(40);
    parameters1.SetRingDim(4096 * 4);
    parameters1.SetBatchSize(32);

    CryptoContext<lbcrypto::DCRTPoly> cc1 = GenCryptoContext(parameters1);
    cc1->Enable(PKE);
    cc1->Enable(KEYSWITCH);
    cc1->Enable(LEVELEDSHE);
    lbcrypto::KeyPair<lbcrypto::DCRTPoly> key1 = cc1->KeyGen();

    // Setup crypto context 2 for testing (not used)
    CCParams<CryptoContextCKKSRNS> parameters2;
    parameters2.SetMultiplicativeDepth(1);
    parameters2.SetScalingModSize(30);
    parameters2.SetRingDim(16);
    parameters2.SetBatchSize(4);
    parameters2.SetSecurityLevel(HEStd_NotSet);

    CryptoContext<lbcrypto::DCRTPoly> cc2 = GenCryptoContext(parameters2);
    cc2->Enable(PKE);
    cc2->Enable(KEYSWITCH);
    cc2->Enable(LEVELEDSHE);
    lbcrypto::KeyPair<lbcrypto::DCRTPoly> key2 = cc2->KeyGen();

    // Setup crypto context 3 for testing (not used)
    CCParams<CryptoContextCKKSRNS> parameters3;
    parameters3.SetMultiplicativeDepth(2);
    parameters3.SetScalingModSize(50);
    parameters3.SetRingDim(2048);
    parameters3.SetDigitSize(3);
    parameters3.SetBatchSize(16);
    parameters3.SetSecurityLevel(HEStd_NotSet);
    parameters3.SetKeySwitchTechnique(BV);
    parameters3.SetScalingTechnique(FIXEDMANUAL);

    CryptoContext<lbcrypto::DCRTPoly> cc3 = GenCryptoContext(parameters3);
    cc3->Enable(PKE);
    cc3->Enable(KEYSWITCH);
    cc3->Enable(LEVELEDSHE);
    lbcrypto::KeyPair<lbcrypto::DCRTPoly> key3 = cc3->KeyGen();

    // Encrypt
    std::vector<double> values = {1.0, 1.1, 1.2};
    // const size_t dataSize = values.size();
    Plaintext ptxt  = cc1->MakeCKKSPackedPlaintext(values);
    auto ciphertext = cc1->Encrypt(ptxt, key1.publicKey);

    // Decrypt
    Plaintext results;
    cc1->Decrypt(ciphertext, key1.secretKey, &results);
    results->SetLength(ptxt->GetLength());

    EXPECT_TRUE(checkEquality(values, results->GetRealPackedValue()))
        << "static data for the first cryptocontext may be overriden";
}
