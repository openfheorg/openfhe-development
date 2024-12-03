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
  unit tests for Proxy Re-Encryption. Demo software for multiparty proxy reencryption operations for various schemes
 */

#include "scheme/bgvrns/gen-cryptocontext-bgvrns.h"
#include "gen-cryptocontext.h"
#include "cryptocontext.h"

#include "include/gtest/gtest.h"

#include <chrono>
#include <fstream>
#include <iostream>
#include <iterator>

using namespace lbcrypto;

class UTGENERAL_MULTIHOP_PRE : public ::testing::TestWithParam<uint32_t> {
protected:
    int run_demo_pre(uint32_t security_model, uint32_t num_of_hops) {
        // Generate parameters.
        PlaintextModulus plaintextModulus{2};
        uint32_t ringDimension;
        uint32_t digitSize;
        CCParams<CryptoContextBGVRNS> parameters;

        if (security_model == 0) {
            ringDimension = 1024;
            digitSize     = 9;
            parameters.SetPREMode(INDCPA);
            parameters.SetKeySwitchTechnique(BV);
            parameters.SetFirstModSize(27);
        }
        else if (security_model == 1) {
            ringDimension = 2048;
            digitSize     = 16;
            parameters.SetPREMode(FIXED_NOISE_HRA);
            parameters.SetKeySwitchTechnique(BV);
            parameters.SetFirstModSize(54);
        }
        else if (security_model == 2) {
            ringDimension = 8192;
            digitSize     = 10;
            parameters.SetPREMode(NOISE_FLOODING_HRA);
            parameters.SetKeySwitchTechnique(BV);
            parameters.SetPRENumHops(num_of_hops);
            parameters.SetStatisticalSecurity(40);
            parameters.SetNumAdversarialQueries(1048576);
        }
        else if (security_model == 3) {
            ringDimension = 8192;
            digitSize     = 0;
            parameters.SetPREMode(NOISE_FLOODING_HRA);
            parameters.SetKeySwitchTechnique(HYBRID);
            parameters.SetPRENumHops(num_of_hops);
            parameters.SetStatisticalSecurity(40);
            parameters.SetNumAdversarialQueries(1048576);
        }
        else {
            OPENFHE_THROW("invalid security model");
        }

        parameters.SetMultiplicativeDepth(0);
        parameters.SetPlaintextModulus(plaintextModulus);
        parameters.SetRingDim(ringDimension);
        parameters.SetDigitSize(digitSize);
        parameters.SetScalingTechnique(FIXEDMANUAL);
        parameters.SetSecurityLevel(HEStd_NotSet);

        auto cc = GenCryptoContext(parameters);
        cc->Enable(PKE);
        cc->Enable(KEYSWITCH);
        cc->Enable(LEVELEDSHE);
        cc->Enable(PRE);

        ////////////////////////////////////////////////////////////
        // Perform Key Generation Operation
        ////////////////////////////////////////////////////////////

        auto keyPair1 = cc->KeyGen();
        if (!keyPair1.good())
            OPENFHE_THROW("key generation failed!");

        ////////////////////////////////////////////////////////////
        // Encode source data
        ////////////////////////////////////////////////////////////

        std::vector<int64_t> vectorOfInts(ringDimension);
        for (auto& v : vectorOfInts)
            v = (std::rand() % plaintextModulus);
        auto plaintext = cc->MakeCoefPackedPlaintext(vectorOfInts);

        ////////////////////////////////////////////////////////////
        // Encryption
        ////////////////////////////////////////////////////////////

        auto ciphertext1 = cc->Encrypt(keyPair1.publicKey, plaintext);

        ////////////////////////////////////////////////////////////
        // Decryption of Ciphertext
        ////////////////////////////////////////////////////////////

        Plaintext plaintextDec1;

        cc->Decrypt(keyPair1.secretKey, ciphertext1, &plaintextDec1);

        plaintextDec1->SetLength(plaintext->GetLength());

        Ciphertext<DCRTPoly> reEncryptedCT;
        Plaintext plaintextDec;

        // multiple hop
        std::vector<KeyPair<DCRTPoly>> keyPairs{keyPair1};
        std::vector<Ciphertext<DCRTPoly>> reEncryptedCTs{ciphertext1};

        for (uint32_t i = 0; i < num_of_hops; ++i) {
            keyPairs.push_back(cc->KeyGen());

            auto reencryptionKey = cc->ReKeyGen(keyPairs[i].secretKey, keyPairs[i + 1].publicKey);

            switch (security_model) {
                case 0:
                    // CPA secure PRE
                    reEncryptedCT = cc->ReEncrypt(reEncryptedCTs[i], reencryptionKey);  // IND-CPA secure
                    break;
                case 1:
                    // Fixed noise (20 bits) practically secure PRE
                    reEncryptedCT = cc->ReEncrypt(reEncryptedCTs[i], reencryptionKey, keyPairs[i].publicKey);
                    break;
                case 2:
                    // Provable HRA secure PRE with noise flooding with BV switching
                    reEncryptedCT = cc->ReEncrypt(reEncryptedCTs[i], reencryptionKey, keyPairs[i].publicKey);
                    if (i < num_of_hops - 1)
                        reEncryptedCT = cc->ModReduce(reEncryptedCT);  // mod reduction for noise flooding
                    break;
                case 3:
                    // Provable HRA secure PRE with noise flooding with Hybrid switching
                    reEncryptedCT = cc->ReEncrypt(reEncryptedCTs[i], reencryptionKey, keyPairs[i].publicKey);
                    if (i < num_of_hops - 1)
                        reEncryptedCT = cc->ModReduce(reEncryptedCT);  // mod reduction for noise flooding
                    break;
                default:
                    OPENFHE_THROW("Not a valid security mode");
            }
            reEncryptedCTs.push_back(reEncryptedCT);
        }

        cc->Decrypt(keyPairs.back().secretKey, reEncryptedCTs.back(), &plaintextDec);

        // verification
        auto& unpackedPT    = plaintextDec1->GetCoefPackedValue();
        auto& unpackedDecPT = plaintextDec->GetCoefPackedValue();
        EXPECT_EQ(unpackedPT.size(), unpackedDecPT.size());
        for (size_t j = 0; j < unpackedPT.size(); ++j) {
            EXPECT_EQ(unpackedPT[j], unpackedDecPT[j]);
        }

        return 0;
    }
};

TEST_P(UTGENERAL_MULTIHOP_PRE, MULTIHOP_PRE_TEST) {
    auto test = GetParam();
    run_demo_pre(test, 1);
    run_demo_pre(test, 3);
    run_demo_pre(test, 4);
    run_demo_pre(test, 5);
}

uint32_t Security_Model_Options[4] = {0, 1, 2, 3};

INSTANTIATE_TEST_SUITE_P(MULTIHOP_PRE_TEST, UTGENERAL_MULTIHOP_PRE, ::testing::ValuesIn(Security_Model_Options));
