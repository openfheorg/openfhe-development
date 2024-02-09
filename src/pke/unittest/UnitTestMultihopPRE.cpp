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

#include "include/gtest/gtest.h"

#include <chrono>
#include <fstream>
#include <iostream>
#include <iterator>

using namespace lbcrypto;

class UTGENERAL_MULTIHOP_PRE : public ::testing::TestWithParam<int> {
protected:
    void SetUp() {}

    int run_demo_pre(int security_model) {
        // Generate parameters.
        int num_of_hops = 2;

        int plaintextModulus = 2;
        usint ringDimension  = 1024;
        usint digitSize      = 1;
        usint dcrtbits       = 0;

        usint qmodulus  = 27;
        usint firstqmod = 27;

        CCParams<CryptoContextBGVRNS> parameters;
        parameters.SetPREMode(INDCPA);
        if (security_model == 0) {
            ringDimension = 1024;
            digitSize     = 9;
            dcrtbits      = 0;

            qmodulus  = 27;
            firstqmod = 27;
            parameters.SetPREMode(INDCPA);
            parameters.SetKeySwitchTechnique(BV);
        }
        else if (security_model == 1) {
            ringDimension = 2048;
            digitSize     = 18;
            dcrtbits      = 0;

            qmodulus  = 54;
            firstqmod = 54;
            parameters.SetPREMode(FIXED_NOISE_HRA);
            parameters.SetKeySwitchTechnique(BV);
        }
        else if (security_model == 2) {
            ringDimension = 8192;
            digitSize     = 1;
            dcrtbits      = 30;

            qmodulus  = 218;
            firstqmod = 60;
            parameters.SetPREMode(NOISE_FLOODING_HRA);
            parameters.SetKeySwitchTechnique(BV);
        }
        else if (security_model == 3) {
            ringDimension = 8192;
            digitSize     = 0;
            dcrtbits      = 30;

            qmodulus      = 218;
            firstqmod     = 60;
            uint32_t dnum = 2;
            parameters.SetPREMode(NOISE_FLOODING_HRA);
            parameters.SetKeySwitchTechnique(HYBRID);
            parameters.SetNumLargeDigits(dnum);
        }

        parameters.SetMultiplicativeDepth(0);
        parameters.SetPlaintextModulus(plaintextModulus);
        parameters.SetRingDim(ringDimension);
        parameters.SetFirstModSize(firstqmod);
        parameters.SetScalingModSize(dcrtbits);
        parameters.SetDigitSize(digitSize);
        parameters.SetScalingTechnique(FIXEDMANUAL);
        parameters.SetMultiHopModSize(qmodulus);

        CryptoContext<DCRTPoly> cryptoContext = GenCryptoContext(parameters);
        cryptoContext->Enable(PKE);
        cryptoContext->Enable(KEYSWITCH);
        cryptoContext->Enable(LEVELEDSHE);
        cryptoContext->Enable(PRE);

        ////////////////////////////////////////////////////////////
        // Perform Key Generation Operation
        ////////////////////////////////////////////////////////////

        // Initialize Key Pair Containers
        KeyPair<DCRTPoly> keyPair1;

        keyPair1 = cryptoContext->KeyGen();

        if (!keyPair1.good()) {
            OPENFHE_THROW("Key generation failed!");
        }

        ////////////////////////////////////////////////////////////
        // Encode source data
        ////////////////////////////////////////////////////////////
        std::vector<int64_t> vectorOfInts;
        unsigned int nShort = 0;
        int ringsize        = 0;
        ringsize            = cryptoContext->GetRingDimension();
        nShort              = ringsize;

        for (size_t i = 0; i < nShort; i++) {
            if (plaintextModulus == 2) {
                vectorOfInts.push_back(std::rand() % plaintextModulus);
            }
            else {
                vectorOfInts.push_back((std::rand() % plaintextModulus) - (std::floor(plaintextModulus / 2) - 1));
            }
        }

        Plaintext plaintext = cryptoContext->MakeCoefPackedPlaintext(vectorOfInts);
        ////////////////////////////////////////////////////////////
        // Encryption
        ////////////////////////////////////////////////////////////

        auto ciphertext1 = cryptoContext->Encrypt(keyPair1.publicKey, plaintext);

        ////////////////////////////////////////////////////////////
        // Decryption of Ciphertext
        ////////////////////////////////////////////////////////////

        Plaintext plaintextDec1;

        cryptoContext->Decrypt(keyPair1.secretKey, ciphertext1, &plaintextDec1);

        plaintextDec1->SetLength(plaintext->GetLength());

        Ciphertext<DCRTPoly> reEncryptedCT1, reEncryptedCT;
        Plaintext plaintextDec;

        // multiple hop
        std::vector<KeyPair<DCRTPoly>> keyPairs;
        std::vector<Ciphertext<DCRTPoly>> reEncryptedCTs;

        keyPairs.push_back(keyPair1);
        reEncryptedCTs.push_back(ciphertext1);

        for (int i = 0; i < num_of_hops; i++) {
            auto keyPair = cryptoContext->KeyGen();
            keyPairs.push_back(keyPair);

            auto reencryptionKey = cryptoContext->ReKeyGen(keyPairs[i].secretKey, keyPairs[i + 1].publicKey);

            switch (security_model) {
                case 0:
                    // CPA secure PRE
                    reEncryptedCT = cryptoContext->ReEncrypt(reEncryptedCTs[i], reencryptionKey);  // IND-CPA secure
                    break;
                case 1:
                    // Fixed noise (20 bits) practically secure PRE
                    reEncryptedCT = cryptoContext->ReEncrypt(reEncryptedCTs[i], reencryptionKey, keyPairs[i].publicKey);
                    break;
                case 2:
                    // Provable HRA secure PRE with noise flooding with BV switching
                    reEncryptedCT1 =
                        cryptoContext->ReEncrypt(reEncryptedCTs[i], reencryptionKey, keyPairs[i].publicKey);
                    reEncryptedCT = cryptoContext->ModReduce(reEncryptedCT1);  // mod reduction for noise flooding
                    break;
                case 3:
                    // Provable HRA secure PRE with noise flooding with Hybrid switching
                    reEncryptedCT1 =
                        cryptoContext->ReEncrypt(reEncryptedCTs[i], reencryptionKey, keyPairs[i].publicKey);
                    reEncryptedCT = cryptoContext->ModReduce(reEncryptedCT1);  // mod reduction for noise flooding
                    break;
                default:
                    OPENFHE_THROW("Not a valid security mode");
            }

            reEncryptedCTs.push_back(reEncryptedCT);
        }

        int kp_size_vec, ct_size_vec;
        kp_size_vec = keyPairs.size();
        ct_size_vec = reEncryptedCTs.size();

        cryptoContext->Decrypt(keyPairs[kp_size_vec - 1].secretKey, reEncryptedCTs[ct_size_vec - 1], &plaintextDec);

        // verification
        std::vector<int64_t> unpackedPT, unpackedDecPT;
        unpackedPT    = plaintextDec1->GetCoefPackedValue();
        unpackedDecPT = plaintextDec->GetCoefPackedValue();
        for (unsigned int j = 0; j < unpackedPT.size(); j++) {
            EXPECT_EQ(unpackedPT[j], unpackedDecPT[j]);
            if (unpackedPT[j] != unpackedDecPT[j]) {
                OPENFHE_THROW("Decryption failure");
            }
        }

        return 0;
    }
};

TEST_P(UTGENERAL_MULTIHOP_PRE, MULTIHOP_PRE_TEST) {
    auto test = GetParam();
    run_demo_pre(test);
}

int Security_Model_Options[4] = {0, 1, 2, 3};

INSTANTIATE_TEST_SUITE_P(MULTIHOP_PRE_TEST, UTGENERAL_MULTIHOP_PRE, ::testing::ValuesIn(Security_Model_Options));

/*
run_demo_pre(0); // IND CPA secure
run_demo_pre(1); // Fixed 20 bits Noise HRA
run_demo_pre(2); // provably secure HRA */
