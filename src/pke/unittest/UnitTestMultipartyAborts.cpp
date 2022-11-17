// @file  threshold-fhe.cpp - Examples of threshold FHE for BGVrns, BFVrns, and
// CKKS
// @author TPOC: contact@palisade-crypto.org
//
// @copyright Copyright (c) 2020, Duality Technologies Inc.
// All rights reserved.
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
// 1. Redistributions of source code must retain the above copyright notice,
// this list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright notice,
// this list of conditions and the following disclaimer in the documentation
// and/or other materials provided with the distribution. THIS SOFTWARE IS
// PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR
// IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO
// EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
// INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
// LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
// ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#include "UnitTestUtils.h"
#include "UnitTestCCParams.h"
#include "UnitTestCryptoContext.h"
#include "scheme/bfvrns/cryptocontext-bfvrns.h"
#include "gen-cryptocontext.h"
#include "utils/exception.h"

#include "include/gtest/gtest.h"

using namespace std;
using namespace lbcrypto;

class UTMultipartyAborts : public ::testing::TestWithParam<string> {
protected:
    void SetUp() {}

    void RunBFVrns(string sharing_scheme) {
        int plaintextModulus        = 65537;
        double sigma                = 3.2;
        SecurityLevel securityLevel = HEStd_128_classic;
        usint batchSize             = 16;
        usint multDepth             = 2;

        CCParams<CryptoContextBFVRNS> parameters;

        parameters.SetPlaintextModulus(plaintextModulus);
        parameters.SetSecurityLevel(securityLevel);
        parameters.SetStandardDeviation(sigma);
        parameters.SetSecretKeyDist(UNIFORM_TERNARY);
        parameters.SetMultiplicativeDepth(multDepth);
        parameters.SetBatchSize(batchSize);

        lbcrypto::CryptoContext<lbcrypto::DCRTPoly> cc = GenCryptoContext(parameters);
        // enable features that you wish to use
        cc->Enable(PKE);
        cc->Enable(KEYSWITCH);
        cc->Enable(LEVELEDSHE);
        cc->Enable(ADVANCEDSHE);
        cc->Enable(MULTIPARTY);

        ////////////////////////////////////////////////////////////
        // Set-up of parameters
        ////////////////////////////////////////////////////////////

        // Initialize Public Key Containers for two parties A and B
        KeyPair<DCRTPoly> kp1;
        KeyPair<DCRTPoly> kp2;
        KeyPair<DCRTPoly> kp3;
        KeyPair<DCRTPoly> kpMultiparty;

        ////////////////////////////////////////////////////////////
        // Perform Key Generation Operation
        ////////////////////////////////////////////////////////////

        // Round 1 (party A)
        kp1          = cc->KeyGen();
        usint N      = 3;
        usint thresh = 2;

        auto kp1smap = cc->ShareKeys(kp1.secretKey, N, thresh, 1, sharing_scheme);

        // Generate evalmult key part for A
        auto evalMultKey = cc->KeySwitchGen(kp1.secretKey, kp1.secretKey);

        // Generate evalsum key part for A
        cc->EvalSumKeyGen(kp1.secretKey);
        auto evalSumKeys =
            std::make_shared<std::map<usint, EvalKey<DCRTPoly>>>(cc->GetEvalSumKeyMap(kp1.secretKey->GetKeyTag()));

        // Round 2 (party B)
        kp2 = cc->MultipartyKeyGen(kp1.publicKey);

        auto kp2smap      = cc->ShareKeys(kp2.secretKey, N, thresh, 2, sharing_scheme);
        auto evalMultKey2 = cc->MultiKeySwitchGen(kp2.secretKey, kp2.secretKey, evalMultKey);

        auto evalMultAB = cc->MultiAddEvalKeys(evalMultKey, evalMultKey2, kp2.publicKey->GetKeyTag());

        auto evalSumKeysB = cc->MultiEvalSumKeyGen(kp2.secretKey, evalSumKeys, kp2.publicKey->GetKeyTag());

        auto evalSumKeysAB = cc->MultiAddEvalSumKeys(evalSumKeys, evalSumKeysB, kp2.publicKey->GetKeyTag());

        kp3 = cc->MultipartyKeyGen(kp2.publicKey);

        auto kp3smap = cc->ShareKeys(kp3.secretKey, N, thresh, 3, sharing_scheme);

        auto evalMultKey3 = cc->MultiKeySwitchGen(kp3.secretKey, kp3.secretKey, evalMultAB);

        auto evalMultABC = cc->MultiAddEvalKeys(evalMultAB, evalMultKey3, kp3.publicKey->GetKeyTag());

        auto evalMultCABC = cc->MultiMultEvalKey(kp3.secretKey, evalMultABC, kp3.publicKey->GetKeyTag());

        auto evalSumKeysC = cc->MultiEvalSumKeyGen(kp3.secretKey, evalSumKeysB, kp3.publicKey->GetKeyTag());

        auto evalSumKeysJoin = cc->MultiAddEvalSumKeys(evalSumKeysC, evalSumKeysAB, kp3.publicKey->GetKeyTag());

        cc->InsertEvalSumKey(evalSumKeysJoin);

        auto evalMultBABC = cc->MultiMultEvalKey(kp2.secretKey, evalMultABC, kp3.publicKey->GetKeyTag());

        auto evalMultBCABC = cc->MultiAddEvalMultKeys(evalMultCABC, evalMultBABC, evalMultCABC->GetKeyTag());

        auto evalMultAABC = cc->MultiMultEvalKey(kp1.secretKey, evalMultABC, kp3.publicKey->GetKeyTag());

        auto evalMultFinal = cc->MultiAddEvalMultKeys(evalMultAABC, evalMultBCABC, evalMultAABC->GetKeyTag());

        cc->InsertEvalMultKey({evalMultFinal});

        ////////////////////////////////////////////////////////////
        // Encode source data
        ////////////////////////////////////////////////////////////
        std::vector<int64_t> vectorOfInts1 = {1, 2, 3, 4, 5, 6, 5, 4, 3, 2, 1, 0};
        std::vector<int64_t> vectorOfInts2 = {1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0};
        std::vector<int64_t> vectorOfInts3 = {2, 2, 3, 4, 5, 6, 7, 8, 9, 10, 0, 0};

        Plaintext plaintext1 = cc->MakePackedPlaintext(vectorOfInts1);
        Plaintext plaintext2 = cc->MakePackedPlaintext(vectorOfInts2);
        Plaintext plaintext3 = cc->MakePackedPlaintext(vectorOfInts3);

        // compute expected results in plain
        size_t encodedLength = vectorOfInts1.size();
        std::vector<int64_t> sumInput(encodedLength);
        std::vector<int64_t> multInput(encodedLength);
        std::vector<int64_t> evalSumInput(encodedLength);
        std::vector<int64_t> allTrue(encodedLength);
        std::vector<int64_t> tmp(encodedLength);

        for (size_t i = 0; i < encodedLength; i++) {
            sumInput[i]  = vectorOfInts1[i] + vectorOfInts2[i] + vectorOfInts3[i];
            multInput[i] = vectorOfInts1[i] * vectorOfInts3[i];
            if (i == 0)
                evalSumInput[encodedLength - i - 1] = vectorOfInts3[encodedLength - i - 1];
            else
                evalSumInput[encodedLength - i - 1] =
                    evalSumInput[encodedLength - i] + vectorOfInts3[encodedLength - i - 1];
        }

        ////////////////////////////////////////////////////////////
        // Encryption
        ////////////////////////////////////////////////////////////

        Ciphertext<DCRTPoly> ciphertext1;
        Ciphertext<DCRTPoly> ciphertext2;
        Ciphertext<DCRTPoly> ciphertext3;

        ciphertext1 = cc->Encrypt(kp3.publicKey, plaintext1);
        ciphertext2 = cc->Encrypt(kp3.publicKey, plaintext2);
        ciphertext3 = cc->Encrypt(kp3.publicKey, plaintext3);

        ////////////////////////////////////////////////////////////
        // Homomorphic Operations
        ////////////////////////////////////////////////////////////

        Ciphertext<DCRTPoly> ciphertextAdd12;
        Ciphertext<DCRTPoly> ciphertextAdd123;

        ciphertextAdd12  = cc->EvalAdd(ciphertext1, ciphertext2);
        ciphertextAdd123 = cc->EvalAdd(ciphertextAdd12, ciphertext3);

        auto ciphertextMult = cc->EvalMult(ciphertext1, ciphertext3);

        auto ciphertextEvalSum = cc->EvalSum(ciphertext3, batchSize);

        ////////////////////////////////////////////////////////////
        // Decryption after Accumulation Operation on Encrypted Data with Multiparty
        ////////////////////////////////////////////////////////////

        Plaintext plaintextAddNew1;
        Plaintext plaintextAddNew2;
        Plaintext plaintextAddNew3;

        DCRTPoly partialPlaintext1;
        DCRTPoly partialPlaintext2;
        DCRTPoly partialPlaintext3;

        Plaintext plaintextMultipartyNew;

        auto cryptoParams  = kp1.secretKey->GetCryptoParameters();
        auto elementParams = cryptoParams->GetElementParams();

        // Aborts - recovering kp1.secret key from the shares assuming party A dropped out (need a protocol to identify this)
        PrivateKey<DCRTPoly> kp1_recovered_sk = std::make_shared<PrivateKeyImpl<DCRTPoly>>(cc);

        cc->RecoverSharedKey(kp1_recovered_sk, kp1smap, N, thresh, sharing_scheme);

        // Distributed decryption

        // partial decryption by party A
        auto ciphertextPartial1 = cc->MultipartyDecryptLead({ciphertextAdd123}, kp1_recovered_sk);

        // partial decryption by party B
        auto ciphertextPartial2 = cc->MultipartyDecryptMain({ciphertextAdd123}, kp2.secretKey);

        // partial decryption by party C
        auto ciphertextPartial3 = cc->MultipartyDecryptMain({ciphertextAdd123}, kp3.secretKey);

        vector<Ciphertext<DCRTPoly>> partialCiphertextVec;
        partialCiphertextVec.push_back(ciphertextPartial1[0]);
        partialCiphertextVec.push_back(ciphertextPartial2[0]);
        partialCiphertextVec.push_back(ciphertextPartial3[0]);

        // Two partial decryptions are combined
        cc->MultipartyDecryptFusion(partialCiphertextVec, &plaintextMultipartyNew);

        plaintextMultipartyNew->SetLength(plaintext1->GetLength());

        Plaintext plaintextMultipartyMult;

        ciphertextPartial1 = cc->MultipartyDecryptLead({ciphertextMult}, kp1_recovered_sk);

        ciphertextPartial2 = cc->MultipartyDecryptMain({ciphertextMult}, kp2.secretKey);

        ciphertextPartial3 = cc->MultipartyDecryptMain({ciphertextMult}, kp3.secretKey);

        vector<Ciphertext<DCRTPoly>> partialCiphertextVecMult;
        partialCiphertextVecMult.push_back(ciphertextPartial1[0]);
        partialCiphertextVecMult.push_back(ciphertextPartial2[0]);
        partialCiphertextVecMult.push_back(ciphertextPartial3[0]);

        cc->MultipartyDecryptFusion(partialCiphertextVecMult, &plaintextMultipartyMult);

        plaintextMultipartyMult->SetLength(plaintext1->GetLength());

        Plaintext plaintextMultipartyEvalSum;

        ciphertextPartial1 = cc->MultipartyDecryptLead({ciphertextEvalSum}, kp1_recovered_sk);

        ciphertextPartial2 = cc->MultipartyDecryptMain({ciphertextEvalSum}, kp2.secretKey);

        ciphertextPartial3 = cc->MultipartyDecryptMain({ciphertextEvalSum}, kp3.secretKey);

        vector<Ciphertext<DCRTPoly>> partialCiphertextVecEvalSum;
        partialCiphertextVecEvalSum.push_back(ciphertextPartial1[0]);
        partialCiphertextVecEvalSum.push_back(ciphertextPartial2[0]);
        partialCiphertextVecEvalSum.push_back(ciphertextPartial3[0]);

        cc->MultipartyDecryptFusion(partialCiphertextVecEvalSum, &plaintextMultipartyEvalSum);

        plaintextMultipartyEvalSum->SetLength(plaintext1->GetLength());

        auto plaintextMultipartyNewVal     = plaintextMultipartyNew->GetPackedValue();
        auto plaintextMultipartyMultVal    = plaintextMultipartyMult->GetPackedValue();
        auto plaintextMultipartyEvalSumVal = plaintextMultipartyEvalSum->GetPackedValue();

        // compare expected and actual results for addition, multiplication and summation
        for (size_t i = 0; i < encodedLength; i++) {
            allTrue[i] = 0;
            tmp[i]     = abs(plaintextMultipartyNewVal[i] - sumInput[i]);
        }
        EXPECT_TRUE(tmp == allTrue) << "Addition failed";

        for (size_t i = 0; i < encodedLength; i++) {
            allTrue[i] = 0;
            tmp[i]     = abs(plaintextMultipartyMultVal[i] - multInput[i]);
        }
        EXPECT_TRUE(tmp == allTrue) << "Multiplication failed";

        for (size_t i = 0; i < encodedLength; i++) {
            allTrue[i] = 0;
            tmp[i]     = abs(plaintextMultipartyEvalSumVal[i] - evalSumInput[i]);
        }
        EXPECT_TRUE(tmp == allTrue) << "Summation failed";
    }
};

TEST_P(UTMultipartyAborts, THRESHFHE_ABORTS) {
    auto test = GetParam();
    RunBFVrns(test);
}

string secret_sharing_schemes[2] = {"additive", "shamir"};

INSTANTIATE_TEST_SUITE_P(THRESHFHE_ABORTS, UTMultipartyAborts, ::testing::ValuesIn(secret_sharing_schemes));
