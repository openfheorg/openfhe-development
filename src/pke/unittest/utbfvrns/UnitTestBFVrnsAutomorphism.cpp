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

#include <algorithm>
#include <iostream>
#include <vector>
#include "UnitTestUtils.h"
#include "gtest/gtest.h"

#include "cryptocontext.h"

#include "encoding/encodings.h"

#include "utils/debug.h"

using namespace lbcrypto;

namespace {
class UTBFVRNS_AUTOMORPHISM : public ::testing::Test {
protected:
    void SetUp() {}

    void TearDown() {
        CryptoContextFactory<DCRTPoly>::ReleaseAllContexts();
    }

public:
};

const std::vector<int64_t> vector8{1, 2, 3, 4, 5, 6, 7, 8};
const std::vector<int64_t> vector10{1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
const std::vector<int64_t> vectorFailure{1, 2, 3, 4};
const std::vector<usint> initIndexList{3, 5, 7, 9, 11, 13, 15};
const usint invalidIndexAutomorphism = 4;
const int64_t vector8Sum             = std::accumulate(vector8.begin(), vector8.end(), int64_t(0));  // 36

enum TEST_ESTIMATED_RESULT {
    SUCCESS,
    INVALID_INPUT_DATA,
    INVALID_PRIVATE_KEY,
    INVALID_PUBLIC_KEY,
    INVALID_EVAL_KEY,
    INVALID_INDEX,
    INVALID_BATCH_SIZE,
    NO_KEY_GEN_CALL
};

}  // anonymous namespace

//================================================================================================

// declaration for Automorphism Test on BFVrns scheme with polynomial operation
// in power of 2 cyclotomics.
std::vector<int64_t> BFVrnsAutomorphismPackedArray(usint i, TEST_ESTIMATED_RESULT testResult = SUCCESS) {
    using Element = DCRTPoly;
    CCParams<CryptoContextBFVRNS> parameters;
    parameters.SetPlaintextModulus(65537);
    parameters.SetStandardDeviation(4);
    parameters.SetScalingModSize(60);

    CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);

    // Initialize the public key containers.
    KeyPair<Element> kp = cc->KeyGen();

    i                             = (INVALID_INDEX == testResult) ? invalidIndexAutomorphism : i;
    std::vector<int64_t> inputVec = (INVALID_INPUT_DATA == testResult) ? vectorFailure : vector8;
    Plaintext intArray            = cc->MakePackedPlaintext(inputVec);

    Ciphertext<Element> ciphertext = (INVALID_PUBLIC_KEY == testResult) ?
                                         cc->Encrypt(PublicKey<Element>(nullptr), intArray) :
                                         cc->Encrypt(kp.publicKey, intArray);

    std::vector<usint> indexList(initIndexList);

    auto evalKeys = (INVALID_PRIVATE_KEY == testResult) ?
                        cc->EvalAutomorphismKeyGen(PrivateKey<Element>(nullptr), indexList) :
                        cc->EvalAutomorphismKeyGen(kp.secretKey, indexList);

    std::map<usint, EvalKey<Element>> emptyEvalKeys;
    Ciphertext<Element> p1 = (INVALID_EVAL_KEY == testResult) ? cc->EvalAutomorphism(ciphertext, i, emptyEvalKeys) :
                                                                cc->EvalAutomorphism(ciphertext, i, *evalKeys);

    Plaintext intArrayNew;
    cc->Decrypt(kp.secretKey, p1, &intArrayNew);

    return intArrayNew->GetPackedValue();
}

TEST_F(UTBFVRNS_AUTOMORPHISM, Test_BFVrns_Automorphism_PowerOf2) {
    PackedEncoding::Destroy();

    for (auto index : initIndexList) {
        auto morphedVector = BFVrnsAutomorphismPackedArray(index);
        EXPECT_TRUE(CheckAutomorphism(morphedVector, vector8));
    }
}

TEST_F(UTBFVRNS_AUTOMORPHISM, Test_BFVrns_Automorphism_PowerOf2_INVALID_INPUT_DATA) {
    PackedEncoding::Destroy();

    for (auto index : initIndexList) {
        auto morphedVector = BFVrnsAutomorphismPackedArray(index, INVALID_INPUT_DATA);
        EXPECT_FALSE(CheckAutomorphism(morphedVector, vector8));
    }
}

TEST_F(UTBFVRNS_AUTOMORPHISM, Test_BFVrns_Automorphism_PowerOf2_INVALID_PRIVATE_KEY) {
    PackedEncoding::Destroy();

    try {
        for (auto index : initIndexList) {
            auto morphedVector = BFVrnsAutomorphismPackedArray(index, INVALID_PRIVATE_KEY);
            EXPECT_EQ(0, 1);
        }
    }
    catch (const std::exception& e) {
        // std::cout << "Test_BFVrns_Automorphism_PowerOf2_INVALID_PRIVATE_KEY exception: " << e.what() << std::endl;
        EXPECT_EQ(1, 1);
    }
}

TEST_F(UTBFVRNS_AUTOMORPHISM, Test_BFVrns_Automorphism_PowerOf2_INVALID_PUBLIC_KEY) {
    PackedEncoding::Destroy();

    try {
        for (auto index : initIndexList) {
            auto morphedVector = BFVrnsAutomorphismPackedArray(index, INVALID_PUBLIC_KEY);
            EXPECT_EQ(0, 1);
        }
    }
    catch (const std::exception& e) {
        // std::cout << "Test_BFVrns_Automorphism_PowerOf2_INVALID_PUBLIC_KEY exception: " << e.what() << std::endl;
        EXPECT_EQ(1, 1);
    }
}

TEST_F(UTBFVRNS_AUTOMORPHISM, Test_BFVrns_Automorphism_PowerOf2_INVALID_EVAL_KEY) {
    PackedEncoding::Destroy();

    try {
        for (auto index : initIndexList) {
            auto morphedVector = BFVrnsAutomorphismPackedArray(index, INVALID_EVAL_KEY);
            EXPECT_EQ(0, 1);
        }
    }
    catch (const std::exception& e) {
        // std::cout << "Test_BFVrns_Automorphism_PowerOf2_INVALID_EVAL_KEY exception: " << e.what() << std::endl;
        EXPECT_EQ(1, 1);
    }
}

TEST_F(UTBFVRNS_AUTOMORPHISM, Test_BFVrns_Automorphism_PowerOf2_INVALID_INDEX) {
    PackedEncoding::Destroy();

    try {
        for (auto index : initIndexList) {
            auto morphedVector = BFVrnsAutomorphismPackedArray(index, INVALID_INDEX);
            EXPECT_EQ(0, 1);
        }
    }
    catch (const std::exception& e) {
        // std::cout << "Test_BFVrns_Automorphism_PowerOf2_INVALID_INDEX exception: " << e.what() << std::endl;
        EXPECT_EQ(1, 1);
    }
}
