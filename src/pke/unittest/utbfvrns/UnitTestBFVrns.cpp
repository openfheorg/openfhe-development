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
#include "UnitTestUtils.h"
#include "UnitTestCCParams.h"
#include "UnitTestCryptoContext.h"

#include <iostream>
#include <vector>
#include "gtest/gtest.h"
#include <iterator>

using namespace lbcrypto;

//===========================================================================================================
enum TEST_CASE_TYPE {
    EVAL_FAST_ROTATION = 0,
    COMPRESSED_BFV     = 1,
};

static std::ostream& operator<<(std::ostream& os, const TEST_CASE_TYPE& type) {
    std::string typeName;
    switch (type) {
        case EVAL_FAST_ROTATION:
            typeName = "EVAL_FAST_ROTATION";
            break;
        case COMPRESSED_BFV:
            typeName = "COMPRESSED_BFV";
            break;
        default:
            typeName = "UNKNOWN";
            break;
    }
    return os << typeName;
}
//===========================================================================================================
struct TEST_CASE_UTBFVRNS {
    TEST_CASE_TYPE testCaseType;
    // test case description - MUST BE UNIQUE
    std::string description;

    UnitTestCCParams params;

    // additional test case data
    // ........

    std::string buildTestName() const {
        std::stringstream ss;
        ss << testCaseType << "_" << description;
        return ss.str();
    }
    std::string toString() const {
        std::stringstream ss;
        ss << "testCaseType [" << testCaseType << "], " << params.toString();
        return ss.str();
    }
};

// this lambda provides a name to be printed for every test run by INSTANTIATE_TEST_SUITE_P.
// the name MUST be constructed from digits, letters and '_' only
static auto testName = [](const testing::TestParamInfo<TEST_CASE_UTBFVRNS>& test) {
    return test.param.buildTestName();
};

static std::ostream& operator<<(std::ostream& os, const TEST_CASE_UTBFVRNS& test) {
    return os << test.toString();
}
//===========================================================================================================
constexpr usint MULDEPTH = 7;
constexpr usint PTM      = 65537;
// clang-format off
static std::vector<TEST_CASE_UTBFVRNS> testCases = {
    // TestType,         Descr,  Scheme,        RDim, MultDepth, SModSize, DSize, BatchSz, SecKeyDist, MaxRelinSkDeg, FModSize, SecLvl, KSTech, ScalTech, LDigits, PtMod, StdDev, EvalAddCt, KSCt, MultTech,         EncTech, PREMode
    { EVAL_FAST_ROTATION, "01", {BFVRNS_SCHEME, DFLT, MULDEPTH,  DFLT,     DFLT,  DFLT,    DFLT,       DFLT,          DFLT,     DFLT,   BV,     DFLT,     DFLT,    PTM,   DFLT,   DFLT,      DFLT, HPSPOVERQLEVELED, DFLT,    DFLT}},
    { EVAL_FAST_ROTATION, "02", {BFVRNS_SCHEME, DFLT, MULDEPTH,  DFLT,     DFLT,  DFLT,    DFLT,       DFLT,          DFLT,     DFLT,   HYBRID, DFLT,     DFLT,    PTM,   DFLT,   DFLT,      DFLT, HPSPOVERQLEVELED, DFLT,    DFLT}},
    { EVAL_FAST_ROTATION, "03", {BFVRNS_SCHEME, DFLT, MULDEPTH,  DFLT,     DFLT,  DFLT,    DFLT,       DFLT,          DFLT,     DFLT,   BV,     DFLT,     DFLT,    PTM,   DFLT,   DFLT,      DFLT, HPSPOVERQ, DFLT,    DFLT}},
    { EVAL_FAST_ROTATION, "04", {BFVRNS_SCHEME, DFLT, MULDEPTH,  DFLT,     DFLT,  DFLT,    DFLT,       DFLT,          DFLT,     DFLT,   HYBRID, DFLT,     DFLT,    PTM,   DFLT,   DFLT,      DFLT, HPSPOVERQ, DFLT,    DFLT}},
    { EVAL_FAST_ROTATION, "05", {BFVRNS_SCHEME, DFLT, MULDEPTH,  DFLT,     DFLT,  DFLT,    DFLT,       DFLT,          DFLT,     DFLT,   BV,     DFLT,     DFLT,    PTM,   DFLT,   DFLT,      DFLT, HPS, DFLT,    DFLT}},
    { EVAL_FAST_ROTATION, "06", {BFVRNS_SCHEME, DFLT, MULDEPTH,  DFLT,     DFLT,  DFLT,    DFLT,       DFLT,          DFLT,     DFLT,   HYBRID, DFLT,     DFLT,    PTM,   DFLT,   DFLT,      DFLT, HPS, DFLT,    DFLT}},
    { EVAL_FAST_ROTATION, "07", {BFVRNS_SCHEME, DFLT, MULDEPTH,  DFLT,     DFLT,  DFLT,    DFLT,       DFLT,          DFLT,     DFLT,   BV,     DFLT,     DFLT,    PTM,   DFLT,   DFLT,      DFLT, BEHZ, DFLT,    DFLT}},
    { EVAL_FAST_ROTATION, "08", {BFVRNS_SCHEME, DFLT, MULDEPTH,  DFLT,     DFLT,  DFLT,    DFLT,       DFLT,          DFLT,     DFLT,   HYBRID, DFLT,     DFLT,    PTM,   DFLT,   DFLT,      DFLT, BEHZ, DFLT,    DFLT}},
    { COMPRESSED_BFV,     "01", {BFVRNS_SCHEME, DFLT, MULDEPTH,  DFLT,     DFLT,  DFLT,    DFLT,       DFLT,          DFLT,     DFLT,   BV,     DFLT,     DFLT,    PTM,   DFLT,   DFLT,      DFLT, HPSPOVERQLEVELED, DFLT,    DFLT}},
    { COMPRESSED_BFV,     "02", {BFVRNS_SCHEME, DFLT, MULDEPTH,  DFLT,     DFLT,  DFLT,    DFLT,       DFLT,          DFLT,     DFLT,   HYBRID, DFLT,     DFLT,    PTM,   DFLT,   DFLT,      DFLT, HPSPOVERQLEVELED, DFLT,    DFLT}},
    { COMPRESSED_BFV,     "03", {BFVRNS_SCHEME, DFLT, MULDEPTH,  DFLT,     DFLT,  DFLT,    DFLT,       DFLT,          DFLT,     DFLT,   BV,     DFLT,     DFLT,    PTM,   DFLT,   DFLT,      DFLT, HPSPOVERQ, DFLT,    DFLT}},
    { COMPRESSED_BFV,     "04", {BFVRNS_SCHEME, DFLT, MULDEPTH,  DFLT,     DFLT,  DFLT,    DFLT,       DFLT,          DFLT,     DFLT,   HYBRID, DFLT,     DFLT,    PTM,   DFLT,   DFLT,      DFLT, HPSPOVERQ, DFLT,    DFLT}},
    // ==========================================
};
// clang-format on
//===========================================================================================================
class UTBFVRNS : public ::testing::TestWithParam<TEST_CASE_UTBFVRNS> {
    using Element = DCRTPoly;

    // The precision after which we consider two values equal.
    // This is necessary because BFV works for approximate numbers.
    const double eps = EPSILON;

protected:
    void SetUp() {}

    void TearDown() {
        CryptoContextFactory<DCRTPoly>::ReleaseAllContexts();
    }

    void UnitTest_EvalFastRotation(const TEST_CASE_UTBFVRNS& testData, const std::string& failmsg = std::string()) {
        try {
            CryptoContext<Element> cc(UnitTestGenerateContext(testData.params));

            KeyPair<DCRTPoly> keyPair = cc->KeyGen();

            // Generate the relinearization key
            cc->EvalMultKeyGen(keyPair.secretKey);

            // Generate the rotation evaluation keys
            cc->EvalRotateKeyGen(keyPair.secretKey, {1, 2, -1, -2});

            std::vector<int64_t> vectorOfInts1 = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12};
            Plaintext plaintext1               = cc->MakePackedPlaintext(vectorOfInts1);
            auto ciphertext1                   = cc->Encrypt(keyPair.publicKey, plaintext1);

            std::vector<int64_t> vectorOfInts2 = {3, 2, 1, 4, 5, 6, 7, 8, 9, 10, 11, 12};
            Plaintext plaintext2               = cc->MakePackedPlaintext(vectorOfInts2);
            auto ciphertext2                   = cc->Encrypt(keyPair.publicKey, plaintext2);

            std::vector<int64_t> vectorOfInts3 = {1, 2, 5, 2, 5, 6, 7, 8, 9, 10, 11, 12};
            Plaintext plaintext3               = cc->MakePackedPlaintext(vectorOfInts3);
            auto ciphertext3                   = cc->Encrypt(keyPair.publicKey, plaintext3);

            // Homomorphic multiplications (do enough to drop some levels)
            auto ciphertextMul12      = cc->EvalMult(ciphertext1, ciphertext2);
            auto ciphertextMultResult = cc->EvalMult(ciphertextMul12, ciphertext3);
            ciphertextMultResult      = cc->EvalSquare(ciphertextMultResult);
            ciphertextMultResult      = cc->EvalSquare(ciphertextMultResult);

            auto digits      = cc->EvalFastRotationPrecompute(ciphertextMul12);
            auto digits2     = cc->EvalFastRotationPrecompute(ciphertextMultResult);
            const uint32_t M = cc->GetCyclotomicOrder();

            auto ciphertextRot1 = cc->EvalFastRotation(ciphertextMul12, 1, M, digits);
            auto ciphertextRot2 = cc->EvalFastRotation(ciphertextMul12, -1, M, digits);
            auto ciphertextRot3 = cc->EvalFastRotation(ciphertextMultResult, 2, M, digits2);
            auto ciphertextRot4 = cc->EvalFastRotation(ciphertextMultResult, -2, M, digits2);

            // EvalFastRotate +1 (left rotation)
            std::vector<int64_t> expectedResults1 = {4, 3, 16, 25, 36, 49, 64, 81, 100, 121, 144, 0};
            Plaintext plaintextRot1;
            cc->Decrypt(keyPair.secretKey, ciphertextRot1, &plaintextRot1);
            plaintextRot1->SetLength(vectorOfInts1.size());
            auto results1 = plaintextRot1->GetPackedValue();
            checkEquality(results1, expectedResults1, eps, failmsg + " EvalFastRotation(+1) failed");

            // EvalFastRotate -1 (right rotation)
            std::vector<int64_t> expectedResults2 = {0, 3, 4, 3, 16, 25, 36, 49, 64, 81, 100, 121};
            Plaintext plaintextRot2;
            cc->Decrypt(keyPair.secretKey, ciphertextRot2, &plaintextRot2);
            plaintextRot2->SetLength(vectorOfInts1.size());
            auto results2 = plaintextRot2->GetPackedValue();
            checkEquality(results2, expectedResults2, eps, failmsg + " EvalFastRotation(-1) failed");

            // EvalFastRotate +2 (left rotation)
            std::vector<int64_t> expectedResults3 = {-14912, -16,   15300, -29119, 3875, 16,
                                                     -2298,  15428, -8061, 5916,   0,    0};
            Plaintext plaintextRot3;
            cc->Decrypt(keyPair.secretKey, ciphertextRot3, &plaintextRot3);
            plaintextRot3->SetLength(vectorOfInts1.size());
            auto results3 = plaintextRot3->GetPackedValue();
            checkEquality(results3, expectedResults3, eps, failmsg + " EvalFastRotation(+2) failed");

            // EvalFastRotate -2 (right rotation)
            std::vector<int64_t> expectedResults4 = {0,     0,      81,   4096, -14912, -16,
                                                     15300, -29119, 3875, 16,   -2298,  15428};
            Plaintext plaintextRot4;
            cc->Decrypt(keyPair.secretKey, ciphertextRot4, &plaintextRot4);
            plaintextRot4->SetLength(vectorOfInts1.size());
            auto results4 = plaintextRot4->GetPackedValue();
            checkEquality(results4, expectedResults4, eps, failmsg + " EvalFastRotation(-2) failed");
        }
        catch (std::exception& e) {
            std::cerr << "Exception thrown from " << __func__ << "(): " << e.what() << std::endl;
            // make it fail
            EXPECT_TRUE(0 == 1) << failmsg;
        }
        catch (...) {
            UNIT_TEST_HANDLE_ALL_EXCEPTIONS;
        }
    }

    void UnitTest_CompressedBFV(const TEST_CASE_UTBFVRNS& testData, const std::string& failmsg = std::string()) {
        try {
            CryptoContext<Element> cc(UnitTestGenerateContext(testData.params));

            KeyPair<DCRTPoly> keyPair = cc->KeyGen();

            // Generate the relinearization key
            cc->EvalMultKeyGen(keyPair.secretKey);

            // Generate the rotation evaluation keys
            cc->EvalRotateKeyGen(keyPair.secretKey, {1});

            std::vector<int64_t> vectorOfInts1 = {1, 2, 3, 4, 5, 6, 7, 8, 9, 11, 11, 12};
            Plaintext plaintext1               = cc->MakePackedPlaintext(vectorOfInts1, 1, 1);
            auto ciphertext1                   = cc->Encrypt(keyPair.publicKey, plaintext1);

            std::vector<int64_t> vectorOfInts2 = {3, 2, 1, 4, 5, 6, 7, 8, 9, 10, 11, 12};
            Plaintext plaintext2               = cc->MakePackedPlaintext(vectorOfInts2, 1, 1);
            auto ciphertext2                   = cc->Encrypt(keyPair.publicKey, plaintext2);

            std::vector<int64_t> vectorOfInts3 = {1, 2, 5, 2, 5, 6, 7, 8, 9, 9, 11, 12};
            Plaintext plaintext3               = cc->MakePackedPlaintext(vectorOfInts3, 1, 1);
            auto ciphertext3                   = cc->Encrypt(keyPair.publicKey, plaintext3);

            // Homomorphic multiplications (do enough to drop some levels)
            auto ciphertextMul12           = cc->EvalMult(ciphertext1, ciphertext2);
            auto ciphertextMultResult      = cc->EvalMult(ciphertextMul12, ciphertext3);
            auto ciphertextMultCompressed1 = cc->Compress(ciphertextMultResult, 1);
            auto ciphertextMultCompressed2 = cc->Compress(ciphertextMultResult, 2);
            auto ciphertextSquareResult    = cc->EvalSquare(ciphertext1);

            auto digits      = cc->EvalFastRotationPrecompute(ciphertextMul12);
            const uint32_t M = cc->GetCyclotomicOrder();

            auto ciphertextRot1 = cc->EvalFastRotation(ciphertextMul12, 1, M, digits);
            auto ciphertextRot2 = cc->EvalRotate(ciphertextMul12, 1);

            auto ciphertextPtxtMult = cc->EvalMult(ciphertext1, plaintext2);

            auto ciphertextPtxtAdd = cc->EvalAdd(ciphertext1, plaintext2);

            // Multiplication
            std::vector<int64_t> expectedResults1 = {3, 8, 15, 32, 125, 216, 343, 512, 729, 990, 1331, 1728};
            Plaintext plaintextMult;
            cc->Decrypt(keyPair.secretKey, ciphertextMultResult, &plaintextMult);
            plaintextMult->SetLength(vectorOfInts1.size());
            auto results1 = plaintextMult->GetPackedValue();
            checkEquality(results1, expectedResults1, eps, failmsg + " EvalMult failed");

            // Squaring
            expectedResults1 = {1, 4, 9, 16, 25, 36, 49, 64, 81, 121, 121, 144};
            Plaintext plaintextSquare;
            cc->Decrypt(keyPair.secretKey, ciphertextSquareResult, &plaintextSquare);
            plaintextSquare->SetLength(vectorOfInts1.size());
            results1 = plaintextSquare->GetPackedValue();
            checkEquality(results1, expectedResults1, eps, failmsg + " EvalSquare failed");

            // Fast Rotation
            expectedResults1 = {4, 3, 16, 25, 36, 49, 64, 81, 110, 121, 144, 0};
            Plaintext plaintextRot1;
            cc->Decrypt(keyPair.secretKey, ciphertextRot1, &plaintextRot1);
            plaintextRot1->SetLength(vectorOfInts1.size());
            results1 = plaintextRot1->GetPackedValue();
            checkEquality(results1, expectedResults1, eps, failmsg + " EvalFastRotation failed");

            // Rotation
            expectedResults1 = {4, 3, 16, 25, 36, 49, 64, 81, 110, 121, 144, 0};
            Plaintext plaintextRot2;
            cc->Decrypt(keyPair.secretKey, ciphertextRot2, &plaintextRot2);
            plaintextRot2->SetLength(vectorOfInts1.size());
            results1 = plaintextRot2->GetPackedValue();
            checkEquality(results1, expectedResults1, eps, failmsg + " EvalRotate failed");

            // Multiplication by plaintext
            expectedResults1 = {3, 4, 3, 16, 25, 36, 49, 64, 81, 110, 121, 144};
            Plaintext plaintextPtxtMult;
            cc->Decrypt(keyPair.secretKey, ciphertextPtxtMult, &plaintextPtxtMult);
            plaintextPtxtMult->SetLength(vectorOfInts1.size());
            results1 = plaintextPtxtMult->GetPackedValue();
            checkEquality(results1, expectedResults1, eps, failmsg + " EvalMult with plaintext failed");

            // Addition of a plaintext
            expectedResults1 = {4, 4, 4, 8, 10, 12, 14, 16, 18, 21, 22, 24};
            Plaintext plaintextPtxtAdd;
            cc->Decrypt(keyPair.secretKey, ciphertextPtxtAdd, &plaintextPtxtAdd);
            plaintextPtxtAdd->SetLength(vectorOfInts1.size());
            results1 = plaintextPtxtAdd->GetPackedValue();
            checkEquality(results1, expectedResults1, eps, failmsg + " EvalAdd with plaintext failed");

            // Multiplication - compressed to 1
            expectedResults1 = {3, 8, 15, 32, 125, 216, 343, 512, 729, 990, 1331, 1728};
            Plaintext plaintextMultComp1;
            cc->Decrypt(keyPair.secretKey, ciphertextMultCompressed1, &plaintextMultComp1);
            plaintextMultComp1->SetLength(vectorOfInts1.size());
            results1 = plaintextMultComp1->GetPackedValue();
            checkEquality(results1, expectedResults1, eps, failmsg + " EvalMult compressed to 1 RNS limb failed");

            // Multiplication - compressed to 2
            expectedResults1 = {3, 8, 15, 32, 125, 216, 343, 512, 729, 990, 1331, 1728};
            Plaintext plaintextMultComp2;
            cc->Decrypt(keyPair.secretKey, ciphertextMultCompressed2, &plaintextMultComp2);
            plaintextMultComp2->SetLength(vectorOfInts1.size());
            results1 = plaintextMultComp2->GetPackedValue();
            checkEquality(results1, expectedResults1, eps, failmsg + " EvalMult compressed to 2 RNS limbs failed");
        }
        catch (std::exception& e) {
            std::cerr << "Exception thrown from " << __func__ << "(): " << e.what() << std::endl;
            // make it fail
            EXPECT_TRUE(0 == 1) << failmsg;
        }
        catch (...) {
            UNIT_TEST_HANDLE_ALL_EXCEPTIONS;
        }
    }
};
//===========================================================================================================
TEST_P(UTBFVRNS, BFVRNS) {
    setupSignals();
    auto test = GetParam();

    switch (test.testCaseType) {
        case EVAL_FAST_ROTATION:
            UnitTest_EvalFastRotation(test, test.buildTestName());
            break;
        case COMPRESSED_BFV:
            UnitTest_CompressedBFV(test, test.buildTestName());
            break;
        default:
            break;
    }
}

INSTANTIATE_TEST_SUITE_P(UnitTests, UTBFVRNS, ::testing::ValuesIn(testCases), testName);
