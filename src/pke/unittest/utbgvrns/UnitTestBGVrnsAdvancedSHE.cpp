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

#if !defined(_MSC_VER)

    #include "UnitTestUtils.h"
    #include "UnitTestCCParams.h"
    #include "UnitTestCryptoContext.h"

    #include <iostream>
    #include <vector>
    #include "gtest/gtest.h"

using namespace lbcrypto;

//===========================================================================================================
enum TEST_CASE_TYPE {
    EVAL_MULT_SINGLE = 0,
    EVAL_ADD_SINGLE,
};

static std::ostream& operator<<(std::ostream& os, const TEST_CASE_TYPE& type) {
    std::string typeName;
    switch (type) {
        case EVAL_MULT_SINGLE:
            typeName = "EVAL_MULT_SINGLE";
            break;
        case EVAL_ADD_SINGLE:
            typeName = "EVAL_ADD_SINGLE";
            break;
        default:
            typeName = "UNKNOWN";
            break;
    }
    return os << typeName;
}
//===========================================================================================================
struct TEST_CASE_UTBGVRNS_SHEADVANCED {
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
static auto testName = [](const testing::TestParamInfo<TEST_CASE_UTBGVRNS_SHEADVANCED>& test) {
    return test.param.buildTestName();
};

static std::ostream& operator<<(std::ostream& os, const TEST_CASE_UTBGVRNS_SHEADVANCED& test) {
    return os << test.toString();
}
//===========================================================================================================
constexpr usint RING_DIM = 8192;
constexpr usint PTM      = 20;
constexpr usint DSIZE    = 4;
constexpr double STD_DEV = 3.19;

// clang-format off
static std::vector<TEST_CASE_UTBGVRNS_SHEADVANCED> testCasesUTBGVRNS_SHEADVANCED = {
    // TestType,       Descr,  Scheme,        RDim,     MultDepth, SModSize, DSize, BatchSz, SecKeyDist, MaxRelinSkDeg, FModSize, SecLvl, KSTech, ScalTech,        LDigits, PtMod, StdDev,  EvalAddCt, KSCt, MultTech, EncTech, PREMode
    { EVAL_MULT_SINGLE, "01", {BGVRNS_SCHEME, RING_DIM, DFLT,      DFLT,     DSIZE, DFLT,    DFLT,       DFLT,          DFLT,     DFLT,   DFLT,   FLEXIBLEAUTO,    DFLT,    PTM,   STD_DEV, DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { EVAL_MULT_SINGLE, "02", {BGVRNS_SCHEME, RING_DIM, DFLT,      DFLT,     DSIZE, DFLT,    DFLT,       DFLT,          DFLT,     DFLT,   DFLT,   FIXEDMANUAL,     DFLT,    PTM,   STD_DEV, DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { EVAL_MULT_SINGLE, "03", {BGVRNS_SCHEME, RING_DIM, DFLT,      DFLT,     DSIZE, DFLT,    DFLT,       DFLT,          DFLT,     DFLT,   DFLT,   FIXEDAUTO,       DFLT,    PTM,   STD_DEV, DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { EVAL_MULT_SINGLE, "04", {BGVRNS_SCHEME, RING_DIM, DFLT,      DFLT,     DSIZE, DFLT,    DFLT,       DFLT,          DFLT,     DFLT,   DFLT,   FLEXIBLEAUTOEXT, DFLT,    PTM,   STD_DEV, DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    // ==========================================
    // TestType,      Descr,  Scheme,        RDim,     MultDepth, SModSize, DSize, BatchSz, SecKeyDist, MaxRelinSkDeg,  FModSize, SecLvl, KSTech, ScalTech,        LDigits, PtMod, StdDev,  EvalAddCt, KSCt, MultTech, EncTech, PREMode
    { EVAL_ADD_SINGLE, "01", {BGVRNS_SCHEME, RING_DIM, DFLT,      DFLT,     DSIZE, DFLT,    DFLT,       DFLT,           DFLT,     DFLT,   DFLT,   FLEXIBLEAUTO,    DFLT,    PTM,   STD_DEV, DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { EVAL_ADD_SINGLE, "02", {BGVRNS_SCHEME, RING_DIM, DFLT,      DFLT,     DSIZE, DFLT,    DFLT,       DFLT,           DFLT,     DFLT,   DFLT,   FIXEDMANUAL,     DFLT,    PTM,   STD_DEV, DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { EVAL_ADD_SINGLE, "03", {BGVRNS_SCHEME, RING_DIM, DFLT,      DFLT,     DSIZE, DFLT,    DFLT,       DFLT,           DFLT,     DFLT,   DFLT,   FIXEDAUTO,       DFLT,    PTM,   STD_DEV, DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { EVAL_ADD_SINGLE, "04", {BGVRNS_SCHEME, RING_DIM, DFLT,      DFLT,     DSIZE, DFLT,    DFLT,       DFLT,           DFLT,     DFLT,   DFLT,   FLEXIBLEAUTOEXT, DFLT,    PTM,   STD_DEV, DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
};
// clang-format on
//===========================================================================================================
class UTBGVRNS_SHEADVANCED : public ::testing::TestWithParam<TEST_CASE_UTBGVRNS_SHEADVANCED> {
    using Element = DCRTPoly;

protected:
    void SetUp() {}

    void TearDown() {
        CryptoContextFactory<DCRTPoly>::ReleaseAllContexts();
    }

    void UnitTest_EvalMultSingle(const TEST_CASE_UTBGVRNS_SHEADVANCED& testData,
                                 const std::string& failmsg = std::string()) {
        try {
            CryptoContext<Element> cc(UnitTestGenerateContext(testData.params));

            // Initialize the public key containers.
            KeyPair<Element> kp = cc->KeyGen();
            cc->EvalMultKeyGen(kp.secretKey);

            std::vector<int64_t> vectorOfInts1          = {2};
            Plaintext intArray1                         = cc->MakeCoefPackedPlaintext(vectorOfInts1);
            std::vector<int64_t> vectorOfInts2          = {3};
            Plaintext intArray2                         = cc->MakeCoefPackedPlaintext(vectorOfInts2);
            std::vector<int64_t> vectorOfExpectedValues = {6};  // = vectorOfInts1 * vectorOfInts2
            Plaintext expectedValues                    = cc->MakeCoefPackedPlaintext(vectorOfExpectedValues);

            Ciphertext<Element> ciphertext1 = cc->Encrypt(kp.publicKey, intArray1);
            Ciphertext<Element> ciphertext2 = cc->Encrypt(kp.publicKey, intArray2);
            Ciphertext<Element> cResult     = cc->EvalMult(ciphertext1, ciphertext2);

            KeyPair<Element> newKp          = cc->KeyGen();
            EvalKey<Element> keySwitchHint2 = cc->KeySwitchGen(kp.secretKey, newKp.secretKey);
            cc->KeySwitchInPlace(cResult, keySwitchHint2);

            Plaintext results;
            cc->Decrypt(newKp.secretKey, cResult, &results);
            results->SetLength(expectedValues->GetLength());

            EXPECT_TRUE(checkEquality(results->GetCoefPackedValue(), expectedValues->GetCoefPackedValue()));
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

    void UnitTest_EvalAddSingle(const TEST_CASE_UTBGVRNS_SHEADVANCED& testData,
                                const std::string& failmsg = std::string()) {
        try {
            CryptoContext<Element> cc(UnitTestGenerateContext(testData.params));

            // Initialize the public key containers.
            KeyPair<Element> kp = cc->KeyGen();

            std::vector<int64_t> vectorOfInts1          = {2, 3, 1, 4};
            Plaintext intArray1                         = cc->MakeCoefPackedPlaintext(vectorOfInts1);
            std::vector<int64_t> vectorOfInts2          = {3, 6, 3, 1};
            Plaintext intArray2                         = cc->MakeCoefPackedPlaintext(vectorOfInts2);
            std::vector<int64_t> vectorOfExpectedValues = {5, 9, 4, 5};  // = vectorOfInts1 + vectorOfInts2
            Plaintext expectedValues                    = cc->MakeCoefPackedPlaintext(vectorOfExpectedValues);

            Ciphertext<Element> ciphertext1 = cc->Encrypt(kp.publicKey, intArray1);
            Ciphertext<Element> ciphertext2 = cc->Encrypt(kp.publicKey, intArray2);
            Ciphertext<Element> cResult     = cc->EvalAdd(ciphertext1, ciphertext2);

            Plaintext results;
            cc->Decrypt(kp.secretKey, cResult, &results);
            results->SetLength(expectedValues->GetLength());

            EXPECT_TRUE(checkEquality(results->GetCoefPackedValue(), expectedValues->GetCoefPackedValue()));
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
TEST_P(UTBGVRNS_SHEADVANCED, SHEADVANCED) {
    setupSignals();
    auto test = GetParam();

    switch (test.testCaseType) {
        case EVAL_MULT_SINGLE:
            UnitTest_EvalMultSingle(test, test.buildTestName());
            break;
        case EVAL_ADD_SINGLE:
            UnitTest_EvalAddSingle(test, test.buildTestName());
            break;
        default:
            break;
    }
}

INSTANTIATE_TEST_SUITE_P(UnitTests, UTBGVRNS_SHEADVANCED, ::testing::ValuesIn(testCasesUTBGVRNS_SHEADVANCED), testName);

#endif
