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

#include "UnitTestUtils.h"
#include "UnitTestCCParams.h"
#include "UnitTestCryptoContext.h"
#include "utils/exception.h"

#include "include/gtest/gtest.h"
#include <iostream>
#include <sstream>
#include <vector>
#include <cxxabi.h>
#include "utils/demangle.h"


using namespace lbcrypto;

//===========================================================================================================
enum TEST_CASE_TYPE {
    STRING_TEST = 0,
    COEF_PACKED_TEST,
};

static std::ostream& operator<<(std::ostream& os, const TEST_CASE_TYPE& type) {
    std::string typeName;
    switch (type) {
    case STRING_TEST:
        typeName = "STRING_TEST";
        break;
    case COEF_PACKED_TEST:
        typeName = "COEF_PACKED_TEST";
        break;
    default:
        typeName = "UNKNOWN";
        break;
    }
    return os << typeName;
}
//===========================================================================================================
struct TEST_CASE_Encrypt_Decrypt {
    TEST_CASE_TYPE testCaseType;
    // test case description - MUST BE UNIQUE
    std::string description;

    UnitTestCCParams  params;

    // additional test case data


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
static auto testName = [](const testing::TestParamInfo<TEST_CASE_Encrypt_Decrypt>& test) {
    return test.param.buildTestName();
};

static std::ostream& operator<<(std::ostream& os, const TEST_CASE_Encrypt_Decrypt& test) {
    return os << test.toString();
}
//===========================================================================================================
constexpr usint BATCH = 16;
constexpr usint BV_DSIZE = 4;
// clang-format off
static std::vector<TEST_CASE_Encrypt_Decrypt> testCases = {
    // TestType,  Descr, Scheme,         RDim, MultDepth, SModSize, DSize,    BatchSz, SecKeyDist,      MaxRelinSkDeg, FModSize, SecLvl,       KSTech, ScalTech,        LDigits, PtMod, StdDev, EvalAddCt, EvalMultCt, KSCt, MultTech,         EncTech
    { STRING_TEST, "01", {BGVRNS_SCHEME, 256,  2,         59,       BV_DSIZE, BATCH,   GAUSSIAN,        1,             60,       HEStd_NotSet, BV,     FIXEDMANUAL,     DFLT,    256,   DFLT,   DFLT,      0,          DFLT, DFLT,             STANDARD} },
    { STRING_TEST, "02", {BGVRNS_SCHEME, 256,  2,         59,       BV_DSIZE, BATCH,   GAUSSIAN,        1,             60,       HEStd_NotSet, BV,     FIXEDAUTO,       DFLT,    256,   DFLT,   DFLT,      0,          DFLT, DFLT,             STANDARD} },
    { STRING_TEST, "03", {BGVRNS_SCHEME, 256,  2,         59,       BV_DSIZE, BATCH,   GAUSSIAN,        1,             60,       HEStd_NotSet, BV,     FLEXIBLEAUTO,    DFLT,    256,   DFLT,   DFLT,      0,          DFLT, DFLT,             STANDARD} },
    { STRING_TEST, "04", {BGVRNS_SCHEME, 256,  2,         59,       BV_DSIZE, BATCH,   GAUSSIAN,        1,             60,       HEStd_NotSet, BV,     FLEXIBLEAUTOEXT, DFLT,    256,   DFLT,   DFLT,      0,          DFLT, DFLT,             STANDARD} },
    { STRING_TEST, "05", {BGVRNS_SCHEME, 256,  2,         59,       BV_DSIZE, BATCH,   UNIFORM_TERNARY, 1,             60,       HEStd_NotSet, BV,     FIXEDMANUAL,     DFLT,    256,   DFLT,   DFLT,      0,          DFLT, DFLT,             STANDARD} },
    { STRING_TEST, "06", {BGVRNS_SCHEME, 256,  2,         59,       BV_DSIZE, BATCH,   UNIFORM_TERNARY, 1,             60,       HEStd_NotSet, BV,     FIXEDAUTO,       DFLT,    256,   DFLT,   DFLT,      0,          DFLT, DFLT,             STANDARD} },
    { STRING_TEST, "07", {BGVRNS_SCHEME, 256,  2,         59,       BV_DSIZE, BATCH,   UNIFORM_TERNARY, 1,             60,       HEStd_NotSet, BV,     FLEXIBLEAUTO,    DFLT,    256,   DFLT,   DFLT,      0,          DFLT, DFLT,             STANDARD} },
    { STRING_TEST, "08", {BGVRNS_SCHEME, 256,  2,         59,       BV_DSIZE, BATCH,   UNIFORM_TERNARY, 1,             60,       HEStd_NotSet, BV,     FLEXIBLEAUTOEXT, DFLT,    256,   DFLT,   DFLT,      0,          DFLT, DFLT,             STANDARD} },
    { STRING_TEST, "09", {BFVRNS_SCHEME, DFLT, DFLT,      60,       20,       BATCH,   GAUSSIAN,        DFLT,          DFLT,     DFLT,         BV,     FIXEDMANUAL,     DFLT,    256,   DFLT,   DFLT,      2,          DFLT, HPS,              STANDARD} },
    { STRING_TEST, "10", {BFVRNS_SCHEME, DFLT, DFLT,      60,       20,       BATCH,   UNIFORM_TERNARY, DFLT,          DFLT,     DFLT,         BV,     FIXEDMANUAL,     DFLT,    256,   DFLT,   DFLT,      2,          DFLT, BEHZ,             STANDARD} },
    { STRING_TEST, "11", {BFVRNS_SCHEME, DFLT, DFLT,      60,       20,       BATCH,   GAUSSIAN,        DFLT,          DFLT,     DFLT,         BV,     FIXEDMANUAL,     DFLT,    256,   DFLT,   DFLT,      2,          DFLT, HPSPOVERQ,        STANDARD} },
    { STRING_TEST, "12", {BFVRNS_SCHEME, DFLT, DFLT,      60,       20,       BATCH,   GAUSSIAN,        DFLT,          DFLT,     DFLT,         BV,     FIXEDMANUAL,     DFLT,    256,   DFLT,   DFLT,      2,          DFLT, HPSPOVERQLEVELED, STANDARD} },
    { STRING_TEST, "13", {BFVRNS_SCHEME, DFLT, DFLT,      60,       20,       BATCH,   GAUSSIAN,        DFLT,          DFLT,     DFLT,         BV,     FIXEDMANUAL,     DFLT,    256,   DFLT,   DFLT,      2,          DFLT, HPS,              POVERQ}   },
    { STRING_TEST, "14", {BFVRNS_SCHEME, DFLT, DFLT,      60,       20,       BATCH,   UNIFORM_TERNARY, DFLT,          DFLT,     DFLT,         BV,     FIXEDMANUAL,     DFLT,    256,   DFLT,   DFLT,      2,          DFLT, BEHZ,             POVERQ}   },
    { STRING_TEST, "15", {BFVRNS_SCHEME, DFLT, DFLT,      60,       20,       BATCH,   GAUSSIAN,        DFLT,          DFLT,     DFLT,         BV,     FIXEDMANUAL,     DFLT,    256,   DFLT,   DFLT,      2,          DFLT, HPSPOVERQ,        POVERQ}   },
    { STRING_TEST, "16", {BFVRNS_SCHEME, DFLT, DFLT,      60,       20,       BATCH,   GAUSSIAN,        DFLT,          DFLT,     DFLT,         BV,     FIXEDMANUAL,     DFLT,    256,   DFLT,   DFLT,      2,          DFLT, HPSPOVERQLEVELED, POVERQ}   },
    // ==========================================
    // TestType,       Descr, Scheme,         RDim, MultDepth, SModSize, DSize,    BatchSz, SecKeyDist,      MaxRelinSkDeg, FModSize, SecLvl,       KSTech, ScalTech,        LDigits, PtMod, StdDev, EvalAddCt, EvalMultCt, KSCt, MultTech,         EncTech
    { COEF_PACKED_TEST, "01", {BGVRNS_SCHEME, 64,   2,         59,       BV_DSIZE, BATCH,   GAUSSIAN,        1,             60,       HEStd_NotSet, BV,     FIXEDMANUAL,     DFLT,    512,   DFLT,   DFLT,      0,          DFLT, DFLT,             STANDARD} },
    { COEF_PACKED_TEST, "02", {BGVRNS_SCHEME, 64,   2,         59,       BV_DSIZE, BATCH,   GAUSSIAN,        1,             60,       HEStd_NotSet, BV,     FIXEDAUTO,       DFLT,    512,   DFLT,   DFLT,      0,          DFLT, DFLT,             STANDARD} },
    { COEF_PACKED_TEST, "03", {BGVRNS_SCHEME, 64,   2,         59,       BV_DSIZE, BATCH,   GAUSSIAN,        1,             60,       HEStd_NotSet, BV,     FLEXIBLEAUTO,    DFLT,    512,   DFLT,   DFLT,      0,          DFLT, DFLT,             STANDARD} },
    { COEF_PACKED_TEST, "04", {BGVRNS_SCHEME, 64,   2,         59,       BV_DSIZE, BATCH,   GAUSSIAN,        1,             60,       HEStd_NotSet, BV,     FLEXIBLEAUTOEXT, DFLT,    512,   DFLT,   DFLT,      0,          DFLT, DFLT,             STANDARD} },
    { COEF_PACKED_TEST, "05", {BGVRNS_SCHEME, 64,   2,         59,       BV_DSIZE, BATCH,   UNIFORM_TERNARY, 1,             60,       HEStd_NotSet, BV,     FIXEDMANUAL,     DFLT,    512,   DFLT,   DFLT,      0,          DFLT, DFLT,             STANDARD} },
    { COEF_PACKED_TEST, "06", {BGVRNS_SCHEME, 64,   2,         59,       BV_DSIZE, BATCH,   UNIFORM_TERNARY, 1,             60,       HEStd_NotSet, BV,     FIXEDAUTO,       DFLT,    512,   DFLT,   DFLT,      0,          DFLT, DFLT,             STANDARD} },
    { COEF_PACKED_TEST, "07", {BGVRNS_SCHEME, 64,   2,         59,       BV_DSIZE, BATCH,   UNIFORM_TERNARY, 1,             60,       HEStd_NotSet, BV,     FLEXIBLEAUTO,    DFLT,    512,   DFLT,   DFLT,      0,          DFLT, DFLT,             STANDARD} },
    { COEF_PACKED_TEST, "08", {BGVRNS_SCHEME, 64,   2,         59,       BV_DSIZE, BATCH,   UNIFORM_TERNARY, 1,             60,       HEStd_NotSet, BV,     FLEXIBLEAUTOEXT, DFLT,    512,   DFLT,   DFLT,      0,          DFLT, DFLT,             STANDARD} },
    { COEF_PACKED_TEST, "09", {BFVRNS_SCHEME, DFLT, DFLT,      60,       20,       BATCH,   GAUSSIAN,        DFLT,          DFLT,     DFLT,         BV,     FIXEDMANUAL,     DFLT,    512,   DFLT,   DFLT,      2,          DFLT, HPS,              STANDARD} },
    { COEF_PACKED_TEST, "10", {BFVRNS_SCHEME, DFLT, DFLT,      60,       20,       BATCH,   UNIFORM_TERNARY, DFLT,          DFLT,     DFLT,         BV,     FIXEDMANUAL,     DFLT,    512,   DFLT,   DFLT,      2,          DFLT, BEHZ,             STANDARD} },
    { COEF_PACKED_TEST, "11", {BFVRNS_SCHEME, DFLT, DFLT,      60,       20,       BATCH,   GAUSSIAN,        DFLT,          DFLT,     DFLT,         BV,     FIXEDMANUAL,     DFLT,    512,   DFLT,   DFLT,      2,          DFLT, HPSPOVERQ,        STANDARD} },
    { COEF_PACKED_TEST, "12", {BFVRNS_SCHEME, DFLT, DFLT,      60,       20,       BATCH,   GAUSSIAN,        DFLT,          DFLT,     DFLT,         BV,     FIXEDMANUAL,     DFLT,    512,   DFLT,   DFLT,      2,          DFLT, HPSPOVERQLEVELED, STANDARD} },
    { COEF_PACKED_TEST, "13", {BFVRNS_SCHEME, DFLT, DFLT,      60,       20,       BATCH,   GAUSSIAN,        DFLT,          DFLT,     DFLT,         BV,     FIXEDMANUAL,     DFLT,    512,   DFLT,   DFLT,      2,          DFLT, HPS,              POVERQ}   },
    { COEF_PACKED_TEST, "14", {BFVRNS_SCHEME, DFLT, DFLT,      60,       20,       BATCH,   UNIFORM_TERNARY, DFLT,          DFLT,     DFLT,         BV,     FIXEDMANUAL,     DFLT,    512,   DFLT,   DFLT,      2,          DFLT, BEHZ,             POVERQ}   },
    { COEF_PACKED_TEST, "15", {BFVRNS_SCHEME, DFLT, DFLT,      60,       20,       BATCH,   GAUSSIAN,        DFLT,          DFLT,     DFLT,         BV,     FIXEDMANUAL,     DFLT,    512,   DFLT,   DFLT,      2,          DFLT, HPSPOVERQ,        POVERQ}   },
    { COEF_PACKED_TEST, "16", {BFVRNS_SCHEME, DFLT, DFLT,      60,       20,       BATCH,   GAUSSIAN,        DFLT,          DFLT,     DFLT,         BV,     FIXEDMANUAL,     DFLT,    512,   DFLT,   DFLT,      2,          DFLT, HPSPOVERQLEVELED, POVERQ}   },
};
// clang-format on
//===========================================================================================================
class Encrypt_Decrypt : public ::testing::TestWithParam<TEST_CASE_Encrypt_Decrypt> {
    using Element = DCRTPoly;

protected:
    void SetUp() {}

    void TearDown() {
        // TODO (dsuponit): do we need to remove keys before releasing all context?
        //CryptoContextImpl<Poly>::ClearEvalMultKeys();
        //CryptoContextImpl<Poly>::ClearEvalSumKeys();
        //CryptoContextImpl<DCRTPoly>::ClearEvalMultKeys();
        //CryptoContextImpl<DCRTPoly>::ClearEvalSumKeys();
        CryptoContextFactory<DCRTPoly>::ReleaseAllContexts();
    }

    void EncryptionString(const TEST_CASE_Encrypt_Decrypt& testData, const std::string& failmsg = std::string()) {
        try {
            CryptoContext<Element> cc(UnitTestGenerateContext(testData.params));

            std::string value = "You keep using that word. I do not think it means what you think it means";
            Plaintext plaintext = CryptoContextImpl<Element>::MakePlaintext(String, cc, value);

            KeyPair<Element> kp = cc->KeyGen();
            EXPECT_EQ(kp.good(), true) << failmsg << " key generation for string encrypt/decrypt failed";

            Ciphertext<Element> ciphertext = cc->Encrypt(kp.publicKey, plaintext);
            Plaintext plaintextNew;
            cc->Decrypt(kp.secretKey, ciphertext, &plaintextNew);
            EXPECT_EQ(*plaintext, *plaintextNew) << failmsg << " string encrypt/decrypt failed";
        }
        catch (std::exception& e) {
            std::cerr << "Exception thrown from " << __func__ << "(): " << e.what() << std::endl;
            // make it fail
            EXPECT_TRUE(0 == 1) << failmsg;
        }
        catch (...) {
            // TODO (dsuponit): demangle separately for linux, MacOS and Windows. see some links below
            // https://stackoverflow.com/questions/142508/how-do-i-check-os-with-a-preprocessor-directive
            // https://docs.microsoft.com/en-us/windows/win32/debug/retrieving-undecorated-symbol-names
            std::string name(demangle(__cxxabiv1::__cxa_current_exception_type()->name()));
            std::cerr << "Unknown exception of type \"" << name << "\" thrown from " << __func__ << "()" << std::endl;
            // make it fail
            EXPECT_TRUE(0 == 1) << failmsg;
        }
    }

    void EncryptionCoefPacked(const TEST_CASE_Encrypt_Decrypt& testData, const std::string& failmsg = std::string()) {
        try {
            CryptoContext<Element> cc(UnitTestGenerateContext(testData.params));

            size_t intSize = cc->GetRingDimension();
            auto ptm = cc->GetCryptoParameters()->GetPlaintextModulus();
            int half = ptm / 2;

            std::vector<int64_t> intvec;
            for (size_t ii = 0; ii < intSize; ii++) intvec.push_back(rand() % half);
            Plaintext plaintextInt = cc->MakeCoefPackedPlaintext(intvec);

            std::vector<int64_t> sintvec;
            for (size_t ii = 0; ii < intSize; ii++) {
                int rnum = rand() % half;
                if (rand() % 2) rnum *= -1;
                sintvec.push_back(rnum);
            }
            Plaintext plaintextSInt = cc->MakeCoefPackedPlaintext(sintvec);

            KeyPair<Element> kp = cc->KeyGen();
            EXPECT_EQ(kp.good(), true)
                << failmsg << " key generation for coef packed encrypt/decrypt failed";

            Ciphertext<Element> ciphertext4 = cc->Encrypt(kp.publicKey, plaintextInt);
            Plaintext plaintextIntNew;
            cc->Decrypt(kp.secretKey, ciphertext4, &plaintextIntNew);
            EXPECT_EQ(*plaintextIntNew, *plaintextInt)
                << failmsg << "coef packed encrypt/decrypt failed for integer plaintext";

            Ciphertext<Element> ciphertext5 = cc->Encrypt(kp.publicKey, plaintextSInt);
            Plaintext plaintextSIntNew;
            cc->Decrypt(kp.secretKey, ciphertext5, &plaintextSIntNew);
            EXPECT_EQ(*plaintextSIntNew, *plaintextSInt)
                << failmsg << "coef packed encrypt/decrypt failed for signed integer plaintext";
        }
        catch (std::exception& e) {
            std::cerr << "Exception thrown from " << __func__ << "(): " << e.what() << std::endl;
            // make it fail
            EXPECT_TRUE(0 == 1) << failmsg;
        }
        catch (...) {
            std::string name(demangle(__cxxabiv1::__cxa_current_exception_type()->name()));
            std::cerr << "Unknown exception of type \"" << name << "\" thrown from " << __func__ << "()" << std::endl;
            // make it fail
            EXPECT_TRUE(0 == 1) << failmsg;
        }
    }
};
//===========================================================================================================
TEST_P(Encrypt_Decrypt, ENCRYPT) {
    setupSignals();
    auto test = GetParam();
    if (test.testCaseType == STRING_TEST)
        EncryptionString(test, test.buildTestName());
    else if (test.testCaseType == COEF_PACKED_TEST)
        EncryptionCoefPacked(test, test.buildTestName());
}

INSTANTIATE_TEST_SUITE_P(UnitTests, Encrypt_Decrypt, ::testing::ValuesIn(testCases), testName);


