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
  Unit tests for the CKKS scheme
 */

#include "UnitTestUtils.h"
#include "UnitTestCCParams.h"
#include "UnitTestCryptoContext.h"

#include <iostream>
#include <vector>
#include "gtest/gtest.h"
#include <cxxabi.h>
#include <iterator>
#include "utils/demangle.h"


using namespace lbcrypto;

//===========================================================================================================
enum TEST_CASE_TYPE {
    EVAL_POLY = 0,

};

static std::ostream& operator<<(std::ostream& os, const TEST_CASE_TYPE& type) {
    std::string typeName;
    switch (type) {
    case EVAL_POLY:
        typeName = "EVAL_POLY";
        break;
    default:
        typeName = "UNKNOWN";
        break;
    }
    return os << typeName;
}
//===========================================================================================================
struct TEST_CASE_UTCKKSRNS_EVAL_POLY {
    TEST_CASE_TYPE testCaseType;
    // test case description - MUST BE UNIQUE
    std::string description;

    UnitTestCCParams  params;

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
static auto testName = [](const testing::TestParamInfo<TEST_CASE_UTCKKSRNS_EVAL_POLY>& test) {
    return test.param.buildTestName();
};

static std::ostream& operator<<(std::ostream& os, const TEST_CASE_UTCKKSRNS_EVAL_POLY& test) {
    return os << test.toString();
}
//===========================================================================================================
constexpr uint32_t RDIM = 512;
constexpr uint32_t MULT_DEPTH = 10;
constexpr uint32_t BATCH = 8;

#if NATIVEINT==128
constexpr uint32_t SFBITS = 78;
constexpr uint32_t FMODSIZE = 89;
#else
constexpr uint32_t SFBITS = 59;
constexpr uint32_t FMODSIZE = 60;
#endif

// clang-format off
static std::vector<TEST_CASE_UTCKKSRNS_EVAL_POLY> testCases = {
    // TestType, Descr, Scheme,         RDim, MultDepth,  SFBits,     DSize, BatchSz, SecKeyDist,      MDepth, ModSize,  SecLvl,       KSTech, RSTech,          LDigits,    PtMod, StdDev, EvalAddCt, EvalMultCt, KSCt, MultTech
    { EVAL_POLY, "01", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SFBITS,     DFLT,  BATCH,   UNIFORM_TERNARY, DFLT,   FMODSIZE, HEStd_NotSet, HYBRID, FIXEDMANUAL,     DFLT,       DFLT,  DFLT,   DFLT,      DFLT,       DFLT, DFLT} },
//    { EVAL_POLY, "02", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SFBITS,     DFLT,  DFLT,    UNIFORM_TERNARY, DFLT,   FMODSIZE, HEStd_NotSet, HYBRID, FIXEDAUTO,       DFLT,       DFLT,  DFLT,   DFLT,      DFLT,       DFLT, DFLT} },
//    { EVAL_POLY, "03", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SFBITS,     DFLT,  DFLT,    UNIFORM_TERNARY, DFLT,   FMODSIZE, HEStd_NotSet, BV,     FIXEDMANUAL,     DFLT,       DFLT,  DFLT,   DFLT,      DFLT,       DFLT, DFLT} },
//    { EVAL_POLY, "04", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SFBITS,     DFLT,  DFLT,    UNIFORM_TERNARY, DFLT,   FMODSIZE, HEStd_NotSet, BV,     FIXEDAUTO,       DFLT,       DFLT,  DFLT,   DFLT,      DFLT,       DFLT, DFLT} },
//#if NATIVEINT != 128
//    { EVAL_POLY, "05", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SFBITS,     DFLT,  BATCH,   UNIFORM_TERNARY, DFLT,   FMODSIZE, HEStd_NotSet, HYBRID, FLEXIBLEAUTO,    DFLT,       DFLT,  DFLT,   DFLT,      DFLT,       DFLT, DFLT} },
//    { EVAL_POLY, "06", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SFBITS,     DFLT,  DFLT,    UNIFORM_TERNARY, DFLT,   FMODSIZE, HEStd_NotSet, HYBRID, FLEXIBLEAUTOEXT, DFLT,       DFLT,  DFLT,   DFLT,      DFLT,       DFLT, DFLT} },
//    { EVAL_POLY, "07", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SFBITS,     DFLT,  DFLT,    UNIFORM_TERNARY, DFLT,   FMODSIZE, HEStd_NotSet, BV,     FLEXIBLEAUTO,    DFLT,       DFLT,  DFLT,   DFLT,      DFLT,       DFLT, DFLT} },
//    { EVAL_POLY, "08", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SFBITS,     DFLT,  DFLT,    UNIFORM_TERNARY, DFLT,   FMODSIZE, HEStd_NotSet, BV,     FLEXIBLEAUTOEXT, DFLT,       DFLT,  DFLT,   DFLT,      DFLT,       DFLT, DFLT} },
//#endif
    // ==========================================
};
// clang-format on
//===========================================================================================================
class UTCKKSRNS_EVAL_POLY : public ::testing::TestWithParam<TEST_CASE_UTCKKSRNS_EVAL_POLY> {
    using Element = DCRTPoly;

    // The precision after which we consider two values equal.
    // This is necessary because CKKS works for approximate numbers.
    //const double eps = EPSILON;
    const double eps = 0.001;

protected:
    void SetUp() {}

    void TearDown() {
        CryptoContextFactory<DCRTPoly>::ReleaseAllContexts();
    }

    void UnitTest_EvalPoly(const TEST_CASE_UTCKKSRNS_EVAL_POLY& testData, const std::string& failmsg = std::string()) {
        try {
            CryptoContext<Element> cc(UnitTestGenerateContext(testData.params));

            std::vector<std::complex<double>> input{ 0.5, 0.7, 0.9, 0.95, 0.93 };
            size_t encodedLength = input.size();

            // with only positive coefficients
            // x^16 + x^11 + 2 x^9 + x^8 + x^6 + 1.25 x^3 + 0.75*x + 0.15
            std::vector<double> coefficients1{ 0.15, 0.75, 0, 1.25, 0, 0, 1, 0, 1, 2, 0, 1, 0, 0, 0, 0, 1 };
            // x^16 + x^11 + 2 x^9 - x^8 + x^6 + 1.25 x^3 - 0.75*x + 0.15
            // with negative coefficients
            std::vector<double> coefficients2{ 0.15, -0.75, 0, 1.25, 0, 0, 1, 0, -1, 2, 0, 1, 0, 0, 0, 0, 1 };
            // x^16
            // power function
            std::vector<double> coefficients3{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
            // x^16 + x^11 + 2 x^9 - x^8 + x^6 - 1.25 x^5 + 1.25 x^3 - 1.75*x + 0.15
            // with negative coefficients with magnitude greater than 1
            std::vector<double> coefficients4{ 0.15, -1.75, 0, 1.25, 0, -1.25, 1, 0, -1, 2, 0, 1, 0, 0, 0, 0, 1 };
            // x + x^2 - x^3
            // low-degree function to check linear implementation
            std::vector<double> coefficients5{ 0, 1, 1, -1 };

            Plaintext plaintext1 = cc->MakeCKKSPackedPlaintext(input);

            std::vector<std::complex<double>> output1{ 0.705191, 1.38285, 3.97211, 5.60216, 4.86358 };
            Plaintext plaintextResult1 = cc->MakeCKKSPackedPlaintext(output1);

            std::vector<std::complex<double>> output2{ -0.0526215, 0.217555, 1.76118, 2.85032, 2.34941 };
            Plaintext plaintextResult2 = cc->MakeCKKSPackedPlaintext(output2);

            std::vector<std::complex<double>> output3{ 0.0000152588, 0.00332329, 0.185302, 0.440127, 0.313132 };
            Plaintext plaintextResult3 = cc->MakeCKKSPackedPlaintext(output3);

            std::vector<std::complex<double>> output4{ -0.59168396, -0.69253274, 0.12306489, 0.93308964, 0.54980166 };
            Plaintext plaintextResult4 = cc->MakeCKKSPackedPlaintext(output4);

            std::vector<std::complex<double>> output5{ 0.625, 0.847, 0.9809999999, 0.995125, 0.990543 };
            Plaintext plaintextResult5 = cc->MakeCKKSPackedPlaintext(output5);

            auto keyPair = cc->KeyGen();
            cc->EvalMultKeyGen(keyPair.secretKey);

            // Encrypt plaintexts
            Ciphertext<Element> ciphertext1 = cc->Encrypt(keyPair.publicKey, plaintext1);
            Ciphertext<Element> cResult2, cResult3, cResult4, cResult5;
            Plaintext results2, results3, results4, results5;

            Plaintext results1;
            auto cResult1 = cc->EvalPoly(ciphertext1, coefficients1);
            cc->Decrypt(keyPair.secretKey, cResult1, &results1);
            results1->SetLength(encodedLength);
            auto tmp_a = plaintextResult1->GetCKKSPackedValue();
            auto tmp_b = results1->GetCKKSPackedValue();
            //std::cerr << "tmp_a:";
            //for(auto a : tmp_a)
            //    std::cerr << " " << a;
            //std::cerr << std::endl;
            //std::cerr << "tmp_b:";
            //for(auto a : tmp_b)
            //    std::cerr << " " << a;
            //std::cerr << std::endl;
            checkEquality(plaintextResult1->GetCKKSPackedValue(), results1->GetCKKSPackedValue(), eps,
                failmsg + " EvalPoly with positive coefficients fails");

            //cResult2 = cc->EvalPoly(ciphertext1, coefficients2);
            //cc->Decrypt(kp.secretKey, cResult2, &results2);
            //results2->SetLength(encodedLength);
            //tmp_a = plaintextResult2->GetCKKSPackedValue();
            //tmp_b = results2->GetCKKSPackedValue();
            //checkApproximateEquality(
            //    tmp_a, tmp_b, encodedLength, eps,
            //    failmsg + " EvalPoly with negative coefficients failed");

            //cResult3 = cc->EvalPoly(ciphertext1, coefficients3);
            //cc->Decrypt(kp.secretKey, cResult3, &results3);
            //results3->SetLength(encodedLength);
            //tmp_a = plaintextResult3->GetCKKSPackedValue();
            //tmp_b = results3->GetCKKSPackedValue();
            //checkApproximateEquality(tmp_a, tmp_b, encodedLength, eps,
            //    failmsg + " EvalPoly for a power function failed");

            //cResult4 = cc->EvalPoly(ciphertext1, coefficients4);
            //cc->Decrypt(kp.secretKey, cResult4, &results4);
            //results4->SetLength(encodedLength);
            //tmp_a = plaintextResult4->GetCKKSPackedValue();
            //tmp_b = results4->GetCKKSPackedValue();
            //checkApproximateEquality(
            //    tmp_a, tmp_b, encodedLength, eps,
            //    failmsg +
            //    " EvalPoly for negative coefficients with magnitude > 1 failed");

            //cResult5 = cc->EvalPoly(ciphertext1, coefficients5);
            //cc->Decrypt(kp.secretKey, cResult5, &results5);
            //results5->SetLength(encodedLength);
            //tmp_a = plaintextResult5->GetCKKSPackedValue();
            //tmp_b = results5->GetCKKSPackedValue();
            //checkApproximateEquality(
            //    tmp_a, tmp_b, encodedLength, eps,
            //    failmsg + " EvalPoly for low-degree polynomial failed");

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
TEST_P(UTCKKSRNS_EVAL_POLY, CKKSRNS) {
    setupSignals();
    auto test = GetParam();

    switch (test.testCaseType) {
    //case EVAL_POLY:
    //    UnitTest_EvalPoly(test, test.buildTestName());
    //    break;
    default:
        break;
    }
}

INSTANTIATE_TEST_SUITE_P(UnitTests, UTCKKSRNS_EVAL_POLY, ::testing::ValuesIn(testCases), testName);

