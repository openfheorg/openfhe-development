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
    BOOTSTRAP_FULL = 0,
    BOOTSTRAP_FULL_FFT,
    BOOTSTRAP_SPARSE,

};

static std::ostream& operator<<(std::ostream& os, const TEST_CASE_TYPE& type) {
    std::string typeName;
    switch (type) {
    case BOOTSTRAP_FULL:
        typeName = "BOOTSTRAP_FULL";
        break;
    case BOOTSTRAP_FULL_FFT:
        typeName = "BOOTSTRAP_FULL_FFT";
        break;
    case BOOTSTRAP_SPARSE:
        typeName = "BOOTSTRAP_SPARSE";
        break;
    default:
        typeName = "UNKNOWN";
        break;
    }
    return os << typeName;
}
//===========================================================================================================
struct TEST_CASE_UTCKKSRNSBOOT {
    TEST_CASE_TYPE testCaseType;
    // test case description - MUST BE UNIQUE
    std::string description;

    UnitTestCCParams  params;

    // additional test case data
    // ........
    std::vector<uint32_t> levelBudget;
    std::vector<uint32_t> dim1;

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
static auto testName = [](const testing::TestParamInfo<TEST_CASE_UTCKKSRNSBOOT>& test) {
    return test.param.buildTestName();
};

static std::ostream& operator<<(std::ostream& os, const TEST_CASE_UTCKKSRNSBOOT& test) {
    return os << test.toString();
}
//===========================================================================================================
constexpr usint MULT_DEPTH = 32;

// clang-format off
static std::vector<TEST_CASE_UTCKKSRNSBOOT> testCases = {
    // TestType,     Descr, Scheme,          RDim, MultDepth,  SFBits, DSize, BatchSz, SecKeyDist,      MDepth, ModSize, SecLvl,       KSTech, RSTech,          LDigits, PtMod, StdDev, EvalAddCt, EvalMultCt, KSCt, MultTech, LvlBudget, Dim1
    { BOOTSTRAP_FULL, "01", {CKKSRNS_SCHEME, 4096, MULT_DEPTH, 55,     DFLT,  DFLT,    UNIFORM_TERNARY, DFLT,   60,      HEStd_NotSet, HYBRID, FIXEDAUTO,       3,       DFLT,  DFLT,   DFLT,      DFLT,       DFLT, DFLT},    { 1, 1 },  { 0, 0 } },
    { BOOTSTRAP_FULL, "02", {CKKSRNS_SCHEME, 4096, MULT_DEPTH, 55,     DFLT,  DFLT,    SPARSE_TERNARY,  DFLT,   60,      HEStd_NotSet, HYBRID, FIXEDAUTO,       3,       DFLT,  DFLT,   DFLT,      DFLT,       DFLT, DFLT},    { 1, 1 },  { 0, 0 } },
    { BOOTSTRAP_FULL, "03", {CKKSRNS_SCHEME, 4096, MULT_DEPTH, 55,     DFLT,  DFLT,    UNIFORM_TERNARY, DFLT,   60,      HEStd_NotSet, HYBRID, FIXEDMANUAL,     3,       DFLT,  DFLT,   DFLT,      DFLT,       DFLT, DFLT},    { 1, 1 },  { 0, 0 } },
    { BOOTSTRAP_FULL, "04", {CKKSRNS_SCHEME, 4096, MULT_DEPTH, 55,     DFLT,  DFLT,    SPARSE_TERNARY,  DFLT,   60,      HEStd_NotSet, HYBRID, FIXEDMANUAL,     3,       DFLT,  DFLT,   DFLT,      DFLT,       DFLT, DFLT},    { 1, 1 },  { 0, 0 } },
#if NATIVEINT != 128
    { BOOTSTRAP_FULL, "05", {CKKSRNS_SCHEME, 4096, MULT_DEPTH, 55,     DFLT,  DFLT,    SPARSE_TERNARY,  DFLT,   60,      HEStd_NotSet, HYBRID, FLEXIBLEAUTO,    3,       DFLT,  DFLT,   DFLT,      DFLT,       DFLT, DFLT},    { 1, 1 },  { 0, 0 } },
    { BOOTSTRAP_FULL, "06", {CKKSRNS_SCHEME, 4096, MULT_DEPTH, 55,     DFLT,  DFLT,    UNIFORM_TERNARY, DFLT,   60,      HEStd_NotSet, HYBRID, FLEXIBLEAUTO,    3,       DFLT,  DFLT,   DFLT,      DFLT,       DFLT, DFLT},    { 1, 1 },  { 0, 0 } },
    { BOOTSTRAP_FULL, "07", {CKKSRNS_SCHEME, 4096, MULT_DEPTH, 55,     DFLT,  DFLT,    SPARSE_TERNARY,  DFLT,   60,      HEStd_NotSet, HYBRID, FLEXIBLEAUTOEXT, 3,       DFLT,  DFLT,   DFLT,      DFLT,       DFLT, DFLT},    { 1, 1 },  { 0, 0 } },
    { BOOTSTRAP_FULL, "08", {CKKSRNS_SCHEME, 4096, MULT_DEPTH, 55,     DFLT,  DFLT,    UNIFORM_TERNARY, DFLT,   60,      HEStd_NotSet, HYBRID, FLEXIBLEAUTOEXT, 3,       DFLT,  DFLT,   DFLT,      DFLT,       DFLT, DFLT},    { 1, 1 },  { 0, 0 } },
#endif
    // ==========================================
    // TestType,         Descr, Scheme,          RDim, MultDepth,  SFBits, DSize, BatchSz, SecKeyDist,      MDepth, ModSize, SecLvl,       KSTech, RSTech,          LDigits, PtMod, StdDev, EvalAddCt, EvalMultCt, KSCt, MultTech, LvlBudget, Dim1
    { BOOTSTRAP_FULL_FFT, "01", {CKKSRNS_SCHEME, 4096, MULT_DEPTH, 55,     DFLT,  DFLT,    UNIFORM_TERNARY, DFLT,   60,      HEStd_NotSet, HYBRID, FIXEDAUTO,       3,       DFLT,  DFLT,   DFLT,      DFLT,       DFLT, DFLT},    { 3, 3 },  { 0, 0 } },
    { BOOTSTRAP_FULL_FFT, "02", {CKKSRNS_SCHEME, 4096, MULT_DEPTH, 55,     DFLT,  DFLT,    SPARSE_TERNARY,  DFLT,   60,      HEStd_NotSet, HYBRID, FIXEDAUTO,       3,       DFLT,  DFLT,   DFLT,      DFLT,       DFLT, DFLT},    { 3, 3 },  { 0, 0 } },
    { BOOTSTRAP_FULL_FFT, "03", {CKKSRNS_SCHEME, 4096, MULT_DEPTH, 55,     DFLT,  DFLT,    UNIFORM_TERNARY, DFLT,   60,      HEStd_NotSet, HYBRID, FIXEDMANUAL,     3,       DFLT,  DFLT,   DFLT,      DFLT,       DFLT, DFLT},    { 3, 3 },  { 0, 0 } },
    { BOOTSTRAP_FULL_FFT, "04", {CKKSRNS_SCHEME, 4096, MULT_DEPTH, 55,     DFLT,  DFLT,    SPARSE_TERNARY,  DFLT,   60,      HEStd_NotSet, HYBRID, FIXEDMANUAL,     3,       DFLT,  DFLT,   DFLT,      DFLT,       DFLT, DFLT},    { 3, 3 },  { 0, 0 } },
#if NATIVEINT != 128
    { BOOTSTRAP_FULL_FFT, "05", {CKKSRNS_SCHEME, 4096, MULT_DEPTH, 55,     DFLT,  DFLT,    SPARSE_TERNARY,  DFLT,   60,      HEStd_NotSet, HYBRID, FLEXIBLEAUTO,    3,       DFLT,  DFLT,   DFLT,      DFLT,       DFLT, DFLT},    { 3, 3 },  { 0, 0 } },
    { BOOTSTRAP_FULL_FFT, "06", {CKKSRNS_SCHEME, 4096, MULT_DEPTH, 55,     DFLT,  DFLT,    UNIFORM_TERNARY, DFLT,   60,      HEStd_NotSet, HYBRID, FLEXIBLEAUTO,    3,       DFLT,  DFLT,   DFLT,      DFLT,       DFLT, DFLT},    { 3, 3 },  { 0, 0 } },
    { BOOTSTRAP_FULL_FFT, "07", {CKKSRNS_SCHEME, 4096, MULT_DEPTH, 55,     DFLT,  DFLT,    SPARSE_TERNARY,  DFLT,   60,      HEStd_NotSet, HYBRID, FLEXIBLEAUTOEXT, 3,       DFLT,  DFLT,   DFLT,      DFLT,       DFLT, DFLT},    { 3, 3 },  { 0, 0 } },
    { BOOTSTRAP_FULL_FFT, "08", {CKKSRNS_SCHEME, 4096, MULT_DEPTH, 55,     DFLT,  DFLT,    UNIFORM_TERNARY, DFLT,   60,      HEStd_NotSet, HYBRID, FLEXIBLEAUTOEXT, 3,       DFLT,  DFLT,   DFLT,      DFLT,       DFLT, DFLT},    { 3, 3 },  { 0, 0 } },
#endif
    // ==========================================
    // TestType,       Descr, Scheme,          RDim, MultDepth,  SFBits, DSize, BatchSz, SecKeyDist,      MDepth, ModSize, SecLvl,       KSTech, RSTech,          LDigits, PtMod, StdDev, EvalAddCt, EvalMultCt, KSCt, MultTech, LvlBudget, Dim1
    { BOOTSTRAP_SPARSE, "01", {CKKSRNS_SCHEME,  512, MULT_DEPTH, 53,     DFLT,  DFLT,    UNIFORM_TERNARY, DFLT,   60,      HEStd_NotSet, HYBRID, FIXEDAUTO,       3,       DFLT,  DFLT,   DFLT,      DFLT,       DFLT, DFLT},    { 1, 1 },  { 8, 8 } },
    { BOOTSTRAP_SPARSE, "02", {CKKSRNS_SCHEME,  512, MULT_DEPTH, 53,     DFLT,  DFLT,    SPARSE_TERNARY,  DFLT,   60,      HEStd_NotSet, HYBRID, FIXEDAUTO,       3,       DFLT,  DFLT,   DFLT,      DFLT,       DFLT, DFLT},    { 1, 1 },  { 8, 8 } },
    { BOOTSTRAP_SPARSE, "03", {CKKSRNS_SCHEME,  512, MULT_DEPTH, 53,     DFLT,  DFLT,    UNIFORM_TERNARY, DFLT,   60,      HEStd_NotSet, HYBRID, FIXEDMANUAL,     3,       DFLT,  DFLT,   DFLT,      DFLT,       DFLT, DFLT},    { 1, 1 },  { 8, 8 } },
    { BOOTSTRAP_SPARSE, "04", {CKKSRNS_SCHEME,  512, MULT_DEPTH, 53,     DFLT,  DFLT,    SPARSE_TERNARY,  DFLT,   60,      HEStd_NotSet, HYBRID, FIXEDMANUAL,     3,       DFLT,  DFLT,   DFLT,      DFLT,       DFLT, DFLT},    { 1, 1 },  { 8, 8 } },
#if NATIVEINT != 128
    { BOOTSTRAP_SPARSE, "05", {CKKSRNS_SCHEME,  512, MULT_DEPTH, 53,     DFLT,  DFLT,    SPARSE_TERNARY,  DFLT,   60,      HEStd_NotSet, HYBRID, FLEXIBLEAUTO,    3,       DFLT,  DFLT,   DFLT,      DFLT,       DFLT, DFLT},    { 1, 1 },  { 8, 8 } },
    { BOOTSTRAP_SPARSE, "06", {CKKSRNS_SCHEME,  512, MULT_DEPTH, 53,     DFLT,  DFLT,    UNIFORM_TERNARY, DFLT,   60,      HEStd_NotSet, HYBRID, FLEXIBLEAUTO,    3,       DFLT,  DFLT,   DFLT,      DFLT,       DFLT, DFLT},    { 1, 1 },  { 8, 8 } },
    { BOOTSTRAP_SPARSE, "07", {CKKSRNS_SCHEME,  512, MULT_DEPTH, 53,     DFLT,  DFLT,    SPARSE_TERNARY,  DFLT,   60,      HEStd_NotSet, HYBRID, FLEXIBLEAUTOEXT, 3,       DFLT,  DFLT,   DFLT,      DFLT,       DFLT, DFLT},    { 1, 1 },  { 8, 8 } },
    { BOOTSTRAP_SPARSE, "08", {CKKSRNS_SCHEME,  512, MULT_DEPTH, 53,     DFLT,  DFLT,    UNIFORM_TERNARY, DFLT,   60,      HEStd_NotSet, HYBRID, FLEXIBLEAUTOEXT, 3,       DFLT,  DFLT,   DFLT,      DFLT,       DFLT, DFLT},    { 1, 1 },  { 8, 8 } },
#endif
    // ==========================================
};
// clang-format on
//===========================================================================================================
class UTCKKSRNSBOOT : public ::testing::TestWithParam<TEST_CASE_UTCKKSRNSBOOT> {
    using Element = DCRTPoly;

    // The precision after which we consider two values equal.
    // This is necessary because CKKS works for approximate numbers.
    //const double eps = EPSILON;
    const double eps = 0.00001;

protected:
    void SetUp() {}

    void TearDown() {
        CryptoContextFactory<DCRTPoly>::ReleaseAllContexts();
    }

    void UnitTest_BootstrapFull(const TEST_CASE_UTCKKSRNSBOOT& testData, const std::string& failmsg = std::string()) {
        try {
            CryptoContext<Element> cc(UnitTestGenerateContext(testData.params));

            const auto& cryptoParams = cc->GetCryptoParameters();
            uint32_t slots = (cryptoParams->GetElementParams()->GetRingDimension()/2) / (1 << 3);

            cc->EvalBootstrapSetup(testData.levelBudget, testData.dim1, slots);

            auto keyPair = cc->KeyGen();
            cc->EvalBootstrapKeyGen(keyPair.secretKey, slots);
            cc->EvalAtIndexKeyGen(keyPair.secretKey, { 6 });
            cc->EvalMultKeyGen(keyPair.secretKey);

            std::vector<std::complex<double>> input(Fill({ 0.111111, 0.222222, 0.333333, 0.444444, 0.555555, 0.666666, 0.777777, 0.888888 }, slots));
            size_t encodedLength = input.size();

            Plaintext plaintext1 = cc->MakeCKKSPackedPlaintext(input, 1, MULT_DEPTH - 1, nullptr, slots);
            auto ciphertext1 = cc->Encrypt(keyPair.publicKey, plaintext1);
            auto ciphertextAfter = cc->EvalBootstrap(ciphertext1);

            Plaintext result;
            cc->Decrypt(keyPair.secretKey, ciphertextAfter, &result);
            result->SetLength(encodedLength);
            plaintext1->SetLength(encodedLength);

            checkEquality(result->GetCKKSPackedValue(), plaintext1->GetCKKSPackedValue(), eps,
                failmsg + " Bootstrapping for fully packed ciphertexts fails");
            //std::cerr << "tmp_a:";
            //for (auto a : result->GetCKKSPackedValue())
            //    std::cerr << " " << a;
            //std::cerr << std::endl;
            //std::cerr << "tmp_b:";
            //for (auto b : plaintext1->GetCKKSPackedValue())
            //    std::cerr << " " << b;
            //std::cerr << std::endl;
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

    void UnitTest_BootstrapFull_FFT(const TEST_CASE_UTCKKSRNSBOOT& testData, const std::string& failmsg = std::string()) {
        try {
            CryptoContext<Element> cc(UnitTestGenerateContext(testData.params));

            const auto& cryptoParams = cc->GetCryptoParameters();
            uint32_t slots = (cryptoParams->GetElementParams()->GetRingDimension() / 2) / (1 << 3);

            cc->EvalBootstrapSetup(testData.levelBudget, testData.dim1, slots);

            auto keyPair = cc->KeyGen();
            cc->EvalBootstrapKeyGen(keyPair.secretKey, slots);
            cc->EvalAtIndexKeyGen(keyPair.secretKey, { 6 });
            cc->EvalMultKeyGen(keyPair.secretKey);

            std::vector<std::complex<double>> input(Fill({ 0.111111, 0.222222, 0.333333, 0.444444, 0.555555, 0.666666, 0.777777, 0.888888 }, slots));
            size_t encodedLength = input.size();

            Plaintext plaintext1 = cc->MakeCKKSPackedPlaintext(input, 1, MULT_DEPTH - 1, nullptr, slots);
            auto ciphertext1 = cc->Encrypt(keyPair.publicKey, plaintext1);
            auto ciphertextAfter = cc->EvalBootstrap(ciphertext1);

            Plaintext result;
            cc->Decrypt(keyPair.secretKey, ciphertextAfter, &result);
            result->SetLength(encodedLength);
            plaintext1->SetLength(encodedLength);
            checkEquality(result->GetCKKSPackedValue(), plaintext1->GetCKKSPackedValue(), eps,
                failmsg + " FFT-based Bootstrapping for fully packed ciphertexts fails");

            auto temp6 = input;
            std::rotate(temp6.begin(), temp6.begin() + 6, temp6.end());

            auto ciphertext6 = cc->EvalAtIndex(ciphertextAfter, 6);
            Plaintext result6;
            cc->Decrypt(keyPair.secretKey, ciphertext6, &result6);
            result6->SetLength(encodedLength);
            checkEquality(result6->GetCKKSPackedValue(), temp6, eps,
                failmsg + " EvalAtIndex after FFT-based Bootstrapping for fully packed ciphertexts fails");
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

    void UnitTest_BootstrapSparse(const TEST_CASE_UTCKKSRNSBOOT& testData, const std::string& failmsg = std::string()) {
        try {
            CryptoContext<Element> cc(UnitTestGenerateContext(testData.params));

            const auto& cryptoParams = cc->GetCryptoParameters();
            uint32_t slots = (cryptoParams->GetElementParams()->GetRingDimension() / 2) / (1 << 3);

            cc->EvalBootstrapSetup(testData.levelBudget, testData.dim1, slots);

            auto keyPair = cc->KeyGen();
            cc->EvalBootstrapKeyGen(keyPair.secretKey, slots);
            cc->EvalAtIndexKeyGen(keyPair.secretKey, { 6 });
            cc->EvalMultKeyGen(keyPair.secretKey);

            std::vector<std::complex<double>> input(Fill({ 0.111111, 0.222222, 0.333333, 0.444444, 0.555555, 0.666666, 0.777777, 0.888888 }, slots));
            size_t encodedLength = input.size();

            Plaintext plaintext1 = cc->MakeCKKSPackedPlaintext(input, 1, MULT_DEPTH - 1, nullptr, slots);
            auto ciphertext1 = cc->Encrypt(keyPair.publicKey, plaintext1);
            auto ciphertextAfter = cc->EvalBootstrap(ciphertext1);

            Plaintext result;
            cc->Decrypt(keyPair.secretKey, ciphertextAfter, &result);
            result->SetLength(encodedLength);
            plaintext1->SetLength(encodedLength);
            checkEquality(result->GetCKKSPackedValue(), plaintext1->GetCKKSPackedValue(), eps,
                failmsg + " Bootstrapping for fully packed ciphertexts fails");

            auto temp6 = input;
            std::rotate(temp6.begin(), temp6.begin() + 6, temp6.end());

            auto ciphertext6 = cc->EvalAtIndex(ciphertextAfter, 6);
            Plaintext result6;
            cc->Decrypt(keyPair.secretKey, ciphertext6, &result6);
            result6->SetLength(encodedLength);
            checkEquality(result6->GetCKKSPackedValue(), temp6, eps,
                failmsg + " EvalAtIndex after bootstrapping for for sparsely packed ciphertexts failed when # slots < n/4 failed");
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
TEST_P(UTCKKSRNSBOOT, CKKSRNS) {
    setupSignals();
    auto test = GetParam();

    switch (test.testCaseType) {
    case BOOTSTRAP_FULL:
        UnitTest_BootstrapFull(test, test.buildTestName());
        break;
    case BOOTSTRAP_FULL_FFT:
        UnitTest_BootstrapFull_FFT(test, test.buildTestName());
        break;
    case BOOTSTRAP_SPARSE:
        UnitTest_BootstrapSparse(test, test.buildTestName());
        break;
    default:
        break;
    }
}

INSTANTIATE_TEST_SUITE_P(UnitTests, UTCKKSRNSBOOT, ::testing::ValuesIn(testCases), testName);

