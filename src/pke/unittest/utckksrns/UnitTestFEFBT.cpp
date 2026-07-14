//==================================================================================
//
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
  Unit tests for pure CKKS FE functional bootstrapping
 */

#include "gtest/gtest.h"
#include "scheme/ckksrns/ckksrns-fhe.h"
#include "UnitTestCCParams.h"
#include "UnitTestCryptoContext.h"
#include "UnitTestUtils.h"

#include <algorithm>
#include <cmath>
#include <functional>
#include <iostream>
#include <ostream>
#include <sstream>
#include <string>
#include <vector>

using namespace lbcrypto;

namespace {

enum TEST_CASE_TYPE : int {
    FEFBT_ACCURACY = 0,
    FEFBT_POST_ROTATION,
};

static std::ostream& operator<<(std::ostream& os, const TEST_CASE_TYPE& type) {
    std::string typeName;
    switch (type) {
        case FEFBT_ACCURACY:
            typeName = "FEFBT_ACCURACY";
            break;
        case FEFBT_POST_ROTATION:
            typeName = "FEFBT_POST_ROTATION";
            break;
        default:
            typeName = "UNKNOWN";
            break;
    }
    return os << typeName;
}

enum FEFBT_FUNCTION : int {
    FEFBT_EXP = 0,
    FEFBT_SIGMOID,
    FEFBT_GELU_TANH,
};

static std::ostream& operator<<(std::ostream& os, const FEFBT_FUNCTION& type) {
    std::string typeName;
    switch (type) {
        case FEFBT_EXP:
            typeName = "FEFBT_EXP";
            break;
        case FEFBT_SIGMOID:
            typeName = "FEFBT_SIGMOID";
            break;
        case FEFBT_GELU_TANH:
            typeName = "FEFBT_GELU_TANH";
            break;
        default:
            typeName = "UNKNOWN";
            break;
    }
    return os << typeName;
}

struct TEST_CASE_UTCKKSRNS_FEFBT {
    TEST_CASE_TYPE testCaseType;
    std::string description;
    UnitTestCCParams params;
    std::vector<uint32_t> levelBudget;
    std::vector<uint32_t> dim1;
    uint32_t slots;
    FEFBT_FUNCTION functionType;

    std::string buildTestName() const {
        std::stringstream ss;
        ss << testCaseType << "_" << description;
        return ss.str();
    }

    std::string toString() const {
        std::stringstream ss;
        ss << "testCaseType [" << testCaseType << "], functionType [" << functionType << "], "
           << params.toString() << ", slots [" << slots << "]";
        return ss.str();
    }
};

static auto testName = [](const testing::TestParamInfo<TEST_CASE_UTCKKSRNS_FEFBT>& test) {
    return test.param.buildTestName();
};

static std::ostream& operator<<(std::ostream& os, const TEST_CASE_UTCKKSRNS_FEFBT& test) {
    return os << test.toString();
}

constexpr uint32_t MULT_DEPTH   = 26;
constexpr uint32_t RDIM         = 1 << 12;
constexpr uint32_t NUM_LRG_DIGS = 3;
constexpr uint32_t SPARSE_SLOTS = 8;

#if NATIVEINT != 128
constexpr uint32_t SMODSIZE = 59;
constexpr uint32_t FMODSIZE = 60;

UnitTestCCParams MakeFEFBTParams(uint32_t batchSize, SecretKeyDist skd) {
    UnitTestCCParams params;
    params.schemeId            = CKKSRNS_SCHEME;
    params.ringDimension       = RDIM;
    params.multiplicativeDepth = MULT_DEPTH;
    params.scalingModSize      = SMODSIZE;
    params.batchSize           = batchSize;
    params.secretKeyDist       = skd;
    params.firstModSize        = FMODSIZE;
    params.securityLevel       = HEStd_NotSet;
    params.ksTech              = HYBRID;
    params.scalTech            = FIXEDMANUAL;
    params.numLargeDigits      = NUM_LRG_DIGS;
    params.ckksDataType        = REAL;

    return params;
}

TEST_CASE_UTCKKSRNS_FEFBT MakeFEFBTCase(TEST_CASE_TYPE testCaseType, const std::string& description,
                                        uint32_t batchSize, SecretKeyDist skd, uint32_t slots,
                                        FEFBT_FUNCTION functionType) {
    TEST_CASE_UTCKKSRNS_FEFBT testCase;
    testCase.testCaseType = testCaseType;
    testCase.description  = description;
    testCase.params       = MakeFEFBTParams(batchSize, skd);
    testCase.levelBudget  = {3, 2};
    testCase.dim1         = {0, 0};
    testCase.slots        = slots;
    testCase.functionType = functionType;

    return testCase;
}

// clang-format off
static std::vector<TEST_CASE_UTCKKSRNS_FEFBT> testCases = {
    MakeFEFBTCase(FEFBT_ACCURACY,      "01", RDIM / 2,    SPARSE_TERNARY,      RDIM / 2,   FEFBT_SIGMOID),
    MakeFEFBTCase(FEFBT_ACCURACY,      "02", RDIM / 2,    SPARSE_ENCAPSULATED, RDIM / 2,   FEFBT_SIGMOID),
    MakeFEFBTCase(FEFBT_ACCURACY,      "03", RDIM / 2,    UNIFORM_TERNARY,     RDIM / 2,   FEFBT_SIGMOID),
    MakeFEFBTCase(FEFBT_ACCURACY,      "04", SPARSE_SLOTS, SPARSE_TERNARY,     SPARSE_SLOTS, FEFBT_SIGMOID),
    MakeFEFBTCase(FEFBT_POST_ROTATION, "05", RDIM / 2,    SPARSE_TERNARY,      RDIM / 2,   FEFBT_SIGMOID),
    MakeFEFBTCase(FEFBT_ACCURACY,      "06", RDIM / 2,    SPARSE_TERNARY,      RDIM / 2,   FEFBT_EXP),
    MakeFEFBTCase(FEFBT_ACCURACY,      "07", RDIM / 2,    SPARSE_TERNARY,      RDIM / 2,   FEFBT_GELU_TANH),
};
// clang-format on
#else
static std::vector<TEST_CASE_UTCKKSRNS_FEFBT> testCases = {};
#endif

class UTCKKSRNS_FEFBT : public ::testing::TestWithParam<TEST_CASE_UTCKKSRNS_FEFBT> {
    using Element = DCRTPoly;

    static constexpr double eps = 0.0001;

protected:
    void SetUp() {
        OpenFHEParallelControls.UnitTestStart();
    }

    void TearDown() {
        CryptoContextFactory<DCRTPoly>::ReleaseAllContexts();
        OpenFHEParallelControls.UnitTestStop();
    }

    const std::vector<std::complex<double>>& GetCoefficients(FEFBT_FUNCTION functionType) const {
        switch (functionType) {
            case FEFBT_EXP:
                return FHECKKSRNS::GetFEExpCoefficients();
            case FEFBT_SIGMOID:
                return FHECKKSRNS::GetFESigmoidCoefficients();
            case FEFBT_GELU_TANH:
                return FHECKKSRNS::GetFEGeluCoefficients();
            default:
                OPENFHE_THROW("Unsupported FEFBT function type");
        }
    }

    double GetRadius(FEFBT_FUNCTION functionType) const {
        switch (functionType) {
            case FEFBT_EXP:
                return 2.0;
            case FEFBT_SIGMOID:
            case FEFBT_GELU_TANH:
                return 8.0;
            default:
                OPENFHE_THROW("Unsupported FEFBT function type");
        }
    }

    std::string GetFunctionName(FEFBT_FUNCTION functionType) const {
        switch (functionType) {
            case FEFBT_EXP:
                return "exp[-2,2]";
            case FEFBT_SIGMOID:
                return "sigmoid[-8,8]";
            case FEFBT_GELU_TANH:
                return "gelu_tanh[-8,8]";
            default:
                return "unknown";
        }
    }

    double EvaluateTarget(FEFBT_FUNCTION functionType, double x) const {
        constexpr double PI = 3.14159265358979323846;

        switch (functionType) {
            case FEFBT_EXP:
                return std::exp(x);
            case FEFBT_SIGMOID:
                return 1.0 / (1.0 + std::exp(-x));
            case FEFBT_GELU_TANH:
                return 0.5 * x * (1.0 + std::tanh(std::sqrt(2.0 / PI) * (x + 0.044715 * std::pow(x, 3))));
            default:
                OPENFHE_THROW("Unsupported FEFBT function type");
        }
    }

    std::vector<double> BuildNormalizedInput(uint32_t slots) const {
        std::vector<double> input(slots);
        constexpr double left  = -0.5;
        constexpr double right = 0.5;

        for (uint32_t i = 0; i < slots; ++i) {
            input[i] = left + static_cast<double>(i) * (right - left) / static_cast<double>(slots);
        }

        return input;
    }

    std::vector<double> BuildExpectedOutput(FEFBT_FUNCTION functionType, const std::vector<double>& normalizedInput) const {
        std::vector<double> expected(normalizedInput.size());
        const double radius = GetRadius(functionType);

        for (size_t i = 0; i < normalizedInput.size(); ++i) {
            expected[i] = EvaluateTarget(functionType, 2.0 * radius * normalizedInput[i]);
        }

        return expected;
    }

    void UnitTest_FEFBT(const TEST_CASE_UTCKKSRNS_FEFBT& testData, const std::string& failmsg = std::string()) {
        try {
            CryptoContext<Element> cc(UnitTestGenerateContext(testData.params));

            cc->EvalFEFuncBootstrapSetup(testData.levelBudget, testData.dim1, testData.slots);

            auto keyPair = cc->KeyGen();
            cc->EvalBootstrapKeyGen(keyPair.secretKey, testData.slots);
            cc->EvalMultKeyGen(keyPair.secretKey);

            auto input         = BuildNormalizedInput(testData.slots);
            auto expected      = BuildExpectedOutput(testData.functionType, input);
            Plaintext plaintext = cc->MakeCKKSPackedPlaintext(
                input, 1, MULT_DEPTH - (testData.levelBudget[1] + 1), nullptr, testData.slots);
            auto ciphertext = cc->Encrypt(keyPair.publicKey, plaintext);
            auto resultCt   = cc->EvalFEFuncBootstrap(ciphertext, GetCoefficients(testData.functionType));

            Plaintext result;
            cc->Decrypt(keyPair.secretKey, resultCt, &result);
            result->SetLength(expected.size());

            checkEquality(result->GetRealPackedValue(), expected, eps,
                          failmsg + " FE functional bootstrapping failed for " +
                              GetFunctionName(testData.functionType) + ".");
        }
        catch (std::exception& e) {
            std::cerr << "Exception thrown from " << __func__ << "(): " << e.what() << std::endl;
            EXPECT_TRUE(0 == 1) << failmsg;
        }
        catch (...) {
            UNIT_TEST_HANDLE_ALL_EXCEPTIONS;
        }
    }

    void UnitTest_FEFBT_PostRotation(const TEST_CASE_UTCKKSRNS_FEFBT& testData,
                                     const std::string& failmsg = std::string()) {
        try {
            CryptoContext<Element> cc(UnitTestGenerateContext(testData.params));

            cc->EvalFEFuncBootstrapSetup(testData.levelBudget, testData.dim1, testData.slots);

            auto keyPair = cc->KeyGen();
            cc->EvalBootstrapKeyGen(keyPair.secretKey, testData.slots);
            cc->EvalAtIndexKeyGen(keyPair.secretKey, {6});
            cc->EvalMultKeyGen(keyPair.secretKey);

            auto input         = BuildNormalizedInput(testData.slots);
            auto expected      = BuildExpectedOutput(testData.functionType, input);
            Plaintext plaintext = cc->MakeCKKSPackedPlaintext(
                input, 1, MULT_DEPTH - (testData.levelBudget[1] + 1), nullptr, testData.slots);
            auto ciphertext = cc->Encrypt(keyPair.publicKey, plaintext);
            auto resultCt   = cc->EvalFEFuncBootstrap(ciphertext, GetCoefficients(testData.functionType));

            constexpr int32_t rotIndex = 6;
            auto rotatedCt             = cc->EvalAtIndex(resultCt, rotIndex);
            std::rotate(expected.begin(), expected.begin() + rotIndex, expected.end());

            Plaintext result;
            cc->Decrypt(keyPair.secretKey, rotatedCt, &result);
            result->SetLength(expected.size());

            checkEquality(result->GetRealPackedValue(), expected, eps,
                          failmsg + " EvalAtIndex after FE functional bootstrapping failed for " +
                              GetFunctionName(testData.functionType) + ".");
        }
        catch (std::exception& e) {
            std::cerr << "Exception thrown from " << __func__ << "(): " << e.what() << std::endl;
            EXPECT_TRUE(0 == 1) << failmsg;
        }
        catch (...) {
            UNIT_TEST_HANDLE_ALL_EXCEPTIONS;
        }
    }
};

TEST_P(UTCKKSRNS_FEFBT, CKKSRNS) {
    setupSignals();
    auto test = GetParam();

    switch (test.testCaseType) {
        case FEFBT_ACCURACY:
            UnitTest_FEFBT(test, test.buildTestName());
            break;
        case FEFBT_POST_ROTATION:
            UnitTest_FEFBT_PostRotation(test, test.buildTestName());
            break;
        default:
            break;
    }
}

GTEST_ALLOW_UNINSTANTIATED_PARAMETERIZED_TEST(UTCKKSRNS_FEFBT);
INSTANTIATE_TEST_SUITE_P(UnitTests, UTCKKSRNS_FEFBT, ::testing::ValuesIn(testCases), testName);

}  // namespace
