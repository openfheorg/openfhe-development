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

UnitTestCCParams MakeFEFBTParams(uint32_t batchSize, SecretKeyDist skd,
                                 ScalingTechnique scalingTechnique = FIXEDMANUAL) {
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
    params.scalTech            = scalingTechnique;
    params.numLargeDigits      = NUM_LRG_DIGS;
    params.ckksDataType        = REAL;

    return params;
}

TEST_CASE_UTCKKSRNS_FEFBT MakeFEFBTCase(TEST_CASE_TYPE testCaseType, const std::string& description,
                                        uint32_t batchSize, SecretKeyDist skd, uint32_t slots,
                                        FEFBT_FUNCTION functionType,
                                        std::vector<uint32_t> levelBudget = {3, 2},
                                        ScalingTechnique scalingTechnique = FIXEDMANUAL) {
    TEST_CASE_UTCKKSRNS_FEFBT testCase;
    testCase.testCaseType = testCaseType;
    testCase.description  = description;
    testCase.params       = MakeFEFBTParams(batchSize, skd, scalingTechnique);
    testCase.levelBudget  = std::move(levelBudget);
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
    MakeFEFBTCase(FEFBT_ACCURACY,      "08", SPARSE_SLOTS, SPARSE_TERNARY,     SPARSE_SLOTS, FEFBT_SIGMOID,
                  {1, 1}, FIXEDMANUAL),
    MakeFEFBTCase(FEFBT_ACCURACY,      "09", SPARSE_SLOTS, SPARSE_TERNARY,     SPARSE_SLOTS, FEFBT_SIGMOID,
                  {1, 1}, FLEXIBLEAUTO),
    MakeFEFBTCase(FEFBT_ACCURACY,      "10", RDIM / 2,    SPARSE_TERNARY,      RDIM / 2,   FEFBT_SIGMOID,
                  {3, 2}, FLEXIBLEAUTO),
    MakeFEFBTCase(FEFBT_ACCURACY,      "11", RDIM / 2,    SPARSE_TERNARY,      RDIM / 2,   FEFBT_SIGMOID,
                  {3, 2}, FIXEDAUTO),
    MakeFEFBTCase(FEFBT_ACCURACY,      "12", SPARSE_SLOTS, SPARSE_TERNARY,     SPARSE_SLOTS, FEFBT_SIGMOID,
                  {1, 1}, FIXEDAUTO),
    MakeFEFBTCase(FEFBT_ACCURACY,      "13", RDIM / 2,    SPARSE_TERNARY,      RDIM / 2,   FEFBT_SIGMOID,
                  {3, 2}, FLEXIBLEAUTOEXT),
    MakeFEFBTCase(FEFBT_ACCURACY,      "14", SPARSE_SLOTS, SPARSE_TERNARY,     SPARSE_SLOTS, FEFBT_SIGMOID,
                  {1, 1}, FLEXIBLEAUTOEXT),
};
// clang-format on
#else
static std::vector<TEST_CASE_UTCKKSRNS_FEFBT> testCases = {};
#endif

static const std::vector<std::complex<double>> coeff_exp_2_double_29{
    std::complex<double>(3.222093706013e+00, 0.000000000000e+00),
    std::complex<double>(-3.847497325992e+00, -3.036911315182e+00),
    std::complex<double>(1.613269565467e+00, 2.561562635536e+00),
    std::complex<double>(-7.142688329459e-01, -1.718044084361e+00),
    std::complex<double>(3.343375256712e-01, 1.087677253934e+00),
    std::complex<double>(-1.590083748525e-01, -6.591856314553e-01),
    std::complex<double>(7.444125399842e-02, 3.797240558554e-01),
    std::complex<double>(-3.347789249240e-02, -2.057416664390e-01),
    std::complex<double>(1.415639337190e-02, 1.036151378646e-01),
    std::complex<double>(-5.504078824289e-03, -4.782261609566e-02),
    std::complex<double>(1.912943397918e-03, 1.985252654576e-02),
    std::complex<double>(-5.690043709362e-04, -7.207032810727e-03),
    std::complex<double>(1.328669037822e-04, 2.177453328757e-03),
    std::complex<double>(-1.854630094550e-05, -4.890711403220e-04),
    std::complex<double>(-1.453596732859e-06, 5.053417952833e-05),
    std::complex<double>(1.572743922262e-06, 1.548627313317e-05),
    std::complex<double>(-2.838788709181e-07, -8.312159353832e-06),
    std::complex<double>(-7.562004956940e-08, 8.274522508133e-07),
    std::complex<double>(4.633880680387e-08, 6.598799631857e-07),
    std::complex<double>(-5.869467412101e-10, -2.528773346321e-07),
    std::complex<double>(-6.055031566421e-09, -3.204665662698e-08),
    std::complex<double>(1.190783888161e-09, 4.385916878681e-08),
    std::complex<double>(7.747582545133e-10, -3.358504294115e-09),
    std::complex<double>(-3.348892690935e-10, -7.088429287982e-09),
    std::complex<double>(-9.585399054352e-11, 1.863929871559e-09),
    std::complex<double>(8.204146390023e-11, 1.136804343802e-09),
    std::complex<double>(9.573941899682e-12, -5.803840255614e-10),
    std::complex<double>(-2.013818972690e-11, -1.764939479287e-10),
    std::complex<double>(1.533040187851e-13, 1.657178907988e-10),
    std::complex<double>(5.134323521894e-12, 2.323787581630e-11)};

static const std::vector<std::complex<double>> coeff_sigmoid_8_double_34{
    std::complex<double>(2.500000000000e-01, 0.000000000000e+00),
    std::complex<double>(1.276756478319e-15, -2.986114677117e-01),
    std::complex<double>(-2.711798613355e-15, -1.305833657358e-03),
    std::complex<double>(2.012279232133e-15, -6.069910606535e-02),
    std::complex<double>(-3.874233833051e-17, -3.496972005070e-03),
    std::complex<double>(-5.065392549852e-16, -1.436915534313e-02),
    std::complex<double>(-4.025501720156e-16, -3.090757902275e-03),
    std::complex<double>(6.661338147751e-16, -3.011048528323e-03),
    std::complex<double>(9.549219054383e-17, -1.395169741000e-03),
    std::complex<double>(-4.406197628981e-16, -7.358936474771e-04),
    std::complex<double>(-2.137022113088e-16, -4.185575122752e-04),
    std::complex<double>(4.614364446098e-16, -2.239585471946e-04),
    std::complex<double>(4.897883314203e-19, -1.182545527493e-04),
    std::complex<double>(-4.024558464266e-16, -6.447113701542e-05),
    std::complex<double>(-1.695114860110e-16, -3.521198006050e-05),
    std::complex<double>(3.903127820948e-16, -1.881494613389e-05),
    std::complex<double>(1.909467050622e-16, -1.006822281208e-05),
    std::complex<double>(-9.540979117872e-17, -5.490602888772e-06),
    std::complex<double>(-6.585471100731e-17, -2.983401096265e-06),
    std::complex<double>(1.040834085586e-16, -1.590510122180e-06),
    std::complex<double>(1.641151407480e-16, -8.526983863427e-07),
    std::complex<double>(-6.938893903907e-17, -4.673955051855e-07),
    std::complex<double>(-1.931861246494e-16, -2.539297722240e-07),
    std::complex<double>(3.035766082959e-16, -1.341034123884e-07),
    std::complex<double>(7.532874064103e-17, -7.180768169489e-08),
    std::complex<double>(-1.049507702966e-16, -4.002071006315e-08),
    std::complex<double>(-8.495889538759e-17, -2.179193493192e-08),
    std::complex<double>(1.587271980519e-16, -1.117364778916e-08),
    std::complex<double>(5.298577332100e-17, -5.959189144748e-09),
    std::complex<double>(-3.009745230820e-16, -3.501207830137e-09),
    std::complex<double>(-9.186228167035e-17, -1.915294608676e-09),
    std::complex<double>(2.055647319033e-16, -8.879601871852e-10),
    std::complex<double>(4.123369939761e-16, -4.698662414010e-10),
    std::complex<double>(-3.139849491518e-16, -3.309931637583e-10),
    std::complex<double>(5.506066522859e-17, -1.816820400721e-10)};

static const std::vector<std::complex<double>> coeff_gelu_8_double_44{
    std::complex<double>(1.970461314322e+00, 0.000000000000e+00),
    std::complex<double>(-1.593875111273e+00, -2.423646025475e+00),
    std::complex<double>(-5.332570094236e-02, 1.043627310063e+00),
    std::complex<double>(-1.570391974449e-01, -5.402873054677e-01),
    std::complex<double>(-3.940694771457e-02, 2.819289867863e-01),
    std::complex<double>(-4.716127625363e-02, -1.391268773786e-01),
    std::complex<double>(-2.418730432251e-02, 6.233923043025e-02),
    std::complex<double>(-1.941167643365e-02, -2.432937320475e-02),
    std::complex<double>(-1.260556521786e-02, 7.763676253796e-03),
    std::complex<double>(-8.664960605021e-03, -1.754420766855e-03),
    std::complex<double>(-5.704614002479e-03, 1.292565051534e-04),
    std::complex<double>(-3.651093482904e-03, 8.792842531399e-05),
    std::complex<double>(-2.270560959509e-03, -3.329062052015e-05),
    std::complex<double>(-1.367226398367e-03, -2.302378982580e-06),
    std::complex<double>(-7.979823621962e-04, 4.854603433774e-06),
    std::complex<double>(-4.528446723700e-04, -5.500080713671e-07),
    std::complex<double>(-2.508556888546e-04, -7.491453056646e-07),
    std::complex<double>(-1.363438350097e-04, 2.239517241233e-07),
    std::complex<double>(-7.312414261638e-05, 1.280298946860e-07),
    std::complex<double>(-3.885704183314e-05, -6.935818435338e-08),
    std::complex<double>(-2.045210744808e-05, -2.372215028579e-08),
    std::complex<double>(-1.059289000752e-05, 2.148573735963e-08),
    std::complex<double>(-5.323541994507e-06, 4.532466957308e-09),
    std::complex<double>(-2.534606159357e-06, -7.005649868379e-09),
    std::complex<double>(-1.095525020071e-06, -8.007947707722e-10),
    std::complex<double>(-3.890401084408e-07, 2.430954434496e-09),
    std::complex<double>(-7.123273537061e-08, 8.161443049159e-11),
    std::complex<double>(5.044242802621e-08, -8.975149646921e-10),
    std::complex<double>(8.120772961289e-08, 3.455961905541e-11),
    std::complex<double>(7.542928368715e-08, 3.512492108152e-10),
    std::complex<double>(5.884712616061e-08, -3.699939660207e-11),
    std::complex<double>(4.212943410103e-08, -1.450199807245e-10),
    std::complex<double>(2.870135674255e-08, 2.446543662105e-11),
    std::complex<double>(1.893829504329e-08, 6.286847323116e-11),
    std::complex<double>(1.220565836477e-08, -1.443831859627e-11),
    std::complex<double>(7.712072154498e-09, -2.849185102259e-11),
    std::complex<double>(4.784403550098e-09, 8.229923686986e-12),
    std::complex<double>(2.915358732203e-09, 1.344066297062e-11),
    std::complex<double>(1.744138401955e-09, -5.307266236734e-12),
    std::complex<double>(1.034329697769e-09, -6.648169766598e-12),
    std::complex<double>(6.098917724102e-10, 3.421664931631e-12),
    std::complex<double>(3.589237189208e-10, 2.944192267787e-12),
    std::complex<double>(2.213863333275e-10, -2.779015756058e-12),
    std::complex<double>(1.478126284614e-10, -1.420742295235e-12),
    std::complex<double>(1.014093012815e-10, 4.286355138519e-13)};

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
                return coeff_exp_2_double_29;
            case FEFBT_SIGMOID:
                return coeff_sigmoid_8_double_34;
            case FEFBT_GELU_TANH:
                return coeff_gelu_8_double_44;
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
