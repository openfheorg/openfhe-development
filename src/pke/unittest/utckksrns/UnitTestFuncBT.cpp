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

#include "cryptocontext.h"
#include "gen-cryptocontext.h"
#include "gtest/gtest.h"
#include "math/hermite.h"
#include "scheme/ckksrns/ckksrns-fhe.h"
#include "scheme/ckksrns/ckksrns-utils.h"
#include "scheme/ckksrns/gen-cryptocontext-ckksrns.h"
#include "schemelet/rlwe-mp.h"
#include "UnitTestUtils.h"
#include "UnitTestCCParams.h"
#include "UnitTestCryptoContext.h"
#include "utils/debug.h"

#include <iostream>
#include <iterator>
#include <vector>

using namespace lbcrypto;

enum TEST_CASE_TYPE {
    FUNCBT_ARBLUT = 0,
    FUNCBT_XXXXXX,
};

static std::ostream& operator<<(std::ostream& os, const TEST_CASE_TYPE& type) {
    std::string typeName;
    switch (type) {
        case FUNCBT_ARBLUT:
            typeName = "FUNCBT_ARBLUT";
            break;
        case FUNCBT_XXXXXX:
            typeName = "FUNCBT_";
            break;
        default:
            typeName = "UNKNOWN";
            break;
    }
    return os << typeName;
}

struct TEST_CASE_FUNCBT {
    TEST_CASE_TYPE testCaseType;
    std::string description;

    BigInteger QBFVInit;
    BigInteger PInput;
    BigInteger POutput;
    BigInteger Q;
    BigInteger Bigq;
    double scale;
    size_t order;
    uint32_t numSlots;
    uint32_t levelsAvailableAfterBootstrap;
    uint32_t levelsAvailableBeforeBootstrap;
    std::vector<uint32_t> lvlb;

    std::string buildTestName() const {
        std::stringstream ss;
        ss << testCaseType << "_" << description;
        return ss.str();
    }
};

// this lambda provides a name to be printed for every test run by INSTANTIATE_TEST_SUITE_P.
// the name MUST be constructed from digits, letters and '_' only
static auto testName = [](const testing::TestParamInfo<TEST_CASE_FUNCBT>& test) {
    return test.param.buildTestName();
};

// TODO: update default values
const BigInteger QBFVINIT("1152921504606846976");
const BigInteger PINPUT(256);
const BigInteger POUTPUT(256);
const BigInteger QDFLT(1UL << 47);
constexpr double SCALE(45.0);
constexpr size_t ORDER(1);
constexpr uint32_t SLOTS(32);
constexpr uint32_t AFTERBOOT(0);
constexpr uint32_t BEFOREBOOT(0);

// clang-format off
static std::vector<TEST_CASE_FUNCBT> testCases = {
    // TestCaseType, Desc, QBFVInit, PInput, POutput,     Q,  Bigq, scale, order, numSlots, lvlsAfterBootstrap, lvlsBeforeBootstrap, levelBudget
    { FUNCBT_ARBLUT, "01", QBFVINIT, PINPUT, POUTPUT, QDFLT, QDFLT, SCALE,     1,    SLOTS,          AFTERBOOT,          BEFOREBOOT, {3, 3} },
    { FUNCBT_ARBLUT, "02", QBFVINIT, PINPUT, POUTPUT, QDFLT, QDFLT, SCALE,     2,    SLOTS,          AFTERBOOT,          BEFOREBOOT, {3, 3} },
    { FUNCBT_ARBLUT, "03", QBFVINIT, PINPUT, POUTPUT, QDFLT, QDFLT, SCALE,     3,    SLOTS,          AFTERBOOT,          BEFOREBOOT, {3, 3} },
};
// clang-format on

class UTCKKSRNS_FUNCBT : public ::testing::TestWithParam<TEST_CASE_FUNCBT> {
protected:
    void SetUp() {}

    void TearDown() {
        CryptoContextFactory<DCRTPoly>::ReleaseAllContexts();
    }

    void UnitTest_ArbLUT(const TEST_CASE_FUNCBT& t, const std::string& failmsg = std::string()) {
        try {
            auto a    = t.PInput.ConvertToInt<int64_t>();
            auto b    = t.POutput.ConvertToInt<int64_t>();
            auto func = [a, b](int64_t x) -> int64_t {
                return (x % a - a / 2) % b;
            };

            std::vector<int64_t> x = {static_cast<int64_t>(t.PInput.ConvertToInt() / 2),
                                      static_cast<int64_t>(t.PInput.ConvertToInt() / 2) + 1,
                                      0,
                                      3,
                                      16,
                                      33,
                                      64,
                                      static_cast<int64_t>(t.PInput.ConvertToInt() - 1)};
            if (x.size() < t.numSlots * 2)
                x = Fillint64(x, t.numSlots * 2);

            auto coefficients = GetHermiteTrigCoefficients(func, t.PInput.ConvertToInt(), t.order, t.scale);
            uint32_t dcrtBits = t.Bigq.GetMSB() - 1;
            uint32_t firstMod = t.Bigq.GetMSB() - 1;

            CCParams<CryptoContextCKKSRNS> parameters;
            SecretKeyDist secretKeyDist = SPARSE_TERNARY;
            parameters.SetSecretKeyDist(secretKeyDist);
            parameters.SetSecurityLevel(HEStd_NotSet);
            parameters.SetScalingModSize(dcrtBits);
            parameters.SetScalingTechnique(FIXEDMANUAL);
            parameters.SetFirstModSize(firstMod);
            parameters.SetNumLargeDigits(4);
            parameters.SetBatchSize(t.numSlots);
            parameters.SetRingDim(2 * t.numSlots);  // Currently not working for sparse packing

            uint32_t depth = t.levelsAvailableAfterBootstrap + t.lvlb[0] + t.lvlb[1] + 2;

            depth += FHECKKSRNS::AdjustDepthFuncBT(coefficients, t.PInput, t.order);

            parameters.SetMultiplicativeDepth(depth);

            auto cc = GenCryptoContext(parameters);
            cc->Enable(PKE);
            cc->Enable(KEYSWITCH);
            cc->Enable(LEVELEDSHE);
            cc->Enable(ADVANCEDSHE);
            cc->Enable(FHE);

            auto keyPair = cc->KeyGen();
            cc->EvalMultKeyGen(keyPair.secretKey);

            BigInteger QPrime = keyPair.publicKey->GetPublicElements()[0].GetParams()->GetParams()[0]->GetModulus();
            uint32_t cnt      = 1;
            auto levels       = t.levelsAvailableAfterBootstrap;
            while (levels > 0) {
                QPrime *= keyPair.publicKey->GetPublicElements()[0].GetParams()->GetParams()[cnt]->GetModulus();
                levels--;
                cnt++;
            }
            double scaleMod =
                QPrime.ConvertToLongDouble() / (t.Bigq.ConvertToLongDouble() * t.PInput.ConvertToDouble());

            cc->EvalFuncBTSetup(t.numSlots, t.PInput.GetMSB() - 1, coefficients, {0, 0}, t.lvlb, scaleMod, 0, t.order);

            cc->EvalBootstrapKeyGen(keyPair.secretKey, t.numSlots);

            auto ep =
                SchemeletRLWEMP::GetElementParams(keyPair.secretKey, depth - (t.levelsAvailableBeforeBootstrap > 0));

            auto ctxtBFV = SchemeletRLWEMP::EncryptCoeff(x, t.QBFVInit, t.PInput, keyPair.secretKey, ep);

            SchemeletRLWEMP::ModSwitch(ctxtBFV, t.Q, t.QBFVInit);

            auto ctxt = SchemeletRLWEMP::convert(*cc, ctxtBFV, keyPair.publicKey, t.Bigq, t.numSlots,
                                                 depth - (t.levelsAvailableBeforeBootstrap > 0));

            auto ctxtAfterFuncBT = cc->EvalFuncBT(ctxt, coefficients, t.PInput.GetMSB() - 1, ep->GetModulus(), 1.0, 0,
                                                  false, t.order);  // Apply LUT

            // Scalar addresses the division in Hermite Interpolation
            cc->GetScheme()->MultByIntegerInPlace(ctxtAfterFuncBT, t.scale);
            cc->ModReduceInPlace(ctxtAfterFuncBT);

            if (QPrime != ctxtAfterFuncBT->GetElements()[0].GetModulus())
                OPENFHE_THROW("The ciphertext modulus after bootstrapping is not as expected.");

            auto polys = SchemeletRLWEMP::convert(ctxtAfterFuncBT, t.Q, QPrime);

            auto computed = SchemeletRLWEMP::DecryptCoeff(polys, t.Q, t.PInput, keyPair.secretKey, ep, t.numSlots);

            auto exact(x);
            std::transform(x.begin(), x.end(), exact.begin(), [&](const int64_t& elem) {
                return (func(elem) > t.POutput.ConvertToDouble() / 2.) ? func(elem) - t.POutput.ConvertToInt() :
                                                                         func(elem);
            });

            std::transform(exact.begin(), exact.end(), computed.begin(), exact.begin(), std::minus<int64_t>());
            std::transform(exact.begin(), exact.end(), exact.begin(),
                           [&](const int64_t& elem) { return (std::abs(elem)) % (t.PInput.ConvertToInt()); });
            auto max_error_it = std::max_element(exact.begin(), exact.end());
            // std::cerr << "\n=======Max absolute error: " << *max_error_it << std::endl << std::endl;

            checkEquality((*max_error_it), int64_t(0), 0.0001);
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

// ===========================================================================================================
TEST_P(UTCKKSRNS_FUNCBT, CKKSRNS) {
    setupSignals();
    auto test = GetParam();

    switch (test.testCaseType) {
        case FUNCBT_ARBLUT:
            UnitTest_ArbLUT(test, test.buildTestName());
            break;
        default:
            break;
    }
}

INSTANTIATE_TEST_SUITE_P(UnitTests, UTCKKSRNS_FUNCBT, ::testing::ValuesIn(testCases), testName);
