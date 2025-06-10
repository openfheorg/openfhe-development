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

#include <chrono>
#include <iostream>
#include <iterator>
#include <vector>

// #define BENCH

using namespace lbcrypto;

enum TEST_CASE_TYPE {
    FUNCBT_ARBLUT = 0,
    FUNCBT_SIGNDIGIT,
};

static std::ostream& operator<<(std::ostream& os, const TEST_CASE_TYPE& type) {
    std::string typeName;
    switch (type) {
        case FUNCBT_ARBLUT:
            typeName = "FUNCBT_ARBLUT";
            break;
        case FUNCBT_SIGNDIGIT:
            typeName = "FUNCBT_SIGNDIGIT";
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
    double scaleStep;
    size_t order;
    uint32_t numSlots;
    uint32_t levelsAvailableAfterBootstrap;
    uint32_t levelsAvailableBeforeBootstrap;
    uint32_t dnum;
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
const BigInteger QBFVINIT("1152921504606846976");             // 2^60
const BigInteger QBFVINITMED("2361183241434822606848");       // 2^71
const BigInteger QBFVINITLARGE("1208925819614629174706176");  // 2^80
const BigInteger PINPUT(256);
const BigInteger POUTPUT(256);
const BigInteger QDFLT(1UL << 47);
constexpr double SCALE(32.0);
constexpr double SCALESTEP(1.0);
// constexpr size_t ORDER(1);
// constexpr uint32_t SLOTS(16);
constexpr uint32_t AFTERBOOT(0);
constexpr uint32_t BEFOREBOOT(0);

// These are for the benchmarks, keep only a few as unit tests.
// clang-format off
static std::vector<TEST_CASE_FUNCBT> testCases = {
    //     estCaseType, Desc,      QBFVInit,    PInput, POutput,           Q,      Bigq, scale, scaleStep, order, numSlots, lvlsAfterBootstrap, lvlsBeforeBootstrap, dnum, levelBudget
    {    FUNCBT_ARBLUT, "01",      QBFVINIT,         2,       2,   1UL << 33, 1UL << 33,     1, SCALESTEP,     1,  1 << 14,          AFTERBOOT,          BEFOREBOOT,    3, {3, 3} },
    {    FUNCBT_ARBLUT, "02",      QBFVINIT,         2,       2,   1UL << 33, 1UL << 33,     1, SCALESTEP,     2,  1 << 14,          AFTERBOOT,          BEFOREBOOT,    7, {3, 3} },
    {    FUNCBT_ARBLUT, "03",      QBFVINIT,         2,       2,   1UL << 33, 1UL << 33,     1, SCALESTEP,     3,  1 << 14,          AFTERBOOT,          BEFOREBOOT,    7, {3, 3} },
    {    FUNCBT_ARBLUT, "04",      QBFVINIT,         4,       4,   1UL << 35, 1UL << 35,    16, SCALESTEP,     1,  1 << 15,          AFTERBOOT,          BEFOREBOOT,    3, {4, 4} },
    {    FUNCBT_ARBLUT, "05",      QBFVINIT,         4,       4,   1UL << 35, 1UL << 35,    16, SCALESTEP,     2,  1 << 15,          AFTERBOOT,          BEFOREBOOT,    3, {4, 4} },
    {    FUNCBT_ARBLUT, "06",      QBFVINIT,         4,       4,   1UL << 35, 1UL << 35,    16, SCALESTEP,     3,  1 << 15,          AFTERBOOT,          BEFOREBOOT,    3, {4, 4} },
    {    FUNCBT_ARBLUT, "07",      QBFVINIT,         8,       8,   1UL << 37, 1UL << 37,    16, SCALESTEP,     1,  1 << 15,          AFTERBOOT,          BEFOREBOOT,    3, {4, 4} },
    {    FUNCBT_ARBLUT, "08",      QBFVINIT,         8,       8,   1UL << 37, 1UL << 37,    16, SCALESTEP,     2,  1 << 15,          AFTERBOOT,          BEFOREBOOT,    3, {4, 4} },
    {    FUNCBT_ARBLUT, "09",      QBFVINIT,         8,       8,   1UL << 37, 1UL << 37,    16, SCALESTEP,     3,  1 << 15,          AFTERBOOT,          BEFOREBOOT,    3, {4, 4} },
    {    FUNCBT_ARBLUT, "10",      QBFVINIT,        16,      16,   1UL << 38, 1UL << 38,    32, SCALESTEP,     1,  1 << 15,          AFTERBOOT,          BEFOREBOOT,    3, {4, 4} },
    {    FUNCBT_ARBLUT, "11",      QBFVINIT,        16,      16,   1UL << 38, 1UL << 38,    32, SCALESTEP,     2,  1 << 15,          AFTERBOOT,          BEFOREBOOT,    3, {4, 4} },
    {    FUNCBT_ARBLUT, "12",      QBFVINIT,        16,      16,   1UL << 38, 1UL << 38,    32, SCALESTEP,     3,  1 << 15,          AFTERBOOT,          BEFOREBOOT,    3, {4, 4} },
    {    FUNCBT_ARBLUT, "13",      QBFVINIT,    PINPUT, POUTPUT,       QDFLT,     QDFLT, SCALE, SCALESTEP,     1,  1 << 15,          AFTERBOOT,          BEFOREBOOT,    4, {3, 3} },
    {    FUNCBT_ARBLUT, "14",      QBFVINIT,    PINPUT, POUTPUT,       QDFLT,     QDFLT, SCALE, SCALESTEP,     2,  1 << 15,          AFTERBOOT,          BEFOREBOOT,    4, {3, 3} },
    {    FUNCBT_ARBLUT, "15",      QBFVINIT,    PINPUT, POUTPUT,       QDFLT,     QDFLT, SCALE, SCALESTEP,     3,  1 << 15,          AFTERBOOT,          BEFOREBOOT,    5, {3, 3} },
    {    FUNCBT_ARBLUT, "16",      QBFVINIT,       512,     512,   1UL << 48, 1UL << 48,    45, SCALESTEP,     1,  1 << 15,          AFTERBOOT,          BEFOREBOOT,    5, {3, 3} },
    {    FUNCBT_ARBLUT, "17",      QBFVINIT,       512,     512,   1UL << 48, 1UL << 48,    45, SCALESTEP,     2,  1 << 15,          AFTERBOOT,          BEFOREBOOT,    5, {3, 3} },
    {    FUNCBT_ARBLUT, "18",      QBFVINIT,       512,     512,   1UL << 48, 1UL << 48,    45, SCALESTEP,     3,  1 << 15,          AFTERBOOT,          BEFOREBOOT,    7, {3, 3} },
    {    FUNCBT_ARBLUT, "19", QBFVINITLARGE,      4096,    4096,   1UL << 55, 1UL << 55,  2000, SCALESTEP,     1,  1 << 16,          AFTERBOOT,          BEFOREBOOT,    3, {4, 4} },
    {    FUNCBT_ARBLUT, "20", QBFVINITLARGE,      4096,    4096,   1UL << 55, 1UL << 55,  2000, SCALESTEP,     2,  1 << 16,          AFTERBOOT,          BEFOREBOOT,    3, {4, 4} },
    {    FUNCBT_ARBLUT, "21", QBFVINITLARGE,      4096,    4096,   1UL << 55, 1UL << 55,  2000, SCALESTEP,     3,  1 << 16,          AFTERBOOT,          BEFOREBOOT,    3, {4, 4} },
    {    FUNCBT_ARBLUT, "22", QBFVINITLARGE,     16382,   16382,   1UL << 58, 1UL << 58,  8000, SCALESTEP,     1,  1 << 16,          AFTERBOOT,          BEFOREBOOT,    3, {4, 4} },
    {    FUNCBT_ARBLUT, "23", QBFVINITLARGE,     16382,   16382,   1UL << 58, 1UL << 58,  8000, SCALESTEP,     2,  1 << 16,          AFTERBOOT,          BEFOREBOOT,    3, {4, 4} },
    {    FUNCBT_ARBLUT, "24", QBFVINITLARGE,     16382,   16382,   1UL << 58, 1UL << 58,  8000, SCALESTEP,     3,  1 << 16,          AFTERBOOT,          BEFOREBOOT,    3, {4, 4} },
    { FUNCBT_SIGNDIGIT, "25",      QBFVINIT,      4096,       2,   1UL << 46, 1UL << 35,     1,         1,     1,  1 << 15,          AFTERBOOT,          BEFOREBOOT,    3, {4, 4} },
    { FUNCBT_SIGNDIGIT, "26",      QBFVINIT,      4096,       2,   1UL << 46, 1UL << 35,     1,         1,     2,  1 << 15,          AFTERBOOT,          BEFOREBOOT,    3, {4, 4} },  // not needed for benchmark
    { FUNCBT_SIGNDIGIT, "27",      QBFVINIT,      4096,       4,   1UL << 45, 1UL << 35,    10,         2,     1,  1 << 15,          AFTERBOOT,          BEFOREBOOT,    3, {4, 4} },
    { FUNCBT_SIGNDIGIT, "28",      QBFVINIT,      4096,       4,   1UL << 45, 1UL << 35,    10,         2,     2,  1 << 15,          AFTERBOOT,          BEFOREBOOT,    3, {4, 4} },  // not needed for benchmark
    { FUNCBT_SIGNDIGIT, "29",      QBFVINIT,      4096,       8,   1UL << 46, 1UL << 37,    16,         4,     1,  1 << 15,          AFTERBOOT,          BEFOREBOOT,    3, {4, 4} },
    { FUNCBT_SIGNDIGIT, "30",      QBFVINIT,      4096,       8,   1UL << 46, 1UL << 37,    16,         4,     2,  1 << 15,          AFTERBOOT,          BEFOREBOOT,    3, {4, 4} },  // not needed for benchmark
    { FUNCBT_SIGNDIGIT, "31",      QBFVINIT,      4096,      16,   1UL << 48, 1UL << 40,    32,         8,     1,  1 << 15,          AFTERBOOT,          BEFOREBOOT,    3, {4, 4} },
    { FUNCBT_SIGNDIGIT, "32",      QBFVINIT,      4096,      16,   1UL << 48, 1UL << 40,    32,         8,     2,  1 << 15,          AFTERBOOT,          BEFOREBOOT,    3, {4, 4} },  // not needed for benchmark
    { FUNCBT_SIGNDIGIT, "33",      QBFVINIT,      4096,      64,   1UL << 48, 1UL << 42,   128,        32,     1,  1 << 15,          AFTERBOOT,          BEFOREBOOT,    3, {4, 4} },
    { FUNCBT_SIGNDIGIT, "34",      QBFVINIT,      4096,      64,   1UL << 48, 1UL << 42,   128,        32,     2,  1 << 15,          AFTERBOOT,          BEFOREBOOT,    3, {4, 4} },  // not needed for benchmark
    { FUNCBT_SIGNDIGIT, "35",   QBFVINITMED, 1UL << 21,       2,   1UL << 56, 1UL << 36,     1,         1,     1,  1 << 15,          AFTERBOOT,          BEFOREBOOT,    3, {4, 4} },
    { FUNCBT_SIGNDIGIT, "36",   QBFVINITMED, 1UL << 21,       2,   1UL << 55, 1UL << 35,     1,         1,     2,  1 << 15,          AFTERBOOT,          BEFOREBOOT,    3, {4, 4} },  // not needed for benchmark
    { FUNCBT_SIGNDIGIT, "37",   QBFVINITMED, 1UL << 21,       8,   1UL << 55, 1UL << 37,    16,         4,     1,  1 << 15,          AFTERBOOT,          BEFOREBOOT,    3, {4, 4} },
    { FUNCBT_SIGNDIGIT, "38",   QBFVINITMED, 1UL << 21,       8,   1UL << 55, 1UL << 37,    16,         4,     2,  1 << 15,          AFTERBOOT,          BEFOREBOOT,    3, {4, 4} },  // not needed for benchmark
    { FUNCBT_SIGNDIGIT, "39",   QBFVINITMED, 1UL << 21,     128,   1UL << 57, 1UL << 43,   256,        16,     1,  1 << 15,          AFTERBOOT,          BEFOREBOOT,    3, {4, 4} },
    { FUNCBT_SIGNDIGIT, "40",   QBFVINITMED, 1UL << 21,     128,   1UL << 57, 1UL << 43,   256,        16,     2,  1 << 15,          AFTERBOOT,          BEFOREBOOT,    3, {4, 4} },  // not needed for benchmark
    { FUNCBT_SIGNDIGIT, "41", QBFVINITLARGE, 1UL << 32,     256, QBFVINITMED, 1UL << 47,   256,        16,     1,  1 << 15,          AFTERBOOT,          BEFOREBOOT,    4, {3, 3} },
    { FUNCBT_SIGNDIGIT, "42", QBFVINITLARGE, 1UL << 32,     256, QBFVINITMED, 1UL << 47,   256,        16,     2,  1 << 15,          AFTERBOOT,          BEFOREBOOT,    4, {3, 3} },  // not needed for benchmark
};
// clang-format on

class UTCKKSRNS_FUNCBT : public ::testing::TestWithParam<TEST_CASE_FUNCBT> {
protected:
    void SetUp() {}

    void TearDown() {
        CryptoContextFactory<DCRTPoly>::ReleaseAllContexts();
    }

    void UnitTest_ArbLUT(TEST_CASE_FUNCBT t, const std::string& failmsg = std::string()) {
        try {
#ifdef BENCH
            auto start = std::chrono::high_resolution_clock::now();
#else
            t.numSlots = 16;
            t.dnum     = 3;
#endif

            auto a    = t.PInput.ConvertToInt<int64_t>();
            auto b    = t.POutput.ConvertToInt<int64_t>();
            auto func = [a, b](int64_t x) -> int64_t {
                return (x % a - a / 2) % b;
            };

            std::vector<int64_t> x = {
                (t.PInput.ConvertToInt<int64_t>() / 2), (t.PInput.ConvertToInt<int64_t>() / 2) + 1, 0, 3, 16, 33, 64,
                (t.PInput.ConvertToInt<int64_t>() - 1)};
            if (x.size() < t.numSlots * 2)
                x = Fillint64(x, t.numSlots * 2);

            std::vector<int64_t> coeffint;
            std::vector<std::complex<double>> coeffcomp;
            bool binaryLUT = (t.PInput.ConvertToInt() == 2) && (t.order == 1);

            if (binaryLUT)
                coeffint = {func(1),
                            func(0) - func(1)};  // those are coefficients for [1, cos^2(pi x)], not [1, cos(2pi x)]
            else
                coeffcomp =
                    GetHermiteTrigCoefficients(func, t.PInput.ConvertToInt(), t.order, t.scale);  // divided by 2

#ifdef BENCH
            auto stop = std::chrono::high_resolution_clock::now();
            std::cerr << "Coefficient Generation: " << std::chrono::duration<double>(stop - start).count() << " s"
                      << std::endl;
            start = std::chrono::high_resolution_clock::now();
#endif

            uint32_t dcrtBits = t.Bigq.GetMSB() - 1;
            uint32_t firstMod = t.Bigq.GetMSB() - 1;
            CCParams<CryptoContextCKKSRNS> parameters;
            SecretKeyDist secretKeyDist = SPARSE_TERNARY;
            parameters.SetSecretKeyDist(secretKeyDist);
            parameters.SetSecurityLevel(HEStd_NotSet);
            parameters.SetScalingModSize(dcrtBits);
            parameters.SetScalingTechnique(FIXEDMANUAL);
            parameters.SetFirstModSize(firstMod);
            parameters.SetNumLargeDigits(t.dnum);
            parameters.SetBatchSize(t.numSlots);
            parameters.SetRingDim(2 * t.numSlots);  // Currently not working for sparse packing
            uint32_t depth = t.levelsAvailableAfterBootstrap + t.lvlb[0] + t.lvlb[1] + 2;

            if (binaryLUT)
                depth += FHECKKSRNS::AdjustDepthFuncBT(coeffint, t.PInput, t.order);
            else
                depth += FHECKKSRNS::AdjustDepthFuncBT(coeffcomp, t.PInput, t.order);

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

            if (binaryLUT)
                cc->EvalFuncBTSetup(t.numSlots, t.PInput.GetMSB() - 1, coeffint, {0, 0}, t.lvlb, scaleMod, 0, t.order);
            else
                cc->EvalFuncBTSetup(t.numSlots, t.PInput.GetMSB() - 1, coeffcomp, {0, 0}, t.lvlb, scaleMod, 0, t.order);

            cc->EvalBootstrapKeyGen(keyPair.secretKey, t.numSlots);

#ifdef BENCH
            stop = std::chrono::high_resolution_clock::now();
            std::cerr << "FuncBootstrapping Setup: " << std::chrono::duration<double>(stop - start).count() << " s"
                      << std::endl;
            start = std::chrono::high_resolution_clock::now();
#endif

            auto ep =
                SchemeletRLWEMP::GetElementParams(keyPair.secretKey, depth - (t.levelsAvailableBeforeBootstrap > 0));

            auto ctxtBFV = SchemeletRLWEMP::EncryptCoeff(x, t.QBFVInit, t.PInput, keyPair.secretKey, ep);

#ifdef BENCH
            stop = std::chrono::high_resolution_clock::now();
            std::cerr << "Coefficient Encryption: " << std::chrono::duration<double>(stop - start).count() << " s"
                      << std::endl;
            start = std::chrono::high_resolution_clock::now();
#endif

            SchemeletRLWEMP::ModSwitch(ctxtBFV, t.Q, t.QBFVInit);

            auto ctxt = SchemeletRLWEMP::convert(*cc, ctxtBFV, keyPair.publicKey, t.Bigq, t.numSlots,
                                                 depth - (t.levelsAvailableBeforeBootstrap > 0));

            Ciphertext<DCRTPoly> ctxtAfterFuncBT;
            if (binaryLUT)
                ctxtAfterFuncBT =
                    cc->EvalFuncBT(ctxt, coeffint, t.PInput.GetMSB() - 1, ep->GetModulus(), 1.0, 0, false, t.order);
            else
                ctxtAfterFuncBT =
                    cc->EvalFuncBT(ctxt, coeffcomp, t.PInput.GetMSB() - 1, ep->GetModulus(), 1.0, 0, false, t.order);

            // Scalar addresses the division in Hermite Interpolation
            cc->GetScheme()->MultByIntegerInPlace(ctxtAfterFuncBT, t.scale);
            cc->ModReduceInPlace(ctxtAfterFuncBT);

            if (QPrime != ctxtAfterFuncBT->GetElements()[0].GetModulus())
                OPENFHE_THROW("The ciphertext modulus after bootstrapping is not as expected.");

            auto polys = SchemeletRLWEMP::convert(ctxtAfterFuncBT, t.Q, QPrime);

#ifdef BENCH
            stop = std::chrono::high_resolution_clock::now();
            std::cerr << "FuncBootstrapping: " << std::chrono::duration<double>(stop - start).count() << " s"
                      << std::endl;
            start = std::chrono::high_resolution_clock::now();
#endif

            auto computed = SchemeletRLWEMP::DecryptCoeff(polys, t.Q, t.PInput, keyPair.secretKey, ep, t.numSlots);

#ifdef BENCH
            stop = std::chrono::high_resolution_clock::now();
            std::cerr << "Poly Decryption: " << std::chrono::duration<double>(stop - start).count() << " s"
                      << std::endl;
#endif

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

            checkEquality((*max_error_it), int64_t(0), 0.0001, failmsg + " LUT evaluation fails");
        }
        catch (std::exception& e) {
            std::cerr << "Exception thrown from " << __func__ << "(): " << e.what() << std::endl;
            EXPECT_TRUE(0 == 1) << failmsg;
        }
        catch (...) {
            UNIT_TEST_HANDLE_ALL_EXCEPTIONS;
        }
    }

    void UnitTest_SignDigit(TEST_CASE_FUNCBT t, const std::string& failmsg = std::string()) {
        try {
#ifndef BENCH
            t.numSlots = 16;
            t.dnum     = 3;
#endif
            auto PInput  = t.PInput;  // Will get modified in the loop.
            BigInteger Q = t.Q;       // Will get modified in the loop.

            auto a = PInput.ConvertToInt<int64_t>();
            auto b = t.POutput.ConvertToInt<int64_t>();

            auto funcMod = [b](int64_t x) -> int64_t {
                return (x % b);
            };
            auto funcStep = [a, b](int64_t x) -> int64_t {
                return (x % a) >= (b / 2);
            };

            std::vector<int64_t> x = {static_cast<int64_t>(PInput.ConvertToInt() / 2),
                                      static_cast<int64_t>(PInput.ConvertToInt() / 2) + 1,
                                      0,
                                      3,
                                      16,
                                      33,
                                      64,
                                      static_cast<int64_t>(PInput.ConvertToInt() - 1)};
            if (x.size() < t.numSlots * 2)
                x = Fillint64(x, t.numSlots * 2);

            auto exact(x);
            std::transform(x.begin(), x.end(), exact.begin(),
                           [&](const int64_t& elem) { return (elem >= PInput.ConvertToDouble() / 2.); });

            std::vector<int64_t> coeffintMod;
            std::vector<std::complex<double>> coeffcompMod;
            std::vector<std::complex<double>> coeffcompStep;
            bool binaryLUT = (t.POutput.ConvertToInt() == 2) && (t.order == 1);

            if (binaryLUT) {
                coeffintMod = {
                    funcMod(1),
                    funcMod(0) - funcMod(1)};  // those are coefficients for [1, cos^2(pi x)], not [1, cos(2pi x)]
            }
            else {
                coeffcompMod =
                    GetHermiteTrigCoefficients(funcMod, t.POutput.ConvertToInt(), t.order, t.scale);  // divided by 2
                coeffcompStep = GetHermiteTrigCoefficients(funcStep, t.POutput.ConvertToInt(), t.order,
                                                           t.scaleStep);  // divided by 2
            }

            uint32_t dcrtBits = t.Bigq.GetMSB() - 1;
            uint32_t firstMod = t.Bigq.GetMSB() - 1;

            CCParams<CryptoContextCKKSRNS> parameters;
            SecretKeyDist secretKeyDist = SPARSE_TERNARY;
            parameters.SetSecretKeyDist(secretKeyDist);
            parameters.SetSecurityLevel(HEStd_NotSet);
            parameters.SetScalingModSize(dcrtBits);
            parameters.SetScalingTechnique(FIXEDMANUAL);
            parameters.SetFirstModSize(firstMod);
            parameters.SetNumLargeDigits(t.dnum);
            parameters.SetBatchSize(t.numSlots);
            parameters.SetRingDim(2 * t.numSlots);  // Currently not working for sparse packing

            uint32_t depth = t.levelsAvailableAfterBootstrap + t.lvlb[0] + t.lvlb[1] + 2;

            if (binaryLUT)
                depth += FHECKKSRNS::AdjustDepthFuncBT(coeffintMod, t.POutput, t.order);
            else
                depth += FHECKKSRNS::AdjustDepthFuncBT(coeffcompMod, t.POutput, t.order);

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
            double scaleOutput =
                QPrime.ConvertToLongDouble() / (t.Bigq.ConvertToLongDouble() * PInput.ConvertToDouble());

            if (binaryLUT)
                cc->EvalFuncBTSetup(t.numSlots, t.POutput.GetMSB() - 1, coeffintMod, {0, 0}, t.lvlb, scaleOutput, 0,
                                    t.order);
            else
                cc->EvalFuncBTSetup(t.numSlots, t.POutput.GetMSB() - 1, coeffcompMod, {0, 0}, t.lvlb, scaleOutput, 0,
                                    t.order);

            cc->EvalBootstrapKeyGen(keyPair.secretKey, t.numSlots);

            auto ep =
                SchemeletRLWEMP::GetElementParams(keyPair.secretKey, depth - (t.levelsAvailableBeforeBootstrap > 0));

            auto ctxtBFV = SchemeletRLWEMP::EncryptCoeff(x, t.QBFVInit, PInput, keyPair.secretKey, ep);

            SchemeletRLWEMP::ModSwitch(ctxtBFV, Q, t.QBFVInit);

            double QBFVDouble   = Q.ConvertToDouble();
            double pBFVDouble   = PInput.ConvertToDouble();
            double pDigitDouble = t.POutput.ConvertToDouble();
            double qDigitDouble = t.Bigq.ConvertToDouble();
            BigInteger pOrig    = PInput;
            std::vector<int64_t> coeffint;
            std::vector<std::complex<double>> coeffcomp;
            if (binaryLUT)
                coeffint = coeffintMod;
            else
                coeffcomp = coeffcompMod;
            double scale        = t.scale;
            bool step           = false;
            bool go             = QBFVDouble > qDigitDouble;
            size_t levelsToDrop = 0;

            // For arbitrary digit size, pNew > 2, the last iteration needs to evaluate step pNew not mod pNew.
            // Currently this only works when log(pNew) divides log(p).
            while (go) {
                auto encryptedDigit = ctxtBFV;

                // Apply mod q
                encryptedDigit[0].SwitchModulus(t.Bigq, 1, 0, 0);
                encryptedDigit[1].SwitchModulus(t.Bigq, 1, 0, 0);

                auto ctxt = SchemeletRLWEMP::convert(*cc, encryptedDigit, keyPair.publicKey, t.Bigq, t.numSlots,
                                                     depth - (t.levelsAvailableBeforeBootstrap > 0));

                // Bootstrap the digit.
                Ciphertext<DCRTPoly> ctxtAfterFuncBT;
                if (binaryLUT)
                    ctxtAfterFuncBT =
                        cc->EvalFuncBT(ctxt, coeffint, t.POutput.GetMSB() - 1, ep->GetModulus(),
                                       pOrig.ConvertToDouble() / pBFVDouble, levelsToDrop, false, t.order);
                else
                    ctxtAfterFuncBT =
                        cc->EvalFuncBT(ctxt, coeffcomp, t.POutput.GetMSB() - 1, ep->GetModulus(),
                                       pOrig.ConvertToDouble() / pBFVDouble, levelsToDrop, false, t.order);

                // Scale to address the division in Hermite Interpolation
                cc->GetScheme()->MultByIntegerInPlace(ctxtAfterFuncBT, scale);
                cc->ModReduceInPlace(ctxtAfterFuncBT);

                if (QPrime != ctxtAfterFuncBT->GetElements()[0].GetModulus())
                    OPENFHE_THROW("The ciphertext modulus after bootstrapping is not as expected.");

                auto polys = SchemeletRLWEMP::convert(ctxtAfterFuncBT, Q, QPrime);

                BigInteger QNew(std::to_string(static_cast<uint64_t>(QBFVDouble / pDigitDouble)));
                BigInteger PNew(std::to_string(static_cast<uint64_t>(pBFVDouble / pDigitDouble)));

                if (!step) {
                    // Subtract digit
                    ctxtBFV[0] = ctxtBFV[0] - polys[0];
                    ctxtBFV[1] = ctxtBFV[1] - polys[1];

                    // Do modulus switching from Q to QNew for the BFV ciphertext
                    ctxtBFV[0] = ctxtBFV[0].MultiplyAndRound(QNew, Q);
                    ctxtBFV[0].SwitchModulus(QNew, 1, 0, 0);
                    ctxtBFV[1] = ctxtBFV[1].MultiplyAndRound(QNew, Q);
                    ctxtBFV[1].SwitchModulus(QNew, 1, 0, 0);

                    QBFVDouble /= pDigitDouble;
                    pBFVDouble /= pDigitDouble;
                    Q      = QNew;
                    PInput = PNew;
                }
                else {
                    ctxtBFV[0] = polys[0];
                    ctxtBFV[1] = polys[1];
                }

                if ((t.POutput == 2 && QBFVDouble <= qDigitDouble) || step) {
                    auto computed =
                        SchemeletRLWEMP::DecryptCoeff(ctxtBFV, Q, PInput, keyPair.secretKey, ep, t.numSlots);

                    std::transform(exact.begin(), exact.end(), computed.begin(), exact.begin(), std::minus<int64_t>());
                    std::transform(exact.begin(), exact.end(), exact.begin(),
                                   [&](const int64_t& elem) { return (std::abs(elem)) % (pOrig.ConvertToInt()); });
                    auto max_error_it = std::max_element(exact.begin(), exact.end());
                    // std::cerr << "\n=======Max absolute error: " << *max_error_it << std::endl << std::endl;

                    checkEquality((*max_error_it), int64_t(0), 0.0001,
                                  failmsg + " Multi-precision sign evaluation fails");
                }

                go = QBFVDouble > qDigitDouble;

                if (t.POutput > 2 && !go && !step) {
                    if (!binaryLUT)
                        coeffcomp = coeffcompStep;
                    scale = t.scaleStep;
                    step  = true;
                    go    = true;
                    if (coeffcompMod.size() > 4 && GetMultiplicativeDepthByCoeffVector(coeffcompMod, true) >
                                                       GetMultiplicativeDepthByCoeffVector(coeffcompStep, true)) {
                        levelsToDrop = GetMultiplicativeDepthByCoeffVector(coeffcompMod, true) -
                                       GetMultiplicativeDepthByCoeffVector(coeffcompStep, true);
                    }
                }
            }
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
        case FUNCBT_SIGNDIGIT:
            UnitTest_SignDigit(test, test.buildTestName());
            break;
        default:
            break;
    }
}

INSTANTIATE_TEST_SUITE_P(UnitTests, UTCKKSRNS_FUNCBT, ::testing::ValuesIn(testCases), testName);
