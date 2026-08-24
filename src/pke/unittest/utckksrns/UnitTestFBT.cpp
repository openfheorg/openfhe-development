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

#include "config_core.h"
#include "cryptocontext.h"
#include "gen-cryptocontext.h"
#include "gtest/gtest.h"
#include "math/hermite.h"
#include "scheme/ckksrns/ckksrns-fhe.h"
#include "scheme/ckksrns/ckksrns-utils.h"
#include "scheme/ckksrns/gen-cryptocontext-ckksrns.h"
#include "schemelet/rlwe-mp.h"
#include "UnitTestCCParams.h"
#include "UnitTestCryptoContext.h"
#include "UnitTestUtils.h"
#include "utils/debug.h"

#include <algorithm>
#include <chrono>
#include <complex>
#include <functional>
#include <iostream>
#include <iterator>
#include <memory>
#include <numeric>
#include <ostream>
#include <string>
#include <utility>
#include <vector>

// Define BENCH below to enable more fine-grained benchmarking.
// The benchmarks using SPARSE_TERNARY distribution correspond exactly to Tables 2 and A.3 in
// https://eprint.iacr.org/2024/1623.pdf, while the benchmarks using SPARSE_ENCAPSULATED are more
// secure and lead to slightly more efficient results as compared to those tables.
// #define BENCH

using namespace lbcrypto;

enum TEST_CASE_TYPE : int {
    FBT_ARBLUT = 0,
    FBT_SIGNDIGIT,
    FBT_CONSECLEV,
    FBT_MVB,
    FBT_NOISE,
    FBT_MVB_REUSE,
    FBT_INVALID,
};

static std::ostream& operator<<(std::ostream& os, const TEST_CASE_TYPE& type) {
    std::string typeName;
    switch (type) {
        case FBT_ARBLUT:
            typeName = "FBT_ARBLUT";
            break;
        case FBT_SIGNDIGIT:
            typeName = "FBT_SIGNDIGIT";
            break;
        case FBT_CONSECLEV:
            typeName = "FBT_CONSECLEV";
            break;
        case FBT_MVB:
            typeName = "FBT_MVB";
            break;
        case FBT_NOISE:
            typeName = "FBT_NOISE";
            break;
        case FBT_MVB_REUSE:
            typeName = "FBT_MVB_REUSE";
            break;
        case FBT_INVALID:
            typeName = "FBT_INVALID";
            break;
        default:
            typeName = "UNKNOWN";
            break;
    }
    return os << typeName;
}

static std::string ScalTechName(ScalingTechnique st) {
    switch (st) {
        case FIXEDMANUAL:
            return "FIXEDMANUAL";
        case FIXEDAUTO:
            return "FIXEDAUTO";
        case FLEXIBLEAUTO:
            return "FLEXIBLEAUTO";
        case FLEXIBLEAUTOEXT:
            return "FLEXIBLEAUTOEXT";
        default:
            return "UNKNOWN";
    }
}

struct TEST_CASE_FBT {
    TEST_CASE_TYPE testCaseType;
    std::string description;

    BigInteger QBFVInit;
    BigInteger PInput;
    BigInteger POutput;
    BigInteger Q;
    BigInteger Bigq;
    double scaleTHI;
    double scaleStepTHI;
    size_t order;
    uint32_t numSlots;
    uint32_t ringDim;
    uint32_t levelsAvailableAfterBootstrap;
    uint32_t levelsAvailableBeforeBootstrap;
    uint32_t dnum;
    uint32_t levelsComputation;
    std::vector<uint32_t> lvlb;
    SecretKeyDist skd;
    // scaling technique used for the CKKS cryptocontext; FIXEDMANUAL by default
    ScalingTechnique scalTech = FIXEDMANUAL;

    std::string buildTestName() const {
        std::stringstream ss;
        ss << testCaseType << "_" << description << "_" << ScalTechName(scalTech);
        return ss.str();
    }
};

// this lambda provides a name to be printed for every test run by INSTANTIATE_TEST_SUITE_P.
// the name MUST be constructed from digits, letters and '_' only
static auto testName = [](const testing::TestParamInfo<TEST_CASE_FBT>& test) {
    return test.param.buildTestName();
};

[[maybe_unused]] const BigInteger PINPUT(256);
[[maybe_unused]] const BigInteger POUTPUT(256);
[[maybe_unused]] const BigInteger Q21(BigInteger(1) << 21);
[[maybe_unused]] const BigInteger Q32(BigInteger(1) << 32);
[[maybe_unused]] const BigInteger Q33(BigInteger(1) << 33);
[[maybe_unused]] const BigInteger Q35(BigInteger(1) << 35);
[[maybe_unused]] const BigInteger Q36(BigInteger(1) << 36);
[[maybe_unused]] const BigInteger Q37(BigInteger(1) << 37);
[[maybe_unused]] const BigInteger Q38(BigInteger(1) << 38);
[[maybe_unused]] const BigInteger Q40(BigInteger(1) << 40);
[[maybe_unused]] const BigInteger Q42(BigInteger(1) << 42);
[[maybe_unused]] const BigInteger Q43(BigInteger(1) << 43);
[[maybe_unused]] const BigInteger Q45(BigInteger(1) << 45);
[[maybe_unused]] const BigInteger Q46(BigInteger(1) << 46);
[[maybe_unused]] const BigInteger Q47(BigInteger(1) << 47);
[[maybe_unused]] const BigInteger Q48(BigInteger(1) << 48);
[[maybe_unused]] const BigInteger Q55(BigInteger(1) << 55);
[[maybe_unused]] const BigInteger Q56(BigInteger(1) << 56);
[[maybe_unused]] const BigInteger Q57(BigInteger(1) << 57);
[[maybe_unused]] const BigInteger Q58(BigInteger(1) << 58);
[[maybe_unused]] const BigInteger Q59(BigInteger(1) << 59);
[[maybe_unused]] const BigInteger Q60(BigInteger(1) << 60);
[[maybe_unused]] const BigInteger Q71(BigInteger(1) << 71);
[[maybe_unused]] const BigInteger Q80(BigInteger(1) << 80);

[[maybe_unused]] constexpr double SCALETHI(32.0);
[[maybe_unused]] constexpr double SCALESTEPTHI(1.0);
[[maybe_unused]] constexpr uint32_t AFTERBOOT(0);
[[maybe_unused]] constexpr uint32_t BEFOREBOOT(0);
[[maybe_unused]] constexpr uint32_t LVLSCOMP(0);
[[maybe_unused]] constexpr uint32_t SLOTSPARSE(8);
[[maybe_unused]] constexpr uint32_t SLOTFULL(32);
[[maybe_unused]] constexpr uint32_t RINGDM(32);
[[maybe_unused]] const std::vector<uint32_t> LVLBDFLT = {3, 3};

// clang-format off
static std::vector<TEST_CASE_FBT> testCases = {
// Functional Bootstrapping does not support NATIVE_SIZE == 128. Composite scaling, which serves that
// purpose elsewhere in CKKS, is not supported here either (EvalFBTSetup rejects it), so the supported
// rescaling modes are FIXEDMANUAL, FIXEDAUTO, FLEXIBLEAUTO, and FLEXIBLEAUTOEXT on the 64-bit build.
#if NATIVEINT != 128
#ifndef BENCH
    // TestCaseType, Desc, QBFVInit, PInput, POutput,  Q, Bigq, scaleTHI, scaleStepTHI, order,   numSlots, ringDim, lvlsAfterBoot, lvlsBeforeBoot, dnum, lvlsComp, lvlBudget, SecretKeyDist
    {    FBT_ARBLUT, "01",      Q60,      2,       2, Q33, Q33,        1, SCALESTEPTHI,     1,   SLOTFULL,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, SPARSE_TERNARY},
    {    FBT_ARBLUT, "02",      Q60,      2,       2, Q33, Q33,        1, SCALESTEPTHI,     2,   SLOTFULL,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, SPARSE_TERNARY},
    {    FBT_ARBLUT, "03",      Q60,      2,       2, Q33, Q33,        1, SCALESTEPTHI,     3,   SLOTFULL,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, SPARSE_TERNARY},
    {    FBT_ARBLUT, "04",      Q60,      2,       2, Q33, Q33,        1, SCALESTEPTHI,     1, SLOTSPARSE,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, SPARSE_TERNARY},
    {    FBT_ARBLUT, "05",      Q60,      2,       2, Q33, Q33,        1, SCALESTEPTHI,     2, SLOTSPARSE,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, SPARSE_TERNARY},
    {    FBT_ARBLUT, "06",      Q60,      2,       2, Q33, Q33,        1, SCALESTEPTHI,     3, SLOTSPARSE,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, SPARSE_TERNARY},
    {    FBT_ARBLUT, "07",      Q60, PINPUT, POUTPUT, Q47, Q47, SCALETHI, SCALESTEPTHI,     1,   SLOTFULL,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, SPARSE_TERNARY},
    {    FBT_ARBLUT, "08",      Q60, PINPUT, POUTPUT, Q47, Q47, SCALETHI, SCALESTEPTHI,     2,   SLOTFULL,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, SPARSE_TERNARY},
    {    FBT_ARBLUT, "09",      Q60, PINPUT, POUTPUT, Q47, Q47, SCALETHI, SCALESTEPTHI,     3,   SLOTFULL,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, SPARSE_TERNARY},
    {    FBT_ARBLUT, "10",      Q60, PINPUT, POUTPUT, Q47, Q47, SCALETHI, SCALESTEPTHI,     1, SLOTSPARSE,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, SPARSE_TERNARY},
    {    FBT_ARBLUT, "11",      Q60, PINPUT, POUTPUT, Q47, Q47, SCALETHI, SCALESTEPTHI,     2, SLOTSPARSE,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, SPARSE_TERNARY},
    {    FBT_ARBLUT, "12",      Q60, PINPUT, POUTPUT, Q47, Q47, SCALETHI, SCALESTEPTHI,     3, SLOTSPARSE,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, SPARSE_TERNARY},
    { FBT_SIGNDIGIT, "13",      Q71,    Q21,       2, Q56, Q36,        1,            1,     1,   SLOTFULL,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, SPARSE_TERNARY},
    { FBT_SIGNDIGIT, "14",      Q71,    Q21,       2, Q55, Q35,        1,            1,     2,   SLOTFULL,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, SPARSE_TERNARY},
    { FBT_SIGNDIGIT, "15",      Q71,    Q21,       2, Q56, Q36,        1,            1,     1, SLOTSPARSE,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, SPARSE_TERNARY},
    { FBT_SIGNDIGIT, "16",      Q71,    Q21,       2, Q55, Q35,        1,            1,     2, SLOTSPARSE,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, SPARSE_TERNARY},
    { FBT_CONSECLEV, "17",      Q60,      2,       2, Q35, Q35,        1, SCALESTEPTHI,     1,   SLOTFULL,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3,        1,  LVLBDFLT, SPARSE_TERNARY},
    { FBT_CONSECLEV, "18",      Q60, PINPUT,  PINPUT, Q48, Q48, SCALETHI, SCALESTEPTHI,     1,   SLOTFULL,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3,        1,  LVLBDFLT, SPARSE_TERNARY},
    { FBT_CONSECLEV, "19",      Q60,      2,       2, Q35, Q35,        1, SCALESTEPTHI,     1, SLOTSPARSE,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3,        1,  LVLBDFLT, SPARSE_TERNARY},
    { FBT_CONSECLEV, "20",      Q60, PINPUT,  PINPUT, Q48, Q48, SCALETHI, SCALESTEPTHI,     1, SLOTSPARSE,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3,        1,  LVLBDFLT, SPARSE_TERNARY},
    {       FBT_MVB, "21",      Q60,      2,       2, Q35, Q35,        1, SCALESTEPTHI,     1,   SLOTFULL,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3,        1,  LVLBDFLT, SPARSE_TERNARY},
    {       FBT_MVB, "22",      Q60, PINPUT,  PINPUT, Q48, Q48, SCALETHI, SCALESTEPTHI,     1,   SLOTFULL,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3,        1,  LVLBDFLT, SPARSE_TERNARY},
    {       FBT_MVB, "23",      Q60,      2,       2, Q35, Q35,        1, SCALESTEPTHI,     1, SLOTSPARSE,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3,        1,  LVLBDFLT, SPARSE_TERNARY},
    {       FBT_MVB, "24",      Q60, PINPUT,  PINPUT, Q48, Q48, SCALETHI, SCALESTEPTHI,     1, SLOTSPARSE,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3,        1,  LVLBDFLT, SPARSE_TERNARY},
    // TestCaseType,  Desc, QBFVInit, PInput, POutput,  Q, Bigq, scaleTHI, scaleStepTHI, order,   numSlots, ringDim, lvlsAfterBoot, lvlsBeforeBoot, dnum, lvlsComp, lvlBudget, SecretKeyDist
    {    FBT_ARBLUT, "101",      Q60,      2,       2, Q33, Q33,        1, SCALESTEPTHI,     1,   SLOTFULL,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, SPARSE_ENCAPSULATED},
    {    FBT_ARBLUT, "102",      Q60,      2,       2, Q33, Q33,        1, SCALESTEPTHI,     2,   SLOTFULL,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, SPARSE_ENCAPSULATED},
    {    FBT_ARBLUT, "103",      Q60,      2,       2, Q33, Q33,        1, SCALESTEPTHI,     3,   SLOTFULL,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, SPARSE_ENCAPSULATED},
    {    FBT_ARBLUT, "104",      Q60,      2,       2, Q33, Q33,        1, SCALESTEPTHI,     1, SLOTSPARSE,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, SPARSE_ENCAPSULATED},
    {    FBT_ARBLUT, "105",      Q60,      2,       2, Q33, Q33,        1, SCALESTEPTHI,     2, SLOTSPARSE,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, SPARSE_ENCAPSULATED},
    {    FBT_ARBLUT, "106",      Q60,      2,       2, Q33, Q33,        1, SCALESTEPTHI,     3, SLOTSPARSE,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, SPARSE_ENCAPSULATED},
    {    FBT_ARBLUT, "107",      Q60, PINPUT, POUTPUT, Q47, Q47, SCALETHI, SCALESTEPTHI,     1,   SLOTFULL,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, SPARSE_ENCAPSULATED},
    {    FBT_ARBLUT, "108",      Q60, PINPUT, POUTPUT, Q47, Q47, SCALETHI, SCALESTEPTHI,     2,   SLOTFULL,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, SPARSE_ENCAPSULATED},
    {    FBT_ARBLUT, "109",      Q60, PINPUT, POUTPUT, Q47, Q47, SCALETHI, SCALESTEPTHI,     3,   SLOTFULL,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, SPARSE_ENCAPSULATED},
    {    FBT_ARBLUT, "110",      Q60, PINPUT, POUTPUT, Q47, Q47, SCALETHI, SCALESTEPTHI,     1, SLOTSPARSE,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, SPARSE_ENCAPSULATED},
    {    FBT_ARBLUT, "111",      Q60, PINPUT, POUTPUT, Q47, Q47, SCALETHI, SCALESTEPTHI,     2, SLOTSPARSE,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, SPARSE_ENCAPSULATED},
    {    FBT_ARBLUT, "112",      Q60, PINPUT, POUTPUT, Q47, Q47, SCALETHI, SCALESTEPTHI,     3, SLOTSPARSE,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, SPARSE_ENCAPSULATED},
    { FBT_SIGNDIGIT, "113",      Q71,    Q21,       2, Q56, Q36,        1,            1,     1,   SLOTFULL,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, SPARSE_ENCAPSULATED},
    { FBT_SIGNDIGIT, "114",      Q71,    Q21,       2, Q55, Q35,        1,            1,     2,   SLOTFULL,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, SPARSE_ENCAPSULATED},
    { FBT_SIGNDIGIT, "115",      Q71,    Q21,       2, Q56, Q36,        1,            1,     1, SLOTSPARSE,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, SPARSE_ENCAPSULATED},
    { FBT_SIGNDIGIT, "116",      Q71,    Q21,       2, Q55, Q35,        1,            1,     2, SLOTSPARSE,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, SPARSE_ENCAPSULATED},
    { FBT_CONSECLEV, "117",      Q60,      2,       2, Q35, Q35,        1, SCALESTEPTHI,     1,   SLOTFULL,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3,        1,  LVLBDFLT, SPARSE_ENCAPSULATED},
    { FBT_CONSECLEV, "118",      Q60, PINPUT,  PINPUT, Q48, Q48, SCALETHI, SCALESTEPTHI,     1,   SLOTFULL,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3,        1,  LVLBDFLT, SPARSE_ENCAPSULATED},
    { FBT_CONSECLEV, "119",      Q60,      2,       2, Q35, Q35,        1, SCALESTEPTHI,     1, SLOTSPARSE,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3,        1,  LVLBDFLT, SPARSE_ENCAPSULATED},
    { FBT_CONSECLEV, "120",      Q60, PINPUT,  PINPUT, Q48, Q48, SCALETHI, SCALESTEPTHI,     1, SLOTSPARSE,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3,        1,  LVLBDFLT, SPARSE_ENCAPSULATED},
    {       FBT_MVB, "121",      Q60,      2,       2, Q35, Q35,        1, SCALESTEPTHI,     1,   SLOTFULL,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3,        1,  LVLBDFLT, SPARSE_ENCAPSULATED},
    {       FBT_MVB, "122",      Q60, PINPUT,  PINPUT, Q48, Q48, SCALETHI, SCALESTEPTHI,     1,   SLOTFULL,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3,        1,  LVLBDFLT, SPARSE_ENCAPSULATED},
    {       FBT_MVB, "123",      Q60,      2,       2, Q35, Q35,        1, SCALESTEPTHI,     1, SLOTSPARSE,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3,        1,  LVLBDFLT, SPARSE_ENCAPSULATED},
    {       FBT_MVB, "124",      Q60, PINPUT,  PINPUT, Q48, Q48, SCALETHI, SCALESTEPTHI,     1, SLOTSPARSE,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3,        1,  LVLBDFLT, SPARSE_ENCAPSULATED},
    // TestCaseType, Desc, QBFVInit, PInput, POutput,  Q, Bigq, scaleTHI, scaleStepTHI, order,   numSlots, ringDim, lvlsAfterBoot, lvlsBeforeBoot, dnum, lvlsComp, lvlBudget, SecretKeyDist, ScalingTechnique
    {    FBT_ARBLUT, "201",      Q60,      2,       2, Q33, Q33,        1, SCALESTEPTHI,     1,   SLOTFULL,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, SPARSE_TERNARY, FIXEDAUTO},
    {    FBT_ARBLUT, "202",      Q60, PINPUT, POUTPUT, Q47, Q47, SCALETHI, SCALESTEPTHI,     1,   SLOTFULL,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, SPARSE_TERNARY, FIXEDAUTO},
    {    FBT_ARBLUT, "203",      Q60, PINPUT, POUTPUT, Q47, Q47, SCALETHI, SCALESTEPTHI,     2, SLOTSPARSE,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, SPARSE_ENCAPSULATED, FIXEDAUTO},
    { FBT_SIGNDIGIT, "204",      Q71,    Q21,       2, Q56, Q36,        1,            1,     1,   SLOTFULL,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, SPARSE_TERNARY, FIXEDAUTO},
    { FBT_CONSECLEV, "205",      Q60, PINPUT,  PINPUT, Q48, Q48, SCALETHI, SCALESTEPTHI,     1,   SLOTFULL,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3,        1,  LVLBDFLT, SPARSE_TERNARY, FIXEDAUTO},
    {       FBT_MVB, "206",      Q60, PINPUT,  PINPUT, Q48, Q48, SCALETHI, SCALESTEPTHI,     1, SLOTSPARSE,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3,        1,  LVLBDFLT, SPARSE_TERNARY, FIXEDAUTO},
    {    FBT_ARBLUT, "301",      Q60,      2,       2, Q33, Q33,        1, SCALESTEPTHI,     1,   SLOTFULL,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, SPARSE_TERNARY, FLEXIBLEAUTO},
    {    FBT_ARBLUT, "302",      Q60, PINPUT, POUTPUT, Q47, Q47, SCALETHI, SCALESTEPTHI,     1,   SLOTFULL,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, SPARSE_TERNARY, FLEXIBLEAUTO},
    {    FBT_ARBLUT, "303",      Q60, PINPUT, POUTPUT, Q47, Q47, SCALETHI, SCALESTEPTHI,     2, SLOTSPARSE,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, SPARSE_ENCAPSULATED, FLEXIBLEAUTO},
    { FBT_SIGNDIGIT, "304",      Q71,    Q21,       2, Q56, Q36,        1,            1,     1,   SLOTFULL,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, SPARSE_TERNARY, FLEXIBLEAUTO},
    { FBT_CONSECLEV, "305",      Q60, PINPUT,  PINPUT, Q48, Q48, SCALETHI, SCALESTEPTHI,     1,   SLOTFULL,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3,        1,  LVLBDFLT, SPARSE_TERNARY, FLEXIBLEAUTO},
    {       FBT_MVB, "306",      Q60, PINPUT,  PINPUT, Q48, Q48, SCALETHI, SCALESTEPTHI,     1, SLOTSPARSE,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3,        1,  LVLBDFLT, SPARSE_TERNARY, FLEXIBLEAUTO},
    {    FBT_ARBLUT, "401",      Q60,      2,       2, Q33, Q33,        1, SCALESTEPTHI,     1,   SLOTFULL,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, SPARSE_TERNARY, FLEXIBLEAUTOEXT},
    {    FBT_ARBLUT, "402",      Q60, PINPUT, POUTPUT, Q47, Q47, SCALETHI, SCALESTEPTHI,     1,   SLOTFULL,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, SPARSE_TERNARY, FLEXIBLEAUTOEXT},
    {    FBT_ARBLUT, "403",      Q60, PINPUT, POUTPUT, Q47, Q47, SCALETHI, SCALESTEPTHI,     2, SLOTSPARSE,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, SPARSE_ENCAPSULATED, FLEXIBLEAUTOEXT},
    { FBT_SIGNDIGIT, "404",      Q71,    Q21,       2, Q56, Q36,        1,            1,     1,   SLOTFULL,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, SPARSE_TERNARY, FLEXIBLEAUTOEXT},
    { FBT_CONSECLEV, "405",      Q60, PINPUT,  PINPUT, Q48, Q48, SCALETHI, SCALESTEPTHI,     1,   SLOTFULL,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3,        1,  LVLBDFLT, SPARSE_TERNARY, FLEXIBLEAUTOEXT},
    {       FBT_MVB, "406",      Q60, PINPUT,  PINPUT, Q48, Q48, SCALETHI, SCALESTEPTHI,     1, SLOTSPARSE,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3,        1,  LVLBDFLT, SPARSE_TERNARY, FLEXIBLEAUTOEXT},
    // Noise-comparison tests: the same LUT is evaluated with FIXEDMANUAL and with the scaling technique below,
    // and the test checks that the FLEXIBLE* technique yields smaller noise in the output RLWE ciphertext.
    {     FBT_NOISE, "501",      Q60,      2,       2, Q33, Q33,        1, SCALESTEPTHI,     1,   SLOTFULL,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, SPARSE_TERNARY, FLEXIBLEAUTO},
    {     FBT_NOISE, "502",      Q60,      2,       2, Q33, Q33,        1, SCALESTEPTHI,     1,   SLOTFULL,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, SPARSE_TERNARY, FLEXIBLEAUTOEXT},
    // Multi-limb initial scaling: the RLWE ciphertext is imported with one level available before
    // bootstrapping, so initialScaling in EvalFBT covers two RNS limbs (q0*q1) and must be
    // corrected before the modulus raise.
    {    FBT_ARBLUT, "601",      Q60,      2,       2, Q33, Q33,        1, SCALESTEPTHI,     1,   SLOTFULL,  RINGDM,     AFTERBOOT,              1,    3, LVLSCOMP,  LVLBDFLT, SPARSE_TERNARY},
    {    FBT_ARBLUT, "602",      Q60,      2,       2, Q33, Q33,        1, SCALESTEPTHI,     1,   SLOTFULL,  RINGDM,     AFTERBOOT,              1,    3, LVLSCOMP,  LVLBDFLT, SPARSE_TERNARY, FLEXIBLEAUTO},
    {    FBT_ARBLUT, "603",      Q60,      2,       2, Q33, Q33,        1, SCALESTEPTHI,     1,   SLOTFULL,  RINGDM,     AFTERBOOT,              1,    3, LVLSCOMP,  LVLBDFLT, SPARSE_TERNARY, FLEXIBLEAUTOEXT},
    {    FBT_ARBLUT, "604",      Q60,      2,       2, Q33, Q33,        1, SCALESTEPTHI,     1,   SLOTFULL,  RINGDM,     AFTERBOOT,              1,    3, LVLSCOMP,  LVLBDFLT, SPARSE_TERNARY, FIXEDAUTO},
    // Repeated LUT evaluation on the same precomputed powers (checks the precomputation is not
    // corrupted in place) and rejection of invalid arguments.
    { FBT_MVB_REUSE, "701",      Q60,      2,       4, Q35, Q35,        1, SCALESTEPTHI,     1,   SLOTFULL,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, SPARSE_TERNARY},
    { FBT_MVB_REUSE, "702",      Q60,      2,       4, Q35, Q35,        1, SCALESTEPTHI,     1,   SLOTFULL,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, SPARSE_TERNARY, FLEXIBLEAUTO},
    {   FBT_INVALID, "801",      Q60,      2,       2, Q33, Q33,        1, SCALESTEPTHI,     1,   SLOTFULL,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, SPARSE_TERNARY, FLEXIBLEAUTO},
#else
    // TestCaseType, Desc, QBFVInit, PInput, POutput,  Q, Bigq, scaleTHI, scaleStepTHI, order, numSlots, ringDim, lvlsAfterBoot, lvlsBeforeBoot, dnum, lvlsComp, lvlBudget, SecretKeyDist
    {    FBT_ARBLUT, "01",      Q60,      2,       2, Q33, Q33,        1, SCALESTEPTHI,     1,  1 << 15, 1 << 15,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,    {3, 3}, SPARSE_TERNARY},
    {    FBT_ARBLUT, "02",      Q60,      2,       2, Q33, Q33,        1, SCALESTEPTHI,     2,  1 << 15, 1 << 15,     AFTERBOOT,     BEFOREBOOT,    7, LVLSCOMP,    {3, 3}, SPARSE_TERNARY},
    {    FBT_ARBLUT, "03",      Q60,      2,       2, Q33, Q33,        1, SCALESTEPTHI,     3,  1 << 15, 1 << 15,     AFTERBOOT,     BEFOREBOOT,    7, LVLSCOMP,    {3, 3}, SPARSE_TERNARY},
    {    FBT_ARBLUT, "04",      Q60,      4,       4, Q35, Q35,       16, SCALESTEPTHI,     1,  1 << 16, 1 << 16,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,    {4, 4}, SPARSE_TERNARY},
    {    FBT_ARBLUT, "05",      Q60,      4,       4, Q35, Q35,       16, SCALESTEPTHI,     2,  1 << 16, 1 << 16,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,    {4, 4}, SPARSE_TERNARY},
    {    FBT_ARBLUT, "06",      Q60,      4,       4, Q35, Q35,       16, SCALESTEPTHI,     3,  1 << 16, 1 << 16,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,    {4, 4}, SPARSE_TERNARY},
    {    FBT_ARBLUT, "07",      Q60,      8,       8, Q37, Q37,       16, SCALESTEPTHI,     1,  1 << 16, 1 << 16,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,    {4, 4}, SPARSE_TERNARY},
    {    FBT_ARBLUT, "08",      Q60,      8,       8, Q37, Q37,       16, SCALESTEPTHI,     2,  1 << 16, 1 << 16,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,    {4, 4}, SPARSE_TERNARY},
    {    FBT_ARBLUT, "09",      Q60,      8,       8, Q37, Q37,       16, SCALESTEPTHI,     3,  1 << 16, 1 << 16,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,    {4, 4}, SPARSE_TERNARY},
    {    FBT_ARBLUT, "10",      Q60,     16,      16, Q38, Q38,       32, SCALESTEPTHI,     1,  1 << 16, 1 << 16,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,    {4, 4}, SPARSE_TERNARY},
    {    FBT_ARBLUT, "11",      Q60,     16,      16, Q38, Q38,       32, SCALESTEPTHI,     2,  1 << 16, 1 << 16,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,    {4, 4}, SPARSE_TERNARY},
    {    FBT_ARBLUT, "12",      Q60,     16,      16, Q38, Q38,       32, SCALESTEPTHI,     3,  1 << 16, 1 << 16,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,    {4, 4}, SPARSE_TERNARY},
    {    FBT_ARBLUT, "13",      Q60, PINPUT, POUTPUT, Q47, Q47, SCALETHI, SCALESTEPTHI,     1,  1 << 16, 1 << 16,     AFTERBOOT,     BEFOREBOOT,    4, LVLSCOMP,    {3, 3}, SPARSE_TERNARY},
    {    FBT_ARBLUT, "14",      Q60, PINPUT, POUTPUT, Q47, Q47, SCALETHI, SCALESTEPTHI,     2,  1 << 16, 1 << 16,     AFTERBOOT,     BEFOREBOOT,    4, LVLSCOMP,    {3, 3}, SPARSE_TERNARY},
    {    FBT_ARBLUT, "15",      Q60, PINPUT, POUTPUT, Q47, Q47, SCALETHI, SCALESTEPTHI,     3,  1 << 16, 1 << 16,     AFTERBOOT,     BEFOREBOOT,    5, LVLSCOMP,    {3, 3}, SPARSE_TERNARY},
    {    FBT_ARBLUT, "16",      Q60,    512,     512, Q48, Q48,       45, SCALESTEPTHI,     1,  1 << 16, 1 << 16,     AFTERBOOT,     BEFOREBOOT,    5, LVLSCOMP,    {3, 3}, SPARSE_TERNARY},
    {    FBT_ARBLUT, "17",      Q60,    512,     512, Q48, Q48,       45, SCALESTEPTHI,     2,  1 << 16, 1 << 16,     AFTERBOOT,     BEFOREBOOT,    5, LVLSCOMP,    {3, 3}, SPARSE_TERNARY},
    {    FBT_ARBLUT, "18",      Q60,    512,     512, Q48, Q48,       45, SCALESTEPTHI,     3,  1 << 16, 1 << 16,     AFTERBOOT,     BEFOREBOOT,    7, LVLSCOMP,    {3, 3}, SPARSE_TERNARY},
    {    FBT_ARBLUT, "19",      Q80,   4096,    4096, Q55, Q55,     2000, SCALESTEPTHI,     1,  1 << 17, 1 << 17,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,    {4, 4}, SPARSE_TERNARY},
    {    FBT_ARBLUT, "20",      Q80,   4096,    4096, Q55, Q55,     2000, SCALESTEPTHI,     2,  1 << 17, 1 << 17,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,    {4, 4}, SPARSE_TERNARY},
    {    FBT_ARBLUT, "21",      Q80,   4096,    4096, Q55, Q55,     2000, SCALESTEPTHI,     3,  1 << 17, 1 << 17,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,    {4, 4}, SPARSE_TERNARY},
    {    FBT_ARBLUT, "22",      Q80,  16384,   16384, Q58, Q58,     8000, SCALESTEPTHI,     1,  1 << 17, 1 << 17,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,    {4, 4}, SPARSE_TERNARY},
    {    FBT_ARBLUT, "23",      Q80,  16384,   16384, Q58, Q58,     8000, SCALESTEPTHI,     2,  1 << 17, 1 << 17,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,    {4, 4}, SPARSE_TERNARY},
    {    FBT_ARBLUT, "24",      Q80,  16384,   16384, Q58, Q58,     8000, SCALESTEPTHI,     3,  1 << 17, 1 << 17,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,    {4, 4}, SPARSE_TERNARY},
    { FBT_SIGNDIGIT, "25",      Q60,   4096,       2, Q46, Q35,        1,            1,     1,  1 << 16, 1 << 16,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,    {4, 4}, SPARSE_TERNARY},
    { FBT_SIGNDIGIT, "27",      Q60,   4096,       4, Q45, Q35,       10,            2,     1,  1 << 16, 1 << 16,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,    {4, 4}, SPARSE_TERNARY},
    { FBT_SIGNDIGIT, "29",      Q60,   4096,       8, Q46, Q37,       16,            4,     1,  1 << 16, 1 << 16,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,    {4, 4}, SPARSE_TERNARY},
    { FBT_SIGNDIGIT, "31",      Q60,   4096,      16, Q48, Q40,       32,            8,     1,  1 << 16, 1 << 16,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,    {4, 4}, SPARSE_TERNARY},
    { FBT_SIGNDIGIT, "33",      Q60,   4096,      64, Q48, Q42,      128,           32,     1,  1 << 16, 1 << 16,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,    {4, 4}, SPARSE_TERNARY},
    { FBT_SIGNDIGIT, "35",      Q71,    Q21,       2, Q56, Q36,        1,            1,     1,  1 << 16, 1 << 16,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,    {4, 4}, SPARSE_TERNARY},
    { FBT_SIGNDIGIT, "37",      Q71,    Q21,       8, Q55, Q37,       16,            4,     1,  1 << 16, 1 << 16,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,    {4, 4}, SPARSE_TERNARY},
    { FBT_SIGNDIGIT, "39",      Q71,    Q21,     128, Q57, Q43,      256,           16,     1,  1 << 16, 1 << 16,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,    {4, 4}, SPARSE_TERNARY},
    { FBT_SIGNDIGIT, "41",      Q80,    Q32,     256, Q71, Q47,      256,           16,     1,  1 << 16, 1 << 16,     AFTERBOOT,     BEFOREBOOT,    4, LVLSCOMP,    {3, 3}, SPARSE_TERNARY},
    // TestCaseType,  Desc, QBFVInit, PInput, POutput,  Q, Bigq, scaleTHI, scaleStepTHI, order, numSlots, ringDim, lvlsAfterBoot, lvlsBeforeBoot, dnum, lvlsComp, lvlBudget, SecretKeyDist
    {    FBT_ARBLUT, "101",      Q60,      2,       2, Q33, Q33,        1, SCALESTEPTHI,     1,  1 << 15, 1 << 15,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,    {3, 3}, SPARSE_ENCAPSULATED},
    {    FBT_ARBLUT, "102",      Q60,      2,       2, Q33, Q33,        1, SCALESTEPTHI,     2,  1 << 15, 1 << 15,     AFTERBOOT,     BEFOREBOOT,    7, LVLSCOMP,    {3, 3}, SPARSE_ENCAPSULATED},
    {    FBT_ARBLUT, "103",      Q60,      2,       2, Q33, Q33,        1, SCALESTEPTHI,     3,  1 << 15, 1 << 15,     AFTERBOOT,     BEFOREBOOT,    7, LVLSCOMP,    {3, 3}, SPARSE_ENCAPSULATED},
    {    FBT_ARBLUT, "104",      Q60,      4,       4, Q35, Q35,       16, SCALESTEPTHI,     1,  1 << 16, 1 << 16,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,    {4, 4}, SPARSE_ENCAPSULATED},
    {    FBT_ARBLUT, "105",      Q60,      4,       4, Q35, Q35,       16, SCALESTEPTHI,     2,  1 << 16, 1 << 16,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,    {4, 4}, SPARSE_ENCAPSULATED},
    {    FBT_ARBLUT, "106",      Q60,      4,       4, Q35, Q35,       16, SCALESTEPTHI,     3,  1 << 16, 1 << 16,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,    {4, 4}, SPARSE_ENCAPSULATED},
    {    FBT_ARBLUT, "107",      Q60,      8,       8, Q37, Q37,       16, SCALESTEPTHI,     1,  1 << 16, 1 << 16,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,    {4, 4}, SPARSE_ENCAPSULATED},
    {    FBT_ARBLUT, "108",      Q60,      8,       8, Q37, Q37,       16, SCALESTEPTHI,     2,  1 << 16, 1 << 16,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,    {4, 4}, SPARSE_ENCAPSULATED},
    {    FBT_ARBLUT, "109",      Q60,      8,       8, Q37, Q37,       16, SCALESTEPTHI,     3,  1 << 16, 1 << 16,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,    {4, 4}, SPARSE_ENCAPSULATED},
    {    FBT_ARBLUT, "110",      Q60,     16,      16, Q38, Q38,       32, SCALESTEPTHI,     1,  1 << 16, 1 << 16,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,    {4, 4}, SPARSE_ENCAPSULATED},
    {    FBT_ARBLUT, "111",      Q60,     16,      16, Q38, Q38,       32, SCALESTEPTHI,     2,  1 << 16, 1 << 16,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,    {4, 4}, SPARSE_ENCAPSULATED},
    {    FBT_ARBLUT, "112",      Q60,     16,      16, Q38, Q38,       32, SCALESTEPTHI,     3,  1 << 16, 1 << 16,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,    {4, 4}, SPARSE_ENCAPSULATED},
    {    FBT_ARBLUT, "113",      Q60, PINPUT, POUTPUT, Q47, Q47, SCALETHI, SCALESTEPTHI,     1,  1 << 16, 1 << 16,     AFTERBOOT,     BEFOREBOOT,    4, LVLSCOMP,    {3, 3}, SPARSE_ENCAPSULATED},
    {    FBT_ARBLUT, "114",      Q60, PINPUT, POUTPUT, Q47, Q47, SCALETHI, SCALESTEPTHI,     2,  1 << 16, 1 << 16,     AFTERBOOT,     BEFOREBOOT,    4, LVLSCOMP,    {3, 3}, SPARSE_ENCAPSULATED},
    {    FBT_ARBLUT, "115",      Q60, PINPUT, POUTPUT, Q47, Q47, SCALETHI, SCALESTEPTHI,     3,  1 << 16, 1 << 16,     AFTERBOOT,     BEFOREBOOT,    5, LVLSCOMP,    {3, 3}, SPARSE_ENCAPSULATED},
    {    FBT_ARBLUT, "116",      Q60,    512,     512, Q48, Q48,       45, SCALESTEPTHI,     1,  1 << 16, 1 << 16,     AFTERBOOT,     BEFOREBOOT,    5, LVLSCOMP,    {3, 3}, SPARSE_ENCAPSULATED},
    {    FBT_ARBLUT, "117",      Q60,    512,     512, Q48, Q48,       45, SCALESTEPTHI,     2,  1 << 16, 1 << 16,     AFTERBOOT,     BEFOREBOOT,    5, LVLSCOMP,    {3, 3}, SPARSE_ENCAPSULATED},
    {    FBT_ARBLUT, "118",      Q60,    512,     512, Q48, Q48,       45, SCALESTEPTHI,     3,  1 << 16, 1 << 16,     AFTERBOOT,     BEFOREBOOT,    7, LVLSCOMP,    {3, 3}, SPARSE_ENCAPSULATED},
    {    FBT_ARBLUT, "119",      Q80,   4096,    4096, Q55, Q55,     2000, SCALESTEPTHI,     1,  1 << 17, 1 << 17,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,    {4, 4}, SPARSE_ENCAPSULATED},
    {    FBT_ARBLUT, "120",      Q80,   4096,    4096, Q55, Q55,     2000, SCALESTEPTHI,     2,  1 << 17, 1 << 17,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,    {4, 4}, SPARSE_ENCAPSULATED},
    {    FBT_ARBLUT, "121",      Q80,   4096,    4096, Q55, Q55,     2000, SCALESTEPTHI,     3,  1 << 17, 1 << 17,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,    {4, 4}, SPARSE_ENCAPSULATED},
    {    FBT_ARBLUT, "122",      Q80,  16384,   16384, Q59, Q59,     8000, SCALESTEPTHI,     1,  1 << 17, 1 << 17,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,    {4, 4}, SPARSE_ENCAPSULATED},
    {    FBT_ARBLUT, "123",      Q80,  16384,   16384, Q59, Q59,     8000, SCALESTEPTHI,     2,  1 << 17, 1 << 17,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,    {4, 4}, SPARSE_ENCAPSULATED},
    {    FBT_ARBLUT, "124",      Q80,  16384,   16384, Q59, Q59,     8000, SCALESTEPTHI,     3,  1 << 17, 1 << 17,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,    {4, 4}, SPARSE_ENCAPSULATED},
    { FBT_SIGNDIGIT, "125",      Q60,   4096,       2, Q46, Q35,        1,            1,     1,  1 << 16, 1 << 16,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,    {4, 4}, SPARSE_ENCAPSULATED},
    { FBT_SIGNDIGIT, "127",      Q60,   4096,       4, Q45, Q35,       10,            2,     1,  1 << 16, 1 << 16,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,    {4, 4}, SPARSE_ENCAPSULATED},
    { FBT_SIGNDIGIT, "129",      Q60,   4096,       8, Q46, Q37,       16,            4,     1,  1 << 16, 1 << 16,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,    {4, 4}, SPARSE_ENCAPSULATED},
    { FBT_SIGNDIGIT, "131",      Q60,   4096,      16, Q48, Q40,       32,            8,     1,  1 << 16, 1 << 16,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,    {4, 4}, SPARSE_ENCAPSULATED},
    { FBT_SIGNDIGIT, "133",      Q60,   4096,      64, Q48, Q42,      128,           32,     1,  1 << 16, 1 << 16,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,    {4, 4}, SPARSE_ENCAPSULATED},
    { FBT_SIGNDIGIT, "135",      Q71,    Q21,       2, Q56, Q36,        1,            1,     1,  1 << 16, 1 << 16,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,    {4, 4}, SPARSE_ENCAPSULATED},
    { FBT_SIGNDIGIT, "137",      Q71,    Q21,       8, Q55, Q37,       16,            4,     1,  1 << 16, 1 << 16,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,    {4, 4}, SPARSE_ENCAPSULATED},
    { FBT_SIGNDIGIT, "139",      Q71,    Q21,     128, Q57, Q43,      256,           16,     1,  1 << 16, 1 << 16,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,    {4, 4}, SPARSE_ENCAPSULATED},
    { FBT_SIGNDIGIT, "141",      Q80,    Q32,     256, Q71, Q47,      256,           16,     1,  1 << 16, 1 << 16,     AFTERBOOT,     BEFOREBOOT,    4, LVLSCOMP,    {3, 3}, SPARSE_ENCAPSULATED},
#endif
#endif
};
// clang-format on

// Measures the maximum noise (in bits) in the message coefficients of an RLWE ciphertext encrypting
// delta*m for delta = Q/p. It follows SchemeletRLWEMP::DecryptCoeff, but instead of rounding to the
// nearest multiple of delta, it returns the centered residual modulo delta (the rounding error).
static double MeasureNoiseBits(const std::vector<Poly>& input, const BigInteger& Q, const BigInteger& p,
                               const PrivateKey<DCRTPoly>& privateKey,
                               const std::shared_ptr<ILDCRTParams<DCRTPoly::Integer>>& ep, uint32_t numSlots,
                               uint32_t length) {
    const auto& bigQPrime = ep->GetModulus();

    Poly bPoly = input[0];
    Poly aPoly = input[1];
    if (Q < bigQPrime) {
        bPoly.SwitchModulus(bigQPrime, 1, 0, 0);
        bPoly = bPoly.MultiplyAndRound(bigQPrime, Q);
        aPoly.SwitchModulus(bigQPrime, 1, 0, 0);
        aPoly = aPoly.MultiplyAndRound(bigQPrime, Q);
    }
    else {
        bPoly = bPoly.MultiplyAndRound(bigQPrime, Q);
        bPoly.SwitchModulus(bigQPrime, 1, 0, 0);
        aPoly = aPoly.MultiplyAndRound(bigQPrime, Q);
        aPoly.SwitchModulus(bigQPrime, 1, 0, 0);
    }

    std::vector<DCRTPoly> ba{DCRTPoly(bPoly, ep), DCRTPoly(aPoly, ep)};
    ba[0].SetFormat(Format::EVALUATION);
    ba[1].SetFormat(Format::EVALUATION);

    auto scopy(privateKey->GetPrivateElement());
    scopy.DropLastElements(scopy.GetParams()->GetParams().size() - ep->GetParams().size());

    auto m = ba[0] + ba[1] * scopy;
    m.SetFormat(Format::COEFFICIENT);
    auto mPoly = m.CRTInterpolate();

    if (Q < bigQPrime) {
        mPoly = mPoly.MultiplyAndRound(Q, bigQPrime);
        mPoly.SwitchModulus(Q, 1, 0, 0);
    }
    else {
        mPoly.SwitchModulus(Q, 1, 0, 0);
        mPoly = mPoly.MultiplyAndRound(Q, bigQPrime);
    }

    BigInteger delta = Q / p;
    BigInteger half  = delta >> 1;
    uint32_t gap     = mPoly.GetLength() / (2 * numSlots);
    gap              = (gap == 0) ? 1 : gap;

    BigInteger maxNoise(0);
    for (uint32_t i = 0, idx = 0; i < length; ++i, idx += gap) {
        BigInteger r = mPoly[idx].Mod(delta);
        if (r > half)
            r = delta - r;
        if (r > maxNoise)
            maxNoise = r;
    }
    return std::log2(maxNoise.ConvertToDouble() + 1);
}

class UTCKKSRNS_FBT : public ::testing::TestWithParam<TEST_CASE_FBT> {
protected:
    void SetUp() {
        OpenFHEParallelControls.UnitTestStart();
    };

    void TearDown() {
        CryptoContextFactory<DCRTPoly>::ReleaseAllContexts();
        OpenFHEParallelControls.UnitTestStop();
    }

    void UnitTest_ArbLUT(TEST_CASE_FBT t, const std::string& failmsg = std::string()) {
        try {
#ifdef BENCH
            auto start = std::chrono::high_resolution_clock::now();
#endif
            bool flagSP = (t.numSlots <= t.ringDim / 2);  // sparse packing
            // t.numSlots represents number of values to be encrypted in BFV. If same as ring dimension, CKKS slots is halved.
            auto numSlotsCKKS = flagSP ? t.numSlots : t.numSlots / 2;

            auto a = t.PInput.ConvertToInt<int64_t>();
            auto b = t.POutput.ConvertToInt<int64_t>();
            auto f = [a, b](int64_t x) -> int64_t {
                return (x % a - a / 2) % b;
            };

            std::vector<int64_t> x = {
                (t.PInput.ConvertToInt<int64_t>() / 2), (t.PInput.ConvertToInt<int64_t>() / 2) + 1, 0, 3, 16, 33, 64,
                (t.PInput.ConvertToInt<int64_t>() - 1)};
            if (x.size() < t.numSlots)
                x = Fill<int64_t>(x, t.numSlots);

            std::vector<int64_t> coeffint;
            std::vector<std::complex<double>> coeffcomp;
            bool binaryLUT = (t.PInput.ConvertToInt() == 2) && (t.order == 1);
            if (binaryLUT)  // coeffs for [1, cos^2(pi x)], not [1, cos(2pi x)]
                coeffint = {f(1), f(0) - f(1)};
            else  // divided by 2
                coeffcomp = GetHermiteTrigCoefficients(f, t.PInput.ConvertToInt(), t.order, t.scaleTHI);

#ifdef BENCH
            auto stop = std::chrono::high_resolution_clock::now();
            std::cerr << "Coefficient Generation: " << std::chrono::duration<double>(stop - start).count() << " s\n";
            start = std::chrono::high_resolution_clock::now();
#endif

            const uint32_t dcrtBits = t.Bigq.GetMSB() - 1;
            CCParams<CryptoContextCKKSRNS> parameters;
            parameters.SetSecretKeyDist(t.skd);
            parameters.SetSecurityLevel(HEStd_NotSet);
            parameters.SetScalingModSize(dcrtBits);
            parameters.SetScalingTechnique(t.scalTech);
            parameters.SetFirstModSize(dcrtBits);
            parameters.SetNumLargeDigits(t.dnum);
            parameters.SetBatchSize(numSlotsCKKS);
            parameters.SetRingDim(t.ringDim);
            uint32_t depth = t.levelsAvailableAfterBootstrap;

            if (binaryLUT)
                depth += FHECKKSRNS::GetFBTDepth(t.lvlb, coeffint, t.PInput, t.order, t.skd);
            else
                depth += FHECKKSRNS::GetFBTDepth(t.lvlb, coeffcomp, t.PInput, t.order, t.skd);

            parameters.SetMultiplicativeDepth(depth);

            auto cc = GenCryptoContext(parameters);
            cc->Enable(PKE);
            cc->Enable(KEYSWITCH);
            cc->Enable(LEVELEDSHE);
            cc->Enable(ADVANCEDSHE);
            cc->Enable(FHE);

            auto keyPair = cc->KeyGen();

#ifdef BENCH
            stop = std::chrono::high_resolution_clock::now();
            std::cerr << "Cryptocontext Generation: " << std::chrono::duration<double>(stop - start).count() << " s\n";
            start = std::chrono::high_resolution_clock::now();
#endif

            if (binaryLUT)
                cc->EvalFBTSetup(coeffint, numSlotsCKKS, t.PInput, t.POutput, t.Bigq, keyPair.publicKey, {0, 0}, t.lvlb,
                                 t.levelsAvailableAfterBootstrap, 0, t.order);
            else
                cc->EvalFBTSetup(coeffcomp, numSlotsCKKS, t.PInput, t.POutput, t.Bigq, keyPair.publicKey, {0, 0},
                                 t.lvlb, t.levelsAvailableAfterBootstrap, 0, t.order);

#ifdef BENCH
            stop = std::chrono::high_resolution_clock::now();
            std::cerr << "FuncBootstrapping Setup: " << std::chrono::duration<double>(stop - start).count() << " s\n";
            start = std::chrono::high_resolution_clock::now();
#endif

            cc->EvalBootstrapKeyGen(keyPair.secretKey, numSlotsCKKS);
            cc->EvalMultKeyGen(keyPair.secretKey);

#ifdef BENCH
            stop = std::chrono::high_resolution_clock::now();
            std::cerr << "FuncBootstrapping KeyGen: " << std::chrono::duration<double>(stop - start).count() << " s\n";
            start = std::chrono::high_resolution_clock::now();
#endif

            auto ep = SchemeletRLWEMP::GetElementParams(keyPair.secretKey,
                                                        depth - (t.levelsAvailableBeforeBootstrap > 0));

            auto ctxtBFV = SchemeletRLWEMP::EncryptCoeff(x, t.QBFVInit, t.PInput, keyPair.secretKey, ep);

#ifdef BENCH
            stop = std::chrono::high_resolution_clock::now();
            std::cerr << "Coefficient Encryption: " << std::chrono::duration<double>(stop - start).count() << " s\n";
            start = std::chrono::high_resolution_clock::now();
#endif

            SchemeletRLWEMP::ModSwitch(ctxtBFV, t.Q, t.QBFVInit);

            auto ctxt = SchemeletRLWEMP::ConvertRLWEToCKKS(*cc, ctxtBFV, keyPair.publicKey, t.Bigq, numSlotsCKKS,
                                                           depth - (t.levelsAvailableBeforeBootstrap > 0));

            Ciphertext<DCRTPoly> ctxtAfterFBT;
            if (binaryLUT)
                ctxtAfterFBT =
                    cc->EvalFBT(ctxt, coeffint, t.PInput.GetMSB() - 1, ep->GetModulus(), t.scaleTHI, 0, t.order);
            else
                ctxtAfterFBT =
                    cc->EvalFBT(ctxt, coeffcomp, t.PInput.GetMSB() - 1, ep->GetModulus(), t.scaleTHI, 0, t.order);

            auto polys = SchemeletRLWEMP::ConvertCKKSToRLWE(ctxtAfterFBT, t.Q);

#ifdef BENCH
            stop = std::chrono::high_resolution_clock::now();
            std::cerr << "FuncBootstrapping Eval: " << std::chrono::duration<double>(stop - start).count() << " s\n";
            start = std::chrono::high_resolution_clock::now();
#endif

            auto computed =
                SchemeletRLWEMP::DecryptCoeff(polys, t.Q, t.POutput, keyPair.secretKey, ep, numSlotsCKKS, t.numSlots);

#ifdef BENCH
            stop = std::chrono::high_resolution_clock::now();
            std::cerr << "Poly Decryption: " << std::chrono::duration<double>(stop - start).count() << " s\n";
#endif

            auto exact(x);
            std::transform(x.begin(), x.end(), exact.begin(), [&](int64_t elem) {
                return (f(elem) > t.POutput.ConvertToDouble() / 2.) ? f(elem) - t.POutput.ConvertToInt<int64_t>() :
                                                                      f(elem);
            });

            std::transform(exact.begin(), exact.end(), computed.begin(), exact.begin(), std::minus<int64_t>());
            std::transform(exact.begin(), exact.end(), exact.begin(),
                           [&](int64_t elem) { return (std::abs(elem)) % (t.POutput.ConvertToInt()); });
            auto max_error_it = std::max_element(exact.begin(), exact.end());
            // std::cerr << "\n=======Error count: " << std::accumulate(exact.begin(), exact.end(), 0) << "\n";
            // std::cerr << "\n=======Max absolute error: " << *max_error_it << "\n";
            checkEquality((*max_error_it), static_cast<int64_t>(0), 0.0001, failmsg + " LUT evaluation fails");

            cc->ClearStaticMapsAndVectors();
        }
        catch (std::exception& e) {
            std::cerr << "Exception thrown from " << __func__ << "(): " << e.what() << std::endl;
            EXPECT_TRUE(0 == 1) << failmsg;
        }
        catch (...) {
            UNIT_TEST_HANDLE_ALL_EXCEPTIONS;
        }
    }

    void UnitTest_SignDigit(TEST_CASE_FBT t, const std::string& failmsg = std::string()) {
        try {
#ifdef BENCH
            auto start = std::chrono::high_resolution_clock::now();
#endif
            bool flagSP = (t.numSlots <= t.ringDim / 2);  // sparse packing
            // t.numSlots represents number of values to be encrypted in BFV. If same as ring dimension, CKKS slots is halved.
            auto numSlotsCKKS = flagSP ? t.numSlots : t.numSlots / 2;

            auto a = t.PInput.ConvertToInt<int64_t>();
            auto b = t.POutput.ConvertToInt<int64_t>();

            auto funcMod = [b](int64_t x) -> int64_t {
                return (x % b);
            };
            auto funcStep = [a, b](int64_t x) -> int64_t {
                return (x % a) >= (b / 2);
            };

            std::vector<int64_t> x = {
                t.PInput.ConvertToInt<int64_t>() / 2, t.PInput.ConvertToInt<int64_t>() / 2 + 1, 0, 3, 16, 33, 64,
                t.PInput.ConvertToInt<int64_t>() - 1};
            if (x.size() < t.numSlots)
                x = Fill<int64_t>(x, t.numSlots);

            auto exact(x);
            std::transform(x.begin(), x.end(), exact.begin(),
                           [&](int64_t elem) { return (elem >= t.PInput.ConvertToDouble() / 2.); });

            std::vector<int64_t> coeffintMod;
            std::vector<std::complex<double>> coeffcompMod;
            std::vector<std::complex<double>> coeffcompStep;
            bool binaryLUT = (t.POutput.ConvertToInt() == 2) && (t.order == 1);
            if (binaryLUT) {
                coeffintMod = {funcMod(1),
                               funcMod(0) - funcMod(1)};  // coeffs for [1, cos^2(pi x)], not [1, cos(2pi x)]
            }
            else {
                coeffcompMod =
                    GetHermiteTrigCoefficients(funcMod, t.POutput.ConvertToInt(), t.order, t.scaleTHI);  // divided by 2
                coeffcompStep = GetHermiteTrigCoefficients(funcStep, t.POutput.ConvertToInt(), t.order,
                                                           t.scaleStepTHI);  // divided by 2
            }

#ifdef BENCH
            auto stop = std::chrono::high_resolution_clock::now();
            std::cerr << "Coefficient Generation: " << std::chrono::duration<double>(stop - start).count() << " s\n";
            start = std::chrono::high_resolution_clock::now();
#endif

            const uint32_t dcrtBits = t.Bigq.GetMSB() - 1;
            CCParams<CryptoContextCKKSRNS> parameters;
            parameters.SetSecretKeyDist(t.skd);
            parameters.SetSecurityLevel(HEStd_NotSet);
            parameters.SetScalingModSize(dcrtBits);
            parameters.SetScalingTechnique(t.scalTech);
            parameters.SetFirstModSize(dcrtBits);
            parameters.SetNumLargeDigits(t.dnum);
            parameters.SetBatchSize(numSlotsCKKS);
            parameters.SetRingDim(t.ringDim);

            uint32_t depth = t.levelsAvailableAfterBootstrap;

            if (binaryLUT)
                depth += FHECKKSRNS::GetFBTDepth(t.lvlb, coeffintMod, t.POutput, t.order, t.skd);
            else
                depth += FHECKKSRNS::GetFBTDepth(t.lvlb, coeffcompMod, t.POutput, t.order, t.skd);

            parameters.SetMultiplicativeDepth(depth);

            auto cc = GenCryptoContext(parameters);
            cc->Enable(PKE);
            cc->Enable(KEYSWITCH);
            cc->Enable(LEVELEDSHE);
            cc->Enable(ADVANCEDSHE);
            cc->Enable(FHE);

            auto keyPair = cc->KeyGen();

#ifdef BENCH
            stop = std::chrono::high_resolution_clock::now();
            std::cerr << "Cryptocontext Generation: " << std::chrono::duration<double>(stop - start).count() << " s\n";
            start = std::chrono::high_resolution_clock::now();
#endif

            if (binaryLUT)
                cc->EvalFBTSetup(coeffintMod, numSlotsCKKS, t.POutput, t.PInput, t.Bigq, keyPair.publicKey, {0, 0},
                                 t.lvlb, t.levelsAvailableAfterBootstrap, 0, t.order);
            else
                cc->EvalFBTSetup(coeffcompMod, numSlotsCKKS, t.POutput, t.PInput, t.Bigq, keyPair.publicKey, {0, 0},
                                 t.lvlb, t.levelsAvailableAfterBootstrap, 0, t.order);

#ifdef BENCH
            stop = std::chrono::high_resolution_clock::now();
            std::cerr << "FuncBootstrapping Setup: " << std::chrono::duration<double>(stop - start).count() << " s\n";
            start = std::chrono::high_resolution_clock::now();
#endif

            cc->EvalBootstrapKeyGen(keyPair.secretKey, numSlotsCKKS);
            cc->EvalMultKeyGen(keyPair.secretKey);

#ifdef BENCH
            stop = std::chrono::high_resolution_clock::now();
            std::cerr << "FuncBootstrapping KeyGen: " << std::chrono::duration<double>(stop - start).count() << " s\n";
            start = std::chrono::high_resolution_clock::now();
#endif

            auto ep = SchemeletRLWEMP::GetElementParams(keyPair.secretKey,
                                                        depth - (t.levelsAvailableBeforeBootstrap > 0));

            auto ctxtBFV = SchemeletRLWEMP::EncryptCoeff(x, t.QBFVInit, t.PInput, keyPair.secretKey, ep);

#ifdef BENCH
            stop = std::chrono::high_resolution_clock::now();
            std::cerr << "Coefficient Encryption: " << std::chrono::duration<double>(stop - start).count() << " s\n";
            start = std::chrono::high_resolution_clock::now();
#endif

            std::vector<int64_t> coeffint;
            std::vector<std::complex<double>> coeffcomp;
            if (binaryLUT)
                coeffint = coeffintMod;
            else
                coeffcomp = coeffcompMod;

            SchemeletRLWEMP::ModSwitch(ctxtBFV, t.Q, t.QBFVInit);

            uint32_t QBFVBits = t.Q.GetMSB() - 1;

            auto Q      = t.Q;       // Will get modified in the loop.
            auto PInput = t.PInput;  // Will get modified in the loop.

            BigInteger QNew;

            const bool checkeq2       = t.POutput.ConvertToInt() == 2;
            const bool checkgt2       = t.POutput.ConvertToInt() > 2;
            const uint32_t pDigitBits = t.POutput.GetMSB() - 1;

            uint64_t scaleTHI        = t.scaleTHI;
            bool step                = false;
            bool go                  = QBFVBits > dcrtBits;
            size_t levelsToDrop      = 0;
            uint32_t postScalingBits = 0;

            // For arbitrary digit size, pNew > 2, the last iteration needs to evaluate step pNew not mod pNew.
            // Currently this only works when log(pNew) divides log(p).
            while (go) {
                auto encryptedDigit = ctxtBFV;

                // Apply mod q
                encryptedDigit[0].SwitchModulus(t.Bigq, 1, 0, 0);
                encryptedDigit[1].SwitchModulus(t.Bigq, 1, 0, 0);

                auto ctxt =
                    SchemeletRLWEMP::ConvertRLWEToCKKS(*cc, encryptedDigit, keyPair.publicKey, t.Bigq, numSlotsCKKS,
                                                       depth - (t.levelsAvailableBeforeBootstrap > 0));

                // Bootstrap the digit.
                Ciphertext<DCRTPoly> ctxtAfterFBT;
                if (binaryLUT)
                    ctxtAfterFBT = cc->EvalFBT(ctxt, coeffint, pDigitBits, ep->GetModulus(),
                                               scaleTHI * (1 << postScalingBits), levelsToDrop, t.order);
                else
                    ctxtAfterFBT = cc->EvalFBT(ctxt, coeffcomp, pDigitBits, ep->GetModulus(),
                                               scaleTHI * (1 << postScalingBits), levelsToDrop, t.order);

                auto polys = SchemeletRLWEMP::ConvertCKKSToRLWE(ctxtAfterFBT, Q);

                if (!step) {
                    QNew = Q >> pDigitBits;

                    // Subtract digit and switch mod from Q to QNew for BFV ciphertext
                    ctxtBFV[0] = (ctxtBFV[0] - polys[0]).MultiplyAndRound(QNew, Q);
                    ctxtBFV[0].SwitchModulus(QNew, 1, 0, 0);
                    ctxtBFV[1] = (ctxtBFV[1] - polys[1]).MultiplyAndRound(QNew, Q);
                    ctxtBFV[1].SwitchModulus(QNew, 1, 0, 0);
                    Q >>= pDigitBits;
                    PInput >>= pDigitBits;
                    QBFVBits -= pDigitBits;
                    postScalingBits += pDigitBits;
                }
                else {
                    ctxtBFV[0] = std::move(polys[0]);
                    ctxtBFV[1] = std::move(polys[1]);
                }

                go = QBFVBits > dcrtBits;

                if (step || (checkeq2 && !go)) {
#ifdef BENCH
                    stop = std::chrono::high_resolution_clock::now();
                    std::cerr << "FuncBootstrapping Eval: " << std::chrono::duration<double>(stop - start).count()
                              << " s\n";
                    start = std::chrono::high_resolution_clock::now();
#endif

                    auto computed = SchemeletRLWEMP::DecryptCoeff(ctxtBFV, Q, PInput, keyPair.secretKey, ep,
                                                                  numSlotsCKKS, t.numSlots);

#ifdef BENCH
                    stop = std::chrono::high_resolution_clock::now();
                    std::cerr << "Poly Decryption: " << std::chrono::duration<double>(stop - start).count() << " s\n";
                    start = std::chrono::high_resolution_clock::now();
#endif

                    std::transform(exact.begin(), exact.end(), computed.begin(), exact.begin(), std::minus<int64_t>());
                    std::transform(exact.begin(), exact.end(), exact.begin(),
                                   [&](int64_t elem) { return (std::abs(elem)) % (t.PInput.ConvertToInt()); });
                    auto max_error_it = std::max_element(exact.begin(), exact.end());
                    // std::cerr << "\n=======Error count: " << std::accumulate(exact.begin(), exact.end(), 0) << "\n";
                    // std::cerr << "\n=======Max absolute error: " << *max_error_it << "\n";
                    checkEquality((*max_error_it), static_cast<int64_t>(0), 0.0001,
                                  failmsg + " MP sign evaluation fails");
                }

                if (checkgt2 && !go && !step) {
                    if (!binaryLUT)
                        coeffcomp = coeffcompStep;
                    scaleTHI = t.scaleStepTHI;
                    step     = true;
                    go       = true;

                    int64_t lvlsToDrop = GetMultiplicativeDepthByCoeffVector(coeffcompMod, true) -
                                         GetMultiplicativeDepthByCoeffVector(coeffcompStep, true);
                    if (coeffcompMod.size() > 4 && lvlsToDrop > 0)
                        levelsToDrop = lvlsToDrop;
                }
            }

            cc->ClearStaticMapsAndVectors();
        }
        catch (std::exception& e) {
            std::cerr << "Exception thrown from " << __func__ << "(): " << e.what() << std::endl;
            EXPECT_TRUE(0 == 1) << failmsg;
        }
        catch (...) {
            UNIT_TEST_HANDLE_ALL_EXCEPTIONS;
        }
    }

    void UnitTest_ConsecLevLUT(TEST_CASE_FBT t, const std::string& failmsg = std::string()) {
        try {
#ifdef BENCH
            auto start = std::chrono::high_resolution_clock::now();
#endif
            bool flagBR = (t.lvlb[0] != 1 || t.lvlb[1] != 1);
            bool flagSP = (t.numSlots <= t.ringDim / 2);  // sparse packing

            // t.numSlots represents number of values to be encrypted in BFV. If same as ring dimension, CKKS slots is halved.
            auto numSlotsCKKS = flagSP ? t.numSlots : t.numSlots / 2;

            auto a = t.PInput.ConvertToInt<int64_t>();
            auto b = t.POutput.ConvertToInt<int64_t>();
            auto f = [a, b](int64_t x) -> int64_t {
                return (x % a - a / 2) % b;
            };

            std::vector<int64_t> x = {
                t.PInput.ConvertToInt<int64_t>() / 2, t.PInput.ConvertToInt<int64_t>() / 2 + 1, 0, 3, 16, 33, 64,
                t.PInput.ConvertToInt<int64_t>() - 1};
            if (x.size() < t.numSlots)
                x = Fill<int64_t>(x, t.numSlots);

            std::vector<int64_t> coeffint;
            std::vector<std::complex<double>> coeffcomp;
            bool binaryLUT = (t.PInput.ConvertToInt() == 2) && (t.order == 1);
            if (binaryLUT)  // coeffs for [1, cos^2(pi x)], not [1, cos(2pi x)]
                coeffint = {f(1), f(0) - f(1)};
            else  // divided by 2
                coeffcomp = GetHermiteTrigCoefficients(f, t.PInput.ConvertToInt(), t.order, t.scaleTHI);

#ifdef BENCH
            auto stop = std::chrono::high_resolution_clock::now();
            std::cerr << "Coefficient Generation: " << std::chrono::duration<double>(stop - start).count() << " s\n";
            start = std::chrono::high_resolution_clock::now();
#endif

            const uint32_t dcrtBits = t.Bigq.GetMSB() - 1;
            CCParams<CryptoContextCKKSRNS> parameters;
            parameters.SetSecretKeyDist(t.skd);
            parameters.SetSecurityLevel(HEStd_NotSet);
            parameters.SetScalingModSize(dcrtBits);
            parameters.SetScalingTechnique(t.scalTech);
            parameters.SetFirstModSize(dcrtBits);
            parameters.SetNumLargeDigits(t.dnum);
            parameters.SetBatchSize(numSlotsCKKS);
            parameters.SetRingDim(t.ringDim);
            uint32_t depth = t.levelsAvailableAfterBootstrap + t.levelsComputation;

            if (binaryLUT)
                depth += FHECKKSRNS::GetFBTDepth(t.lvlb, coeffint, t.PInput, t.order, t.skd);
            else
                depth += FHECKKSRNS::GetFBTDepth(t.lvlb, coeffcomp, t.PInput, t.order, t.skd);

            parameters.SetMultiplicativeDepth(depth);

            auto cc = GenCryptoContext(parameters);
            cc->Enable(PKE);
            cc->Enable(KEYSWITCH);
            cc->Enable(LEVELEDSHE);
            cc->Enable(ADVANCEDSHE);
            cc->Enable(FHE);

            auto keyPair = cc->KeyGen();

#ifdef BENCH
            stop = std::chrono::high_resolution_clock::now();
            std::cerr << "Cryptocontext Generation: " << std::chrono::duration<double>(stop - start).count() << " s\n";
            start = std::chrono::high_resolution_clock::now();
#endif

            if (binaryLUT)
                cc->EvalFBTSetup(coeffint, numSlotsCKKS, t.PInput, t.POutput, t.Bigq, keyPair.publicKey, {0, 0}, t.lvlb,
                                 t.levelsAvailableAfterBootstrap, t.levelsComputation, t.order);
            else
                cc->EvalFBTSetup(coeffcomp, numSlotsCKKS, t.PInput, t.POutput, t.Bigq, keyPair.publicKey, {0, 0},
                                 t.lvlb, t.levelsAvailableAfterBootstrap, t.levelsComputation, t.order);

#ifdef BENCH
            stop = std::chrono::high_resolution_clock::now();
            std::cerr << "FuncBootstrapping Setup: " << std::chrono::duration<double>(stop - start).count() << " s\n";
            start = std::chrono::high_resolution_clock::now();
#endif

            cc->EvalBootstrapKeyGen(keyPair.secretKey, numSlotsCKKS);
            cc->EvalMultKeyGen(keyPair.secretKey);
            cc->EvalAtIndexKeyGen(keyPair.secretKey, std::vector<int32_t>({-2}));

#ifdef BENCH
            stop = std::chrono::high_resolution_clock::now();
            std::cerr << "FuncBootstrapping KeyGen: " << std::chrono::duration<double>(stop - start).count() << " s\n";
            start = std::chrono::high_resolution_clock::now();
#endif

            auto mask_real = Fill<double>({1, 1, 1, 1, 0, 0, 0, 0}, t.numSlots);

            // The mask level is counted on the full modulus chain, which has an extra modulus for FLEXIBLEAUTOEXT
            const uint32_t extOff = (t.scalTech == FLEXIBLEAUTOEXT) ? 1 : 0;

            // Note that the corresponding plaintext mask for full packing can be just real, as real times complex multiplies both real and imaginary parts
            Plaintext ptxt_mask = cc->MakeCKKSPackedPlaintext(
                Fill<double>({1, 1, 1, 1, 0, 0, 0, 0}, numSlotsCKKS), 1,
                depth + extOff - t.lvlb[1] - t.levelsAvailableAfterBootstrap - t.levelsComputation, nullptr,
                numSlotsCKKS);

            auto ep = SchemeletRLWEMP::GetElementParams(keyPair.secretKey,
                                                        depth - (t.levelsAvailableBeforeBootstrap > 0));

            // Set bitReverse true to be able to perform correct rotations in CKKS
            auto ctxtBFV = SchemeletRLWEMP::EncryptCoeff(x, t.QBFVInit, t.PInput, keyPair.secretKey, ep, flagBR);

#ifdef BENCH
            stop = std::chrono::high_resolution_clock::now();
            std::cerr << "Coefficient Encryption: " << std::chrono::duration<double>(stop - start).count() << " s\n";
            start = std::chrono::high_resolution_clock::now();
#endif

            SchemeletRLWEMP::ModSwitch(ctxtBFV, t.Q, t.QBFVInit);

            auto ctxt = SchemeletRLWEMP::ConvertRLWEToCKKS(*cc, ctxtBFV, keyPair.publicKey, t.Bigq, numSlotsCKKS,
                                                           depth - (t.levelsAvailableBeforeBootstrap > 0));

            // Apply LUT and remain in slots encodings.
            Ciphertext<DCRTPoly> ctxtAfterFBT;
            if (binaryLUT)
                ctxtAfterFBT = cc->EvalFBTNoDecoding(ctxt, coeffint, t.PInput.GetMSB() - 1, ep->GetModulus(), t.order);
            else
                ctxtAfterFBT = cc->EvalFBTNoDecoding(ctxt, coeffcomp, t.PInput.GetMSB() - 1, ep->GetModulus(), t.order);

            // Apply a rotation
            ctxtAfterFBT = cc->EvalRotate(ctxtAfterFBT, -2);

            // Apply a multiplicative mask
            ctxtAfterFBT = cc->EvalMult(ctxtAfterFBT, ptxt_mask);
            cc->ModReduceInPlace(ctxtAfterFBT);

            // Go back to coefficients, 0 because there are no extra levels to remove
            ctxtAfterFBT = cc->EvalHomDecoding(ctxtAfterFBT, t.scaleTHI, 0);

            auto polys1 = SchemeletRLWEMP::ConvertCKKSToRLWE(ctxtAfterFBT, t.Q);

            // Apply a subsequent LUT
            ctxt = SchemeletRLWEMP::ConvertRLWEToCKKS(*cc, polys1, keyPair.publicKey, t.Bigq, numSlotsCKKS,
                                                      depth - (t.levelsAvailableBeforeBootstrap > 0));

            if (binaryLUT)
                ctxtAfterFBT = cc->EvalFBT(ctxt, coeffint, t.PInput.GetMSB() - 1, ep->GetModulus(), t.scaleTHI,
                                           t.levelsComputation, t.order);
            else
                ctxtAfterFBT = cc->EvalFBT(ctxt, coeffcomp, t.PInput.GetMSB() - 1, ep->GetModulus(), t.scaleTHI,
                                           t.levelsComputation, t.order);

            auto polys2 = SchemeletRLWEMP::ConvertCKKSToRLWE(ctxtAfterFBT, t.Q);

#ifdef BENCH
            stop = std::chrono::high_resolution_clock::now();
            std::cerr << "FuncBootstrapping Eval: " << std::chrono::duration<double>(stop - start).count() << " s\n";
            start = std::chrono::high_resolution_clock::now();
#endif

            auto computed1 = SchemeletRLWEMP::DecryptCoeff(polys1, t.Q, t.POutput, keyPair.secretKey, ep, numSlotsCKKS,
                                                           t.numSlots, flagBR);

            auto computed2 = SchemeletRLWEMP::DecryptCoeff(polys2, t.Q, t.POutput, keyPair.secretKey, ep, numSlotsCKKS,
                                                           t.numSlots, flagBR);

#ifdef BENCH
            stop = std::chrono::high_resolution_clock::now();
            std::cerr << "Poly Decryption: " << std::chrono::duration<double>(stop - start).count() << " s\n";
#endif

            auto exact(x);
            std::transform(x.begin(), x.end(), exact.begin(), [&](int64_t elem) {
                return (f(elem) % t.POutput.ConvertToInt() > t.POutput.ConvertToDouble() / 2.) ?
                           f(elem) % t.POutput.ConvertToInt() - t.POutput.ConvertToInt() :
                           f(elem) % t.POutput.ConvertToInt();
            });

            // Apply a rotation
            std::vector<int64_t> exact2 = flagSP ? Rotate(exact, -2) : RotateTwoHalves(exact, -2);

            std::transform(exact2.begin(), exact2.end(), mask_real.begin(), exact2.begin(), std::multiplies<double>());

            auto exact3 = exact2;

            std::transform(exact2.begin(), exact2.end(), computed1.begin(), exact2.begin(), std::minus<int64_t>());
            std::transform(exact2.begin(), exact2.end(), exact2.begin(),
                           [&](int64_t elem) { return (std::abs(elem)) % (t.POutput.ConvertToInt()); });

            auto max_error_it = std::max_element(exact2.begin(), exact2.end());
            // std::cerr << "\n=======Error count: " << std::accumulate(exact.begin(), exact.end(), 0) << "\n";
            // std::cerr << "\n=======Max absolute error: " << *max_error_it << "\n";
            checkEquality((*max_error_it), static_cast<int64_t>(0), 0.0001, failmsg + " LUT evaluation fails");

            std::transform(exact3.begin(), exact3.end(), exact.begin(), [&](int64_t elem) {
                return (f(elem) % t.POutput.ConvertToInt() > t.POutput.ConvertToDouble() / 2.) ?
                           f(elem) % t.POutput.ConvertToInt() - t.POutput.ConvertToInt() :
                           f(elem) % t.POutput.ConvertToInt();
            });

            std::transform(exact.begin(), exact.end(), computed2.begin(), exact.begin(), std::minus<int64_t>());
            std::transform(exact.begin(), exact.end(), exact.begin(),
                           [&](int64_t elem) { return (std::abs(elem)) % (t.POutput.ConvertToInt()); });
            max_error_it = std::max_element(exact.begin(), exact.end());
            // std::cerr << "\n=======Error count: " << std::accumulate(exact.begin(), exact.end(), 0) << "\n";
            // std::cerr << "\n=======Max absolute error: " << *max_error_it << "\n";
            checkEquality((*max_error_it), static_cast<int64_t>(0), 0.0001, failmsg + " LUT evaluation fails");

            cc->ClearStaticMapsAndVectors();
        }
        catch (std::exception& e) {
            std::cerr << "Exception thrown from " << __func__ << "(): " << e.what() << std::endl;
            EXPECT_TRUE(0 == 1) << failmsg;
        }
        catch (...) {
            UNIT_TEST_HANDLE_ALL_EXCEPTIONS;
        }
    }

    void UnitTest_MVB(TEST_CASE_FBT t, const std::string& failmsg = std::string()) {
        try {
#ifdef BENCH
            auto start = std::chrono::high_resolution_clock::now();
#endif
            bool flagSP = (t.numSlots <= t.ringDim / 2);  // sparse packing
            // t.numSlots represents number of values to be encrypted in BFV. If same as ring dimension, CKKS slots is halved.
            auto numSlotsCKKS = flagSP ? t.numSlots : t.numSlots / 2;

            auto a  = t.PInput.ConvertToInt<int64_t>();
            auto b  = t.POutput.ConvertToInt<int64_t>();
            auto f1 = [a, b](int64_t x) -> int64_t {
                return (x % a - a / 2) % b;
            };
            auto f2 = [a, b](int64_t x) -> int64_t {
                return (x % a) % b;
            };

            std::vector<int64_t> x = {
                t.PInput.ConvertToInt<int64_t>() / 2, t.PInput.ConvertToInt<int64_t>() / 2 + 1, 0, 3, 16, 33, 64,
                t.PInput.ConvertToInt<int64_t>() - 1};
            if (x.size() < t.numSlots)
                x = Fill<int64_t>(x, t.numSlots);

            std::vector<int64_t> coeffint1;
            std::vector<int64_t> coeffint2;
            std::vector<std::complex<double>> coeffcomp1;
            std::vector<std::complex<double>> coeffcomp2;
            bool binaryLUT = (t.PInput.ConvertToInt() == 2) && (t.order == 1);
            if (binaryLUT) {
                coeffint1 = {f1(1), f1(0) - f1(1)};
                coeffint2 = {f2(1), f2(0) - f2(1)};
            }
            else {
                coeffcomp1 = GetHermiteTrigCoefficients(f1, t.PInput.ConvertToInt(), t.order, t.scaleTHI);
                coeffcomp2 = GetHermiteTrigCoefficients(f2, t.PInput.ConvertToInt(), t.order, t.scaleTHI);
            }

#ifdef BENCH
            auto stop = std::chrono::high_resolution_clock::now();
            std::cerr << "Coefficient Generation: " << std::chrono::duration<double>(stop - start).count() << " s\n";
            start = std::chrono::high_resolution_clock::now();
#endif

            const uint32_t dcrtBits = t.Bigq.GetMSB() - 1;
            CCParams<CryptoContextCKKSRNS> parameters;
            parameters.SetSecretKeyDist(t.skd);
            parameters.SetSecurityLevel(HEStd_NotSet);
            parameters.SetScalingModSize(dcrtBits);
            parameters.SetScalingTechnique(t.scalTech);
            parameters.SetFirstModSize(dcrtBits);
            parameters.SetNumLargeDigits(t.dnum);
            parameters.SetBatchSize(numSlotsCKKS);
            parameters.SetRingDim(t.ringDim);
            uint32_t depth = t.levelsAvailableAfterBootstrap + t.levelsComputation;

            if (binaryLUT)
                depth += FHECKKSRNS::GetFBTDepth(t.lvlb, coeffint1, t.PInput, t.order, t.skd);
            else
                depth += FHECKKSRNS::GetFBTDepth(t.lvlb, coeffcomp1, t.PInput, t.order, t.skd);

            parameters.SetMultiplicativeDepth(depth);

            auto cc = GenCryptoContext(parameters);
            cc->Enable(PKE);
            cc->Enable(KEYSWITCH);
            cc->Enable(LEVELEDSHE);
            cc->Enable(ADVANCEDSHE);
            cc->Enable(FHE);

            auto keyPair = cc->KeyGen();

#ifdef BENCH
            stop = std::chrono::high_resolution_clock::now();
            std::cerr << "Cryptocontext Generation: " << std::chrono::duration<double>(stop - start).count() << " s\n";
            start = std::chrono::high_resolution_clock::now();
#endif

            if (binaryLUT)
                cc->EvalFBTSetup(coeffint1, numSlotsCKKS, t.PInput, t.POutput, t.Bigq, keyPair.publicKey, {0, 0},
                                 t.lvlb, t.levelsAvailableAfterBootstrap, t.levelsComputation, t.order);
            else
                cc->EvalFBTSetup(coeffcomp1, numSlotsCKKS, t.PInput, t.POutput, t.Bigq, keyPair.publicKey, {0, 0},
                                 t.lvlb, t.levelsAvailableAfterBootstrap, t.levelsComputation, t.order);

#ifdef BENCH
            stop = std::chrono::high_resolution_clock::now();
            std::cerr << "FuncBootstrapping Setup: " << std::chrono::duration<double>(stop - start).count() << " s\n";
            start = std::chrono::high_resolution_clock::now();
#endif

            cc->EvalBootstrapKeyGen(keyPair.secretKey, numSlotsCKKS);
            cc->EvalMultKeyGen(keyPair.secretKey);

#ifdef BENCH
            stop = std::chrono::high_resolution_clock::now();
            std::cerr << "FuncBootstrapping KeyGen: " << std::chrono::duration<double>(stop - start).count() << " s\n";
            start = std::chrono::high_resolution_clock::now();
#endif

            auto ep = SchemeletRLWEMP::GetElementParams(keyPair.secretKey,
                                                        depth - (t.levelsAvailableBeforeBootstrap > 0));

            auto ctxtBFV = SchemeletRLWEMP::EncryptCoeff(x, t.QBFVInit, t.PInput, keyPair.secretKey, ep);

#ifdef BENCH
            stop = std::chrono::high_resolution_clock::now();
            std::cerr << "Coefficient Encryption: " << std::chrono::duration<double>(stop - start).count() << " s\n";
            start = std::chrono::high_resolution_clock::now();
#endif

            SchemeletRLWEMP::ModSwitch(ctxtBFV, t.Q, t.QBFVInit);

            auto ctxt = SchemeletRLWEMP::ConvertRLWEToCKKS(*cc, ctxtBFV, keyPair.publicKey, t.Bigq, numSlotsCKKS,
                                                           depth - (t.levelsAvailableBeforeBootstrap > 0));

            std::vector<Ciphertext<DCRTPoly>> complexExp;
            Ciphertext<DCRTPoly> ctxtAfterFBT1, ctxtAfterFBT2;

            if (binaryLUT) {
                // Compute the complex exponential and its powers to reuse
                auto complexExpPowers =
                    cc->EvalMVBPrecompute(ctxt, coeffint1, t.PInput.GetMSB() - 1, ep->GetModulus(), t.order);
                // Apply multiple LUTs
                ctxtAfterFBT1 = cc->EvalMVB(complexExpPowers, coeffint1, t.PInput.GetMSB() - 1, t.scaleTHI,
                                            t.levelsComputation, t.order);
                ctxtAfterFBT2 = cc->EvalMVBNoDecoding(complexExpPowers, coeffint2, t.PInput.GetMSB() - 1, t.order);
                ctxtAfterFBT2 = cc->EvalHomDecoding(ctxtAfterFBT2, t.scaleTHI, t.levelsComputation);
            }
            else {
                // Compute the complex exponential and its powers to reuse
                auto complexExpPowers =
                    cc->EvalMVBPrecompute(ctxt, coeffcomp1, t.PInput.GetMSB() - 1, ep->GetModulus(), t.order);
                // Apply multiple LUTs
                ctxtAfterFBT1 = cc->EvalMVB(complexExpPowers, coeffcomp1, t.PInput.GetMSB() - 1, t.scaleTHI,
                                            t.levelsComputation, t.order);
                ctxtAfterFBT2 = cc->EvalMVBNoDecoding(complexExpPowers, coeffcomp2, t.PInput.GetMSB() - 1, t.order);
                ctxtAfterFBT2 = cc->EvalHomDecoding(ctxtAfterFBT2, t.scaleTHI, t.levelsComputation);
            }

            auto polys1 = SchemeletRLWEMP::ConvertCKKSToRLWE(ctxtAfterFBT1, t.Q);

            auto polys2 = SchemeletRLWEMP::ConvertCKKSToRLWE(ctxtAfterFBT2, t.Q);

#ifdef BENCH
            stop = std::chrono::high_resolution_clock::now();
            std::cerr << "FuncBootstrapping Eval: " << std::chrono::duration<double>(stop - start).count() << " s\n";
            start = std::chrono::high_resolution_clock::now();
#endif

            auto computed1 =
                SchemeletRLWEMP::DecryptCoeff(polys1, t.Q, t.POutput, keyPair.secretKey, ep, numSlotsCKKS, t.numSlots);

            auto computed2 =
                SchemeletRLWEMP::DecryptCoeff(polys2, t.Q, t.POutput, keyPair.secretKey, ep, numSlotsCKKS, t.numSlots);

#ifdef BENCH
            stop = std::chrono::high_resolution_clock::now();
            std::cerr << "Poly Decryption: " << std::chrono::duration<double>(stop - start).count() << " s\n";
#endif

            auto exact(x);
            std::transform(x.begin(), x.end(), exact.begin(), [&](int64_t elem) {
                return (f1(elem) % t.POutput.ConvertToInt() > t.POutput.ConvertToDouble() / 2.) ?
                           f1(elem) % t.POutput.ConvertToInt() - t.POutput.ConvertToInt() :
                           f1(elem);
            });

            std::transform(exact.begin(), exact.end(), computed1.begin(), exact.begin(), std::minus<int64_t>());
            std::transform(exact.begin(), exact.end(), exact.begin(),
                           [&](int64_t elem) { return (std::abs(elem)) % (t.POutput.ConvertToInt()); });
            auto max_error_it = std::max_element(exact.begin(), exact.end());
            // std::cerr << "\n=======Error count: " << std::accumulate(exact.begin(), exact.end(), 0) << "\n";
            // std::cerr << "\n=======Max absolute error: " << *max_error_it << "\n";
            checkEquality((*max_error_it), static_cast<int64_t>(0), 0.0001, failmsg + " LUT evaluation fails");

            std::transform(x.begin(), x.end(), exact.begin(), [&](int64_t elem) {
                return (f2(elem) % t.POutput.ConvertToInt() > t.POutput.ConvertToDouble() / 2.) ?
                           f2(elem) % t.POutput.ConvertToInt() - t.POutput.ConvertToInt() :
                           f2(elem);
            });

            std::transform(exact.begin(), exact.end(), computed2.begin(), exact.begin(), std::minus<int64_t>());
            std::transform(exact.begin(), exact.end(), exact.begin(),
                           [&](int64_t elem) { return (std::abs(elem)) % (t.POutput.ConvertToInt()); });
            max_error_it = std::max_element(exact.begin(), exact.end());
            // std::cerr << "\n=======Error count: " << std::accumulate(exact.begin(), exact.end(), 0) << "\n";
            // std::cerr << "\n=======Max absolute error: " << *max_error_it << "\n";
            checkEquality((*max_error_it), static_cast<int64_t>(0), 0.0001, failmsg + " LUT evaluation fails");

            cc->ClearStaticMapsAndVectors();
        }
        catch (std::exception& e) {
            std::cerr << "Exception thrown from " << __func__ << "(): " << e.what() << std::endl;
            EXPECT_TRUE(0 == 1) << failmsg;
        }
        catch (...) {
            UNIT_TEST_HANDLE_ALL_EXCEPTIONS;
        }
    }
    // Evaluates the same LUT with FIXEDMANUAL and with t.scalTech (a FLEXIBLE* technique) and checks that
    // the FLEXIBLE* technique yields smaller noise in the output RLWE ciphertext. The FLEXIBLE* techniques
    // track the exact level-specific scaling factors, so the scaling-factor drift of the FIXED* techniques
    // is absent; for the same parameters this shows up as smaller output noise (equivalently, correctness
    // can be achieved with a smaller CKKS scaling factor).
    void UnitTest_Noise(TEST_CASE_FBT t, const std::string& failmsg = std::string()) {
        try {
            auto runOnce = [&t](ScalingTechnique scalTech, int64_t& maxErr) -> double {
                bool flagSP       = (t.numSlots <= t.ringDim / 2);  // sparse packing
                auto numSlotsCKKS = flagSP ? t.numSlots : t.numSlots / 2;

                auto a = t.PInput.ConvertToInt<int64_t>();
                auto b = t.POutput.ConvertToInt<int64_t>();
                auto f = [a, b](int64_t x) -> int64_t {
                    return (x % a - a / 2) % b;
                };

                std::vector<int64_t> x = {(t.PInput.ConvertToInt<int64_t>() / 2),
                                          (t.PInput.ConvertToInt<int64_t>() / 2) + 1,
                                          0,
                                          3,
                                          16,
                                          33,
                                          64,
                                          (t.PInput.ConvertToInt<int64_t>() - 1)};
                if (x.size() < t.numSlots)
                    x = Fill<int64_t>(x, t.numSlots);

                std::vector<int64_t> coeffint;
                std::vector<std::complex<double>> coeffcomp;
                bool binaryLUT = (t.PInput.ConvertToInt() == 2) && (t.order == 1);
                if (binaryLUT)  // coeffs for [1, cos^2(pi x)], not [1, cos(2pi x)]
                    coeffint = {f(1), f(0) - f(1)};
                else  // divided by 2
                    coeffcomp = GetHermiteTrigCoefficients(f, t.PInput.ConvertToInt(), t.order, t.scaleTHI);

                const uint32_t dcrtBits = t.Bigq.GetMSB() - 1;
                CCParams<CryptoContextCKKSRNS> parameters;
                parameters.SetSecretKeyDist(t.skd);
                parameters.SetSecurityLevel(HEStd_NotSet);
                parameters.SetScalingModSize(dcrtBits);
                parameters.SetScalingTechnique(scalTech);
                parameters.SetFirstModSize(dcrtBits);
                parameters.SetNumLargeDigits(t.dnum);
                parameters.SetBatchSize(numSlotsCKKS);
                parameters.SetRingDim(t.ringDim);
                uint32_t depth = t.levelsAvailableAfterBootstrap;

                if (binaryLUT)
                    depth += FHECKKSRNS::GetFBTDepth(t.lvlb, coeffint, t.PInput, t.order, t.skd);
                else
                    depth += FHECKKSRNS::GetFBTDepth(t.lvlb, coeffcomp, t.PInput, t.order, t.skd);

                parameters.SetMultiplicativeDepth(depth);

                auto cc = GenCryptoContext(parameters);
                cc->Enable(PKE);
                cc->Enable(KEYSWITCH);
                cc->Enable(LEVELEDSHE);
                cc->Enable(ADVANCEDSHE);
                cc->Enable(FHE);

                auto keyPair = cc->KeyGen();

                if (binaryLUT)
                    cc->EvalFBTSetup(coeffint, numSlotsCKKS, t.PInput, t.POutput, t.Bigq, keyPair.publicKey, {0, 0},
                                     t.lvlb, t.levelsAvailableAfterBootstrap, 0, t.order);
                else
                    cc->EvalFBTSetup(coeffcomp, numSlotsCKKS, t.PInput, t.POutput, t.Bigq, keyPair.publicKey, {0, 0},
                                     t.lvlb, t.levelsAvailableAfterBootstrap, 0, t.order);

                cc->EvalBootstrapKeyGen(keyPair.secretKey, numSlotsCKKS);
                cc->EvalMultKeyGen(keyPair.secretKey);

                auto ep = SchemeletRLWEMP::GetElementParams(keyPair.secretKey, depth);

                auto ctxtBFV = SchemeletRLWEMP::EncryptCoeff(x, t.QBFVInit, t.PInput, keyPair.secretKey, ep);

                SchemeletRLWEMP::ModSwitch(ctxtBFV, t.Q, t.QBFVInit);

                auto ctxt = SchemeletRLWEMP::ConvertRLWEToCKKS(*cc, ctxtBFV, keyPair.publicKey, t.Bigq, numSlotsCKKS,
                                                               depth);

                Ciphertext<DCRTPoly> ctxtAfterFBT;
                if (binaryLUT)
                    ctxtAfterFBT =
                        cc->EvalFBT(ctxt, coeffint, t.PInput.GetMSB() - 1, ep->GetModulus(), t.scaleTHI, 0, t.order);
                else
                    ctxtAfterFBT =
                        cc->EvalFBT(ctxt, coeffcomp, t.PInput.GetMSB() - 1, ep->GetModulus(), t.scaleTHI, 0, t.order);

                auto polys = SchemeletRLWEMP::ConvertCKKSToRLWE(ctxtAfterFBT, t.Q);

                auto computed = SchemeletRLWEMP::DecryptCoeff(polys, t.Q, t.POutput, keyPair.secretKey, ep,
                                                              numSlotsCKKS, t.numSlots);

                auto exact(x);
                std::transform(x.begin(), x.end(), exact.begin(), [&](int64_t elem) {
                    return (f(elem) > t.POutput.ConvertToDouble() / 2.) ? f(elem) - t.POutput.ConvertToInt<int64_t>() :
                                                                          f(elem);
                });

                std::transform(exact.begin(), exact.end(), computed.begin(), exact.begin(), std::minus<int64_t>());
                std::transform(exact.begin(), exact.end(), exact.begin(),
                               [&](int64_t elem) { return (std::abs(elem)) % (t.POutput.ConvertToInt()); });
                maxErr = *std::max_element(exact.begin(), exact.end());

                double noiseBits =
                    MeasureNoiseBits(polys, t.Q, t.POutput, keyPair.secretKey, ep, numSlotsCKKS, t.numSlots);

                cc->ClearStaticMapsAndVectors();
                return noiseBits;
            };

            int64_t errFixed  = -1;
            int64_t errFlex   = -1;
            double noiseFixed = runOnce(FIXEDMANUAL, errFixed);
            double noiseFlex  = runOnce(t.scalTech, errFlex);

            checkEquality(errFixed, static_cast<int64_t>(0), 0.0001, failmsg + " FIXEDMANUAL LUT evaluation fails");
            checkEquality(errFlex, static_cast<int64_t>(0), 0.0001,
                          failmsg + " " + ScalTechName(t.scalTech) + " LUT evaluation fails");
            EXPECT_LT(noiseFlex, noiseFixed)
                << failmsg << " " << ScalTechName(t.scalTech) << " did not yield smaller noise than FIXEDMANUAL ("
                << noiseFlex << " vs " << noiseFixed << " bits)";
        }
        catch (std::exception& e) {
            std::cerr << "Exception thrown from " << __func__ << "(): " << e.what() << std::endl;
            EXPECT_TRUE(0 == 1) << failmsg;
        }
        catch (...) {
            UNIT_TEST_HANDLE_ALL_EXCEPTIONS;
        }
    }

    // Evaluates the same binary LUT twice on the same precomputed powers and checks that both results
    // are correct, so the second evaluation detects any in-place corruption of the shared precomputation.
    // The LUT values f(0) = 2, f(1) = 1 give the coefficients {1, 1}, for which the evaluation performs
    // an in-place multiplication and addition (coefficients {c, -1}, as in UnitTest_MVB, take a
    // different, non-mutating path).
    void UnitTest_MVBReuse(TEST_CASE_FBT t, const std::string& failmsg = std::string()) {
        try {
            bool flagSP       = (t.numSlots <= t.ringDim / 2);  // sparse packing
            auto numSlotsCKKS = flagSP ? t.numSlots : t.numSlots / 2;

            auto f = [](int64_t x) -> int64_t {
                return 2 - (x % 2);
            };
            std::vector<int64_t> coeffint = {f(1), f(0) - f(1)};

            std::vector<int64_t> x = {1, 0, 1, 1, 0, 1, 0, 0};
            if (x.size() < t.numSlots)
                x = Fill<int64_t>(x, t.numSlots);

            const uint32_t dcrtBits = t.Bigq.GetMSB() - 1;
            CCParams<CryptoContextCKKSRNS> parameters;
            parameters.SetSecretKeyDist(t.skd);
            parameters.SetSecurityLevel(HEStd_NotSet);
            parameters.SetScalingModSize(dcrtBits);
            parameters.SetScalingTechnique(t.scalTech);
            parameters.SetFirstModSize(dcrtBits);
            parameters.SetNumLargeDigits(t.dnum);
            parameters.SetBatchSize(numSlotsCKKS);
            parameters.SetRingDim(t.ringDim);
            uint32_t depth = t.levelsAvailableAfterBootstrap +
                             FHECKKSRNS::GetFBTDepth(t.lvlb, coeffint, t.PInput, t.order, t.skd);
            parameters.SetMultiplicativeDepth(depth);

            auto cc = GenCryptoContext(parameters);
            cc->Enable(PKE);
            cc->Enable(KEYSWITCH);
            cc->Enable(LEVELEDSHE);
            cc->Enable(ADVANCEDSHE);
            cc->Enable(FHE);

            auto keyPair = cc->KeyGen();

            cc->EvalFBTSetup(coeffint, numSlotsCKKS, t.PInput, t.POutput, t.Bigq, keyPair.publicKey, {0, 0}, t.lvlb,
                             t.levelsAvailableAfterBootstrap, 0, t.order);
            cc->EvalBootstrapKeyGen(keyPair.secretKey, numSlotsCKKS);
            cc->EvalMultKeyGen(keyPair.secretKey);

            auto ep      = SchemeletRLWEMP::GetElementParams(keyPair.secretKey, depth);
            auto ctxtBFV = SchemeletRLWEMP::EncryptCoeff(x, t.QBFVInit, t.PInput, keyPair.secretKey, ep);
            SchemeletRLWEMP::ModSwitch(ctxtBFV, t.Q, t.QBFVInit);
            auto ctxt =
                SchemeletRLWEMP::ConvertRLWEToCKKS(*cc, ctxtBFV, keyPair.publicKey, t.Bigq, numSlotsCKKS, depth);

            auto powers = cc->EvalMVBPrecompute(ctxt, coeffint, t.PInput.GetMSB() - 1, ep->GetModulus(), t.order);

            auto exact(x);
            std::transform(x.begin(), x.end(), exact.begin(), f);

            for (uint32_t run = 1; run <= 2; ++run) {
                auto ctxtAfterFBT = cc->EvalMVB(powers, coeffint, t.PInput.GetMSB() - 1, t.scaleTHI, 0, t.order);
                auto polys        = SchemeletRLWEMP::ConvertCKKSToRLWE(ctxtAfterFBT, t.Q);
                auto computed     = SchemeletRLWEMP::DecryptCoeff(polys, t.Q, t.POutput, keyPair.secretKey, ep,
                                                                  numSlotsCKKS, t.numSlots);

                std::vector<int64_t> err(exact.size());
                std::transform(exact.begin(), exact.end(), computed.begin(), err.begin(), std::minus<int64_t>());
                std::transform(err.begin(), err.end(), err.begin(),
                               [&](int64_t elem) { return (std::abs(elem)) % (t.POutput.ConvertToInt()); });
                auto max_error_it = std::max_element(err.begin(), err.end());
                checkEquality((*max_error_it), static_cast<int64_t>(0), 0.0001,
                              failmsg + " LUT evaluation " + std::to_string(run) + " on the reused precomputation fails");
            }

            cc->ClearStaticMapsAndVectors();
        }
        catch (std::exception& e) {
            std::cerr << "Exception thrown from " << __func__ << "(): " << e.what() << std::endl;
            EXPECT_TRUE(0 == 1) << failmsg;
        }
        catch (...) {
            UNIT_TEST_HANDLE_ALL_EXCEPTIONS;
        }
    }

    // Checks that invalid usage is rejected with an exception instead of silently corrupting results:
    // 1) an oversized levelToReduce in EvalHomDecoding under FLEXIBLE*, and 2) a FLEXIBLEAUTOEXT input
    // that still includes the extra modulus. EvalFBTSetup also rejects the scaling techniques it does
    // not support, which is left to be covered when composite scaling is supported.
    void UnitTest_InvalidArgs(TEST_CASE_FBT t, const std::string& failmsg = std::string()) {
        try {
            bool flagSP       = (t.numSlots <= t.ringDim / 2);  // sparse packing
            auto numSlotsCKKS = flagSP ? t.numSlots : t.numSlots / 2;

            auto a = t.PInput.ConvertToInt<int64_t>();
            auto b = t.POutput.ConvertToInt<int64_t>();
            auto f = [a, b](int64_t x) -> int64_t {
                return (x % a - a / 2) % b;
            };
            std::vector<int64_t> coeffint = {f(1), f(0) - f(1)};

            const uint32_t dcrtBits = t.Bigq.GetMSB() - 1;
            uint32_t depth          = t.levelsAvailableAfterBootstrap +
                             FHECKKSRNS::GetFBTDepth(t.lvlb, coeffint, t.PInput, t.order, t.skd);

            auto makeParams = [&](ScalingTechnique st) {
                CCParams<CryptoContextCKKSRNS> parameters;
                parameters.SetSecretKeyDist(t.skd);
                parameters.SetSecurityLevel(HEStd_NotSet);
                parameters.SetScalingModSize(dcrtBits);
                parameters.SetScalingTechnique(st);
                parameters.SetFirstModSize(dcrtBits);
                parameters.SetNumLargeDigits(t.dnum);
                parameters.SetBatchSize(numSlotsCKKS);
                parameters.SetRingDim(t.ringDim);
                parameters.SetMultiplicativeDepth(depth);
                return parameters;
            };
            auto enableAll = [](CryptoContext<DCRTPoly>& cc) {
                cc->Enable(PKE);
                cc->Enable(KEYSWITCH);
                cc->Enable(LEVELEDSHE);
                cc->Enable(ADVANCEDSHE);
                cc->Enable(FHE);
            };

            {
                // an oversized levelToReduce under FLEXIBLE* is rejected instead of silently zeroing the result
                auto parameters = makeParams(FLEXIBLEAUTO);
                auto cc         = GenCryptoContext(parameters);
                enableAll(cc);
                auto keyPair = cc->KeyGen();
                cc->EvalFBTSetup(coeffint, numSlotsCKKS, t.PInput, t.POutput, t.Bigq, keyPair.publicKey, {0, 0},
                                 t.lvlb, t.levelsAvailableAfterBootstrap, 0, t.order);
                std::vector<double> y(numSlotsCKKS, 0.5);
                auto ctxt = cc->Encrypt(keyPair.publicKey, cc->MakeCKKSPackedPlaintext(y));
                EXPECT_THROW(cc->EvalHomDecoding(ctxt, 1, depth), OpenFHEException)
                    << failmsg << " oversized levelToReduce not rejected";
                cc->ClearStaticMapsAndVectors();
            }

            {
                // a FLEXIBLEAUTOEXT input that includes the extra modulus is rejected
                auto parameters = makeParams(FLEXIBLEAUTOEXT);
                auto cc         = GenCryptoContext(parameters);
                enableAll(cc);
                auto keyPair = cc->KeyGen();
                cc->EvalFBTSetup(coeffint, numSlotsCKKS, t.PInput, t.POutput, t.Bigq, keyPair.publicKey, {0, 0},
                                 t.lvlb, t.levelsAvailableAfterBootstrap, 0, t.order);
                cc->EvalBootstrapKeyGen(keyPair.secretKey, numSlotsCKKS);
                cc->EvalMultKeyGen(keyPair.secretKey);
                std::vector<double> y(numSlotsCKKS, 0.5);
                // a level-0 ciphertext still includes the FLEXIBLEAUTOEXT extra modulus
                auto ctxt = cc->Encrypt(keyPair.publicKey, cc->MakeCKKSPackedPlaintext(y));
                EXPECT_THROW(cc->EvalFBT(ctxt, coeffint, t.PInput.GetMSB() - 1, t.Bigq, t.scaleTHI, 0, t.order),
                             OpenFHEException)
                    << failmsg << " FLEXIBLEAUTOEXT level-0 input not rejected";
                cc->ClearStaticMapsAndVectors();
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
TEST_P(UTCKKSRNS_FBT, CKKSRNS) {
    setupSignals();
    auto test = GetParam();

    switch (test.testCaseType) {
        case FBT_ARBLUT:
            UnitTest_ArbLUT(test, test.buildTestName());
            break;
        case FBT_SIGNDIGIT:
            UnitTest_SignDigit(test, test.buildTestName());
            break;
        case FBT_CONSECLEV:
            UnitTest_ConsecLevLUT(test, test.buildTestName());
            break;
        case FBT_MVB:
            UnitTest_MVB(test, test.buildTestName());
            break;
        case FBT_NOISE:
            UnitTest_Noise(test, test.buildTestName());
            break;
        case FBT_MVB_REUSE:
            UnitTest_MVBReuse(test, test.buildTestName());
            break;
        case FBT_INVALID:
            UnitTest_InvalidArgs(test, test.buildTestName());
            break;
        default:
            break;
    }
}

GTEST_ALLOW_UNINSTANTIATED_PARAMETERIZED_TEST(UTCKKSRNS_FBT);  // testCases.size() == 0 if NATIVEINT == 128
INSTANTIATE_TEST_SUITE_P(UnitTests, UTCKKSRNS_FBT, ::testing::ValuesIn(testCases), testName);
