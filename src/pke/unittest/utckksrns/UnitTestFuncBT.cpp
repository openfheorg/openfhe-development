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

#include <chrono>
#include <complex>
#include <iterator>
#include <numeric>
#include <ostream>
#include <vector>

// Define BENCH below to enable more fine-grained benchmarking.
// The benchmarks using SPARSE_TERNARY distribution correspond exactly to Tables 2 and A.3 in
// https://eprint.iacr.org/2024/1623.pdf, while the benchmarks using SPARSE_ENCAPSULATED are more
// secure and lead to slightly more efficient results as compared to those tables.
// #define BENCH

using namespace lbcrypto;

enum TEST_CASE_TYPE {
    FUNCBT_ARBLUT = 0,
    FUNCBT_SIGNDIGIT,
    FUNCBT_CONSECLEV,
    FUNCBT_MVB,
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
        case FUNCBT_CONSECLEV:
            typeName = "FUNCBT_CONSECLEV";
            break;
        case FUNCBT_MVB:
            typeName = "FUNCBT_MVB";
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
// TODO: finalize default values
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
static std::vector<TEST_CASE_FUNCBT> testCases = {
// Functional Bootstrapping does not support NATIVE_SIZE == 128
// For higher precision, consider using composite scaling instead
#if NATIVEINT != 128
#ifndef BENCH
    //    TestCaseType, Desc, QBFVInit, PInput, POutput,  Q, Bigq, scaleTHI, scaleStepTHI, order,   numSlots, ringDim, lvlsAfterBoot, lvlsBeforeBoot, dnum, lvlsComp, lvlBudget, SecretKeyDist
    {    FUNCBT_ARBLUT, "01",      Q60,      2,       2, Q33, Q33,        1, SCALESTEPTHI,     1,   SLOTFULL,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, SPARSE_TERNARY},
    {    FUNCBT_ARBLUT, "02",      Q60,      2,       2, Q33, Q33,        1, SCALESTEPTHI,     2,   SLOTFULL,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, SPARSE_TERNARY},
    {    FUNCBT_ARBLUT, "03",      Q60,      2,       2, Q33, Q33,        1, SCALESTEPTHI,     3,   SLOTFULL,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, SPARSE_TERNARY},
    {    FUNCBT_ARBLUT, "04",      Q60,      2,       2, Q33, Q33,        1, SCALESTEPTHI,     1, SLOTSPARSE,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, SPARSE_TERNARY},
    {    FUNCBT_ARBLUT, "05",      Q60,      2,       2, Q33, Q33,        1, SCALESTEPTHI,     2, SLOTSPARSE,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, SPARSE_TERNARY},
    {    FUNCBT_ARBLUT, "06",      Q60,      2,       2, Q33, Q33,        1, SCALESTEPTHI,     3, SLOTSPARSE,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, SPARSE_TERNARY},
    {    FUNCBT_ARBLUT, "07",      Q60, PINPUT, POUTPUT, Q47, Q47, SCALETHI, SCALESTEPTHI,     1,   SLOTFULL,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, SPARSE_TERNARY},
    {    FUNCBT_ARBLUT, "08",      Q60, PINPUT, POUTPUT, Q47, Q47, SCALETHI, SCALESTEPTHI,     2,   SLOTFULL,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, SPARSE_TERNARY},
    {    FUNCBT_ARBLUT, "09",      Q60, PINPUT, POUTPUT, Q47, Q47, SCALETHI, SCALESTEPTHI,     3,   SLOTFULL,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, SPARSE_TERNARY},
    {    FUNCBT_ARBLUT, "10",      Q60, PINPUT, POUTPUT, Q47, Q47, SCALETHI, SCALESTEPTHI,     1, SLOTSPARSE,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, SPARSE_TERNARY},
    {    FUNCBT_ARBLUT, "11",      Q60, PINPUT, POUTPUT, Q47, Q47, SCALETHI, SCALESTEPTHI,     2, SLOTSPARSE,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, SPARSE_TERNARY},
    {    FUNCBT_ARBLUT, "12",      Q60, PINPUT, POUTPUT, Q47, Q47, SCALETHI, SCALESTEPTHI,     3, SLOTSPARSE,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, SPARSE_TERNARY},
    { FUNCBT_SIGNDIGIT, "13",      Q71,    Q21,       2, Q56, Q36,        1,            1,     1,   SLOTFULL,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, SPARSE_TERNARY},
    { FUNCBT_SIGNDIGIT, "14",      Q71,    Q21,       2, Q55, Q35,        1,            1,     2,   SLOTFULL,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, SPARSE_TERNARY},
    { FUNCBT_SIGNDIGIT, "15",      Q71,    Q21,       2, Q56, Q36,        1,            1,     1, SLOTSPARSE,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, SPARSE_TERNARY},
    { FUNCBT_SIGNDIGIT, "16",      Q71,    Q21,       2, Q55, Q35,        1,            1,     2, SLOTSPARSE,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, SPARSE_TERNARY},
    { FUNCBT_CONSECLEV, "17",      Q60,      2,       2, Q35, Q35,        1, SCALESTEPTHI,     1,   SLOTFULL,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3,        1,  LVLBDFLT, SPARSE_TERNARY},
    { FUNCBT_CONSECLEV, "18",      Q60, PINPUT,  PINPUT, Q48, Q48, SCALETHI, SCALESTEPTHI,     1,   SLOTFULL,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3,        1,  LVLBDFLT, SPARSE_TERNARY},
    { FUNCBT_CONSECLEV, "19",      Q60,      2,       2, Q35, Q35,        1, SCALESTEPTHI,     1, SLOTSPARSE,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3,        1,  LVLBDFLT, SPARSE_TERNARY},
    { FUNCBT_CONSECLEV, "20",      Q60, PINPUT,  PINPUT, Q48, Q48, SCALETHI, SCALESTEPTHI,     1, SLOTSPARSE,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3,        1,  LVLBDFLT, SPARSE_TERNARY},
    {       FUNCBT_MVB, "21",      Q60,      2,       2, Q35, Q35,        1, SCALESTEPTHI,     1,   SLOTFULL,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3,        1,  LVLBDFLT, SPARSE_TERNARY},
    {       FUNCBT_MVB, "22",      Q60, PINPUT,  PINPUT, Q48, Q48, SCALETHI, SCALESTEPTHI,     1,   SLOTFULL,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3,        1,  LVLBDFLT, SPARSE_TERNARY},
    {       FUNCBT_MVB, "23",      Q60,      2,       2, Q35, Q35,        1, SCALESTEPTHI,     1, SLOTSPARSE,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3,        1,  LVLBDFLT, SPARSE_TERNARY},
    {       FUNCBT_MVB, "24",      Q60, PINPUT,  PINPUT, Q48, Q48, SCALETHI, SCALESTEPTHI,     1, SLOTSPARSE,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3,        1,  LVLBDFLT, SPARSE_TERNARY},
    //    TestCaseType,  Desc, QBFVInit, PInput, POutput,  Q, Bigq, scaleTHI, scaleStepTHI, order,   numSlots, ringDim, lvlsAfterBoot, lvlsBeforeBoot, dnum, lvlsComp, lvlBudget, SecretKeyDist
    {    FUNCBT_ARBLUT, "101",      Q60,      2,       2, Q33, Q33,        1, SCALESTEPTHI,     1,   SLOTFULL,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, SPARSE_ENCAPSULATED},
    {    FUNCBT_ARBLUT, "102",      Q60,      2,       2, Q33, Q33,        1, SCALESTEPTHI,     2,   SLOTFULL,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, SPARSE_ENCAPSULATED},
    {    FUNCBT_ARBLUT, "103",      Q60,      2,       2, Q33, Q33,        1, SCALESTEPTHI,     3,   SLOTFULL,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, SPARSE_ENCAPSULATED},
    {    FUNCBT_ARBLUT, "104",      Q60,      2,       2, Q33, Q33,        1, SCALESTEPTHI,     1, SLOTSPARSE,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, SPARSE_ENCAPSULATED},
    {    FUNCBT_ARBLUT, "105",      Q60,      2,       2, Q33, Q33,        1, SCALESTEPTHI,     2, SLOTSPARSE,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, SPARSE_ENCAPSULATED},
    {    FUNCBT_ARBLUT, "106",      Q60,      2,       2, Q33, Q33,        1, SCALESTEPTHI,     3, SLOTSPARSE,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, SPARSE_ENCAPSULATED},
    {    FUNCBT_ARBLUT, "107",      Q60, PINPUT, POUTPUT, Q47, Q47, SCALETHI, SCALESTEPTHI,     1,   SLOTFULL,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, SPARSE_ENCAPSULATED},
    {    FUNCBT_ARBLUT, "108",      Q60, PINPUT, POUTPUT, Q47, Q47, SCALETHI, SCALESTEPTHI,     2,   SLOTFULL,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, SPARSE_ENCAPSULATED},
    {    FUNCBT_ARBLUT, "109",      Q60, PINPUT, POUTPUT, Q47, Q47, SCALETHI, SCALESTEPTHI,     3,   SLOTFULL,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, SPARSE_ENCAPSULATED},
    {    FUNCBT_ARBLUT, "110",      Q60, PINPUT, POUTPUT, Q47, Q47, SCALETHI, SCALESTEPTHI,     1, SLOTSPARSE,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, SPARSE_ENCAPSULATED},
    {    FUNCBT_ARBLUT, "111",      Q60, PINPUT, POUTPUT, Q47, Q47, SCALETHI, SCALESTEPTHI,     2, SLOTSPARSE,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, SPARSE_ENCAPSULATED},
    {    FUNCBT_ARBLUT, "112",      Q60, PINPUT, POUTPUT, Q47, Q47, SCALETHI, SCALESTEPTHI,     3, SLOTSPARSE,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, SPARSE_ENCAPSULATED},
    { FUNCBT_SIGNDIGIT, "113",      Q71,    Q21,       2, Q56, Q36,        1,            1,     1,   SLOTFULL,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, SPARSE_ENCAPSULATED},
    { FUNCBT_SIGNDIGIT, "114",      Q71,    Q21,       2, Q55, Q35,        1,            1,     2,   SLOTFULL,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, SPARSE_ENCAPSULATED},
    { FUNCBT_SIGNDIGIT, "115",      Q71,    Q21,       2, Q56, Q36,        1,            1,     1, SLOTSPARSE,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, SPARSE_ENCAPSULATED},
    { FUNCBT_SIGNDIGIT, "116",      Q71,    Q21,       2, Q55, Q35,        1,            1,     2, SLOTSPARSE,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,  LVLBDFLT, SPARSE_ENCAPSULATED},
    { FUNCBT_CONSECLEV, "117",      Q60,      2,       2, Q35, Q35,        1, SCALESTEPTHI,     1,   SLOTFULL,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3,        1,  LVLBDFLT, SPARSE_ENCAPSULATED},
    { FUNCBT_CONSECLEV, "118",      Q60, PINPUT,  PINPUT, Q48, Q48, SCALETHI, SCALESTEPTHI,     1,   SLOTFULL,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3,        1,  LVLBDFLT, SPARSE_ENCAPSULATED},
    { FUNCBT_CONSECLEV, "119",      Q60,      2,       2, Q35, Q35,        1, SCALESTEPTHI,     1, SLOTSPARSE,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3,        1,  LVLBDFLT, SPARSE_ENCAPSULATED},
    { FUNCBT_CONSECLEV, "120",      Q60, PINPUT,  PINPUT, Q48, Q48, SCALETHI, SCALESTEPTHI,     1, SLOTSPARSE,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3,        1,  LVLBDFLT, SPARSE_ENCAPSULATED},
    {       FUNCBT_MVB, "121",      Q60,      2,       2, Q35, Q35,        1, SCALESTEPTHI,     1,   SLOTFULL,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3,        1,  LVLBDFLT, SPARSE_ENCAPSULATED},
    {       FUNCBT_MVB, "122",      Q60, PINPUT,  PINPUT, Q48, Q48, SCALETHI, SCALESTEPTHI,     1,   SLOTFULL,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3,        1,  LVLBDFLT, SPARSE_ENCAPSULATED},
    {       FUNCBT_MVB, "123",      Q60,      2,       2, Q35, Q35,        1, SCALESTEPTHI,     1, SLOTSPARSE,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3,        1,  LVLBDFLT, SPARSE_ENCAPSULATED},
    {       FUNCBT_MVB, "124",      Q60, PINPUT,  PINPUT, Q48, Q48, SCALETHI, SCALESTEPTHI,     1, SLOTSPARSE,  RINGDM,     AFTERBOOT,     BEFOREBOOT,    3,        1,  LVLBDFLT, SPARSE_ENCAPSULATED},
#else
    //    TestCaseType, Desc, QBFVInit, PInput, POutput,  Q, Bigq, scaleTHI, scaleStepTHI, order, numSlots, ringDim, lvlsAfterBoot, lvlsBeforeBoot, dnum, lvlsComp, lvlBudget, SecretKeyDist
    {    FUNCBT_ARBLUT, "01",      Q60,      2,       2, Q33, Q33,        1, SCALESTEPTHI,     1,  1 << 15, 1 << 15,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,    {3, 3}, SPARSE_TERNARY},
    {    FUNCBT_ARBLUT, "02",      Q60,      2,       2, Q33, Q33,        1, SCALESTEPTHI,     2,  1 << 15, 1 << 15,     AFTERBOOT,     BEFOREBOOT,    7, LVLSCOMP,    {3, 3}, SPARSE_TERNARY},
    {    FUNCBT_ARBLUT, "03",      Q60,      2,       2, Q33, Q33,        1, SCALESTEPTHI,     3,  1 << 15, 1 << 15,     AFTERBOOT,     BEFOREBOOT,    7, LVLSCOMP,    {3, 3}, SPARSE_TERNARY},
    {    FUNCBT_ARBLUT, "04",      Q60,      4,       4, Q35, Q35,       16, SCALESTEPTHI,     1,  1 << 16, 1 << 16,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,    {4, 4}, SPARSE_TERNARY},
    {    FUNCBT_ARBLUT, "05",      Q60,      4,       4, Q35, Q35,       16, SCALESTEPTHI,     2,  1 << 16, 1 << 16,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,    {4, 4}, SPARSE_TERNARY},
    {    FUNCBT_ARBLUT, "06",      Q60,      4,       4, Q35, Q35,       16, SCALESTEPTHI,     3,  1 << 16, 1 << 16,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,    {4, 4}, SPARSE_TERNARY},
    {    FUNCBT_ARBLUT, "07",      Q60,      8,       8, Q37, Q37,       16, SCALESTEPTHI,     1,  1 << 16, 1 << 16,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,    {4, 4}, SPARSE_TERNARY},
    {    FUNCBT_ARBLUT, "08",      Q60,      8,       8, Q37, Q37,       16, SCALESTEPTHI,     2,  1 << 16, 1 << 16,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,    {4, 4}, SPARSE_TERNARY},
    {    FUNCBT_ARBLUT, "09",      Q60,      8,       8, Q37, Q37,       16, SCALESTEPTHI,     3,  1 << 16, 1 << 16,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,    {4, 4}, SPARSE_TERNARY},
    {    FUNCBT_ARBLUT, "10",      Q60,     16,      16, Q38, Q38,       32, SCALESTEPTHI,     1,  1 << 16, 1 << 16,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,    {4, 4}, SPARSE_TERNARY},
    {    FUNCBT_ARBLUT, "11",      Q60,     16,      16, Q38, Q38,       32, SCALESTEPTHI,     2,  1 << 16, 1 << 16,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,    {4, 4}, SPARSE_TERNARY},
    {    FUNCBT_ARBLUT, "12",      Q60,     16,      16, Q38, Q38,       32, SCALESTEPTHI,     3,  1 << 16, 1 << 16,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,    {4, 4}, SPARSE_TERNARY},
    {    FUNCBT_ARBLUT, "13",      Q60, PINPUT, POUTPUT, Q47, Q47, SCALETHI, SCALESTEPTHI,     1,  1 << 16, 1 << 16,     AFTERBOOT,     BEFOREBOOT,    4, LVLSCOMP,    {3, 3}, SPARSE_TERNARY},
    {    FUNCBT_ARBLUT, "14",      Q60, PINPUT, POUTPUT, Q47, Q47, SCALETHI, SCALESTEPTHI,     2,  1 << 16, 1 << 16,     AFTERBOOT,     BEFOREBOOT,    4, LVLSCOMP,    {3, 3}, SPARSE_TERNARY},
    {    FUNCBT_ARBLUT, "15",      Q60, PINPUT, POUTPUT, Q47, Q47, SCALETHI, SCALESTEPTHI,     3,  1 << 16, 1 << 16,     AFTERBOOT,     BEFOREBOOT,    5, LVLSCOMP,    {3, 3}, SPARSE_TERNARY},
    {    FUNCBT_ARBLUT, "16",      Q60,    512,     512, Q48, Q48,       45, SCALESTEPTHI,     1,  1 << 16, 1 << 16,     AFTERBOOT,     BEFOREBOOT,    5, LVLSCOMP,    {3, 3}, SPARSE_TERNARY},
    {    FUNCBT_ARBLUT, "17",      Q60,    512,     512, Q48, Q48,       45, SCALESTEPTHI,     2,  1 << 16, 1 << 16,     AFTERBOOT,     BEFOREBOOT,    5, LVLSCOMP,    {3, 3}, SPARSE_TERNARY},
    {    FUNCBT_ARBLUT, "18",      Q60,    512,     512, Q48, Q48,       45, SCALESTEPTHI,     3,  1 << 16, 1 << 16,     AFTERBOOT,     BEFOREBOOT,    7, LVLSCOMP,    {3, 3}, SPARSE_TERNARY},
    {    FUNCBT_ARBLUT, "19",      Q80,   4096,    4096, Q55, Q55,     2000, SCALESTEPTHI,     1,  1 << 17, 1 << 17,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,    {4, 4}, SPARSE_TERNARY},
    {    FUNCBT_ARBLUT, "20",      Q80,   4096,    4096, Q55, Q55,     2000, SCALESTEPTHI,     2,  1 << 17, 1 << 17,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,    {4, 4}, SPARSE_TERNARY},
    {    FUNCBT_ARBLUT, "21",      Q80,   4096,    4096, Q55, Q55,     2000, SCALESTEPTHI,     3,  1 << 17, 1 << 17,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,    {4, 4}, SPARSE_TERNARY},
    {    FUNCBT_ARBLUT, "22",      Q80,  16384,   16384, Q58, Q58,     8000, SCALESTEPTHI,     1,  1 << 17, 1 << 17,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,    {4, 4}, SPARSE_TERNARY},
    {    FUNCBT_ARBLUT, "23",      Q80,  16384,   16384, Q58, Q58,     8000, SCALESTEPTHI,     2,  1 << 17, 1 << 17,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,    {4, 4}, SPARSE_TERNARY},
    {    FUNCBT_ARBLUT, "24",      Q80,  16384,   16384, Q58, Q58,     8000, SCALESTEPTHI,     3,  1 << 17, 1 << 17,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,    {4, 4}, SPARSE_TERNARY},
    { FUNCBT_SIGNDIGIT, "25",      Q60,   4096,       2, Q46, Q35,        1,            1,     1,  1 << 16, 1 << 16,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,    {4, 4}, SPARSE_TERNARY},
    { FUNCBT_SIGNDIGIT, "27",      Q60,   4096,       4, Q45, Q35,       10,            2,     1,  1 << 16, 1 << 16,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,    {4, 4}, SPARSE_TERNARY},
    { FUNCBT_SIGNDIGIT, "29",      Q60,   4096,       8, Q46, Q37,       16,            4,     1,  1 << 16, 1 << 16,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,    {4, 4}, SPARSE_TERNARY},
    { FUNCBT_SIGNDIGIT, "31",      Q60,   4096,      16, Q48, Q40,       32,            8,     1,  1 << 16, 1 << 16,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,    {4, 4}, SPARSE_TERNARY},
    { FUNCBT_SIGNDIGIT, "33",      Q60,   4096,      64, Q48, Q42,      128,           32,     1,  1 << 16, 1 << 16,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,    {4, 4}, SPARSE_TERNARY},
    { FUNCBT_SIGNDIGIT, "35",      Q71,    Q21,       2, Q56, Q36,        1,            1,     1,  1 << 16, 1 << 16,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,    {4, 4}, SPARSE_TERNARY},
    { FUNCBT_SIGNDIGIT, "37",      Q71,    Q21,       8, Q55, Q37,       16,            4,     1,  1 << 16, 1 << 16,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,    {4, 4}, SPARSE_TERNARY},
    { FUNCBT_SIGNDIGIT, "39",      Q71,    Q21,     128, Q57, Q43,      256,           16,     1,  1 << 16, 1 << 16,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,    {4, 4}, SPARSE_TERNARY},
    { FUNCBT_SIGNDIGIT, "41",      Q80,    Q32,     256, Q71, Q47,      256,           16,     1,  1 << 16, 1 << 16,     AFTERBOOT,     BEFOREBOOT,    4, LVLSCOMP,    {3, 3}, SPARSE_TERNARY},
    //    TestCaseType,  Desc, QBFVInit, PInput, POutput,  Q, Bigq, scaleTHI, scaleStepTHI, order, numSlots, ringDim, lvlsAfterBoot, lvlsBeforeBoot, dnum, lvlsComp, lvlBudget, SecretKeyDist
    {    FUNCBT_ARBLUT, "101",      Q60,      2,       2, Q33, Q33,        1, SCALESTEPTHI,     1,  1 << 15, 1 << 15,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,    {3, 3}, SPARSE_ENCAPSULATED},
    {    FUNCBT_ARBLUT, "102",      Q60,      2,       2, Q33, Q33,        1, SCALESTEPTHI,     2,  1 << 15, 1 << 15,     AFTERBOOT,     BEFOREBOOT,    7, LVLSCOMP,    {3, 3}, SPARSE_ENCAPSULATED},
    {    FUNCBT_ARBLUT, "103",      Q60,      2,       2, Q33, Q33,        1, SCALESTEPTHI,     3,  1 << 15, 1 << 15,     AFTERBOOT,     BEFOREBOOT,    7, LVLSCOMP,    {3, 3}, SPARSE_ENCAPSULATED},
    {    FUNCBT_ARBLUT, "104",      Q60,      4,       4, Q35, Q35,       16, SCALESTEPTHI,     1,  1 << 16, 1 << 16,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,    {4, 4}, SPARSE_ENCAPSULATED},
    {    FUNCBT_ARBLUT, "105",      Q60,      4,       4, Q35, Q35,       16, SCALESTEPTHI,     2,  1 << 16, 1 << 16,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,    {4, 4}, SPARSE_ENCAPSULATED},
    {    FUNCBT_ARBLUT, "106",      Q60,      4,       4, Q35, Q35,       16, SCALESTEPTHI,     3,  1 << 16, 1 << 16,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,    {4, 4}, SPARSE_ENCAPSULATED},
    {    FUNCBT_ARBLUT, "107",      Q60,      8,       8, Q37, Q37,       16, SCALESTEPTHI,     1,  1 << 16, 1 << 16,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,    {4, 4}, SPARSE_ENCAPSULATED},
    {    FUNCBT_ARBLUT, "108",      Q60,      8,       8, Q37, Q37,       16, SCALESTEPTHI,     2,  1 << 16, 1 << 16,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,    {4, 4}, SPARSE_ENCAPSULATED},
    {    FUNCBT_ARBLUT, "109",      Q60,      8,       8, Q37, Q37,       16, SCALESTEPTHI,     3,  1 << 16, 1 << 16,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,    {4, 4}, SPARSE_ENCAPSULATED},
    {    FUNCBT_ARBLUT, "110",      Q60,     16,      16, Q38, Q38,       32, SCALESTEPTHI,     1,  1 << 16, 1 << 16,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,    {4, 4}, SPARSE_ENCAPSULATED},
    {    FUNCBT_ARBLUT, "111",      Q60,     16,      16, Q38, Q38,       32, SCALESTEPTHI,     2,  1 << 16, 1 << 16,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,    {4, 4}, SPARSE_ENCAPSULATED},
    {    FUNCBT_ARBLUT, "112",      Q60,     16,      16, Q38, Q38,       32, SCALESTEPTHI,     3,  1 << 16, 1 << 16,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,    {4, 4}, SPARSE_ENCAPSULATED},
    {    FUNCBT_ARBLUT, "113",      Q60, PINPUT, POUTPUT, Q47, Q47, SCALETHI, SCALESTEPTHI,     1,  1 << 16, 1 << 16,     AFTERBOOT,     BEFOREBOOT,    4, LVLSCOMP,    {3, 3}, SPARSE_ENCAPSULATED},
    {    FUNCBT_ARBLUT, "114",      Q60, PINPUT, POUTPUT, Q47, Q47, SCALETHI, SCALESTEPTHI,     2,  1 << 16, 1 << 16,     AFTERBOOT,     BEFOREBOOT,    4, LVLSCOMP,    {3, 3}, SPARSE_ENCAPSULATED},
    {    FUNCBT_ARBLUT, "115",      Q60, PINPUT, POUTPUT, Q47, Q47, SCALETHI, SCALESTEPTHI,     3,  1 << 16, 1 << 16,     AFTERBOOT,     BEFOREBOOT,    5, LVLSCOMP,    {3, 3}, SPARSE_ENCAPSULATED},
    {    FUNCBT_ARBLUT, "116",      Q60,    512,     512, Q48, Q48,       45, SCALESTEPTHI,     1,  1 << 16, 1 << 16,     AFTERBOOT,     BEFOREBOOT,    5, LVLSCOMP,    {3, 3}, SPARSE_ENCAPSULATED},
    {    FUNCBT_ARBLUT, "117",      Q60,    512,     512, Q48, Q48,       45, SCALESTEPTHI,     2,  1 << 16, 1 << 16,     AFTERBOOT,     BEFOREBOOT,    5, LVLSCOMP,    {3, 3}, SPARSE_ENCAPSULATED},
    {    FUNCBT_ARBLUT, "118",      Q60,    512,     512, Q48, Q48,       45, SCALESTEPTHI,     3,  1 << 16, 1 << 16,     AFTERBOOT,     BEFOREBOOT,    7, LVLSCOMP,    {3, 3}, SPARSE_ENCAPSULATED},
    {    FUNCBT_ARBLUT, "119",      Q80,   4096,    4096, Q55, Q55,     2000, SCALESTEPTHI,     1,  1 << 17, 1 << 17,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,    {4, 4}, SPARSE_ENCAPSULATED},
    {    FUNCBT_ARBLUT, "120",      Q80,   4096,    4096, Q55, Q55,     2000, SCALESTEPTHI,     2,  1 << 17, 1 << 17,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,    {4, 4}, SPARSE_ENCAPSULATED},
    {    FUNCBT_ARBLUT, "121",      Q80,   4096,    4096, Q55, Q55,     2000, SCALESTEPTHI,     3,  1 << 17, 1 << 17,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,    {4, 4}, SPARSE_ENCAPSULATED},
    {    FUNCBT_ARBLUT, "122",      Q80,  16384,   16384, Q59, Q59,     8000, SCALESTEPTHI,     1,  1 << 17, 1 << 17,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,    {4, 4}, SPARSE_ENCAPSULATED},
    {    FUNCBT_ARBLUT, "123",      Q80,  16384,   16384, Q59, Q59,     8000, SCALESTEPTHI,     2,  1 << 17, 1 << 17,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,    {4, 4}, SPARSE_ENCAPSULATED},
    {    FUNCBT_ARBLUT, "124",      Q80,  16384,   16384, Q59, Q59,     8000, SCALESTEPTHI,     3,  1 << 17, 1 << 17,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,    {4, 4}, SPARSE_ENCAPSULATED},
    { FUNCBT_SIGNDIGIT, "125",      Q60,   4096,       2, Q46, Q35,        1,            1,     1,  1 << 16, 1 << 16,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,    {4, 4}, SPARSE_ENCAPSULATED},
    { FUNCBT_SIGNDIGIT, "127",      Q60,   4096,       4, Q45, Q35,       10,            2,     1,  1 << 16, 1 << 16,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,    {4, 4}, SPARSE_ENCAPSULATED},
    { FUNCBT_SIGNDIGIT, "129",      Q60,   4096,       8, Q46, Q37,       16,            4,     1,  1 << 16, 1 << 16,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,    {4, 4}, SPARSE_ENCAPSULATED},
    { FUNCBT_SIGNDIGIT, "131",      Q60,   4096,      16, Q48, Q40,       32,            8,     1,  1 << 16, 1 << 16,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,    {4, 4}, SPARSE_ENCAPSULATED},
    { FUNCBT_SIGNDIGIT, "133",      Q60,   4096,      64, Q48, Q42,      128,           32,     1,  1 << 16, 1 << 16,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,    {4, 4}, SPARSE_ENCAPSULATED},
    { FUNCBT_SIGNDIGIT, "135",      Q71,    Q21,       2, Q56, Q36,        1,            1,     1,  1 << 16, 1 << 16,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,    {4, 4}, SPARSE_ENCAPSULATED},
    { FUNCBT_SIGNDIGIT, "137",      Q71,    Q21,       8, Q55, Q37,       16,            4,     1,  1 << 16, 1 << 16,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,    {4, 4}, SPARSE_ENCAPSULATED},
    { FUNCBT_SIGNDIGIT, "139",      Q71,    Q21,     128, Q57, Q43,      256,           16,     1,  1 << 16, 1 << 16,     AFTERBOOT,     BEFOREBOOT,    3, LVLSCOMP,    {4, 4}, SPARSE_ENCAPSULATED},
    { FUNCBT_SIGNDIGIT, "141",      Q80,    Q32,     256, Q71, Q47,      256,           16,     1,  1 << 16, 1 << 16,     AFTERBOOT,     BEFOREBOOT,    4, LVLSCOMP,    {3, 3}, SPARSE_ENCAPSULATED},
#endif
#endif
};
// clang-format on

class UTCKKSRNS_FUNCBT : public ::testing::TestWithParam<TEST_CASE_FUNCBT> {
protected:
    void SetUp(){};

    void TearDown() {
        CryptoContextFactory<DCRTPoly>::ReleaseAllContexts();
    }

    void UnitTest_ArbLUT(TEST_CASE_FUNCBT t, const std::string& failmsg = std::string()) {
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
                x = Fillint64(x, t.numSlots);

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

            uint32_t dcrtBits = t.Bigq.GetMSB() - 1;
            uint32_t firstMod = t.Bigq.GetMSB() - 1;
            CCParams<CryptoContextCKKSRNS> parameters;
            parameters.SetSecretKeyDist(t.skd);
            parameters.SetSecurityLevel(HEStd_NotSet);
            parameters.SetScalingModSize(dcrtBits);
            parameters.SetScalingTechnique(FIXEDMANUAL);
            parameters.SetFirstModSize(firstMod);
            parameters.SetNumLargeDigits(t.dnum);
            parameters.SetBatchSize(numSlotsCKKS);
            parameters.SetRingDim(t.ringDim);
            uint32_t depth = t.levelsAvailableAfterBootstrap + t.lvlb[0] + t.lvlb[1] + 2;

            if (binaryLUT)
                depth += FHECKKSRNS::AdjustDepthFuncBT(coeffint, t.PInput, t.order, t.skd);
            else
                depth += FHECKKSRNS::AdjustDepthFuncBT(coeffcomp, t.PInput, t.order, t.skd);

            parameters.SetMultiplicativeDepth(depth);

            auto cc = GenCryptoContext(parameters);
            cc->Enable(PKE);
            cc->Enable(KEYSWITCH);
            cc->Enable(LEVELEDSHE);
            cc->Enable(ADVANCEDSHE);
            cc->Enable(FHE);

            auto keyPair = cc->KeyGen();

            BigInteger QPrime = keyPair.publicKey->GetPublicElements()[0].GetParams()->GetParams()[0]->GetModulus();
            uint32_t cnt      = 1;
            auto levels       = t.levelsAvailableAfterBootstrap;
            while (levels > 0) {
                QPrime *= keyPair.publicKey->GetPublicElements()[0].GetParams()->GetParams()[cnt]->GetModulus();
                levels--;
                cnt++;
            }
            double scaleMod =
                QPrime.ConvertToLongDouble() / (t.Bigq.ConvertToLongDouble() * t.POutput.ConvertToDouble());

#ifdef BENCH
            stop = std::chrono::high_resolution_clock::now();
            std::cerr << "Cryptocontext Generation: " << std::chrono::duration<double>(stop - start).count() << " s\n";
            start = std::chrono::high_resolution_clock::now();
#endif

            if (binaryLUT)
                cc->EvalFuncBTSetup(numSlotsCKKS, t.PInput, coeffint, {0, 0}, t.lvlb, scaleMod, 0, t.order);
            else
                cc->EvalFuncBTSetup(numSlotsCKKS, t.PInput, coeffcomp, {0, 0}, t.lvlb, scaleMod, 0, t.order);

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

            auto ep =
                SchemeletRLWEMP::GetElementParams(keyPair.secretKey, depth - (t.levelsAvailableBeforeBootstrap > 0));

            auto ctxtBFV = SchemeletRLWEMP::EncryptCoeff(x, t.QBFVInit, t.PInput, keyPair.secretKey, ep);

#ifdef BENCH
            stop = std::chrono::high_resolution_clock::now();
            std::cerr << "Coefficient Encryption: " << std::chrono::duration<double>(stop - start).count() << " s\n";
            start = std::chrono::high_resolution_clock::now();
#endif

            SchemeletRLWEMP::ModSwitch(ctxtBFV, t.Q, t.QBFVInit);

            auto ctxt = SchemeletRLWEMP::convert(*cc, ctxtBFV, keyPair.publicKey, t.Bigq, numSlotsCKKS,
                                                 depth - (t.levelsAvailableBeforeBootstrap > 0));

            Ciphertext<DCRTPoly> ctxtAfterFuncBT;
            if (binaryLUT)
                ctxtAfterFuncBT =
                    cc->EvalFuncBT(ctxt, coeffint, t.PInput.GetMSB() - 1, ep->GetModulus(), t.scaleTHI, 0, t.order);
            else
                ctxtAfterFuncBT =
                    cc->EvalFuncBT(ctxt, coeffcomp, t.PInput.GetMSB() - 1, ep->GetModulus(), t.scaleTHI, 0, t.order);

            if (QPrime != ctxtAfterFuncBT->GetElements()[0].GetModulus())
                OPENFHE_THROW("The ciphertext modulus after bootstrapping is not as expected.");

            auto polys = SchemeletRLWEMP::convert(ctxtAfterFuncBT, t.Q, QPrime);

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
            std::transform(x.begin(), x.end(), exact.begin(), [&](const int64_t& elem) {
                return (f(elem) > t.POutput.ConvertToDouble() / 2.) ? f(elem) - t.POutput.ConvertToInt() : f(elem);
            });

            std::transform(exact.begin(), exact.end(), computed.begin(), exact.begin(), std::minus<int64_t>());
            std::transform(exact.begin(), exact.end(), exact.begin(),
                           [&](const int64_t& elem) { return (std::abs(elem)) % (t.POutput.ConvertToInt()); });
            auto max_error_it = std::max_element(exact.begin(), exact.end());
            // std::cerr << "\n=======Error count: " << std::accumulate(exact.begin(), exact.end(), 0) << "\n";
            // std::cerr << "\n=======Max absolute error: " << *max_error_it << "\n";
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
#ifdef BENCH
            auto start = std::chrono::high_resolution_clock::now();
#endif
            bool flagSP = (t.numSlots <= t.ringDim / 2);  // sparse packing
            // t.numSlots represents number of values to be encrypted in BFV. If same as ring dimension, CKKS slots is halved.
            auto numSlotsCKKS = flagSP ? t.numSlots : t.numSlots / 2;

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
            if (x.size() < t.numSlots)
                x = Fillint64(x, t.numSlots);

            auto exact(x);
            std::transform(x.begin(), x.end(), exact.begin(),
                           [&](const int64_t& elem) { return (elem >= PInput.ConvertToDouble() / 2.); });

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

            uint32_t dcrtBits = t.Bigq.GetMSB() - 1;
            uint32_t firstMod = t.Bigq.GetMSB() - 1;

            CCParams<CryptoContextCKKSRNS> parameters;
            parameters.SetSecretKeyDist(t.skd);
            parameters.SetSecurityLevel(HEStd_NotSet);
            parameters.SetScalingModSize(dcrtBits);
            parameters.SetScalingTechnique(FIXEDMANUAL);
            parameters.SetFirstModSize(firstMod);
            parameters.SetNumLargeDigits(t.dnum);
            parameters.SetBatchSize(numSlotsCKKS);
            parameters.SetRingDim(t.ringDim);

            uint32_t depth = t.levelsAvailableAfterBootstrap + t.lvlb[0] + t.lvlb[1] + 2;

            if (binaryLUT)
                depth += FHECKKSRNS::AdjustDepthFuncBT(coeffintMod, t.POutput, t.order, t.skd);
            else
                depth += FHECKKSRNS::AdjustDepthFuncBT(coeffcompMod, t.POutput, t.order, t.skd);

            parameters.SetMultiplicativeDepth(depth);

            auto cc = GenCryptoContext(parameters);
            cc->Enable(PKE);
            cc->Enable(KEYSWITCH);
            cc->Enable(LEVELEDSHE);
            cc->Enable(ADVANCEDSHE);
            cc->Enable(FHE);

            auto keyPair = cc->KeyGen();

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

#ifdef BENCH
            stop = std::chrono::high_resolution_clock::now();
            std::cerr << "Cryptocontext Generation: " << std::chrono::duration<double>(stop - start).count() << " s\n";
            start = std::chrono::high_resolution_clock::now();
#endif

            if (binaryLUT)
                cc->EvalFuncBTSetup(numSlotsCKKS, t.POutput, coeffintMod, {0, 0}, t.lvlb, scaleOutput, 0, t.order);
            else
                cc->EvalFuncBTSetup(numSlotsCKKS, t.POutput, coeffcompMod, {0, 0}, t.lvlb, scaleOutput, 0, t.order);

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

            auto ep =
                SchemeletRLWEMP::GetElementParams(keyPair.secretKey, depth - (t.levelsAvailableBeforeBootstrap > 0));

            auto ctxtBFV = SchemeletRLWEMP::EncryptCoeff(x, t.QBFVInit, PInput, keyPair.secretKey, ep);

#ifdef BENCH
            stop = std::chrono::high_resolution_clock::now();
            std::cerr << "Coefficient Encryption: " << std::chrono::duration<double>(stop - start).count() << " s\n";
            start = std::chrono::high_resolution_clock::now();
#endif

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

            double scaleTHI     = t.scaleTHI;
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

                auto ctxt = SchemeletRLWEMP::convert(*cc, encryptedDigit, keyPair.publicKey, t.Bigq, numSlotsCKKS,
                                                     depth - (t.levelsAvailableBeforeBootstrap > 0));

                // Bootstrap the digit.
                Ciphertext<DCRTPoly> ctxtAfterFuncBT;
                if (binaryLUT)
                    ctxtAfterFuncBT =
                        cc->EvalFuncBT(ctxt, coeffint, t.POutput.GetMSB() - 1, ep->GetModulus(),
                                       pOrig.ConvertToDouble() / pBFVDouble * scaleTHI, levelsToDrop, t.order);
                else
                    ctxtAfterFuncBT =
                        cc->EvalFuncBT(ctxt, coeffcomp, t.POutput.GetMSB() - 1, ep->GetModulus(),
                                       pOrig.ConvertToDouble() / pBFVDouble * scaleTHI, levelsToDrop, t.order);

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

                if ((t.POutput.ConvertToInt() == 2 && QBFVDouble <= qDigitDouble) || step) {
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
                                   [&](const int64_t& elem) { return (std::abs(elem)) % (pOrig.ConvertToInt()); });
                    auto max_error_it = std::max_element(exact.begin(), exact.end());
                    // std::cerr << "\n=======Error count: " << std::accumulate(exact.begin(), exact.end(), 0) << "\n";
                    // std::cerr << "\n=======Max absolute error: " << *max_error_it << "\n";
                    checkEquality((*max_error_it), int64_t(0), 0.0001, failmsg + " MP sign evaluation fails");
                }

                go = QBFVDouble > qDigitDouble;

                if (t.POutput.ConvertToInt() > 2 && !go && !step) {
                    if (!binaryLUT)
                        coeffcomp = coeffcompStep;
                    scaleTHI = t.scaleStepTHI;
                    step     = true;
                    go       = true;
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

    void UnitTest_ConsecLevLUT(TEST_CASE_FUNCBT t, const std::string& failmsg = std::string()) {
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
                (t.PInput.ConvertToInt<int64_t>() / 2), (t.PInput.ConvertToInt<int64_t>() / 2) + 1, 0, 3, 16, 33, 64,
                (t.PInput.ConvertToInt<int64_t>() - 1)};
            if (x.size() < t.numSlots)
                x = Fillint64(x, t.numSlots);

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

            uint32_t dcrtBits = t.Bigq.GetMSB() - 1;
            uint32_t firstMod = t.Bigq.GetMSB() - 1;
            CCParams<CryptoContextCKKSRNS> parameters;
            parameters.SetSecretKeyDist(t.skd);
            parameters.SetSecurityLevel(HEStd_NotSet);
            parameters.SetScalingModSize(dcrtBits);
            parameters.SetScalingTechnique(FIXEDMANUAL);
            parameters.SetFirstModSize(firstMod);
            parameters.SetNumLargeDigits(t.dnum);
            parameters.SetBatchSize(numSlotsCKKS);
            parameters.SetRingDim(t.ringDim);
            uint32_t depth = t.levelsAvailableAfterBootstrap + t.lvlb[0] + t.lvlb[1] + 2 + t.levelsComputation;

            if (binaryLUT)
                depth += FHECKKSRNS::AdjustDepthFuncBT(coeffint, t.PInput, t.order, t.skd);
            else
                depth += FHECKKSRNS::AdjustDepthFuncBT(coeffcomp, t.PInput, t.order, t.skd);

            parameters.SetMultiplicativeDepth(depth);

            auto cc = GenCryptoContext(parameters);
            cc->Enable(PKE);
            cc->Enable(KEYSWITCH);
            cc->Enable(LEVELEDSHE);
            cc->Enable(ADVANCEDSHE);
            cc->Enable(FHE);

            auto keyPair = cc->KeyGen();

            BigInteger QPrime = keyPair.publicKey->GetPublicElements()[0].GetParams()->GetParams()[0]->GetModulus();
            uint32_t cnt      = 1;
            auto levels       = t.levelsAvailableAfterBootstrap;
            while (levels > 0) {
                QPrime *= keyPair.publicKey->GetPublicElements()[0].GetParams()->GetParams()[cnt]->GetModulus();
                levels--;
                cnt++;
            }
            double scaleMod =
                QPrime.ConvertToLongDouble() / (t.Bigq.ConvertToLongDouble() * t.POutput.ConvertToDouble());

#ifdef BENCH
            stop = std::chrono::high_resolution_clock::now();
            std::cerr << "Cryptocontext Generation: " << std::chrono::duration<double>(stop - start).count() << " s\n";
            start = std::chrono::high_resolution_clock::now();
#endif

            if (binaryLUT)
                cc->EvalFuncBTSetup(numSlotsCKKS, t.PInput, coeffint, {0, 0}, t.lvlb, scaleMod, t.levelsComputation,
                                    t.order);
            else
                cc->EvalFuncBTSetup(numSlotsCKKS, t.PInput, coeffcomp, {0, 0}, t.lvlb, scaleMod, t.levelsComputation,
                                    t.order);

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

            std::vector<double> mask_real = FillDouble(std::vector<double>({1, 1, 1, 1, 0, 0, 0, 0}), t.numSlots);

            // Note that the corresponding plaintext mask for full packing can be just real, as real times complex multiplies both real and imaginary parts
            Plaintext ptxt_mask = cc->MakeCKKSPackedPlaintext(
                FillDouble(std::vector<double>({1, 1, 1, 1, 0, 0, 0, 0}), numSlotsCKKS), 1,
                depth - t.lvlb[1] - t.levelsAvailableAfterBootstrap - t.levelsComputation, nullptr, numSlotsCKKS);

            auto ep =
                SchemeletRLWEMP::GetElementParams(keyPair.secretKey, depth - (t.levelsAvailableBeforeBootstrap > 0));

            // Set bitReverse true to be able to perform correct rotations in CKKS
            auto ctxtBFV = SchemeletRLWEMP::EncryptCoeff(x, t.QBFVInit, t.PInput, keyPair.secretKey, ep, flagBR);

#ifdef BENCH
            stop = std::chrono::high_resolution_clock::now();
            std::cerr << "Coefficient Encryption: " << std::chrono::duration<double>(stop - start).count() << " s\n";
            start = std::chrono::high_resolution_clock::now();
#endif

            SchemeletRLWEMP::ModSwitch(ctxtBFV, t.Q, t.QBFVInit);

            auto ctxt = SchemeletRLWEMP::convert(*cc, ctxtBFV, keyPair.publicKey, t.Bigq, numSlotsCKKS,
                                                 depth - (t.levelsAvailableBeforeBootstrap > 0));

            // Apply LUT and remain in slots encodings.
            Ciphertext<DCRTPoly> ctxtAfterFuncBT;
            if (binaryLUT)
                ctxtAfterFuncBT =
                    cc->EvalFuncBTNoDecoding(ctxt, coeffint, t.PInput.GetMSB() - 1, ep->GetModulus(), t.order);
            else
                ctxtAfterFuncBT =
                    cc->EvalFuncBTNoDecoding(ctxt, coeffcomp, t.PInput.GetMSB() - 1, ep->GetModulus(), t.order);

            // Apply a rotation
            ctxtAfterFuncBT = cc->EvalRotate(ctxtAfterFuncBT, -2);

            // Apply a multiplicative mask
            ctxtAfterFuncBT = cc->EvalMult(ctxtAfterFuncBT, ptxt_mask);
            cc->ModReduceInPlace(ctxtAfterFuncBT);

            // Go back to coefficients, 0 because there are no extra levels to remove
            ctxtAfterFuncBT = cc->EvalHomDecoding(ctxtAfterFuncBT, t.scaleTHI, 0);

            if (QPrime != ctxtAfterFuncBT->GetElements()[0].GetModulus())
                OPENFHE_THROW("The ciphertext modulus after bootstrapping is not as expected.");

            auto polys1 = SchemeletRLWEMP::convert(ctxtAfterFuncBT, t.Q, QPrime);

            // Apply a subsequent LUT
            ctxt = SchemeletRLWEMP::convert(*cc, polys1, keyPair.publicKey, t.Bigq, numSlotsCKKS,
                                            depth - (t.levelsAvailableBeforeBootstrap > 0));

            if (binaryLUT)
                ctxtAfterFuncBT = cc->EvalFuncBT(ctxt, coeffint, t.PInput.GetMSB() - 1, ep->GetModulus(), t.scaleTHI,
                                                 t.levelsComputation, t.order);
            else
                ctxtAfterFuncBT = cc->EvalFuncBT(ctxt, coeffcomp, t.PInput.GetMSB() - 1, ep->GetModulus(), t.scaleTHI,
                                                 t.levelsComputation, t.order);

            if (QPrime != ctxtAfterFuncBT->GetElements()[0].GetModulus())
                OPENFHE_THROW("The ciphertext modulus after bootstrapping is not as expected.");

            auto polys2 = SchemeletRLWEMP::convert(ctxtAfterFuncBT, t.Q, QPrime);

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
            std::transform(x.begin(), x.end(), exact.begin(), [&](const int64_t& elem) {
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
                           [&](const int64_t& elem) { return (std::abs(elem)) % (t.POutput.ConvertToInt()); });

            auto max_error_it = std::max_element(exact2.begin(), exact2.end());
            // std::cerr << "\n=======Error count: " << std::accumulate(exact.begin(), exact.end(), 0) << "\n";
            // std::cerr << "\n=======Max absolute error: " << *max_error_it << "\n";
            checkEquality((*max_error_it), int64_t(0), 0.0001, failmsg + " LUT evaluation fails");

            std::transform(exact3.begin(), exact3.end(), exact.begin(), [&](const int64_t& elem) {
                return (f(elem) % t.POutput.ConvertToInt() > t.POutput.ConvertToDouble() / 2.) ?
                           f(elem) % t.POutput.ConvertToInt() - t.POutput.ConvertToInt() :
                           f(elem) % t.POutput.ConvertToInt();
            });

            std::transform(exact.begin(), exact.end(), computed2.begin(), exact.begin(), std::minus<int64_t>());
            std::transform(exact.begin(), exact.end(), exact.begin(),
                           [&](const int64_t& elem) { return (std::abs(elem)) % (t.POutput.ConvertToInt()); });
            max_error_it = std::max_element(exact.begin(), exact.end());
            // std::cerr << "\n=======Error count: " << std::accumulate(exact.begin(), exact.end(), 0) << "\n";
            // std::cerr << "\n=======Max absolute error: " << *max_error_it << "\n";
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

    void UnitTest_MVB(TEST_CASE_FUNCBT t, const std::string& failmsg = std::string()) {
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
                (t.PInput.ConvertToInt<int64_t>() / 2), (t.PInput.ConvertToInt<int64_t>() / 2) + 1, 0, 3, 16, 33, 64,
                (t.PInput.ConvertToInt<int64_t>() - 1)};
            if (x.size() < t.numSlots)
                x = Fillint64(x, t.numSlots);

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

            uint32_t dcrtBits = t.Bigq.GetMSB() - 1;
            uint32_t firstMod = t.Bigq.GetMSB() - 1;
            CCParams<CryptoContextCKKSRNS> parameters;
            parameters.SetSecretKeyDist(t.skd);
            parameters.SetSecurityLevel(HEStd_NotSet);
            parameters.SetScalingModSize(dcrtBits);
            parameters.SetScalingTechnique(FIXEDMANUAL);
            parameters.SetFirstModSize(firstMod);
            parameters.SetNumLargeDigits(t.dnum);
            parameters.SetBatchSize(numSlotsCKKS);
            parameters.SetRingDim(t.ringDim);
            uint32_t depth = t.levelsAvailableAfterBootstrap + t.lvlb[0] + t.lvlb[1] + 2 + t.levelsComputation;

            if (binaryLUT)
                depth += FHECKKSRNS::AdjustDepthFuncBT(coeffint1, t.PInput, t.order, t.skd);
            else
                depth += FHECKKSRNS::AdjustDepthFuncBT(coeffcomp1, t.PInput, t.order, t.skd);

            parameters.SetMultiplicativeDepth(depth);

            auto cc = GenCryptoContext(parameters);
            cc->Enable(PKE);
            cc->Enable(KEYSWITCH);
            cc->Enable(LEVELEDSHE);
            cc->Enable(ADVANCEDSHE);
            cc->Enable(FHE);

            auto keyPair = cc->KeyGen();

            BigInteger QPrime = keyPair.publicKey->GetPublicElements()[0].GetParams()->GetParams()[0]->GetModulus();
            uint32_t cnt      = 1;
            auto levels       = t.levelsAvailableAfterBootstrap;
            while (levels > 0) {
                QPrime *= keyPair.publicKey->GetPublicElements()[0].GetParams()->GetParams()[cnt]->GetModulus();
                levels--;
                cnt++;
            }
            double scaleMod =
                QPrime.ConvertToLongDouble() / (t.Bigq.ConvertToLongDouble() * t.POutput.ConvertToDouble());

#ifdef BENCH
            stop = std::chrono::high_resolution_clock::now();
            std::cerr << "Cryptocontext Generation: " << std::chrono::duration<double>(stop - start).count() << " s\n";
            start = std::chrono::high_resolution_clock::now();
#endif

            if (binaryLUT)
                cc->EvalFuncBTSetup(numSlotsCKKS, t.PInput, coeffint1, {0, 0}, t.lvlb, scaleMod, t.levelsComputation,
                                    t.order);
            else
                cc->EvalFuncBTSetup(numSlotsCKKS, t.PInput, coeffcomp1, {0, 0}, t.lvlb, scaleMod, t.levelsComputation,
                                    t.order);

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

            auto ep =
                SchemeletRLWEMP::GetElementParams(keyPair.secretKey, depth - (t.levelsAvailableBeforeBootstrap > 0));

            auto ctxtBFV = SchemeletRLWEMP::EncryptCoeff(x, t.QBFVInit, t.PInput, keyPair.secretKey, ep);

#ifdef BENCH
            stop = std::chrono::high_resolution_clock::now();
            std::cerr << "Coefficient Encryption: " << std::chrono::duration<double>(stop - start).count() << " s\n";
            start = std::chrono::high_resolution_clock::now();
#endif

            SchemeletRLWEMP::ModSwitch(ctxtBFV, t.Q, t.QBFVInit);

            auto ctxt = SchemeletRLWEMP::convert(*cc, ctxtBFV, keyPair.publicKey, t.Bigq, numSlotsCKKS,
                                                 depth - (t.levelsAvailableBeforeBootstrap > 0));

            std::vector<Ciphertext<DCRTPoly>> complexExp;
            Ciphertext<DCRTPoly> ctxtAfterFuncBT1, ctxtAfterFuncBT2;

            if (binaryLUT) {
                // Compute the complex exponential and its powers to reuse
                auto complexExpPowers =
                    cc->EvalMVBPrecompute(ctxt, coeffint1, t.PInput.GetMSB() - 1, ep->GetModulus(), t.order);
                // Apply multiple LUTs
                ctxtAfterFuncBT1 = cc->EvalMVB(complexExpPowers, coeffint1, t.PInput.GetMSB() - 1, t.scaleTHI,
                                               t.levelsComputation, t.order);
                ctxtAfterFuncBT2 = cc->EvalMVBNoDecoding(complexExpPowers, coeffint2, t.PInput.GetMSB() - 1, t.order);
                ctxtAfterFuncBT2 = cc->EvalHomDecoding(ctxtAfterFuncBT2, t.scaleTHI, t.levelsComputation);
            }
            else {
                // Compute the complex exponential and its powers to reuse
                auto complexExpPowers =
                    cc->EvalMVBPrecompute(ctxt, coeffcomp1, t.PInput.GetMSB() - 1, ep->GetModulus(), t.order);
                // Apply multiple LUTs
                ctxtAfterFuncBT1 = cc->EvalMVB(complexExpPowers, coeffcomp1, t.PInput.GetMSB() - 1, t.scaleTHI,
                                               t.levelsComputation, t.order);
                ctxtAfterFuncBT2 = cc->EvalMVBNoDecoding(complexExpPowers, coeffcomp2, t.PInput.GetMSB() - 1, t.order);
                ctxtAfterFuncBT2 = cc->EvalHomDecoding(ctxtAfterFuncBT2, t.scaleTHI, t.levelsComputation);
            }

            if (QPrime != ctxtAfterFuncBT1->GetElements()[0].GetModulus())
                OPENFHE_THROW("The ciphertext modulus after bootstrapping is not as expected.");

            auto polys1 = SchemeletRLWEMP::convert(ctxtAfterFuncBT1, t.Q, QPrime);

            auto polys2 = SchemeletRLWEMP::convert(ctxtAfterFuncBT2, t.Q, QPrime);

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
            std::transform(x.begin(), x.end(), exact.begin(), [&](const int64_t& elem) {
                return (f1(elem) % t.POutput.ConvertToInt() > t.POutput.ConvertToDouble() / 2.) ?
                           f1(elem) % t.POutput.ConvertToInt() - t.POutput.ConvertToInt() :
                           f1(elem);
            });

            std::transform(exact.begin(), exact.end(), computed1.begin(), exact.begin(), std::minus<int64_t>());
            std::transform(exact.begin(), exact.end(), exact.begin(),
                           [&](const int64_t& elem) { return (std::abs(elem)) % (t.POutput.ConvertToInt()); });
            auto max_error_it = std::max_element(exact.begin(), exact.end());
            // std::cerr << "\n=======Error count: " << std::accumulate(exact.begin(), exact.end(), 0) << "\n";
            // std::cerr << "\n=======Max absolute error: " << *max_error_it << "\n";
            checkEquality((*max_error_it), int64_t(0), 0.0001, failmsg + " LUT evaluation fails");

            std::transform(x.begin(), x.end(), exact.begin(), [&](const int64_t& elem) {
                return (f2(elem) % t.POutput.ConvertToInt() > t.POutput.ConvertToDouble() / 2.) ?
                           f2(elem) % t.POutput.ConvertToInt() - t.POutput.ConvertToInt() :
                           f2(elem);
            });

            std::transform(exact.begin(), exact.end(), computed2.begin(), exact.begin(), std::minus<int64_t>());
            std::transform(exact.begin(), exact.end(), exact.begin(),
                           [&](const int64_t& elem) { return (std::abs(elem)) % (t.POutput.ConvertToInt()); });
            max_error_it = std::max_element(exact.begin(), exact.end());
            // std::cerr << "\n=======Error count: " << std::accumulate(exact.begin(), exact.end(), 0) << "\n";
            // std::cerr << "\n=======Max absolute error: " << *max_error_it << "\n";
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
        case FUNCBT_CONSECLEV:
            UnitTest_ConsecLevLUT(test, test.buildTestName());
            break;
        case FUNCBT_MVB:
            UnitTest_MVB(test, test.buildTestName());
            break;
        default:
            break;
    }
}

GTEST_ALLOW_UNINSTANTIATED_PARAMETERIZED_TEST(UTCKKSRNS_FUNCBT);  // testCases.size() == 0 if NATIVEINT == 128
INSTANTIATE_TEST_SUITE_P(UnitTests, UTCKKSRNS_FUNCBT, ::testing::ValuesIn(testCases), testName);
