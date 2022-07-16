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
    CKKSRNS_TEST = 0,
    BFVRNS_TEST,
    BGVRNS_TEST,
    BFVRNS_TEST_EXTRA,
};

static std::ostream& operator<<(std::ostream& os, const TEST_CASE_TYPE& type) {
    std::string typeName;
    switch (type) {
    case CKKSRNS_TEST:
        typeName = "CKKSRNS_TEST";
        break;
    case BFVRNS_TEST:
        typeName = "BFVRNS_TEST";
        break;
    case BGVRNS_TEST:
        typeName = "BGVRNS_TEST";
        break;
    case BFVRNS_TEST_EXTRA:
        typeName = "BFVRNS_TEST_EXTRA";
        break;
    default:
        typeName = "UNKNOWN";
        break;
    }
    return os << typeName;
}
//===========================================================================================================
struct TEST_CASE_UTGENERAL_MULTIPARTY {
    TEST_CASE_TYPE testCaseType;
    // test case description - MUST BE UNIQUE
    std::string description;

    UnitTestCCParams  params;

    // additional test case data
    bool star;
    uint32_t slots = 0;


    std::string buildTestName() const {
        std::stringstream ss;
        ss  << testCaseType << "_" << description;
        return ss.str();
    }
    std::string toString() const {
        std::stringstream ss;
        ss  << "testCaseType [" << testCaseType << "], " << params.toString();
        return ss.str();
    }
};

// this lambda provides a name to be printed for every test run by INSTANTIATE_TEST_SUITE_P.
// the name MUST be constructed from digits, letters and '_' only
static auto testName = [](const testing::TestParamInfo<TEST_CASE_UTGENERAL_MULTIPARTY>& test) {
    return test.param.buildTestName();
};

static std::ostream& operator<<(std::ostream& os, const TEST_CASE_UTGENERAL_MULTIPARTY& test) {
    return os << test.toString();
}
//===========================================================================================================
constexpr usint BATCH = 16;
// clang-format off
static std::vector<TEST_CASE_UTGENERAL_MULTIPARTY> testCases = {
    // TestType,   Descr, Scheme,          RDim, MultDepth, SModSize, DSize,BatchSz, SecKeyDist, MaxRelinSkDeg, FModSize, SecLvl,       KSTech, ScalTech,        LDigits, PtMod, StdDev, EvalAddCt, KSCt, MultTech, EncTech,  Star, Slots
    { CKKSRNS_TEST, "01", {CKKSRNS_SCHEME, 2048, 2,         50,       3,    BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, BV,     FIXEDMANUAL,     DFLT,    DFLT,  DFLT,   0,         0,    DFLT,     DFLT},    false,    0},
    { CKKSRNS_TEST, "02", {CKKSRNS_SCHEME, 2048, 2,         50,       3,    BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, BV,     FIXEDAUTO,       DFLT,    DFLT,  DFLT,   0,         0,    DFLT,     DFLT},    false,    0},
    { CKKSRNS_TEST, "03", {CKKSRNS_SCHEME, 2048, 2,         50,       3,    BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, HYBRID, FIXEDMANUAL,     DFLT,    DFLT,  DFLT,   0,         0,    DFLT,     DFLT},    false,    0},
    { CKKSRNS_TEST, "04", {CKKSRNS_SCHEME, 2048, 2,         50,       3,    BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, HYBRID, FIXEDAUTO,       DFLT,    DFLT,  DFLT,   0,         0,    DFLT,     DFLT},    false,    0},
    { CKKSRNS_TEST, "05", {CKKSRNS_SCHEME, 2048, 2,         50,       3,    BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, BV,     FIXEDMANUAL,     DFLT,    DFLT,  DFLT,   0,         0,    DFLT,     DFLT},    true,     0},
    { CKKSRNS_TEST, "06", {CKKSRNS_SCHEME, 2048, 2,         50,       3,    BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, BV,     FIXEDAUTO,       DFLT,    DFLT,  DFLT,   0,         0,    DFLT,     DFLT},    true,     0},
    { CKKSRNS_TEST, "07", {CKKSRNS_SCHEME, 2048, 2,         50,       3,    BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, HYBRID, FIXEDMANUAL,     DFLT,    DFLT,  DFLT,   0,         0,    DFLT,     DFLT},    true,     0},
    { CKKSRNS_TEST, "08", {CKKSRNS_SCHEME, 2048, 2,         50,       3,    BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, HYBRID, FIXEDAUTO,       DFLT,    DFLT,  DFLT,   0,         0,    DFLT,     DFLT},    true,     0},
#if NATIVEINT != 128
    { CKKSRNS_TEST, "09", {CKKSRNS_SCHEME, 2048, 2,         50,       3,    BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, BV,     FLEXIBLEAUTO,    DFLT,    DFLT,  DFLT,   0,         0,    DFLT,     DFLT},    false,    0},
    { CKKSRNS_TEST, "10", {CKKSRNS_SCHEME, 2048, 2,         50,       3,    BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, HYBRID, FLEXIBLEAUTO,    DFLT,    DFLT,  DFLT,   0,         0,    DFLT,     DFLT},    false,    0},
    { CKKSRNS_TEST, "11", {CKKSRNS_SCHEME, 2048, 2,         50,       3,    BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, BV,     FLEXIBLEAUTOEXT, DFLT,    DFLT,  DFLT,   0,         0,    DFLT,     DFLT},    false,    0},
    { CKKSRNS_TEST, "12", {CKKSRNS_SCHEME, 2048, 2,         50,       3,    BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, HYBRID, FLEXIBLEAUTOEXT, DFLT,    DFLT,  DFLT,   0,         0,    DFLT,     DFLT},    false,    0},
    { CKKSRNS_TEST, "13", {CKKSRNS_SCHEME, 2048, 2,         50,       3,    BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, BV,     FLEXIBLEAUTO,    DFLT,    DFLT,  DFLT,   0,         0,    DFLT,     DFLT},    true,     0},
    { CKKSRNS_TEST, "14", {CKKSRNS_SCHEME, 2048, 2,         50,       3,    BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, HYBRID, FLEXIBLEAUTO,    DFLT,    DFLT,  DFLT,   0,         0,    DFLT,     DFLT},    true,     0},
    { CKKSRNS_TEST, "15", {CKKSRNS_SCHEME, 2048, 2,         50,       3,    BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, BV,     FLEXIBLEAUTOEXT, DFLT,    DFLT,  DFLT,   0,         0,    DFLT,     DFLT},    true,     0},
    { CKKSRNS_TEST, "16", {CKKSRNS_SCHEME, 2048, 2,         50,       3,    BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, HYBRID, FLEXIBLEAUTOEXT, DFLT,    DFLT,  DFLT,   0,         0,    DFLT,     DFLT},    true,     0},
#endif
    // TestType,   Descr, Scheme,          RDim, MultDepth, SModSize, DSize,BatchSz, SecKeyDist, MaxRelinSkDeg, FModSize, SecLvl,       KSTech, ScalTech,        LDigits, PtMod, StdDev, EvalAddCt, KSCt, MultTech, EncTech,  Star, Slots
    { CKKSRNS_TEST, "21", {CKKSRNS_SCHEME, 2048, 2,         50,       3,    BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, BV,     FIXEDMANUAL,     DFLT,    DFLT,  DFLT,   0,         0,    DFLT,     DFLT},    false,   16},
    { CKKSRNS_TEST, "22", {CKKSRNS_SCHEME, 2048, 2,         50,       3,    BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, BV,     FIXEDAUTO,       DFLT,    DFLT,  DFLT,   0,         0,    DFLT,     DFLT},    false,   16},
    { CKKSRNS_TEST, "23", {CKKSRNS_SCHEME, 2048, 2,         50,       3,    BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, HYBRID, FIXEDMANUAL,     DFLT,    DFLT,  DFLT,   0,         0,    DFLT,     DFLT},    false,   16},
    { CKKSRNS_TEST, "24", {CKKSRNS_SCHEME, 2048, 2,         50,       3,    BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, HYBRID, FIXEDAUTO,       DFLT,    DFLT,  DFLT,   0,         0,    DFLT,     DFLT},    false,   16},
    { CKKSRNS_TEST, "25", {CKKSRNS_SCHEME, 2048, 2,         50,       3,    BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, BV,     FIXEDMANUAL,     DFLT,    DFLT,  DFLT,   0,         0,    DFLT,     DFLT},    true,    16},
    { CKKSRNS_TEST, "26", {CKKSRNS_SCHEME, 2048, 2,         50,       3,    BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, BV,     FIXEDAUTO,       DFLT,    DFLT,  DFLT,   0,         0,    DFLT,     DFLT},    true,    16},
    { CKKSRNS_TEST, "27", {CKKSRNS_SCHEME, 2048, 2,         50,       3,    BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, HYBRID, FIXEDMANUAL,     DFLT,    DFLT,  DFLT,   0,         0,    DFLT,     DFLT},    true,    16},
    { CKKSRNS_TEST, "28", {CKKSRNS_SCHEME, 2048, 2,         50,       3,    BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, HYBRID, FIXEDAUTO,       DFLT,    DFLT,  DFLT,   0,         0,    DFLT,     DFLT},    true,    16},
#if NATIVEINT != 128
    { CKKSRNS_TEST, "29", {CKKSRNS_SCHEME, 2048, 2,         50,       3,    BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, BV,     FLEXIBLEAUTO,    DFLT,    DFLT,  DFLT,   0,         0,    DFLT,     DFLT},    false,   16},
    { CKKSRNS_TEST, "30", {CKKSRNS_SCHEME, 2048, 2,         50,       3,    BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, HYBRID, FLEXIBLEAUTO,    DFLT,    DFLT,  DFLT,   0,         0,    DFLT,     DFLT},    false,   16},
    { CKKSRNS_TEST, "31", {CKKSRNS_SCHEME, 2048, 2,         50,       3,    BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, BV,     FLEXIBLEAUTOEXT, DFLT,    DFLT,  DFLT,   0,         0,    DFLT,     DFLT},    false,   16},
    { CKKSRNS_TEST, "32", {CKKSRNS_SCHEME, 2048, 2,         50,       3,    BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, HYBRID, FLEXIBLEAUTOEXT, DFLT,    DFLT,  DFLT,   0,         0,    DFLT,     DFLT},    false,   16},
    { CKKSRNS_TEST, "33", {CKKSRNS_SCHEME, 2048, 2,         50,       3,    BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, BV,     FLEXIBLEAUTO,    DFLT,    DFLT,  DFLT,   0,         0,    DFLT,     DFLT},    true,    16},
    { CKKSRNS_TEST, "34", {CKKSRNS_SCHEME, 2048, 2,         50,       3,    BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, HYBRID, FLEXIBLEAUTO,    DFLT,    DFLT,  DFLT,   0,         0,    DFLT,     DFLT},    true,    16},
    { CKKSRNS_TEST, "35", {CKKSRNS_SCHEME, 2048, 2,         50,       3,    BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, BV,     FLEXIBLEAUTOEXT, DFLT,    DFLT,  DFLT,   0,         0,    DFLT,     DFLT},    true,    16},
    { CKKSRNS_TEST, "36", {CKKSRNS_SCHEME, 2048, 2,         50,       3,    BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, HYBRID, FLEXIBLEAUTOEXT, DFLT,    DFLT,  DFLT,   0,         0,    DFLT,     DFLT},    true,    16},
#endif
    // TestType,   Descr, Scheme,          RDim, MultDepth, SModSize, DSize,BatchSz, SecKeyDist, MaxRelinSkDeg, FModSize, SecLvl,       KSTech, ScalTech,        LDigits, PtMod, StdDev, EvalAddCt, KSCt, MultTech, EncTech,  Star, Slots
    { CKKSRNS_TEST, "41", {CKKSRNS_SCHEME, 2048, 2,         50,       3,    BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, BV,     FIXEDMANUAL,     DFLT,    DFLT,  DFLT,   0,         0,    DFLT,     DFLT},    false,   32},
    { CKKSRNS_TEST, "42", {CKKSRNS_SCHEME, 2048, 2,         50,       3,    BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, BV,     FIXEDAUTO,       DFLT,    DFLT,  DFLT,   0,         0,    DFLT,     DFLT},    false,   32},
    { CKKSRNS_TEST, "43", {CKKSRNS_SCHEME, 2048, 2,         50,       3,    BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, HYBRID, FIXEDMANUAL,     DFLT,    DFLT,  DFLT,   0,         0,    DFLT,     DFLT},    false,   32},
    { CKKSRNS_TEST, "44", {CKKSRNS_SCHEME, 2048, 2,         50,       3,    BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, HYBRID, FIXEDAUTO,       DFLT,    DFLT,  DFLT,   0,         0,    DFLT,     DFLT},    false,   32},
    { CKKSRNS_TEST, "45", {CKKSRNS_SCHEME, 2048, 2,         50,       3,    BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, BV,     FIXEDMANUAL,     DFLT,    DFLT,  DFLT,   0,         0,    DFLT,     DFLT},    true,    32},
    { CKKSRNS_TEST, "46", {CKKSRNS_SCHEME, 2048, 2,         50,       3,    BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, BV,     FIXEDAUTO,       DFLT,    DFLT,  DFLT,   0,         0,    DFLT,     DFLT},    true,    32},
    { CKKSRNS_TEST, "47", {CKKSRNS_SCHEME, 2048, 2,         50,       3,    BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, HYBRID, FIXEDMANUAL,     DFLT,    DFLT,  DFLT,   0,         0,    DFLT,     DFLT},    true,    32},
    { CKKSRNS_TEST, "48", {CKKSRNS_SCHEME, 2048, 2,         50,       3,    BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, HYBRID, FIXEDAUTO,       DFLT,    DFLT,  DFLT,   0,         0,    DFLT,     DFLT},    true,    32},
#if NATIVEINT != 128
    { CKKSRNS_TEST, "49", {CKKSRNS_SCHEME, 2048, 2,         50,       3,    BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, BV,     FLEXIBLEAUTO,    DFLT,    DFLT,  DFLT,   0,         0,    DFLT,     DFLT},    false,   32},
    { CKKSRNS_TEST, "50", {CKKSRNS_SCHEME, 2048, 2,         50,       3,    BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, HYBRID, FLEXIBLEAUTO,    DFLT,    DFLT,  DFLT,   0,         0,    DFLT,     DFLT},    false,   32},
    { CKKSRNS_TEST, "51", {CKKSRNS_SCHEME, 2048, 2,         50,       3,    BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, BV,     FLEXIBLEAUTOEXT, DFLT,    DFLT,  DFLT,   0,         0,    DFLT,     DFLT},    false,   32},
    { CKKSRNS_TEST, "52", {CKKSRNS_SCHEME, 2048, 2,         50,       3,    BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, HYBRID, FLEXIBLEAUTOEXT, DFLT,    DFLT,  DFLT,   0,         0,    DFLT,     DFLT},    false,   32},
    { CKKSRNS_TEST, "53", {CKKSRNS_SCHEME, 2048, 2,         50,       3,    BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, BV,     FLEXIBLEAUTO,    DFLT,    DFLT,  DFLT,   0,         0,    DFLT,     DFLT},    true,    32},
    { CKKSRNS_TEST, "54", {CKKSRNS_SCHEME, 2048, 2,         50,       3,    BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, HYBRID, FLEXIBLEAUTO,    DFLT,    DFLT,  DFLT,   0,         0,    DFLT,     DFLT},    true,    32},
    { CKKSRNS_TEST, "55", {CKKSRNS_SCHEME, 2048, 2,         50,       3,    BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, BV,     FLEXIBLEAUTOEXT, DFLT,    DFLT,  DFLT,   0,         0,    DFLT,     DFLT},    true,    32},
    { CKKSRNS_TEST, "56", {CKKSRNS_SCHEME, 2048, 2,         50,       3,    BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, HYBRID, FLEXIBLEAUTOEXT, DFLT,    DFLT,  DFLT,   0,         0,    DFLT,     DFLT},    true,    32},
#endif
    // TestType,   Descr, Scheme,          RDim, MultDepth, SModSize, DSize,BatchSz, SecKeyDist, MaxRelinSkDeg, FModSize, SecLvl,       KSTech, ScalTech,        LDigits, PtMod, StdDev, EvalAddCt, KSCt, MultTech, EncTech,  Star, Slots
    { CKKSRNS_TEST, "61", {CKKSRNS_SCHEME, 2048, 2,         50,       3,    BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, BV,     FIXEDMANUAL,     DFLT,    DFLT,  DFLT,   0,         0,    DFLT,     DFLT},    false, 1024},
    { CKKSRNS_TEST, "62", {CKKSRNS_SCHEME, 2048, 2,         50,       3,    BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, BV,     FIXEDAUTO,       DFLT,    DFLT,  DFLT,   0,         0,    DFLT,     DFLT},    false, 1024},
    { CKKSRNS_TEST, "63", {CKKSRNS_SCHEME, 2048, 2,         50,       3,    BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, HYBRID, FIXEDMANUAL,     DFLT,    DFLT,  DFLT,   0,         0,    DFLT,     DFLT},    false, 1024},
    { CKKSRNS_TEST, "64", {CKKSRNS_SCHEME, 2048, 2,         50,       3,    BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, HYBRID, FIXEDAUTO,       DFLT,    DFLT,  DFLT,   0,         0,    DFLT,     DFLT},    false, 1024},
    { CKKSRNS_TEST, "65", {CKKSRNS_SCHEME, 2048, 2,         50,       3,    BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, BV,     FIXEDMANUAL,     DFLT,    DFLT,  DFLT,   0,         0,    DFLT,     DFLT},    true,  1024},
    { CKKSRNS_TEST, "66", {CKKSRNS_SCHEME, 2048, 2,         50,       3,    BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, BV,     FIXEDAUTO,       DFLT,    DFLT,  DFLT,   0,         0,    DFLT,     DFLT},    true,  1024},
    { CKKSRNS_TEST, "67", {CKKSRNS_SCHEME, 2048, 2,         50,       3,    BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, HYBRID, FIXEDMANUAL,     DFLT,    DFLT,  DFLT,   0,         0,    DFLT,     DFLT},    true,  1024},
    { CKKSRNS_TEST, "68", {CKKSRNS_SCHEME, 2048, 2,         50,       3,    BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, HYBRID, FIXEDAUTO,       DFLT,    DFLT,  DFLT,   0,         0,    DFLT,     DFLT},    true,  1024},
#if NATIVEINT != 128
    { CKKSRNS_TEST, "69", {CKKSRNS_SCHEME, 2048, 2,         50,       3,    BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, BV,     FLEXIBLEAUTO,    DFLT,    DFLT,  DFLT,   0,         0,    DFLT,     DFLT},    false, 1024},
    { CKKSRNS_TEST, "70", {CKKSRNS_SCHEME, 2048, 2,         50,       3,    BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, HYBRID, FLEXIBLEAUTO,    DFLT,    DFLT,  DFLT,   0,         0,    DFLT,     DFLT},    false, 1024},
    { CKKSRNS_TEST, "71", {CKKSRNS_SCHEME, 2048, 2,         50,       3,    BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, BV,     FLEXIBLEAUTOEXT, DFLT,    DFLT,  DFLT,   0,         0,    DFLT,     DFLT},    false, 1024},
    { CKKSRNS_TEST, "72", {CKKSRNS_SCHEME, 2048, 2,         50,       3,    BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, HYBRID, FLEXIBLEAUTOEXT, DFLT,    DFLT,  DFLT,   0,         0,    DFLT,     DFLT},    false, 1024},
    { CKKSRNS_TEST, "73", {CKKSRNS_SCHEME, 2048, 2,         50,       3,    BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, BV,     FLEXIBLEAUTO,    DFLT,    DFLT,  DFLT,   0,         0,    DFLT,     DFLT},    true,  1024},
    { CKKSRNS_TEST, "74", {CKKSRNS_SCHEME, 2048, 2,         50,       3,    BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, HYBRID, FLEXIBLEAUTO,    DFLT,    DFLT,  DFLT,   0,         0,    DFLT,     DFLT},    true,  1024},
    { CKKSRNS_TEST, "75", {CKKSRNS_SCHEME, 2048, 2,         50,       3,    BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, BV,     FLEXIBLEAUTOEXT, DFLT,    DFLT,  DFLT,   0,         0,    DFLT,     DFLT},    true,  1024},
    { CKKSRNS_TEST, "76", {CKKSRNS_SCHEME, 2048, 2,         50,       3,    BATCH,   DFLT,       DFLT,          DFLT,     HEStd_NotSet, HYBRID, FLEXIBLEAUTOEXT, DFLT,    DFLT,  DFLT,   0,         0,    DFLT,     DFLT},    true,  1024},
#endif
    // ==========================================
    // TestType,   Descr, Scheme,          RDim, MultDepth, SModSize, DSize, BatchSz, SecKeyDist,      MaxRelinSkDeg, FModSize, SecLvl,       KSTech, ScalTech,     LDigits, PtMod, StdDev, EvalAddCt, KSCt, MultTech,         EncTech,   Star, Slots
    { BFVRNS_TEST, "01", {BFVRNS_SCHEME,   DFLT, DFLT,      60,       20,    DFLT,    UNIFORM_TERNARY, DFLT,          DFLT,     DFLT,         DFLT,   DFLT,         DFLT,    65537, DFLT,   DFLT,      DFLT, HPS,              STANDARD}, false, 0},
    { BFVRNS_TEST, "02", {BFVRNS_SCHEME,   DFLT, DFLT,      60,       20,    DFLT,    GAUSSIAN,        DFLT,          DFLT,     DFLT,         DFLT,   DFLT,         DFLT,    65537, DFLT,   DFLT,      DFLT, HPS,              STANDARD}, false, 0},
    { BFVRNS_TEST, "03", {BFVRNS_SCHEME,   DFLT, DFLT,      60,       20,    DFLT,    UNIFORM_TERNARY, DFLT,          DFLT,     DFLT,         DFLT,   DFLT,         DFLT,    65537, DFLT,   DFLT,      DFLT, BEHZ,             STANDARD}, false, 0},
    { BFVRNS_TEST, "04", {BFVRNS_SCHEME,   DFLT, DFLT,      60,       20,    DFLT,    GAUSSIAN,        DFLT,          DFLT,     DFLT,         DFLT,   DFLT,         DFLT,    65537, DFLT,   DFLT,      DFLT, BEHZ,             STANDARD}, false, 0},
    { BFVRNS_TEST, "05", {BFVRNS_SCHEME,   DFLT, DFLT,      60,       20,    DFLT,    UNIFORM_TERNARY, DFLT,          DFLT,     DFLT,         DFLT,   DFLT,         DFLT,    65537, DFLT,   DFLT,      DFLT, HPSPOVERQ,        STANDARD}, false, 0},
    { BFVRNS_TEST, "06", {BFVRNS_SCHEME,   DFLT, DFLT,      60,       20,    DFLT,    GAUSSIAN,        DFLT,          DFLT,     DFLT,         DFLT,   DFLT,         DFLT,    65537, DFLT,   DFLT,      DFLT, HPSPOVERQ,        STANDARD}, false, 0},
    { BFVRNS_TEST, "07", {BFVRNS_SCHEME,   DFLT, DFLT,      60,       20,    DFLT,    UNIFORM_TERNARY, DFLT,          DFLT,     DFLT,         DFLT,   DFLT,         DFLT,    65537, DFLT,   DFLT,      DFLT, HPSPOVERQLEVELED, STANDARD}, false, 0},
    { BFVRNS_TEST, "08", {BFVRNS_SCHEME,   DFLT, DFLT,      60,       20,    DFLT,    GAUSSIAN,        DFLT,          DFLT,     DFLT,         DFLT,   DFLT,         DFLT,    65537, DFLT,   DFLT,      DFLT, HPSPOVERQLEVELED, STANDARD}, false, 0},
    { BFVRNS_TEST, "09", {BFVRNS_SCHEME,   DFLT, DFLT,      60,       20,    DFLT,    UNIFORM_TERNARY, DFLT,          DFLT,     DFLT,         DFLT,   DFLT,         DFLT,    65537, DFLT,   DFLT,      DFLT, HPS,              STANDARD}, true,  0},
    { BFVRNS_TEST, "10", {BFVRNS_SCHEME,   DFLT, DFLT,      60,       20,    DFLT,    GAUSSIAN,        DFLT,          DFLT,     DFLT,         DFLT,   DFLT,         DFLT,    65537, DFLT,   DFLT,      DFLT, HPS,              STANDARD}, true,  0},
    { BFVRNS_TEST, "11", {BFVRNS_SCHEME,   DFLT, DFLT,      60,       20,    DFLT,    UNIFORM_TERNARY, DFLT,          DFLT,     DFLT,         DFLT,   DFLT,         DFLT,    65537, DFLT,   DFLT,      DFLT, BEHZ,             STANDARD}, true,  0},
    { BFVRNS_TEST, "12", {BFVRNS_SCHEME,   DFLT, DFLT,      60,       20,    DFLT,    GAUSSIAN,        DFLT,          DFLT,     DFLT,         DFLT,   DFLT,         DFLT,    65537, DFLT,   DFLT,      DFLT, BEHZ,             STANDARD}, true,  0},
    { BFVRNS_TEST, "13", {BFVRNS_SCHEME,   DFLT, DFLT,      60,       20,    DFLT,    UNIFORM_TERNARY, DFLT,          DFLT,     DFLT,         DFLT,   DFLT,         DFLT,    65537, DFLT,   DFLT,      DFLT, HPSPOVERQ,        STANDARD}, true,  0},
    { BFVRNS_TEST, "14", {BFVRNS_SCHEME,   DFLT, DFLT,      60,       20,    DFLT,    GAUSSIAN,        DFLT,          DFLT,     DFLT,         DFLT,   DFLT,         DFLT,    65537, DFLT,   DFLT,      DFLT, HPSPOVERQ,        STANDARD}, true,  0},
    { BFVRNS_TEST, "15", {BFVRNS_SCHEME,   DFLT, DFLT,      60,       20,    DFLT,    UNIFORM_TERNARY, DFLT,          DFLT,     DFLT,         DFLT,   DFLT,         DFLT,    65537, DFLT,   DFLT,      DFLT, HPSPOVERQLEVELED, STANDARD}, true,  0},
    { BFVRNS_TEST, "16", {BFVRNS_SCHEME,   DFLT, DFLT,      60,       20,    DFLT,    GAUSSIAN,        DFLT,          DFLT,     DFLT,         DFLT,   DFLT,         DFLT,    65537, DFLT,   DFLT,      DFLT, HPSPOVERQLEVELED, STANDARD}, true,  0},
    { BFVRNS_TEST, "17", {BFVRNS_SCHEME,   DFLT, DFLT,      60,       20,    DFLT,    UNIFORM_TERNARY, DFLT,          DFLT,     DFLT,         DFLT,   DFLT,         DFLT,    65537, DFLT,   DFLT,      DFLT, HPS,              EXTENDED},   false, 0},
    { BFVRNS_TEST, "18", {BFVRNS_SCHEME,   DFLT, DFLT,      60,       20,    DFLT,    GAUSSIAN,        DFLT,          DFLT,     DFLT,         DFLT,   DFLT,         DFLT,    65537, DFLT,   DFLT,      DFLT, HPS,              EXTENDED},   false, 0},
    { BFVRNS_TEST, "19", {BFVRNS_SCHEME,   DFLT, DFLT,      60,       20,    DFLT,    UNIFORM_TERNARY, DFLT,          DFLT,     DFLT,         DFLT,   DFLT,         DFLT,    65537, DFLT,   DFLT,      DFLT, BEHZ,             EXTENDED},   false, 0},
    { BFVRNS_TEST, "20", {BFVRNS_SCHEME,   DFLT, DFLT,      60,       20,    DFLT,    GAUSSIAN,        DFLT,          DFLT,     DFLT,         DFLT,   DFLT,         DFLT,    65537, DFLT,   DFLT,      DFLT, BEHZ,             EXTENDED},   false, 0},
    { BFVRNS_TEST, "21", {BFVRNS_SCHEME,   DFLT, DFLT,      60,       20,    DFLT,    UNIFORM_TERNARY, DFLT,          DFLT,     DFLT,         DFLT,   DFLT,         DFLT,    65537, DFLT,   DFLT,      DFLT, HPSPOVERQ,        EXTENDED},   false, 0},
    { BFVRNS_TEST, "22", {BFVRNS_SCHEME,   DFLT, DFLT,      60,       20,    DFLT,    GAUSSIAN,        DFLT,          DFLT,     DFLT,         DFLT,   DFLT,         DFLT,    65537, DFLT,   DFLT,      DFLT, HPSPOVERQ,        EXTENDED},   false, 0},
    { BFVRNS_TEST, "23", {BFVRNS_SCHEME,   DFLT, DFLT,      60,       20,    DFLT,    UNIFORM_TERNARY, DFLT,          DFLT,     DFLT,         DFLT,   DFLT,         DFLT,    65537, DFLT,   DFLT,      DFLT, HPSPOVERQLEVELED, EXTENDED},   false, 0},
    { BFVRNS_TEST, "24", {BFVRNS_SCHEME,   DFLT, DFLT,      60,       20,    DFLT,    GAUSSIAN,        DFLT,          DFLT,     DFLT,         DFLT,   DFLT,         DFLT,    65537, DFLT,   DFLT,      DFLT, HPSPOVERQLEVELED, EXTENDED},   false, 0},
    { BFVRNS_TEST, "25", {BFVRNS_SCHEME,   DFLT, DFLT,      60,       20,    DFLT,    UNIFORM_TERNARY, DFLT,          DFLT,     DFLT,         DFLT,   DFLT,         DFLT,    65537, DFLT,   DFLT,      DFLT, HPS,              EXTENDED},   true,  0},
    { BFVRNS_TEST, "26", {BFVRNS_SCHEME,   DFLT, DFLT,      60,       20,    DFLT,    GAUSSIAN,        DFLT,          DFLT,     DFLT,         DFLT,   DFLT,         DFLT,    65537, DFLT,   DFLT,      DFLT, HPS,              EXTENDED},   true,  0},
    { BFVRNS_TEST, "27", {BFVRNS_SCHEME,   DFLT, DFLT,      60,       20,    DFLT,    UNIFORM_TERNARY, DFLT,          DFLT,     DFLT,         DFLT,   DFLT,         DFLT,    65537, DFLT,   DFLT,      DFLT, BEHZ,             EXTENDED},   true,  0},
    { BFVRNS_TEST, "28", {BFVRNS_SCHEME,   DFLT, DFLT,      60,       20,    DFLT,    GAUSSIAN,        DFLT,          DFLT,     DFLT,         DFLT,   DFLT,         DFLT,    65537, DFLT,   DFLT,      DFLT, BEHZ,             EXTENDED},   true,  0},
    { BFVRNS_TEST, "29", {BFVRNS_SCHEME,   DFLT, DFLT,      60,       20,    DFLT,    UNIFORM_TERNARY, DFLT,          DFLT,     DFLT,         DFLT,   DFLT,         DFLT,    65537, DFLT,   DFLT,      DFLT, HPSPOVERQ,        EXTENDED},   true,  0},
    { BFVRNS_TEST, "30", {BFVRNS_SCHEME,   DFLT, DFLT,      60,       20,    DFLT,    GAUSSIAN,        DFLT,          DFLT,     DFLT,         DFLT,   DFLT,         DFLT,    65537, DFLT,   DFLT,      DFLT, HPSPOVERQ,        EXTENDED},   true,  0},
    { BFVRNS_TEST, "31", {BFVRNS_SCHEME,   DFLT, DFLT,      60,       20,    DFLT,    UNIFORM_TERNARY, DFLT,          DFLT,     DFLT,         DFLT,   DFLT,         DFLT,    65537, DFLT,   DFLT,      DFLT, HPSPOVERQLEVELED, EXTENDED},   true,  0},
    { BFVRNS_TEST, "32", {BFVRNS_SCHEME,   DFLT, DFLT,      60,       20,    DFLT,    GAUSSIAN,        DFLT,          DFLT,     DFLT,         DFLT,   DFLT,         DFLT,    65537, DFLT,   DFLT,      DFLT, HPSPOVERQLEVELED, EXTENDED},   true,  0},
    // ==========================================
    // TestType,   Descr, Scheme,          RDim, MultDepth, SModSize, DSize,BatchSz, SecKeyDist,      MaxRelinSkDeg, FModSize, SecLvl,       KSTech, ScalTech,        LDigits, PtMod, StdDev, EvalAddCt, KSCt, MultTech, EncTech,  Star, Slots
    { BGVRNS_TEST, "01", {BGVRNS_SCHEME,   256,  2,         DFLT,     3,    BATCH,   UNIFORM_TERNARY, 1,             60,       HEStd_NotSet, BV,     FIXEDMANUAL,     DFLT,    65537, DFLT,   DFLT,      DFLT, DFLT,     DFLT},    false,    0},
    { BGVRNS_TEST, "02", {BGVRNS_SCHEME,   256,  2,         DFLT,     3,    BATCH,   GAUSSIAN,        DFLT,          60,       HEStd_NotSet, BV,     FIXEDMANUAL,     DFLT,    65537, DFLT,   DFLT,      DFLT, DFLT,     DFLT},    false,    0},
    { BGVRNS_TEST, "03", {BGVRNS_SCHEME,   256,  2,         DFLT,     3,    BATCH,   UNIFORM_TERNARY, 1,             60,       HEStd_NotSet, HYBRID, FIXEDMANUAL,     DFLT,    65537, DFLT,   DFLT,      DFLT, DFLT,     DFLT},    false,    0},
    { BGVRNS_TEST, "04", {BGVRNS_SCHEME,   256,  2,         DFLT,     3,    BATCH,   GAUSSIAN,        DFLT,          60,       HEStd_NotSet, HYBRID, FIXEDMANUAL,     DFLT,    65537, DFLT,   DFLT,      DFLT, DFLT,     DFLT},    false,    0},
    { BGVRNS_TEST, "05", {BGVRNS_SCHEME,   256,  2,         DFLT,     3,    BATCH,   UNIFORM_TERNARY, 1,             60,       HEStd_NotSet, BV,     FIXEDMANUAL,     DFLT,    65537, DFLT,   DFLT,      DFLT, DFLT,     DFLT},    true,     0},
    { BGVRNS_TEST, "06", {BGVRNS_SCHEME,   256,  2,         DFLT,     3,    BATCH,   GAUSSIAN,        DFLT,          60,       HEStd_NotSet, BV,     FIXEDMANUAL,     DFLT,    65537, DFLT,   DFLT,      DFLT, DFLT,     DFLT},    true,     0},
    { BGVRNS_TEST, "07", {BGVRNS_SCHEME,   256,  2,         DFLT,     3,    BATCH,   UNIFORM_TERNARY, 1,             60,       HEStd_NotSet, HYBRID, FIXEDMANUAL,     DFLT,    65537, DFLT,   DFLT,      DFLT, DFLT,     DFLT},    true,     0},
    { BGVRNS_TEST, "08", {BGVRNS_SCHEME,   256,  2,         DFLT,     3,    BATCH,   GAUSSIAN,        DFLT,          60,       HEStd_NotSet, HYBRID, FIXEDMANUAL,     DFLT,    65537, DFLT,   DFLT,      DFLT, DFLT,     DFLT},    true,     0},
    { BGVRNS_TEST, "09", {BGVRNS_SCHEME,   256,  2,         DFLT,     3,    BATCH,   UNIFORM_TERNARY, 1,             60,       HEStd_NotSet, BV,     FIXEDAUTO,       DFLT,    65537, DFLT,   DFLT,      DFLT, DFLT,     DFLT},    false,    0},
    { BGVRNS_TEST, "10", {BGVRNS_SCHEME,   256,  2,         DFLT,     3,    BATCH,   GAUSSIAN,        DFLT,          60,       HEStd_NotSet, BV,     FIXEDAUTO,       DFLT,    65537, DFLT,   DFLT,      DFLT, DFLT,     DFLT},    false,    0},
    { BGVRNS_TEST, "11", {BGVRNS_SCHEME,   256,  2,         DFLT,     3,    BATCH,   UNIFORM_TERNARY, 1,             60,       HEStd_NotSet, HYBRID, FIXEDAUTO,       DFLT,    65537, DFLT,   DFLT,      DFLT, DFLT,     DFLT},    false,    0},
    { BGVRNS_TEST, "12", {BGVRNS_SCHEME,   256,  2,         DFLT,     3,    BATCH,   GAUSSIAN,        DFLT,          60,       HEStd_NotSet, HYBRID, FIXEDAUTO,       DFLT,    65537, DFLT,   DFLT,      DFLT, DFLT,     DFLT},    false,    0},
    { BGVRNS_TEST, "13", {BGVRNS_SCHEME,   256,  2,         DFLT,     3,    BATCH,   UNIFORM_TERNARY, 1,             60,       HEStd_NotSet, BV,     FIXEDAUTO,       DFLT,    65537, DFLT,   DFLT,      DFLT, DFLT,     DFLT},    true,     0},
    { BGVRNS_TEST, "14", {BGVRNS_SCHEME,   256,  2,         DFLT,     3,    BATCH,   GAUSSIAN,        DFLT,          60,       HEStd_NotSet, BV,     FIXEDAUTO,       DFLT,    65537, DFLT,   DFLT,      DFLT, DFLT,     DFLT},    true,     0},
    { BGVRNS_TEST, "15", {BGVRNS_SCHEME,   256,  2,         DFLT,     3,    BATCH,   UNIFORM_TERNARY, 1,             60,       HEStd_NotSet, HYBRID, FIXEDAUTO,       DFLT,    65537, DFLT,   DFLT,      DFLT, DFLT,     DFLT},    true,     0},
    { BGVRNS_TEST, "16", {BGVRNS_SCHEME,   256,  2,         DFLT,     3,    BATCH,   GAUSSIAN,        DFLT,          60,       HEStd_NotSet, HYBRID, FIXEDAUTO,       DFLT,    65537, DFLT,   DFLT,      DFLT, DFLT,     DFLT},    true,     0},
    { BGVRNS_TEST, "17", {BGVRNS_SCHEME,   256,  2,         DFLT,     3,    BATCH,   UNIFORM_TERNARY, 1,             60,       HEStd_NotSet, BV,     FLEXIBLEAUTO,    DFLT,    65537, DFLT,   DFLT,      DFLT, DFLT,     DFLT},    false,    0},
    { BGVRNS_TEST, "18", {BGVRNS_SCHEME,   256,  2,         DFLT,     3,    BATCH,   GAUSSIAN,        DFLT,          60,       HEStd_NotSet, BV,     FLEXIBLEAUTO,    DFLT,    65537, DFLT,   DFLT,      DFLT, DFLT,     DFLT},    false,    0},
    { BGVRNS_TEST, "19", {BGVRNS_SCHEME,   256,  2,         DFLT,     3,    BATCH,   UNIFORM_TERNARY, 1,             60,       HEStd_NotSet, HYBRID, FLEXIBLEAUTO,    DFLT,    65537, DFLT,   DFLT,      DFLT, DFLT,     DFLT},    false,    0},
    { BGVRNS_TEST, "20", {BGVRNS_SCHEME,   256,  2,         DFLT,     3,    BATCH,   GAUSSIAN,        DFLT,          60,       HEStd_NotSet, HYBRID, FLEXIBLEAUTO,    DFLT,    65537, DFLT,   DFLT,      DFLT, DFLT,     DFLT},    false,    0},
    { BGVRNS_TEST, "21", {BGVRNS_SCHEME,   256,  2,         DFLT,     3,    BATCH,   UNIFORM_TERNARY, 1,             60,       HEStd_NotSet, BV,     FLEXIBLEAUTO,    DFLT,    65537, DFLT,   DFLT,      DFLT, DFLT,     DFLT},    true,     0},
    { BGVRNS_TEST, "22", {BGVRNS_SCHEME,   256,  2,         DFLT,     3,    BATCH,   GAUSSIAN,        DFLT,          60,       HEStd_NotSet, BV,     FLEXIBLEAUTO,    DFLT,    65537, DFLT,   DFLT,      DFLT, DFLT,     DFLT},    true,     0},
    { BGVRNS_TEST, "23", {BGVRNS_SCHEME,   256,  2,         DFLT,     3,    BATCH,   UNIFORM_TERNARY, 1,             60,       HEStd_NotSet, HYBRID, FLEXIBLEAUTO,    DFLT,    65537, DFLT,   DFLT,      DFLT, DFLT,     DFLT},    true,     0},
    { BGVRNS_TEST, "24", {BGVRNS_SCHEME,   256,  2,         DFLT,     3,    BATCH,   GAUSSIAN,        DFLT,          60,       HEStd_NotSet, HYBRID, FLEXIBLEAUTO,    DFLT,    65537, DFLT,   DFLT,      DFLT, DFLT,     DFLT},    true,     0},
    { BGVRNS_TEST, "25", {BGVRNS_SCHEME,   256,  2,         DFLT,     3,    BATCH,   UNIFORM_TERNARY, 1,             60,       HEStd_NotSet, BV,     FLEXIBLEAUTOEXT, DFLT,    65537, DFLT,   DFLT,      DFLT, DFLT,     DFLT},    false,    0},
    { BGVRNS_TEST, "26", {BGVRNS_SCHEME,   256,  2,         DFLT,     3,    BATCH,   GAUSSIAN,        DFLT,          60,       HEStd_NotSet, BV,     FLEXIBLEAUTOEXT, DFLT,    65537, DFLT,   DFLT,      DFLT, DFLT,     DFLT},    false,    0},
    { BGVRNS_TEST, "27", {BGVRNS_SCHEME,   256,  2,         DFLT,     3,    BATCH,   UNIFORM_TERNARY, 1,             60,       HEStd_NotSet, HYBRID, FLEXIBLEAUTOEXT, DFLT,    65537, DFLT,   DFLT,      DFLT, DFLT,     DFLT},    false,    0},
    { BGVRNS_TEST, "28", {BGVRNS_SCHEME,   256,  2,         DFLT,     3,    BATCH,   GAUSSIAN,        DFLT,          60,       HEStd_NotSet, HYBRID, FLEXIBLEAUTOEXT, DFLT,    65537, DFLT,   DFLT,      DFLT, DFLT,     DFLT},    false,    0},
    { BGVRNS_TEST, "29", {BGVRNS_SCHEME,   256,  2,         DFLT,     3,    BATCH,   UNIFORM_TERNARY, 1,             60,       HEStd_NotSet, BV,     FLEXIBLEAUTOEXT, DFLT,    65537, DFLT,   DFLT,      DFLT, DFLT,     DFLT},    true,     0},
    { BGVRNS_TEST, "30", {BGVRNS_SCHEME,   256,  2,         DFLT,     3,    BATCH,   GAUSSIAN,        DFLT,          60,       HEStd_NotSet, BV,     FLEXIBLEAUTOEXT, DFLT,    65537, DFLT,   DFLT,      DFLT, DFLT,     DFLT},    true,     0},
    { BGVRNS_TEST, "31", {BGVRNS_SCHEME,   256,  2,         DFLT,     3,    BATCH,   UNIFORM_TERNARY, 1,             60,       HEStd_NotSet, HYBRID, FLEXIBLEAUTOEXT, DFLT,    65537, DFLT,   DFLT,      DFLT, DFLT,     DFLT},    true,     0},
    { BGVRNS_TEST, "32", {BGVRNS_SCHEME,   256,  2,         DFLT,     3,    BATCH,   GAUSSIAN,        DFLT,          60,       HEStd_NotSet, HYBRID, FLEXIBLEAUTOEXT, DFLT,    65537, DFLT,   DFLT,      DFLT, DFLT,     DFLT},    true,     0},
    // ==========================================
    // TestType,   Descr, Scheme,          RDim, MultDepth, SModSize, DSize,BatchSz, SecKeyDist,      MaxRelinSkDeg, FModSize, SecLvl,       KSTech, ScalTech,     LDigits, PtMod, StdDev, EvalAddCt, KSCt, MultTech,         EncTech,   Star, Slots
    { BFVRNS_TEST_EXTRA, "01", {BFVRNS_SCHEME, DFLT, DFLT,  60,       20,   DFLT,    GAUSSIAN,        DFLT,          DFLT,     DFLT,         DFLT,   DFLT,         DFLT,    4,     DFLT,   DFLT,      DFLT, HPS,              STANDARD}, false,    0},
    { BFVRNS_TEST_EXTRA, "02", {BFVRNS_SCHEME, DFLT, DFLT,  60,       20,   DFLT,    UNIFORM_TERNARY, DFLT,          DFLT,     DFLT,         DFLT,   DFLT,         DFLT,    16,    DFLT,   DFLT,      DFLT, HPS,              STANDARD}, false,    0},
    { BFVRNS_TEST_EXTRA, "03", {BFVRNS_SCHEME, DFLT, DFLT,  60,       20,   DFLT,    GAUSSIAN,        DFLT,          DFLT,     DFLT,         DFLT,   DFLT,         DFLT,    4,     DFLT,   DFLT,      DFLT, BEHZ,             STANDARD}, false,    0},
    { BFVRNS_TEST_EXTRA, "04", {BFVRNS_SCHEME, DFLT, DFLT,  60,       20,   DFLT,    UNIFORM_TERNARY, DFLT,          DFLT,     DFLT,         DFLT,   DFLT,         DFLT,    16,    DFLT,   DFLT,      DFLT, BEHZ,             STANDARD}, false,    0},
    { BFVRNS_TEST_EXTRA, "05", {BFVRNS_SCHEME, DFLT, DFLT,  60,       20,   DFLT,    GAUSSIAN,        DFLT,          DFLT,     DFLT,         DFLT,   DFLT,         DFLT,    4,     DFLT,   DFLT,      DFLT, HPSPOVERQ,        STANDARD}, false,    0},
    { BFVRNS_TEST_EXTRA, "06", {BFVRNS_SCHEME, DFLT, DFLT,  60,       20,   DFLT,    UNIFORM_TERNARY, DFLT,          DFLT,     DFLT,         DFLT,   DFLT,         DFLT,    16,    DFLT,   DFLT,      DFLT, HPSPOVERQ,        STANDARD}, false,    0},
    { BFVRNS_TEST_EXTRA, "07", {BFVRNS_SCHEME, DFLT, DFLT,  60,       20,   DFLT,    GAUSSIAN,        DFLT,          DFLT,     DFLT,         DFLT,   DFLT,         DFLT,    4,     DFLT,   DFLT,      DFLT, HPSPOVERQLEVELED, STANDARD}, false,    0},
    { BFVRNS_TEST_EXTRA, "08", {BFVRNS_SCHEME, DFLT, DFLT,  60,       20,   DFLT,    UNIFORM_TERNARY, DFLT,          DFLT,     DFLT,         DFLT,   DFLT,         DFLT,    16,    DFLT,   DFLT,      DFLT, HPSPOVERQLEVELED, STANDARD}, false,    0},
    { BFVRNS_TEST_EXTRA, "09", {BFVRNS_SCHEME, DFLT, DFLT,  60,       20,   DFLT,    GAUSSIAN,        DFLT,          DFLT,     DFLT,         DFLT,   DFLT,         DFLT,    4,     DFLT,   DFLT,      DFLT, HPS,              EXTENDED},   false,    0},
    { BFVRNS_TEST_EXTRA, "10", {BFVRNS_SCHEME, DFLT, DFLT,  60,       20,   DFLT,    UNIFORM_TERNARY, DFLT,          DFLT,     DFLT,         DFLT,   DFLT,         DFLT,    16,    DFLT,   DFLT,      DFLT, HPS,              EXTENDED},   false,    0},
    { BFVRNS_TEST_EXTRA, "11", {BFVRNS_SCHEME, DFLT, DFLT,  60,       20,   DFLT,    GAUSSIAN,        DFLT,          DFLT,     DFLT,         DFLT,   DFLT,         DFLT,    4,     DFLT,   DFLT,      DFLT, BEHZ,             EXTENDED},   false,    0},
    { BFVRNS_TEST_EXTRA, "12", {BFVRNS_SCHEME, DFLT, DFLT,  60,       20,   DFLT,    UNIFORM_TERNARY, DFLT,          DFLT,     DFLT,         DFLT,   DFLT,         DFLT,    16,    DFLT,   DFLT,      DFLT, BEHZ,             EXTENDED},   false,    0},
    { BFVRNS_TEST_EXTRA, "13", {BFVRNS_SCHEME, DFLT, DFLT,  60,       20,   DFLT,    GAUSSIAN,        DFLT,          DFLT,     DFLT,         DFLT,   DFLT,         DFLT,    4,     DFLT,   DFLT,      DFLT, HPSPOVERQ,        EXTENDED},   false,    0},
    { BFVRNS_TEST_EXTRA, "14", {BFVRNS_SCHEME, DFLT, DFLT,  60,       20,   DFLT,    UNIFORM_TERNARY, DFLT,          DFLT,     DFLT,         DFLT,   DFLT,         DFLT,    16,    DFLT,   DFLT,      DFLT, HPSPOVERQ,        EXTENDED},   false,    0},
    { BFVRNS_TEST_EXTRA, "15", {BFVRNS_SCHEME, DFLT, DFLT,  60,       20,   DFLT,    GAUSSIAN,        DFLT,          DFLT,     DFLT,         DFLT,   DFLT,         DFLT,    4,     DFLT,   DFLT,      DFLT, HPSPOVERQLEVELED, EXTENDED},   false,    0},
    { BFVRNS_TEST_EXTRA, "16", {BFVRNS_SCHEME, DFLT, DFLT,  60,       20,   DFLT,    UNIFORM_TERNARY, DFLT,          DFLT,     DFLT,         DFLT,   DFLT,         DFLT,    16,    DFLT,   DFLT,      DFLT, HPSPOVERQLEVELED, EXTENDED},   false,    0},
};
// clang-format on
//===========================================================================================================
class UTGENERAL_MULTIPARTY : public ::testing::TestWithParam<TEST_CASE_UTGENERAL_MULTIPARTY> {
    using Element = DCRTPoly;

protected:
    void SetUp() {}
    void TearDown() {
        CryptoContextFactory<Element>::ReleaseAllContexts();
    }

    // in order to avoid redundancy, UnitTest_MultiParty() uses 2 conditions:
    //  - testData.star false/true
    //  - CKKSRNS_TEST false/true
    void UnitTest_MultiParty(const TEST_CASE_UTGENERAL_MULTIPARTY& testData, const std::string& failmsg = std::string()) {
        try {
            CryptoContext<Element> cc(UnitTestGenerateContext(testData.params));

            const double eps = 0.000001;
            std::vector<int32_t> indices = { 2 };
            //====================================================================
            KeyPair<Element> kp1 = cc->KeyGen();
            auto evalMultKey = cc->KeySwitchGen(kp1.secretKey, kp1.secretKey);
            cc->EvalSumKeyGen(kp1.secretKey);
            auto evalSumKeys = std::make_shared<std::map<usint, EvalKey<Element>>>(
                cc->GetEvalSumKeyMap(kp1.secretKey->GetKeyTag()));
            cc->EvalAtIndexKeyGen(kp1.secretKey, indices);
            auto evalAtIndexKeys = std::make_shared<std::map<usint, EvalKey<Element>>>(
                cc->GetEvalAutomorphismKeyMap(kp1.secretKey->GetKeyTag()));
            //====================================================================
            KeyPair<Element> kp2 = testData.star ?
                cc->MultipartyKeyGen(kp1.publicKey) : cc->MultipartyKeyGen(kp1.publicKey, false, true);

            auto evalMultKey2 = cc->MultiKeySwitchGen(kp2.secretKey, kp2.secretKey, evalMultKey);
            auto evalMultAB = cc->MultiAddEvalKeys(evalMultKey, evalMultKey2, kp2.publicKey->GetKeyTag());
            auto evalMultBAB = cc->MultiMultEvalKey(kp2.secretKey, evalMultAB, kp2.publicKey->GetKeyTag());
            auto evalSumKeysB = cc->MultiEvalSumKeyGen(kp2.secretKey, evalSumKeys, kp2.publicKey->GetKeyTag());
            auto evalSumKeysJoin = cc->MultiAddEvalSumKeys(evalSumKeys, evalSumKeysB, kp2.publicKey->GetKeyTag());
            cc->InsertEvalSumKey(evalSumKeysJoin);

            auto evalAtIndexKeysB = cc->MultiEvalAtIndexKeyGen(
                kp2.secretKey, evalAtIndexKeys, indices, kp2.publicKey->GetKeyTag());
            auto evalAtIndexKeysJoin = cc->MultiAddEvalAutomorphismKeys(
                evalAtIndexKeys, evalAtIndexKeysB, kp2.publicKey->GetKeyTag());
            cc->InsertEvalAutomorphismKey(evalAtIndexKeysJoin);

            auto evalMultAAB = cc->MultiMultEvalKey(kp1.secretKey, evalMultAB, kp2.publicKey->GetKeyTag());
            auto evalMultFinal = cc->MultiAddEvalMultKeys(
                evalMultAAB,
                evalMultBAB,
                (CKKSRNS_TEST == testData.testCaseType) ? evalMultAB->GetKeyTag() : kp2.publicKey->GetKeyTag());
            cc->InsertEvalMultKey({ evalMultFinal });
            //====================================================================
            std::vector<PrivateKey<Element>> secretKeys{ kp1.secretKey, kp2.secretKey };
            KeyPair<Element> kpMultiparty = cc->MultipartyKeyGen(secretKeys);
            if (!kpMultiparty.good())
                OPENFHE_THROW(openfhe_error, "Key generation failed");

            ////////////////////////////////////////////////////////////
            // Encode source data
            ////////////////////////////////////////////////////////////
            std::vector<int64_t> vectorOfInts1{ 1, 2, 3, 4, 5, 6, 5, 4, 3, 2, 1, 0 };
            std::vector<int64_t> vectorOfInts2{ 1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0 };
            std::vector<int64_t> vectorOfInts3{ 2, 2, 3, 4, 5, 6, 7, 8, 9, 10, 0, 0 };

            size_t encodedLength = vectorOfInts1.size();
            std::vector<int64_t> sumInput(encodedLength, 0);
            std::vector<int64_t> multInput(encodedLength, 0);
            for (usint i = 0; i < encodedLength; ++i) {
                sumInput[i] = vectorOfInts1[i] + vectorOfInts2[i] + vectorOfInts3[i];
                multInput[i] = vectorOfInts1[i] * vectorOfInts3[i];
            }

            std::vector<int64_t> evalSumInput(encodedLength, 0);
            std::vector<int64_t> rotateInput(encodedLength, 0);
            if (CKKSRNS_TEST == testData.testCaseType) {
              // For CKKS there is different logic, depending on slots value
              uint32_t slots = (testData.slots != 0) ? testData.slots : (BATCH != 0) ? BATCH : cc->GetRingDimension() / 2;
              for (usint i = 0; i < encodedLength; ++i) {
                evalSumInput[i] = 0;
                // we add to evalSumInput[i] value vectorOfInts3[(i + j) % BATCH];
                for (usint j = 0; j < BATCH; ++j) {
                  if ((i + j) % slots < encodedLength) {
                    evalSumInput[i] += vectorOfInts3[(i + j) % slots];
                  }
                }
              }

              for (usint i = 0; i < encodedLength; ++i) {
                if ((slots + i + indices[0]) % slots < encodedLength) {
                  rotateInput[i] = vectorOfInts1[(slots + i + indices[0]) % slots];
                }
              }
            } else {
              // For BGV and BFV no slots is given
              for (usint i = 0, rev = (encodedLength - 1); i < encodedLength; ++i, --rev) {
                if (i == 0)
                    evalSumInput[rev] = vectorOfInts3[rev];
                else
                    evalSumInput[rev] = evalSumInput[rev + 1] + vectorOfInts3[rev];
                if (i + indices[0] > encodedLength - 1)
                    rotateInput[i] = 0;
                else
                    rotateInput[i] = vectorOfInts1[i + indices[0]];
              }
            }


            Plaintext plaintext1(nullptr);
            Plaintext plaintext2(nullptr);
            Plaintext plaintext3(nullptr);
            Plaintext plaintextSumInput(nullptr);
            Plaintext plaintextMultInput(nullptr);
            Plaintext plaintextEvalSumInput(nullptr);
            Plaintext plaintextRotateInput(nullptr);
            if (CKKSRNS_TEST == testData.testCaseType) {
                // TODO (dsuponit): we have to rename MakeCKKSPackedPlaintext() to MakePackedPlaintext(). All of them have different input params
                // for CKKS we need to convert vectors of integers to vectors of complex numbers
                plaintext1 = cc->MakeCKKSPackedPlaintext(toComplexDoubleVec(vectorOfInts1), 1, 0, nullptr, testData.slots);
                plaintext2 = cc->MakeCKKSPackedPlaintext(toComplexDoubleVec(vectorOfInts2), 1, 0, nullptr, testData.slots);
                plaintext3 = cc->MakeCKKSPackedPlaintext(toComplexDoubleVec(vectorOfInts3), 1, 0, nullptr, testData.slots);
                plaintextSumInput = cc->MakeCKKSPackedPlaintext(toComplexDoubleVec(sumInput), 1, 0, nullptr, testData.slots);
                plaintextMultInput = cc->MakeCKKSPackedPlaintext(toComplexDoubleVec(multInput), 1, 0, nullptr, testData.slots);
                plaintextEvalSumInput = cc->MakeCKKSPackedPlaintext(toComplexDoubleVec(evalSumInput), 1, 0, nullptr, testData.slots);
                plaintextRotateInput = cc->MakeCKKSPackedPlaintext(toComplexDoubleVec(rotateInput), 1, 0, nullptr, testData.slots);
            }
            else {
                plaintext1 = cc->MakePackedPlaintext(vectorOfInts1);
                plaintext2 = cc->MakePackedPlaintext(vectorOfInts2);
                plaintext3 = cc->MakePackedPlaintext(vectorOfInts3);
                plaintextSumInput = cc->MakePackedPlaintext(sumInput);
                plaintextMultInput = cc->MakePackedPlaintext(multInput);
                plaintextEvalSumInput = cc->MakePackedPlaintext(evalSumInput);
                plaintextRotateInput = cc->MakePackedPlaintext(rotateInput);
            }
            ////////////////////////////////////////////////////////////
            // Encryption
            ////////////////////////////////////////////////////////////
            auto pubKeyForEncryption = testData.star ?
                kp2.publicKey : cc->MultiAddPubKeys(kp1.publicKey, kp2.publicKey, kp2.publicKey->GetKeyTag());
            Ciphertext<Element> ciphertext1 = cc->Encrypt(pubKeyForEncryption, plaintext1);
            Ciphertext<Element> ciphertext2 = cc->Encrypt(pubKeyForEncryption, plaintext2);
            Ciphertext<Element> ciphertext3 = cc->Encrypt(pubKeyForEncryption, plaintext3);

            ////////////////////////////////////////////////////////////
            // EvalAdd Operation on Re-Encrypted Data
            ////////////////////////////////////////////////////////////
            Ciphertext<Element> ciphertextAdd12 = cc->EvalAdd(ciphertext1, ciphertext2);
            Ciphertext<Element> ciphertextAdd123 = cc->EvalAdd(ciphertextAdd12, ciphertext3);

            auto ciphertextMult = cc->EvalMult(ciphertext1, ciphertext3);
            if (CKKSRNS_TEST == testData.testCaseType) {
                ciphertextMult = cc->ModReduce(ciphertextMult);
                ciphertext1 = cc->EvalMult(ciphertext1, 1);
            }
            auto ciphertextEvalSum = cc->EvalSum(ciphertext3, BATCH);
            auto ciphertextRotate = cc->EvalAtIndex(ciphertext1, indices[0]);

            ////////////////////////////////////////////////////////////
            // Decryption after Accumulation Operation on Encrypted Data
            ////////////////////////////////////////////////////////////
            Plaintext plaintextAddNew;
            cc->Decrypt(kpMultiparty.secretKey, ciphertextAdd123, &plaintextAddNew);
            plaintextAddNew->SetLength(plaintext1->GetLength());

            // TODO (dsuponit): we have to rename GetCKKSPackedValue() to GetPackedValue(). it should be an override of the virtual function in plaintext.h
            std::string errMsg = failmsg + " accumulation failed";
            if (CKKSRNS_TEST == testData.testCaseType) {
                checkEquality(
                    plaintextAddNew->GetCKKSPackedValue(),
                    plaintextSumInput->GetCKKSPackedValue(),
                    eps,
                    errMsg);
            }
            else {
                checkEquality(
                    plaintextAddNew->GetPackedValue(),
                    plaintextSumInput->GetPackedValue(),
                    eps,
                    errMsg);
            }
            //====================================================================
            Plaintext plaintextMult;
            cc->Decrypt(kpMultiparty.secretKey, ciphertextMult, &plaintextMult);
            plaintextMult->SetLength(plaintext1->GetLength());

            errMsg = failmsg + " multiplication failed";
            if (CKKSRNS_TEST == testData.testCaseType) {
                checkEquality(
                    plaintextMult->GetCKKSPackedValue(),
                    plaintextMultInput->GetCKKSPackedValue(),
                    eps,
                    errMsg);
            }
            else {
                checkEquality(
                    plaintextMult->GetPackedValue(),
                    plaintextMultInput->GetPackedValue(),
                    eps,
                    errMsg);
            }
            //====================================================================
            Plaintext plaintextRotate;
            cc->Decrypt(kpMultiparty.secretKey, ciphertextRotate, &plaintextRotate);
            plaintextRotate->SetLength(plaintext1->GetLength());

            errMsg = failmsg + " rotation failed";
            if (CKKSRNS_TEST == testData.testCaseType) {
                checkEquality(
                    plaintextRotate->GetCKKSPackedValue(),
                    plaintextRotateInput->GetCKKSPackedValue(),
                    eps,
                    errMsg);
            }
            else {
                checkEquality(
                    plaintextRotate->GetPackedValue(),
                    plaintextRotateInput->GetPackedValue(),
                    eps,
                    errMsg);
            }

            ////////////////////////////////////////////////////////////
            // Decryption after Accumulation Operation on Encrypted Data with Multiparty
            ////////////////////////////////////////////////////////////
            Plaintext plaintextMultipartyNew;
            auto ciphertextPartial1 = cc->MultipartyDecryptLead({ ciphertextAdd123 }, kp1.secretKey);
            auto ciphertextPartial2 = cc->MultipartyDecryptMain({ ciphertextAdd123 }, kp2.secretKey);
            std::vector<Ciphertext<Element>> partialCiphertextVec{ ciphertextPartial1[0], ciphertextPartial2[0] };
            cc->MultipartyDecryptFusion(partialCiphertextVec, &plaintextMultipartyNew);
            plaintextMultipartyNew->SetLength(plaintext1->GetLength());

            errMsg = failmsg + " Multiparty accumulation failed";
            if (CKKSRNS_TEST == testData.testCaseType) {
              std::stringstream buffer;
              buffer << "should be: " << plaintextMultipartyNew->GetCKKSPackedValue() << " - we get: " << plaintextSumInput->GetCKKSPackedValue();

                checkEquality(
                    plaintextMultipartyNew->GetCKKSPackedValue(),
                    plaintextSumInput->GetCKKSPackedValue(),
                    eps,
                    errMsg + buffer.str());
            }
            else {
                checkEquality(
                    plaintextMultipartyNew->GetPackedValue(),
                    plaintextSumInput->GetPackedValue(),
                    eps,
                    errMsg);
            }
            //====================================================================
            if (BGVRNS_TEST == testData.testCaseType && testData.star) { // TODO (dsuponit): is this necessary???
                uint32_t targetTowers = (testData.params.scalTech == FIXEDMANUAL) ? 1 : 2;
                ciphertextMult = cc->Compress(ciphertextMult, targetTowers);
            }
            Plaintext plaintextMultipartyMult;
            ciphertextPartial1 = cc->MultipartyDecryptLead({ ciphertextMult }, kp1.secretKey);
            ciphertextPartial2 = cc->MultipartyDecryptMain({ ciphertextMult }, kp2.secretKey);
            std::vector<Ciphertext<Element>> partialCiphertextVecMult{ ciphertextPartial1[0], ciphertextPartial2[0] };
            cc->MultipartyDecryptFusion(partialCiphertextVecMult, &plaintextMultipartyMult);
            plaintextMultipartyMult->SetLength(plaintext1->GetLength());

            errMsg = failmsg + " Multiparty multiplication failed";
            if (CKKSRNS_TEST == testData.testCaseType) {
                checkEquality(
                    plaintextMultipartyMult->GetCKKSPackedValue(),
                    plaintextMultInput->GetCKKSPackedValue(),
                    eps,
                    errMsg);
            }
            else {
                checkEquality(
                    plaintextMultipartyMult->GetPackedValue(),
                    plaintextMultInput->GetPackedValue(),
                    eps,
                    errMsg);
            }
            //====================================================================
            Plaintext plaintextMultipartyEvalSum;
            ciphertextPartial1 = cc->MultipartyDecryptLead({ ciphertextEvalSum }, kp1.secretKey);
            ciphertextPartial2 = cc->MultipartyDecryptMain({ ciphertextEvalSum }, kp2.secretKey);
            std::vector<Ciphertext<Element>> partialCiphertextVecEvalSum{ ciphertextPartial1[0], ciphertextPartial2[0] };
            cc->MultipartyDecryptFusion(partialCiphertextVecEvalSum, &plaintextMultipartyEvalSum);
            plaintextMultipartyEvalSum->SetLength(plaintext1->GetLength());

            errMsg = failmsg + " Multiparty eval sum failed";
            if (CKKSRNS_TEST == testData.testCaseType) {
                checkEquality(
                    plaintextMultipartyEvalSum->GetCKKSPackedValue(),
                    plaintextEvalSumInput->GetCKKSPackedValue(),
                    eps,
                    errMsg);
            }
            else {
                checkEquality(
                    plaintextMultipartyEvalSum->GetPackedValue(),
                    plaintextEvalSumInput->GetPackedValue(),
                    eps,
                    errMsg);
            }
            //====================================================================
            Plaintext plaintextMultipartyRotate;
            ciphertextPartial1 = cc->MultipartyDecryptLead({ ciphertextRotate }, kp1.secretKey);
            ciphertextPartial2 = cc->MultipartyDecryptMain({ ciphertextRotate }, kp2.secretKey);
            std::vector<Ciphertext<Element>> partialCiphertextVecRotate{ ciphertextPartial1[0], ciphertextPartial2[0] };
            cc->MultipartyDecryptFusion(partialCiphertextVecRotate, &plaintextMultipartyRotate);
            plaintextMultipartyRotate->SetLength(plaintext1->GetLength());

            errMsg = failmsg + " Multiparty rotation failed";
            if (CKKSRNS_TEST == testData.testCaseType) {
                checkEquality(
                    plaintextMultipartyRotate->GetCKKSPackedValue(),
                    plaintextRotateInput->GetCKKSPackedValue(),
                    eps,
                    errMsg);
            }
            else {
                checkEquality(
                    plaintextMultipartyRotate->GetPackedValue(),
                    plaintextRotateInput->GetPackedValue(),
                    eps,
                    errMsg);
            }
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

    void UnitTestMultiparty(const TEST_CASE_UTGENERAL_MULTIPARTY& testData, const std::string& failmsg = std::string()) {
        try {
            CryptoContext<Element> cc(UnitTestGenerateContext(testData.params));

            ////////////////////////////////////////////////////////////
            // Perform Key Generation Operation
            ////////////////////////////////////////////////////////////

            KeyPair<Element> kp1 = cc->KeyGen();
            ASSERT_TRUE(kp1.good()) << failmsg + "kp1 generation failed!";

            KeyPair<Element> kp2 = cc->MultipartyKeyGen(kp1.publicKey, false, true);
            ASSERT_TRUE(kp2.good()) << failmsg + "kp2 generation failed!";

            KeyPair<Element> kp3 = cc->MultipartyKeyGen(kp1.publicKey, false, true);
            ASSERT_TRUE(kp3.good()) << failmsg + "kp3 generation failed!";

            ////////////////////////////////////////////////////////////
            // Perform the second key generation operation.
            // This generates the keys which should be able to decrypt the ciphertext
            // after the re-encryption operation.
            ////////////////////////////////////////////////////////////

            std::vector<PrivateKey<Element>> secretKeys{ kp1.secretKey, kp2.secretKey, kp3.secretKey };
            KeyPair<Element> kpMultiparty = cc->MultipartyKeyGen(secretKeys);  // This is the same core key generation operation.
            ASSERT_TRUE(kpMultiparty.good()) << "kpMultiparty generation failed!";

            ////////////////////////////////////////////////////////////
            // Perform the proxy re-encryption key generation operation.
            // This generates the keys which are used to perform the key switching.
            ////////////////////////////////////////////////////////////

            EvalKey<Element> evalKey1 = cc->ReKeyGen(kp1.secretKey, kpMultiparty.publicKey);
            EvalKey<Element> evalKey2 = cc->ReKeyGen(kp2.secretKey, kpMultiparty.publicKey);
            EvalKey<Element> evalKey3 = cc->ReKeyGen(kp3.secretKey, kpMultiparty.publicKey);

            ////////////////////////////////////////////////////////////
            // Encode source data
            ////////////////////////////////////////////////////////////
            std::vector<int64_t> vectorOfInts1 = { 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0 };
            std::vector<int64_t> vectorOfInts2 = { 1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0 };
            std::vector<int64_t> vectorOfInts3 = { 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0 };
            Plaintext plaintext1 = cc->MakeCoefPackedPlaintext(vectorOfInts1);
            Plaintext plaintext2 = cc->MakeCoefPackedPlaintext(vectorOfInts2);
            Plaintext plaintext3 = cc->MakeCoefPackedPlaintext(vectorOfInts3);

            auto plaintextModulus = cc->GetCryptoParameters()->GetPlaintextModulus();
            int64_t half(plaintextModulus >> 1);
            std::vector<int64_t> vectorOfIntsSum(vectorOfInts1.size());
            for (size_t i = 0; i < vectorOfInts1.size(); i++) {
                int64_t value = (vectorOfInts1[i] + vectorOfInts2[i] + vectorOfInts3[i]) % plaintextModulus;
                if (value > half)
                    value -= plaintextModulus;
                vectorOfIntsSum[i] = value;
            }

            ////////////////////////////////////////////////////////////
            // Encryption
            ////////////////////////////////////////////////////////////

            Ciphertext<Element> ciphertext1 = cc->Encrypt(kp1.publicKey, plaintext1);
            Ciphertext<Element> ciphertext2 = cc->Encrypt(kp2.publicKey, plaintext2);
            Ciphertext<Element> ciphertext3 = cc->Encrypt(kp3.publicKey, plaintext3);

            ////////////////////////////////////////////////////////////
            // Re-Encryption
            ////////////////////////////////////////////////////////////

            Ciphertext<Element> ciphertext1New = cc->ReEncrypt(ciphertext1, evalKey1);
            Ciphertext<Element> ciphertext2New = cc->ReEncrypt(ciphertext2, evalKey2);
            Ciphertext<Element> ciphertext3New = cc->ReEncrypt(ciphertext3, evalKey3);

            ////////////////////////////////////////////////////////////
            // EvalAdd Operation on Re-Encrypted Data
            ////////////////////////////////////////////////////////////

            Ciphertext<Element> ciphertextAddNew12 = cc->EvalAdd(ciphertext1New, ciphertext2New);
            Ciphertext<Element> ciphertextAddNew = cc->EvalAdd(ciphertextAddNew12, ciphertext3New);

            ////////////////////////////////////////////////////////////
            // Decryption after Accumulation Operation on Re-Encrypted Data
            ////////////////////////////////////////////////////////////

            Plaintext plaintextAddNew;
            cc->Decrypt(kpMultiparty.secretKey, ciphertextAddNew, &plaintextAddNew);
            plaintextAddNew->SetLength(plaintext1->GetLength());

            ////////////////////////////////////////////////////////////
            // Decryption after Accumulation Operation on Re-Encrypted Data with
            // Multiparty
            ////////////////////////////////////////////////////////////

            auto ciphertextPartial1 = cc->MultipartyDecryptLead({ ciphertextAddNew }, kp1.secretKey);
            auto ciphertextPartial2 = cc->MultipartyDecryptMain({ ciphertextAddNew }, kp2.secretKey);
            auto ciphertextPartial3 = cc->MultipartyDecryptMain({ ciphertextAddNew }, kp3.secretKey);

            std::vector<Ciphertext<Element>> partialCiphertextVec{
                ciphertextPartial1[0],
                ciphertextPartial2[0],
                ciphertextPartial3[0] };

            Plaintext plaintextMultipartyNew;
            cc->MultipartyDecryptFusion(partialCiphertextVec, &plaintextMultipartyNew);
            plaintextMultipartyNew->SetLength(plaintext1->GetLength());

            const double eps = EPSILON;
            std::string errMsg = failmsg + " Multiparty: Does not match plaintext addition";
            checkEquality(
                vectorOfIntsSum,
                plaintextMultipartyNew->GetCoefPackedValue(),
                eps,
                errMsg);

            errMsg = failmsg + " Multiparty: Does not match the results of direction encryption";
            checkEquality(
                plaintextAddNew->GetCoefPackedValue(),
                plaintextMultipartyNew->GetCoefPackedValue(),
                eps,
                errMsg);
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
TEST_P(UTGENERAL_MULTIPARTY, Multiparty) {
    setupSignals();
    auto test = GetParam();
    if (test.testCaseType == BFVRNS_TEST_EXTRA)
        UnitTestMultiparty(test, test.buildTestName());
    else
        UnitTest_MultiParty(test, test.buildTestName());
}

INSTANTIATE_TEST_SUITE_P(UnitTests, UTGENERAL_MULTIPARTY, ::testing::ValuesIn(testCases), testName);

