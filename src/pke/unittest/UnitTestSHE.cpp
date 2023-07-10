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
  unit tests for the SHE capabilities
 */

#include "UnitTestUtils.h"
#include "UnitTestCCParams.h"
#include "UnitTestCryptoContext.h"
#include "UnitTestMetadataTest.h"

#include <iostream>
#include <vector>
#include "gtest/gtest.h"
#include <cxxabi.h>
#include "utils/demangle.h"

using namespace lbcrypto;

//===========================================================================================================
enum TEST_CASE_TYPE {
    ADD_PACKED = 0,
    MULT_COEF_PACKED,
    MULT_PACKED,
    EVALATINDEX,
    EVALMERGE,
    EVALSUM,
    METADATA,
    EVALSUM_ALL,
    KS_SINGLE_CRT,
    KS_MOD_REDUCE_DCRT,
    EVALSQUARE,
    RING_DIM_ERROR_HANDLING
};

static std::ostream& operator<<(std::ostream& os, const TEST_CASE_TYPE& type) {
    std::string typeName;
    switch (type) {
        case ADD_PACKED:
            typeName = "ADD_PACKED";
            break;
        case MULT_COEF_PACKED:
            typeName = "MULT_COEF_PACKED";
            break;
        case MULT_PACKED:
            typeName = "MULT_PACKED";
            break;
        case EVALATINDEX:
            typeName = "EVALATINDEX";
            break;
        case EVALMERGE:
            typeName = "EVALMERGE";
            break;
        case EVALSUM:
            typeName = "EVALSUM";
            break;
        case METADATA:
            typeName = "METADATA";
            break;
        case EVALSUM_ALL:
            typeName = "EVALSUM_ALL";
            break;
        case KS_SINGLE_CRT:
            typeName = "KS_SINGLE_CRT";
            break;
        case KS_MOD_REDUCE_DCRT:
            typeName = "KS_MOD_REDUCE_DCRT";
            break;
        case EVALSQUARE:
            typeName = "EVALSQUARE";
            break;
        case RING_DIM_ERROR_HANDLING:
            typeName = "RING_DIM_ERROR_HANDLING";
            break;
        default:
            typeName = "UNKNOWN";
            break;
    }
    return os << typeName;
}
//===========================================================================================================
struct TEST_CASE_UTGENERAL_SHE {
    TEST_CASE_TYPE testCaseType;
    // test case description - MUST BE UNIQUE
    std::string description;

    UnitTestCCParams params;

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
static auto testName = [](const testing::TestParamInfo<TEST_CASE_UTGENERAL_SHE>& test) {
    return test.param.buildTestName();
};

static std::ostream& operator<<(std::ostream& os, const TEST_CASE_UTGENERAL_SHE& test) {
    return os << test.toString();
}
//===========================================================================================================
// NOTE the SHE tests are all based on these
constexpr usint BATCH     = 16;
constexpr usint BATCH_LRG = 1 << 12;
constexpr usint PTM       = 64;
constexpr usint PTM_LRG   = 65537;
constexpr usint BV_DSIZE  = 4;
// clang-format off
static std::vector<TEST_CASE_UTGENERAL_SHE> testCases = {
    // TestType,  Descr, Scheme,        RDim, MultDepth, SModSize, DSize,    BatchSz, SecKeyDist,      MaxRelinSkDeg, FModSize, SecLvl,       KSTech, ScalTech,        LDigits, PtMod, StdDev, EvalAddCt, KSCt, MultTech,         EncTech,   PREMode
    { ADD_PACKED, "01", {BGVRNS_SCHEME, 16,   2,         DFLT,     BV_DSIZE, BATCH,   UNIFORM_TERNARY, 1,             60,       HEStd_NotSet, BV,     FIXEDMANUAL,     DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,             STANDARD,  DFLT}, },
    { ADD_PACKED, "02", {BGVRNS_SCHEME, 16,   2,         DFLT,     BV_DSIZE, BATCH,   UNIFORM_TERNARY, 1,             60,       HEStd_NotSet, BV,     FIXEDAUTO,       DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,             STANDARD,  DFLT}, },
    { ADD_PACKED, "03", {BGVRNS_SCHEME, 16,   2,         DFLT,     BV_DSIZE, BATCH,   UNIFORM_TERNARY, 1,             60,       HEStd_NotSet, BV,     FLEXIBLEAUTO,    DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,             STANDARD,  DFLT}, },
    { ADD_PACKED, "04", {BGVRNS_SCHEME, 16,   2,         DFLT,     BV_DSIZE, BATCH,   UNIFORM_TERNARY, 1,             60,       HEStd_NotSet, BV,     FLEXIBLEAUTOEXT, DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,             STANDARD,  DFLT}, },
    { ADD_PACKED, "05", {BGVRNS_SCHEME, 16,   2,         DFLT,     BV_DSIZE, BATCH,   GAUSSIAN,        1,             60,       HEStd_NotSet, BV,     FIXEDMANUAL,     DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,             STANDARD,  DFLT}, },
    { ADD_PACKED, "06", {BGVRNS_SCHEME, 16,   2,         DFLT,     BV_DSIZE, BATCH,   GAUSSIAN,        1,             60,       HEStd_NotSet, BV,     FIXEDAUTO,       DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,             STANDARD,  DFLT}, },
    { ADD_PACKED, "07", {BGVRNS_SCHEME, 16,   2,         DFLT,     BV_DSIZE, BATCH,   GAUSSIAN,        1,             60,       HEStd_NotSet, BV,     FLEXIBLEAUTO,    DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,             STANDARD,  DFLT}, },
    { ADD_PACKED, "08", {BGVRNS_SCHEME, 16,   2,         DFLT,     BV_DSIZE, BATCH,   GAUSSIAN,        1,             60,       HEStd_NotSet, BV,     FLEXIBLEAUTOEXT, DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,             STANDARD,  DFLT}, },
    { ADD_PACKED, "09", {BFVRNS_SCHEME, DFLT, 0,         DFLT,     20,       BATCH,   UNIFORM_TERNARY, DFLT,          DFLT,     DFLT,         BV,     DFLT,            DFLT,    PTM,   DFLT,      1,      DFLT, HPS,              STANDARD,  DFLT}, },
    { ADD_PACKED, "10", {BFVRNS_SCHEME, DFLT, 0,         DFLT,     20,       BATCH,   GAUSSIAN,        DFLT,          DFLT,     DFLT,         BV,     DFLT,            DFLT,    PTM,   DFLT,      1,      DFLT, HPS,              STANDARD,  DFLT}, },
    { ADD_PACKED, "11", {BFVRNS_SCHEME, DFLT, 0,         DFLT,     20,       BATCH,   UNIFORM_TERNARY, DFLT,          DFLT,     DFLT,         BV,     DFLT,            DFLT,    PTM,   DFLT,      1,      DFLT, BEHZ,             STANDARD,  DFLT}, },
    { ADD_PACKED, "12", {BFVRNS_SCHEME, DFLT, 0,         DFLT,     20,       BATCH,   GAUSSIAN,        DFLT,          DFLT,     DFLT,         BV,     DFLT,            DFLT,    PTM,   DFLT,      1,      DFLT, BEHZ,             STANDARD,  DFLT}, },
    { ADD_PACKED, "13", {BFVRNS_SCHEME, DFLT, 0,         DFLT,     20,       BATCH,   UNIFORM_TERNARY, DFLT,          DFLT,     DFLT,         BV,     DFLT,            DFLT,    PTM,   DFLT,      1,      DFLT, HPSPOVERQ,        STANDARD,  DFLT}, },
    { ADD_PACKED, "14", {BFVRNS_SCHEME, DFLT, 0,         DFLT,     20,       BATCH,   GAUSSIAN,        DFLT,          DFLT,     DFLT,         BV,     DFLT,            DFLT,    PTM,   DFLT,      1,      DFLT, HPSPOVERQ,        STANDARD,  DFLT}, },
    { ADD_PACKED, "15", {BFVRNS_SCHEME, DFLT, 0,         DFLT,     20,       BATCH,   UNIFORM_TERNARY, DFLT,          DFLT,     DFLT,         BV,     DFLT,            DFLT,    PTM,   DFLT,      1,      DFLT, HPSPOVERQLEVELED, STANDARD,  DFLT}, },
    { ADD_PACKED, "16", {BFVRNS_SCHEME, DFLT, 0,         DFLT,     20,       BATCH,   GAUSSIAN,        DFLT,          DFLT,     DFLT,         BV,     DFLT,            DFLT,    PTM,   DFLT,      1,      DFLT, HPSPOVERQLEVELED, STANDARD,  DFLT}, },
    { ADD_PACKED, "17", {BFVRNS_SCHEME, DFLT, 0,         DFLT,     20,       BATCH,   UNIFORM_TERNARY, DFLT,          DFLT,     DFLT,         HYBRID, DFLT,            DFLT,    PTM,   DFLT,      1,      DFLT, HPS,              STANDARD,  DFLT}, },
    { ADD_PACKED, "18", {BFVRNS_SCHEME, DFLT, 0,         DFLT,     20,       BATCH,   GAUSSIAN,        DFLT,          DFLT,     DFLT,         HYBRID, DFLT,            DFLT,    PTM,   DFLT,      1,      DFLT, HPS,              STANDARD,  DFLT}, },
    { ADD_PACKED, "19", {BFVRNS_SCHEME, DFLT, 0,         DFLT,     20,       BATCH,   UNIFORM_TERNARY, DFLT,          DFLT,     DFLT,         HYBRID, DFLT,            DFLT,    PTM,   DFLT,      1,      DFLT, BEHZ,             STANDARD,  DFLT}, },
    { ADD_PACKED, "20", {BFVRNS_SCHEME, DFLT, 0,         DFLT,     20,       BATCH,   GAUSSIAN,        DFLT,          DFLT,     DFLT,         HYBRID, DFLT,            DFLT,    PTM,   DFLT,      1,      DFLT, BEHZ,             STANDARD,  DFLT}, },
    { ADD_PACKED, "21", {BFVRNS_SCHEME, DFLT, 0,         DFLT,     20,       BATCH,   UNIFORM_TERNARY, DFLT,          DFLT,     DFLT,         HYBRID, DFLT,            DFLT,    PTM,   DFLT,      1,      DFLT, HPSPOVERQ,        STANDARD,  DFLT}, },
    { ADD_PACKED, "22", {BFVRNS_SCHEME, DFLT, 0,         DFLT,     20,       BATCH,   GAUSSIAN,        DFLT,          DFLT,     DFLT,         HYBRID, DFLT,            DFLT,    PTM,   DFLT,      1,      DFLT, HPSPOVERQ,        STANDARD,  DFLT}, },
    { ADD_PACKED, "23", {BFVRNS_SCHEME, DFLT, 0,         DFLT,     20,       BATCH,   UNIFORM_TERNARY, DFLT,          DFLT,     DFLT,         HYBRID, DFLT,            DFLT,    PTM,   DFLT,      1,      DFLT, HPSPOVERQLEVELED, STANDARD,  DFLT}, },
    { ADD_PACKED, "24", {BFVRNS_SCHEME, DFLT, 0,         DFLT,     20,       BATCH,   GAUSSIAN,        DFLT,          DFLT,     DFLT,         HYBRID, DFLT,            DFLT,    PTM,   DFLT,      1,      DFLT, HPSPOVERQLEVELED, STANDARD,  DFLT}, },
    { ADD_PACKED, "25", {BFVRNS_SCHEME, DFLT, 0,         DFLT,     20,       BATCH,   UNIFORM_TERNARY, DFLT,          DFLT,     DFLT,         BV,     DFLT,            DFLT,    PTM,   DFLT,      1,      DFLT, HPS,              EXTENDED,  DFLT}, },
    { ADD_PACKED, "26", {BFVRNS_SCHEME, DFLT, 0,         DFLT,     20,       BATCH,   GAUSSIAN,        DFLT,          DFLT,     DFLT,         BV,     DFLT,            DFLT,    PTM,   DFLT,      1,      DFLT, HPS,              EXTENDED,  DFLT}, },
    { ADD_PACKED, "27", {BFVRNS_SCHEME, DFLT, 0,         DFLT,     20,       BATCH,   UNIFORM_TERNARY, DFLT,          DFLT,     DFLT,         BV,     DFLT,            DFLT,    PTM,   DFLT,      1,      DFLT, BEHZ,             EXTENDED,  DFLT}, },
    { ADD_PACKED, "28", {BFVRNS_SCHEME, DFLT, 0,         DFLT,     20,       BATCH,   GAUSSIAN,        DFLT,          DFLT,     DFLT,         BV,     DFLT,            DFLT,    PTM,   DFLT,      1,      DFLT, BEHZ,             EXTENDED,  DFLT}, },
    { ADD_PACKED, "29", {BFVRNS_SCHEME, DFLT, 0,         DFLT,     20,       BATCH,   UNIFORM_TERNARY, DFLT,          DFLT,     DFLT,         BV,     DFLT,            DFLT,    PTM,   DFLT,      1,      DFLT, HPSPOVERQ,        EXTENDED,  DFLT}, },
    { ADD_PACKED, "30", {BFVRNS_SCHEME, DFLT, 0,         DFLT,     20,       BATCH,   GAUSSIAN,        DFLT,          DFLT,     DFLT,         BV,     DFLT,            DFLT,    PTM,   DFLT,      1,      DFLT, HPSPOVERQ,        EXTENDED,  DFLT}, },
    { ADD_PACKED, "31", {BFVRNS_SCHEME, DFLT, 0,         DFLT,     20,       BATCH,   UNIFORM_TERNARY, DFLT,          DFLT,     DFLT,         BV,     DFLT,            DFLT,    PTM,   DFLT,      1,      DFLT, HPSPOVERQLEVELED, EXTENDED,  DFLT}, },
    { ADD_PACKED, "32", {BFVRNS_SCHEME, DFLT, 0,         DFLT,     20,       BATCH,   GAUSSIAN,        DFLT,          DFLT,     DFLT,         BV,     DFLT,            DFLT,    PTM,   DFLT,      1,      DFLT, HPSPOVERQLEVELED, EXTENDED,  DFLT}, },
    { ADD_PACKED, "33", {BFVRNS_SCHEME, DFLT, 0,         DFLT,     20,       BATCH,   UNIFORM_TERNARY, DFLT,          DFLT,     DFLT,         HYBRID, DFLT,            DFLT,    PTM,   DFLT,      1,      DFLT, HPS,              EXTENDED,  DFLT}, },
    { ADD_PACKED, "34", {BFVRNS_SCHEME, DFLT, 0,         DFLT,     20,       BATCH,   GAUSSIAN,        DFLT,          DFLT,     DFLT,         HYBRID, DFLT,            DFLT,    PTM,   DFLT,      1,      DFLT, HPS,              EXTENDED,  DFLT}, },
    { ADD_PACKED, "35", {BFVRNS_SCHEME, DFLT, 0,         DFLT,     20,       BATCH,   UNIFORM_TERNARY, DFLT,          DFLT,     DFLT,         HYBRID, DFLT,            DFLT,    PTM,   DFLT,      1,      DFLT, BEHZ,             EXTENDED,  DFLT}, },
    { ADD_PACKED, "36", {BFVRNS_SCHEME, DFLT, 0,         DFLT,     20,       BATCH,   GAUSSIAN,        DFLT,          DFLT,     DFLT,         HYBRID, DFLT,            DFLT,    PTM,   DFLT,      1,      DFLT, BEHZ,             EXTENDED,  DFLT}, },
    { ADD_PACKED, "37", {BFVRNS_SCHEME, DFLT, 0,         DFLT,     20,       BATCH,   UNIFORM_TERNARY, DFLT,          DFLT,     DFLT,         HYBRID, DFLT,            DFLT,    PTM,   DFLT,      1,      DFLT, HPSPOVERQ,        EXTENDED,  DFLT}, },
    { ADD_PACKED, "38", {BFVRNS_SCHEME, DFLT, 0,         DFLT,     20,       BATCH,   GAUSSIAN,        DFLT,          DFLT,     DFLT,         HYBRID, DFLT,            DFLT,    PTM,   DFLT,      1,      DFLT, HPSPOVERQ,        EXTENDED,  DFLT}, },
    { ADD_PACKED, "39", {BFVRNS_SCHEME, DFLT, 0,         DFLT,     20,       BATCH,   UNIFORM_TERNARY, DFLT,          DFLT,     DFLT,         HYBRID, DFLT,            DFLT,    PTM,   DFLT,      1,      DFLT, HPSPOVERQLEVELED, EXTENDED,  DFLT}, },
    { ADD_PACKED, "40", {BFVRNS_SCHEME, DFLT, 0,         DFLT,     20,       BATCH,   GAUSSIAN,        DFLT,          DFLT,     DFLT,         HYBRID, DFLT,            DFLT,    PTM,   DFLT,      1,      DFLT, HPSPOVERQLEVELED, EXTENDED,  DFLT}, },
    // ==========================================
    // TestType,        Descr, Scheme,        RDim, MultDepth, SModSize, DSize,    BatchSz, SecKeyDist,       MaxRelinSkDeg, FModSize, SecLvl,       KSTech, ScalTech,        LDigits, PtMod, StdDev, EvalAddCt, KSCt, MultTech,         EncTech,   PREMode
    { MULT_COEF_PACKED, "01", {BGVRNS_SCHEME, 16,   2,         DFLT,     BV_DSIZE, BATCH,   UNIFORM_TERNARY,  1,             60,       HEStd_NotSet, BV,     FIXEDMANUAL,     DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,             STANDARD,  DFLT}, },
    { MULT_COEF_PACKED, "02", {BGVRNS_SCHEME, 16,   2,         DFLT,     BV_DSIZE, BATCH,   UNIFORM_TERNARY,  1,             60,       HEStd_NotSet, BV,     FIXEDAUTO,       DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,             STANDARD,  DFLT}, },
    { MULT_COEF_PACKED, "03", {BGVRNS_SCHEME, 16,   2,         DFLT,     BV_DSIZE, BATCH,   UNIFORM_TERNARY,  1,             60,       HEStd_NotSet, BV,     FLEXIBLEAUTO,    DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,             STANDARD,  DFLT}, },
    { MULT_COEF_PACKED, "04", {BGVRNS_SCHEME, 16,   2,         DFLT,     BV_DSIZE, BATCH,   UNIFORM_TERNARY,  1,             60,       HEStd_NotSet, BV,     FLEXIBLEAUTOEXT, DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,             STANDARD,  DFLT}, },
    { MULT_COEF_PACKED, "05", {BGVRNS_SCHEME, 16,   2,         DFLT,     BV_DSIZE, BATCH,   GAUSSIAN,         1,             60,       HEStd_NotSet, BV,     FIXEDMANUAL,     DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,             STANDARD,  DFLT}, },
    { MULT_COEF_PACKED, "06", {BGVRNS_SCHEME, 16,   2,         DFLT,     BV_DSIZE, BATCH,   GAUSSIAN,         1,             60,       HEStd_NotSet, BV,     FIXEDAUTO,       DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,             STANDARD,  DFLT}, },
    { MULT_COEF_PACKED, "07", {BGVRNS_SCHEME, 16,   2,         DFLT,     BV_DSIZE, BATCH,   GAUSSIAN,         1,             60,       HEStd_NotSet, BV,     FLEXIBLEAUTO,    DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,             STANDARD,  DFLT}, },
    { MULT_COEF_PACKED, "08", {BGVRNS_SCHEME, 16,   2,         DFLT,     BV_DSIZE, BATCH,   GAUSSIAN,         1,             60,       HEStd_NotSet, BV,     FLEXIBLEAUTOEXT, DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,             STANDARD,  DFLT}, },
    { MULT_COEF_PACKED, "09", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   UNIFORM_TERNARY,  DFLT,          DFLT,     DFLT,         BV,     DFLT,            DFLT,    PTM,   DFLT,   DFLT,      DFLT, HPS,              STANDARD,  DFLT}, },
    { MULT_COEF_PACKED, "10", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   GAUSSIAN,         DFLT,          DFLT,     DFLT,         BV,     DFLT,            DFLT,    PTM,   DFLT,   DFLT,      DFLT, HPS,              STANDARD,  DFLT}, },
    { MULT_COEF_PACKED, "11", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   UNIFORM_TERNARY,  DFLT,          DFLT,     DFLT,         BV,     DFLT,            DFLT,    PTM,   DFLT,   DFLT,      DFLT, BEHZ,             STANDARD,  DFLT}, },
    { MULT_COEF_PACKED, "12", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   GAUSSIAN,         DFLT,          DFLT,     DFLT,         BV,     DFLT,            DFLT,    PTM,   DFLT,   DFLT,      DFLT, BEHZ,             STANDARD,  DFLT}, },
    { MULT_COEF_PACKED, "13", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   UNIFORM_TERNARY,  DFLT,          DFLT,     DFLT,         BV,     DFLT,            DFLT,    PTM,   DFLT,   DFLT,      DFLT, HPSPOVERQ,        STANDARD,  DFLT}, },
    { MULT_COEF_PACKED, "14", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   GAUSSIAN,         DFLT,          DFLT,     DFLT,         BV,     DFLT,            DFLT,    PTM,   DFLT,   DFLT,      DFLT, HPSPOVERQ,        STANDARD,  DFLT}, },
    { MULT_COEF_PACKED, "15", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   UNIFORM_TERNARY,  DFLT,          DFLT,     DFLT,         BV,     DFLT,            DFLT,    PTM,   DFLT,   DFLT,      DFLT, HPSPOVERQLEVELED, STANDARD,  DFLT}, },
    { MULT_COEF_PACKED, "16", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   GAUSSIAN,         DFLT,          DFLT,     DFLT,         BV,     DFLT,            DFLT,    PTM,   DFLT,   DFLT,      DFLT, HPSPOVERQLEVELED, STANDARD,  DFLT}, },
    { MULT_COEF_PACKED, "17", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   UNIFORM_TERNARY,  DFLT,          DFLT,     DFLT,         HYBRID, DFLT,            DFLT,    PTM,   DFLT,   DFLT,      DFLT, HPS,              STANDARD,  DFLT}, },
    { MULT_COEF_PACKED, "18", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   GAUSSIAN,         DFLT,          DFLT,     DFLT,         HYBRID, DFLT,            DFLT,    PTM,   DFLT,   DFLT,      DFLT, HPS,              STANDARD,  DFLT}, },
    { MULT_COEF_PACKED, "19", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   UNIFORM_TERNARY,  DFLT,          DFLT,     DFLT,         HYBRID, DFLT,            DFLT,    PTM,   DFLT,   DFLT,      DFLT, BEHZ,             STANDARD,  DFLT}, },
    { MULT_COEF_PACKED, "20", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   GAUSSIAN,         DFLT,          DFLT,     DFLT,         HYBRID, DFLT,            DFLT,    PTM,   DFLT,   DFLT,      DFLT, BEHZ,             STANDARD,  DFLT}, },
    { MULT_COEF_PACKED, "21", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   UNIFORM_TERNARY,  DFLT,          DFLT,     DFLT,         HYBRID, DFLT,            DFLT,    PTM,   DFLT,   DFLT,      DFLT, HPSPOVERQ,        STANDARD,  DFLT}, },
    { MULT_COEF_PACKED, "22", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   GAUSSIAN,         DFLT,          DFLT,     DFLT,         HYBRID, DFLT,            DFLT,    PTM,   DFLT,   DFLT,      DFLT, HPSPOVERQ,        STANDARD,  DFLT}, },
    { MULT_COEF_PACKED, "23", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   UNIFORM_TERNARY,  DFLT,          DFLT,     DFLT,         HYBRID, DFLT,            DFLT,    PTM,   DFLT,   DFLT,      DFLT, HPSPOVERQLEVELED, STANDARD,  DFLT}, },
    { MULT_COEF_PACKED, "24", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   GAUSSIAN,         DFLT,          DFLT,     DFLT,         HYBRID, DFLT,            DFLT,    PTM,   DFLT,   DFLT,      DFLT, HPSPOVERQLEVELED, STANDARD,  DFLT}, },
    { MULT_COEF_PACKED, "25", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   UNIFORM_TERNARY,  DFLT,          DFLT,     DFLT,         BV,     DFLT,            DFLT,    PTM,   DFLT,   DFLT,      DFLT, HPS,              EXTENDED,  DFLT}, },
    { MULT_COEF_PACKED, "26", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   GAUSSIAN,         DFLT,          DFLT,     DFLT,         BV,     DFLT,            DFLT,    PTM,   DFLT,   DFLT,      DFLT, HPS,              EXTENDED,  DFLT}, },
    { MULT_COEF_PACKED, "27", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   UNIFORM_TERNARY,  DFLT,          DFLT,     DFLT,         BV,     DFLT,            DFLT,    PTM,   DFLT,   DFLT,      DFLT, BEHZ,             EXTENDED,  DFLT}, },
    { MULT_COEF_PACKED, "28", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   GAUSSIAN,         DFLT,          DFLT,     DFLT,         BV,     DFLT,            DFLT,    PTM,   DFLT,   DFLT,      DFLT, BEHZ,             EXTENDED,  DFLT}, },
    { MULT_COEF_PACKED, "29", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   UNIFORM_TERNARY,  DFLT,          DFLT,     DFLT,         BV,     DFLT,            DFLT,    PTM,   DFLT,   DFLT,      DFLT, HPSPOVERQ,        EXTENDED,  DFLT}, },
    { MULT_COEF_PACKED, "30", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   GAUSSIAN,         DFLT,          DFLT,     DFLT,         BV,     DFLT,            DFLT,    PTM,   DFLT,   DFLT,      DFLT, HPSPOVERQ,        EXTENDED,  DFLT}, },
    { MULT_COEF_PACKED, "31", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   UNIFORM_TERNARY,  DFLT,          DFLT,     DFLT,         BV,     DFLT,            DFLT,    PTM,   DFLT,   DFLT,      DFLT, HPSPOVERQLEVELED, EXTENDED,  DFLT}, },
    { MULT_COEF_PACKED, "32", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   GAUSSIAN,         DFLT,          DFLT,     DFLT,         BV,     DFLT,            DFLT,    PTM,   DFLT,   DFLT,      DFLT, HPSPOVERQLEVELED, EXTENDED,  DFLT}, },
    { MULT_COEF_PACKED, "33", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   UNIFORM_TERNARY,  DFLT,          DFLT,     DFLT,         HYBRID, DFLT,            DFLT,    PTM,   DFLT,   DFLT,      DFLT, HPS,              EXTENDED,  DFLT}, },
    { MULT_COEF_PACKED, "34", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   GAUSSIAN,         DFLT,          DFLT,     DFLT,         HYBRID, DFLT,            DFLT,    PTM,   DFLT,   DFLT,      DFLT, HPS,              EXTENDED,  DFLT}, },
    { MULT_COEF_PACKED, "35", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   UNIFORM_TERNARY,  DFLT,          DFLT,     DFLT,         HYBRID, DFLT,            DFLT,    PTM,   DFLT,   DFLT,      DFLT, BEHZ,             EXTENDED,  DFLT}, },
    { MULT_COEF_PACKED, "36", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   GAUSSIAN,         DFLT,          DFLT,     DFLT,         HYBRID, DFLT,            DFLT,    PTM,   DFLT,   DFLT,      DFLT, BEHZ,             EXTENDED,  DFLT}, },
    { MULT_COEF_PACKED, "37", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   UNIFORM_TERNARY,  DFLT,          DFLT,     DFLT,         HYBRID, DFLT,            DFLT,    PTM,   DFLT,   DFLT,      DFLT, HPSPOVERQ,        EXTENDED,  DFLT}, },
    { MULT_COEF_PACKED, "38", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   GAUSSIAN,         DFLT,          DFLT,     DFLT,         HYBRID, DFLT,            DFLT,    PTM,   DFLT,   DFLT,      DFLT, HPSPOVERQ,        EXTENDED,  DFLT}, },
    { MULT_COEF_PACKED, "39", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   UNIFORM_TERNARY,  DFLT,          DFLT,     DFLT,         HYBRID, DFLT,            DFLT,    PTM,   DFLT,   DFLT,      DFLT, HPSPOVERQLEVELED, EXTENDED,  DFLT}, },
    { MULT_COEF_PACKED, "40", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   GAUSSIAN,         DFLT,          DFLT,     DFLT,         HYBRID, DFLT,            DFLT,    PTM,   DFLT,   DFLT,      DFLT, HPSPOVERQLEVELED, EXTENDED,  DFLT}, },
    // ==========================================
    // TestType,   Descr, Scheme,        RDim, MultDepth, SModSize, DSize,    BatchSz, SecKeyDist,       MaxRelinSkDeg, FModSize, SecLvl,       KSTech, ScalTech,        LDigits, PtMod,   StdDev, EvalAddCt, KSCt, MultTech,         EncTech,   PREMode
    { MULT_PACKED, "01", {BGVRNS_SCHEME, 256,  2,         DFLT,     BV_DSIZE, BATCH,   UNIFORM_TERNARY,  1,             60,       HEStd_NotSet, BV,     FIXEDMANUAL,     DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, DFLT,             STANDARD,  DFLT}, },
    { MULT_PACKED, "02", {BGVRNS_SCHEME, 256,  2,         DFLT,     BV_DSIZE, BATCH,   UNIFORM_TERNARY,  1,             60,       HEStd_NotSet, BV,     FIXEDAUTO,       DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, DFLT,             STANDARD,  DFLT}, },
    { MULT_PACKED, "03", {BGVRNS_SCHEME, 256,  2,         DFLT,     BV_DSIZE, BATCH,   UNIFORM_TERNARY,  1,             60,       HEStd_NotSet, BV,     FLEXIBLEAUTO,    DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, DFLT,             STANDARD,  DFLT}, },
    { MULT_PACKED, "04", {BGVRNS_SCHEME, 256,  2,         DFLT,     BV_DSIZE, BATCH,   UNIFORM_TERNARY,  1,             60,       HEStd_NotSet, BV,     FLEXIBLEAUTOEXT, DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, DFLT,             STANDARD,  DFLT}, },
    { MULT_PACKED, "05", {BGVRNS_SCHEME, 256,  2,         DFLT,     BV_DSIZE, BATCH,   GAUSSIAN,         1,             60,       HEStd_NotSet, BV,     FIXEDMANUAL,     DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, DFLT,             STANDARD,  DFLT}, },
    { MULT_PACKED, "06", {BGVRNS_SCHEME, 256,  2,         DFLT,     BV_DSIZE, BATCH,   GAUSSIAN,         1,             60,       HEStd_NotSet, BV,     FIXEDAUTO,       DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, DFLT,             STANDARD,  DFLT}, },
    { MULT_PACKED, "07", {BGVRNS_SCHEME, 256,  2,         DFLT,     BV_DSIZE, BATCH,   GAUSSIAN,         1,             60,       HEStd_NotSet, BV,     FLEXIBLEAUTO,    DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, DFLT,             STANDARD,  DFLT}, },
    { MULT_PACKED, "08", {BGVRNS_SCHEME, 256,  2,         DFLT,     BV_DSIZE, BATCH,   GAUSSIAN,         1,             60,       HEStd_NotSet, BV,     FLEXIBLEAUTOEXT, DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, DFLT,             STANDARD,  DFLT}, },
    { MULT_PACKED, "09", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   UNIFORM_TERNARY,  DFLT,          DFLT,     DFLT,         BV,     DFLT,            DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, HPS,              STANDARD,  DFLT}, },
    { MULT_PACKED, "10", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   GAUSSIAN,         DFLT,          DFLT,     DFLT,         BV,     DFLT,            DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, HPS,              STANDARD,  DFLT}, },
    { MULT_PACKED, "11", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   UNIFORM_TERNARY,  DFLT,          DFLT,     DFLT,         BV,     DFLT,            DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, BEHZ,             STANDARD,  DFLT}, },
    { MULT_PACKED, "12", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   GAUSSIAN,         DFLT,          DFLT,     DFLT,         BV,     DFLT,            DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, BEHZ,             STANDARD,  DFLT}, },
    { MULT_PACKED, "13", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   UNIFORM_TERNARY,  DFLT,          DFLT,     DFLT,         BV,     DFLT,            DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, HPSPOVERQ,        STANDARD,  DFLT}, },
    { MULT_PACKED, "14", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   GAUSSIAN,         DFLT,          DFLT,     DFLT,         BV,     DFLT,            DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, HPSPOVERQ,        STANDARD,  DFLT}, },
    { MULT_PACKED, "15", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   UNIFORM_TERNARY,  DFLT,          DFLT,     DFLT,         BV,     DFLT,            DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, HPSPOVERQLEVELED, STANDARD,  DFLT}, },
    { MULT_PACKED, "16", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   GAUSSIAN,         DFLT,          DFLT,     DFLT,         BV,     DFLT,            DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, HPSPOVERQLEVELED, STANDARD,  DFLT}, },
    { MULT_PACKED, "17", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   UNIFORM_TERNARY,  DFLT,          DFLT,     DFLT,         HYBRID, DFLT,            DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, HPS,              STANDARD,  DFLT}, },
    { MULT_PACKED, "18", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   GAUSSIAN,         DFLT,          DFLT,     DFLT,         HYBRID, DFLT,            DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, HPS,              STANDARD,  DFLT}, },
    { MULT_PACKED, "19", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   UNIFORM_TERNARY,  DFLT,          DFLT,     DFLT,         HYBRID, DFLT,            DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, BEHZ,             STANDARD,  DFLT}, },
    { MULT_PACKED, "20", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   GAUSSIAN,         DFLT,          DFLT,     DFLT,         HYBRID, DFLT,            DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, BEHZ,             STANDARD,  DFLT}, },
    { MULT_PACKED, "21", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   UNIFORM_TERNARY,  DFLT,          DFLT,     DFLT,         HYBRID, DFLT,            DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, HPSPOVERQ,        STANDARD,  DFLT}, },
    { MULT_PACKED, "22", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   GAUSSIAN,         DFLT,          DFLT,     DFLT,         HYBRID, DFLT,            DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, HPSPOVERQ,        STANDARD,  DFLT}, },
    { MULT_PACKED, "23", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   UNIFORM_TERNARY,  DFLT,          DFLT,     DFLT,         HYBRID, DFLT,            DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, HPSPOVERQLEVELED, STANDARD,  DFLT}, },
    { MULT_PACKED, "24", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   GAUSSIAN,         DFLT,          DFLT,     DFLT,         HYBRID, DFLT,            DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, HPSPOVERQLEVELED, STANDARD,  DFLT}, },
    { MULT_PACKED, "25", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   UNIFORM_TERNARY,  DFLT,          DFLT,     DFLT,         BV,     DFLT,            DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, HPS,              EXTENDED,  DFLT}, },
    { MULT_PACKED, "26", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   GAUSSIAN,         DFLT,          DFLT,     DFLT,         BV,     DFLT,            DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, HPS,              EXTENDED,  DFLT}, },
    { MULT_PACKED, "27", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   UNIFORM_TERNARY,  DFLT,          DFLT,     DFLT,         BV,     DFLT,            DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, BEHZ,             EXTENDED,  DFLT}, },
    { MULT_PACKED, "28", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   GAUSSIAN,         DFLT,          DFLT,     DFLT,         BV,     DFLT,            DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, BEHZ,             EXTENDED,  DFLT}, },
    { MULT_PACKED, "29", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   UNIFORM_TERNARY,  DFLT,          DFLT,     DFLT,         BV,     DFLT,            DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, HPSPOVERQ,        EXTENDED,  DFLT}, },
    { MULT_PACKED, "30", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   GAUSSIAN,         DFLT,          DFLT,     DFLT,         BV,     DFLT,            DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, HPSPOVERQ,        EXTENDED,  DFLT}, },
    { MULT_PACKED, "31", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   UNIFORM_TERNARY,  DFLT,          DFLT,     DFLT,         BV,     DFLT,            DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, HPSPOVERQLEVELED, EXTENDED,  DFLT}, },
    { MULT_PACKED, "32", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   GAUSSIAN,         DFLT,          DFLT,     DFLT,         BV,     DFLT,            DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, HPSPOVERQLEVELED, EXTENDED,  DFLT}, },
    { MULT_PACKED, "33", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   UNIFORM_TERNARY,  DFLT,          DFLT,     DFLT,         HYBRID, DFLT,            DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, HPS,              EXTENDED,  DFLT}, },
    { MULT_PACKED, "34", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   GAUSSIAN,         DFLT,          DFLT,     DFLT,         HYBRID, DFLT,            DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, HPS,              EXTENDED,  DFLT}, },
    { MULT_PACKED, "35", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   UNIFORM_TERNARY,  DFLT,          DFLT,     DFLT,         HYBRID, DFLT,            DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, BEHZ,             EXTENDED,  DFLT}, },
    { MULT_PACKED, "36", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   GAUSSIAN,         DFLT,          DFLT,     DFLT,         HYBRID, DFLT,            DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, BEHZ,             EXTENDED,  DFLT}, },
    { MULT_PACKED, "37", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   UNIFORM_TERNARY,  DFLT,          DFLT,     DFLT,         HYBRID, DFLT,            DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, HPSPOVERQ,        EXTENDED,  DFLT}, },
    { MULT_PACKED, "38", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   GAUSSIAN,         DFLT,          DFLT,     DFLT,         HYBRID, DFLT,            DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, HPSPOVERQ,        EXTENDED,  DFLT}, },
    { MULT_PACKED, "39", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   UNIFORM_TERNARY,  DFLT,          DFLT,     DFLT,         HYBRID, DFLT,            DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, HPSPOVERQLEVELED, EXTENDED,  DFLT}, },
    { MULT_PACKED, "40", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   GAUSSIAN,         DFLT,          DFLT,     DFLT,         HYBRID, DFLT,            DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, HPSPOVERQLEVELED, EXTENDED,  DFLT}, },
    // ==========================================
    // TestType,   Descr, Scheme,        RDim, MultDepth, SModSize, DSize,    BatchSz, SecKeyDist,       MaxRelinSkDeg, FModSize, SecLvl,       KSTech, ScalTech,        LDigits, PtMod,   StdDev, EvalAddCt, KSCt, MultTech,         EncTech,   PREMode
    { EVALATINDEX, "01", {BGVRNS_SCHEME, 256,  2,         DFLT,     BV_DSIZE, BATCH,   UNIFORM_TERNARY,  1,             60,       HEStd_NotSet, BV,     FIXEDMANUAL,     DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, DFLT,             STANDARD,  DFLT}, },
    { EVALATINDEX, "02", {BGVRNS_SCHEME, 256,  2,         DFLT,     BV_DSIZE, BATCH,   UNIFORM_TERNARY,  1,             60,       HEStd_NotSet, BV,     FIXEDAUTO,       DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, DFLT,             STANDARD,  DFLT}, },
    { EVALATINDEX, "03", {BGVRNS_SCHEME, 256,  2,         DFLT,     BV_DSIZE, BATCH,   UNIFORM_TERNARY,  1,             60,       HEStd_NotSet, BV,     FLEXIBLEAUTO,    DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, DFLT,             STANDARD,  DFLT}, },
    { EVALATINDEX, "04", {BGVRNS_SCHEME, 256,  2,         DFLT,     BV_DSIZE, BATCH,   UNIFORM_TERNARY,  1,             60,       HEStd_NotSet, BV,     FLEXIBLEAUTOEXT, DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, DFLT,             STANDARD,  DFLT}, },
    { EVALATINDEX, "05", {BGVRNS_SCHEME, 256,  2,         DFLT,     BV_DSIZE, BATCH,   GAUSSIAN,         1,             60,       HEStd_NotSet, BV,     FIXEDMANUAL,     DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, DFLT,             STANDARD,  DFLT}, },
    { EVALATINDEX, "06", {BGVRNS_SCHEME, 256,  2,         DFLT,     BV_DSIZE, BATCH,   GAUSSIAN,         1,             60,       HEStd_NotSet, BV,     FIXEDAUTO,       DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, DFLT,             STANDARD,  DFLT}, },
    { EVALATINDEX, "07", {BGVRNS_SCHEME, 256,  2,         DFLT,     BV_DSIZE, BATCH,   GAUSSIAN,         1,             60,       HEStd_NotSet, BV,     FLEXIBLEAUTO,    DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, DFLT,             STANDARD,  DFLT}, },
    { EVALATINDEX, "08", {BGVRNS_SCHEME, 256,  2,         DFLT,     BV_DSIZE, BATCH,   GAUSSIAN,         1,             60,       HEStd_NotSet, BV,     FLEXIBLEAUTOEXT, DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, DFLT,             STANDARD,  DFLT}, },
    { EVALATINDEX, "09", {BFVRNS_SCHEME, DFLT, 0,         DFLT,     20,       BATCH,   UNIFORM_TERNARY,  DFLT,          DFLT,     DFLT,         BV,     DFLT,            DFLT,    PTM_LRG, DFLT,   DFLT,      1,    HPS,              STANDARD,  DFLT}, },
    { EVALATINDEX, "10", {BFVRNS_SCHEME, DFLT, 0,         DFLT,     20,       BATCH,   GAUSSIAN,         DFLT,          DFLT,     DFLT,         BV,     DFLT,            DFLT,    PTM_LRG, DFLT,   DFLT,      1,    HPS,              STANDARD,  DFLT}, },
    { EVALATINDEX, "11", {BFVRNS_SCHEME, DFLT, 0,         DFLT,     20,       BATCH,   UNIFORM_TERNARY,  DFLT,          DFLT,     DFLT,         BV,     DFLT,            DFLT,    PTM_LRG, DFLT,   DFLT,      1,    BEHZ,             STANDARD,  DFLT}, },
    { EVALATINDEX, "12", {BFVRNS_SCHEME, DFLT, 0,         DFLT,     20,       BATCH,   GAUSSIAN,         DFLT,          DFLT,     DFLT,         BV,     DFLT,            DFLT,    PTM_LRG, DFLT,   DFLT,      1,    BEHZ,             STANDARD,  DFLT}, },
    { EVALATINDEX, "13", {BFVRNS_SCHEME, DFLT, 0,         DFLT,     20,       BATCH,   UNIFORM_TERNARY,  DFLT,          DFLT,     DFLT,         BV,     DFLT,            DFLT,    PTM_LRG, DFLT,   DFLT,      1,    HPSPOVERQ,        STANDARD,  DFLT}, },
    { EVALATINDEX, "14", {BFVRNS_SCHEME, DFLT, 0,         DFLT,     20,       BATCH,   GAUSSIAN,         DFLT,          DFLT,     DFLT,         BV,     DFLT,            DFLT,    PTM_LRG, DFLT,   DFLT,      1,    HPSPOVERQ,        STANDARD,  DFLT}, },
    { EVALATINDEX, "15", {BFVRNS_SCHEME, DFLT, 0,         DFLT,     20,       BATCH,   UNIFORM_TERNARY,  DFLT,          DFLT,     DFLT,         BV,     DFLT,            DFLT,    PTM_LRG, DFLT,   DFLT,      1,    HPSPOVERQLEVELED, STANDARD,  DFLT}, },
    { EVALATINDEX, "16", {BFVRNS_SCHEME, DFLT, 0,         DFLT,     20,       BATCH,   GAUSSIAN,         DFLT,          DFLT,     DFLT,         BV,     DFLT,            DFLT,    PTM_LRG, DFLT,   DFLT,      1,    HPSPOVERQLEVELED, STANDARD,  DFLT}, },
    { EVALATINDEX, "17", {BFVRNS_SCHEME, DFLT, 0,         DFLT,     20,       BATCH,   UNIFORM_TERNARY,  DFLT,          DFLT,     DFLT,         HYBRID, DFLT,            DFLT,    PTM_LRG, DFLT,   DFLT,      1,    HPS,              STANDARD,  DFLT}, },
    { EVALATINDEX, "18", {BFVRNS_SCHEME, DFLT, 0,         DFLT,     20,       BATCH,   GAUSSIAN,         DFLT,          DFLT,     DFLT,         HYBRID, DFLT,            DFLT,    PTM_LRG, DFLT,   DFLT,      1,    HPS,              STANDARD,  DFLT}, },
    { EVALATINDEX, "19", {BFVRNS_SCHEME, DFLT, 0,         DFLT,     20,       BATCH,   UNIFORM_TERNARY,  DFLT,          DFLT,     DFLT,         HYBRID, DFLT,            DFLT,    PTM_LRG, DFLT,   DFLT,      1,    BEHZ,             STANDARD,  DFLT}, },
    { EVALATINDEX, "20", {BFVRNS_SCHEME, DFLT, 0,         DFLT,     20,       BATCH,   GAUSSIAN,         DFLT,          DFLT,     DFLT,         HYBRID, DFLT,            DFLT,    PTM_LRG, DFLT,   DFLT,      1,    BEHZ,             STANDARD,  DFLT}, },
    { EVALATINDEX, "21", {BFVRNS_SCHEME, DFLT, 0,         DFLT,     20,       BATCH,   UNIFORM_TERNARY,  DFLT,          DFLT,     DFLT,         HYBRID, DFLT,            DFLT,    PTM_LRG, DFLT,   DFLT,      1,    HPSPOVERQ,        STANDARD,  DFLT}, },
    { EVALATINDEX, "22", {BFVRNS_SCHEME, DFLT, 0,         DFLT,     20,       BATCH,   GAUSSIAN,         DFLT,          DFLT,     DFLT,         HYBRID, DFLT,            DFLT,    PTM_LRG, DFLT,   DFLT,      1,    HPSPOVERQ,        STANDARD,  DFLT}, },
    { EVALATINDEX, "23", {BFVRNS_SCHEME, DFLT, 0,         DFLT,     20,       BATCH,   UNIFORM_TERNARY,  DFLT,          DFLT,     DFLT,         HYBRID, DFLT,            DFLT,    PTM_LRG, DFLT,   DFLT,      1,    HPSPOVERQLEVELED, STANDARD,  DFLT}, },
    { EVALATINDEX, "24", {BFVRNS_SCHEME, DFLT, 0,         DFLT,     20,       BATCH,   GAUSSIAN,         DFLT,          DFLT,     DFLT,         HYBRID, DFLT,            DFLT,    PTM_LRG, DFLT,   DFLT,      1,    HPSPOVERQLEVELED, STANDARD,  DFLT}, },
    { EVALATINDEX, "25", {BFVRNS_SCHEME, DFLT, 0,         DFLT,     20,       BATCH,   UNIFORM_TERNARY,  DFLT,          DFLT,     DFLT,         BV,     DFLT,            DFLT,    PTM_LRG, DFLT,   DFLT,      1,    HPS,              EXTENDED,  DFLT}, },
    { EVALATINDEX, "26", {BFVRNS_SCHEME, DFLT, 0,         DFLT,     20,       BATCH,   GAUSSIAN,         DFLT,          DFLT,     DFLT,         BV,     DFLT,            DFLT,    PTM_LRG, DFLT,   DFLT,      1,    HPS,              EXTENDED,  DFLT}, },
    { EVALATINDEX, "27", {BFVRNS_SCHEME, DFLT, 0,         DFLT,     20,       BATCH,   UNIFORM_TERNARY,  DFLT,          DFLT,     DFLT,         BV,     DFLT,            DFLT,    PTM_LRG, DFLT,   DFLT,      1,    BEHZ,             EXTENDED,  DFLT}, },
    { EVALATINDEX, "28", {BFVRNS_SCHEME, DFLT, 0,         DFLT,     20,       BATCH,   GAUSSIAN,         DFLT,          DFLT,     DFLT,         BV,     DFLT,            DFLT,    PTM_LRG, DFLT,   DFLT,      1,    BEHZ,             EXTENDED,  DFLT}, },
    { EVALATINDEX, "29", {BFVRNS_SCHEME, DFLT, 0,         DFLT,     20,       BATCH,   UNIFORM_TERNARY,  DFLT,          DFLT,     DFLT,         BV,     DFLT,            DFLT,    PTM_LRG, DFLT,   DFLT,      1,    HPSPOVERQ,        EXTENDED,  DFLT}, },
    { EVALATINDEX, "30", {BFVRNS_SCHEME, DFLT, 0,         DFLT,     20,       BATCH,   GAUSSIAN,         DFLT,          DFLT,     DFLT,         BV,     DFLT,            DFLT,    PTM_LRG, DFLT,   DFLT,      1,    HPSPOVERQ,        EXTENDED,  DFLT}, },
    { EVALATINDEX, "31", {BFVRNS_SCHEME, DFLT, 0,         DFLT,     20,       BATCH,   UNIFORM_TERNARY,  DFLT,          DFLT,     DFLT,         BV,     DFLT,            DFLT,    PTM_LRG, DFLT,   DFLT,      1,    HPSPOVERQLEVELED, EXTENDED,  DFLT}, },
    { EVALATINDEX, "32", {BFVRNS_SCHEME, DFLT, 0,         DFLT,     20,       BATCH,   GAUSSIAN,         DFLT,          DFLT,     DFLT,         BV,     DFLT,            DFLT,    PTM_LRG, DFLT,   DFLT,      1,    HPSPOVERQLEVELED, EXTENDED,  DFLT}, },
    { EVALATINDEX, "33", {BFVRNS_SCHEME, DFLT, 0,         DFLT,     20,       BATCH,   UNIFORM_TERNARY,  DFLT,          DFLT,     DFLT,         HYBRID, DFLT,            DFLT,    PTM_LRG, DFLT,   DFLT,      1,    HPS,              EXTENDED,  DFLT}, },
    { EVALATINDEX, "34", {BFVRNS_SCHEME, DFLT, 0,         DFLT,     20,       BATCH,   GAUSSIAN,         DFLT,          DFLT,     DFLT,         HYBRID, DFLT,            DFLT,    PTM_LRG, DFLT,   DFLT,      1,    HPS,              EXTENDED,  DFLT}, },
    { EVALATINDEX, "35", {BFVRNS_SCHEME, DFLT, 0,         DFLT,     20,       BATCH,   UNIFORM_TERNARY,  DFLT,          DFLT,     DFLT,         HYBRID, DFLT,            DFLT,    PTM_LRG, DFLT,   DFLT,      1,    BEHZ,             EXTENDED,  DFLT}, },
    { EVALATINDEX, "36", {BFVRNS_SCHEME, DFLT, 0,         DFLT,     20,       BATCH,   GAUSSIAN,         DFLT,          DFLT,     DFLT,         HYBRID, DFLT,            DFLT,    PTM_LRG, DFLT,   DFLT,      1,    BEHZ,             EXTENDED,  DFLT}, },
    { EVALATINDEX, "37", {BFVRNS_SCHEME, DFLT, 0,         DFLT,     20,       BATCH,   UNIFORM_TERNARY,  DFLT,          DFLT,     DFLT,         HYBRID, DFLT,            DFLT,    PTM_LRG, DFLT,   DFLT,      1,    HPSPOVERQ,        EXTENDED,  DFLT}, },
    { EVALATINDEX, "38", {BFVRNS_SCHEME, DFLT, 0,         DFLT,     20,       BATCH,   GAUSSIAN,         DFLT,          DFLT,     DFLT,         HYBRID, DFLT,            DFLT,    PTM_LRG, DFLT,   DFLT,      1,    HPSPOVERQ,        EXTENDED,  DFLT}, },
    { EVALATINDEX, "39", {BFVRNS_SCHEME, DFLT, 0,         DFLT,     20,       BATCH,   UNIFORM_TERNARY,  DFLT,          DFLT,     DFLT,         HYBRID, DFLT,            DFLT,    PTM_LRG, DFLT,   DFLT,      1,    HPSPOVERQLEVELED, EXTENDED,  DFLT}, },
    { EVALATINDEX, "40", {BFVRNS_SCHEME, DFLT, 0,         DFLT,     20,       BATCH,   GAUSSIAN,         DFLT,          DFLT,     DFLT,         HYBRID, DFLT,            DFLT,    PTM_LRG, DFLT,   DFLT,      1,    HPSPOVERQLEVELED, EXTENDED,  DFLT}, },
    // ==========================================
    // TestType,   Descr, Scheme,       RDim, MultDepth, SModSize, DSize,    BatchSz, SecKeyDist,       MaxRelinSkDeg, FModSize, SecLvl,       KSTech, ScalTech,        LDigits, PtMod,   StdDev, EvalAddCt, KSCt, MultTech          EncTech,   PREMode
    { EVALMERGE,  "01", {BGVRNS_SCHEME, 256,  2,         DFLT,     BV_DSIZE, BATCH,   UNIFORM_TERNARY,  1,             60,       HEStd_NotSet, BV,     FIXEDMANUAL,     DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, DFLT,             STANDARD,  DFLT}, },
    { EVALMERGE,  "02", {BGVRNS_SCHEME, 256,  2,         DFLT,     BV_DSIZE, BATCH,   UNIFORM_TERNARY,  1,             60,       HEStd_NotSet, BV,     FIXEDAUTO,       DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, DFLT,             STANDARD,  DFLT}, },
    { EVALMERGE,  "03", {BGVRNS_SCHEME, 256,  2,         DFLT,     BV_DSIZE, BATCH,   UNIFORM_TERNARY,  1,             60,       HEStd_NotSet, BV,     FLEXIBLEAUTO,    DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, DFLT,             STANDARD,  DFLT}, },
    { EVALMERGE,  "04", {BGVRNS_SCHEME, 256,  2,         DFLT,     BV_DSIZE, BATCH,   UNIFORM_TERNARY,  1,             60,       HEStd_NotSet, BV,     FLEXIBLEAUTOEXT, DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, DFLT,             STANDARD,  DFLT}, },
    { EVALMERGE,  "05", {BGVRNS_SCHEME, 256,  2,         DFLT,     BV_DSIZE, BATCH,   GAUSSIAN,         1,             60,       HEStd_NotSet, BV,     FIXEDMANUAL,     DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, DFLT,             STANDARD,  DFLT}, },
    { EVALMERGE,  "06", {BGVRNS_SCHEME, 256,  2,         DFLT,     BV_DSIZE, BATCH,   GAUSSIAN,         1,             60,       HEStd_NotSet, BV,     FIXEDAUTO,       DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, DFLT,             STANDARD,  DFLT}, },
    { EVALMERGE,  "07", {BGVRNS_SCHEME, 256,  2,         DFLT,     BV_DSIZE, BATCH,   GAUSSIAN,         1,             60,       HEStd_NotSet, BV,     FLEXIBLEAUTO,    DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, DFLT,             STANDARD,  DFLT}, },
    { EVALMERGE,  "08", {BGVRNS_SCHEME, 256,  2,         DFLT,     BV_DSIZE, BATCH,   GAUSSIAN,         1,             60,       HEStd_NotSet, BV,     FLEXIBLEAUTOEXT, DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, DFLT,             STANDARD,  DFLT}, },
    { EVALMERGE,  "09", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   UNIFORM_TERNARY,  DFLT,          DFLT,     DFLT,         DFLT,   FIXEDMANUAL,     DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, HPS,              STANDARD,  DFLT}, },
    { EVALMERGE,  "10", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   GAUSSIAN,         DFLT,          DFLT,     DFLT,         DFLT,   FIXEDMANUAL,     DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, HPS,              STANDARD,  DFLT}, },
    { EVALMERGE,  "11", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   UNIFORM_TERNARY,  DFLT,          DFLT,     DFLT,         DFLT,   FIXEDMANUAL,     DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, BEHZ,             STANDARD,  DFLT}, },
    { EVALMERGE,  "12", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   GAUSSIAN,         DFLT,          DFLT,     DFLT,         DFLT,   FIXEDMANUAL,     DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, BEHZ,             STANDARD,  DFLT}, },
    { EVALMERGE,  "13", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   UNIFORM_TERNARY,  DFLT,          DFLT,     DFLT,         DFLT,   FIXEDMANUAL,     DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, HPSPOVERQ,        STANDARD,  DFLT}, },
    { EVALMERGE,  "14", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   GAUSSIAN,         DFLT,          DFLT,     DFLT,         DFLT,   FIXEDMANUAL,     DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, HPSPOVERQ,        STANDARD,  DFLT}, },
    { EVALMERGE,  "15", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   UNIFORM_TERNARY,  DFLT,          DFLT,     DFLT,         DFLT,   FIXEDMANUAL,     DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, HPSPOVERQLEVELED, STANDARD,  DFLT}, },
    { EVALMERGE,  "16", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   GAUSSIAN,         DFLT,          DFLT,     DFLT,         DFLT,   FIXEDMANUAL,     DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, HPSPOVERQLEVELED, STANDARD,  DFLT}, },
    { EVALMERGE,  "17", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   UNIFORM_TERNARY,  DFLT,          DFLT,     DFLT,         DFLT,   FIXEDMANUAL,     DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, HPS,              EXTENDED,  DFLT}, },
    { EVALMERGE,  "18", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   GAUSSIAN,         DFLT,          DFLT,     DFLT,         DFLT,   FIXEDMANUAL,     DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, HPS,              EXTENDED,  DFLT}, },
    { EVALMERGE,  "19", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   UNIFORM_TERNARY,  DFLT,          DFLT,     DFLT,         DFLT,   FIXEDMANUAL,     DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, BEHZ,             EXTENDED,  DFLT}, },
    { EVALMERGE,  "20", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   GAUSSIAN,         DFLT,          DFLT,     DFLT,         DFLT,   FIXEDMANUAL,     DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, BEHZ,             EXTENDED,  DFLT}, },
    { EVALMERGE,  "21", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   UNIFORM_TERNARY,  DFLT,          DFLT,     DFLT,         DFLT,   FIXEDMANUAL,     DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, HPSPOVERQ,        EXTENDED,  DFLT}, },
    { EVALMERGE,  "22", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   GAUSSIAN,         DFLT,          DFLT,     DFLT,         DFLT,   FIXEDMANUAL,     DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, HPSPOVERQ,        EXTENDED,  DFLT}, },
    { EVALMERGE,  "23", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   UNIFORM_TERNARY,  DFLT,          DFLT,     DFLT,         DFLT,   FIXEDMANUAL,     DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, HPSPOVERQLEVELED, EXTENDED,  DFLT}, },
    { EVALMERGE,  "24", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   GAUSSIAN,         DFLT,          DFLT,     DFLT,         DFLT,   FIXEDMANUAL,     DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, HPSPOVERQLEVELED, EXTENDED,  DFLT}, },
    // ==========================================
    // TestType,   Descr, Scheme,       RDim, MultDepth, SModSize, DSize,    BatchSz, SecKeyDist,       MaxRelinSkDeg, FModSize, SecLvl,       KSTech, ScalTech,        LDigits, PtMod,   StdDev, EvalAddCt, KSCt, MultTech,         EncTech,   PREMode
    { EVALSUM,    "01", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   UNIFORM_TERNARY,  DFLT,          DFLT,     DFLT,         DFLT,   FIXEDMANUAL,     DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, HPS,              STANDARD,  DFLT}, },
    { EVALSUM,    "02", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   GAUSSIAN,         DFLT,          DFLT,     DFLT,         DFLT,   FIXEDMANUAL,     DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, HPS,              STANDARD,  DFLT}, },
    { EVALSUM,    "03", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   UNIFORM_TERNARY,  DFLT,          DFLT,     DFLT,         DFLT,   FIXEDMANUAL,     DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, BEHZ,             STANDARD,  DFLT}, },
    { EVALSUM,    "04", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   GAUSSIAN,         DFLT,          DFLT,     DFLT,         DFLT,   FIXEDMANUAL,     DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, BEHZ,             STANDARD,  DFLT}, },
    { EVALSUM,    "05", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   UNIFORM_TERNARY,  DFLT,          DFLT,     DFLT,         DFLT,   FIXEDMANUAL,     DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, HPSPOVERQ,        STANDARD,  DFLT}, },
    { EVALSUM,    "06", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   GAUSSIAN,         DFLT,          DFLT,     DFLT,         DFLT,   FIXEDMANUAL,     DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, HPSPOVERQ,        STANDARD,  DFLT}, },
    { EVALSUM,    "07", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   UNIFORM_TERNARY,  DFLT,          DFLT,     DFLT,         DFLT,   FIXEDMANUAL,     DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, HPSPOVERQLEVELED, STANDARD,  DFLT}, },
    { EVALSUM,    "08", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   GAUSSIAN,         DFLT,          DFLT,     DFLT,         DFLT,   FIXEDMANUAL,     DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, HPSPOVERQLEVELED, STANDARD,  DFLT}, },
    { EVALSUM,    "09", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   UNIFORM_TERNARY,  DFLT,          DFLT,     DFLT,         DFLT,   FIXEDMANUAL,     DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, HPS,              EXTENDED,  DFLT}, },
    { EVALSUM,    "10", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   GAUSSIAN,         DFLT,          DFLT,     DFLT,         DFLT,   FIXEDMANUAL,     DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, HPS,              EXTENDED,  DFLT}, },
    { EVALSUM,    "11", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   UNIFORM_TERNARY,  DFLT,          DFLT,     DFLT,         DFLT,   FIXEDMANUAL,     DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, BEHZ,             EXTENDED,  DFLT}, },
    { EVALSUM,    "12", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   GAUSSIAN,         DFLT,          DFLT,     DFLT,         DFLT,   FIXEDMANUAL,     DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, BEHZ,             EXTENDED,  DFLT}, },
    { EVALSUM,    "13", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   UNIFORM_TERNARY,  DFLT,          DFLT,     DFLT,         DFLT,   FIXEDMANUAL,     DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, HPSPOVERQ,        EXTENDED,  DFLT}, },
    { EVALSUM,    "14", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   GAUSSIAN,         DFLT,          DFLT,     DFLT,         DFLT,   FIXEDMANUAL,     DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, HPSPOVERQ,        EXTENDED,  DFLT}, },
    { EVALSUM,    "15", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   UNIFORM_TERNARY,  DFLT,          DFLT,     DFLT,         DFLT,   FIXEDMANUAL,     DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, HPSPOVERQLEVELED, EXTENDED,  DFLT}, },
    { EVALSUM,    "16", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   GAUSSIAN,         DFLT,          DFLT,     DFLT,         DFLT,   FIXEDMANUAL,     DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, HPSPOVERQLEVELED, EXTENDED,  DFLT}, },
    // ==========================================
    // TestType,   Descr, Scheme,       RDim, MultDepth, SModSize, DSize,    BatchSz, SecKeyDist,       MaxRelinSkDeg, FModSize, SecLvl,       KSTech, ScalTech,        LDigits, PtMod,   StdDev, EvalAddCt, KSCt, MultTech,         EncTech,   PREMode
    { METADATA,   "01", {BGVRNS_SCHEME, 256,  2,         DFLT,     BV_DSIZE, BATCH,   UNIFORM_TERNARY,  1,             60,       HEStd_NotSet, BV,     FIXEDMANUAL,     DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, DFLT,             STANDARD,  DFLT}, },
    { METADATA,   "02", {BGVRNS_SCHEME, 256,  2,         DFLT,     BV_DSIZE, BATCH,   UNIFORM_TERNARY,  1,             60,       HEStd_NotSet, BV,     FIXEDAUTO,       DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, DFLT,             STANDARD,  DFLT}, },
    { METADATA,   "03", {BGVRNS_SCHEME, 256,  2,         DFLT,     BV_DSIZE, BATCH,   UNIFORM_TERNARY,  1,             60,       HEStd_NotSet, BV,     FLEXIBLEAUTO,    DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, DFLT,             STANDARD,  DFLT}, },
    { METADATA,   "04", {BGVRNS_SCHEME, 256,  2,         DFLT,     BV_DSIZE, BATCH,   UNIFORM_TERNARY,  1,             60,       HEStd_NotSet, BV,     FLEXIBLEAUTOEXT, DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, DFLT,             STANDARD,  DFLT}, },
    { METADATA,   "05", {BGVRNS_SCHEME, 256,  2,         DFLT,     BV_DSIZE, BATCH,   GAUSSIAN,         1,             60,       HEStd_NotSet, BV,     FIXEDMANUAL,     DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, DFLT,             STANDARD,  DFLT}, },
    { METADATA,   "06", {BGVRNS_SCHEME, 256,  2,         DFLT,     BV_DSIZE, BATCH,   GAUSSIAN,         1,             60,       HEStd_NotSet, BV,     FIXEDAUTO,       DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, DFLT,             STANDARD,  DFLT}, },
    { METADATA,   "07", {BGVRNS_SCHEME, 256,  2,         DFLT,     BV_DSIZE, BATCH,   GAUSSIAN,         1,             60,       HEStd_NotSet, BV,     FLEXIBLEAUTO,    DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, DFLT,             STANDARD,  DFLT}, },
    { METADATA,   "08", {BGVRNS_SCHEME, 256,  2,         DFLT,     BV_DSIZE, BATCH,   GAUSSIAN,         1,             60,       HEStd_NotSet, BV,     FLEXIBLEAUTOEXT, DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, DFLT,             STANDARD,  DFLT}, },
    { METADATA,   "09", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   UNIFORM_TERNARY,  DFLT,          DFLT,     DFLT,         DFLT,   FIXEDMANUAL,     DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, HPS,              STANDARD,  DFLT}, },
    { METADATA,   "10", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   GAUSSIAN,         DFLT,          DFLT,     DFLT,         DFLT,   FIXEDMANUAL,     DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, HPS,              STANDARD,  DFLT}, },
    { METADATA,   "11", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   UNIFORM_TERNARY,  DFLT,          DFLT,     DFLT,         DFLT,   FIXEDMANUAL,     DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, BEHZ,             STANDARD,  DFLT}, },
    { METADATA,   "12", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   GAUSSIAN,         DFLT,          DFLT,     DFLT,         DFLT,   FIXEDMANUAL,     DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, BEHZ,             STANDARD,  DFLT}, },
    { METADATA,   "13", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   UNIFORM_TERNARY,  DFLT,          DFLT,     DFLT,         DFLT,   FIXEDMANUAL,     DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, HPSPOVERQ,        STANDARD,  DFLT}, },
    { METADATA,   "14", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   GAUSSIAN,         DFLT,          DFLT,     DFLT,         DFLT,   FIXEDMANUAL,     DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, HPSPOVERQ,        STANDARD,  DFLT}, },
    { METADATA,   "15", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   UNIFORM_TERNARY,  DFLT,          DFLT,     DFLT,         DFLT,   FIXEDMANUAL,     DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, HPSPOVERQLEVELED, STANDARD,  DFLT}, },
    { METADATA,   "16", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   GAUSSIAN,         DFLT,          DFLT,     DFLT,         DFLT,   FIXEDMANUAL,     DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, HPSPOVERQLEVELED, STANDARD,  DFLT}, },
    { METADATA,   "17", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   UNIFORM_TERNARY,  DFLT,          DFLT,     DFLT,         DFLT,   FIXEDMANUAL,     DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, HPS,              EXTENDED,  DFLT}, },
    { METADATA,   "18", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   GAUSSIAN,         DFLT,          DFLT,     DFLT,         DFLT,   FIXEDMANUAL,     DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, HPS,              EXTENDED,  DFLT}, },
    { METADATA,   "19", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   UNIFORM_TERNARY,  DFLT,          DFLT,     DFLT,         DFLT,   FIXEDMANUAL,     DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, BEHZ,             EXTENDED,  DFLT}, },
    { METADATA,   "20", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   GAUSSIAN,         DFLT,          DFLT,     DFLT,         DFLT,   FIXEDMANUAL,     DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, BEHZ,             EXTENDED,  DFLT}, },
    { METADATA,   "21", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   UNIFORM_TERNARY,  DFLT,          DFLT,     DFLT,         DFLT,   FIXEDMANUAL,     DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, HPSPOVERQ,        EXTENDED,  DFLT}, },
    { METADATA,   "22", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   GAUSSIAN,         DFLT,          DFLT,     DFLT,         DFLT,   FIXEDMANUAL,     DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, HPSPOVERQ,        EXTENDED,  DFLT}, },
    { METADATA,   "23", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   UNIFORM_TERNARY,  DFLT,          DFLT,     DFLT,         DFLT,   FIXEDMANUAL,     DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, HPSPOVERQLEVELED, EXTENDED,  DFLT}, },
    { METADATA,   "24", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   GAUSSIAN,         DFLT,          DFLT,     DFLT,         DFLT,   FIXEDMANUAL,     DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, HPSPOVERQLEVELED, EXTENDED,  DFLT}, },
    // ==========================================
    // TestType,    Descr, Scheme,       RDim,      MultDepth, SModSize, DSize, BatchSz,   SecKeyDist, MaxRelinSkDeg, FModSize, SecLvl,  KSTech, ScalTech,        LDigits, PtMod,   StdDev, EvalAddCt, KSCt, MultTech, EncTech,   PREMode
    { EVALSUM_ALL, "01", {BFVRNS_SCHEME, BATCH_LRG, 0,         DFLT,     20,    BATCH_LRG, DFLT,       DFLT,          DFLT,     DFLT,    DFLT,   FIXEDMANUAL,     DFLT,    PTM_LRG, DFLT,   DFLT,      12,   DFLT,     STANDARD,  DFLT}, },
    { EVALSUM_ALL, "02", {BFVRNS_SCHEME, BATCH_LRG, 0,         DFLT,     20,    BATCH_LRG, DFLT,       DFLT,          DFLT,     DFLT,    DFLT,   FIXEDMANUAL,     DFLT,    PTM_LRG, DFLT,   DFLT,      12,   DFLT,     EXTENDED,  DFLT}, },
    // ==========================================
    // TestType,      Descr, Scheme,       RDim,      MultDepth, SModSize, DSize, BatchSz, SecKeyDist, MaxRelinSkDeg, FModSize, SecLvl,  KSTech, ScalTech,        LDigits, PtMod,   StdDev, EvalAddCt, KSCt, MultTech, EncTech,   PREMode
    { KS_SINGLE_CRT, "01", {BGVRNS_SCHEME, 1<<13,     1,         DFLT,     1,     DFLT,    DFLT,       DFLT,          DFLT,     DFLT,    DFLT,   FIXEDMANUAL,     DFLT,    256,     4,      DFLT,      DFLT, DFLT,     STANDARD,  DFLT}, },
    { KS_SINGLE_CRT, "02", {BGVRNS_SCHEME, 1<<13,     1,         DFLT,     1,     DFLT,    DFLT,       DFLT,          DFLT,     DFLT,    DFLT,   FIXEDAUTO,       DFLT,    256,     4,      DFLT,      DFLT, DFLT,     STANDARD,  DFLT}, },
    { KS_SINGLE_CRT, "03", {BGVRNS_SCHEME, 1<<13,     1,         DFLT,     1,     DFLT,    DFLT,       DFLT,          DFLT,     DFLT,    DFLT,   FLEXIBLEAUTO,    DFLT,    256,     4,      DFLT,      DFLT, DFLT,     STANDARD,  DFLT}, },
    { KS_SINGLE_CRT, "04", {BGVRNS_SCHEME, 1<<13,     1,         DFLT,     1,     DFLT,    DFLT,       DFLT,          DFLT,     DFLT,    DFLT,   FLEXIBLEAUTOEXT, DFLT,    256,     4,      DFLT,      DFLT, DFLT,     STANDARD,  DFLT}, },
    // ==========================================
    // TestType,           Descr, Scheme,       RDim,      MultDepth, SModSize, DSize, BatchSz, SecKeyDist, MaxRelinSkDeg, FModSize, SecLvl,  KSTech, ScalTech,        LDigits, PtMod,   StdDev, EvalAddCt, KSCt, MultTech, EncTech,   PREMode
    { KS_MOD_REDUCE_DCRT, "01", {BGVRNS_SCHEME, 1<<13,     1,         DFLT,     1,     DFLT,    DFLT,       DFLT,          DFLT,     DFLT,    DFLT,   FIXEDMANUAL,     DFLT,    256,     4,      DFLT,      DFLT, DFLT,     STANDARD,  DFLT}, },
    // Calling ModReduce in the AUTO modes doesn't do anything because we automatically mod reduce before multiplication,
    // so we don't need unit tests for KS_MOD_REDUCE_DCRT in the AUTO modes.
    // ==========================================
    // TestType,   Descr, Scheme,        RDim, MultDepth, SModSize, DSize,    BatchSz, SecKeyDist,       MaxRelinSkDeg, FModSize, SecLvl,       KSTech, ScalTech,        LDigits, PtMod,   StdDev, EvalAddCt, KSCt, MultTech,         EncTech,   PREMode
    { EVALSQUARE,  "01", {BGVRNS_SCHEME, DFLT, 3,         DFLT,     20,       BATCH,   UNIFORM_TERNARY,  DFLT,          DFLT,     DFLT,         DFLT,   FIXEDMANUAL,     DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, HPS,              STANDARD,  DFLT}, },
    { EVALSQUARE,  "02", {BGVRNS_SCHEME, 256,  3,         DFLT,     BV_DSIZE, BATCH,   UNIFORM_TERNARY,  1,             60,       HEStd_NotSet, BV,     FIXEDAUTO,       DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, DFLT,             STANDARD,  DFLT}, },
    { EVALSQUARE,  "03", {BGVRNS_SCHEME, 256,  3,         DFLT,     BV_DSIZE, BATCH,   UNIFORM_TERNARY,  1,             60,       HEStd_NotSet, BV,     FLEXIBLEAUTO,    DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, DFLT,             STANDARD,  DFLT}, },
    { EVALSQUARE,  "04", {BGVRNS_SCHEME, 256,  3,         DFLT,     BV_DSIZE, BATCH,   UNIFORM_TERNARY,  1,             60,       HEStd_NotSet, BV,     FLEXIBLEAUTOEXT, DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, DFLT,             STANDARD,  DFLT}, },
    { EVALSQUARE,  "05", {BGVRNS_SCHEME, 256,  3,         DFLT,     BV_DSIZE, BATCH,   GAUSSIAN,         1,             60,       HEStd_NotSet, BV,     FIXEDMANUAL,     DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, DFLT,             STANDARD,  DFLT}, },
    { EVALSQUARE,  "06", {BGVRNS_SCHEME, 256,  3,         DFLT,     BV_DSIZE, BATCH,   GAUSSIAN,         1,             60,       HEStd_NotSet, BV,     FIXEDAUTO,       DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, DFLT,             STANDARD,  DFLT}, },
    { EVALSQUARE,  "07", {BGVRNS_SCHEME, 256,  3,         DFLT,     BV_DSIZE, BATCH,   GAUSSIAN,         1,             60,       HEStd_NotSet, BV,     FLEXIBLEAUTO,    DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, DFLT,             STANDARD,  DFLT}, },
    { EVALSQUARE,  "08", {BGVRNS_SCHEME, 256,  3,         DFLT,     BV_DSIZE, BATCH,   GAUSSIAN,         1,             60,       HEStd_NotSet, BV,     FLEXIBLEAUTOEXT, DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, DFLT,             STANDARD,  DFLT}, },
    { EVALSQUARE,  "09", {BFVRNS_SCHEME, DFLT, 3,         DFLT,     20,       BATCH,   UNIFORM_TERNARY,  DFLT,          DFLT,     DFLT,         DFLT,   FIXEDMANUAL,     DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, HPS,              STANDARD,  DFLT}, },
    { EVALSQUARE,  "10", {BFVRNS_SCHEME, DFLT, 3,         DFLT,     20,       BATCH,   GAUSSIAN,         DFLT,          DFLT,     DFLT,         DFLT,   FIXEDMANUAL,     DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, HPS,              STANDARD,  DFLT}, },
    { EVALSQUARE,  "11", {BFVRNS_SCHEME, DFLT, 3,         DFLT,     20,       BATCH,   UNIFORM_TERNARY,  DFLT,          DFLT,     DFLT,         DFLT,   FIXEDMANUAL,     DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, BEHZ,             STANDARD,  DFLT}, },
    { EVALSQUARE,  "12", {BFVRNS_SCHEME, DFLT, 3,         DFLT,     20,       BATCH,   GAUSSIAN,         DFLT,          DFLT,     DFLT,         DFLT,   FIXEDMANUAL,     DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, BEHZ,             STANDARD,  DFLT}, },
    { EVALSQUARE,  "13", {BFVRNS_SCHEME, DFLT, 3,         DFLT,     20,       BATCH,   UNIFORM_TERNARY,  DFLT,          DFLT,     DFLT,         DFLT,   FIXEDMANUAL,     DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, HPSPOVERQ,        STANDARD,  DFLT}, },
    { EVALSQUARE,  "14", {BFVRNS_SCHEME, DFLT, 3,         DFLT,     20,       BATCH,   GAUSSIAN,         DFLT,          DFLT,     DFLT,         DFLT,   FIXEDMANUAL,     DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, HPSPOVERQ,        STANDARD,  DFLT}, },
    { EVALSQUARE,  "15", {BFVRNS_SCHEME, DFLT, 3,         DFLT,     20,       BATCH,   UNIFORM_TERNARY,  DFLT,          DFLT,     DFLT,         DFLT,   FIXEDMANUAL,     DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, HPSPOVERQLEVELED, STANDARD,  DFLT}, },
    { EVALSQUARE,  "16", {BFVRNS_SCHEME, DFLT, 3,         DFLT,     20,       BATCH,   GAUSSIAN,         DFLT,          DFLT,     DFLT,         DFLT,   FIXEDMANUAL,     DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, HPSPOVERQLEVELED, STANDARD,  DFLT}, },
    { EVALSQUARE,  "17", {BFVRNS_SCHEME, DFLT, 3,         DFLT,     20,       BATCH,   UNIFORM_TERNARY,  DFLT,          DFLT,     DFLT,         DFLT,   FIXEDMANUAL,     DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, HPS,              EXTENDED,  DFLT}, },
    { EVALSQUARE,  "18", {BFVRNS_SCHEME, DFLT, 3,         DFLT,     20,       BATCH,   GAUSSIAN,         DFLT,          DFLT,     DFLT,         DFLT,   FIXEDMANUAL,     DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, HPS,              EXTENDED,  DFLT}, },
    { EVALSQUARE,  "19", {BFVRNS_SCHEME, DFLT, 3,         DFLT,     20,       BATCH,   UNIFORM_TERNARY,  DFLT,          DFLT,     DFLT,         DFLT,   FIXEDMANUAL,     DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, BEHZ,             EXTENDED,  DFLT}, },
    { EVALSQUARE,  "20", {BFVRNS_SCHEME, DFLT, 3,         DFLT,     20,       BATCH,   GAUSSIAN,         DFLT,          DFLT,     DFLT,         DFLT,   FIXEDMANUAL,     DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, BEHZ,             EXTENDED,  DFLT}, },
    { EVALSQUARE,  "21", {BFVRNS_SCHEME, DFLT, 3,         DFLT,     20,       BATCH,   UNIFORM_TERNARY,  DFLT,          DFLT,     DFLT,         DFLT,   FIXEDMANUAL,     DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, HPSPOVERQ,        EXTENDED,  DFLT}, },
    { EVALSQUARE,  "22", {BFVRNS_SCHEME, DFLT, 3,         DFLT,     20,       BATCH,   GAUSSIAN,         DFLT,          DFLT,     DFLT,         DFLT,   FIXEDMANUAL,     DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, HPSPOVERQ,        EXTENDED,  DFLT}, },
    { EVALSQUARE,  "23", {BFVRNS_SCHEME, DFLT, 3,         DFLT,     20,       BATCH,   UNIFORM_TERNARY,  DFLT,          DFLT,     DFLT,         DFLT,   FIXEDMANUAL,     DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, HPSPOVERQLEVELED, EXTENDED,  DFLT}, },
    { EVALSQUARE,  "24", {BFVRNS_SCHEME, DFLT, 3,         DFLT,     20,       BATCH,   GAUSSIAN,         DFLT,          DFLT,     DFLT,         DFLT,   FIXEDMANUAL,     DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, HPSPOVERQLEVELED, EXTENDED,  DFLT}, },
    // ==========================================
    // TestType,               Descr, Scheme,        RDim,  MultDepth, SModSize, DSize, BatchSz, SecKeyDist, MaxRelinSkDeg, FModSize, SecLvl, KSTech, ScalTech, LDigits, PtMod,      StdDev, EvalAddCt, KSCt, MultTech, EncTech, PREMode
    { RING_DIM_ERROR_HANDLING, "01", {BFVRNS_SCHEME, 1<<13, 3,         DFLT,     DFLT,  DFLT,    DFLT,       DFLT,          DFLT,     DFLT,   DFLT,   DFLT,     DFLT,    4293918721, DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
 };
// clang-format on
//===========================================================================================================
class UTGENERAL_SHE : public ::testing::TestWithParam<TEST_CASE_UTGENERAL_SHE> {
    using Element = DCRTPoly;

protected:
    void SetUp() {}

    void TearDown() {
        CryptoContextFactory<DCRTPoly>::ReleaseAllContexts();
    }

    void UnitTest_Add_Packed(const TEST_CASE_UTGENERAL_SHE& testData, const std::string& failmsg = std::string()) {
        try {
            CryptoContext<Element> cc(UnitTestGenerateContext(testData.params));

            std::vector<int64_t> vectorOfInts1 = {1, 0, 3, 1, 0, 1, 2, 1};
            Plaintext plaintext1               = cc->MakeCoefPackedPlaintext(vectorOfInts1);

            std::vector<int64_t> vectorOfInts2 = {2, 1, 3, 2, 2, 1, 3, 0};
            Plaintext plaintext2               = cc->MakeCoefPackedPlaintext(vectorOfInts2);

            std::vector<int64_t> vectorOfIntsAdd = {3, 1, 6, 3, 2, 2, 5, 1};
            Plaintext plaintextAdd               = cc->MakeCoefPackedPlaintext(vectorOfIntsAdd);

            std::vector<int64_t> vectorOfIntsSub = {-1, -1, 0, -1, -2, 0, -1, 1};
            Plaintext plaintextSub               = cc->MakeCoefPackedPlaintext(vectorOfIntsSub);

            KeyPair<Element> kp             = cc->KeyGen();
            Ciphertext<Element> ciphertext1 = cc->Encrypt(kp.publicKey, plaintext1);
            Ciphertext<Element> ciphertext2 = cc->Encrypt(kp.publicKey, plaintext2);

            Ciphertext<Element> cResult;
            Plaintext results;

            cResult = cc->EvalAdd(ciphertext1, ciphertext2);
            cc->Decrypt(kp.secretKey, cResult, &results);
            results->SetLength(plaintextAdd->GetLength());
            EXPECT_EQ(plaintextAdd->GetCoefPackedValue(), results->GetCoefPackedValue()) << failmsg << " EvalAdd fails";

            auto ct1_clone = ciphertext1->Clone();
            cc->EvalAddInPlace(ct1_clone, ciphertext2);
            cc->Decrypt(kp.secretKey, ct1_clone, &results);
            results->SetLength(plaintextAdd->GetLength());
            EXPECT_EQ(plaintextAdd->GetCoefPackedValue(), results->GetCoefPackedValue())
                << failmsg << " EvalAddInPlace fails";

            cResult = ciphertext1 + ciphertext2;
            cc->Decrypt(kp.secretKey, cResult, &results);
            results->SetLength(plaintextAdd->GetLength());
            EXPECT_EQ(plaintextAdd->GetCoefPackedValue(), results->GetCoefPackedValue())
                << failmsg << " operator+ fails";

            Ciphertext<Element> caddInplace = ciphertext1->Clone();
            caddInplace += ciphertext2;
            cc->Decrypt(kp.secretKey, caddInplace, &results);
            results->SetLength(plaintextAdd->GetLength());
            EXPECT_EQ(plaintextAdd->GetCoefPackedValue(), results->GetCoefPackedValue())
                << failmsg << " operator+= fails";

            cResult = cc->EvalSub(ciphertext1, ciphertext2);
            cc->Decrypt(kp.secretKey, cResult, &results);
            results->SetLength(plaintextSub->GetLength());
            EXPECT_EQ(plaintextSub->GetCoefPackedValue(), results->GetCoefPackedValue()) << failmsg << " EvalSub fails";

            cResult = ciphertext1 - ciphertext2;
            cc->Decrypt(kp.secretKey, cResult, &results);
            results->SetLength(plaintextSub->GetLength());
            EXPECT_EQ(plaintextSub->GetCoefPackedValue(), results->GetCoefPackedValue())
                << failmsg << " operator- fails";

            Ciphertext<Element> csubInplace = ciphertext1->Clone();
            csubInplace -= ciphertext2;
            cc->Decrypt(kp.secretKey, csubInplace, &results);
            results->SetLength(plaintextSub->GetLength());
            EXPECT_EQ(plaintextSub->GetCoefPackedValue(), results->GetCoefPackedValue())
                << failmsg << " operator-= fails";

            cResult = cc->EvalAdd(ciphertext1, plaintext2);
            cc->Decrypt(kp.secretKey, cResult, &results);
            results->SetLength(plaintextAdd->GetLength());
            EXPECT_EQ(plaintextAdd->GetCoefPackedValue(), results->GetCoefPackedValue())
                << failmsg << " EvalAdd Ct and Pt fails";

            cResult = cc->EvalSub(ciphertext1, plaintext2);
            cc->Decrypt(kp.secretKey, cResult, &results);
            results->SetLength(plaintextSub->GetLength());
            EXPECT_EQ(plaintextSub->GetCoefPackedValue(), results->GetCoefPackedValue())
                << failmsg << " EvalSub Ct and Pt fails";
        }
        catch (std::exception& e) {
            std::cerr << "Exception thrown from " << __func__ << "(): " << e.what() << std::endl;
            // make it fail
            EXPECT_TRUE(0 == 1) << failmsg;
        }
        catch (...) {
#if defined EMSCRIPTEN
            std::string name("EMSCRIPTEN_UNKNOWN");
#else
            std::string name(demangle(__cxxabiv1::__cxa_current_exception_type()->name()));
#endif
            std::cerr << "Unknown exception of type \"" << name << "\" thrown from " << __func__ << "()" << std::endl;
            // make it fail
            EXPECT_TRUE(0 == 1) << failmsg;
        }
    }

    void UnitTest_Mult_CoefPacked(const TEST_CASE_UTGENERAL_SHE& testData, const std::string& failmsg = std::string()) {
        try {
            CryptoContext<Element> cc(UnitTestGenerateContext(testData.params));

            std::vector<int64_t> vectorOfInts1 = {1, 0, 3, 1, 0, 1, 2, 1};
            Plaintext plaintext1               = cc->MakeCoefPackedPlaintext(vectorOfInts1);

            std::vector<int64_t> vectorOfInts2 = {2, 1, 3, 2, 2, 1, 3, 0};
            Plaintext plaintext2               = cc->MakeCoefPackedPlaintext(vectorOfInts2);

            // For cyclotomic order != 16, the expected result is the convolution of
            // vectorOfInt21 and vectorOfInts2
            std::vector<int64_t> vectorOfIntsMultLong = {2, 1, 9, 7, 12, 12, 16, 12, 19, 12, 7, 7, 7, 3};
            std::vector<int64_t> vectorOfIntsMult     = {-17, -11, 2, 0, 5, 9, 16, 12};

            Plaintext intArray1 = cc->MakeCoefPackedPlaintext(vectorOfInts1);

            Plaintext intArray2 = cc->MakeCoefPackedPlaintext(vectorOfInts2);

            Plaintext intArrayExpected =
                cc->MakeCoefPackedPlaintext(cc->GetCyclotomicOrder() == 16 ? vectorOfIntsMult : vectorOfIntsMultLong);

            // Initialize the public key containers.
            KeyPair<Element> kp = cc->KeyGen();

            Ciphertext<Element> ciphertext1 = cc->Encrypt(kp.publicKey, intArray1);

            Ciphertext<Element> ciphertext2 = cc->Encrypt(kp.publicKey, intArray2);

            cc->EvalMultKeyGen(kp.secretKey);

            Ciphertext<Element> cResult;
            Plaintext results;

            cResult = cc->EvalMult(ciphertext1, ciphertext2);
            cc->Decrypt(kp.secretKey, cResult, &results);
            results->SetLength(intArrayExpected->GetLength());
            EXPECT_EQ(intArrayExpected->GetCoefPackedValue(), results->GetCoefPackedValue())
                << failmsg << " EvalMult fails";

            cResult = ciphertext1 * ciphertext2;
            cc->Decrypt(kp.secretKey, cResult, &results);
            results->SetLength(intArrayExpected->GetLength());
            EXPECT_EQ(intArrayExpected->GetCoefPackedValue(), results->GetCoefPackedValue())
                << failmsg << " operator* fails";

            Ciphertext<Element> cmulInplace = ciphertext1->Clone();
            cmulInplace *= ciphertext2;
            cc->Decrypt(kp.secretKey, cmulInplace, &results);
            results->SetLength(intArrayExpected->GetLength());
            EXPECT_EQ(intArrayExpected->GetCoefPackedValue(), results->GetCoefPackedValue())
                << failmsg << " operator*= fails";

            cResult = cc->EvalMult(ciphertext1, plaintext2);
            cc->Decrypt(kp.secretKey, cResult, &results);
            results->SetLength(intArrayExpected->GetLength());
            EXPECT_EQ(intArrayExpected->GetCoefPackedValue(), results->GetCoefPackedValue())
                << failmsg << " EvalMult Ct and Pt fails";
        }
        catch (std::exception& e) {
            std::cerr << "Exception thrown from " << __func__ << "(): " << e.what() << std::endl;
            // make it fail
            EXPECT_TRUE(0 == 1) << failmsg;
        }
        catch (...) {
#if defined EMSCRIPTEN
            std::string name("EMSCRIPTEN_UNKNOWN");
#else
            std::string name(demangle(__cxxabiv1::__cxa_current_exception_type()->name()));
#endif
            std::cerr << "Unknown exception of type \"" << name << "\" thrown from " << __func__ << "()" << std::endl;
            // make it fail
            EXPECT_TRUE(0 == 1) << failmsg;
        }
    }

    void UnitTest_Mult_Packed(const TEST_CASE_UTGENERAL_SHE& testData, const std::string& failmsg = std::string()) {
        try {
            CryptoContext<Element> cc(UnitTestGenerateContext(testData.params));

            std::vector<int64_t> vectorOfInts1 = {1, 0, 3, 1, 0, 1, 2, 1};
            Plaintext plaintext1               = cc->MakePackedPlaintext(vectorOfInts1);

            std::vector<int64_t> vectorOfInts2 = {2, 1, 3, 2, 2, 1, 3, 1};
            Plaintext plaintext2               = cc->MakePackedPlaintext(vectorOfInts2);

            // For cyclotomic order != 16, the expected result is the convolution of
            // vectorOfInt21 and vectorOfInts2
            std::vector<int64_t> vectorOfIntsMult = {2, 0, 9, 2, 0, 1, 6, 1};

            Plaintext intArray1 = cc->MakePackedPlaintext(vectorOfInts1);

            Plaintext intArray2 = cc->MakePackedPlaintext(vectorOfInts2);

            Plaintext intArrayExpected = cc->MakePackedPlaintext(vectorOfIntsMult);

            // Initialize the public key containers.
            KeyPair<Element> kp = cc->KeyGen();

            Ciphertext<Element> ciphertext1 = cc->Encrypt(kp.publicKey, intArray1);

            Ciphertext<Element> ciphertext2 = cc->Encrypt(kp.publicKey, intArray2);

            cc->EvalMultKeyGen(kp.secretKey);

            Ciphertext<Element> cResult;
            Plaintext results;

            cResult = cc->EvalMult(ciphertext1, ciphertext2);

            cc->Decrypt(kp.secretKey, cResult, &results);
            results->SetLength(intArrayExpected->GetLength());
            EXPECT_EQ(intArrayExpected->GetPackedValue(), results->GetPackedValue()) << failmsg << " EvalMult fails";

            if (!((cc->getSchemeId() == SCHEME::BFVRNS_SCHEME) &&
                  (std::dynamic_pointer_cast<CryptoParametersBFVRNS>(cc->GetCryptoParameters())
                       ->GetMultiplicationTechnique() == BEHZ))) {
                cResult = cc->Compress(cResult, 1);
                cc->Decrypt(kp.secretKey, cResult, &results);
                results->SetLength(intArrayExpected->GetLength());
                EXPECT_EQ(intArrayExpected->GetPackedValue(), results->GetPackedValue())
                    << failmsg << " EvalMult fails after Compress";
            }

            cResult = ciphertext1 * ciphertext2;

            cc->Decrypt(kp.secretKey, cResult, &results);
            results->SetLength(intArrayExpected->GetLength());
            EXPECT_EQ(intArrayExpected->GetPackedValue(), results->GetPackedValue()) << failmsg << " operator* fails";

            if (!((cc->getSchemeId() == SCHEME::BFVRNS_SCHEME) &&
                  (std::dynamic_pointer_cast<CryptoParametersBFVRNS>(cc->GetCryptoParameters())
                       ->GetMultiplicationTechnique() == BEHZ))) {
                cResult = cc->Compress(cResult, 1);
                cc->Decrypt(kp.secretKey, cResult, &results);
                results->SetLength(intArrayExpected->GetLength());
                EXPECT_EQ(intArrayExpected->GetPackedValue(), results->GetPackedValue())
                    << failmsg << " operator* fails after Compress";
            }

            Ciphertext<Element> cmulInplace = ciphertext1->Clone();
            cmulInplace *= ciphertext2;
            cc->Decrypt(kp.secretKey, cmulInplace, &results);
            results->SetLength(intArrayExpected->GetLength());
            EXPECT_EQ(intArrayExpected->GetPackedValue(), results->GetPackedValue()) << failmsg << " operator*= fails";

            cResult = cc->EvalMult(ciphertext1, plaintext2);
            cc->Decrypt(kp.secretKey, cResult, &results);
            results->SetLength(intArrayExpected->GetLength());
            EXPECT_EQ(intArrayExpected->GetPackedValue(), results->GetPackedValue())
                << failmsg << " EvalMult Ct and Pt fails";
        }
        catch (std::exception& e) {
            std::cerr << "Exception thrown from " << __func__ << "(): " << e.what() << std::endl;
            // make it fail
            EXPECT_TRUE(0 == 1) << failmsg;
        }
        catch (...) {
#if defined EMSCRIPTEN
            std::string name("EMSCRIPTEN_UNKNOWN");
#else
            std::string name(demangle(__cxxabiv1::__cxa_current_exception_type()->name()));
#endif
            std::cerr << "Unknown exception of type \"" << name << "\" thrown from " << __func__ << "()" << std::endl;
            // make it fail
            EXPECT_TRUE(0 == 1) << failmsg;
        }
    }

    void UnitTest_EvalAtIndex(const TEST_CASE_UTGENERAL_SHE& testData, const std::string& failmsg = std::string()) {
        try {
            CryptoContext<Element> cc(UnitTestGenerateContext(testData.params));

            std::vector<int64_t> vectorOfInts1 = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
            Plaintext plaintext1               = cc->MakePackedPlaintext(vectorOfInts1);

            // Expected results after evaluating EvalAtIndex(3) and EvalAtIndex(-3)
            std::vector<int64_t> vectorOfIntsPlus3  = {4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 0, 0, 0};
            std::vector<int64_t> vectorOfIntsMinus3 = {0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13};

            Plaintext intArray1 = cc->MakePackedPlaintext(vectorOfInts1);

            Plaintext intArrayPlus3  = cc->MakePackedPlaintext(vectorOfIntsPlus3);
            Plaintext intArrayMinus3 = cc->MakePackedPlaintext(vectorOfIntsMinus3);

            // Initialize the public key containers.
            KeyPair<Element> kp = cc->KeyGen();

            Ciphertext<Element> ciphertext1 = cc->Encrypt(kp.publicKey, intArray1);

            cc->EvalAtIndexKeyGen(kp.secretKey, {3, -3});

            Ciphertext<Element> cResult1 = cc->EvalAtIndex(ciphertext1, 3);

            Ciphertext<Element> cResult2 = cc->EvalAtIndex(ciphertext1, -3);

            Plaintext results1;

            Plaintext results2;

            cc->Decrypt(kp.secretKey, cResult1, &results1);

            cc->Decrypt(kp.secretKey, cResult2, &results2);

            results1->SetLength(intArrayPlus3->GetLength());
            EXPECT_EQ(intArrayPlus3->GetPackedValue(), results1->GetPackedValue())
                << failmsg << " EvalAtIndex(3) fails";

            results2->SetLength(intArrayMinus3->GetLength());
            EXPECT_EQ(intArrayMinus3->GetPackedValue(), results2->GetPackedValue())
                << failmsg << " EvalAtIndex(-3) fails";
        }
        catch (std::exception& e) {
            std::cerr << "Exception thrown from " << __func__ << "(): " << e.what() << std::endl;
            // make it fail
            EXPECT_TRUE(0 == 1) << failmsg;
        }
        catch (...) {
#if defined EMSCRIPTEN
            std::string name("EMSCRIPTEN_UNKNOWN");
#else
            std::string name(demangle(__cxxabiv1::__cxa_current_exception_type()->name()));
#endif
            std::cerr << "Unknown exception of type \"" << name << "\" thrown from " << __func__ << "()" << std::endl;
            // make it fail
            EXPECT_TRUE(0 == 1) << failmsg;
        }
    }

    void UnitTest_EvalMerge(const TEST_CASE_UTGENERAL_SHE& testData, const std::string& failmsg = std::string()) {
        try {
            CryptoContext<Element> cc(UnitTestGenerateContext(testData.params));

            // Initialize the public key containers.
            KeyPair<Element> kp = cc->KeyGen();

            std::vector<Ciphertext<Element>> ciphertexts;

            std::vector<int64_t> vectorOfInts1 = {32, 0, 0, 0, 0, 0, 0, 0, 0, 0};
            Plaintext intArray1                = cc->MakePackedPlaintext(vectorOfInts1);
            ciphertexts.push_back(cc->Encrypt(kp.publicKey, intArray1));

            std::vector<int64_t> vectorOfInts2 = {2, 0, 0, 0, 0, 0, 0, 0, 0, 0};
            Plaintext intArray2                = cc->MakePackedPlaintext(vectorOfInts2);
            ciphertexts.push_back(cc->Encrypt(kp.publicKey, intArray2));

            std::vector<int64_t> vectorOfInts3 = {4, 0, 0, 0, 0, 0, 0, 0, 0, 0};
            Plaintext intArray3                = cc->MakePackedPlaintext(vectorOfInts3);
            ciphertexts.push_back(cc->Encrypt(kp.publicKey, intArray3));

            std::vector<int64_t> vectorOfInts4 = {8, 0, 0, 0, 0, 0, 0, 0, 0, 0};
            Plaintext intArray4                = cc->MakePackedPlaintext(vectorOfInts4);
            ciphertexts.push_back(cc->Encrypt(kp.publicKey, intArray4));

            std::vector<int64_t> vectorOfInts5 = {16, 0, 0, 0, 0, 0, 0, 0, 0, 0};
            Plaintext intArray5                = cc->MakePackedPlaintext(vectorOfInts5);
            ciphertexts.push_back(cc->Encrypt(kp.publicKey, intArray5));

            // Expected results after evaluating EvalAtIndex(3) and EvalAtIndex(-3)
            std::vector<int64_t> vectorMerged = {32, 2, 4, 8, 16, 0, 0, 0};
            Plaintext intArrayMerged          = cc->MakePackedPlaintext(vectorMerged);

            std::vector<int32_t> indexList = {-1, -2, -3, -4, -5};

            cc->EvalAtIndexKeyGen(kp.secretKey, indexList);

            auto mergedCiphertext = cc->EvalMerge(ciphertexts);

            Plaintext results1;

            cc->Decrypt(kp.secretKey, mergedCiphertext, &results1);

            results1->SetLength(intArrayMerged->GetLength());
            EXPECT_EQ(intArrayMerged->GetPackedValue(), results1->GetPackedValue()) << failmsg << " EvalMerge fails";
        }
        catch (std::exception& e) {
            std::cerr << "Exception thrown from " << __func__ << "(): " << e.what() << std::endl;
            // make it fail
            EXPECT_TRUE(0 == 1) << failmsg;
        }
        catch (...) {
#if defined EMSCRIPTEN
            std::string name("EMSCRIPTEN_UNKNOWN");
#else
            std::string name(demangle(__cxxabiv1::__cxa_current_exception_type()->name()));
#endif
            std::cerr << "Unknown exception of type \"" << name << "\" thrown from " << __func__ << "()" << std::endl;
            // make it fail
            EXPECT_TRUE(0 == 1) << failmsg;
        }
    }

    void UnitTest_EvalSum(const TEST_CASE_UTGENERAL_SHE& testData, const std::string& failmsg = std::string()) {
        try {
            CryptoContext<Element> cc(UnitTestGenerateContext(testData.params));

            // Initialize the public key containers.
            KeyPair<Element> kp = cc->KeyGen();

            std::vector<Ciphertext<Element>> ciphertexts;

            uint32_t n = cc->GetRingDimension();

            std::vector<int64_t> vectorOfInts1 = {1, 2, 3, 4, 5, 6, 7, 8};
            uint32_t dim                       = vectorOfInts1.size();
            vectorOfInts1.resize(n);
            for (uint32_t i = dim; i < n; i++)
                vectorOfInts1[i] = vectorOfInts1[i % dim];
            Plaintext intArray1 = cc->MakePackedPlaintext(vectorOfInts1);
            auto ct1            = cc->Encrypt(kp.publicKey, intArray1);

            cc->EvalSumKeyGen(kp.secretKey);

            auto ctsum1 = cc->EvalSum(ct1, 1);
            auto ctsum2 = cc->EvalSum(ct1, 2);
            auto ctsum3 = cc->EvalSum(ct1, 8);

            std::vector<int64_t> vectorOfInts2 = {3, 5, 7, 9, 11, 13, 15, 9};
            vectorOfInts2.resize(n);
            for (uint32_t i = dim; i < n; i++)
                vectorOfInts2[i] = vectorOfInts2[i % dim];
            Plaintext intArray2 = cc->MakePackedPlaintext(vectorOfInts2);

            std::vector<int64_t> vectorOfIntsAll = {36, 36, 36, 36, 36, 36, 36, 36};
            vectorOfIntsAll.resize(n);
            for (uint32_t i = dim; i < n; i++)
                vectorOfIntsAll[i] = vectorOfIntsAll[i % dim];
            Plaintext intArrayAll = cc->MakePackedPlaintext(vectorOfIntsAll);

            Plaintext results1;
            cc->Decrypt(kp.secretKey, ctsum1, &results1);
            Plaintext results2;
            cc->Decrypt(kp.secretKey, ctsum2, &results2);
            Plaintext results3;
            cc->Decrypt(kp.secretKey, ctsum3, &results3);

            intArray1->SetLength(dim);
            intArray2->SetLength(dim);
            intArrayAll->SetLength(dim);
            results1->SetLength(dim);
            results2->SetLength(dim);
            results3->SetLength(dim);

            EXPECT_EQ(intArray1->GetPackedValue(), results1->GetPackedValue())
                << failmsg << " EvalSum for batch size = 1 failed";
            EXPECT_EQ(intArray2->GetPackedValue(), results2->GetPackedValue())
                << failmsg << " EvalSum for batch size = 2 failed";
            EXPECT_EQ(intArrayAll->GetPackedValue(), results3->GetPackedValue())
                << failmsg << " EvalSum for batch size = 8 failed";
        }
        catch (std::exception& e) {
            std::cerr << "Exception thrown from " << __func__ << "(): " << e.what() << std::endl;
            // make it fail
            EXPECT_TRUE(0 == 1) << failmsg;
        }
        catch (...) {
#if defined EMSCRIPTEN
            std::string name("EMSCRIPTEN_UNKNOWN");
#else
            std::string name(demangle(__cxxabiv1::__cxa_current_exception_type()->name()));
#endif
            std::cerr << "Unknown exception of type \"" << name << "\" thrown from " << __func__ << "()" << std::endl;
            // make it fail
            EXPECT_TRUE(0 == 1) << failmsg;
        }
    }

    void UnitTest_Metadata(const TEST_CASE_UTGENERAL_SHE& testData, const std::string& failmsg = std::string()) {
        try {
            CryptoContext<Element> cc(UnitTestGenerateContext(testData.params));

            std::vector<int64_t> input1{0, 1, 2, 3, 4, 5, 6, 7};
            std::vector<int64_t> input2{0, -1, -2, -3, -4, -5, -6, -7};
            Plaintext plaintext1 = cc->MakePackedPlaintext(input1);
            Plaintext plaintext2 = cc->MakePackedPlaintext(input2);

            // Generate encryption keys
            KeyPair<Element> kp = cc->KeyGen();
            // Generate multiplication keys
            cc->EvalMultKeyGen(kp.secretKey);
            // Generate rotation keys for offsets +2 (left rotate) and -2 (right rotate)
            cc->EvalAtIndexKeyGen(kp.secretKey, {2, -2});
            // Generate keys for EvalSum
            cc->EvalSumKeyGen(kp.secretKey);

            // Encrypt plaintexts
            Ciphertext<Element> ciphertext1 = cc->Encrypt(kp.publicKey, plaintext1);
            Ciphertext<Element> ciphertext2 = cc->Encrypt(kp.publicKey, plaintext2);
            Plaintext results;

            // Populating metadata map in ciphertexts
            auto val1 = std::make_shared<MetadataTest>();
            val1->SetMetadata("ciphertext1");
            MetadataTest::StoreMetadata<Element>(ciphertext1, val1);
            auto val2 = std::make_shared<MetadataTest>();
            val2->SetMetadata("ciphertext2");
            MetadataTest::StoreMetadata<Element>(ciphertext2, val2);

            // Checking if metadata is carried over in EvalAdd(ctx,ctx)
            Ciphertext<Element> cAddCC = cc->EvalAdd(ciphertext1, ciphertext2);
            auto addCCValTest          = MetadataTest::GetMetadata<Element>(cAddCC);
            EXPECT_EQ(val1->GetMetadata(), addCCValTest->GetMetadata())
                << "Ciphertext metadata mismatch in EvalAdd(ctx,ctx)";

            // Checking if metadata is carried over in EvalAddInPlace(ctx,ctx)
            Ciphertext<Element> ciphertext1_clone = ciphertext1->Clone();
            cc->EvalAddInPlace(ciphertext1_clone, ciphertext2);
            auto addCCInPlaceValTest = MetadataTest::GetMetadata<Element>(ciphertext1_clone);
            EXPECT_EQ(val1->GetMetadata(), addCCInPlaceValTest->GetMetadata())
                << "Ciphertext metadata mismatch in EvalAddInPlace(ctx,ctx)";

            // Checking if metadata is carried over in EvalAdd(ctx,ptx)
            Ciphertext<Element> cAddCP = cc->EvalAdd(ciphertext1, plaintext1);
            auto addCPValTest          = MetadataTest::GetMetadata<Element>(cAddCP);
            EXPECT_EQ(val1->GetMetadata(), addCPValTest->GetMetadata())
                << "Ciphertext metadata mismatch in EvalAdd(ctx,ptx)";

            // Checking if metadata is carried over in EvalSub(ctx,ctx)
            Ciphertext<Element> cSubCC = cc->EvalSub(ciphertext1, ciphertext2);
            auto subCCValTest          = MetadataTest::GetMetadata<Element>(cSubCC);
            EXPECT_EQ(val1->GetMetadata(), subCCValTest->GetMetadata())
                << "Ciphertext metadata mismatch in EvalSub(ctx,ctx)";

            // Checking if metadata is carried over in EvalSub(ctx,ptx)
            Ciphertext<Element> cSubCP = cc->EvalSub(ciphertext1, plaintext1);
            auto subCPValTest          = MetadataTest::GetMetadata<Element>(cSubCP);
            EXPECT_EQ(val1->GetMetadata(), subCPValTest->GetMetadata())
                << "Ciphertext metadata mismatch in EvalSub(ctx,ptx)";

            // Checking if metadata is carried over in EvalMult(ctx,ctx)
            Ciphertext<Element> cMultCC = cc->EvalMult(ciphertext1, ciphertext2);
            auto multCCValTest          = MetadataTest::GetMetadata<Element>(cMultCC);
            EXPECT_EQ(val1->GetMetadata(), multCCValTest->GetMetadata())
                << "Ciphertext metadata mismatch in EvalMult(ctx,ctx)";

            // Checking if metadata is carried over in EvalMult(ctx,ptx)
            Ciphertext<Element> cMultCP = cc->EvalMult(ciphertext1, plaintext1);
            auto multCPValTest          = MetadataTest::GetMetadata<Element>(cMultCP);
            EXPECT_EQ(val1->GetMetadata(), multCPValTest->GetMetadata())
                << "Ciphertext metadata mismatch in EvalMult(ctx,ptx)";

            // Checking if metadata is carried over in EvalAtIndex +2 (left rotate)
            auto cAtIndex2       = cc->EvalAtIndex(ciphertext1, 2);
            auto atIndex2ValTest = MetadataTest::GetMetadata<Element>(cAtIndex2);
            EXPECT_EQ(val1->GetMetadata(), atIndex2ValTest->GetMetadata())
                << "Ciphertext metadata mismatch in EvalAtIndex +2";

            // Checking if metadata is carried over in EvalAtIndex -2 (right rotate)
            auto cAtIndexMinus2       = cc->EvalAtIndex(ciphertext1, -2);
            auto atIndexMinus2ValTest = MetadataTest::GetMetadata<Element>(cAtIndexMinus2);
            EXPECT_EQ(val1->GetMetadata(), atIndexMinus2ValTest->GetMetadata())
                << "Ciphertext metadata mismatch in EvalAtIndex -2";

            std::vector<double> weights(2);
            for (usint i = 0; i < 2; i++)
                weights[i] = i;

            std::vector<Ciphertext<Element>> ciphertexts(2);
            ciphertexts[0] = ciphertext1;
            ciphertexts[1] = ciphertext2;
        }
        catch (std::exception& e) {
            std::cerr << "Exception thrown from " << __func__ << "(): " << e.what() << std::endl;
            // make it fail
            EXPECT_TRUE(0 == 1) << failmsg;
        }
        catch (...) {
#if defined EMSCRIPTEN
            std::string name("EMSCRIPTEN_UNKNOWN");
#else
            std::string name(demangle(__cxxabiv1::__cxa_current_exception_type()->name()));
#endif
            std::cerr << "Unknown exception of type \"" << name << "\" thrown from " << __func__ << "()" << std::endl;
            // make it fail
            EXPECT_TRUE(0 == 1) << failmsg;
        }
    }

    void UnitTest_EvalSum_BFVrns_All(const TEST_CASE_UTGENERAL_SHE& testData,
                                     const std::string& failmsg = std::string()) {
        try {
            CryptoContext<Element> cc(UnitTestGenerateContext(testData.params));

            // Initialize the public key containers.
            KeyPair<DCRTPoly> kp = cc->KeyGen();

            std::vector<Ciphertext<DCRTPoly>> ciphertexts;

            uint32_t n = cc->GetRingDimension();

            std::vector<int64_t> vectorOfInts1 = {1, 2, 3, 4, 5, 6, 7, 8};
            uint32_t dim                       = vectorOfInts1.size();
            vectorOfInts1.resize(n);
            for (uint32_t i = n - dim; i < n; i++)
                vectorOfInts1[i] = i;

            Plaintext intArray1 = cc->MakePackedPlaintext(vectorOfInts1);

            std::vector<int64_t> vectorOfIntsAll = {32768, 32768, 32768, 32768, 32768, 32768, 32768, 32768};
            Plaintext intArrayAll                = cc->MakePackedPlaintext(vectorOfIntsAll);

            auto ct1 = cc->Encrypt(kp.publicKey, intArray1);

            cc->EvalSumKeyGen(kp.secretKey);

            auto ctsum1 = cc->EvalSum(ct1, BATCH_LRG);

            Plaintext results1;
            cc->Decrypt(kp.secretKey, ctsum1, &results1);

            intArrayAll->SetLength(dim);
            results1->SetLength(dim);

            EXPECT_EQ(intArrayAll->GetPackedValue(), results1->GetPackedValue())
                << " BFVrns EvalSum for batch size = All failed";
        }
        catch (std::exception& e) {
            std::cerr << "Exception thrown from " << __func__ << "(): " << e.what() << std::endl;
            // make it fail
            EXPECT_TRUE(0 == 1) << failmsg;
        }
        catch (...) {
#if defined EMSCRIPTEN
            std::string name("EMSCRIPTEN_UNKNOWN");
#else
            std::string name(demangle(__cxxabiv1::__cxa_current_exception_type()->name()));
#endif
            std::cerr << "Unknown exception of type \"" << name << "\" thrown from " << __func__ << "()" << std::endl;
            // make it fail
            EXPECT_TRUE(0 == 1) << failmsg;
        }
    }

    void UnitTest_Keyswitch_SingleCRT(const TEST_CASE_UTGENERAL_SHE& testData,
                                      const std::string& failmsg = std::string()) {
        try {
            CryptoContext<Element> cc(UnitTestGenerateContext(testData.params));

            Plaintext plaintext  = cc->MakeStringPlaintext("I am good, what are you?! 32 ch");
            KeyPair<DCRTPoly> kp = cc->KeyGen();

            Ciphertext<DCRTPoly> ciphertext = cc->Encrypt(kp.publicKey, plaintext);

            KeyPair<DCRTPoly> kp2           = cc->KeyGen();
            EvalKey<DCRTPoly> keySwitchHint = cc->KeySwitchGen(kp.secretKey, kp2.secretKey);

            Ciphertext<DCRTPoly> newCt = cc->KeySwitch(ciphertext, keySwitchHint);

            Plaintext plaintextNew;

            cc->Decrypt(kp2.secretKey, newCt, &plaintextNew);

            EXPECT_EQ(plaintext->GetStringValue(), plaintextNew->GetStringValue()) << "Key-Switched Decrypt fails";
        }
        catch (std::exception& e) {
            std::cerr << "Exception thrown from " << __func__ << "(): " << e.what() << std::endl;
            // make it fail
            EXPECT_TRUE(0 == 1) << failmsg;
        }
        catch (...) {
#if defined EMSCRIPTEN
            std::string name("EMSCRIPTEN_UNKNOWN");
#else
            std::string name(demangle(__cxxabiv1::__cxa_current_exception_type()->name()));
#endif
            std::cerr << "Unknown exception of type \"" << name << "\" thrown from " << __func__ << "()" << std::endl;
            // make it fail
            EXPECT_TRUE(0 == 1) << failmsg;
        }
    }

    void UnitTest_Keyswitch_ModReduce_DCRT(const TEST_CASE_UTGENERAL_SHE& testData,
                                           const std::string& failmsg = std::string()) {
        try {
            CryptoContext<Element> cc(UnitTestGenerateContext(testData.params));

            Plaintext plaintext = cc->MakeStringPlaintext("I am good, what are you?! 32 ch");

            KeyPair<DCRTPoly> kp            = cc->KeyGen();
            Ciphertext<DCRTPoly> ciphertext = cc->Encrypt(kp.publicKey, plaintext);

            KeyPair<DCRTPoly> kp2           = cc->KeyGen();
            EvalKey<DCRTPoly> keySwitchHint = cc->KeySwitchGen(kp.secretKey, kp2.secretKey);

            Ciphertext<DCRTPoly> newCt = cc->KeySwitch(ciphertext, keySwitchHint);

            Plaintext plaintextNewKeySwitch;

            cc->Decrypt(kp2.secretKey, newCt, &plaintextNewKeySwitch);

            EXPECT_EQ(plaintext->GetStringValue(), plaintextNewKeySwitch->GetStringValue())
                << "Key-Switched Decrypt fails";

            /**************************KEYSWITCH TEST END******************************/
            /**************************MODREDUCE TEST BEGIN******************************/

            cc->ModReduceInPlace(newCt);
            DCRTPoly sk2PrivateElement(kp2.secretKey->GetPrivateElement());
            sk2PrivateElement.DropLastElement();
            kp2.secretKey->SetPrivateElement(sk2PrivateElement);

            Plaintext plaintextNewModReduce;

            cc->Decrypt(kp2.secretKey, newCt, &plaintextNewModReduce);

            EXPECT_EQ(plaintext->GetStringValue(), plaintextNewModReduce->GetStringValue())
                << "Mod Reduced Decrypt fails";
        }
        catch (std::exception& e) {
            std::cerr << "Exception thrown from " << __func__ << "(): " << e.what() << std::endl;
            // make it fail
            EXPECT_TRUE(0 == 1) << failmsg;
        }
        catch (...) {
#if defined EMSCRIPTEN
            std::string name("EMSCRIPTEN_UNKNOWN");
#else
            std::string name(demangle(__cxxabiv1::__cxa_current_exception_type()->name()));
#endif
            std::cerr << "Unknown exception of type \"" << name << "\" thrown from " << __func__ << "()" << std::endl;
            // make it fail
            EXPECT_TRUE(0 == 1) << failmsg;
        }
    }

    void UnitTest_EvalSquare(const TEST_CASE_UTGENERAL_SHE& testData, const std::string& failmsg = std::string()) {
        try {
            CryptoContext<Element> cc(UnitTestGenerateContext(testData.params));

            std::vector<int64_t> vectorOfInts1 = {2, 1, 3, 2, 2, 1, 3, 0};
            Plaintext plaintext1               = cc->MakePackedPlaintext(vectorOfInts1);

            std::vector<int64_t> vectorOfIntsSquare1 = {4, 1, 9, 4, 4, 1, 9, 0};
            Plaintext intArrayExpectedSquare1        = cc->MakePackedPlaintext(vectorOfIntsSquare1);

            std::vector<int64_t> vectorOfIntsSixth1 = {64, 1, 729, 64, 64, 1, 729, 0};
            Plaintext intArrayExpectedSixth1        = cc->MakePackedPlaintext(vectorOfIntsSixth1);

            std::vector<int64_t> vectorOfInts2 = {1, 1, -1, 1, 1, 1, 0, 0, 0, 0, 0, 0};
            Plaintext plaintext2               = cc->MakeCoefPackedPlaintext(vectorOfInts2);
            // These are the coefficients of the square polynomial of the polynomial with coefficients in vectorOfInts2.
            std::vector<int64_t> vectorOfIntsSquare2 = {1, 2, -1, 0, 5, 2, 1, 0, 3, 2, 1};
            Plaintext intArrayExpectedSquare2        = cc->MakeCoefPackedPlaintext(vectorOfIntsSquare2);

            // Initialize the public key containers.
            KeyPair<Element> kp = cc->KeyGen();

            Ciphertext<Element> ciphertext1 = cc->Encrypt(kp.publicKey, plaintext1);
            Ciphertext<Element> ciphertext2 = cc->Encrypt(kp.publicKey, plaintext2);

            cc->EvalMultKeyGen(kp.secretKey);

            Plaintext results;

            Ciphertext<Element> ciphertextSq1 = cc->EvalSquare(ciphertext1);
            cc->Decrypt(kp.secretKey, ciphertextSq1, &results);
            results->SetLength(intArrayExpectedSquare1->GetLength());
            EXPECT_EQ(intArrayExpectedSquare1->GetPackedValue(), results->GetPackedValue())
                << failmsg << " EvalSquare (Packed) fails";

            Ciphertext<Element> ciphertextThird1 = cc->EvalMult(ciphertextSq1, plaintext1);
            cc->Decrypt(kp.secretKey, ciphertextThird1, &results);

            Ciphertext<Element> ciphertextSixth1 = cc->EvalSquare(ciphertextThird1);
            cc->Decrypt(kp.secretKey, ciphertextSixth1, &results);
            results->SetLength(intArrayExpectedSixth1->GetLength());
            EXPECT_EQ(intArrayExpectedSixth1->GetPackedValue(), results->GetPackedValue())
                << failmsg << " EvalSquare Sixth (Packed) fails";

            Ciphertext<Element> ciphertextSq2 = cc->EvalSquare(ciphertext2);
            cc->Decrypt(kp.secretKey, ciphertextSq2, &results);
            results->SetLength(intArrayExpectedSquare2->GetLength());
            EXPECT_EQ(intArrayExpectedSquare2->GetCoefPackedValue(), results->GetCoefPackedValue())
                << failmsg << " EvalSquare (CoefPacked) fails";
        }
        catch (std::exception& e) {
            std::cerr << "Exception thrown from " << __func__ << "(): " << e.what() << std::endl;
            // make it fail
            EXPECT_TRUE(0 == 1) << failmsg;
        }
        catch (...) {
#if defined EMSCRIPTEN
            std::string name("EMSCRIPTEN_UNKNOWN");
#else
            std::string name(demangle(__cxxabiv1::__cxa_current_exception_type()->name()));
#endif
            std::cerr << "Unknown exception of type \"" << name << "\" thrown from " << __func__ << "()" << std::endl;
            // make it fail
            EXPECT_TRUE(0 == 1) << failmsg;
        }
    }

    void UnitTest_BFV_Ringdimension_Security_Check(const TEST_CASE_UTGENERAL_SHE& testData,
                                                   const std::string& failmsg = std::string()) {
        try {
            CryptoContext<Element> cc(UnitTestGenerateContext(testData.params));

            // make it fail if there is no exception thrown
            EXPECT_EQ(0, 1);
        }
        catch (std::exception& e) {
            // we expect to catch an exception for this test as ring dimension should not meet the security requirement
            // std::cerr << "Exception thrown from " << __func__ << "(): " << e.what() << std::endl;
            EXPECT_EQ(1, 1);
        }
        catch (...) {
#if defined EMSCRIPTEN
            std::string name("EMSCRIPTEN_UNKNOWN");
#else
            std::string name(demangle(__cxxabiv1::__cxa_current_exception_type()->name()));
#endif
            std::cerr << "Unknown exception of type \"" << name << "\" thrown from " << __func__ << "()" << std::endl;
            // make it fail
            EXPECT_EQ(0, 1) << failmsg;
        }
    }
};
//===========================================================================================================
TEST_P(UTGENERAL_SHE, SHE) {
    setupSignals();
    auto test = GetParam();

    switch (test.testCaseType) {
        case ADD_PACKED:
            UnitTest_Add_Packed(test, test.buildTestName());
            break;
        case MULT_COEF_PACKED:
            UnitTest_Mult_CoefPacked(test, test.buildTestName());
            break;
        case MULT_PACKED:
            UnitTest_Mult_Packed(test, test.buildTestName());
            break;
        case EVALATINDEX:
            UnitTest_EvalAtIndex(test, test.buildTestName());
            break;
        case EVALMERGE:
            UnitTest_EvalMerge(test, test.buildTestName());
            break;
        case EVALSUM:
            UnitTest_EvalSum(test, test.buildTestName());
            break;
        case METADATA:
            UnitTest_Metadata(test, test.buildTestName());
            break;
        case EVALSUM_ALL:
            UnitTest_EvalSum_BFVrns_All(test, test.buildTestName());
            break;
        case KS_SINGLE_CRT:
            UnitTest_Keyswitch_SingleCRT(test, test.buildTestName());
            break;
        case KS_MOD_REDUCE_DCRT:
            UnitTest_Keyswitch_ModReduce_DCRT(test, test.buildTestName());
            break;
        case EVALSQUARE:
            UnitTest_EvalSquare(test, test.buildTestName());
            break;
        case RING_DIM_ERROR_HANDLING:
            UnitTest_BFV_Ringdimension_Security_Check(test, test.buildTestName());
            break;
        default:
            break;
    }
}

INSTANTIATE_TEST_SUITE_P(UnitTests, UTGENERAL_SHE, ::testing::ValuesIn(testCases), testName);
