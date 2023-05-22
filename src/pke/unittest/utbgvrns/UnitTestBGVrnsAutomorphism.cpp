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

#include <iostream>
#include <vector>
#include "gtest/gtest.h"
#include <cxxabi.h>
#include "utils/demangle.h"

using namespace lbcrypto;

//===========================================================================================================
enum TEST_CASE_TYPE {
    BGVRNS_AUTOMORPHISM = 0,
    EVAL_AT_INDX_PACKED_ARRAY,
    EVAL_SUM_PACKED_ARRAY,
};

static std::ostream& operator<<(std::ostream& os, const TEST_CASE_TYPE& type) {
    std::string typeName;
    switch (type) {
        case BGVRNS_AUTOMORPHISM:
            typeName = "BGVRNS_AUTOMORPHISM";
            break;
        case EVAL_AT_INDX_PACKED_ARRAY:
            typeName = "EVAL_AT_INDX_PACKED_ARRAY";
            break;
        case EVAL_SUM_PACKED_ARRAY:
            typeName = "EVAL_SUM_PACKED_ARRAY";
            break;
        default:
            typeName = "UNKNOWN_UTBGVRNS_AUTOMORPHISM";
            break;
    }
    return os << typeName;
}

enum TEST_CASE_ERROR {
    SUCCESS = 0,
    CORNER_CASES,
    INVALID_INPUT_DATA,
    INVALID_PRIVATE_KEY,
    INVALID_PUBLIC_KEY,
    INVALID_EVAL_KEY,
    INVALID_INDEX,
    INVALID_BATCH_SIZE,
    NO_KEY_GEN_CALL
};

struct TEST_CASE_UTBGVRNS_AUTOMORPHISM {
    TEST_CASE_TYPE testCaseType;
    // test case description - MUST BE UNIQUE
    std::string description;

    UnitTestCCParams params;

    // additional test case data
    TEST_CASE_ERROR error;
    const std::vector<uint32_t> indexList;

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
static auto testName = [](const testing::TestParamInfo<TEST_CASE_UTBGVRNS_AUTOMORPHISM>& test) {
    return test.param.buildTestName();
};

static std::ostream& operator<<(std::ostream& os, const TEST_CASE_UTBGVRNS_AUTOMORPHISM& test) {
    return os << test.toString();
}
//===========================================================================================================
constexpr usint MULT_DEPTH      = 1;
constexpr usint PTM             = 17;
constexpr usint PTM_LRG         = 65537;
constexpr SecurityLevel SEC_LVL = HEStd_NotSet;
constexpr usint RING_DIM        = 8;
constexpr usint DSIZE           = 1;

static const std::vector<uint32_t> initIndexList{3, 5, 7, 9, 11, 13, 15};
static const std::vector<uint32_t> cornerCaseIndexList{0};

// clang-format off
static std::vector<TEST_CASE_UTBGVRNS_AUTOMORPHISM> testCasesUTBGVRNS_AUTOMORPHISM = {
    // TestType,          Descr,  Scheme,        RDim,     MultDepth,  SModSize, DSize, BatchSz, SecKeyDist, MaxRelinSkDeg, FModSize, SecLvl,  KSTech, ScalTech,        LDigits, PtMod, StdDev, EvalAddCt, KSCt, MultTech, EncTech, PREMode,  Error,               indexList
    { BGVRNS_AUTOMORPHISM, "01", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,     DSIZE, DFLT,    DFLT,       DFLT,          DFLT,     SEC_LVL, BV,     FIXEDMANUAL,     DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    SUCCESS,             initIndexList },
    { BGVRNS_AUTOMORPHISM, "02", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,     DSIZE, DFLT,    DFLT,       DFLT,          DFLT,     SEC_LVL, BV,     FIXEDMANUAL,     DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    INVALID_INPUT_DATA,  initIndexList },
    { BGVRNS_AUTOMORPHISM, "03", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,     DSIZE, DFLT,    DFLT,       DFLT,          DFLT,     SEC_LVL, BV,     FIXEDMANUAL,     DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    INVALID_PRIVATE_KEY, initIndexList },
    { BGVRNS_AUTOMORPHISM, "04", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,     DSIZE, DFLT,    DFLT,       DFLT,          DFLT,     SEC_LVL, BV,     FIXEDMANUAL,     DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    INVALID_PUBLIC_KEY,  initIndexList },
    { BGVRNS_AUTOMORPHISM, "05", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,     DSIZE, DFLT,    DFLT,       DFLT,          DFLT,     SEC_LVL, BV,     FIXEDMANUAL,     DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    INVALID_EVAL_KEY,    initIndexList },
    { BGVRNS_AUTOMORPHISM, "06", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,     DSIZE, DFLT,    DFLT,       DFLT,          DFLT,     SEC_LVL, BV,     FIXEDMANUAL,     DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    INVALID_INDEX,       initIndexList },
    // ==========================================
    { BGVRNS_AUTOMORPHISM, "07", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,     DSIZE, DFLT,    DFLT,       DFLT,          DFLT,     SEC_LVL, BV,     FIXEDAUTO,       DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    SUCCESS,             initIndexList },
    { BGVRNS_AUTOMORPHISM, "08", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,     DSIZE, DFLT,    DFLT,       DFLT,          DFLT,     SEC_LVL, BV,     FIXEDAUTO,       DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    INVALID_INPUT_DATA,  initIndexList },
    { BGVRNS_AUTOMORPHISM, "09", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,     DSIZE, DFLT,    DFLT,       DFLT,          DFLT,     SEC_LVL, BV,     FIXEDAUTO,       DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    INVALID_PRIVATE_KEY, initIndexList },
    { BGVRNS_AUTOMORPHISM, "10", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,     DSIZE, DFLT,    DFLT,       DFLT,          DFLT,     SEC_LVL, BV,     FIXEDAUTO,       DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    INVALID_PUBLIC_KEY,  initIndexList },
    { BGVRNS_AUTOMORPHISM, "11", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,     DSIZE, DFLT,    DFLT,       DFLT,          DFLT,     SEC_LVL, BV,     FIXEDAUTO,       DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    INVALID_EVAL_KEY,    initIndexList },
    { BGVRNS_AUTOMORPHISM, "12", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,     DSIZE, DFLT,    DFLT,       DFLT,          DFLT,     SEC_LVL, BV,     FIXEDAUTO,       DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    INVALID_INDEX,       initIndexList },
    // ==========================================
    { BGVRNS_AUTOMORPHISM, "13", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,     DSIZE, DFLT,    DFLT,       DFLT,          DFLT,     SEC_LVL, BV,     FLEXIBLEAUTO,    DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    SUCCESS,             initIndexList },
    { BGVRNS_AUTOMORPHISM, "14", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,     DSIZE, DFLT,    DFLT,       DFLT,          DFLT,     SEC_LVL, BV,     FLEXIBLEAUTO,    DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    INVALID_INPUT_DATA,  initIndexList },
    { BGVRNS_AUTOMORPHISM, "15", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,     DSIZE, DFLT,    DFLT,       DFLT,          DFLT,     SEC_LVL, BV,     FLEXIBLEAUTO,    DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    INVALID_PRIVATE_KEY, initIndexList },
    { BGVRNS_AUTOMORPHISM, "16", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,     DSIZE, DFLT,    DFLT,       DFLT,          DFLT,     SEC_LVL, BV,     FLEXIBLEAUTO,    DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    INVALID_PUBLIC_KEY,  initIndexList },
    { BGVRNS_AUTOMORPHISM, "17", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,     DSIZE, DFLT,    DFLT,       DFLT,          DFLT,     SEC_LVL, BV,     FLEXIBLEAUTO,    DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    INVALID_EVAL_KEY,    initIndexList },
    { BGVRNS_AUTOMORPHISM, "18", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,     DSIZE, DFLT,    DFLT,       DFLT,          DFLT,     SEC_LVL, BV,     FLEXIBLEAUTO,    DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    INVALID_INDEX,       initIndexList },
    // ==========================================
    { BGVRNS_AUTOMORPHISM, "19", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,     DSIZE, DFLT,    DFLT,       DFLT,          DFLT,     SEC_LVL, BV,     FLEXIBLEAUTOEXT, DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    SUCCESS,             initIndexList },
    { BGVRNS_AUTOMORPHISM, "20", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,     DSIZE, DFLT,    DFLT,       DFLT,          DFLT,     SEC_LVL, BV,     FLEXIBLEAUTOEXT, DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    INVALID_INPUT_DATA,  initIndexList },
    { BGVRNS_AUTOMORPHISM, "21", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,     DSIZE, DFLT,    DFLT,       DFLT,          DFLT,     SEC_LVL, BV,     FLEXIBLEAUTOEXT, DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    INVALID_PRIVATE_KEY, initIndexList },
    { BGVRNS_AUTOMORPHISM, "22", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,     DSIZE, DFLT,    DFLT,       DFLT,          DFLT,     SEC_LVL, BV,     FLEXIBLEAUTOEXT, DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    INVALID_PUBLIC_KEY,  initIndexList },
    { BGVRNS_AUTOMORPHISM, "23", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,     DSIZE, DFLT,    DFLT,       DFLT,          DFLT,     SEC_LVL, BV,     FLEXIBLEAUTOEXT, DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    INVALID_EVAL_KEY,    initIndexList },
    { BGVRNS_AUTOMORPHISM, "24", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,     DSIZE, DFLT,    DFLT,       DFLT,          DFLT,     SEC_LVL, BV,     FLEXIBLEAUTOEXT, DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    INVALID_INDEX,       initIndexList },
    // ==========================================
    // TestType,                Descr,  Scheme,        RDim, MultDepth,  SModSize, DSize,BatchSz, SecKeyDist, MaxRelinSkDeg, FModSize, SecLvl, KSTech, ScalTech,        LDigits, PtMod,   StdDev, EvalAddCt, KSCt, MultTech, EncTech, PREMode,  Error,               indexList
    { EVAL_AT_INDX_PACKED_ARRAY, "31", {BGVRNS_SCHEME, DFLT, MULT_DEPTH, DFLT,     DFLT, DFLT,    DFLT,       DFLT,          DFLT,     DFLT,   DFLT,   FIXEDMANUAL,     DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    SUCCESS,             initIndexList },
    { EVAL_AT_INDX_PACKED_ARRAY, "32", {BGVRNS_SCHEME, DFLT, MULT_DEPTH, DFLT,     DFLT, DFLT,    DFLT,       DFLT,          DFLT,     DFLT,   DFLT,   FIXEDMANUAL,     DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    CORNER_CASES,        cornerCaseIndexList },
    { EVAL_AT_INDX_PACKED_ARRAY, "33", {BGVRNS_SCHEME, DFLT, MULT_DEPTH, DFLT,     DFLT, DFLT,    DFLT,       DFLT,          DFLT,     DFLT,   DFLT,   FIXEDMANUAL,     DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    INVALID_INPUT_DATA,  initIndexList },
    { EVAL_AT_INDX_PACKED_ARRAY, "34", {BGVRNS_SCHEME, DFLT, MULT_DEPTH, DFLT,     DFLT, DFLT,    DFLT,       DFLT,          DFLT,     DFLT,   DFLT,   FIXEDMANUAL,     DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    INVALID_PRIVATE_KEY, initIndexList },
    { EVAL_AT_INDX_PACKED_ARRAY, "35", {BGVRNS_SCHEME, DFLT, MULT_DEPTH, DFLT,     DFLT, DFLT,    DFLT,       DFLT,          DFLT,     DFLT,   DFLT,   FIXEDMANUAL,     DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    INVALID_PUBLIC_KEY,  initIndexList },
    { EVAL_AT_INDX_PACKED_ARRAY, "36", {BGVRNS_SCHEME, DFLT, MULT_DEPTH, DFLT,     DFLT, DFLT,    DFLT,       DFLT,          DFLT,     DFLT,   DFLT,   FIXEDMANUAL,     DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    NO_KEY_GEN_CALL,     initIndexList },
    // ==========================================
    // TestType,                Descr,  Scheme,        RDim, MultDepth,  SModSize, DSize,BatchSz, SecKeyDist, MaxRelinSkDeg, FModSize, SecLvl, KSTech, ScalTech,        LDigits, PtMod,   StdDev, EvalAddCt, KSCt, MultTech, EncTech, PREMode,  Error,               indexList
    { EVAL_AT_INDX_PACKED_ARRAY, "37", {BGVRNS_SCHEME, DFLT, MULT_DEPTH, DFLT,     DFLT, DFLT,    DFLT,       DFLT,          DFLT,     DFLT,   DFLT,   FIXEDAUTO,       DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    SUCCESS,             initIndexList },
    { EVAL_AT_INDX_PACKED_ARRAY, "38", {BGVRNS_SCHEME, DFLT, MULT_DEPTH, DFLT,     DFLT, DFLT,    DFLT,       DFLT,          DFLT,     DFLT,   DFLT,   FIXEDAUTO,       DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    CORNER_CASES,        cornerCaseIndexList },
    { EVAL_AT_INDX_PACKED_ARRAY, "39", {BGVRNS_SCHEME, DFLT, MULT_DEPTH, DFLT,     DFLT, DFLT,    DFLT,       DFLT,          DFLT,     DFLT,   DFLT,   FIXEDAUTO,       DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    INVALID_INPUT_DATA,  initIndexList },
    { EVAL_AT_INDX_PACKED_ARRAY, "40", {BGVRNS_SCHEME, DFLT, MULT_DEPTH, DFLT,     DFLT, DFLT,    DFLT,       DFLT,          DFLT,     DFLT,   DFLT,   FIXEDAUTO,       DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    INVALID_PRIVATE_KEY, initIndexList },
    { EVAL_AT_INDX_PACKED_ARRAY, "41", {BGVRNS_SCHEME, DFLT, MULT_DEPTH, DFLT,     DFLT, DFLT,    DFLT,       DFLT,          DFLT,     DFLT,   DFLT,   FIXEDAUTO,       DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    INVALID_PUBLIC_KEY,  initIndexList },
    { EVAL_AT_INDX_PACKED_ARRAY, "42", {BGVRNS_SCHEME, DFLT, MULT_DEPTH, DFLT,     DFLT, DFLT,    DFLT,       DFLT,          DFLT,     DFLT,   DFLT,   FIXEDAUTO,       DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    NO_KEY_GEN_CALL,     initIndexList },
    // ==========================================
    // TestType,                Descr,  Scheme,        RDim, MultDepth,  SModSize, DSize,BatchSz, SecKeyDist, MaxRelinSkDeg, FModSize, SecLvl, KSTech, ScalTech,        LDigits, PtMod,   StdDev, EvalAddCt, KSCt, MultTech, EncTech, PREMode,  Error,               indexList
    { EVAL_AT_INDX_PACKED_ARRAY, "44", {BGVRNS_SCHEME, DFLT, MULT_DEPTH, DFLT,     DFLT, DFLT,    DFLT,       DFLT,          DFLT,     DFLT,   DFLT,   FLEXIBLEAUTO,    DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    SUCCESS,             initIndexList },
    { EVAL_AT_INDX_PACKED_ARRAY, "45", {BGVRNS_SCHEME, DFLT, MULT_DEPTH, DFLT,     DFLT, DFLT,    DFLT,       DFLT,          DFLT,     DFLT,   DFLT,   FLEXIBLEAUTO,    DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    CORNER_CASES,        cornerCaseIndexList },
    { EVAL_AT_INDX_PACKED_ARRAY, "46", {BGVRNS_SCHEME, DFLT, MULT_DEPTH, DFLT,     DFLT, DFLT,    DFLT,       DFLT,          DFLT,     DFLT,   DFLT,   FLEXIBLEAUTO,    DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    INVALID_INPUT_DATA,  initIndexList },
    { EVAL_AT_INDX_PACKED_ARRAY, "47", {BGVRNS_SCHEME, DFLT, MULT_DEPTH, DFLT,     DFLT, DFLT,    DFLT,       DFLT,          DFLT,     DFLT,   DFLT,   FLEXIBLEAUTO,    DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    INVALID_PRIVATE_KEY, initIndexList },
    { EVAL_AT_INDX_PACKED_ARRAY, "48", {BGVRNS_SCHEME, DFLT, MULT_DEPTH, DFLT,     DFLT, DFLT,    DFLT,       DFLT,          DFLT,     DFLT,   DFLT,   FLEXIBLEAUTO,    DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    INVALID_PUBLIC_KEY,  initIndexList },
    { EVAL_AT_INDX_PACKED_ARRAY, "49", {BGVRNS_SCHEME, DFLT, MULT_DEPTH, DFLT,     DFLT, DFLT,    DFLT,       DFLT,          DFLT,     DFLT,   DFLT,   FLEXIBLEAUTO,    DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    NO_KEY_GEN_CALL,     initIndexList },
    // ==========================================
    // TestType,                Descr,  Scheme,        RDim, MultDepth,  SModSize, DSize,BatchSz, SecKeyDist, MaxRelinSkDeg, FModSize, SecLvl, KSTech, ScalTech,        LDigits, PtMod,   StdDev, EvalAddCt, KSCt, MultTech, EncTech, PREMode,  Error,               indexList
    { EVAL_AT_INDX_PACKED_ARRAY, "50", {BGVRNS_SCHEME, DFLT, MULT_DEPTH, DFLT,     DFLT, DFLT,    DFLT,       DFLT,          DFLT,     DFLT,   DFLT,   FLEXIBLEAUTOEXT, DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    SUCCESS,             initIndexList },
    { EVAL_AT_INDX_PACKED_ARRAY, "51", {BGVRNS_SCHEME, DFLT, MULT_DEPTH, DFLT,     DFLT, DFLT,    DFLT,       DFLT,          DFLT,     DFLT,   DFLT,   FLEXIBLEAUTOEXT, DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    CORNER_CASES,        cornerCaseIndexList },
    { EVAL_AT_INDX_PACKED_ARRAY, "52", {BGVRNS_SCHEME, DFLT, MULT_DEPTH, DFLT,     DFLT, DFLT,    DFLT,       DFLT,          DFLT,     DFLT,   DFLT,   FLEXIBLEAUTOEXT, DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    INVALID_INPUT_DATA,  initIndexList },
    { EVAL_AT_INDX_PACKED_ARRAY, "53", {BGVRNS_SCHEME, DFLT, MULT_DEPTH, DFLT,     DFLT, DFLT,    DFLT,       DFLT,          DFLT,     DFLT,   DFLT,   FLEXIBLEAUTOEXT, DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    INVALID_PRIVATE_KEY, initIndexList },
    { EVAL_AT_INDX_PACKED_ARRAY, "54", {BGVRNS_SCHEME, DFLT, MULT_DEPTH, DFLT,     DFLT, DFLT,    DFLT,       DFLT,          DFLT,     DFLT,   DFLT,   FLEXIBLEAUTOEXT, DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    INVALID_PUBLIC_KEY,  initIndexList },
    { EVAL_AT_INDX_PACKED_ARRAY, "55", {BGVRNS_SCHEME, DFLT, MULT_DEPTH, DFLT,     DFLT, DFLT,    DFLT,       DFLT,          DFLT,     DFLT,   DFLT,   FLEXIBLEAUTOEXT, DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    NO_KEY_GEN_CALL,     initIndexList },
    // ==========================================
    // TestType,            Descr,  Scheme,        RDim, MultDepth,  SModSize, DSize,BatchSz, SecKeyDist, MaxRelinSkDeg, FModSize, SecLvl, KSTech, ScalTech,        LDigits, PtMod,   StdDev, EvalAddCt, KSCt, MultTech, EncTech, PREMode,  Error,               indexList
    { EVAL_SUM_PACKED_ARRAY, "61", {BGVRNS_SCHEME, DFLT, MULT_DEPTH, DFLT,     DFLT, DFLT,    DFLT,       DFLT,          DFLT,     DFLT,   DFLT,   FIXEDMANUAL,     DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    SUCCESS },
    { EVAL_SUM_PACKED_ARRAY, "62", {BGVRNS_SCHEME, DFLT, MULT_DEPTH, DFLT,     DFLT, DFLT,    DFLT,       DFLT,          DFLT,     DFLT,   DFLT,   FIXEDMANUAL,     DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    INVALID_PRIVATE_KEY },
    { EVAL_SUM_PACKED_ARRAY, "63", {BGVRNS_SCHEME, DFLT, MULT_DEPTH, DFLT,     DFLT, DFLT,    DFLT,       DFLT,          DFLT,     DFLT,   DFLT,   FIXEDMANUAL,     DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    INVALID_PUBLIC_KEY },
    { EVAL_SUM_PACKED_ARRAY, "64", {BGVRNS_SCHEME, DFLT, MULT_DEPTH, DFLT,     DFLT, DFLT,    DFLT,       DFLT,          DFLT,     DFLT,   DFLT,   FIXEDMANUAL,     DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    INVALID_BATCH_SIZE },
    { EVAL_SUM_PACKED_ARRAY, "65", {BGVRNS_SCHEME, DFLT, MULT_DEPTH, DFLT,     DFLT, DFLT,    DFLT,       DFLT,          DFLT,     DFLT,   DFLT,   FIXEDMANUAL,     DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    NO_KEY_GEN_CALL },
    // ==========================================
    // TestType,            Descr,  Scheme,        RDim, MultDepth,  SModSize, DSize,BatchSz, SecKeyDist, MaxRelinSkDeg, FModSize, SecLvl, KSTech, ScalTech,        LDigits, PtMod,   StdDev, EvalAddCt, KSCt, MultTech, EncTech, PREMode,  Error,               indexList
    { EVAL_SUM_PACKED_ARRAY, "66", {BGVRNS_SCHEME, DFLT, MULT_DEPTH, DFLT,     DFLT, DFLT,    DFLT,       DFLT,          DFLT,     DFLT,   DFLT,   FIXEDAUTO,       DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    SUCCESS },
    { EVAL_SUM_PACKED_ARRAY, "67", {BGVRNS_SCHEME, DFLT, MULT_DEPTH, DFLT,     DFLT, DFLT,    DFLT,       DFLT,          DFLT,     DFLT,   DFLT,   FIXEDAUTO,       DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    INVALID_PRIVATE_KEY },
    { EVAL_SUM_PACKED_ARRAY, "68", {BGVRNS_SCHEME, DFLT, MULT_DEPTH, DFLT,     DFLT, DFLT,    DFLT,       DFLT,          DFLT,     DFLT,   DFLT,   FIXEDAUTO,       DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    INVALID_PUBLIC_KEY },
    { EVAL_SUM_PACKED_ARRAY, "69", {BGVRNS_SCHEME, DFLT, MULT_DEPTH, DFLT,     DFLT, DFLT,    DFLT,       DFLT,          DFLT,     DFLT,   DFLT,   FIXEDAUTO,       DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    INVALID_BATCH_SIZE },
    { EVAL_SUM_PACKED_ARRAY, "70", {BGVRNS_SCHEME, DFLT, MULT_DEPTH, DFLT,     DFLT, DFLT,    DFLT,       DFLT,          DFLT,     DFLT,   DFLT,   FIXEDAUTO,       DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    NO_KEY_GEN_CALL },
    // ==========================================
    // TestType,            Descr,  Scheme,        RDim, MultDepth,  SModSize, DSize,BatchSz, SecKeyDist, MaxRelinSkDeg, FModSize, SecLvl, KSTech, ScalTech,        LDigits, PtMod,   StdDev, EvalAddCt, KSCt, MultTech, EncTech, PREMode,  Error,               indexList
    { EVAL_SUM_PACKED_ARRAY, "71", {BGVRNS_SCHEME, DFLT, MULT_DEPTH, DFLT,     DFLT, DFLT,    DFLT,       DFLT,          DFLT,     DFLT,   DFLT,   FLEXIBLEAUTO,    DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    SUCCESS },
    { EVAL_SUM_PACKED_ARRAY, "72", {BGVRNS_SCHEME, DFLT, MULT_DEPTH, DFLT,     DFLT, DFLT,    DFLT,       DFLT,          DFLT,     DFLT,   DFLT,   FLEXIBLEAUTO,    DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    INVALID_PRIVATE_KEY },
    { EVAL_SUM_PACKED_ARRAY, "73", {BGVRNS_SCHEME, DFLT, MULT_DEPTH, DFLT,     DFLT, DFLT,    DFLT,       DFLT,          DFLT,     DFLT,   DFLT,   FLEXIBLEAUTO,    DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    INVALID_PUBLIC_KEY },
    { EVAL_SUM_PACKED_ARRAY, "74", {BGVRNS_SCHEME, DFLT, MULT_DEPTH, DFLT,     DFLT, DFLT,    DFLT,       DFLT,          DFLT,     DFLT,   DFLT,   FLEXIBLEAUTO,    DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    INVALID_BATCH_SIZE },
    { EVAL_SUM_PACKED_ARRAY, "75", {BGVRNS_SCHEME, DFLT, MULT_DEPTH, DFLT,     DFLT, DFLT,    DFLT,       DFLT,          DFLT,     DFLT,   DFLT,   FLEXIBLEAUTO,    DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    NO_KEY_GEN_CALL },
    // ==========================================
    // TestType,            Descr,  Scheme,        RDim, MultDepth,  SModSize, DSize,BatchSz, SecKeyDist, MaxRelinSkDeg, FModSize, SecLvl, KSTech, ScalTech,        LDigits, PtMod,   StdDev, EvalAddCt, KSCt, MultTech, EncTech, PREMode,  Error,               indexList
    { EVAL_SUM_PACKED_ARRAY, "76", {BGVRNS_SCHEME, DFLT, MULT_DEPTH, DFLT,     DFLT, DFLT,    DFLT,       DFLT,          DFLT,     DFLT,   DFLT,   FLEXIBLEAUTOEXT, DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    SUCCESS },
    { EVAL_SUM_PACKED_ARRAY, "77", {BGVRNS_SCHEME, DFLT, MULT_DEPTH, DFLT,     DFLT, DFLT,    DFLT,       DFLT,          DFLT,     DFLT,   DFLT,   FLEXIBLEAUTOEXT, DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    INVALID_PRIVATE_KEY },
    { EVAL_SUM_PACKED_ARRAY, "78", {BGVRNS_SCHEME, DFLT, MULT_DEPTH, DFLT,     DFLT, DFLT,    DFLT,       DFLT,          DFLT,     DFLT,   DFLT,   FLEXIBLEAUTOEXT, DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    INVALID_PUBLIC_KEY },
    { EVAL_SUM_PACKED_ARRAY, "79", {BGVRNS_SCHEME, DFLT, MULT_DEPTH, DFLT,     DFLT, DFLT,    DFLT,       DFLT,          DFLT,     DFLT,   DFLT,   FLEXIBLEAUTOEXT, DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    INVALID_BATCH_SIZE },
    { EVAL_SUM_PACKED_ARRAY, "80", {BGVRNS_SCHEME, DFLT, MULT_DEPTH, DFLT,     DFLT, DFLT,    DFLT,       DFLT,          DFLT,     DFLT,   DFLT,   FLEXIBLEAUTOEXT, DFLT,    PTM_LRG, DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    NO_KEY_GEN_CALL },
    // ==========================================
};
// clang-format on
//===========================================================================================================

class UTBGVRNS_AUTOMORPHISM : public ::testing::TestWithParam<TEST_CASE_UTBGVRNS_AUTOMORPHISM> {
    using Element    = DCRTPoly;
    const double eps = EPSILON;

    const std::vector<int64_t> vector8{1, 2, 3, 4, 5, 6, 7, 8};
    const std::vector<int64_t> vectorFailure{1, 2, 3, 4};
    const usint invalidIndexAutomorphism = 4;
    const int64_t vector8Sum             = std::accumulate(vector8.begin(), vector8.end(), int64_t(0));  // 36

protected:
    void SetUp() {}

    void TearDown() {
        PackedEncoding::Destroy();
        CryptoContextFactory<DCRTPoly>::ReleaseAllContexts();
    }

    void UnitTest_AutomorphismPackedArray(const TEST_CASE_UTBGVRNS_AUTOMORPHISM& testData,
                                          const std::string& failmsg = std::string()) {
        for (auto index : testData.indexList) {
            try {
                CryptoContext<Element> cc(UnitTestGenerateContext(testData.params));

                // Initialize the public key containers.
                KeyPair<Element> kp = cc->KeyGen();

                index                         = (INVALID_INDEX == testData.error) ? invalidIndexAutomorphism : index;
                std::vector<int64_t> inputVec = (INVALID_INPUT_DATA == testData.error) ? vectorFailure : vector8;
                Plaintext intArray            = cc->MakePackedPlaintext(inputVec);

                Ciphertext<Element> ciphertext =
                    (INVALID_PUBLIC_KEY == testData.error) ?
                        cc->Encrypt(static_cast<const PublicKey<Element>>(nullptr), intArray) :
                        cc->Encrypt(kp.publicKey, intArray);

                std::vector<usint> indexList(testData.indexList);

                auto evalKeys =
                    (INVALID_PRIVATE_KEY == testData.error) ?
                        cc->EvalAutomorphismKeyGen(static_cast<const PrivateKey<Element>>(nullptr), indexList) :
                        cc->EvalAutomorphismKeyGen(kp.secretKey, indexList);

                std::map<usint, EvalKey<Element>> emptyEvalKeys;
                Ciphertext<Element> p1 = (INVALID_EVAL_KEY == testData.error) ?
                                             cc->EvalAutomorphism(ciphertext, index, emptyEvalKeys) :
                                             cc->EvalAutomorphism(ciphertext, index, *evalKeys);

                Plaintext intArrayNew;
                cc->Decrypt(kp.secretKey, p1, &intArrayNew);

                std::string errMsg(" for index[" + std::to_string(index) + "]");
                switch (testData.error) {
                    case SUCCESS:
                        // should not fail
                        EXPECT_TRUE(CheckAutomorphism(intArrayNew->GetPackedValue(), vector8)) << errMsg;
                        break;
                    case INVALID_INPUT_DATA:
                        // should fail
                        EXPECT_FALSE(CheckAutomorphism(intArrayNew->GetPackedValue(), vector8)) << errMsg;
                        break;
                    default:
                        // make it fail
                        std::cerr << __func__ << " failed " << errMsg << std::endl;
                        EXPECT_EQ(0, 1);
                        break;
                }
            }
            catch (std::exception& e) {
                switch (testData.error) {
                    case SUCCESS:
                    case INVALID_INPUT_DATA:
                        std::cerr << "Exception thrown from " << __func__ << "(): " << e.what() << std::endl;
                        // make it fail
                        EXPECT_EQ(0, 1);
                        break;
                    default:
                        EXPECT_EQ(1, 1);
                        break;
                }
            }
            catch (...) {
#if defined EMSCRIPTEN
                std::string name("EMSCRIPTEN_UNKNOWN");
#else
                std::string name(demangle(__cxxabiv1::__cxa_current_exception_type()->name()));
#endif
                std::cerr << "Unknown exception of type \"" << name << "\" thrown from " << __func__ << "()"
                          << std::endl;
                // make it fail
                EXPECT_TRUE(0 == 1) << failmsg;
            }
        }
    }

    void UnitTest_EvalAtIndexPackedArray(const TEST_CASE_UTBGVRNS_AUTOMORPHISM& testData,
                                         const std::string& failmsg = std::string()) {
        for (auto index : testData.indexList) {
            try {
                CryptoContext<Element> cc(UnitTestGenerateContext(testData.params));

                // Initialize the public key containers.
                KeyPair<Element> kp = cc->KeyGen();

                std::vector<int64_t> inputVec = (INVALID_INPUT_DATA == testData.error) ? vectorFailure : vector8;
                Plaintext intArray            = cc->MakePackedPlaintext(inputVec);

                if (NO_KEY_GEN_CALL != testData.error) {
                    std::vector<int32_t> indices{(int32_t)index, (int32_t)-index};
                    if (INVALID_PRIVATE_KEY == testData.error)
                        cc->EvalAtIndexKeyGen(static_cast<const PrivateKey<Element>>(nullptr), indices);
                    else
                        cc->EvalAtIndexKeyGen(kp.secretKey, indices);
                }

                Ciphertext<Element> ciphertext =
                    (INVALID_PUBLIC_KEY == testData.error) ?
                        cc->Encrypt(static_cast<const PublicKey<Element>>(nullptr), intArray) :
                        cc->Encrypt(kp.publicKey, intArray);

                if (INVALID_INDEX == testData.error)
                    index = invalidIndexAutomorphism;
                Ciphertext<Element> p1 = cc->EvalAtIndex(ciphertext, index);
                Ciphertext<Element> p2 = cc->EvalAtIndex(p1, -index);

                Plaintext intArrayNew;
                cc->Decrypt(kp.secretKey, p2, &intArrayNew);
                intArrayNew->SetLength(inputVec.size());

                std::string errMsg(" for index[" + std::to_string(index) + "]");
                switch (testData.error) {
                    case SUCCESS:
                    case CORNER_CASES:
                        // should not fail
                        checkEquality(intArrayNew->GetPackedValue(), vector8, eps, errMsg);
                        break;
                    case INVALID_INPUT_DATA:
                        // should fail
                        EXPECT_FALSE(checkEquality(intArrayNew->GetPackedValue(), vector8)) << errMsg;
                        break;
                    default:
                        // make it fail
                        std::cerr << __func__ << " failed " << errMsg << std::endl;
                        EXPECT_EQ(0, 1);
                        break;
                }
            }
            catch (std::exception& e) {
                switch (testData.error) {
                    case SUCCESS:
                    case CORNER_CASES:
                    case INVALID_INPUT_DATA:
                        std::cerr << "Exception thrown from " << __func__ << "(): " << e.what() << std::endl;
                        // make it fail
                        EXPECT_EQ(0, 1);
                        break;
                    default:
                        EXPECT_EQ(1, 1);
                        break;
                }
            }
            catch (...) {
#if defined EMSCRIPTEN
                std::string name("EMSCRIPTEN_UNKNOWN");
#else
                std::string name(demangle(__cxxabiv1::__cxa_current_exception_type()->name()));
#endif
                std::cerr << "Unknown exception of type \"" << name << "\" thrown from " << __func__ << "()"
                          << std::endl;
                // make it fail
                EXPECT_TRUE(0 == 1) << failmsg;
            }
        }
    }

    void UnitTest_EvalSumPackedArray(const TEST_CASE_UTBGVRNS_AUTOMORPHISM& testData,
                                     const std::string& failmsg = std::string()) {
        try {
            CryptoContext<Element> cc(UnitTestGenerateContext(testData.params));

            // Initialize the public key containers.
            KeyPair<Element> kp = cc->KeyGen();

            std::vector<int64_t> inputVec = vector8;
            Plaintext intArray            = cc->MakePackedPlaintext(inputVec);

            if (NO_KEY_GEN_CALL != testData.error) {
                if (INVALID_PRIVATE_KEY == testData.error)
                    cc->EvalSumKeyGen(static_cast<const PrivateKey<Element>>(nullptr));
                else
                    cc->EvalSumKeyGen(kp.secretKey);
            }

            Ciphertext<Element> ciphertext = (INVALID_PUBLIC_KEY == testData.error) ?
                                                 cc->Encrypt(static_cast<const PublicKey<Element>>(nullptr), intArray) :
                                                 cc->Encrypt(kp.publicKey, intArray);

            uint32_t batchSize     = 8;
            uint32_t batchSz       = (INVALID_BATCH_SIZE == testData.error) ? (batchSize * 1000) : batchSize;
            Ciphertext<Element> p1 = cc->EvalSum(ciphertext, batchSz);

            Plaintext intArrayNew;
            cc->Decrypt(kp.secretKey, p1, &intArrayNew);

            switch (testData.error) {
                case SUCCESS:
                    // should not fail
                    EXPECT_TRUE(checkEquality(intArrayNew->GetPackedValue()[0], vector8Sum));
                    break;
                default:
                    // make it fail
                    std::cerr << __func__ << " failed" << std::endl;
                    EXPECT_EQ(0, 1);
                    break;
            }
        }
        catch (std::exception& e) {
            if (SUCCESS == testData.error) {
                std::cerr << "Exception thrown from " << __func__ << "(): " << e.what() << std::endl;
                // make it fail
                EXPECT_EQ(0, 1);
            }
            else
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
            EXPECT_TRUE(0 == 1) << failmsg;
        }
    }
};

//===========================================================================================================
TEST_P(UTBGVRNS_AUTOMORPHISM, Automorphism) {
    setupSignals();
    auto test = GetParam();

    switch (test.testCaseType) {
        case BGVRNS_AUTOMORPHISM:
            UnitTest_AutomorphismPackedArray(test, test.buildTestName());
            break;
        case EVAL_AT_INDX_PACKED_ARRAY:
            UnitTest_EvalAtIndexPackedArray(test, test.buildTestName());
            break;
        case EVAL_SUM_PACKED_ARRAY:
            UnitTest_EvalSumPackedArray(test, test.buildTestName());
            break;
        default:
            break;
    }
}

INSTANTIATE_TEST_SUITE_P(UnitTests, UTBGVRNS_AUTOMORPHISM, ::testing::ValuesIn(testCasesUTBGVRNS_AUTOMORPHISM),
                         testName);
