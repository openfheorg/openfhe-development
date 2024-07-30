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
  UnitTestAutomorphism for all transform testing
 */
#include "UnitTestUtils.h"
#include "UnitTestCCParams.h"
#include "UnitTestCryptoContext.h"

#include <iostream>
#include <vector>
#include "gtest/gtest.h"

using namespace lbcrypto;

//===========================================================================================================
enum TEST_CASE_TYPE {
    EVAL_AT_INDX_PACKED_ARRAY = 0,
    EVAL_SUM_PACKED_ARRAY,
    EVAL_SUM_ROWS,
    EVAL_SUM_COLS,
};

static std::ostream& operator<<(std::ostream& os, const TEST_CASE_TYPE& type) {
    std::string typeName;
    switch (type) {
        case EVAL_AT_INDX_PACKED_ARRAY:
            typeName = "EVAL_AT_INDX_PACKED_ARRAY";
            break;
        case EVAL_SUM_PACKED_ARRAY:
            typeName = "EVAL_SUM_PACKED_ARRAY";
            break;
        case EVAL_SUM_ROWS:
            typeName = "EVAL_SUM_ROWS";
            break;
        case EVAL_SUM_COLS:
            typeName = "EVAL_SUM_COLS";
            break;
        default:
            typeName = "UNKNOWN_UTCKKSRNS_AUTOMORPHISM";
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
    NO_KEY_GEN_CALL,
};

struct TEST_CASE_UTCKKSRNS_AUTOMORPHISM {
    TEST_CASE_TYPE testCaseType;
    // test case description - MUST BE UNIQUE
    std::string description;

    UnitTestCCParams params;

    // additional test case data
    TEST_CASE_ERROR error;
    const std::vector<int32_t> indexList;

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
static auto testName = [](const testing::TestParamInfo<TEST_CASE_UTCKKSRNS_AUTOMORPHISM>& test) {
    return test.param.buildTestName();
};

static std::ostream& operator<<(std::ostream& os, const TEST_CASE_UTCKKSRNS_AUTOMORPHISM& test) {
    return os << test.toString();
}
//===========================================================================================================
constexpr usint SMODSIZE        = 50;
constexpr usint RING_DIM        = 16;
constexpr usint BATCH           = 8;
constexpr usint MULT_DEPTH      = 1;
constexpr SecurityLevel SEC_LVL = HEStd_NotSet;
static const std::vector<int32_t> initIndexList{3, 5, 7, 9, 11, 13, 15};
static const std::vector<int32_t> cornerCaseIndexList{0};

// clang-format off
static std::vector<TEST_CASE_UTCKKSRNS_AUTOMORPHISM> testCasesUTCKKSRNS_AUTOMORPHISM = {
    // TestType,                Descr,  Scheme,         RDim,     MultDepth,  SModSize, DSize,BatchSz, SecKeyDist, MaxRelinSkDeg, FModSize, SecLvl,  KSTech, ScalTech,        LDigits, PtMod, StdDev, EvalAddCt, KSCt, MultTech, EncTech, PREMode, Error,               indexList
    { EVAL_AT_INDX_PACKED_ARRAY, "01", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SMODSIZE, DFLT, BATCH,   DFLT,       DFLT,          DFLT,     SEC_LVL, DFLT,   FIXEDMANUAL,     DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   SUCCESS,             initIndexList },
    { EVAL_AT_INDX_PACKED_ARRAY, "02", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SMODSIZE, DFLT, BATCH,   DFLT,       DFLT,          DFLT,     SEC_LVL, DFLT,   FIXEDMANUAL,     DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   CORNER_CASES,        cornerCaseIndexList },
    { EVAL_AT_INDX_PACKED_ARRAY, "03", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SMODSIZE, DFLT, BATCH,   DFLT,       DFLT,          DFLT,     SEC_LVL, DFLT,   FIXEDMANUAL,     DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   INVALID_INPUT_DATA,  initIndexList },
    { EVAL_AT_INDX_PACKED_ARRAY, "04", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SMODSIZE, DFLT, BATCH,   DFLT,       DFLT,          DFLT,     SEC_LVL, DFLT,   FIXEDMANUAL,     DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   INVALID_PRIVATE_KEY, initIndexList },
    { EVAL_AT_INDX_PACKED_ARRAY, "05", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SMODSIZE, DFLT, BATCH,   DFLT,       DFLT,          DFLT,     SEC_LVL, DFLT,   FIXEDMANUAL,     DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   INVALID_PUBLIC_KEY,  initIndexList },
    { EVAL_AT_INDX_PACKED_ARRAY, "06", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SMODSIZE, DFLT, BATCH,   DFLT,       DFLT,          DFLT,     SEC_LVL, DFLT,   FIXEDMANUAL,     DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   NO_KEY_GEN_CALL,     initIndexList },
    { EVAL_AT_INDX_PACKED_ARRAY, "07", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SMODSIZE, DFLT, BATCH,   DFLT,       DFLT,          DFLT,     SEC_LVL, DFLT,   FIXEDMANUAL,     DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   INVALID_INDEX,       initIndexList },
    // ==========================================
    { EVAL_AT_INDX_PACKED_ARRAY, "11", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SMODSIZE, DFLT, BATCH,   DFLT,       DFLT,          DFLT,     SEC_LVL, DFLT,   FIXEDAUTO,       DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   SUCCESS,             initIndexList },
    { EVAL_AT_INDX_PACKED_ARRAY, "12", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SMODSIZE, DFLT, BATCH,   DFLT,       DFLT,          DFLT,     SEC_LVL, DFLT,   FIXEDAUTO,       DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   CORNER_CASES,        cornerCaseIndexList },
    { EVAL_AT_INDX_PACKED_ARRAY, "13", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SMODSIZE, DFLT, BATCH,   DFLT,       DFLT,          DFLT,     SEC_LVL, DFLT,   FIXEDAUTO,       DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   INVALID_INPUT_DATA,  initIndexList },
    { EVAL_AT_INDX_PACKED_ARRAY, "14", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SMODSIZE, DFLT, BATCH,   DFLT,       DFLT,          DFLT,     SEC_LVL, DFLT,   FIXEDAUTO,       DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   INVALID_PRIVATE_KEY, initIndexList },
    { EVAL_AT_INDX_PACKED_ARRAY, "15", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SMODSIZE, DFLT, BATCH,   DFLT,       DFLT,          DFLT,     SEC_LVL, DFLT,   FIXEDAUTO,       DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   INVALID_PUBLIC_KEY,  initIndexList },
    { EVAL_AT_INDX_PACKED_ARRAY, "16", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SMODSIZE, DFLT, BATCH,   DFLT,       DFLT,          DFLT,     SEC_LVL, DFLT,   FIXEDAUTO,       DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   NO_KEY_GEN_CALL,     initIndexList },
    { EVAL_AT_INDX_PACKED_ARRAY, "17", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SMODSIZE, DFLT, BATCH,   DFLT,       DFLT,          DFLT,     SEC_LVL, DFLT,   FIXEDAUTO,       DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   INVALID_INDEX,       initIndexList },
    // ==========================================
#if NATIVEINT != 128
    { EVAL_AT_INDX_PACKED_ARRAY, "21", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SMODSIZE, DFLT, BATCH,   DFLT,       DFLT,          DFLT,     SEC_LVL, DFLT,   FLEXIBLEAUTO,    DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   SUCCESS,             initIndexList },
    { EVAL_AT_INDX_PACKED_ARRAY, "22", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SMODSIZE, DFLT, BATCH,   DFLT,       DFLT,          DFLT,     SEC_LVL, DFLT,   FLEXIBLEAUTO,    DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   CORNER_CASES,        cornerCaseIndexList },
    { EVAL_AT_INDX_PACKED_ARRAY, "23", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SMODSIZE, DFLT, BATCH,   DFLT,       DFLT,          DFLT,     SEC_LVL, DFLT,   FLEXIBLEAUTO,    DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   INVALID_INPUT_DATA,  initIndexList },
    { EVAL_AT_INDX_PACKED_ARRAY, "24", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SMODSIZE, DFLT, BATCH,   DFLT,       DFLT,          DFLT,     SEC_LVL, DFLT,   FLEXIBLEAUTO,    DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   INVALID_PRIVATE_KEY, initIndexList },
    { EVAL_AT_INDX_PACKED_ARRAY, "25", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SMODSIZE, DFLT, BATCH,   DFLT,       DFLT,          DFLT,     SEC_LVL, DFLT,   FLEXIBLEAUTO,    DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   INVALID_PUBLIC_KEY,  initIndexList },
    { EVAL_AT_INDX_PACKED_ARRAY, "26", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SMODSIZE, DFLT, BATCH,   DFLT,       DFLT,          DFLT,     SEC_LVL, DFLT,   FLEXIBLEAUTO,    DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   NO_KEY_GEN_CALL,     initIndexList },
    { EVAL_AT_INDX_PACKED_ARRAY, "27", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SMODSIZE, DFLT, BATCH,   DFLT,       DFLT,          DFLT,     SEC_LVL, DFLT,   FLEXIBLEAUTO,    DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   INVALID_INDEX,       initIndexList },
    // ==========================================
    { EVAL_AT_INDX_PACKED_ARRAY, "31", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SMODSIZE, DFLT, BATCH,   DFLT,       DFLT,          DFLT,     SEC_LVL, DFLT,   FLEXIBLEAUTOEXT, DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   SUCCESS,             initIndexList },
    { EVAL_AT_INDX_PACKED_ARRAY, "32", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SMODSIZE, DFLT, BATCH,   DFLT,       DFLT,          DFLT,     SEC_LVL, DFLT,   FLEXIBLEAUTOEXT, DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   CORNER_CASES,        cornerCaseIndexList },
    { EVAL_AT_INDX_PACKED_ARRAY, "33", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SMODSIZE, DFLT, BATCH,   DFLT,       DFLT,          DFLT,     SEC_LVL, DFLT,   FLEXIBLEAUTOEXT, DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   INVALID_INPUT_DATA,  initIndexList },
    { EVAL_AT_INDX_PACKED_ARRAY, "34", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SMODSIZE, DFLT, BATCH,   DFLT,       DFLT,          DFLT,     SEC_LVL, DFLT,   FLEXIBLEAUTOEXT, DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   INVALID_PRIVATE_KEY, initIndexList },
    { EVAL_AT_INDX_PACKED_ARRAY, "35", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SMODSIZE, DFLT, BATCH,   DFLT,       DFLT,          DFLT,     SEC_LVL, DFLT,   FLEXIBLEAUTOEXT, DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   INVALID_PUBLIC_KEY,  initIndexList },
    { EVAL_AT_INDX_PACKED_ARRAY, "36", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SMODSIZE, DFLT, BATCH,   DFLT,       DFLT,          DFLT,     SEC_LVL, DFLT,   FLEXIBLEAUTOEXT, DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   NO_KEY_GEN_CALL,     initIndexList },
    { EVAL_AT_INDX_PACKED_ARRAY, "37", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SMODSIZE, DFLT, BATCH,   DFLT,       DFLT,          DFLT,     SEC_LVL, DFLT,   FLEXIBLEAUTOEXT, DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   INVALID_INDEX,       initIndexList },
#endif
    // ==========================================
    // TestType,            Descr,  Scheme,         RDim,     MultDepth,  SModSize, DSize,BatchSz, SecKeyDist, MaxRelinSkDeg, FModSize, SecLvl,  KSTech, ScalTech,        LDigits, PtMod, StdDev, EvalAddCt, KSCt, MultTech, EncTech, PREMode, Error,               indexList
    { EVAL_SUM_PACKED_ARRAY, "01", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SMODSIZE, DFLT, BATCH,   DFLT,       DFLT,          DFLT,     SEC_LVL, DFLT,   FIXEDMANUAL,     DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   SUCCESS },
    { EVAL_SUM_PACKED_ARRAY, "02", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SMODSIZE, DFLT, BATCH,   DFLT,       DFLT,          DFLT,     SEC_LVL, DFLT,   FIXEDMANUAL,     DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   INVALID_PRIVATE_KEY },
    { EVAL_SUM_PACKED_ARRAY, "03", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SMODSIZE, DFLT, BATCH,   DFLT,       DFLT,          DFLT,     SEC_LVL, DFLT,   FIXEDMANUAL,     DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   INVALID_PUBLIC_KEY },
    { EVAL_SUM_PACKED_ARRAY, "04", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SMODSIZE, DFLT, BATCH,   DFLT,       DFLT,          DFLT,     SEC_LVL, DFLT,   FIXEDMANUAL,     DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   INVALID_BATCH_SIZE },
    { EVAL_SUM_PACKED_ARRAY, "05", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SMODSIZE, DFLT, BATCH,   DFLT,       DFLT,          DFLT,     SEC_LVL, DFLT,   FIXEDMANUAL,     DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   NO_KEY_GEN_CALL },
    // ==========================================
    { EVAL_SUM_PACKED_ARRAY, "11", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SMODSIZE, DFLT, BATCH,   DFLT,       DFLT,          DFLT,     SEC_LVL, DFLT,   FIXEDAUTO,       DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   SUCCESS },
    { EVAL_SUM_PACKED_ARRAY, "12", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SMODSIZE, DFLT, BATCH,   DFLT,       DFLT,          DFLT,     SEC_LVL, DFLT,   FIXEDAUTO,       DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   INVALID_PRIVATE_KEY },
    { EVAL_SUM_PACKED_ARRAY, "13", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SMODSIZE, DFLT, BATCH,   DFLT,       DFLT,          DFLT,     SEC_LVL, DFLT,   FIXEDAUTO,       DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   INVALID_PUBLIC_KEY },
    { EVAL_SUM_PACKED_ARRAY, "14", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SMODSIZE, DFLT, BATCH,   DFLT,       DFLT,          DFLT,     SEC_LVL, DFLT,   FIXEDAUTO,       DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   INVALID_BATCH_SIZE },
    { EVAL_SUM_PACKED_ARRAY, "15", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SMODSIZE, DFLT, BATCH,   DFLT,       DFLT,          DFLT,     SEC_LVL, DFLT,   FIXEDAUTO,       DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   NO_KEY_GEN_CALL },
#if NATIVEINT != 128
    { EVAL_SUM_PACKED_ARRAY, "21", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SMODSIZE, DFLT, BATCH,   DFLT,       DFLT,          DFLT,     SEC_LVL, DFLT,   FLEXIBLEAUTOEXT, DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   SUCCESS },
    { EVAL_SUM_PACKED_ARRAY, "22", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SMODSIZE, DFLT, BATCH,   DFLT,       DFLT,          DFLT,     SEC_LVL, DFLT,   FLEXIBLEAUTOEXT, DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   INVALID_PRIVATE_KEY },
    { EVAL_SUM_PACKED_ARRAY, "23", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SMODSIZE, DFLT, BATCH,   DFLT,       DFLT,          DFLT,     SEC_LVL, DFLT,   FLEXIBLEAUTOEXT, DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   INVALID_PUBLIC_KEY },
    { EVAL_SUM_PACKED_ARRAY, "24", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SMODSIZE, DFLT, BATCH,   DFLT,       DFLT,          DFLT,     SEC_LVL, DFLT,   FLEXIBLEAUTOEXT, DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   INVALID_BATCH_SIZE },
    { EVAL_SUM_PACKED_ARRAY, "25", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SMODSIZE, DFLT, BATCH,   DFLT,       DFLT,          DFLT,     SEC_LVL, DFLT,   FLEXIBLEAUTOEXT, DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   NO_KEY_GEN_CALL },
    // ==========================================
    { EVAL_SUM_PACKED_ARRAY, "31", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SMODSIZE, DFLT, BATCH,   DFLT,       DFLT,          DFLT,     SEC_LVL, DFLT,   FLEXIBLEAUTOEXT, DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   SUCCESS },
    { EVAL_SUM_PACKED_ARRAY, "32", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SMODSIZE, DFLT, BATCH,   DFLT,       DFLT,          DFLT,     SEC_LVL, DFLT,   FLEXIBLEAUTOEXT, DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   INVALID_PRIVATE_KEY },
    { EVAL_SUM_PACKED_ARRAY, "33", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SMODSIZE, DFLT, BATCH,   DFLT,       DFLT,          DFLT,     SEC_LVL, DFLT,   FLEXIBLEAUTOEXT, DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   INVALID_PUBLIC_KEY },
    { EVAL_SUM_PACKED_ARRAY, "34", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SMODSIZE, DFLT, BATCH,   DFLT,       DFLT,          DFLT,     SEC_LVL, DFLT,   FLEXIBLEAUTOEXT, DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   INVALID_BATCH_SIZE },
    { EVAL_SUM_PACKED_ARRAY, "35", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SMODSIZE, DFLT, BATCH,   DFLT,       DFLT,          DFLT,     SEC_LVL, DFLT,   FLEXIBLEAUTOEXT, DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   NO_KEY_GEN_CALL },
#endif
    // ==========================================
    // TestType,    Descr,  Scheme,         RDim,     MultDepth,  SModSize, DSize,BatchSz,    SecKeyDist, MaxRelinSkDeg, FModSize, SecLvl,  KSTech, ScalTech, LDigits, PtMod, StdDev, EvalAddCt, KSCt, MultTech, EncTech, PREMode, Error,               indexList
    { EVAL_SUM_ROWS, "01", {CKKSRNS_SCHEME, RING_DIM, DFLT,       DFLT,     DFLT, RING_DIM/2, DFLT,       DFLT,          DFLT,     SEC_LVL, DFLT,   DFLT,     DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   SUCCESS },
    // ==========================================
    // TestType,    Descr,  Scheme,         RDim,     MultDepth,  SModSize, DSize,BatchSz,    SecKeyDist, MaxRelinSkDeg, FModSize, SecLvl,  KSTech, ScalTech, LDigits, PtMod, StdDev, EvalAddCt, KSCt, MultTech, EncTech, PREMode, Error,               indexList
    { EVAL_SUM_COLS, "01", {CKKSRNS_SCHEME, RING_DIM, DFLT,       DFLT,     DFLT, RING_DIM/2, DFLT,       DFLT,          DFLT,     SEC_LVL, DFLT,   DFLT,     DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   SUCCESS },
};
// clang-format on
//===========================================================================================================

class UTCKKSRNS_AUTOMORPHISM : public ::testing::TestWithParam<TEST_CASE_UTCKKSRNS_AUTOMORPHISM> {
    using Element    = DCRTPoly;
    const double eps = EPSILON;

    const std::vector<int64_t> vector8{1, 2, 3, 4, 5, 6, 7, 8};
    const std::vector<int64_t> vector10{1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
    const std::vector<int64_t> vectorFailure{1, 2, 3, 4};
    const usint invalidIndexAutomorphism = 4;
    const std::vector<std::complex<double>> vectorComplexFailure{1.0, 2.0, 3.0, 4.0};
    const std::vector<std::complex<double>> vector8Complex{1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0};
    const std::complex<double> vector8ComplexSum =
        std::accumulate(vector8Complex.begin(), vector8Complex.end(), std::complex<double>(0));  // 36.0;
    const int64_t vector8Sum = std::accumulate(vector8.begin(), vector8.end(), int64_t(0));      // 36

protected:
    void SetUp() {}

    void TearDown() {
        PackedEncoding::Destroy();
        CryptoContextFactory<DCRTPoly>::ReleaseAllContexts();
    }

    void UnitTest_EvalAtIndexPackedArray(const TEST_CASE_UTCKKSRNS_AUTOMORPHISM& testData,
                                         const std::string& failmsg = std::string()) {
        for (auto index : testData.indexList) {
            try {
                CryptoContext<Element> cc(UnitTestGenerateContext(testData.params));

                // Initialize the public key containers.
                KeyPair<Element> kp = cc->KeyGen();

                std::vector<std::complex<double>> inputVec =
                    (INVALID_INPUT_DATA == testData.error) ? vectorComplexFailure : vector8Complex;
                Plaintext intArray = cc->MakeCKKSPackedPlaintext(inputVec);

                std::vector<int32_t> indices{index, -index};
                if (NO_KEY_GEN_CALL != testData.error) {
                    if (INVALID_PRIVATE_KEY == testData.error) {
                        cc->EvalAtIndexKeyGen(nullptr, indices);
                    }
                    else {
                        cc->EvalAtIndexKeyGen(kp.secretKey, indices);
                    }
                }

                Ciphertext<Element> ciphertext = (INVALID_PUBLIC_KEY == testData.error) ?
                                                     cc->Encrypt(PublicKey<Element>(nullptr), intArray) :
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
                        checkEquality(intArrayNew->GetCKKSPackedValue(), vector8Complex, eps, errMsg);
                        break;
                    case INVALID_INPUT_DATA:
                        // should fail
                        EXPECT_FALSE(checkEquality(intArrayNew->GetCKKSPackedValue(), vector8Complex)) << errMsg;
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
                UNIT_TEST_HANDLE_ALL_EXCEPTIONS;
            }
        }
    }

    void UnitTest_EvalSumPackedArray(const TEST_CASE_UTCKKSRNS_AUTOMORPHISM& testData,
                                     const std::string& failmsg = std::string()) {
        try {
            CryptoContext<Element> cc(UnitTestGenerateContext(testData.params));

            // Initialize the public key containers.
            KeyPair<Element> kp = cc->KeyGen();

            std::vector<std::complex<double>> inputVec = vector8Complex;
            Plaintext intArray                         = cc->MakeCKKSPackedPlaintext(inputVec);

            if (NO_KEY_GEN_CALL != testData.error) {
                if (INVALID_PRIVATE_KEY == testData.error)
                    cc->EvalSumKeyGen(nullptr);
                else
                    cc->EvalSumKeyGen(kp.secretKey);
            }

            Ciphertext<Element> ciphertext = (INVALID_PUBLIC_KEY == testData.error) ?
                                                 cc->Encrypt(PublicKey<Element>(nullptr), intArray) :
                                                 cc->Encrypt(kp.publicKey, intArray);

            uint32_t batchSz       = (INVALID_BATCH_SIZE == testData.error) ? (BATCH * 2) : BATCH;
            Ciphertext<Element> p1 = cc->EvalSum(ciphertext, batchSz);

            Plaintext intArrayNew;
            cc->Decrypt(kp.secretKey, p1, &intArrayNew);

            switch (testData.error) {
                case SUCCESS:
                case CORNER_CASES:
                    // should not fail
                    EXPECT_TRUE(checkEquality(intArrayNew->GetCKKSPackedValue()[0], vector8ComplexSum));
                    break;
                case INVALID_INPUT_DATA:
                    // should fail
                    EXPECT_FALSE(checkEquality(intArrayNew->GetCKKSPackedValue()[0], vector8ComplexSum));
                    break;
                default:
                    // make it fail
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
            UNIT_TEST_HANDLE_ALL_EXCEPTIONS;
        }
    }

    void UnitTest_EvalSumRows(const TEST_CASE_UTCKKSRNS_AUTOMORPHISM& testData,
                              const std::string& failmsg = std::string()) {
        try {
            CryptoContext<Element> cc(UnitTestGenerateContext(testData.params));

            KeyPair<Element> kp = cc->KeyGen();

            std::vector<double> mat{1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0};
            uint32_t rowSize   = 4;
            uint32_t batchSize = cc->GetEncodingParams()->GetBatchSize();

            const std::vector<std::complex<double>> outputSumRows{6.0, 8.0, 10.0, 12.0, 6.0, 8.0, 10.0, 12.0};

            // Encoding as plaintexts
            Plaintext ptxtMat = cc->MakeCKKSPackedPlaintext(mat);

            // Encrypt the encoded vectors
            auto ctMat = cc->Encrypt(kp.publicKey, ptxtMat);

            auto evalSumRowKeys = cc->EvalSumRowsKeyGen(kp.secretKey, nullptr, rowSize);

            // Evaluation
            auto ctRowsSum = cc->EvalSumRows(ctMat, rowSize, *evalSumRowKeys);

            // Decrypt
            Plaintext result;
            cc->Decrypt(kp.secretKey, ctRowsSum, &result);
            result->SetLength(batchSize);
            // std::cout << "sum Rows: " << result;
            checkEquality(result->GetCKKSPackedValue(), outputSumRows, eps,
                          failmsg + " EvalSumRowsKeyGen()/EvalSumRows fails - result is incorrect");
        }
        catch (std::exception& e) {
            std::cerr << "Exception thrown from " << __func__ << "(): " << e.what() << std::endl;
            // make it fail
            EXPECT_TRUE(0 == 1) << failmsg;
        }
        catch (...) {
            UNIT_TEST_HANDLE_ALL_EXCEPTIONS;
        }
    }

    void UnitTest_EvalSumCols(const TEST_CASE_UTCKKSRNS_AUTOMORPHISM& testData,
                              const std::string& failmsg = std::string()) {
        try {
            CryptoContext<Element> cc(UnitTestGenerateContext(testData.params));

            KeyPair<Element> kp = cc->KeyGen();

            std::vector<double> mat{8.0, 1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0};
            uint32_t colSize   = 4;
            uint32_t batchSize = cc->GetEncodingParams()->GetBatchSize();

            const std::vector<std::complex<double>> outputSumCols{14.0, 14.0, 14.0, 14.0, 22.0, 22.0, 22.0, 22.0};

            // Encoding as plaintexts
            Plaintext ptxtMat = cc->MakeCKKSPackedPlaintext(mat);

            // Encrypt the encoded vectors
            auto ctMat = cc->Encrypt(kp.publicKey, ptxtMat);

            auto evalSumColKeys = cc->EvalSumColsKeyGen(kp.secretKey);

            // Evaluation
            auto ctColsSum = cc->EvalSumCols(ctMat, colSize, *evalSumColKeys);

            // Decrypt
            Plaintext result;
            cc->Decrypt(kp.secretKey, ctColsSum, &result);
            result->SetLength(batchSize);
            // std::cout << "sum Cols: " << result;
            checkEquality(result->GetCKKSPackedValue(), outputSumCols, eps,
                          failmsg + " EvalSumColsKeyGen()/EvalSumCols fails - result is incorrect");
        }
        catch (std::exception& e) {
            std::cerr << "Exception thrown from " << __func__ << "(): " << e.what() << std::endl;
            // make it fail
            EXPECT_TRUE(0 == 1) << failmsg;
        }
        catch (...) {
            UNIT_TEST_HANDLE_ALL_EXCEPTIONS;
        }
    }
};
//===========================================================================================================
TEST_P(UTCKKSRNS_AUTOMORPHISM, Automorphism) {
    setupSignals();
    auto test = GetParam();

    switch (test.testCaseType) {
        case EVAL_AT_INDX_PACKED_ARRAY:
            UnitTest_EvalAtIndexPackedArray(test, test.buildTestName());
            break;
        case EVAL_SUM_PACKED_ARRAY:
            UnitTest_EvalSumPackedArray(test, test.buildTestName());
            break;
        case EVAL_SUM_ROWS:
            UnitTest_EvalSumRows(test, test.buildTestName());
            break;
        case EVAL_SUM_COLS:
            UnitTest_EvalSumCols(test, test.buildTestName());
            break;
        default:
            break;
    }
}

INSTANTIATE_TEST_SUITE_P(UnitTests, UTCKKSRNS_AUTOMORPHISM, ::testing::ValuesIn(testCasesUTCKKSRNS_AUTOMORPHISM),
                         testName);
