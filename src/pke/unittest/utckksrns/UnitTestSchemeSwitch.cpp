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
  Unit tests for the scheme switching
 */

#include "UnitTestUtils.h"
#include "UnitTestCCParams.h"
#include "UnitTestCryptoContext.h"
#include "utils/demangle.h"
#include "scheme/ckksrns/ckksrns-utils.h"

#include <iostream>
#include <vector>
#include "gtest/gtest.h"
#include <cxxabi.h>
#include <iterator>

using namespace lbcrypto;

//===========================================================================================================
enum TEST_CASE_TYPE {
    SCHEME_SWITCH_CKKS_FHEW,
    SCHEME_SWITCH_FHEW_CKKS,
    SCHEME_SWITCH_COMPARISON,
    SCHEME_SWITCH_FUNC,
    SCHEME_SWITCH_ARGMIN,
    SCHEME_SWITCH_ALT_ARGMIN,
};

static std::ostream& operator<<(std::ostream& os, const TEST_CASE_TYPE& type) {
    std::string typeName;
    switch (type) {
        case SCHEME_SWITCH_CKKS_FHEW:
            typeName = "SCHEME_SWITCH_CKKS_FHEW";
            break;
        case SCHEME_SWITCH_FHEW_CKKS:
            typeName = "SCHEME_SWITCH_FHEW_CKKS";
            break;
        case SCHEME_SWITCH_COMPARISON:
            typeName = "SCHEME_SWITCH_COMPARISON";
            break;
        case SCHEME_SWITCH_ARGMIN:
            typeName = "SCHEME_SWITCH_ARGMIN";
            break;
        case SCHEME_SWITCH_ALT_ARGMIN:
            typeName = "SCHEME_SWITCH_ALT_ARGMIN";
            break;
        default:
            typeName = "UNKNOWN";
            break;
    }
    return os << typeName;
}
//===========================================================================================================
struct TEST_CASE_UTCKKSRNS_SCHEMESWITCH {
    TEST_CASE_TYPE testCaseType;
    // test case description - MUST BE UNIQUE
    std::string description;

    UnitTestCCParams params;

    // additional test case data
    // ........
    std::vector<uint32_t> dim1;  // dim1_CF, dim1_FC
    uint32_t logQ;
    uint32_t numValues;
    uint32_t slots;
    bool oneHot;

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
static auto testName = [](const testing::TestParamInfo<TEST_CASE_UTCKKSRNS_SCHEMESWITCH>& test) {
    return test.param.buildTestName();
};

static std::ostream& operator<<(std::ostream& os, const TEST_CASE_UTCKKSRNS_SCHEMESWITCH& test) {
    return os << test.toString();
}
//===========================================================================================================

constexpr uint32_t MULT_DEPTH1  = 13;
constexpr uint32_t MULT_DEPTH2  = 16;
constexpr uint32_t RDIM         = 64;
constexpr uint32_t NUM_LRG_DIGS = 3;

#if NATIVEINT == 128 && !defined(__EMSCRIPTEN__)
constexpr uint32_t SMODSIZE = 70;
constexpr uint32_t FMODSIZE = 80;
#else
constexpr uint32_t SMODSIZE = 50;
constexpr uint32_t FMODSIZE = 60;
#endif

// clang-format off
static std::vector<TEST_CASE_UTCKKSRNS_SCHEMESWITCH> testCases = {
    // TestType,     Descr, Scheme,          RDim, MultDepth,  SModSize,     DSize, BatchSz, SecKeyDist,      MaxRelinSkDeg, FModSize,  SecLvl,       KSTech, ScalTech,        LDigits,      PtMod, StdDev, EvalAddCt, KSCt, MultTech, EncTech, PREMode, Dim1, LogQ, NumValues, Slots
    { SCHEME_SWITCH_CKKS_FHEW, "01", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH1, SMODSIZE,     DFLT,  DFLT,    UNIFORM_TERNARY, DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FIXEDAUTO,       NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   { 16, 16 }, 25, 8, 8 },
    { SCHEME_SWITCH_CKKS_FHEW, "02", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH1, SMODSIZE,     DFLT,  DFLT,    UNIFORM_TERNARY, DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FIXEDMANUAL,     NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   { 16, 16 }, 25, 8, 8 },
    { SCHEME_SWITCH_CKKS_FHEW, "03", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH1, SMODSIZE,     DFLT,  DFLT,    UNIFORM_TERNARY, DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FIXEDAUTO,       NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   { 16, 16 }, 25, 8, RDIM/2 },
    { SCHEME_SWITCH_CKKS_FHEW, "04", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH1, SMODSIZE,     DFLT,  DFLT,    UNIFORM_TERNARY, DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FIXEDMANUAL,     NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   { 16, 16 }, 25, 8, RDIM/2 },
    { SCHEME_SWITCH_CKKS_FHEW, "05", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH1, SMODSIZE,     DFLT,  DFLT,    SPARSE_TERNARY, DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FIXEDAUTO,       NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   { 16, 16 }, 25, 8, 8 },
    { SCHEME_SWITCH_CKKS_FHEW, "06", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH1, SMODSIZE,     DFLT,  DFLT,    SPARSE_TERNARY, DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FIXEDMANUAL,     NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   { 16, 16 }, 25, 8, 8 },
    { SCHEME_SWITCH_CKKS_FHEW, "07", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH1, SMODSIZE,     DFLT,  DFLT,    SPARSE_TERNARY, DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FIXEDAUTO,       NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   { 16, 16 }, 25, 8, RDIM/2 },
    { SCHEME_SWITCH_CKKS_FHEW, "08", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH1, SMODSIZE,     DFLT,  DFLT,    SPARSE_TERNARY, DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FIXEDMANUAL,     NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   { 16, 16 }, 25, 8, RDIM/2 },
#if NATIVEINT != 128
    { SCHEME_SWITCH_CKKS_FHEW, "09", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH1, SMODSIZE,     DFLT,  DFLT,    UNIFORM_TERNARY,  DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FLEXIBLEAUTO,    NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   { 16, 16 }, 25, 8, 8 },
    { SCHEME_SWITCH_CKKS_FHEW, "10", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH1, SMODSIZE,     DFLT,  DFLT,    UNIFORM_TERNARY,  DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FLEXIBLEAUTOEXT, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   { 16, 16 }, 25, 8, 8 },
    { SCHEME_SWITCH_CKKS_FHEW, "11", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH1, SMODSIZE,     DFLT,  DFLT,    UNIFORM_TERNARY,  DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FLEXIBLEAUTO,    NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   { 16, 16 }, 25, 8, RDIM/2 },
    { SCHEME_SWITCH_CKKS_FHEW, "12", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH1, SMODSIZE,     DFLT,  DFLT,    UNIFORM_TERNARY,  DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FLEXIBLEAUTOEXT, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   { 16, 16 }, 25, 8, RDIM/2 },
    { SCHEME_SWITCH_CKKS_FHEW, "13", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH1, SMODSIZE,     DFLT,  DFLT,    SPARSE_TERNARY,  DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FLEXIBLEAUTO,    NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   { 16, 16 }, 25, 8, 8 },
    { SCHEME_SWITCH_CKKS_FHEW, "14", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH1, SMODSIZE,     DFLT,  DFLT,    SPARSE_TERNARY,  DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FLEXIBLEAUTOEXT, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   { 16, 16 }, 25, 8, 8 },
    { SCHEME_SWITCH_CKKS_FHEW, "15", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH1, SMODSIZE,     DFLT,  DFLT,    SPARSE_TERNARY,  DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FLEXIBLEAUTO,    NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   { 16, 16 }, 25, 8, RDIM/2 },
    { SCHEME_SWITCH_CKKS_FHEW, "16", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH1, SMODSIZE,     DFLT,  DFLT,    SPARSE_TERNARY,  DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FLEXIBLEAUTOEXT, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   { 16, 16 }, 25, 8, RDIM/2 },

#endif
    // ==========================================
    // TestType,     Descr, Scheme,          RDim, MultDepth,  SModSize,     DSize, BatchSz, SecKeyDist,      MaxRelinSkDeg, FModSize,  SecLvl,       KSTech, ScalTech,        LDigits,      PtMod, StdDev, EvalAddCt, KSCt, MultTech, EncTech, PREMode, Dim1, LogQ, NumValues, Slots
    { SCHEME_SWITCH_FHEW_CKKS, "01", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH1, SMODSIZE,     DFLT,  DFLT,    UNIFORM_TERNARY, DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FIXEDAUTO,       NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   { 16, 16 }, 25, 8, 8 },
    { SCHEME_SWITCH_FHEW_CKKS, "02", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH1, SMODSIZE,     DFLT,  DFLT,    UNIFORM_TERNARY, DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FIXEDMANUAL,     NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   { 16, 16 }, 25, 8, 8 },
    { SCHEME_SWITCH_FHEW_CKKS, "03", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH1, SMODSIZE,     DFLT,  DFLT,    UNIFORM_TERNARY, DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FIXEDAUTO,       NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   { 16, 16 }, 25, 8, RDIM/2 },
    { SCHEME_SWITCH_FHEW_CKKS, "04", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH1, SMODSIZE,     DFLT,  DFLT,    UNIFORM_TERNARY, DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FIXEDMANUAL,     NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   { 16, 16 }, 25, 8, RDIM/2 },
    { SCHEME_SWITCH_FHEW_CKKS, "05", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH1, SMODSIZE,     DFLT,  DFLT,    SPARSE_TERNARY, DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FIXEDAUTO,       NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   { 16, 16 }, 25, 8, 8 },
    { SCHEME_SWITCH_FHEW_CKKS, "06", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH1, SMODSIZE,     DFLT,  DFLT,    SPARSE_TERNARY, DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FIXEDMANUAL,     NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   { 16, 16 }, 25, 8, 8 },
    { SCHEME_SWITCH_FHEW_CKKS, "07", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH1, SMODSIZE,     DFLT,  DFLT,    SPARSE_TERNARY, DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FIXEDAUTO,       NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   { 16, 16 }, 25, 8, RDIM/2 },
    { SCHEME_SWITCH_FHEW_CKKS, "08", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH1, SMODSIZE,     DFLT,  DFLT,    SPARSE_TERNARY, DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FIXEDMANUAL,     NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   { 16, 16 }, 25, 8, RDIM/2 },

#if NATIVEINT != 128
    { SCHEME_SWITCH_FHEW_CKKS, "09", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH1, SMODSIZE,     DFLT,  DFLT,    UNIFORM_TERNARY,  DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FLEXIBLEAUTO,    NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   { 16, 16 }, 25, 8, 8 },
    { SCHEME_SWITCH_FHEW_CKKS, "10", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH1, SMODSIZE,     DFLT,  DFLT,    UNIFORM_TERNARY,  DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FLEXIBLEAUTOEXT, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   { 16, 16 }, 25, 8, 8 },
    { SCHEME_SWITCH_FHEW_CKKS, "11", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH1, SMODSIZE,     DFLT,  DFLT,    UNIFORM_TERNARY,  DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FLEXIBLEAUTO,    NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   { 16, 16 }, 25, 8, RDIM/2 },
    { SCHEME_SWITCH_FHEW_CKKS, "12", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH1, SMODSIZE,     DFLT,  DFLT,    UNIFORM_TERNARY,  DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FLEXIBLEAUTOEXT, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   { 16, 16 }, 25, 8, RDIM/2 },
    { SCHEME_SWITCH_FHEW_CKKS, "13", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH1, SMODSIZE,     DFLT,  DFLT,    SPARSE_TERNARY,  DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FLEXIBLEAUTO,    NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   { 16, 16 }, 25, 8, 8 },
    { SCHEME_SWITCH_FHEW_CKKS, "14", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH1, SMODSIZE,     DFLT,  DFLT,    SPARSE_TERNARY,  DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FLEXIBLEAUTOEXT, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   { 16, 16 }, 25, 8, 8 },
    { SCHEME_SWITCH_FHEW_CKKS, "15", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH1, SMODSIZE,     DFLT,  DFLT,    SPARSE_TERNARY,  DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FLEXIBLEAUTO,    NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   { 16, 16 }, 25, 8, RDIM/2 },
    { SCHEME_SWITCH_FHEW_CKKS, "16", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH1, SMODSIZE,     DFLT,  DFLT,    SPARSE_TERNARY,  DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FLEXIBLEAUTOEXT, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   { 16, 16 }, 25, 8, RDIM/2 },

#endif
    // ==========================================
    // TestType,     Descr, Scheme,          RDim, MultDepth,  SModSize,     DSize, BatchSz, SecKeyDist,      MaxRelinSkDeg, FModSize,  SecLvl,       KSTech, ScalTech,        LDigits,      PtMod, StdDev, EvalAddCt, KSCt, MultTech, EncTech, PREMode, Dim1, LogQ, NumValues, Slots
    { SCHEME_SWITCH_COMPARISON, "01", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH1, SMODSIZE,     DFLT,  DFLT,    UNIFORM_TERNARY, DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FIXEDAUTO,       NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   { 16, 16 }, 25, 8, 8 },
    { SCHEME_SWITCH_COMPARISON, "02", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH1, SMODSIZE,     DFLT,  DFLT,    UNIFORM_TERNARY, DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FIXEDMANUAL,     NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   { 16, 16 }, 25, 8, 8 },
    { SCHEME_SWITCH_COMPARISON, "03", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH1, SMODSIZE,     DFLT,  DFLT,    UNIFORM_TERNARY, DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FIXEDAUTO,       NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   { 16, 16 }, 25, 8, RDIM/2 },
    { SCHEME_SWITCH_COMPARISON, "04", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH1, SMODSIZE,     DFLT,  DFLT,    UNIFORM_TERNARY, DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FIXEDMANUAL,     NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   { 16, 16 }, 25, 8, RDIM/2 },
#if NATIVEINT != 128
    { SCHEME_SWITCH_COMPARISON, "05", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH1, SMODSIZE,     DFLT,  DFLT,    UNIFORM_TERNARY,  DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FLEXIBLEAUTO,    NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   { 16, 16 }, 25, 8, 8 },
    { SCHEME_SWITCH_COMPARISON, "06", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH1, SMODSIZE,     DFLT,  DFLT,    UNIFORM_TERNARY,  DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FLEXIBLEAUTOEXT, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   { 16, 16 }, 25, 8, 8 },
    { SCHEME_SWITCH_COMPARISON, "07", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH1, SMODSIZE,     DFLT,  DFLT,    UNIFORM_TERNARY,  DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FLEXIBLEAUTO,    NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   { 16, 16 }, 25, 8, RDIM/2 },
    { SCHEME_SWITCH_COMPARISON, "08", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH1, SMODSIZE,     DFLT,  DFLT,    UNIFORM_TERNARY,  DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FLEXIBLEAUTOEXT, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   { 16, 16 }, 25, 8, RDIM/2 },
#endif
    // ==========================================
    // TestType,     Descr, Scheme,          RDim, MultDepth,  SModSize,     DSize, BatchSz, SecKeyDist,      MaxRelinSkDeg, FModSize,  SecLvl,       KSTech, ScalTech,        LDigits,      PtMod, StdDev, EvalAddCt, KSCt, MultTech, EncTech, PREMode, Dim1, LogQ, NumValues, Slots
    { SCHEME_SWITCH_ARGMIN, "01", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH2, SMODSIZE,     DFLT,  DFLT,    UNIFORM_TERNARY, DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FIXEDAUTO,       NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   { 16, 16 }, 25, 8, 8, true },
    { SCHEME_SWITCH_ARGMIN, "02", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH2, SMODSIZE,     DFLT,  DFLT,    UNIFORM_TERNARY, DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FIXEDMANUAL,     NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   { 16, 16 }, 25, 8, 8, true },
    { SCHEME_SWITCH_ARGMIN, "03", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH2, SMODSIZE,     DFLT,  DFLT,    UNIFORM_TERNARY, DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FIXEDAUTO,       NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   { 16, 16 }, 25, 8, RDIM/2, true },
    { SCHEME_SWITCH_ARGMIN, "04", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH2, SMODSIZE,     DFLT,  DFLT,    UNIFORM_TERNARY, DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FIXEDMANUAL,     NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   { 16, 16 }, 25, 8, RDIM/2, true },
    { SCHEME_SWITCH_ARGMIN, "05", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH2, SMODSIZE,     DFLT,  DFLT,    UNIFORM_TERNARY, DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FIXEDAUTO,       NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   { 16, 16 }, 25, 8, 8, false },
    { SCHEME_SWITCH_ARGMIN, "06", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH2, SMODSIZE,     DFLT,  DFLT,    UNIFORM_TERNARY, DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FIXEDMANUAL,     NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   { 16, 16 }, 25, 8, 8, false },
    { SCHEME_SWITCH_ARGMIN, "07", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH2, SMODSIZE,     DFLT,  DFLT,    UNIFORM_TERNARY, DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FIXEDAUTO,       NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   { 16, 16 }, 25, 8, RDIM/2, false },
    { SCHEME_SWITCH_ARGMIN, "08", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH2, SMODSIZE,     DFLT,  DFLT,    UNIFORM_TERNARY, DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FIXEDMANUAL,     NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   { 16, 16 }, 25, 8, RDIM/2, false },
#if NATIVEINT != 128
    { SCHEME_SWITCH_ARGMIN, "09", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH2, SMODSIZE,     DFLT,  DFLT,    UNIFORM_TERNARY,  DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FLEXIBLEAUTO,    NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   { 16, 16 }, 25, 8, 8, true },
    { SCHEME_SWITCH_ARGMIN, "10", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH2, SMODSIZE,     DFLT,  DFLT,    UNIFORM_TERNARY,  DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FLEXIBLEAUTOEXT, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   { 16, 16 }, 25, 8, 8, true },
    { SCHEME_SWITCH_ARGMIN, "11", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH2, SMODSIZE,     DFLT,  DFLT,    UNIFORM_TERNARY,  DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FLEXIBLEAUTO,    NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   { 16, 16 }, 25, 8, 8, false },
    { SCHEME_SWITCH_ARGMIN, "12", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH2, SMODSIZE,     DFLT,  DFLT,    UNIFORM_TERNARY,  DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FLEXIBLEAUTOEXT, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   { 16, 16 }, 25, 8, 8, false },
    // { SCHEME_SWITCH_ARGMIN, "13", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH2, SMODSIZE,     DFLT,  DFLT,    UNIFORM_TERNARY,  DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FLEXIBLEAUTO,    NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   { 16, 16 }, 25, 8, RDIM/2, true },
    // { SCHEME_SWITCH_ARGMIN, "14", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH2, SMODSIZE,     DFLT,  DFLT,    UNIFORM_TERNARY,  DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FLEXIBLEAUTOEXT, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   { 16, 16 }, 25, 8, RDIM/2, true },
    // { SCHEME_SWITCH_ARGMIN, "15", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH2, SMODSIZE,     DFLT,  DFLT,    UNIFORM_TERNARY,  DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FLEXIBLEAUTO,    NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   { 16, 16 }, 25, 8, RDIM/2, false },
    // { SCHEME_SWITCH_ARGMIN, "16", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH2, SMODSIZE,     DFLT,  DFLT,    UNIFORM_TERNARY,  DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FLEXIBLEAUTOEXT, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   { 16, 16 }, 25, 8, RDIM/2, false },
#endif
    // ==========================================
    // TestType,     Descr, Scheme,          RDim, MultDepth,  SModSize,     DSize, BatchSz, SecKeyDist,      MaxRelinSkDeg, FModSize,  SecLvl,       KSTech, ScalTech,        LDigits,      PtMod, StdDev, EvalAddCt, KSCt, MultTech, EncTech, PREMode, Dim1, LogQ, NumValues, Slots
    { SCHEME_SWITCH_ALT_ARGMIN, "01", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH2, SMODSIZE,     DFLT,  DFLT,    UNIFORM_TERNARY, DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FIXEDAUTO,       NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   { 16, 16 }, 25, 8, 8, true },
    { SCHEME_SWITCH_ALT_ARGMIN, "02", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH2, SMODSIZE,     DFLT,  DFLT,    UNIFORM_TERNARY, DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FIXEDMANUAL,     NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   { 16, 16 }, 25, 8, 8, true },
    { SCHEME_SWITCH_ALT_ARGMIN, "03", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH2, SMODSIZE,     DFLT,  DFLT,    UNIFORM_TERNARY, DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FIXEDAUTO,       NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   { 16, 16 }, 25, 8, RDIM/2, true },
    { SCHEME_SWITCH_ALT_ARGMIN, "04", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH2, SMODSIZE,     DFLT,  DFLT,    UNIFORM_TERNARY, DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FIXEDMANUAL,     NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   { 16, 16 }, 25, 8, RDIM/2, true },
    { SCHEME_SWITCH_ALT_ARGMIN, "05", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH2, SMODSIZE,     DFLT,  DFLT,    UNIFORM_TERNARY, DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FIXEDAUTO,       NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   { 16, 16 }, 25, 8, 8, false },
    { SCHEME_SWITCH_ALT_ARGMIN, "06", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH2, SMODSIZE,     DFLT,  DFLT,    UNIFORM_TERNARY, DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FIXEDMANUAL,     NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   { 16, 16 }, 25, 8, 8, false },
    { SCHEME_SWITCH_ALT_ARGMIN, "07", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH2, SMODSIZE,     DFLT,  DFLT,    UNIFORM_TERNARY, DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FIXEDAUTO,       NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   { 16, 16 }, 25, 8, RDIM/2, false },
    { SCHEME_SWITCH_ALT_ARGMIN, "08", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH2, SMODSIZE,     DFLT,  DFLT,    UNIFORM_TERNARY, DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FIXEDMANUAL,     NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   { 16, 16 }, 25, 8, RDIM/2, false },
#if NATIVEINT != 128
    { SCHEME_SWITCH_ALT_ARGMIN, "09", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH2, SMODSIZE,     DFLT,  DFLT,    UNIFORM_TERNARY,  DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FLEXIBLEAUTO,    NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   { 16, 16 }, 25, 8, 8, true },
    { SCHEME_SWITCH_ALT_ARGMIN, "10", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH2, SMODSIZE,     DFLT,  DFLT,    UNIFORM_TERNARY,  DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FLEXIBLEAUTOEXT, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   { 16, 16 }, 25, 8, 8, true },
    { SCHEME_SWITCH_ALT_ARGMIN, "11", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH2, SMODSIZE,     DFLT,  DFLT,    UNIFORM_TERNARY,  DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FLEXIBLEAUTO,    NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   { 16, 16 }, 25, 8, 8, false },
    { SCHEME_SWITCH_ALT_ARGMIN, "12", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH2, SMODSIZE,     DFLT,  DFLT,    UNIFORM_TERNARY,  DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FLEXIBLEAUTOEXT, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   { 16, 16 }, 25, 8, 8, false },
    // { SCHEME_SWITCH_ALT_ARGMIN, "13", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH2, SMODSIZE,     DFLT,  DFLT,    UNIFORM_TERNARY,  DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FLEXIBLEAUTO,    NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   { 16, 16 }, 25, 8, RDIM/2, true },
    // { SCHEME_SWITCH_ALT_ARGMIN, "14", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH2, SMODSIZE,     DFLT,  DFLT,    UNIFORM_TERNARY,  DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FLEXIBLEAUTOEXT, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   { 16, 16 }, 25, 8, RDIM/2, true },
    // { SCHEME_SWITCH_ALT_ARGMIN, "15", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH2, SMODSIZE,     DFLT,  DFLT,    UNIFORM_TERNARY,  DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FLEXIBLEAUTO,    NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   { 16, 16 }, 25, 8, RDIM/2, false },
    // { SCHEME_SWITCH_ALT_ARGMIN, "16", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH2, SMODSIZE,     DFLT,  DFLT,    UNIFORM_TERNARY,  DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FLEXIBLEAUTOEXT, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},   { 16, 16 }, 25, 8, RDIM/2, false },
#endif
};
// clang-format on
//===========================================================================================================
class UTCKKSRNS_SCHEMESWITCH : public ::testing::TestWithParam<TEST_CASE_UTCKKSRNS_SCHEMESWITCH> {
    using Element = DCRTPoly;

    // The precision after which we consider two values equal.
    // This is necessary because CKKS works for approximate numbers.
    const double eps1 = 0.0001;  // When working with binary or small values
    const double eps2 =
        0.05;  // When working with conversion to FHEW of larger values, since it implies multiplying by a large value and modular approximation around zero

    // CalculateApproximationError() calculates the precision number (or approximation error).
    // The higher the precision, the less the error.
    double CalculateApproximationError(const std::vector<std::complex<double>>& result,
                                       const std::vector<std::complex<double>>& expectedResult) {
        if (result.size() != expectedResult.size())
            OPENFHE_THROW(config_error, "Cannot compare vectors with different numbers of elements");

        // using the infinity norm
        double maxError = 0;
        for (size_t i = 0; i < result.size(); ++i) {
            double error = std::abs(result[i].real() - expectedResult[i].real());
            if (maxError < error)
                maxError = error;
        }

        return std::abs(std::log2(maxError));
    }

    double CalculateApproximationErrorInt(const std::vector<int32_t>& result,
                                          const std::vector<int32_t>& expectedResult) {
        if (result.size() != expectedResult.size())
            OPENFHE_THROW(config_error, "Cannot compare vectors with different numbers of elements");

        // using the infinity norm
        double maxError = 0;
        for (size_t i = 0; i < result.size(); ++i) {
            double error = std::abs(result[i] - expectedResult[i]);
            if (maxError < error)
                maxError = error;
        }

        return std::abs(std::log2(maxError));
    }

protected:
    void SetUp() {}

    void TearDown() {
        CryptoContextFactory<DCRTPoly>::ReleaseAllContexts();
    }

    void UnitTest_SchemeSwitch_CKKS_FHEW(const TEST_CASE_UTCKKSRNS_SCHEMESWITCH& testData,
                                         const std::string& failmsg = std::string()) {
        try {
            CryptoContext<Element> cc(UnitTestGenerateContext(testData.params));

            cc->Enable(SCHEMESWITCH);

            auto keyPair = cc->KeyGen();

            auto FHEWparams = cc->EvalCKKStoFHEWSetup(HEStd_NotSet, TOY, false, testData.logQ, false, testData.slots);
            auto ccLWE      = FHEWparams.first;
            auto privateKeyFHEW = FHEWparams.second;
            cc->EvalCKKStoFHEWKeyGen(keyPair, privateKeyFHEW, testData.dim1[0]);

            const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(cc->GetCryptoParameters());
            ILDCRTParams<DCRTPoly::Integer> elementParams = *(cryptoParams->GetElementParams());
            auto paramsQ                                  = elementParams.GetParams();
            auto modulus_CKKS_from                        = paramsQ[0]->GetModulus();
            auto modulus_LWE                              = 1 << testData.logQ;
            auto pLWE                                     = modulus_LWE / (2 * ccLWE.GetBeta().ConvertToInt());

            double scFactor = cryptoParams->GetScalingFactorReal(0);
            if (cryptoParams->GetScalingTechnique() == FLEXIBLEAUTOEXT)
                scFactor = cryptoParams->GetScalingFactorReal(1);
            double scale = modulus_CKKS_from.ConvertToInt() / (scFactor * pLWE);

            cc->EvalCKKStoFHEWPrecompute(scale);

            std::vector<std::complex<double>> input(
                Fill({0, 1, -2, -3, pLWE / 8.0, pLWE / 4.0, pLWE / 2.0, pLWE / 1.0}, testData.slots));

            size_t encodedLength = input.size();
            std::vector<int32_t> inputInt(encodedLength);
            std::transform(input.begin(), input.end(), inputInt.begin(), [&](const std::complex<double>& elem) {
                return static_cast<int32_t>(static_cast<int32_t>(std::round(elem.real())) % pLWE);
            });

            Plaintext plaintext1 = cc->MakeCKKSPackedPlaintext(input, 1, 0, nullptr, testData.slots);
            auto ciphertext1     = cc->Encrypt(keyPair.publicKey, plaintext1);
            auto ciphertextAfter = cc->EvalCKKStoFHEW(ciphertext1, testData.numValues);

            std::string failed = "Scheme switching from CKKS to FHEW for sparsely packed ciphertexts fails.";

            LWEPlaintext result;
            for (uint32_t i = 0; i < ciphertextAfter.size(); ++i) {
                ccLWE.Decrypt(privateKeyFHEW, ciphertextAfter[i], &result, pLWE);
                EXPECT_EQ(result, inputInt[i]) << failed;
            }
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

    void UnitTest_SchemeSwitch_FHEW_CKKS(const TEST_CASE_UTCKKSRNS_SCHEMESWITCH& testData,
                                         const std::string& failmsg = std::string()) {
        try {
            CryptoContext<Element> cc(UnitTestGenerateContext(testData.params));

            cc->Enable(SCHEMESWITCH);

            auto keyPair = cc->KeyGen();

            auto ccLWE = BinFHEContext();
            ccLWE.BinFHEContext::GenerateBinFHEContext(TOY, false, testData.logQ, 0, GINX, false);
            LWEPrivateKey lwesk;
            lwesk = ccLWE.KeyGen();

            auto modulus_LWE        = 1 << testData.logQ;
            uint32_t pLWE           = modulus_LWE / (2 * ccLWE.GetBeta().ConvertToInt());  // larger precision
            std::vector<int32_t> x1 = {0, 0, 1, 1, 0, 0, 1, 1};
            std::vector<int32_t> x2 = {0, -1, 2, -3, 4, -8, 16, -32};
            std::vector<LWECiphertext> ctxtsLWE1(testData.slots);
            for (uint32_t i = 0; i < testData.slots; i++) {
                ctxtsLWE1[i] =
                    ccLWE.Encrypt(lwesk, x1[i], FRESH, 4,
                                  modulus_LWE);  // encrypted under small plantext modulus p = 4 and ciphertext modulus
            }
            std::vector<LWECiphertext> ctxtsLWE2(testData.slots);
            for (uint32_t i = 0; i < testData.slots; i++) {
                ctxtsLWE2[i] = ccLWE.Encrypt(
                    lwesk, x2[i], FRESH, pLWE,
                    modulus_LWE);  // encrypted under larger plaintext modulus and large ciphertext modulus
            }

            cc->EvalFHEWtoCKKSSetup(ccLWE, testData.slots, testData.logQ);
            cc->EvalFHEWtoCKKSKeyGen(keyPair, lwesk, testData.numValues, testData.dim1[1]);

            auto cTemp = cc->EvalFHEWtoCKKS(ctxtsLWE1, testData.numValues, testData.slots);

            Plaintext plaintextDec;
            cc->Decrypt(keyPair.secretKey, cTemp, &plaintextDec);
            plaintextDec->SetLength(testData.numValues);

            checkEquality(plaintextDec->GetCKKSPackedValue(), toComplexDoubleVec(x1), eps1,
                          failmsg + "FHEW to CKKS fails for binary messages.");

            cTemp = cc->EvalFHEWtoCKKS(ctxtsLWE2, testData.numValues, testData.slots, pLWE, 0, pLWE);

            cc->Decrypt(keyPair.secretKey, cTemp, &plaintextDec);
            plaintextDec->SetLength(testData.numValues);

            checkEquality(plaintextDec->GetCKKSPackedValue(), toComplexDoubleVec(x2), eps2,
                          failmsg + "FHEW to CKKS fails for larger messages.");
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

    void UnitTest_SchemeSwitch_Comparison(const TEST_CASE_UTCKKSRNS_SCHEMESWITCH& testData,
                                          const std::string& failmsg = std::string()) {
        try {
            CryptoContext<Element> cc(UnitTestGenerateContext(testData.params));

            cc->Enable(SCHEMESWITCH);

            auto keyPair = cc->KeyGen();

            auto FHEWparams =
                cc->EvalSchemeSwitchingSetup(HEStd_NotSet, TOY, false, testData.logQ, false, testData.slots);
            auto ccLWE          = FHEWparams.first;
            auto privateKeyFHEW = FHEWparams.second;

            ccLWE.BTKeyGen(privateKeyFHEW);

            cc->EvalSchemeSwitchingKeyGen(keyPair, privateKeyFHEW, testData.numValues, true, false, testData.dim1[0],
                                          testData.dim1[1]);

            std::vector<double> x1 = {0.0, 1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0};
            std::vector<double> x2(testData.slots, 5.25);

            Plaintext ptxt1 = cc->MakeCKKSPackedPlaintext(x1, 1, 0, nullptr, testData.slots);
            Plaintext ptxt2 = cc->MakeCKKSPackedPlaintext(x2, 1, 0, nullptr, testData.slots);

            auto c1 = cc->Encrypt(keyPair.publicKey, ptxt1);
            auto c2 = cc->Encrypt(keyPair.publicKey, ptxt2);

            auto cDiff = cc->EvalSub(c1, c2);

            auto modulus_LWE = 1 << testData.logQ;
            auto pLWE        = modulus_LWE / (2 * ccLWE.GetBeta().ConvertToInt());

            const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(cc->GetCryptoParameters());
            uint32_t init_level     = 0;
            if (cryptoParams->GetScalingTechnique() == FLEXIBLEAUTOEXT)
                init_level = 1;
            double scaleSignFHEW = 8.0;

            cc->EvalCompareSwitchPrecompute(pLWE, init_level, scaleSignFHEW);

            Plaintext pDiff;
            cc->Decrypt(keyPair.secretKey, cDiff, &pDiff);
            std::vector<std::complex<double>> inputSign(testData.numValues);
            pDiff->SetLength(testData.numValues);
            std::vector<double> vDiff(pDiff->GetRealPackedValue());
            std::transform(vDiff.begin(), vDiff.end(), inputSign.begin(), [&](const std::complex<double>& elem) {
                return std::complex<double>(static_cast<int32_t>(std::round(elem.real() / eps1) * eps1 < 0), 0);
            });

            auto cResult = cc->EvalCompareSchemeSwitching(c1, c2, testData.numValues, testData.slots);

            Plaintext plaintextDec;
            cc->Decrypt(keyPair.secretKey, cResult, &plaintextDec);
            plaintextDec->SetLength(testData.numValues);

            checkEquality(plaintextDec->GetCKKSPackedValue(), inputSign, eps1, failmsg + "EvalCompare fails.");
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

    void UnitTest_SchemeSwitch_Argmin(const TEST_CASE_UTCKKSRNS_SCHEMESWITCH& testData,
                                      const std::string& failmsg = std::string()) {
        try {
            CryptoContext<Element> cc(UnitTestGenerateContext(testData.params));

            cc->Enable(SCHEMESWITCH);

            auto keyPair = cc->KeyGen();

            auto FHEWparams =
                cc->EvalSchemeSwitchingSetup(HEStd_NotSet, TOY, false, testData.logQ, false, testData.slots);
            auto ccLWE          = FHEWparams.first;
            auto privateKeyFHEW = FHEWparams.second;

            cc->EvalSchemeSwitchingKeyGen(keyPair, privateKeyFHEW, testData.numValues, testData.oneHot, false,
                                          testData.dim1[0], testData.dim1[1]);

            double scaleSign = 128.0;

            auto modulus_LWE = 1 << testData.logQ;
            auto pLWE        = modulus_LWE / (2 * ccLWE.GetBeta().ConvertToInt());

            const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(cc->GetCryptoParameters());

            uint32_t init_level = 0;
            if (cryptoParams->GetScalingTechnique() == FLEXIBLEAUTOEXT)
                init_level = 1;
            cc->EvalCompareSwitchPrecompute(pLWE, init_level, scaleSign);

            std::vector<double> x1 = {-1.1, -1.05, 5.0, 6.0, -1.0, 2.0, 8.0, -1.0};
            auto xmin              = *std::min_element(x1.begin(), x1.begin() + testData.numValues);
            auto xargmin           = std::min_element(x1.begin(), x1.begin() + testData.numValues) - x1.begin();

            Plaintext p1 = cc->MakeCKKSPackedPlaintext(x1, 1, 0, nullptr, testData.slots);
            auto c1      = cc->Encrypt(keyPair.publicKey, p1);

            auto result =
                cc->EvalMinSchemeSwitching(c1, keyPair.publicKey, testData.numValues, testData.slots, testData.oneHot);

            Plaintext ptxtMin;
            cc->Decrypt(keyPair.secretKey, result[0], &ptxtMin);
            ptxtMin->SetLength(1);

            checkEquality(ptxtMin->GetRealPackedValue()[0], xmin, eps1);

            cc->Decrypt(keyPair.secretKey, result[1], &ptxtMin);
            if (testData.oneHot) {
                ptxtMin->SetLength(testData.numValues);

                std::vector<std::complex<double>> xargminOH(testData.numValues);
                xargminOH[xargmin] = 1;
                checkEquality(ptxtMin->GetCKKSPackedValue(), xargminOH, eps1,
                              failmsg + "EvalMinSchemeSwitching fails.");
            }
            else {
                ptxtMin->SetLength(1);
                checkEquality(ptxtMin->GetRealPackedValue()[0], static_cast<double>(xargmin), eps1);
            }

            // Uncomment to test the max+argmax functionality
            /* auto xmax    = *std::max_element(x1.begin(), x1.begin() + testData.numValues);
            auto xargmax = std::max_element(x1.begin(), x1.begin() + testData.numValues) - x1.begin();

            result =
                cc->EvalMaxSchemeSwitching(c1, keyPair.publicKey, testData.numValues, testData.slots, testData.oneHot);

            Plaintext ptxtMax;
            cc->Decrypt(keyPair.secretKey, result[0], &ptxtMax);
            ptxtMax->SetLength(1);
            checkEquality(ptxtMax->GetRealPackedValue()[0], xmax, eps1);

            cc->Decrypt(keyPair.secretKey, result[1], &ptxtMax);
            if (testData.oneHot) {
                ptxtMax->SetLength(testData.numValues);
                std::vector<std::complex<double>> xargmaxOH(testData.numValues);
                xargmaxOH[xargmax] = 1;
                checkEquality(ptxtMax->GetCKKSPackedValue(), xargmaxOH, eps1,
                              failmsg + "EvalMinSchemeSwitching fails.");
            }
            else {
                ptxtMax->SetLength(1);
                checkEquality(ptxtMax->GetRealPackedValue()[0], static_cast<double>(xargmax), eps1);
            }
            */
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

    void UnitTest_SchemeSwitch_AltArgmin(const TEST_CASE_UTCKKSRNS_SCHEMESWITCH& testData,
                                         const std::string& failmsg = std::string()) {
        try {
            CryptoContext<Element> cc(UnitTestGenerateContext(testData.params));

            cc->Enable(SCHEMESWITCH);

            auto keyPair = cc->KeyGen();

            auto FHEWparams =
                cc->EvalSchemeSwitchingSetup(HEStd_NotSet, TOY, false, testData.logQ, false, testData.slots);
            auto ccLWE          = FHEWparams.first;
            auto privateKeyFHEW = FHEWparams.second;

            bool alt = true;
            cc->EvalSchemeSwitchingKeyGen(keyPair, privateKeyFHEW, testData.numValues, testData.oneHot, alt,
                                          testData.dim1[0], testData.dim1[1]);

            double scaleSign = 128.0;

            auto modulus_LWE = 1 << testData.logQ;
            auto pLWE        = modulus_LWE / (2 * ccLWE.GetBeta().ConvertToInt());

            const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(cc->GetCryptoParameters());

            uint32_t init_level = 0;
            if (cryptoParams->GetScalingTechnique() == FLEXIBLEAUTOEXT)
                init_level = 1;
            cc->EvalCompareSwitchPrecompute(pLWE, init_level, scaleSign);

            std::vector<double> x1 = {-1.1, -1.05, 5.0, 6.0, -1.0, 2.0, 8.0, -1.0};
            auto xmin              = *std::min_element(x1.begin(), x1.begin() + testData.numValues);
            auto xargmin           = std::min_element(x1.begin(), x1.begin() + testData.numValues) - x1.begin();

            Plaintext p1 = cc->MakeCKKSPackedPlaintext(x1, 1, 0, nullptr, testData.slots);
            auto c1      = cc->Encrypt(keyPair.publicKey, p1);

            auto result = cc->EvalMinSchemeSwitchingAlt(c1, keyPair.publicKey, testData.numValues, testData.slots,
                                                        testData.oneHot);

            Plaintext ptxtMin;
            cc->Decrypt(keyPair.secretKey, result[0], &ptxtMin);
            ptxtMin->SetLength(1);

            checkEquality(ptxtMin->GetRealPackedValue()[0], xmin, eps1);

            cc->Decrypt(keyPair.secretKey, result[1], &ptxtMin);
            if (testData.oneHot) {
                ptxtMin->SetLength(testData.numValues);
                std::vector<std::complex<double>> xargminOH(testData.numValues);
                xargminOH[xargmin] = 1;
                checkEquality(ptxtMin->GetCKKSPackedValue(), xargminOH, eps1,
                              failmsg + "EvalMinSchemeSwitching fails.");
            }
            else {
                ptxtMin->SetLength(1);
                checkEquality(ptxtMin->GetRealPackedValue()[0], static_cast<double>(xargmin), eps1);
            }

            // Uncomment to test the max+argmax functionality
            /* auto xmax    = *std::max_element(x1.begin(), x1.begin() + testData.numValues);
            auto xargmax = std::max_element(x1.begin(), x1.begin() + testData.numValues) - x1.begin();

            result = cc->EvalMaxSchemeSwitchingAlt(c1, keyPair.publicKey, testData.numValues, testData.slots,
                                                   testData.oneHot);

            Plaintext ptxtMax;
            cc->Decrypt(keyPair.secretKey, result[0], &ptxtMax);
            ptxtMax->SetLength(1);
            checkEquality(ptxtMax->GetRealPackedValue()[0], xmax, eps1);

            cc->Decrypt(keyPair.secretKey, result[1], &ptxtMax);
            if (testData.oneHot) {
                ptxtMax->SetLength(testData.numValues);
                std::vector<std::complex<double>> xargmaxOH(testData.numValues);
                xargmaxOH[xargmax] = 1;
                checkEquality(ptxtMax->GetCKKSPackedValue(), xargmaxOH, eps1,
                              failmsg + "EvalMinSchemeSwitching fails.");
            }
            else {
                ptxtMax->SetLength(1);
                checkEquality(ptxtMax->GetRealPackedValue()[0], static_cast<double>(xargmax), eps1);
            }
            */
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
};

//===========================================================================================================
TEST_P(UTCKKSRNS_SCHEMESWITCH, CKKSRNS) {
    setupSignals();
    auto test = GetParam();

    switch (test.testCaseType) {
        case SCHEME_SWITCH_CKKS_FHEW:
            UnitTest_SchemeSwitch_CKKS_FHEW(test, test.buildTestName());
            break;
        case SCHEME_SWITCH_FHEW_CKKS:
            UnitTest_SchemeSwitch_FHEW_CKKS(test, test.buildTestName());
            break;
        case SCHEME_SWITCH_COMPARISON:
            UnitTest_SchemeSwitch_Comparison(test, test.buildTestName());
            break;
        case SCHEME_SWITCH_ARGMIN:
            UnitTest_SchemeSwitch_Argmin(test, test.buildTestName());
            break;
        case SCHEME_SWITCH_ALT_ARGMIN:
            UnitTest_SchemeSwitch_AltArgmin(test, test.buildTestName());
            break;
        default:
            break;
    }
}

INSTANTIATE_TEST_SUITE_P(UnitTests, UTCKKSRNS_SCHEMESWITCH, ::testing::ValuesIn(testCases), testName);
