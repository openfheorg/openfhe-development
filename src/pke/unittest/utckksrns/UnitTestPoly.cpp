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
  Unit tests for the CKKS scheme
 */

#include "UnitTestUtils.h"
#include "UnitTestCCParams.h"
#include "UnitTestCryptoContext.h"

#include <iostream>
#include <vector>
#include "gtest/gtest.h"
#include <iterator>

using namespace lbcrypto;

//===========================================================================================================
enum TEST_CASE_TYPE {
    EVAL_POLY = 0,
    EVAL_CHEB_DIVISION,
    EVAL_CHEB_LOGIT,
    EVAL_CHEB_LOGIT_NOLIN,
    EVAL_CHEB_SINE,
    EVAL_CHEB_POLY,
    EVAL_DIVIDE,
    EVAL_LOGISTIC,
    EVAL_SIN,
    EVAL_COS,
};

static std::ostream& operator<<(std::ostream& os, const TEST_CASE_TYPE& type) {
    std::string typeName;
    switch (type) {
        case EVAL_POLY:
            typeName = "EVAL_POLY";
            break;
        case EVAL_CHEB_DIVISION:
            typeName = "EVAL_CHEB_DIVISION";
            break;
        case EVAL_CHEB_LOGIT:
            typeName = "EVAL_CHEB_LOGIT";
            break;
        case EVAL_CHEB_LOGIT_NOLIN:
            typeName = "EVAL_CHEB_LOGIT_NOLIN";
            break;
        case EVAL_CHEB_SINE:
            typeName = "EVAL_CHEB_SINE";
            break;
        case EVAL_CHEB_POLY:
            typeName = "EVAL_CHEB_POLY";
            break;
        case EVAL_DIVIDE:
            typeName = "EVAL_DIVIDE";
            break;
        case EVAL_LOGISTIC:
            typeName = "EVAL_LOGISTIC";
            break;
        case EVAL_SIN:
            typeName = "EVAL_SIN";
            break;
        case EVAL_COS:
            typeName = "EVAL_COS";
            break;
        default:
            typeName = "UNKNOWN";
            break;
    }
    return os << typeName;
}
//===========================================================================================================
struct TEST_CASE_UTCKKSRNS_EVAL_POLY {
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
static auto testName = [](const testing::TestParamInfo<TEST_CASE_UTCKKSRNS_EVAL_POLY>& test) {
    return test.param.buildTestName();
};

static std::ostream& operator<<(std::ostream& os, const TEST_CASE_UTCKKSRNS_EVAL_POLY& test) {
    return os << test.toString();
}
//===========================================================================================================
constexpr uint32_t RDIM       = 512;
constexpr uint32_t RDIM_LRG   = 1024;
constexpr uint32_t MULT_DEPTH = 10;
constexpr uint32_t BATCH      = 8;

#if NATIVEINT == 128 && !defined(__EMSCRIPTEN__)
constexpr uint32_t SMODSIZE = 78;
constexpr uint32_t FMODSIZE = 89;
#else
constexpr uint32_t SMODSIZE = 50;
constexpr uint32_t FMODSIZE = 60;
#endif

// clang-format off
static std::vector<TEST_CASE_UTCKKSRNS_EVAL_POLY> testCases = {
    // TestType, Descr, Scheme,         RDim, MultDepth,  SModSize,   DSize, BatchSz, SecKeyDist,      MaxRelinSkDeg, FModSize, SecLvl,       KSTech, ScalTech,        LDigits,    PtMod, StdDev, EvalAddCt, KSCt, MultTech, EncTech, PREMode
    { EVAL_POLY, "01", {CKKSRNS_SCHEME, RDIM, 5,          SMODSIZE,   20,    BATCH,   UNIFORM_TERNARY, DFLT,          FMODSIZE, HEStd_NotSet, HYBRID, FIXEDMANUAL,     DFLT,       DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT} },
    { EVAL_POLY, "02", {CKKSRNS_SCHEME, RDIM, 5,          SMODSIZE,   20,    BATCH,   UNIFORM_TERNARY, DFLT,          FMODSIZE, HEStd_NotSet, HYBRID, FIXEDAUTO,       DFLT,       DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT} },
    { EVAL_POLY, "03", {CKKSRNS_SCHEME, RDIM, 5,          SMODSIZE,   20,    BATCH,   UNIFORM_TERNARY, DFLT,          FMODSIZE, HEStd_NotSet, BV,     FIXEDMANUAL,     DFLT,       DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT} },
    { EVAL_POLY, "04", {CKKSRNS_SCHEME, RDIM, 5,          SMODSIZE,   20,    BATCH,   UNIFORM_TERNARY, DFLT,          FMODSIZE, HEStd_NotSet, BV,     FIXEDAUTO,       DFLT,       DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT} },
#if NATIVEINT != 128
    { EVAL_POLY, "05", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,   DFLT,  BATCH,   UNIFORM_TERNARY, DFLT,          FMODSIZE, HEStd_NotSet, HYBRID, FLEXIBLEAUTO,    DFLT,       DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT} },
    { EVAL_POLY, "06", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,   DFLT,  BATCH,   UNIFORM_TERNARY, DFLT,          FMODSIZE, HEStd_NotSet, HYBRID, FLEXIBLEAUTOEXT, DFLT,       DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT} },
    { EVAL_POLY, "07", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,   DFLT,  BATCH,   UNIFORM_TERNARY, DFLT,          FMODSIZE, HEStd_NotSet, BV,     FLEXIBLEAUTO,    DFLT,       DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT} },
    { EVAL_POLY, "08", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,   DFLT,  BATCH,   UNIFORM_TERNARY, DFLT,          FMODSIZE, HEStd_NotSet, BV,     FLEXIBLEAUTOEXT, DFLT,       DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT} },
#endif
    // ==========================================
    // TestType,          Descr, Scheme,         RDim, MultDepth,  SModSize,   DSize, BatchSz, SecKeyDist,      MaxRelinSkDeg, FModSize, SecLvl,       KSTech, ScalTech,        LDigits,    PtMod, StdDev, EvalAddCt, KSCt, MultTech, EncTech, PREMode
    { EVAL_CHEB_DIVISION, "01", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,   DFLT,  BATCH,   UNIFORM_TERNARY, DFLT,          FMODSIZE, HEStd_NotSet, HYBRID, FIXEDMANUAL,     DFLT,       DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT} },
    { EVAL_CHEB_DIVISION, "02", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,   DFLT,  BATCH,   UNIFORM_TERNARY, DFLT,          FMODSIZE, HEStd_NotSet, HYBRID, FIXEDAUTO,       DFLT,       DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT} },
    { EVAL_CHEB_DIVISION, "03", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,   DFLT,  BATCH,   UNIFORM_TERNARY, DFLT,          FMODSIZE, HEStd_NotSet, HYBRID, FIXEDMANUAL,     DFLT,       DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT} },
    { EVAL_CHEB_DIVISION, "04", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,   DFLT,  BATCH,   UNIFORM_TERNARY, DFLT,          FMODSIZE, HEStd_NotSet, HYBRID, FIXEDAUTO,       DFLT,       DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT} },
#if NATIVEINT != 128
    { EVAL_CHEB_DIVISION, "05", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,   DFLT,  BATCH,   UNIFORM_TERNARY, DFLT,          FMODSIZE, HEStd_NotSet, HYBRID, FLEXIBLEAUTO,    DFLT,       DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT} },
    { EVAL_CHEB_DIVISION, "06", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,   DFLT,  BATCH,   UNIFORM_TERNARY, DFLT,          FMODSIZE, HEStd_NotSet, HYBRID, FLEXIBLEAUTOEXT, DFLT,       DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT} },
    { EVAL_CHEB_DIVISION, "07", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,   DFLT,  BATCH,   UNIFORM_TERNARY, DFLT,          FMODSIZE, HEStd_NotSet, HYBRID, FLEXIBLEAUTO,    DFLT,       DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT} },
    { EVAL_CHEB_DIVISION, "08", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,   DFLT,  BATCH,   UNIFORM_TERNARY, DFLT,          FMODSIZE, HEStd_NotSet, HYBRID, FLEXIBLEAUTOEXT, DFLT,       DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT} },
#endif
    // ==========================================
    // TestType,       Descr, Scheme,         RDim,     MultDepth,  SModSize,   DSize, BatchSz, SecKeyDist,      MaxRelinSkDeg, FModSize, SecLvl,       KSTech, ScalTech,        LDigits,    PtMod, StdDev, EvalAddCt, KSCt, MultTech, EncTech, PREMode
    { EVAL_CHEB_LOGIT, "01", {CKKSRNS_SCHEME, RDIM_LRG, MULT_DEPTH, SMODSIZE,   DFLT,  16,      UNIFORM_TERNARY, DFLT,          FMODSIZE, HEStd_NotSet, HYBRID, FIXEDMANUAL,     DFLT,       DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT} },
    { EVAL_CHEB_LOGIT, "02", {CKKSRNS_SCHEME, RDIM_LRG, MULT_DEPTH, SMODSIZE,   DFLT,  16,      UNIFORM_TERNARY, DFLT,          FMODSIZE, HEStd_NotSet, HYBRID, FIXEDAUTO,       DFLT,       DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT} },
    { EVAL_CHEB_LOGIT, "03", {CKKSRNS_SCHEME, RDIM_LRG, MULT_DEPTH, SMODSIZE,   DFLT,  16,      UNIFORM_TERNARY, DFLT,          FMODSIZE, HEStd_NotSet, HYBRID, FIXEDMANUAL,     DFLT,       DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT} },
    { EVAL_CHEB_LOGIT, "04", {CKKSRNS_SCHEME, RDIM_LRG, MULT_DEPTH, SMODSIZE,   DFLT,  16,      UNIFORM_TERNARY, DFLT,          FMODSIZE, HEStd_NotSet, HYBRID, FIXEDAUTO,       DFLT,       DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT} },
#if NATIVEINT != 128
    { EVAL_CHEB_LOGIT, "05", {CKKSRNS_SCHEME, RDIM_LRG, MULT_DEPTH, SMODSIZE,   DFLT,  16,      UNIFORM_TERNARY, DFLT,          FMODSIZE, HEStd_NotSet, HYBRID, FLEXIBLEAUTO,    DFLT,       DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT} },
    { EVAL_CHEB_LOGIT, "06", {CKKSRNS_SCHEME, RDIM_LRG, MULT_DEPTH, SMODSIZE,   DFLT,  16,      UNIFORM_TERNARY, DFLT,          FMODSIZE, HEStd_NotSet, HYBRID, FLEXIBLEAUTOEXT, DFLT,       DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT} },
    { EVAL_CHEB_LOGIT, "07", {CKKSRNS_SCHEME, RDIM_LRG, MULT_DEPTH, SMODSIZE,   DFLT,  16,      UNIFORM_TERNARY, DFLT,          FMODSIZE, HEStd_NotSet, HYBRID, FLEXIBLEAUTO,    DFLT,       DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT} },
    { EVAL_CHEB_LOGIT, "08", {CKKSRNS_SCHEME, RDIM_LRG, MULT_DEPTH, SMODSIZE,   DFLT,  16,      UNIFORM_TERNARY, DFLT,          FMODSIZE, HEStd_NotSet, HYBRID, FLEXIBLEAUTOEXT, DFLT,       DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT} },
#endif
    // ==========================================
    // TestType,             Descr, Scheme,         RDim,     MultDepth,  SModSize,   DSize, BatchSz, SecKeyDist,      MaxRelinSkDeg, FModSize, SecLvl,       KSTech, ScalTech,        LDigits,    PtMod, StdDev, EvalAddCt, KSCt, MultTech, EncTech, PREMode
    { EVAL_CHEB_LOGIT_NOLIN, "01", {CKKSRNS_SCHEME, RDIM_LRG, MULT_DEPTH, SMODSIZE,   DFLT,  16,      UNIFORM_TERNARY, DFLT,          FMODSIZE, HEStd_NotSet, HYBRID, FIXEDMANUAL,     DFLT,       DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT} },
    { EVAL_CHEB_LOGIT_NOLIN, "02", {CKKSRNS_SCHEME, RDIM_LRG, MULT_DEPTH, SMODSIZE,   DFLT,  16,      UNIFORM_TERNARY, DFLT,          FMODSIZE, HEStd_NotSet, HYBRID, FIXEDAUTO,       DFLT,       DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT} },
    { EVAL_CHEB_LOGIT_NOLIN, "03", {CKKSRNS_SCHEME, RDIM_LRG, MULT_DEPTH, SMODSIZE,   DFLT,  16,      UNIFORM_TERNARY, DFLT,          FMODSIZE, HEStd_NotSet, HYBRID, FIXEDMANUAL,     DFLT,       DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT} },
    { EVAL_CHEB_LOGIT_NOLIN, "04", {CKKSRNS_SCHEME, RDIM_LRG, MULT_DEPTH, SMODSIZE,   DFLT,  16,      UNIFORM_TERNARY, DFLT,          FMODSIZE, HEStd_NotSet, HYBRID, FIXEDAUTO,       DFLT,       DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT} },
#if NATIVEINT != 128
    { EVAL_CHEB_LOGIT_NOLIN, "05", {CKKSRNS_SCHEME, RDIM_LRG, MULT_DEPTH, SMODSIZE,   DFLT,  16,      UNIFORM_TERNARY, DFLT,          FMODSIZE, HEStd_NotSet, HYBRID, FLEXIBLEAUTO,    DFLT,       DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT} },
    { EVAL_CHEB_LOGIT_NOLIN, "06", {CKKSRNS_SCHEME, RDIM_LRG, MULT_DEPTH, SMODSIZE,   DFLT,  16,      UNIFORM_TERNARY, DFLT,          FMODSIZE, HEStd_NotSet, HYBRID, FLEXIBLEAUTOEXT, DFLT,       DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT} },
    { EVAL_CHEB_LOGIT_NOLIN, "07", {CKKSRNS_SCHEME, RDIM_LRG, MULT_DEPTH, SMODSIZE,   DFLT,  16,      UNIFORM_TERNARY, DFLT,          FMODSIZE, HEStd_NotSet, HYBRID, FLEXIBLEAUTO,    DFLT,       DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT} },
    { EVAL_CHEB_LOGIT_NOLIN, "08", {CKKSRNS_SCHEME, RDIM_LRG, MULT_DEPTH, SMODSIZE,   DFLT,  16,      UNIFORM_TERNARY, DFLT,          FMODSIZE, HEStd_NotSet, HYBRID, FLEXIBLEAUTOEXT, DFLT,       DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT} },
#endif
    // ==========================================
    // TestType,      Descr, Scheme,         RDim,     MultDepth,  SModSize,   DSize, BatchSz, SecKeyDist,      MaxRelinSkDeg, FModSize, SecLvl,       KSTech, ScalTech,        LDigits,    PtMod, StdDev, EvalAddCt, KSCt, MultTech, EncTech, PREMode
    { EVAL_CHEB_SINE, "01", {CKKSRNS_SCHEME, RDIM_LRG, MULT_DEPTH, SMODSIZE,   DFLT,  16,      UNIFORM_TERNARY, DFLT,          FMODSIZE, HEStd_NotSet, HYBRID, FIXEDMANUAL,     DFLT,       DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT} },
    { EVAL_CHEB_SINE, "02", {CKKSRNS_SCHEME, RDIM_LRG, MULT_DEPTH, SMODSIZE,   DFLT,  16,      UNIFORM_TERNARY, DFLT,          FMODSIZE, HEStd_NotSet, HYBRID, FIXEDAUTO,       DFLT,       DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT} },
    { EVAL_CHEB_SINE, "03", {CKKSRNS_SCHEME, RDIM_LRG, MULT_DEPTH, SMODSIZE,   DFLT,  16,      UNIFORM_TERNARY, DFLT,          FMODSIZE, HEStd_NotSet, HYBRID, FIXEDMANUAL,     DFLT,       DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT} },
    { EVAL_CHEB_SINE, "04", {CKKSRNS_SCHEME, RDIM_LRG, MULT_DEPTH, SMODSIZE,   DFLT,  16,      UNIFORM_TERNARY, DFLT,          FMODSIZE, HEStd_NotSet, HYBRID, FIXEDAUTO,       DFLT,       DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT} },
#if NATIVEINT != 128
    { EVAL_CHEB_SINE, "05", {CKKSRNS_SCHEME, RDIM_LRG, MULT_DEPTH, SMODSIZE,   DFLT,  16,      UNIFORM_TERNARY, DFLT,          FMODSIZE, HEStd_NotSet, HYBRID, FLEXIBLEAUTO,    DFLT,       DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT} },
    { EVAL_CHEB_SINE, "06", {CKKSRNS_SCHEME, RDIM_LRG, MULT_DEPTH, SMODSIZE,   DFLT,  16,      UNIFORM_TERNARY, DFLT,          FMODSIZE, HEStd_NotSet, HYBRID, FLEXIBLEAUTOEXT, DFLT,       DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT} },
    { EVAL_CHEB_SINE, "07", {CKKSRNS_SCHEME, RDIM_LRG, MULT_DEPTH, SMODSIZE,   DFLT,  16,      UNIFORM_TERNARY, DFLT,          FMODSIZE, HEStd_NotSet, HYBRID, FLEXIBLEAUTO,    DFLT,       DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT} },
    { EVAL_CHEB_SINE, "08", {CKKSRNS_SCHEME, RDIM_LRG, MULT_DEPTH, SMODSIZE,   DFLT,  16,      UNIFORM_TERNARY, DFLT,          FMODSIZE, HEStd_NotSet, HYBRID, FLEXIBLEAUTOEXT, DFLT,       DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT} },
#endif
    // ==========================================
    // TestType,      Descr, Scheme,         RDim,     MultDepth,  SModSize,   DSize, BatchSz, SecKeyDist,      MaxRelinSkDeg, FModSize, SecLvl,       KSTech, ScalTech,        LDigits,    PtMod, StdDev, EvalAddCt, KSCt, MultTech, EncTech, PREMode
    { EVAL_CHEB_POLY, "01", {CKKSRNS_SCHEME, RDIM_LRG, MULT_DEPTH, SMODSIZE,   DFLT,  BATCH,   UNIFORM_TERNARY, DFLT,          FMODSIZE, HEStd_NotSet, HYBRID, FIXEDMANUAL,     DFLT,       DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT} },
    { EVAL_CHEB_POLY, "02", {CKKSRNS_SCHEME, RDIM_LRG, MULT_DEPTH, SMODSIZE,   DFLT,  BATCH,   UNIFORM_TERNARY, DFLT,          FMODSIZE, HEStd_NotSet, HYBRID, FIXEDAUTO,       DFLT,       DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT} },
    { EVAL_CHEB_POLY, "03", {CKKSRNS_SCHEME, RDIM_LRG, MULT_DEPTH, SMODSIZE,   DFLT,  BATCH,   UNIFORM_TERNARY, DFLT,          FMODSIZE, HEStd_NotSet, HYBRID, FIXEDMANUAL,     DFLT,       DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT} },
    { EVAL_CHEB_POLY, "04", {CKKSRNS_SCHEME, RDIM_LRG, MULT_DEPTH, SMODSIZE,   DFLT,  BATCH,   UNIFORM_TERNARY, DFLT,          FMODSIZE, HEStd_NotSet, HYBRID, FIXEDAUTO,       DFLT,       DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT} },
#if NATIVEINT != 128
    { EVAL_CHEB_POLY, "05", {CKKSRNS_SCHEME, RDIM_LRG, MULT_DEPTH, SMODSIZE,   DFLT,  BATCH,   UNIFORM_TERNARY, DFLT,          FMODSIZE, HEStd_NotSet, HYBRID, FLEXIBLEAUTO,    DFLT,       DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT} },
    { EVAL_CHEB_POLY, "06", {CKKSRNS_SCHEME, RDIM_LRG, MULT_DEPTH, SMODSIZE,   DFLT,  BATCH,   UNIFORM_TERNARY, DFLT,          FMODSIZE, HEStd_NotSet, HYBRID, FLEXIBLEAUTOEXT, DFLT,       DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT} },
    { EVAL_CHEB_POLY, "07", {CKKSRNS_SCHEME, RDIM_LRG, MULT_DEPTH, SMODSIZE,   DFLT,  BATCH,   UNIFORM_TERNARY, DFLT,          FMODSIZE, HEStd_NotSet, HYBRID, FLEXIBLEAUTO,    DFLT,       DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT} },
    { EVAL_CHEB_POLY, "08", {CKKSRNS_SCHEME, RDIM_LRG, MULT_DEPTH, SMODSIZE,   DFLT,  BATCH,   UNIFORM_TERNARY, DFLT,          FMODSIZE, HEStd_NotSet, HYBRID, FLEXIBLEAUTOEXT, DFLT,       DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT} },
#endif
    // ==========================================
    // TestType,   Descr, Scheme,         RDim, MultDepth,  SModSize,   DSize, BatchSz, SecKeyDist,      MaxRelinSkDeg, FModSize, SecLvl,       KSTech, ScalTech,        LDigits,    PtMod, StdDev, EvalAddCt, KSCt, MultTech, EncTech, PREMode
    { EVAL_DIVIDE, "01", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,   DFLT,  BATCH,   UNIFORM_TERNARY, DFLT,          FMODSIZE, HEStd_NotSet, HYBRID, FIXEDMANUAL,     DFLT,       DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT} },
    { EVAL_DIVIDE, "02", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,   DFLT,  BATCH,   UNIFORM_TERNARY, DFLT,          FMODSIZE, HEStd_NotSet, HYBRID, FIXEDAUTO,       DFLT,       DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT} },
    { EVAL_DIVIDE, "03", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,   DFLT,  BATCH,   UNIFORM_TERNARY, DFLT,          FMODSIZE, HEStd_NotSet, HYBRID, FIXEDMANUAL,     DFLT,       DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT} },
    { EVAL_DIVIDE, "04", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,   DFLT,  BATCH,   UNIFORM_TERNARY, DFLT,          FMODSIZE, HEStd_NotSet, HYBRID, FIXEDAUTO,       DFLT,       DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT} },
#if NATIVEINT != 128
    { EVAL_DIVIDE, "05", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,   DFLT,  BATCH,   UNIFORM_TERNARY, DFLT,          FMODSIZE, HEStd_NotSet, HYBRID, FLEXIBLEAUTO,    DFLT,       DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT} },
    { EVAL_DIVIDE, "06", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,   DFLT,  BATCH,   UNIFORM_TERNARY, DFLT,          FMODSIZE, HEStd_NotSet, HYBRID, FLEXIBLEAUTOEXT, DFLT,       DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT} },
    { EVAL_DIVIDE, "07", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,   DFLT,  BATCH,   UNIFORM_TERNARY, DFLT,          FMODSIZE, HEStd_NotSet, HYBRID, FLEXIBLEAUTO,    DFLT,       DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT} },
    { EVAL_DIVIDE, "08", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,   DFLT,  BATCH,   UNIFORM_TERNARY, DFLT,          FMODSIZE, HEStd_NotSet, HYBRID, FLEXIBLEAUTOEXT, DFLT,       DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT} },
#endif
    // ==========================================
    // TestType,     Descr, Scheme,         RDim,     MultDepth,  SModSize,   DSize, BatchSz, SecKeyDist,      MaxRelinSkDeg, FModSize, SecLvl,       KSTech, ScalTech,        LDigits,    PtMod, StdDev, EvalAddCt, KSCt, MultTech, EncTech, PREMode
    { EVAL_LOGISTIC, "01", {CKKSRNS_SCHEME, RDIM_LRG, MULT_DEPTH, SMODSIZE,   DFLT,  16,      UNIFORM_TERNARY, DFLT,          FMODSIZE, HEStd_NotSet, HYBRID, FIXEDMANUAL,     DFLT,       DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT} },
    { EVAL_LOGISTIC, "02", {CKKSRNS_SCHEME, RDIM_LRG, MULT_DEPTH, SMODSIZE,   DFLT,  16,      UNIFORM_TERNARY, DFLT,          FMODSIZE, HEStd_NotSet, HYBRID, FIXEDAUTO,       DFLT,       DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT} },
    { EVAL_LOGISTIC, "03", {CKKSRNS_SCHEME, RDIM_LRG, MULT_DEPTH, SMODSIZE,   DFLT,  16,      UNIFORM_TERNARY, DFLT,          FMODSIZE, HEStd_NotSet, HYBRID, FIXEDMANUAL,     DFLT,       DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT} },
    { EVAL_LOGISTIC, "04", {CKKSRNS_SCHEME, RDIM_LRG, MULT_DEPTH, SMODSIZE,   DFLT,  16,      UNIFORM_TERNARY, DFLT,          FMODSIZE, HEStd_NotSet, HYBRID, FIXEDAUTO,       DFLT,       DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT} },
#if NATIVEINT != 128
    { EVAL_LOGISTIC, "05", {CKKSRNS_SCHEME, RDIM_LRG, MULT_DEPTH, SMODSIZE,   DFLT,  16,      UNIFORM_TERNARY, DFLT,          FMODSIZE, HEStd_NotSet, HYBRID, FLEXIBLEAUTO,    DFLT,       DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT} },
    { EVAL_LOGISTIC, "06", {CKKSRNS_SCHEME, RDIM_LRG, MULT_DEPTH, SMODSIZE,   DFLT,  16,      UNIFORM_TERNARY, DFLT,          FMODSIZE, HEStd_NotSet, HYBRID, FLEXIBLEAUTOEXT, DFLT,       DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT} },
    { EVAL_LOGISTIC, "07", {CKKSRNS_SCHEME, RDIM_LRG, MULT_DEPTH, SMODSIZE,   DFLT,  16,      UNIFORM_TERNARY, DFLT,          FMODSIZE, HEStd_NotSet, HYBRID, FLEXIBLEAUTO,    DFLT,       DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT} },
    { EVAL_LOGISTIC, "08", {CKKSRNS_SCHEME, RDIM_LRG, MULT_DEPTH, SMODSIZE,   DFLT,  16,      UNIFORM_TERNARY, DFLT,          FMODSIZE, HEStd_NotSet, HYBRID, FLEXIBLEAUTOEXT, DFLT,       DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT} },
#endif
    // ==========================================
    // TestType Descr, Scheme,         RDim,     MultDepth,  SModSize,   DSize, BatchSz, SecKeyDist,      MaxRelinSkDeg, FModSize, SecLvl,       KSTech, ScalTech,        LDigits,    PtMod, StdDev, EvalAddCt, KSCt, MultTech, EncTech, PREMode
    { EVAL_SIN, "01", {CKKSRNS_SCHEME, RDIM_LRG, MULT_DEPTH, SMODSIZE,   DFLT,  16,      UNIFORM_TERNARY, DFLT,          FMODSIZE, HEStd_NotSet, HYBRID, FIXEDMANUAL,     DFLT,       DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT} },
    { EVAL_SIN, "02", {CKKSRNS_SCHEME, RDIM_LRG, MULT_DEPTH, SMODSIZE,   DFLT,  16,      UNIFORM_TERNARY, DFLT,          FMODSIZE, HEStd_NotSet, HYBRID, FIXEDAUTO,       DFLT,       DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT} },
    { EVAL_SIN, "03", {CKKSRNS_SCHEME, RDIM_LRG, MULT_DEPTH, SMODSIZE,   DFLT,  16,      UNIFORM_TERNARY, DFLT,          FMODSIZE, HEStd_NotSet, HYBRID, FIXEDMANUAL,     DFLT,       DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT} },
    { EVAL_SIN, "04", {CKKSRNS_SCHEME, RDIM_LRG, MULT_DEPTH, SMODSIZE,   DFLT,  16,      UNIFORM_TERNARY, DFLT,          FMODSIZE, HEStd_NotSet, HYBRID, FIXEDAUTO,       DFLT,       DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT} },
#if NATIVEINT != 128
    { EVAL_SIN, "05", {CKKSRNS_SCHEME, RDIM_LRG, MULT_DEPTH, SMODSIZE,   DFLT,  16,      UNIFORM_TERNARY, DFLT,          FMODSIZE, HEStd_NotSet, HYBRID, FLEXIBLEAUTO,    DFLT,       DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT} },
    { EVAL_SIN, "06", {CKKSRNS_SCHEME, RDIM_LRG, MULT_DEPTH, SMODSIZE,   DFLT,  16,      UNIFORM_TERNARY, DFLT,          FMODSIZE, HEStd_NotSet, HYBRID, FLEXIBLEAUTOEXT, DFLT,       DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT} },
    { EVAL_SIN, "07", {CKKSRNS_SCHEME, RDIM_LRG, MULT_DEPTH, SMODSIZE,   DFLT,  16,      UNIFORM_TERNARY, DFLT,          FMODSIZE, HEStd_NotSet, HYBRID, FLEXIBLEAUTO,    DFLT,       DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT} },
    { EVAL_SIN, "08", {CKKSRNS_SCHEME, RDIM_LRG, MULT_DEPTH, SMODSIZE,   DFLT,  16,      UNIFORM_TERNARY, DFLT,          FMODSIZE, HEStd_NotSet, HYBRID, FLEXIBLEAUTOEXT, DFLT,       DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT} },
#endif
    // ==========================================
    // TestType Descr, Scheme,         RDim,     MultDepth,  SModSize,   DSize, BatchSz, SecKeyDist,      MaxRelinSkDeg, FModSize, SecLvl,       KSTech, ScalTech,        LDigits,    PtMod, StdDev, EvalAddCt, KSCt, MultTech, EncTech, PREMode
    { EVAL_COS, "01", {CKKSRNS_SCHEME, RDIM_LRG, MULT_DEPTH, SMODSIZE,   DFLT,  16,      UNIFORM_TERNARY, DFLT,          FMODSIZE, HEStd_NotSet, HYBRID, FIXEDMANUAL,     DFLT,       DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT} },
    { EVAL_COS, "02", {CKKSRNS_SCHEME, RDIM_LRG, MULT_DEPTH, SMODSIZE,   DFLT,  16,      UNIFORM_TERNARY, DFLT,          FMODSIZE, HEStd_NotSet, HYBRID, FIXEDAUTO,       DFLT,       DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT} },
    { EVAL_COS, "03", {CKKSRNS_SCHEME, RDIM_LRG, MULT_DEPTH, SMODSIZE,   DFLT,  16,      UNIFORM_TERNARY, DFLT,          FMODSIZE, HEStd_NotSet, HYBRID, FIXEDMANUAL,     DFLT,       DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT} },
    { EVAL_COS, "04", {CKKSRNS_SCHEME, RDIM_LRG, MULT_DEPTH, SMODSIZE,   DFLT,  16,      UNIFORM_TERNARY, DFLT,          FMODSIZE, HEStd_NotSet, HYBRID, FIXEDAUTO,       DFLT,       DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT} },
#if NATIVEINT != 128
    { EVAL_COS, "05", {CKKSRNS_SCHEME, RDIM_LRG, MULT_DEPTH, SMODSIZE,   DFLT,  16,      UNIFORM_TERNARY, DFLT,          FMODSIZE, HEStd_NotSet, HYBRID, FLEXIBLEAUTO,    DFLT,       DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT} },
    { EVAL_COS, "06", {CKKSRNS_SCHEME, RDIM_LRG, MULT_DEPTH, SMODSIZE,   DFLT,  16,      UNIFORM_TERNARY, DFLT,          FMODSIZE, HEStd_NotSet, HYBRID, FLEXIBLEAUTOEXT, DFLT,       DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT} },
    { EVAL_COS, "07", {CKKSRNS_SCHEME, RDIM_LRG, MULT_DEPTH, SMODSIZE,   DFLT,  16,      UNIFORM_TERNARY, DFLT,          FMODSIZE, HEStd_NotSet, HYBRID, FLEXIBLEAUTO,    DFLT,       DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT} },
    { EVAL_COS, "08", {CKKSRNS_SCHEME, RDIM_LRG, MULT_DEPTH, SMODSIZE,   DFLT,  16,      UNIFORM_TERNARY, DFLT,          FMODSIZE, HEStd_NotSet, HYBRID, FLEXIBLEAUTOEXT, DFLT,       DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT} },
#endif
    // ==========================================
};
// clang-format on
//===========================================================================================================
class UTCKKSRNS_EVAL_POLY : public ::testing::TestWithParam<TEST_CASE_UTCKKSRNS_EVAL_POLY> {
    using Element = DCRTPoly;

    // The precision after which we consider two values equal.
    // This is necessary because CKKS works for approximate numbers.
    const double eps = 0.001;

protected:
    void SetUp() {}

    void TearDown() {
        CryptoContextFactory<DCRTPoly>::ReleaseAllContexts();
    }

    void UnitTest_EvalPoly(const TEST_CASE_UTCKKSRNS_EVAL_POLY& testData, const std::string& failmsg = std::string()) {
        try {
            CryptoContext<Element> cc(UnitTestGenerateContext(testData.params));

            std::vector<std::complex<double>> input{0.5, 0.7, 0.9, 0.95, 0.93};
            size_t encodedLength = input.size();

            // with only positive coefficients
            // x^16 + x^11 + 2 x^9 + x^8 + x^6 + 1.25 x^3 + 0.75*x + 0.15
            std::vector<double> coefficients1{0.15, 0.75, 0, 1.25, 0, 0, 1, 0, 1, 2, 0, 1, 0, 0, 0, 0, 1};
            // x^16 + x^11 + 2 x^9 - x^8 + x^6 + 1.25 x^3 - 0.75*x + 0.15
            // with negative coefficients
            std::vector<double> coefficients2{0.15, -0.75, 0, 1.25, 0, 0, 1, 0, -1, 2, 0, 1, 0, 0, 0, 0, 1};
            // x^16
            // power function
            std::vector<double> coefficients3{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
            // x^16 + x^11 + 2 x^9 - x^8 + x^6 - 1.25 x^5 + 1.25 x^3 - 1.75*x + 0.15
            // with negative coefficients with magnitude greater than 1
            std::vector<double> coefficients4{0.15, -1.75, 0, 1.25, 0, -1.25, 1, 0, -1, 2, 0, 1, 0, 0, 0, 0, 1};
            // x + x^2 - x^3
            // low-degree function to check linear implementation
            std::vector<double> coefficients5{0, 1, 1, -1};

            Plaintext plaintext1 = cc->MakeCKKSPackedPlaintext(input);

            std::vector<std::complex<double>> output1{0.705191, 1.38285, 3.97211, 5.60216, 4.86358};
            Plaintext plaintextResult1 = cc->MakeCKKSPackedPlaintext(output1);

            std::vector<std::complex<double>> output2{-0.0526215, 0.217555, 1.76118, 2.85032, 2.34941};
            Plaintext plaintextResult2 = cc->MakeCKKSPackedPlaintext(output2);

            std::vector<std::complex<double>> output3{0.0000152588, 0.00332329, 0.185302, 0.440127, 0.313132};
            Plaintext plaintextResult3 = cc->MakeCKKSPackedPlaintext(output3);

            std::vector<std::complex<double>> output4{-0.59168396, -0.69253274, 0.12306489, 0.93308964, 0.54980166};
            Plaintext plaintextResult4 = cc->MakeCKKSPackedPlaintext(output4);

            std::vector<std::complex<double>> output5{0.625, 0.847, 0.9809999999, 0.995125, 0.990543};
            Plaintext plaintextResult5 = cc->MakeCKKSPackedPlaintext(output5);

            auto keyPair = cc->KeyGen();
            cc->EvalMultKeyGen(keyPair.secretKey);

            // Encrypt plaintexts
            Ciphertext<Element> ciphertext1 = cc->Encrypt(keyPair.publicKey, plaintext1);

            Plaintext results1;
            auto cResult1 = cc->EvalPoly(ciphertext1, coefficients1);
            cc->Decrypt(keyPair.secretKey, cResult1, &results1);
            results1->SetLength(encodedLength);
            checkEquality(plaintextResult1->GetCKKSPackedValue(), results1->GetCKKSPackedValue(), eps,
                          failmsg + " EvalPoly with positive coefficients fails");

            Plaintext results2;
            auto cResult2 = cc->EvalPoly(ciphertext1, coefficients2);
            cc->Decrypt(keyPair.secretKey, cResult2, &results2);
            results2->SetLength(encodedLength);
            checkEquality(plaintextResult2->GetCKKSPackedValue(), results2->GetCKKSPackedValue(), eps,
                          failmsg + " EvalPoly with negative coefficients fails");

            Plaintext results3;
            auto cResult3 = cc->EvalPoly(ciphertext1, coefficients3);
            cc->Decrypt(keyPair.secretKey, cResult3, &results3);
            results3->SetLength(encodedLength);
            checkEquality(plaintextResult3->GetCKKSPackedValue(), results3->GetCKKSPackedValue(), eps,
                          failmsg + " EvalPoly for a power function fails");

            Plaintext results4;
            auto cResult4 = cc->EvalPoly(ciphertext1, coefficients4);
            cc->Decrypt(keyPair.secretKey, cResult4, &results4);
            results4->SetLength(encodedLength);
            checkEquality(plaintextResult4->GetCKKSPackedValue(), results4->GetCKKSPackedValue(), eps,
                          failmsg + " EvalPoly for negative coefficients with magnitude > 1 fails");

            Plaintext results5;
            auto cResult5 = cc->EvalPoly(ciphertext1, coefficients5);
            cc->Decrypt(keyPair.secretKey, cResult5, &results5);
            results5->SetLength(encodedLength);
            checkEquality(plaintextResult5->GetCKKSPackedValue(), results5->GetCKKSPackedValue(), eps,
                          failmsg + " EvalPoly for low-degree polynomial fails");
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

    void UnitTest_EvalChebDivision(const TEST_CASE_UTCKKSRNS_EVAL_POLY& testData,
                                   const std::string& failmsg = std::string()) {
        try {
            CryptoContext<Element> cc(UnitTestGenerateContext(testData.params));

            std::vector<std::complex<double>> input{2.0, 16.0, 64.0, 128.0, 512.0};
            size_t encodedLength = input.size();

            std::vector<double> coefficients(
                {0.0625,       -0.0587121,    0.0551538,    -0.0518111,    0.0486711,    -0.0457213,
                 0.0429503,    -0.0403473,    0.037902,     -0.0356049,    0.033447,     -0.0314199,
                 0.0295157,    -0.0277269,    0.0260464,    -0.0244679,    0.022985,     -0.0215919,
                 0.0202833,    -0.019054,     0.0178992,    -0.0168144,    0.0157954,    -0.0148381,
                 0.0139388,    -0.013094,     0.0123004,    -0.011555,     0.0108546,    -0.0101968,
                 0.00957879,   -0.00899825,   0.0084529,    -0.0079406,    0.00745934,   -0.00700726,
                 0.00658257,   -0.00618362,   0.00580884,   -0.00545678,   0.00512606,   -0.00481538,
                 0.00452353,   -0.00424937,   0.00399182,   -0.00374988,   0.0035226,    -0.00330909,
                 0.00310853,   -0.00292012,   0.00274312,   -0.00257686,   0.00242066,   -0.00227394,
                 0.0021361,    -0.00200662,   0.00188498,   -0.00177071,   0.00166337,   -0.00156253,
                 0.0014678,    -0.00137881,   0.00129521,   -0.00121668,   0.0011429,    -0.00107359,
                 0.00100848,   -0.000947312,  0.000889848,  -0.000835863,  0.000785147,  -0.000737501,
                 0.000692739,  -0.000650685,  0.000611175,  -0.000574055,  0.00053918,   -0.000506413,
                 0.000475626,  -0.000446699,  0.000419519,  -0.000393978,  0.000369979,  -0.000347425,
                 0.000326231,  -0.000306312,  0.00028759,   -0.000269994,  0.000253452,  -0.000237902,
                 0.000223282,  -0.000209536,  0.000196608,  -0.000184449,  0.000173012,  -0.00016225,
                 0.000152124,  -0.000142592,  0.000133617,  -0.000125166,  0.000117203,  -0.000109699,
                 0.000102624,  -0.0000959495, 0.0000896506, -0.0000837023, 0.0000780812, -0.0000727655,
                 0.0000677343, -0.0000629679, 0.0000584477, -0.0000541561, 0.0000500762, -0.0000461921,
                 0.0000424887, -0.0000389514, 0.0000355663, -0.0000323204, 0.0000292008, -0.0000261954,
                 0.0000232924, -0.0000204805, 0.0000177487, -0.0000150862, 0.0000124828, -9.92817e-6,
                 7.41236e-6,   -4.92553e-6,   2.45796e-6});

            std::vector<std::complex<double>> output1{0.500067, 0.0624609, 0.0156279, 0.00781142, 0.00195297};
            Plaintext plaintextResult1 = cc->MakeCKKSPackedPlaintext(output1);

            auto keyPair = cc->KeyGen();
            cc->EvalMultKeyGen(keyPair.secretKey);

            Plaintext plaintext1 = cc->MakeCKKSPackedPlaintext(input);
            auto ciphertext1     = cc->Encrypt(keyPair.publicKey, plaintext1);

            double a    = 1;
            double b    = 1024;
            auto result = cc->EvalChebyshevSeries(ciphertext1, coefficients, a, b);

            Plaintext plaintextDec;
            cc->Decrypt(keyPair.secretKey, result, &plaintextDec);
            plaintextDec->SetLength(encodedLength);

            std::vector<std::complex<double>> finalResult = plaintextDec->GetCKKSPackedValue();
            finalResult.resize(encodedLength);
            checkEquality(plaintextResult1->GetCKKSPackedValue(), finalResult, eps,
                          failmsg + " EvalChebyshevSeries approximation for division fails");
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

    void UnitTest_EvalChebLogit(const TEST_CASE_UTCKKSRNS_EVAL_POLY& testData,
                                const std::string& failmsg = std::string()) {
        try {
            CryptoContext<Element> cc(UnitTestGenerateContext(testData.params));

            std::vector<std::complex<double>> input{-4.0, -3.0, -2.0, -1.0, 0.0, 1.0, 2.0, 3.0, 4.0};
            size_t encodedLength = input.size();

            std::vector<double> coefficients({1.0, 0.558971, 0.0, -0.0943712, 0.0, 0.0215023, 0.0, -0.00505348, 0.0,
                                              0.00119324, 0.0, -0.000281928, 0.0, 0.0000664347, 0.0, -0.0000148709});
            std::vector<std::complex<double>> output1(
                {0.0179885, 0.0474289, 0.119205, 0.268936, 0.5, 0.731064, 0.880795, 0.952571, 0.982011});

            Plaintext plaintext1       = cc->MakeCKKSPackedPlaintext(input);
            Plaintext plaintextResult1 = cc->MakeCKKSPackedPlaintext(output1);

            auto keyPair = cc->KeyGen();
            cc->EvalMultKeyGen(keyPair.secretKey);
            auto ciphertext1 = cc->Encrypt(keyPair.publicKey, plaintext1);

            double a    = -4;
            double b    = 4;
            auto result = cc->EvalChebyshevSeries(ciphertext1, coefficients, a, b);

            Plaintext plaintextDec;
            cc->Decrypt(keyPair.secretKey, result, &plaintextDec);
            plaintextDec->SetLength(encodedLength);

            std::vector<std::complex<double>> finalResult = plaintextDec->GetCKKSPackedValue();
            finalResult.resize(encodedLength);

            checkEquality(plaintextResult1->GetCKKSPackedValue(), finalResult, eps,
                          failmsg + " EvalChebyshevSeries approximation for logistic function fails");
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

    void UnitTest_EvalChebLogitNoLin(const TEST_CASE_UTCKKSRNS_EVAL_POLY& testData,
                                     const std::string& failmsg = std::string()) {
        try {
            CryptoContext<Element> cc(UnitTestGenerateContext(testData.params));

            std::vector<std::complex<double>> input{-4.0, -3.0, -2.0, -1.0, 0.0, 1.0, 2.0, 3.0, 4.0};
            size_t encodedLength = input.size();
            for (size_t i = 0; i < encodedLength; ++i)
                input[i] *= 0.25;

            std::vector<double> coefficients({1.0, 0.558971, 0.0, -0.0943712, 0.0, 0.0215023, 0.0, -0.00505348, 0.0,
                                              0.00119324, 0.0, -0.000281928, 0.0, 0.0000664347, 0.0, -0.0000148709});
            std::vector<std::complex<double>> output1(
                {0.0179885, 0.0474289, 0.119205, 0.268936, 0.5, 0.731064, 0.880795, 0.952571, 0.982011});

            Plaintext plaintext1       = cc->MakeCKKSPackedPlaintext(input);
            Plaintext plaintextResult1 = cc->MakeCKKSPackedPlaintext(output1);

            auto keyPair = cc->KeyGen();
            cc->EvalMultKeyGen(keyPair.secretKey);
            auto ciphertext1 = cc->Encrypt(keyPair.publicKey, plaintext1);

            double a    = -1;
            double b    = 1;
            auto result = cc->EvalChebyshevSeries(ciphertext1, coefficients, a, b);

            Plaintext plaintextDec;
            cc->Decrypt(keyPair.secretKey, result, &plaintextDec);
            plaintextDec->SetLength(encodedLength);

            std::vector<std::complex<double>> finalResult = plaintextDec->GetCKKSPackedValue();
            finalResult.resize(encodedLength);

            checkEquality(plaintextResult1->GetCKKSPackedValue(), finalResult, eps,
                          failmsg + " EvalChebyshevSeries approximation for logistic function fails");
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

    void UnitTest_EvalChebSine(const TEST_CASE_UTCKKSRNS_EVAL_POLY& testData,
                               const std::string& failmsg = std::string()) {
        try {
            CryptoContext<Element> cc(UnitTestGenerateContext(testData.params));

            std::vector<std::complex<double>> input{-1., -0.8, -0.6, -0.4, -0.2, 0., 0.2, 0.4, 0.6, 0.8, 1.};
            size_t encodedLength = input.size();

            std::vector<double> coefficients{
                0., -0.0178446,   0., -0.0171187,  0., -0.0155856,    0., -0.0131009,   0., -0.00949759,
                0., -0.00465513,  0., 0.00139902,  0., 0.00836141,    0., 0.0155242,    0., 0.0217022,
                0., 0.0253027,    0., 0.0246365,   0., 0.0185273,     0., 0.00714273,   0., -0.00725482,
                0., -0.0201827,   0., -0.0260483,  0., -0.0207132,    0., -0.00473479,  0., 0.0147661,
                0., 0.0261764,    0., 0.0203168,   0., -0.00103552,   0., -0.0225101,   0., -0.0248192,
                0., -0.00315799,  0., 0.0226844,   0., 0.0238252,     0., -0.00403513,  0., -0.0276106,
                0., -0.0133143,   0., 0.0213882,   0., 0.0230787,     0., -0.0143638,   0., -0.0270401,
                0., 0.0116019,    0., 0.0278743,   0., -0.0149975,    0., -0.025194,    0., 0.0242296,
                0., 0.0143133,    0., -0.0334779,  0., 0.00994475,    0., 0.0256291,    0., -0.0359815,
                0., 0.0150778,    0., 0.0173112,   0., -0.0403029,    0., 0.0463332,    0., -0.039547,
                0., 0.0277765,    0., -0.0168089,  0., 0.00899558,    0., -0.00433006,  0., 0.00189728,
                0., -0.000763553, 0., 0.000284227, 0., -0.0000984182, 0., 0.0000318501, 0., -9.67162e-6,
                0., 2.76517e-6,   0., -7.46488e-7, 0., 1.90362e-7,    0., -4.39544e-8,  0.};
            std::vector<std::complex<double>> output1{6.80601e-09, 0.151365,  0.0935489,  -0.0935489, -0.151365,   0.,
                                                      0.151365,    0.0935489, -0.0935489, -0.151365,  -6.80601e-09};

            Plaintext plaintext1       = cc->MakeCKKSPackedPlaintext(input);
            Plaintext plaintextResult1 = cc->MakeCKKSPackedPlaintext(output1);

            auto keyPair = cc->KeyGen();
            cc->EvalMultKeyGen(keyPair.secretKey);
            auto ciphertext1 = cc->Encrypt(keyPair.publicKey, plaintext1);

            double a    = -1;
            double b    = 1;
            auto result = cc->EvalChebyshevSeries(ciphertext1, coefficients, a, b);

            Plaintext plaintextDec;
            cc->Decrypt(keyPair.secretKey, result, &plaintextDec);
            plaintextDec->SetLength(encodedLength);

            std::vector<std::complex<double>> finalResult = plaintextDec->GetCKKSPackedValue();
            finalResult.resize(encodedLength);

            checkEquality(plaintextResult1->GetCKKSPackedValue(), finalResult, eps,
                          failmsg + " EvalChebyshevSeries approximation for sine fails");
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

    void UnitTest_EvalChebPoly(const TEST_CASE_UTCKKSRNS_EVAL_POLY& testData,
                               const std::string& failmsg = std::string()) {
        try {
            CryptoContext<Element> cc(UnitTestGenerateContext(testData.params));

            std::vector<std::complex<double>> input{-3.0, -2.0, -1.0, 0.0, 1.0, 2.0, 3.0};
            size_t encodedLength = input.size();

            std::vector<double> coefficients{9, -17.25, 4.5, -6.75, -0};
            std::vector<std::complex<double>> output1{33, 10, 1, 0, 1, -2, -15};

            Plaintext plaintext1       = cc->MakeCKKSPackedPlaintext(input);
            Plaintext plaintextResult1 = cc->MakeCKKSPackedPlaintext(output1);

            auto keyPair = cc->KeyGen();
            cc->EvalMultKeyGen(keyPair.secretKey);
            auto ciphertext1 = cc->Encrypt(keyPair.publicKey, plaintext1);

            double a    = -3;
            double b    = 3;
            auto result = cc->EvalChebyshevSeries(ciphertext1, coefficients, a, b);

            Plaintext plaintextDec;
            cc->Decrypt(keyPair.secretKey, result, &plaintextDec);
            plaintextDec->SetLength(encodedLength);

            std::vector<std::complex<double>> finalResult = plaintextDec->GetCKKSPackedValue();
            finalResult.resize(encodedLength);

            checkEquality(plaintextResult1->GetCKKSPackedValue(), finalResult, eps,
                          failmsg + " EvalChebyshevSeries approximation for sine fails");
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

    void UnitTest_EvalDivide(const TEST_CASE_UTCKKSRNS_EVAL_POLY& testData,
                             const std::string& failmsg = std::string()) {
        try {
            CryptoContext<Element> cc(UnitTestGenerateContext(testData.params));

            std::vector<std::complex<double>> input{2.0, 16.0, 64.0, 128.0, 512.0};
            size_t encodedLength = input.size();

            std::vector<std::complex<double>> expectedOutput{0.500067, 0.0624609, 0.0156279, 0.00781142, 0.00195297};

            auto keyPair = cc->KeyGen();
            cc->EvalMultKeyGen(keyPair.secretKey);

            Plaintext plaintext1 = cc->MakeCKKSPackedPlaintext(input);
            auto ciphertext1     = cc->Encrypt(keyPair.publicKey, plaintext1);

            double a        = 1;
            double b        = 1024;
            uint32_t degree = 129;
            auto result     = cc->EvalDivide(ciphertext1, a, b, degree);

            Plaintext plaintextDec;
            cc->Decrypt(keyPair.secretKey, result, &plaintextDec);
            plaintextDec->SetLength(encodedLength);

            std::vector<std::complex<double>> finalResult = plaintextDec->GetCKKSPackedValue();
            checkEquality(expectedOutput, finalResult, eps, failmsg + " EvalDivide Chebyshev approximation fails");
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
    void UnitTest_EvalLogistic(const TEST_CASE_UTCKKSRNS_EVAL_POLY& testData,
                               const std::string& failmsg = std::string()) {
        CryptoContext<Element> cc(UnitTestGenerateContext(testData.params));

        std::vector<std::complex<double>> input{-4.0, -3.0, -2.0, -1.0, 0.0, 1.0, 2.0, 3.0, 4.0};
        size_t encodedLength = input.size();

        std::vector<std::complex<double>> expectedOutput(
            {0.0179885, 0.0474289, 0.119205, 0.268936, 0.5, 0.731064, 0.880795, 0.952571, 0.982011});

        Plaintext plaintext = cc->MakeCKKSPackedPlaintext(input);

        auto keyPair = cc->KeyGen();
        cc->EvalMultKeyGen(keyPair.secretKey);
        auto ciphertext = cc->Encrypt(keyPair.publicKey, plaintext);

        double a        = -4;
        double b        = 4;
        uint32_t degree = 16;
        auto result     = cc->EvalLogistic(ciphertext, a, b, degree);

        Plaintext plaintextDec;
        cc->Decrypt(keyPair.secretKey, result, &plaintextDec);
        plaintextDec->SetLength(encodedLength);

        std::vector<std::complex<double>> finalResult = plaintextDec->GetCKKSPackedValue();

        checkEquality(expectedOutput, finalResult, eps, failmsg + " EvalLogistic Chebyshev approximation fails");
    }
    void UnitTest_EvalSin(const TEST_CASE_UTCKKSRNS_EVAL_POLY& testData, const std::string& failmsg = std::string()) {
        CryptoContext<Element> cc(UnitTestGenerateContext(testData.params));

        std::vector<std::complex<double>> input{-1., -0.8, -0.6, -0.4, -0.2, 0., 0.2, 0.4, 0.6, 0.8, 1.};
        size_t encodedLength = input.size();

        std::vector<std::complex<double>> expectedOutput{-0.841470, -0.717356, -0.564642, -0.389418, -0.198669, 0,
                                                         0.198669,  0.389418,  0.564642,  0.717356,  0.841470};

        Plaintext plaintext = cc->MakeCKKSPackedPlaintext(input);

        auto keyPair = cc->KeyGen();
        cc->EvalMultKeyGen(keyPair.secretKey);
        auto ciphertext = cc->Encrypt(keyPair.publicKey, plaintext);

        double a        = -1;
        double b        = 1;
        uint32_t degree = 129;
        auto result     = cc->EvalSin(ciphertext, a, b, degree);

        Plaintext plaintextDec;
        cc->Decrypt(keyPair.secretKey, result, &plaintextDec);
        plaintextDec->SetLength(encodedLength);

        std::vector<std::complex<double>> finalResult = plaintextDec->GetCKKSPackedValue();

        checkEquality(expectedOutput, finalResult, eps, failmsg + " EvalSin Chebyshev approximation fails");
    }
    void UnitTest_EvalCos(const TEST_CASE_UTCKKSRNS_EVAL_POLY& testData, const std::string& failmsg = std::string()) {
        CryptoContext<Element> cc(UnitTestGenerateContext(testData.params));

        std::vector<std::complex<double>> input{-1., -0.8, -0.6, -0.4, -0.2, 0., 0.2, 0.4, 0.6, 0.8, 1.};
        size_t encodedLength = input.size();

        std::vector<std::complex<double>> expectedOutput{0.540302, 0.696706, 0.825335, 0.921060, 0.980066, 1.0,
                                                         0.980066, 0.921060, 0.825335, 0.696706, 0.540302};

        Plaintext plaintext = cc->MakeCKKSPackedPlaintext(input);

        auto keyPair = cc->KeyGen();
        cc->EvalMultKeyGen(keyPair.secretKey);
        auto ciphertext = cc->Encrypt(keyPair.publicKey, plaintext);

        double a        = -1;
        double b        = 1;
        uint32_t degree = 129;
        auto result     = cc->EvalCos(ciphertext, a, b, degree);

        Plaintext plaintextDec;
        cc->Decrypt(keyPair.secretKey, result, &plaintextDec);
        plaintextDec->SetLength(encodedLength);

        std::vector<std::complex<double>> finalResult = plaintextDec->GetCKKSPackedValue();

        checkEquality(expectedOutput, finalResult, eps, failmsg + " EvalCos Chebyshev approximation fails");
    }
};

//===========================================================================================================
TEST_P(UTCKKSRNS_EVAL_POLY, CKKSRNS) {
    setupSignals();
    auto test = GetParam();

    switch (test.testCaseType) {
        case EVAL_POLY:
            UnitTest_EvalPoly(test, test.buildTestName());
            break;
        case EVAL_CHEB_DIVISION:
            UnitTest_EvalChebDivision(test, test.buildTestName());
            break;
        case EVAL_CHEB_LOGIT:
            UnitTest_EvalChebLogit(test, test.buildTestName());
            break;
        case EVAL_CHEB_LOGIT_NOLIN:
            UnitTest_EvalChebLogitNoLin(test, test.buildTestName());
            break;
        case EVAL_CHEB_SINE:
            UnitTest_EvalChebSine(test, test.buildTestName());
            break;
        case EVAL_CHEB_POLY:
            UnitTest_EvalChebPoly(test, test.buildTestName());
            break;
        case EVAL_DIVIDE:
            UnitTest_EvalDivide(test, test.buildTestName());
            break;
        case EVAL_LOGISTIC:
            UnitTest_EvalLogistic(test, test.buildTestName());
            break;
        case EVAL_SIN:
            UnitTest_EvalSin(test, test.buildTestName());
            break;
        case EVAL_COS:
            UnitTest_EvalCos(test, test.buildTestName());
            break;
        default:
            break;
    }
}

INSTANTIATE_TEST_SUITE_P(UnitTests, UTCKKSRNS_EVAL_POLY, ::testing::ValuesIn(testCases), testName);
