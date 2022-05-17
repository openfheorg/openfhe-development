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
#include <cxxabi.h>
#include "utils/demangle.h"


using namespace lbcrypto;

//===========================================================================================================
enum TEST_CASE_TYPE {
    ADD_PACKED = 0,
    MULT_PACKED,
    SCALE_FACTOR_ADJUSTMENTS,
    AUTO_LEVEL_REDUCE,
    COMPRESS,
    EVAL_FAST_ROTATION,
    EVALATINDEX,
    EVALMERGE,
    EVAL_LINEAR_WSUM,
    RE_ENCRYPTION,
    EVAL_POLY,
    METADATA,
};

static std::ostream& operator<<(std::ostream& os, const TEST_CASE_TYPE& type) {
    std::string typeName;
    switch (type) {
    case ADD_PACKED:
        typeName = "ADD_PACKED";
        break;
    case MULT_PACKED:
        typeName = "MULT_PACKED";
        break;
    case SCALE_FACTOR_ADJUSTMENTS:
        typeName = "SCALE_FACTOR_ADJUSTMENTS";
        break;
    case AUTO_LEVEL_REDUCE:
        typeName = "AUTO_LEVEL_REDUCE";
        break;
    case COMPRESS:
        typeName = "COMPRESS";
        break;
    case EVAL_FAST_ROTATION:
        typeName = "EVAL_FAST_ROTATION";
        break;
    case EVALATINDEX:
        typeName = "EVALATINDEX";
        break;
    case EVALMERGE:
        typeName = "EVALMERGE";
        break;
    case EVAL_LINEAR_WSUM:
        typeName = "EVAL_LINEAR_WSUM";
        break;
    case RE_ENCRYPTION:
        typeName = "RE_ENCRYPTION";
        break;
    case EVAL_POLY:
        typeName = "EVAL_POLY";
        break;
    case METADATA:
        typeName = "METADATA";
        break;
    default:
        typeName = "UNKNOWN";
        break;
    }
    return os << typeName;
}
//===========================================================================================================
struct TEST_CASE_UTCKKSRNS {
    TEST_CASE_TYPE testCaseType;
    // test case description - MUST BE UNIQUE
    std::string description;

    UnitTestCCParams  params;

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
static auto testName = [](const testing::TestParamInfo<TEST_CASE_UTCKKSRNS>& test) {
    return test.param.buildTestName();
};

static std::ostream& operator<<(std::ostream& os, const TEST_CASE_UTCKKSRNS& test) {
    return os << test.toString();
}
//===========================================================================================================
/***
 * ORDER: Cyclotomic order. Must be a power of 2 for CKKS. RING_DIM = cyclOrder / 2
 * NUMPRIME: Number of towers comprising the ciphertext modulus. MultDepth = NUMPRIME - 1
 * SCALE: Scaling factor bit-length.
 *       Should fit into a machine word, i.e., less than 64.
 * RELIN: The bit decomposition count used in BV relinearization.
 * BATCH: The length of the packed vectors to be used with CKKS.
 */
constexpr usint RING_DIM = 512;
constexpr usint RELIN    = 10;
constexpr usint BATCH    = 8;
#if NATIVEINT == 128
constexpr usint SCALE = 90;
#else
constexpr usint SCALE = 50;
#endif

// clang-format off
static std::vector<TEST_CASE_UTCKKSRNS> testCases = {
    // TestType,  Descr, Scheme,        RDim, MultDepth, SFBits, RWin,  BatchSz, Mode,       Depth, MDepth, ModSize, SecLvl,       KSTech, RSTech,          LDigits, PtMod, StdDev, EvalAddCt, EvalMultCt, KSCt, MultTech
    { ADD_PACKED, "1", {CKKSRNS_SCHEME, RING_DIM, 7,     SCALE,  RELIN, BATCH,   OPTIMIZED,  DFLT,  DFLT,   DFLT,    HEStd_NotSet, BV,     FIXEDMANUAL,     DFLT,    DFLT,  DFLT,   DFLT,      DFLT,       DFLT, DFLT}, },
    { ADD_PACKED, "2", {CKKSRNS_SCHEME, RING_DIM, 7,     SCALE,  RELIN, BATCH,   OPTIMIZED,  DFLT,  DFLT,   DFLT,    HEStd_NotSet, BV,     FIXEDAUTO,       DFLT,    DFLT,  DFLT,   DFLT,      DFLT,       DFLT, DFLT}, },
    { ADD_PACKED, "3", {CKKSRNS_SCHEME, RING_DIM, 7,     SCALE,  RELIN, BATCH,   OPTIMIZED,  DFLT,  DFLT,   DFLT,    HEStd_NotSet, HYBRID, FIXEDMANUAL,     DFLT,    DFLT,  DFLT,   DFLT,      DFLT,       DFLT, DFLT}, },
    { ADD_PACKED, "4", {CKKSRNS_SCHEME, RING_DIM, 7,     SCALE,  RELIN, BATCH,   OPTIMIZED,  DFLT,  DFLT,   DFLT,    HEStd_NotSet, HYBRID, FIXEDAUTO,       DFLT,    DFLT,  DFLT,   DFLT,      DFLT,       DFLT, DFLT}, },
#if NATIVEINT != 128
    { ADD_PACKED, "5", {CKKSRNS_SCHEME, RING_DIM, 7,     SCALE,  RELIN, BATCH,   OPTIMIZED,  DFLT,  DFLT,   DFLT,    HEStd_NotSet, BV,     FLEXIBLEAUTO,    DFLT,    DFLT,  DFLT,   DFLT,      DFLT,       DFLT, DFLT}, },
    { ADD_PACKED, "6", {CKKSRNS_SCHEME, RING_DIM, 7,     SCALE,  RELIN, BATCH,   OPTIMIZED,  DFLT,  DFLT,   DFLT,    HEStd_NotSet, HYBRID, FLEXIBLEAUTO,    DFLT,    DFLT,  DFLT,   DFLT,      DFLT,       DFLT, DFLT}, },
    { ADD_PACKED, "7", {CKKSRNS_SCHEME, RING_DIM, 7,     SCALE,  RELIN, BATCH,   OPTIMIZED,  DFLT,  DFLT,   DFLT,    HEStd_NotSet, BV,     FLEXIBLEAUTOEXT, DFLT,    DFLT,  DFLT,   DFLT,      DFLT,       DFLT, DFLT}, },
    { ADD_PACKED, "8", {CKKSRNS_SCHEME, RING_DIM, 7,     SCALE,  RELIN, BATCH,   OPTIMIZED,  DFLT,  DFLT,   DFLT,    HEStd_NotSet, HYBRID, FLEXIBLEAUTOEXT, DFLT,    DFLT,  DFLT,   DFLT,      DFLT,       DFLT, DFLT}, },
#endif
    // ==========================================
    // TestType,  Descr, Scheme,         RDim, MultDepth, SFBits, RWin,  BatchSz, Mode,       Depth, MDepth, ModSize, SecLvl,       KSTech, RSTech,          LDigits, PtMod, StdDev, EvalAddCt, EvalMultCt, KSCt, MultTech
    { MULT_PACKED, "1", {CKKSRNS_SCHEME, RING_DIM, 7,     SCALE,  RELIN, BATCH,   OPTIMIZED,  DFLT,  DFLT,   DFLT,    HEStd_NotSet, BV,     FIXEDMANUAL,     DFLT,    DFLT,  DFLT,   DFLT,      DFLT,       DFLT, DFLT}, },
    { MULT_PACKED, "2", {CKKSRNS_SCHEME, RING_DIM, 7,     SCALE,  RELIN, BATCH,   OPTIMIZED,  DFLT,  DFLT,   DFLT,    HEStd_NotSet, BV,     FIXEDAUTO,       DFLT,    DFLT,  DFLT,   DFLT,      DFLT,       DFLT, DFLT}, },
    { MULT_PACKED, "3", {CKKSRNS_SCHEME, RING_DIM, 7,     SCALE,  RELIN, BATCH,   OPTIMIZED,  DFLT,  DFLT,   DFLT,    HEStd_NotSet, HYBRID, FIXEDMANUAL,     DFLT,    DFLT,  DFLT,   DFLT,      DFLT,       DFLT, DFLT}, },
    { MULT_PACKED, "4", {CKKSRNS_SCHEME, RING_DIM, 7,     SCALE,  RELIN, BATCH,   OPTIMIZED,  DFLT,  DFLT,   DFLT,    HEStd_NotSet, HYBRID, FIXEDAUTO,       DFLT,    DFLT,  DFLT,   DFLT,      DFLT,       DFLT, DFLT}, },
#if NATIVEINT != 128
    { MULT_PACKED, "5", {CKKSRNS_SCHEME, RING_DIM, 7,     SCALE,  RELIN, BATCH,   OPTIMIZED,  DFLT,  DFLT,   DFLT,    HEStd_NotSet, BV,     FLEXIBLEAUTO,    DFLT,    DFLT,  DFLT,   DFLT,      DFLT,       DFLT, DFLT}, },
    { MULT_PACKED, "6", {CKKSRNS_SCHEME, RING_DIM, 7,     SCALE,  RELIN, BATCH,   OPTIMIZED,  DFLT,  DFLT,   DFLT,    HEStd_NotSet, HYBRID, FLEXIBLEAUTO,    DFLT,    DFLT,  DFLT,   DFLT,      DFLT,       DFLT, DFLT}, },
    { MULT_PACKED, "7", {CKKSRNS_SCHEME, RING_DIM, 7,     SCALE,  RELIN, BATCH,   OPTIMIZED,  DFLT,  DFLT,   DFLT,    HEStd_NotSet, BV,     FLEXIBLEAUTOEXT, DFLT,    DFLT,  DFLT,   DFLT,      DFLT,       DFLT, DFLT}, },
    { MULT_PACKED, "8", {CKKSRNS_SCHEME, RING_DIM, 7,     SCALE,  RELIN, BATCH,   OPTIMIZED,  DFLT,  DFLT,   DFLT,    HEStd_NotSet, HYBRID, FLEXIBLEAUTOEXT, DFLT,    DFLT,  DFLT,   DFLT,      DFLT,       DFLT, DFLT}, },
#endif
    // ==========================================
    // TestType,               Descr, Scheme,         RDim, MultDepth, SFBits, RWin,  BatchSz, Mode,       Depth, MDepth, ModSize, SecLvl,       KSTech, RSTech,          LDigits, PtMod, StdDev, EvalAddCt, EvalMultCt, KSCt, MultTech
    { SCALE_FACTOR_ADJUSTMENTS, "1", {CKKSRNS_SCHEME, RING_DIM, 7,     SCALE,  RELIN, BATCH,   OPTIMIZED,  DFLT,  DFLT,   DFLT,    HEStd_NotSet, BV,     FIXEDAUTO,       DFLT,    DFLT,  DFLT,   DFLT,      DFLT,       DFLT, DFLT}, },
    { SCALE_FACTOR_ADJUSTMENTS, "2", {CKKSRNS_SCHEME, RING_DIM, 7,     SCALE,  RELIN, BATCH,   OPTIMIZED,  DFLT,  DFLT,   DFLT,    HEStd_NotSet, HYBRID, FIXEDAUTO,       DFLT,    DFLT,  DFLT,   DFLT,      DFLT,       DFLT, DFLT}, },
#if NATIVEINT != 128
    { SCALE_FACTOR_ADJUSTMENTS, "3", {CKKSRNS_SCHEME, RING_DIM, 7,     SCALE,  RELIN, BATCH,   OPTIMIZED,  DFLT,  DFLT,   DFLT,    HEStd_NotSet, BV,     FLEXIBLEAUTO,    DFLT,    DFLT,  DFLT,   DFLT,      DFLT,       DFLT, DFLT}, },
    { SCALE_FACTOR_ADJUSTMENTS, "4", {CKKSRNS_SCHEME, RING_DIM, 7,     SCALE,  RELIN, BATCH,   OPTIMIZED,  DFLT,  DFLT,   DFLT,    HEStd_NotSet, HYBRID, FLEXIBLEAUTO,    DFLT,    DFLT,  DFLT,   DFLT,      DFLT,       DFLT, DFLT}, },
    { SCALE_FACTOR_ADJUSTMENTS, "5", {CKKSRNS_SCHEME, RING_DIM, 7,     SCALE,  RELIN, BATCH,   OPTIMIZED,  DFLT,  DFLT,   DFLT,    HEStd_NotSet, BV,     FLEXIBLEAUTOEXT, DFLT,    DFLT,  DFLT,   DFLT,      DFLT,       DFLT, DFLT}, },
    { SCALE_FACTOR_ADJUSTMENTS, "6", {CKKSRNS_SCHEME, RING_DIM, 7,     SCALE,  RELIN, BATCH,   OPTIMIZED,  DFLT,  DFLT,   DFLT,    HEStd_NotSet, HYBRID, FLEXIBLEAUTOEXT, DFLT,    DFLT,  DFLT,   DFLT,      DFLT,       DFLT, DFLT}, },
#endif
    // ==========================================
    // TestType,        Descr, Scheme,         RDim, MultDepth, SFBits, RWin,  BatchSz, Mode,       Depth, MDepth, ModSize, SecLvl,       KSTech, RSTech,          LDigits, PtMod, StdDev, EvalAddCt, EvalMultCt, KSCt, MultTech
    { AUTO_LEVEL_REDUCE, "1", {CKKSRNS_SCHEME, RING_DIM, 7,     SCALE,  RELIN, BATCH,   OPTIMIZED,  DFLT,  DFLT,   DFLT,    HEStd_NotSet, BV,     FIXEDMANUAL,     DFLT,    DFLT,  DFLT,   DFLT,      DFLT,       DFLT, DFLT}, },
    { AUTO_LEVEL_REDUCE, "2", {CKKSRNS_SCHEME, RING_DIM, 7,     SCALE,  RELIN, BATCH,   OPTIMIZED,  DFLT,  DFLT,   DFLT,    HEStd_NotSet, BV,     FIXEDAUTO,       DFLT,    DFLT,  DFLT,   DFLT,      DFLT,       DFLT, DFLT}, },
    { AUTO_LEVEL_REDUCE, "3", {CKKSRNS_SCHEME, RING_DIM, 7,     SCALE,  RELIN, BATCH,   OPTIMIZED,  DFLT,  DFLT,   DFLT,    HEStd_NotSet, HYBRID, FIXEDMANUAL,     DFLT,    DFLT,  DFLT,   DFLT,      DFLT,       DFLT, DFLT}, },
    { AUTO_LEVEL_REDUCE, "4", {CKKSRNS_SCHEME, RING_DIM, 7,     SCALE,  RELIN, BATCH,   OPTIMIZED,  DFLT,  DFLT,   DFLT,    HEStd_NotSet, HYBRID, FIXEDAUTO,       DFLT,    DFLT,  DFLT,   DFLT,      DFLT,       DFLT, DFLT}, },
#if NATIVEINT != 128
    { AUTO_LEVEL_REDUCE, "5", {CKKSRNS_SCHEME, RING_DIM, 7,     SCALE,  RELIN, BATCH,   OPTIMIZED,  DFLT,  DFLT,   DFLT,    HEStd_NotSet, BV,     FLEXIBLEAUTO,    DFLT,    DFLT,  DFLT,   DFLT,      DFLT,       DFLT, DFLT}, },
    { AUTO_LEVEL_REDUCE, "6", {CKKSRNS_SCHEME, RING_DIM, 7,     SCALE,  RELIN, BATCH,   OPTIMIZED,  DFLT,  DFLT,   DFLT,    HEStd_NotSet, HYBRID, FLEXIBLEAUTO,    DFLT,    DFLT,  DFLT,   DFLT,      DFLT,       DFLT, DFLT}, },
    { AUTO_LEVEL_REDUCE, "7", {CKKSRNS_SCHEME, RING_DIM, 7,     SCALE,  RELIN, BATCH,   OPTIMIZED,  DFLT,  DFLT,   DFLT,    HEStd_NotSet, BV,     FLEXIBLEAUTOEXT, DFLT,    DFLT,  DFLT,   DFLT,      DFLT,       DFLT, DFLT}, },
    { AUTO_LEVEL_REDUCE, "8", {CKKSRNS_SCHEME, RING_DIM, 7,     SCALE,  RELIN, BATCH,   OPTIMIZED,  DFLT,  DFLT,   DFLT,    HEStd_NotSet, HYBRID, FLEXIBLEAUTOEXT, DFLT,    DFLT,  DFLT,   DFLT,      DFLT,       DFLT, DFLT}, },
#endif
    // ==========================================
    // TestType, Descr, Scheme,         RDim, MultDepth, SFBits, RWin,  BatchSz, Mode,       Depth, MDepth, ModSize, SecLvl,       KSTech, RSTech,          LDigits, PtMod, StdDev, EvalAddCt, EvalMultCt, KSCt, MultTech
    { COMPRESS,   "1", {CKKSRNS_SCHEME, RING_DIM, 7,     SCALE,  RELIN, BATCH,   OPTIMIZED,  DFLT,  DFLT,   DFLT,    HEStd_NotSet, BV,     FIXEDMANUAL,     DFLT,    DFLT,  DFLT,   DFLT,      DFLT,       DFLT, DFLT}, },
    { COMPRESS,   "2", {CKKSRNS_SCHEME, RING_DIM, 7,     SCALE,  RELIN, BATCH,   OPTIMIZED,  DFLT,  DFLT,   DFLT,    HEStd_NotSet, BV,     FIXEDAUTO,       DFLT,    DFLT,  DFLT,   DFLT,      DFLT,       DFLT, DFLT}, },
    { COMPRESS,   "3", {CKKSRNS_SCHEME, RING_DIM, 7,     SCALE,  RELIN, BATCH,   OPTIMIZED,  DFLT,  DFLT,   DFLT,    HEStd_NotSet, HYBRID, FIXEDMANUAL,     DFLT,    DFLT,  DFLT,   DFLT,      DFLT,       DFLT, DFLT}, },
    { COMPRESS,   "4", {CKKSRNS_SCHEME, RING_DIM, 7,     SCALE,  RELIN, BATCH,   OPTIMIZED,  DFLT,  DFLT,   DFLT,    HEStd_NotSet, HYBRID, FIXEDAUTO,       DFLT,    DFLT,  DFLT,   DFLT,      DFLT,       DFLT, DFLT}, },
#if NATIVEINT != 128
    { COMPRESS,   "5", {CKKSRNS_SCHEME, RING_DIM, 7,     SCALE,  RELIN, BATCH,   OPTIMIZED,  DFLT,  DFLT,   DFLT,    HEStd_NotSet, BV,     FLEXIBLEAUTO,    DFLT,    DFLT,  DFLT,   DFLT,      DFLT,       DFLT, DFLT}, },
    { COMPRESS,   "6", {CKKSRNS_SCHEME, RING_DIM, 7,     SCALE,  RELIN, BATCH,   OPTIMIZED,  DFLT,  DFLT,   DFLT,    HEStd_NotSet, HYBRID, FLEXIBLEAUTO,    DFLT,    DFLT,  DFLT,   DFLT,      DFLT,       DFLT, DFLT}, },
    { COMPRESS,   "7", {CKKSRNS_SCHEME, RING_DIM, 7,     SCALE,  RELIN, BATCH,   OPTIMIZED,  DFLT,  DFLT,   DFLT,    HEStd_NotSet, BV,     FLEXIBLEAUTOEXT, DFLT,    DFLT,  DFLT,   DFLT,      DFLT,       DFLT, DFLT}, },
    { COMPRESS,   "8", {CKKSRNS_SCHEME, RING_DIM, 7,     SCALE,  RELIN, BATCH,   OPTIMIZED,  DFLT,  DFLT,   DFLT,    HEStd_NotSet, HYBRID, FLEXIBLEAUTOEXT, DFLT,    DFLT,  DFLT,   DFLT,      DFLT,       DFLT, DFLT}, },
#endif
    // ==========================================
    // TestType,         Descr, Scheme,         RDim, MultDepth, SFBits, RWin,  BatchSz, Mode,       Depth, MDepth, ModSize, SecLvl,       KSTech, RSTech,          LDigits, PtMod, StdDev, EvalAddCt, EvalMultCt, KSCt, MultTech
    { EVAL_FAST_ROTATION, "1", {CKKSRNS_SCHEME, RING_DIM, 7,     SCALE,  RELIN, BATCH,   OPTIMIZED,  DFLT,  DFLT,   DFLT,    HEStd_NotSet, BV,     FIXEDMANUAL,     DFLT,    DFLT,  DFLT,   DFLT,      DFLT,       DFLT, DFLT}, },
    { EVAL_FAST_ROTATION, "2", {CKKSRNS_SCHEME, RING_DIM, 7,     SCALE,  RELIN, BATCH,   OPTIMIZED,  DFLT,  DFLT,   DFLT,    HEStd_NotSet, BV,     FIXEDAUTO,       DFLT,    DFLT,  DFLT,   DFLT,      DFLT,       DFLT, DFLT}, },
    { EVAL_FAST_ROTATION, "3", {CKKSRNS_SCHEME, RING_DIM, 7,     SCALE,  RELIN, BATCH,   OPTIMIZED,  DFLT,  DFLT,   DFLT,    HEStd_NotSet, HYBRID, FIXEDMANUAL,     DFLT,    DFLT,  DFLT,   DFLT,      DFLT,       DFLT, DFLT}, },
    { EVAL_FAST_ROTATION, "4", {CKKSRNS_SCHEME, RING_DIM, 7,     SCALE,  RELIN, BATCH,   OPTIMIZED,  DFLT,  DFLT,   DFLT,    HEStd_NotSet, HYBRID, FIXEDAUTO,       DFLT,    DFLT,  DFLT,   DFLT,      DFLT,       DFLT, DFLT}, },
#if NATIVEINT != 128
    { EVAL_FAST_ROTATION, "5", {CKKSRNS_SCHEME, RING_DIM, 7,     SCALE,  RELIN, BATCH,   OPTIMIZED,  DFLT,  DFLT,   DFLT,    HEStd_NotSet, BV,     FLEXIBLEAUTO,    DFLT,    DFLT,  DFLT,   DFLT,      DFLT,       DFLT, DFLT}, },
    { EVAL_FAST_ROTATION, "6", {CKKSRNS_SCHEME, RING_DIM, 7,     SCALE,  RELIN, BATCH,   OPTIMIZED,  DFLT,  DFLT,   DFLT,    HEStd_NotSet, HYBRID, FLEXIBLEAUTO,    DFLT,    DFLT,  DFLT,   DFLT,      DFLT,       DFLT, DFLT}, },
    { EVAL_FAST_ROTATION, "7", {CKKSRNS_SCHEME, RING_DIM, 7,     SCALE,  RELIN, BATCH,   OPTIMIZED,  DFLT,  DFLT,   DFLT,    HEStd_NotSet, BV,     FLEXIBLEAUTOEXT, DFLT,    DFLT,  DFLT,   DFLT,      DFLT,       DFLT, DFLT}, },
    { EVAL_FAST_ROTATION, "8", {CKKSRNS_SCHEME, RING_DIM, 7,     SCALE,  RELIN, BATCH,   OPTIMIZED,  DFLT,  DFLT,   DFLT,    HEStd_NotSet, HYBRID, FLEXIBLEAUTOEXT, DFLT,    DFLT,  DFLT,   DFLT,      DFLT,       DFLT, DFLT}, },
#endif
    // ==========================================
    // TestType,  Descr, Scheme,         RDim, MultDepth, SFBits, RWin,  BatchSz, Mode,       Depth, MDepth, ModSize, SecLvl,       KSTech, RSTech,          LDigits, PtMod, StdDev, EvalAddCt, EvalMultCt, KSCt, MultTech
    { EVALATINDEX, "1", {CKKSRNS_SCHEME, RING_DIM, 7,     SCALE,  RELIN, BATCH,   OPTIMIZED,  DFLT,  DFLT,   DFLT,    HEStd_NotSet, BV,     FIXEDMANUAL,     DFLT,    DFLT,  DFLT,   DFLT,      DFLT,       DFLT, DFLT}, },
    { EVALATINDEX, "2", {CKKSRNS_SCHEME, RING_DIM, 7,     SCALE,  RELIN, BATCH,   OPTIMIZED,  DFLT,  DFLT,   DFLT,    HEStd_NotSet, BV,     FIXEDAUTO,       DFLT,    DFLT,  DFLT,   DFLT,      DFLT,       DFLT, DFLT}, },
    { EVALATINDEX, "3", {CKKSRNS_SCHEME, RING_DIM, 7,     SCALE,  RELIN, BATCH,   OPTIMIZED,  DFLT,  DFLT,   DFLT,    HEStd_NotSet, HYBRID, FIXEDMANUAL,     DFLT,    DFLT,  DFLT,   DFLT,      DFLT,       DFLT, DFLT}, },
    { EVALATINDEX, "4", {CKKSRNS_SCHEME, RING_DIM, 7,     SCALE,  RELIN, BATCH,   OPTIMIZED,  DFLT,  DFLT,   DFLT,    HEStd_NotSet, HYBRID, FIXEDAUTO,       DFLT,    DFLT,  DFLT,   DFLT,      DFLT,       DFLT, DFLT}, },
#if NATIVEINT != 128
    { EVALATINDEX, "5", {CKKSRNS_SCHEME, RING_DIM, 7,     SCALE,  RELIN, BATCH,   OPTIMIZED,  DFLT,  DFLT,   DFLT,    HEStd_NotSet, BV,     FLEXIBLEAUTO,    DFLT,    DFLT,  DFLT,   DFLT,      DFLT,       DFLT, DFLT}, },
    { EVALATINDEX, "6", {CKKSRNS_SCHEME, RING_DIM, 7,     SCALE,  RELIN, BATCH,   OPTIMIZED,  DFLT,  DFLT,   DFLT,    HEStd_NotSet, HYBRID, FLEXIBLEAUTO,    DFLT,    DFLT,  DFLT,   DFLT,      DFLT,       DFLT, DFLT}, },
    { EVALATINDEX, "7", {CKKSRNS_SCHEME, RING_DIM, 7,     SCALE,  RELIN, BATCH,   OPTIMIZED,  DFLT,  DFLT,   DFLT,    HEStd_NotSet, BV,     FLEXIBLEAUTOEXT, DFLT,    DFLT,  DFLT,   DFLT,      DFLT,       DFLT, DFLT}, },
    { EVALATINDEX, "8", {CKKSRNS_SCHEME, RING_DIM, 7,     SCALE,  RELIN, BATCH,   OPTIMIZED,  DFLT,  DFLT,   DFLT,    HEStd_NotSet, HYBRID, FLEXIBLEAUTOEXT, DFLT,    DFLT,  DFLT,   DFLT,      DFLT,       DFLT, DFLT}, },
#endif
    // ==========================================
    // TestType, Descr, Scheme,        RDim, MultDepth, SFBits, RWin,  BatchSz, Mode,       Depth, MDepth, ModSize, SecLvl,       KSTech, RSTech,          LDigits, PtMod, StdDev, EvalAddCt, EvalMultCt, KSCt, MultTech
    { EVALMERGE, "1", {CKKSRNS_SCHEME, RING_DIM, 7,     SCALE,  RELIN, BATCH,   OPTIMIZED,  DFLT,  DFLT,   DFLT,    HEStd_NotSet, BV,     FIXEDMANUAL,     DFLT,    DFLT,  DFLT,   DFLT,      DFLT,       DFLT, DFLT}, },
    { EVALMERGE, "2", {CKKSRNS_SCHEME, RING_DIM, 7,     SCALE,  RELIN, BATCH,   OPTIMIZED,  DFLT,  DFLT,   DFLT,    HEStd_NotSet, BV,     FIXEDAUTO,       DFLT,    DFLT,  DFLT,   DFLT,      DFLT,       DFLT, DFLT}, },
    { EVALMERGE, "3", {CKKSRNS_SCHEME, RING_DIM, 7,     SCALE,  RELIN, BATCH,   OPTIMIZED,  DFLT,  DFLT,   DFLT,    HEStd_NotSet, HYBRID, FIXEDMANUAL,     DFLT,    DFLT,  DFLT,   DFLT,      DFLT,       DFLT, DFLT}, },
    { EVALMERGE, "4", {CKKSRNS_SCHEME, RING_DIM, 7,     SCALE,  RELIN, BATCH,   OPTIMIZED,  DFLT,  DFLT,   DFLT,    HEStd_NotSet, HYBRID, FIXEDAUTO,       DFLT,    DFLT,  DFLT,   DFLT,      DFLT,       DFLT, DFLT}, },
#if NATIVEINT != 128
    { EVALMERGE, "5", {CKKSRNS_SCHEME, RING_DIM, 7,     SCALE,  RELIN, BATCH,   OPTIMIZED,  DFLT,  DFLT,   DFLT,    HEStd_NotSet, BV,     FLEXIBLEAUTO,    DFLT,    DFLT,  DFLT,   DFLT,      DFLT,       DFLT, DFLT}, },
    { EVALMERGE, "6", {CKKSRNS_SCHEME, RING_DIM, 7,     SCALE,  RELIN, BATCH,   OPTIMIZED,  DFLT,  DFLT,   DFLT,    HEStd_NotSet, HYBRID, FLEXIBLEAUTO,    DFLT,    DFLT,  DFLT,   DFLT,      DFLT,       DFLT, DFLT}, },
    { EVALMERGE, "7", {CKKSRNS_SCHEME, RING_DIM, 7,     SCALE,  RELIN, BATCH,   OPTIMIZED,  DFLT,  DFLT,   DFLT,    HEStd_NotSet, BV,     FLEXIBLEAUTOEXT, DFLT,    DFLT,  DFLT,   DFLT,      DFLT,       DFLT, DFLT}, },
    { EVALMERGE, "8", {CKKSRNS_SCHEME, RING_DIM, 7,     SCALE,  RELIN, BATCH,   OPTIMIZED,  DFLT,  DFLT,   DFLT,    HEStd_NotSet, HYBRID, FLEXIBLEAUTOEXT, DFLT,    DFLT,  DFLT,   DFLT,      DFLT,       DFLT, DFLT}, },
#endif
    // ==========================================
    // TestType,       Descr, Scheme,         RDim, MultDepth, SFBits, RWin,  BatchSz, Mode,       Depth, MDepth, ModSize, SecLvl,       KSTech, RSTech,          LDigits, PtMod, StdDev, EvalAddCt, EvalMultCt, KSCt, MultTech
    { EVAL_LINEAR_WSUM, "1", {CKKSRNS_SCHEME, RING_DIM, 7,     SCALE,  RELIN, BATCH,   OPTIMIZED,  DFLT,  DFLT,   DFLT,    HEStd_NotSet, BV,     FIXEDMANUAL,     DFLT,    DFLT,  DFLT,   DFLT,      DFLT,       DFLT, DFLT}, },
    { EVAL_LINEAR_WSUM, "2", {CKKSRNS_SCHEME, RING_DIM, 7,     SCALE,  RELIN, BATCH,   OPTIMIZED,  DFLT,  DFLT,   DFLT,    HEStd_NotSet, BV,     FIXEDAUTO,       DFLT,    DFLT,  DFLT,   DFLT,      DFLT,       DFLT, DFLT}, },
    { EVAL_LINEAR_WSUM, "3", {CKKSRNS_SCHEME, RING_DIM, 7,     SCALE,  RELIN, BATCH,   OPTIMIZED,  DFLT,  DFLT,   DFLT,    HEStd_NotSet, HYBRID, FIXEDMANUAL,     DFLT,    DFLT,  DFLT,   DFLT,      DFLT,       DFLT, DFLT}, },
    { EVAL_LINEAR_WSUM, "4", {CKKSRNS_SCHEME, RING_DIM, 7,     SCALE,  RELIN, BATCH,   OPTIMIZED,  DFLT,  DFLT,   DFLT,    HEStd_NotSet, HYBRID, FIXEDAUTO,       DFLT,    DFLT,  DFLT,   DFLT,      DFLT,       DFLT, DFLT}, },
#if NATIVEINT != 128
    { EVAL_LINEAR_WSUM, "5", {CKKSRNS_SCHEME, RING_DIM, 7,     SCALE,  RELIN, BATCH,   OPTIMIZED,  DFLT,  DFLT,   DFLT,    HEStd_NotSet, BV,     FLEXIBLEAUTO,    DFLT,    DFLT,  DFLT,   DFLT,      DFLT,       DFLT, DFLT}, },
    { EVAL_LINEAR_WSUM, "6", {CKKSRNS_SCHEME, RING_DIM, 7,     SCALE,  RELIN, BATCH,   OPTIMIZED,  DFLT,  DFLT,   DFLT,    HEStd_NotSet, HYBRID, FLEXIBLEAUTO,    DFLT,    DFLT,  DFLT,   DFLT,      DFLT,       DFLT, DFLT}, },
    { EVAL_LINEAR_WSUM, "7", {CKKSRNS_SCHEME, RING_DIM, 7,     SCALE,  RELIN, BATCH,   OPTIMIZED,  DFLT,  DFLT,   DFLT,    HEStd_NotSet, BV,     FLEXIBLEAUTOEXT, DFLT,    DFLT,  DFLT,   DFLT,      DFLT,       DFLT, DFLT}, },
    { EVAL_LINEAR_WSUM, "8", {CKKSRNS_SCHEME, RING_DIM, 7,     SCALE,  RELIN, BATCH,   OPTIMIZED,  DFLT,  DFLT,   DFLT,    HEStd_NotSet, HYBRID, FLEXIBLEAUTOEXT, DFLT,    DFLT,  DFLT,   DFLT,      DFLT,       DFLT, DFLT}, },
#endif
    // ==========================================
    // TestType,     Descr, Scheme,        RDim, MultDepth, SFBits, RWin,  BatchSz, Mode,       Depth, MDepth, ModSize, SecLvl,       KSTech, RSTech,          LDigits, PtMod, StdDev, EvalAddCt, EvalMultCt, KSCt, MultTech
    { RE_ENCRYPTION, "1", {CKKSRNS_SCHEME, RING_DIM, 7,     SCALE,  RELIN, BATCH,   OPTIMIZED,  DFLT,  DFLT,   DFLT,    HEStd_NotSet, BV,     FIXEDMANUAL,     DFLT,    DFLT,  DFLT,   DFLT,      DFLT,       DFLT, DFLT}, },
    { RE_ENCRYPTION, "2", {CKKSRNS_SCHEME, RING_DIM, 7,     SCALE,  RELIN, BATCH,   OPTIMIZED,  DFLT,  DFLT,   DFLT,    HEStd_NotSet, HYBRID, FIXEDMANUAL,     DFLT,    DFLT,  DFLT,   DFLT,      DFLT,       DFLT, DFLT}, },
    { RE_ENCRYPTION, "3", {CKKSRNS_SCHEME, RING_DIM, 7,     SCALE,  RELIN, BATCH,   OPTIMIZED,  DFLT,  DFLT,   DFLT,    HEStd_NotSet, BV,     FIXEDAUTO,       DFLT,    DFLT,  DFLT,   DFLT,      DFLT,       DFLT, DFLT}, },
    { RE_ENCRYPTION, "4", {CKKSRNS_SCHEME, RING_DIM, 7,     SCALE,  RELIN, BATCH,   OPTIMIZED,  DFLT,  DFLT,   DFLT,    HEStd_NotSet, HYBRID, FIXEDAUTO,       DFLT,    DFLT,  DFLT,   DFLT,      DFLT,       DFLT, DFLT}, },
#if NATIVEINT != 128
    { RE_ENCRYPTION, "5", {CKKSRNS_SCHEME, RING_DIM, 7,     SCALE,  RELIN, BATCH,   OPTIMIZED,  DFLT,  DFLT,   DFLT,    HEStd_NotSet, BV,     FLEXIBLEAUTO,    DFLT,    DFLT,  DFLT,   DFLT,      DFLT,       DFLT, DFLT}, },
    { RE_ENCRYPTION, "6", {CKKSRNS_SCHEME, RING_DIM, 7,     SCALE,  RELIN, BATCH,   OPTIMIZED,  DFLT,  DFLT,   DFLT,    HEStd_NotSet, HYBRID, FLEXIBLEAUTO,    DFLT,    DFLT,  DFLT,   DFLT,      DFLT,       DFLT, DFLT}, },
    { RE_ENCRYPTION, "7", {CKKSRNS_SCHEME, RING_DIM, 7,     SCALE,  RELIN, BATCH,   OPTIMIZED,  DFLT,  DFLT,   DFLT,    HEStd_NotSet, BV,     FLEXIBLEAUTOEXT, DFLT,    DFLT,  DFLT,   DFLT,      DFLT,       DFLT, DFLT}, },
    { RE_ENCRYPTION, "8", {CKKSRNS_SCHEME, RING_DIM, 7,     SCALE,  RELIN, BATCH,   OPTIMIZED,  DFLT,  DFLT,   DFLT,    HEStd_NotSet, HYBRID, FLEXIBLEAUTOEXT, DFLT,    DFLT,  DFLT,   DFLT,      DFLT,       DFLT, DFLT}, },
#endif
    // ==========================================
    // TestType, Descr, Scheme,        RDim, MultDepth, SFBits, RWin,  BatchSz, Mode,       Depth, MDepth, ModSize, SecLvl,       KSTech, RSTech,          LDigits, PtMod, StdDev, EvalAddCt, EvalMultCt, KSCt, MultTech
    { EVAL_POLY, "1", {CKKSRNS_SCHEME, RING_DIM, 5,     SCALE,  RELIN, BATCH,   OPTIMIZED,  DFLT,  DFLT,   DFLT,    HEStd_NotSet, BV,     FIXEDMANUAL,     DFLT,    DFLT,  DFLT,   DFLT,      DFLT,       DFLT, DFLT}, },
    { EVAL_POLY, "2", {CKKSRNS_SCHEME, RING_DIM, 5,     SCALE,  RELIN, BATCH,   OPTIMIZED,  DFLT,  DFLT,   DFLT,    HEStd_NotSet, BV,     FIXEDAUTO,       DFLT,    DFLT,  DFLT,   DFLT,      DFLT,       DFLT, DFLT}, },
    { EVAL_POLY, "3", {CKKSRNS_SCHEME, RING_DIM, 5,     SCALE,  RELIN, BATCH,   OPTIMIZED,  DFLT,  DFLT,   DFLT,    HEStd_NotSet, HYBRID, FIXEDMANUAL,     DFLT,    DFLT,  DFLT,   DFLT,      DFLT,       DFLT, DFLT}, },
    { EVAL_POLY, "4", {CKKSRNS_SCHEME, RING_DIM, 5,     SCALE,  RELIN, BATCH,   OPTIMIZED,  DFLT,  DFLT,   DFLT,    HEStd_NotSet, HYBRID, FIXEDAUTO,       DFLT,    DFLT,  DFLT,   DFLT,      DFLT,       DFLT, DFLT}, },
#if NATIVEINT != 128
    { EVAL_POLY, "5", {CKKSRNS_SCHEME, RING_DIM, 5,     SCALE,  RELIN, BATCH,   OPTIMIZED,  DFLT,  DFLT,   DFLT,    HEStd_NotSet, BV,     FLEXIBLEAUTO,    DFLT,    DFLT,  DFLT,   DFLT,      DFLT,       DFLT, DFLT}, },
    { EVAL_POLY, "6", {CKKSRNS_SCHEME, RING_DIM, 5,     SCALE,  RELIN, BATCH,   OPTIMIZED,  DFLT,  DFLT,   DFLT,    HEStd_NotSet, HYBRID, FLEXIBLEAUTO,    DFLT,    DFLT,  DFLT,   DFLT,      DFLT,       DFLT, DFLT}, },
    { EVAL_POLY, "7", {CKKSRNS_SCHEME, RING_DIM, 7,     SCALE,  RELIN, BATCH,   OPTIMIZED,  DFLT,  DFLT,   DFLT,    HEStd_NotSet, BV,     FLEXIBLEAUTOEXT, DFLT,    DFLT,  DFLT,   DFLT,      DFLT,       DFLT, DFLT}, },
    { EVAL_POLY, "8", {CKKSRNS_SCHEME, RING_DIM, 7,     SCALE,  RELIN, BATCH,   OPTIMIZED,  DFLT,  DFLT,   DFLT,    HEStd_NotSet, HYBRID, FLEXIBLEAUTOEXT, DFLT,    DFLT,  DFLT,   DFLT,      DFLT,       DFLT, DFLT}, },
#endif
    // ==========================================
    // TestType, Descr, Scheme,       RDim, MultDepth, SFBits, RWin,  BatchSz, Mode,       Depth, MDepth, ModSize, SecLvl,       KSTech, RSTech,          LDigits, PtMod, StdDev, EvalAddCt, EvalMultCt, KSCt, MultTech
    { METADATA, "1", {CKKSRNS_SCHEME, RING_DIM, 7,     SCALE,  RELIN, BATCH,   OPTIMIZED,  DFLT,  DFLT,   DFLT,    HEStd_NotSet, BV,     FIXEDMANUAL,     DFLT,    DFLT,  DFLT,   DFLT,      DFLT,       DFLT, DFLT}, },
    { METADATA, "2", {CKKSRNS_SCHEME, RING_DIM, 7,     SCALE,  RELIN, BATCH,   OPTIMIZED,  DFLT,  DFLT,   DFLT,    HEStd_NotSet, BV,     FIXEDAUTO,       DFLT,    DFLT,  DFLT,   DFLT,      DFLT,       DFLT, DFLT}, },
    { METADATA, "3", {CKKSRNS_SCHEME, RING_DIM, 7,     SCALE,  RELIN, BATCH,   OPTIMIZED,  DFLT,  DFLT,   DFLT,    HEStd_NotSet, HYBRID, FIXEDMANUAL,     DFLT,    DFLT,  DFLT,   DFLT,      DFLT,       DFLT, DFLT}, },
    { METADATA, "4", {CKKSRNS_SCHEME, RING_DIM, 7,     SCALE,  RELIN, BATCH,   OPTIMIZED,  DFLT,  DFLT,   DFLT,    HEStd_NotSet, HYBRID, FIXEDAUTO,       DFLT,    DFLT,  DFLT,   DFLT,      DFLT,       DFLT, DFLT}, },
#if NATIVEINT != 128
    { METADATA, "5", {CKKSRNS_SCHEME, RING_DIM, 7,     SCALE,  RELIN, BATCH,   OPTIMIZED,  DFLT,  DFLT,   DFLT,    HEStd_NotSet, BV,     FLEXIBLEAUTO,    DFLT,    DFLT,  DFLT,   DFLT,      DFLT,       DFLT, DFLT}, },
    { METADATA, "6", {CKKSRNS_SCHEME, RING_DIM, 7,     SCALE,  RELIN, BATCH,   OPTIMIZED,  DFLT,  DFLT,   DFLT,    HEStd_NotSet, HYBRID, FLEXIBLEAUTO,    DFLT,    DFLT,  DFLT,   DFLT,      DFLT,       DFLT, DFLT}, },
    { METADATA, "7", {CKKSRNS_SCHEME, RING_DIM, 7,     SCALE,  RELIN, BATCH,   OPTIMIZED,  DFLT,  DFLT,   DFLT,    HEStd_NotSet, BV,     FLEXIBLEAUTOEXT, DFLT,    DFLT,  DFLT,   DFLT,      DFLT,       DFLT, DFLT}, },
    { METADATA, "8", {CKKSRNS_SCHEME, RING_DIM, 7,     SCALE,  RELIN, BATCH,   OPTIMIZED,  DFLT,  DFLT,   DFLT,    HEStd_NotSet, HYBRID, FLEXIBLEAUTOEXT, DFLT,    DFLT,  DFLT,   DFLT,      DFLT,       DFLT, DFLT}, },
#endif
    // ==========================================
};
// clang-format on
//===========================================================================================================

class UTCKKSRNS : public ::testing::TestWithParam<TEST_CASE_UTCKKSRNS> {
    using Element = DCRTPoly;

    // the size for all vectors remains const - 8 elements
    const usint VECTOR_SIZE = 8;

    // The precision after which we consider two values equal.
    // This is necessary because CKKS works for approximate numbers.
    const double eps = EPSILON;

    const double epsHigh = 0.00001;

    const std::vector<std::complex<double>> vectorOfInts0_7{ 0, 1, 2, 3, 4, 5, 6, 7 };
    const std::vector<std::complex<double>> vectorOfInts0_7neg{ 0,-1,-2,-3,-4,-5,-6,-7 };
    const std::vector<std::complex<double>> vectorOfInts7_0{ 7, 6, 5, 4, 3, 2, 1, 0 };

    const std::vector<std::complex<double>> vectorOfInts1_8{ 1, 2, 3, 4, 5, 6, 7, 8 };
    const std::vector<std::complex<double>> vectorOfInts1_8neg{ -1,-2,-3,-4,-5,-6,-7,-8 };
    const std::vector<std::complex<double>> vectorOfInts8_1{ 8, 7, 6, 5, 4, 3, 2, 1 };

    const std::vector<std::complex<double>> vectorOfInts1s{1, 1, 1, 1, 1, 1, 1, 1}; // all 1's

protected:
    void SetUp() {}

    void TearDown() {
        CryptoContextFactory<DCRTPoly>::ReleaseAllContexts();
    }

    void UnitTest_Add_Packed(const TEST_CASE_UTCKKSRNS& testData, const std::string& failmsg = std::string()) {
        try {
            CryptoContext<Element> cc(UnitTestGenerateContext(testData.params));

            Plaintext plaintext1 = cc->MakeCKKSPackedPlaintext(vectorOfInts0_7);
            Plaintext negatives1 = cc->MakeCKKSPackedPlaintext(vectorOfInts0_7neg);
            Plaintext plaintext2 = cc->MakeCKKSPackedPlaintext(vectorOfInts7_0);

            Plaintext plaintextAdd = cc->MakeCKKSPackedPlaintext(std::vector<std::complex<double>>(VECTOR_SIZE, 7)); // vector of 7s
            Plaintext plaintextSub = cc->MakeCKKSPackedPlaintext(std::vector<std::complex<double>>{ -7, -5, -3, -1, 1, 3, 5, 7 });

            // Generate encryption keys
            KeyPair<Element> kp = cc->KeyGen();

            // Encrypt plaintexts
            Ciphertext<Element> ciphertext1 = cc->Encrypt(kp.publicKey, plaintext1);
            Ciphertext<Element> ciphertext1_mutable = cc->Encrypt(kp.publicKey, plaintext1);
            Ciphertext<Element> ciphertext2 = cc->Encrypt(kp.publicKey, plaintext2);

            // Testing EvalAdd
            Plaintext results;
            Ciphertext<Element> cResult;

            cResult = cc->EvalAdd(ciphertext1, ciphertext2);
            cc->Decrypt(kp.secretKey, cResult, &results);
            results->SetLength(plaintextAdd->GetLength());
            checkEquality(plaintextAdd->GetCKKSPackedValue(), results->GetCKKSPackedValue(), eps,
                failmsg + " EvalAdd fails");

            // Testing EvalAddInPlace
            cc->EvalAddInPlace(ciphertext1_mutable, ciphertext2);
            cc->Decrypt(kp.secretKey, ciphertext1_mutable, &results);
            results->SetLength(plaintextAdd->GetLength());
            checkEquality(plaintextAdd->GetCKKSPackedValue(), results->GetCKKSPackedValue(), eps,
                failmsg + " EvalAddInPlace fails");

            // Testing operator+
            cResult = ciphertext1 + ciphertext2;
            cc->Decrypt(kp.secretKey, cResult, &results);
            results->SetLength(plaintextAdd->GetLength());
            checkEquality(plaintextAdd->GetCKKSPackedValue(), results->GetCKKSPackedValue(), eps,
                failmsg + " operator+ fails");

            // Testing operator+=
            Ciphertext<Element> caddInplace(ciphertext1);
            caddInplace += ciphertext2;
            cc->Decrypt(kp.secretKey, caddInplace, &results);
            results->SetLength(plaintextAdd->GetLength());
            checkEquality(plaintextAdd->GetCKKSPackedValue(), results->GetCKKSPackedValue(), eps,
                failmsg + " operator+= fails");

            // Testing EvalSub
            cResult = cc->EvalSub(ciphertext1, ciphertext2);
            cc->Decrypt(kp.secretKey, cResult, &results);
            results->SetLength(plaintextSub->GetLength());
            checkEquality(plaintextSub->GetCKKSPackedValue(), results->GetCKKSPackedValue(), eps,
                failmsg + " EvalSub fails");

            // Testing operator-
            cResult = ciphertext1 - ciphertext2;
            cc->Decrypt(kp.secretKey, cResult, &results);
            results->SetLength(plaintextSub->GetLength());
            checkEquality(plaintextSub->GetCKKSPackedValue(), results->GetCKKSPackedValue(), eps,
                failmsg + " operator- fails");

            // Testing operator-=
            Ciphertext<Element> csubInplace(ciphertext1);
            csubInplace -= ciphertext2;
            cc->Decrypt(kp.secretKey, csubInplace, &results);
            results->SetLength(plaintextSub->GetLength());
            checkEquality(plaintextSub->GetCKKSPackedValue(), results->GetCKKSPackedValue(), eps,
                failmsg + " operator-= fails");

            // Testing EvalAdd ciphertext + plaintext
            cResult = cc->EvalAdd(ciphertext1, plaintext2);
            cc->Decrypt(kp.secretKey, cResult, &results);
            results->SetLength(plaintextAdd->GetLength());
            checkEquality(plaintextAdd->GetCKKSPackedValue(), results->GetCKKSPackedValue(), eps,
                failmsg + " EvalAdd Ct and Pt fails");

            // Testing EvalSub ciphertext - plaintext
            cResult = cc->EvalSub(ciphertext1, plaintext2);
            cc->Decrypt(kp.secretKey, cResult, &results);
            results->SetLength(plaintextSub->GetLength());
            checkEquality(plaintextSub->GetCKKSPackedValue(), results->GetCKKSPackedValue(), eps,
                failmsg + " EvalSub Ct and Pt fails fails");

            // Testing EvalNegate
            cResult = cc->EvalNegate(ciphertext1);
            cc->Decrypt(kp.secretKey, cResult, &results);
            results->SetLength(negatives1->GetLength());
            checkEquality(negatives1->GetCKKSPackedValue(), results->GetCKKSPackedValue(), eps,
                failmsg + " EvalNegate fails");
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

    void UnitTest_Mult_Packed(const TEST_CASE_UTCKKSRNS& testData, const std::string& failmsg = std::string()) {
        try {
            CryptoContext<Element> cc(UnitTestGenerateContext(testData.params));

            Plaintext plaintext1 = cc->MakeCKKSPackedPlaintext(vectorOfInts0_7);
            Plaintext plaintext2 = cc->MakeCKKSPackedPlaintext(vectorOfInts7_0);
            Plaintext plaintextMult =
                cc->MakeCKKSPackedPlaintext(std::vector<std::complex<double>>({ 0, 6,10,12,12,10, 6, 0 }));

            // Generate encryption keys
            KeyPair<Element> kp = cc->KeyGen();
            // Generate multiplication keys
            cc->EvalMultKeyGen(kp.secretKey);

            // Encrypt plaintexts
            Ciphertext<Element> ciphertext1 = cc->Encrypt(kp.publicKey, plaintext1);
            Ciphertext<Element> ciphertext2 = cc->Encrypt(kp.publicKey, plaintext2);

            // Testing EvalMult
            Ciphertext<Element> cResult;
            Plaintext results;
            cc->EvalMult(ciphertext1, plaintext1);
            cc->EvalMult(ciphertext2, plaintext2);
            cResult = cc->EvalMult(ciphertext1, ciphertext2);
            cc->Decrypt(kp.secretKey, cResult, &results);
            results->SetLength(plaintextMult->GetLength());
            checkEquality(plaintextMult->GetCKKSPackedValue(), results->GetCKKSPackedValue(), eps,
                failmsg + " EvalMult fails");

            // Testing operator*
            cResult = ciphertext1 * ciphertext2;
            cc->Decrypt(kp.secretKey, cResult, &results);
            results->SetLength(plaintextMult->GetLength());
            checkEquality(plaintextMult->GetCKKSPackedValue(), results->GetCKKSPackedValue(), eps,
                failmsg + " operator* fails");

            // Testing operator*=
            Ciphertext<Element> cmultInplace(ciphertext1);
            cmultInplace *= ciphertext2;
            cc->Decrypt(kp.secretKey, cmultInplace, &results);
            results->SetLength(plaintextMult->GetLength());
            checkEquality(plaintextMult->GetCKKSPackedValue(), results->GetCKKSPackedValue(), eps,
                failmsg + " operator*= fails");

            // Testing EvalMult ciphertext * plaintext
            cResult = cc->EvalMult(ciphertext1, plaintext2);
            cc->Decrypt(kp.secretKey, cResult, &results);
            results->SetLength(plaintextMult->GetLength());
            checkEquality(plaintextMult->GetCKKSPackedValue(), results->GetCKKSPackedValue(), eps,
                failmsg + " EvalMult Ct and Pt fails");

            // Testing EvalMultNoRelin ciphertext * ciphertext
            cResult = cc->EvalMultNoRelin(ciphertext1, ciphertext2);
            cc->Decrypt(kp.secretKey, cResult, &results);
            results->SetLength(plaintextMult->GetLength());
            checkEquality(plaintextMult->GetCKKSPackedValue(), results->GetCKKSPackedValue(), eps,
                failmsg + " EvalMultNoRelin Ct fails");
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

    /**
     * Tests the correct operation of the following:
     * - addition/subtraction of constant to ciphertext of depth > 1
     * - addition/subtraction of plaintext to ciphertext of depth > 1
     * - encoding of plaintext at depth > 1
     * - automatic scaling up of plaintexts to a depth that matches that of a
     * ciphertext
     */
    void UnitTest_ScaleFactorAdjustments(const TEST_CASE_UTCKKSRNS& testData, const std::string& failmsg = std::string()) {
        try {
            CryptoContext<Element> cc(UnitTestGenerateContext(testData.params));

            std::vector<std::complex<double>> vectorOfInts1(vectorOfInts0_7);
            Plaintext plaintext1 = cc->MakeCKKSPackedPlaintext(vectorOfInts1);

            std::vector<std::complex<double>> constantInts(std::vector<std::complex<double>>(VECTOR_SIZE, 11)); // vector of 11s
            Plaintext plaintextConst = cc->MakeCKKSPackedPlaintext(constantInts);
            Plaintext plaintextConstDeep = cc->MakeCKKSPackedPlaintext(constantInts, 3);

            std::vector<std::complex<double>> constantInts2(std::vector<std::complex<double>>(VECTOR_SIZE, -11)); // vector of "-11"s
            Plaintext plaintextConst2 = cc->MakeCKKSPackedPlaintext(constantInts2);
            Plaintext plaintextConst2Deep = cc->MakeCKKSPackedPlaintext(constantInts2, 3);

            Plaintext plaintext2 = cc->MakeCKKSPackedPlaintext(vectorOfInts7_0);
            Plaintext plaintext3 = cc->MakeCKKSPackedPlaintext(vectorOfInts0_7neg);

            std::vector<std::complex<double>> vectorOfIntsMult(VECTOR_SIZE);
            std::vector<std::complex<double>> vectorOfIntsMult2(VECTOR_SIZE);
            std::vector<std::complex<double>> vectorOfIntsAddAfterMult(VECTOR_SIZE);
            std::vector<std::complex<double>> vectorOfIntsSubAfterMult(VECTOR_SIZE);
            std::vector<std::complex<double>> vectorOfIntsAddAfterMult2(VECTOR_SIZE);
            std::vector<std::complex<double>> vectorOfIntsSubAfterMult2(VECTOR_SIZE);
            for (usint i = 0; i < VECTOR_SIZE; i++) {
                vectorOfIntsMult[i] = i * VECTOR_SIZE - i * i - i;
                vectorOfIntsAddAfterMult[i] = vectorOfIntsMult[i] + std::complex<double>(10, 0);
                vectorOfIntsSubAfterMult[i] = vectorOfIntsMult[i] - std::complex<double>(10, 0);
                vectorOfIntsMult2[i] = vectorOfIntsMult[i] * vectorOfInts1[i];
                vectorOfIntsAddAfterMult2[i] = vectorOfIntsMult2[i] + constantInts[i];  // complex<double>({11,0});
                vectorOfIntsSubAfterMult2[i] = vectorOfIntsMult2[i] - constantInts[i];  // complex<double>({11,0});
            }
            // The vector values should be:
            // vectorOfIntsMult = { 0,6,10,12,12,10,6,0 };
            // vectorOfIntsMult2 = { 0,6,20,36,48,50,36,0 };
            // vectorOfIntsAddAfterMult = { 10,16,20,22,22,20,16,10 };
            // vectorOfIntsSubAfterMult = { -10,-4,0,2,2,0,-4,-10 };
            // vectorOfIntsAddAfterMult2 = { 11,17,31,47,59,61,47,11 };
            // vectorOfIntsSubAfterMult2 = { -11,-5,9,25,37,39,25,-11 };
            Plaintext plaintextMult = cc->MakeCKKSPackedPlaintext(vectorOfIntsMult);
            Plaintext plaintexAddAfterMult = cc->MakeCKKSPackedPlaintext(vectorOfIntsAddAfterMult);
            Plaintext plaintexSubAfterMult = cc->MakeCKKSPackedPlaintext(vectorOfIntsSubAfterMult);
            Plaintext plaintexttMult2 = cc->MakeCKKSPackedPlaintext(vectorOfIntsMult2);
            Plaintext plaintexAddAfterMult2 = cc->MakeCKKSPackedPlaintext(vectorOfIntsAddAfterMult2);
            Plaintext plaintexSubAfterMult2 = cc->MakeCKKSPackedPlaintext(vectorOfIntsSubAfterMult2);
            Plaintext plaintex2AddAfterMult2 = cc->MakeCKKSPackedPlaintext(vectorOfIntsSubAfterMult2);
            Plaintext plaintex2SubAfterMult2 = cc->MakeCKKSPackedPlaintext(vectorOfIntsAddAfterMult2);

            // Generate encryption keys
            KeyPair<Element> kp = cc->KeyGen();
            // Generate multiplication keys
            cc->EvalMultKeyGen(kp.secretKey);

            // Encrypt plaintexts
            Ciphertext<Element> ciphertext1 = cc->Encrypt(kp.publicKey, plaintext1);
            Ciphertext<Element> ciphertext2 = cc->Encrypt(kp.publicKey, plaintext2);

            auto cMult = cc->EvalMult(ciphertext1, ciphertext2);
            auto cMultRs = cc->Rescale(cMult);

            auto cAddAfterMult = cc->EvalAdd(cMultRs, 10);
            auto cSubAfterMult = cc->EvalSub(cMultRs, 10);
            auto cMult2 = cc->EvalMult(ciphertext1, cMultRs);
            auto cMultRs2 = cc->Rescale(cMult2);
            auto cAddAfterMult2 = cc->EvalAdd(cMultRs2, 11);
            auto cSubAfterMult2 = cc->EvalSub(cMultRs2, 11);
            auto c2AddAfterMult2 = cc->EvalAdd(cMultRs2, -11);
            auto c2SubAfterMult2 = cc->EvalSub(cMultRs2, -11);
            auto cAddPtAfterMult2 = cc->EvalAdd(cMultRs2, plaintextConst);
            auto cSubPtAfterMult2 = cc->EvalSub(cMultRs2, plaintextConst);
            auto cAddPt2AfterMult2 = cc->EvalAdd(cMultRs2, plaintextConst2);
            auto cSubPt2AfterMult2 = cc->EvalSub(cMultRs2, plaintextConst2);
            auto cDeepAdd = cc->EvalAdd(cMultRs2, plaintextConstDeep);
            auto cDeepSub = cc->EvalSub(cMultRs2, plaintextConstDeep);
            auto c2DeepAdd = cc->EvalAdd(cMultRs2, plaintextConst2Deep);
            auto c2DeepSub = cc->EvalSub(cMultRs2, plaintextConst2Deep);

            Plaintext results;
            cc->Decrypt(kp.secretKey, cAddAfterMult, &results);
            results->SetLength(plaintexAddAfterMult->GetLength());
            checkEquality(plaintexAddAfterMult->GetCKKSPackedValue(), results->GetCKKSPackedValue(), eps,
                failmsg + " add after 1 multiplication fails");

            cc->Decrypt(kp.secretKey, cSubAfterMult, &results);
            results->SetLength(plaintexSubAfterMult->GetLength());
            checkEquality(plaintexSubAfterMult->GetCKKSPackedValue(), results->GetCKKSPackedValue(), eps,
                failmsg + " subtract after 1 multiplication fails");

            cc->Decrypt(kp.secretKey, cAddAfterMult2, &results);
            results->SetLength(plaintexAddAfterMult2->GetLength());
            checkEquality(plaintexAddAfterMult2->GetCKKSPackedValue(), results->GetCKKSPackedValue(), eps,
                failmsg + " add after 2 multiplications fails");

            cc->Decrypt(kp.secretKey, cSubAfterMult2, &results);
            results->SetLength(plaintexSubAfterMult2->GetLength());
            checkEquality(plaintexSubAfterMult2->GetCKKSPackedValue(), results->GetCKKSPackedValue(), eps,
                failmsg + " subtract after 2 multiplications fails");

            cc->Decrypt(kp.secretKey, c2AddAfterMult2, &results);
            results->SetLength(plaintex2AddAfterMult2->GetLength());
            checkEquality(plaintex2AddAfterMult2->GetCKKSPackedValue(), results->GetCKKSPackedValue(), eps,
                failmsg + " add (negative) after 2 multiplications fails");

            cc->Decrypt(kp.secretKey, c2SubAfterMult2, &results);
            results->SetLength(plaintex2SubAfterMult2->GetLength());
            checkEquality(plaintex2SubAfterMult2->GetCKKSPackedValue(), results->GetCKKSPackedValue(), eps,
                failmsg + " subtract (negative) after 2 multiplications fails");

            cc->Decrypt(kp.secretKey, cAddPtAfterMult2, &results);
            results->SetLength(plaintexAddAfterMult2->GetLength());
            checkEquality(plaintexAddAfterMult2->GetCKKSPackedValue(), results->GetCKKSPackedValue(), eps,
                failmsg + " add plaintext (auto scale factor matching) after 2 multiplications fails");

            cc->Decrypt(kp.secretKey, cSubPtAfterMult2, &results);
            results->SetLength(plaintexSubAfterMult2->GetLength());
            checkEquality(plaintexSubAfterMult2->GetCKKSPackedValue(), results->GetCKKSPackedValue(), eps,
                failmsg + " subtract plaintext (auto scale factor matching) after 2 multiplications fails");

            cc->Decrypt(kp.secretKey, cAddPt2AfterMult2, &results);
            results->SetLength(plaintex2AddAfterMult2->GetLength());
            checkEquality(plaintex2AddAfterMult2->GetCKKSPackedValue(), results->GetCKKSPackedValue(), eps,
                failmsg + " add negative plaintext (auto scale factor matching) after 2 multiplications fails");

            cc->Decrypt(kp.secretKey, cSubPt2AfterMult2, &results);
            results->SetLength(plaintex2SubAfterMult2->GetLength());
            checkEquality(plaintex2SubAfterMult2->GetCKKSPackedValue(), results->GetCKKSPackedValue(), eps,
                failmsg + " subtract negative plaintext (auto scale factor matching) after 2 multiplications fails");

            cc->Decrypt(kp.secretKey, cDeepAdd, &results);
            results->SetLength(plaintexAddAfterMult2->GetLength());
            checkEquality(plaintexAddAfterMult2->GetCKKSPackedValue(), results->GetCKKSPackedValue(), eps,
                failmsg + " add with deep plaintext fails");

            cc->Decrypt(kp.secretKey, cDeepSub, &results);
            results->SetLength(plaintexSubAfterMult2->GetLength());
            checkEquality(plaintexSubAfterMult2->GetCKKSPackedValue(), results->GetCKKSPackedValue(), eps,
                failmsg + " subtract with deep plaintext fails");

            cc->Decrypt(kp.secretKey, c2DeepAdd, &results);
            results->SetLength(plaintex2AddAfterMult2->GetLength());
            checkEquality(plaintex2AddAfterMult2->GetCKKSPackedValue(), results->GetCKKSPackedValue(), eps,
                failmsg + " add with deep negative plaintext fails");

            cc->Decrypt(kp.secretKey, c2DeepSub, &results);
            results->SetLength(plaintex2SubAfterMult2->GetLength());
            checkEquality(plaintex2SubAfterMult2->GetCKKSPackedValue(), results->GetCKKSPackedValue(), eps,
                failmsg + " subtract with deep negative plaintext fails");
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

    void UnitTest_AutoLevelReduce(const TEST_CASE_UTCKKSRNS& testData, const std::string& failmsg = std::string()) {
        try {
            CryptoContext<Element> cc(UnitTestGenerateContext(testData.params));

            std::vector<std::complex<double>> vectorOfInts1(vectorOfInts0_7);
            Plaintext plaintext1 = cc->MakeCKKSPackedPlaintext(vectorOfInts1);

            std::vector<std::complex<double>> vectorOfInts2(vectorOfInts7_0);
            Plaintext plaintext2 = cc->MakeCKKSPackedPlaintext(vectorOfInts2);

            std::vector<std::complex<double>> pCtMult(VECTOR_SIZE);
            std::vector<std::complex<double>> pCtMult3(VECTOR_SIZE);
            std::vector<std::complex<double>> pCt3(VECTOR_SIZE);
            std::vector<std::complex<double>> pCt3_b(VECTOR_SIZE);
            std::vector<std::complex<double>> pCt4(VECTOR_SIZE);
            std::vector<std::complex<double>> pCt5(VECTOR_SIZE);
            std::vector<std::complex<double>> pCt6(VECTOR_SIZE);
            std::vector<std::complex<double>> pCt7(VECTOR_SIZE);
            std::vector<std::complex<double>> pCt_5(VECTOR_SIZE);
            std::vector<std::complex<double>> pCt_6(VECTOR_SIZE);
            std::vector<std::complex<double>> pCt_7(VECTOR_SIZE);
            std::vector<std::complex<double>> pCt8(VECTOR_SIZE);
            std::vector<std::complex<double>> pCt9(VECTOR_SIZE);
            std::vector<std::complex<double>> pCt10(VECTOR_SIZE);
            std::vector<std::complex<double>> pCt11(VECTOR_SIZE);
            std::vector<std::complex<double>> pCt12(VECTOR_SIZE);
            std::vector<std::complex<double>> pCt13(VECTOR_SIZE);
            std::vector<std::complex<double>> pCt14(VECTOR_SIZE);
            for (usint i = 0; i < VECTOR_SIZE; i++) {
                pCtMult[i] = vectorOfInts1[i] * vectorOfInts2[i];
                pCt3[i] = pCtMult[i] + vectorOfInts1[i];
                pCt4[i] = pCtMult[i] - vectorOfInts1[i];
                pCt5[i] = pCtMult[i] * vectorOfInts1[i];
                pCt6[i] = vectorOfInts1[i] + pCtMult[i];
                pCt7[i] = vectorOfInts1[i] - pCtMult[i];
                auto tmp = (vectorOfInts1[i] * vectorOfInts1[i] +
                    vectorOfInts1[i] * vectorOfInts1[i]) *
                    vectorOfInts1[i];
                pCt_5[i] = tmp + vectorOfInts2[i];
                pCt_6[i] = tmp - vectorOfInts2[i];
                pCt_7[i] = tmp * vectorOfInts2[i];
                pCt8[i] = vectorOfInts1[i] * pCtMult[i];
                pCtMult3[i] = pCtMult[i] * vectorOfInts1[i] * vectorOfInts1[i];
                pCt9[i] = pCtMult3[i] + vectorOfInts1[i];
                pCt10[i] = pCtMult3[i] - vectorOfInts1[i];
                pCt11[i] = pCtMult3[i] * vectorOfInts1[i];
                pCt12[i] = vectorOfInts1[i] + pCtMult3[i];
                pCt13[i] = vectorOfInts1[i] - pCtMult3[i];
                pCt14[i] = vectorOfInts1[i] * pCtMult3[i];
            }
            Plaintext plaintextCt3 = cc->MakeCKKSPackedPlaintext(pCt3);
            Plaintext plaintextCt4 = cc->MakeCKKSPackedPlaintext(pCt4);
            Plaintext plaintextCt5 = cc->MakeCKKSPackedPlaintext(pCt5);
            Plaintext plaintextCt6 = cc->MakeCKKSPackedPlaintext(pCt6);
            Plaintext plaintextCt7 = cc->MakeCKKSPackedPlaintext(pCt7);
            Plaintext plaintextCt_5 = cc->MakeCKKSPackedPlaintext(pCt_5);
            Plaintext plaintextCt_6 = cc->MakeCKKSPackedPlaintext(pCt_6);
            Plaintext plaintextCt_7 = cc->MakeCKKSPackedPlaintext(pCt_7);
            Plaintext plaintextCt8 = cc->MakeCKKSPackedPlaintext(pCt8);
            Plaintext plaintextCt9 = cc->MakeCKKSPackedPlaintext(pCt9);
            Plaintext plaintextCt10 = cc->MakeCKKSPackedPlaintext(pCt10);
            Plaintext plaintextCt11 = cc->MakeCKKSPackedPlaintext(pCt11);
            Plaintext plaintextCt12 = cc->MakeCKKSPackedPlaintext(pCt12);
            Plaintext plaintextCt13 = cc->MakeCKKSPackedPlaintext(pCt13);
            Plaintext plaintextCt14 = cc->MakeCKKSPackedPlaintext(pCt14);

            // Generate encryption keys
            KeyPair<Element> kp = cc->KeyGen();
            // Generate multiplication keys
            cc->EvalMultKeyGen(kp.secretKey);

            // Encrypt plaintexts
            Ciphertext<Element> ct = cc->Encrypt(kp.publicKey, plaintext1);
            Ciphertext<Element> ct2 = cc->Encrypt(kp.publicKey, plaintext2);

            auto ctMul = cc->EvalMult(ct, ct2);
            auto ctRed = cc->ModReduce(ctMul);

            Plaintext results;
            // Addition with tower diff = 1
            auto ct3 = cc->EvalAdd(ctRed, ct);
            cc->Decrypt(kp.secretKey, ct3, &results);
            results->SetLength(plaintextCt3->GetLength());
            checkEquality(plaintextCt3->GetCKKSPackedValue(), results->GetCKKSPackedValue(), eps,
                failmsg + " addition with tower diff = 1 fails");

            // in-place addition with tower diff = 1
            auto ctRedClone = ctRed->Clone();
            cc->EvalAddInPlace(ctRedClone, ct);
            cc->Decrypt(kp.secretKey, ctRedClone, &results);
            results->SetLength(plaintextCt3->GetLength());
            checkEquality(plaintextCt3->GetCKKSPackedValue(), results->GetCKKSPackedValue(), eps,
                failmsg + " in-place addition with tower diff = 1 fails");

            // Subtraction with tower diff = 1
            auto ct4 = cc->EvalSub(ctRed, ct);
            cc->Decrypt(kp.secretKey, ct4, &results);
            results->SetLength(plaintextCt4->GetLength());
            checkEquality(plaintextCt4->GetCKKSPackedValue(), results->GetCKKSPackedValue(), eps,
                failmsg + " subtraction with tower diff = 1 fails");

            // Multiplication with tower diff = 1
            auto ct5 = cc->EvalMult(ctRed, ct);
            cc->Decrypt(kp.secretKey, ct5, &results);
            results->SetLength(plaintextCt5->GetLength());
            checkEquality(plaintextCt5->GetCKKSPackedValue(), results->GetCKKSPackedValue(), eps,
                failmsg + " multiplication with tower diff = 1 fails");

            // Addition with tower diff = 1 (inputs reversed)
            auto ct6 = cc->EvalAdd(ct, ctRed);
            cc->Decrypt(kp.secretKey, ct6, &results);
            results->SetLength(plaintextCt6->GetLength());
            checkEquality(plaintextCt6->GetCKKSPackedValue(), results->GetCKKSPackedValue(), eps,
                failmsg + " addition (reverse) with tower diff = 1 fails");

            // in-place addition with tower diff = 1 (inputs reversed)
            Ciphertext<Element> ctClone = ct->Clone();
            cc->EvalAddInPlace(ctClone, ctRed);
            cc->Decrypt(kp.secretKey, ctClone, &results);
            results->SetLength(plaintextCt6->GetLength());
            checkEquality(plaintextCt6->GetCKKSPackedValue(), results->GetCKKSPackedValue(), eps,
                failmsg + " in-place addition (reverse) with tower diff = 1 fails");

            // Subtraction with tower diff = 1 (inputs reversed)
            auto ct7 = cc->EvalSub(ct, ctRed);
            cc->Decrypt(kp.secretKey, ct7, &results);
            results->SetLength(plaintextCt7->GetLength());
            checkEquality(plaintextCt7->GetCKKSPackedValue(), results->GetCKKSPackedValue(), eps,
                failmsg + " subtraction (reverse) with tower diff = 1 fails");

            // Multiplication with tower diff = 1 (inputs reversed)
            auto ct8 = cc->EvalMult(ct, ctRed);
            cc->Decrypt(kp.secretKey, ct8, &results);
            results->SetLength(plaintextCt8->GetLength());
            checkEquality(plaintextCt8->GetCKKSPackedValue(), results->GetCKKSPackedValue(), eps,
                failmsg + " multiplication (reverse) with tower diff = 1 fails");

            auto ctMul2 = cc->EvalMult(ctRed, ct);
            auto ctRed2 = cc->ModReduce(ctMul2);
            auto ctMul3 = cc->EvalMult(ctRed2, ct);
            auto ctRed3 = cc->ModReduce(ctMul3);

            // Addition with more than 1 level difference
            auto ct9 = cc->EvalAdd(ctRed3, ct);
            cc->Decrypt(kp.secretKey, ct9, &results);
            results->SetLength(plaintextCt9->GetLength());
            checkEquality(plaintextCt9->GetCKKSPackedValue(), results->GetCKKSPackedValue(), eps,
                failmsg + " addition with tower diff > 1 fails");

            // In-place addition with more than 1 level difference
            auto ctRed3Clone = ctRed3->Clone();
            cc->EvalAddInPlace(ctRed3Clone, ct);
            cc->Decrypt(kp.secretKey, ctRed3Clone, &results);
            results->SetLength(plaintextCt9->GetLength());
            checkEquality(plaintextCt9->GetCKKSPackedValue(), results->GetCKKSPackedValue(), eps,
                failmsg + " in-place addition with tower diff > 1 fails");

            // Subtraction with more than 1 level difference
            auto ct10 = cc->EvalSub(ctRed3, ct);
            cc->Decrypt(kp.secretKey, ct10, &results);
            results->SetLength(plaintextCt10->GetLength());
            checkEquality(plaintextCt10->GetCKKSPackedValue(), results->GetCKKSPackedValue(), epsHigh,
                failmsg + " in-place addition with tower diff > 1 fails");

            // Multiplication with more than 1 level difference
            auto ct11 = cc->EvalMult(ctRed3, ct);
            cc->Decrypt(kp.secretKey, ct11, &results);
            results->SetLength(plaintextCt11->GetLength());
            std::stringstream buffer;
            buffer << plaintextCt11->GetCKKSPackedValue() << " - we get: " << results->GetCKKSPackedValue();
            checkEquality(plaintextCt11->GetCKKSPackedValue(), results->GetCKKSPackedValue(), epsHigh,
                failmsg + " multiplication with tower diff > 1 fails" + buffer.str());

            // Addition with more than 1 level difference (inputs reversed)
            auto ct12 = cc->EvalAdd(ct, ctRed3);
            cc->Decrypt(kp.secretKey, ct12, &results);
            results->SetLength(plaintextCt12->GetLength());
            checkEquality(plaintextCt12->GetCKKSPackedValue(), results->GetCKKSPackedValue(), eps,
                failmsg + " addition (reverse) with tower diff > 1 fails");

            // In-place addition with more than 1 level difference (inputs reversed)
            ctClone = ct->Clone();
            cc->EvalAddInPlace(ctClone, ctRed3);
            cc->Decrypt(kp.secretKey, ctClone, &results);
            results->SetLength(plaintextCt12->GetLength());
            checkEquality(plaintextCt12->GetCKKSPackedValue(), results->GetCKKSPackedValue(), eps,
                failmsg + " in-place addition (reverse) with tower diff > 1 fails");

            // Subtraction with more than 1 level difference (inputs reversed)
            auto ct13 = cc->EvalSub(ct, ctRed3);
            cc->Decrypt(kp.secretKey, ct13, &results);
            results->SetLength(plaintextCt13->GetLength());
            checkEquality(plaintextCt13->GetCKKSPackedValue(), results->GetCKKSPackedValue(), eps,
                failmsg + " subtraction (reverse) with tower diff > 1 fails");

            // Multiplication with more than 1 level difference (inputs reversed)
            auto ct14 = cc->EvalMult(ct, ctRed3);
            cc->Decrypt(kp.secretKey, ct14, &results);
            results->SetLength(plaintextCt14->GetLength());
            checkEquality(plaintextCt14->GetCKKSPackedValue(), results->GetCKKSPackedValue(), epsHigh,
                failmsg + " multiplication (reverse) with tower diff > 1 fails");

            // This scenario tests for operations on ciphertext and plaintext that differ on
            // both scaling factor and number of towers.
            auto ct_1 = cc->EvalMult(ct, plaintext1);
            auto ct_2 = cc->EvalAdd(ct_1, ct_1);
            auto ct_3 = cc->ModReduce(ct_2);
            auto ct_4 = cc->EvalMult(ct_3, plaintext1);
            ct_4 = cc->ModReduce(ct_4);

            // Addition with plaintext and tower diff = 1
            auto ct_5 = cc->EvalAdd(ct_4, plaintext2);
            cc->Decrypt(kp.secretKey, ct_5, &results);
            results->SetLength(plaintextCt_5->GetLength());
            checkEquality(plaintextCt_5->GetCKKSPackedValue(), results->GetCKKSPackedValue(), eps,
                failmsg + " addition with plaintext and tower diff = 1 fails");

            // Subtraction with plaintext and tower diff = 1
            auto ct_6 = cc->EvalSub(ct_4, plaintext2);
            cc->Decrypt(kp.secretKey, ct_6, &results);
            results->SetLength(plaintextCt_6->GetLength());
            checkEquality(plaintextCt_6->GetCKKSPackedValue(), results->GetCKKSPackedValue(), eps,
                failmsg + " subtraction with plaintext and tower diff = 1 fails");

            // Multiplication with plaintext and tower diff = 1
            auto ct_7 = cc->EvalMult(ct_4, plaintext2);
            cc->Decrypt(kp.secretKey, ct_7, &results);
            results->SetLength(plaintextCt_7->GetLength());
            checkEquality(plaintextCt_7->GetCKKSPackedValue(), results->GetCKKSPackedValue(), epsHigh,
                failmsg + " multiplication with plaintext and tower diff = 1 fails");
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

    void UnitTest_Compress(const TEST_CASE_UTCKKSRNS& testData, const std::string& failmsg = std::string()) {
        try {
            CryptoContext<Element> cc(UnitTestGenerateContext(testData.params));

            Plaintext plaintext = cc->MakeCKKSPackedPlaintext(vectorOfInts0_7);

            // Generate encryption keys
            KeyPair<Element> kp = cc->KeyGen();
            // Generate multiplication keys
            cc->EvalMultKeyGen(kp.secretKey);

            // Encrypt plaintexts
            Ciphertext<Element> ct = cc->Encrypt(kp.publicKey, plaintext);
            ct *= ct;
            size_t targetTowers = 1;
            auto ctCompressed = cc->Compress(ct, targetTowers);

            size_t towersLeft = ctCompressed->GetElements()[0].GetNumOfElements();
            EXPECT_TRUE(towersLeft == targetTowers) << " compress fails - towers mismatch";

            Plaintext result;
            Plaintext resultCompressed;
            cc->Decrypt(kp.secretKey, ct, &result);
            cc->Decrypt(kp.secretKey, ctCompressed, &resultCompressed);
            checkEquality(result->GetCKKSPackedValue(), resultCompressed->GetCKKSPackedValue(), eps,
                failmsg + " compress fails - result is incorrect");
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

    void UnitTest_EvalFastRotation(const TEST_CASE_UTCKKSRNS& testData, const std::string& failmsg = std::string()) {
        try {
            CryptoContext<Element> cc(UnitTestGenerateContext(testData.params));

            const uint32_t ringDim = cc->GetRingDimension();
            const uint32_t Nh = ringDim >> 1;

            std::vector<std::complex<double>> vectorOfInts1(Nh);
            for (uint32_t i = 0; i < Nh; i++) {
                vectorOfInts1[i] = rand() % 10;
            }
            Plaintext plaintext1 = cc->MakeCKKSPackedPlaintext(vectorOfInts1);

            std::vector<std::complex<double>> vIntsRightRotate2(Nh);
            for (uint32_t i = 0; i < Nh; i++) {
                vIntsRightRotate2[(i + Nh + 2) % Nh] = vectorOfInts1[i];
            }
            Plaintext plaintextRight2 = cc->MakeCKKSPackedPlaintext(vIntsRightRotate2);

            std::vector<std::complex<double>> vIntsLeftRotate2(Nh);
            for (uint32_t i = 0; i < Nh; i++) {
                vIntsLeftRotate2[(i + Nh - 2) % Nh] = vectorOfInts1[i];
            }
            Plaintext plaintextLeft2 = cc->MakeCKKSPackedPlaintext(vIntsLeftRotate2);

            // Generate encryption keys
            KeyPair<Element> kp = cc->KeyGen();
            // Generate multiplication keys
            cc->EvalMultKeyGen(kp.secretKey);
            // Generate rotation keys for offsets +2 (left rotate) and -2 (right rotate)
            cc->EvalAtIndexKeyGen(kp.secretKey, { 2, -2 });

            // Encrypt plaintexts
            Ciphertext<Element> ciphertext1 = cc->Encrypt(kp.publicKey, plaintext1);

            /* First, do one multiplication and apply the rotation to the result.
             * This helps hide the rotation noise and get the correct result without
             * using a smaller relinWindow in BV (when creating the crypto context cc).
             */
            std::vector<std::complex<double>> vOnes(Nh, 1); // all 1s
            Plaintext pOnes = cc->MakeCKKSPackedPlaintext(vOnes);
            Ciphertext<Element> cOnes = cc->Encrypt(kp.publicKey, pOnes);
            ciphertext1 *= cOnes;

            /* Testing EvalFastRotate +2 (left rotate)
             */
            uint32_t M = ringDim << 1;
            auto cPrecomp1 = cc->EvalFastRotationPrecompute(ciphertext1);
            Ciphertext<Element> cResult = cc->EvalFastRotation(ciphertext1, 2, M, cPrecomp1);
            Plaintext results;
            cc->Decrypt(kp.secretKey, cResult, &results);
            results->SetLength(plaintextLeft2->GetLength());
            checkEquality(plaintextLeft2->GetCKKSPackedValue(), results->GetCKKSPackedValue(), eps,
                failmsg + " EvalFastRotation(+2) fails");

            /* Testing EvalFastRotate -2 (right rotate)
             */
            cResult = cc->EvalFastRotation(ciphertext1, -2, M, cPrecomp1);
            cc->Decrypt(kp.secretKey, cResult, &results);
            results->SetLength(plaintextRight2->GetLength());
            checkEquality(plaintextRight2->GetCKKSPackedValue(), results->GetCKKSPackedValue(), eps,
                failmsg + " EvalFastRotation(-2) fails");
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

    void UnitTest_EvalAtIndex(const TEST_CASE_UTCKKSRNS& testData, const std::string& failmsg = std::string()) {
        try {
            CryptoContext<Element> cc(UnitTestGenerateContext(testData.params));

            Plaintext plaintext1 = cc->MakeCKKSPackedPlaintext(vectorOfInts1_8);

            // vIntsRightShift2 = { 0,0,1,2,3,4,5,6 };
            std::vector<std::complex<double>> vIntsRightShift2(VECTOR_SIZE);
            for (usint i = 0; i < VECTOR_SIZE; i++) {
                vIntsRightShift2[i] = (i >= 2) ? vectorOfInts1_8[i - 2] : 0;
            }
            Plaintext plaintextRight2 = cc->MakeCKKSPackedPlaintext(vIntsRightShift2);

            // vIntsLeftShift2 = { 3,4,5,6,7,8,0,0 };
            std::vector<std::complex<double>> vIntsLeftShift2(VECTOR_SIZE);
            for (usint i = 0; i < VECTOR_SIZE; i++) {
                vIntsLeftShift2[i] = (i < VECTOR_SIZE - 2) ? vectorOfInts1_8[i + 2] : 0;
            }
            Plaintext plaintextLeft2 = cc->MakeCKKSPackedPlaintext(vIntsLeftShift2);

            // Generate encryption keys
            KeyPair<Element> kp = cc->KeyGen();
            // Generate multiplication keys
            cc->EvalMultKeyGen(kp.secretKey);
            // Generate rotation keys for offsets +2 (left shift) and -2 (right shift)
            cc->EvalAtIndexKeyGen(kp.secretKey, { 2, -2 });

            // Encrypt plaintexts
            Ciphertext<Element> ciphertext1 = cc->Encrypt(kp.publicKey, plaintext1);

            /* First, do one multiplication and apply the rotation to the result.
             * This helps hide the rotation noise and get the correct result without
             * using a smaller relinWindow in BV (when creating the crypto context cc).
             */
            Plaintext pOnes = cc->MakeCKKSPackedPlaintext(vectorOfInts1s);
            Ciphertext<Element> cOnes = cc->Encrypt(kp.publicKey, pOnes);
            ciphertext1 *= cOnes;

            /* Testing EvalAtIndex +2
             */
            Ciphertext<Element> cResult = cc->EvalAtIndex(ciphertext1, 2);
            Plaintext results;
            cc->Decrypt(kp.secretKey, cResult, &results);
            results->SetLength(plaintextLeft2->GetLength());
            checkEquality(plaintextLeft2->GetCKKSPackedValue(), results->GetCKKSPackedValue(), eps,
                failmsg + " EvalAtIndex(+2) fails");

            /* Testing EvalAtIndex -2
             */
            cResult = cc->EvalAtIndex(ciphertext1, -2);
            cc->Decrypt(kp.secretKey, cResult, &results);
            results->SetLength(plaintextRight2->GetLength());
            checkEquality(plaintextRight2->GetCKKSPackedValue(), results->GetCKKSPackedValue(), eps,
                failmsg + " EvalAtIndex(-2) fails");
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

    void UnitTest_EvalMerge(const TEST_CASE_UTCKKSRNS& testData, const std::string& failmsg = std::string()) {
        // TODO (dsuponit) error from pke/include/schemebase/base-scheme.h:1500 EvalMerge operation has not been enabled"
        try {
            CryptoContext<Element> cc(UnitTestGenerateContext(testData.params));

            // v* = { i,0,0,0,0,0,0,0 };
            std::vector<std::complex<double>> vOne(VECTOR_SIZE, 0);
            vOne[0] = 1;
            std::vector<std::complex<double>> vTwo(VECTOR_SIZE, 0);
            vTwo[0] = 2;
            std::vector<std::complex<double>> vThree(VECTOR_SIZE, 0);
            vThree[0] = 3;
            std::vector<std::complex<double>> vFour(VECTOR_SIZE, 0);
            vFour[0] = 4;
            std::vector<std::complex<double>> vFive(VECTOR_SIZE, 0);
            vFive[0] = 5;
            std::vector<std::complex<double>> vSix(VECTOR_SIZE, 0);
            vSix[0] = 6;
            std::vector<std::complex<double>> vSeven(VECTOR_SIZE, 0);
            vSeven[0] = 7;
            std::vector<std::complex<double>> vEight(VECTOR_SIZE, 0);
            vEight[0] = 8;
            Plaintext pOne = cc->MakeCKKSPackedPlaintext(vOne);
            Plaintext pTwo = cc->MakeCKKSPackedPlaintext(vTwo);
            Plaintext pThree = cc->MakeCKKSPackedPlaintext(vThree);
            Plaintext pFour = cc->MakeCKKSPackedPlaintext(vFour);
            Plaintext pFive = cc->MakeCKKSPackedPlaintext(vFive);
            Plaintext pSix = cc->MakeCKKSPackedPlaintext(vSix);
            Plaintext pSeven = cc->MakeCKKSPackedPlaintext(vSeven);
            Plaintext pEight = cc->MakeCKKSPackedPlaintext(vEight);

            Plaintext pMerged = cc->MakeCKKSPackedPlaintext(vectorOfInts1_8);
            Plaintext pOnes = cc->MakeCKKSPackedPlaintext(vectorOfInts1s);

            // Generate encryption keys
            KeyPair<Element> kp = cc->KeyGen();
            // Generate multiplication keys
            cc->EvalMultKeyGen(kp.secretKey);
            // Generate rotation keys for all right rotations 1 to 8.
            std::vector<int32_t> indexList = { -1, -2, -3, -4, -5, -6, -7, -8 };
            cc->EvalAtIndexKeyGen(kp.secretKey, indexList);

            // Encrypt plaintexts
            Ciphertext<Element> cOnes = cc->Encrypt(kp.publicKey, pOnes);

            // Here, we perform the same trick (mult with one) as in
            // UnitTest_EvalAtiIndex.
            std::vector<Ciphertext<Element>> ciphertexts;
            ciphertexts.push_back(cc->Encrypt(kp.publicKey, pOne) * cOnes);
            ciphertexts.push_back(cc->Encrypt(kp.publicKey, pTwo) * cOnes);
            ciphertexts.push_back(cc->Encrypt(kp.publicKey, pThree) * cOnes);
            ciphertexts.push_back(cc->Encrypt(kp.publicKey, pFour) * cOnes);
            ciphertexts.push_back(cc->Encrypt(kp.publicKey, pFive) * cOnes);
            ciphertexts.push_back(cc->Encrypt(kp.publicKey, pSix) * cOnes);
            ciphertexts.push_back(cc->Encrypt(kp.publicKey, pSeven) * cOnes);
            ciphertexts.push_back(cc->Encrypt(kp.publicKey, pEight) * cOnes);

            /* Testing EvalMerge
             */
            auto cResult = cc->EvalMerge(ciphertexts);
            Plaintext results;
            cc->Decrypt(kp.secretKey, cResult, &results);
            results->SetLength(pMerged->GetLength());
            checkEquality(pMerged->GetCKKSPackedValue(), results->GetCKKSPackedValue(), eps,
                failmsg + " EvalMerge fails");
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

    void UnitTest_EvalLinearWSum(const TEST_CASE_UTCKKSRNS& testData, const std::string& failmsg = std::string()) {
        try {
            CryptoContext<Element> cc(UnitTestGenerateContext(testData.params));

            std::vector<double> weights{ 0, 1, 2 };
            std::vector<std::complex<double>> in1(VECTOR_SIZE, 3); // all 3's
            std::vector<std::complex<double>> in2(VECTOR_SIZE, 2); // all 2's
            std::vector<std::complex<double>> in3(VECTOR_SIZE, 1); // all 1's
            std::vector<std::complex<double>> out(VECTOR_SIZE);
            for (usint i = 0; i < VECTOR_SIZE; i++) {
                // TODO (dsuponit): what is the purpose of this calculation? to have a noise?
                // otherwise it is better to create "out" without calculating values in the loop
                out[i] = weights[0] * in1[i] + weights[1] * in2[i] + weights[2] * in3[i];
            }
            Plaintext pIn1 = cc->MakeCKKSPackedPlaintext(in1);
            Plaintext pIn2 = cc->MakeCKKSPackedPlaintext(in2);
            Plaintext pIn3 = cc->MakeCKKSPackedPlaintext(in3);
            Plaintext pOut = cc->MakeCKKSPackedPlaintext(out);

            // Generate encryption keys
            KeyPair<Element> kp = cc->KeyGen();
            // Generate multiplication keys
            cc->EvalMultKeyGen(kp.secretKey);

            // Encrypt plaintexts
            Ciphertext<Element> cIn1 = cc->Encrypt(kp.publicKey, pIn1);
            Ciphertext<Element> cIn2 = cc->Encrypt(kp.publicKey, pIn2);
            Ciphertext<Element> cIn3 = cc->Encrypt(kp.publicKey, pIn3);

            std::vector<Ciphertext<Element>> ciphertexts{ cIn1, cIn2, cIn3 };
            std::vector<ConstCiphertext<Element>> constCiphertexts{ cIn1, cIn2, cIn3 };

            auto cResult = cc->EvalLinearWSum(constCiphertexts, weights);
            Plaintext results;
            cc->Decrypt(kp.secretKey, cResult, &results);
            results->SetLength(pOut->GetLength());
            checkEquality(pOut->GetCKKSPackedValue(), results->GetCKKSPackedValue(), eps,
                failmsg + " EvalLinearWSum fails");

            auto cResult2 = cc->EvalLinearWSumMutable(ciphertexts, weights);
            cc->Decrypt(kp.secretKey, cResult2, &results);
            results->SetLength(pOut->GetLength());
            checkEquality(pOut->GetCKKSPackedValue(), results->GetCKKSPackedValue(), eps,
                failmsg + " EvalLinearWSumMutable fails");
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

    void UnitTest_ReEncryption(const TEST_CASE_UTCKKSRNS& testData, const std::string& failmsg = std::string()) {
        try {
            CryptoContext<Element> cc(UnitTestGenerateContext(testData.params));

            //const double eps = 0.01;

            size_t max = 128;
            auto ptm = 10;

            std::vector<std::complex<double>> intvec(max);
            for (size_t i = 0; i < max; ++i) {
                intvec[i] = (rand() % (ptm / 2)) * (rand() % 2 ? 1 : -1);
            }
            Plaintext plaintextInt = cc->MakeCKKSPackedPlaintext(intvec);

            KeyPair<Element> kp = cc->KeyGen();
            EXPECT_EQ(kp.good(), true) << failmsg << " key generation for scalar encrypt/decrypt failed";

            KeyPair<Element> newKp = cc->KeyGen();
            EXPECT_EQ(newKp.good(), true) << failmsg << " second key generation for scalar encrypt/decrypt failed";

            // This generates the keys which are used to perform the key switching.
            EvalKey<Element> evalKey = cc->ReKeyGen(kp.secretKey, newKp.publicKey);

            Ciphertext<Element> ciphertext = cc->Encrypt(kp.publicKey, plaintextInt);
            Ciphertext<Element> reCiphertext = cc->ReEncrypt(ciphertext, evalKey);
            Plaintext plaintextIntNew;
            cc->Decrypt(newKp.secretKey, reCiphertext, &plaintextIntNew);
            plaintextIntNew->SetLength(plaintextInt->GetLength());
            auto tmp_a = plaintextIntNew->GetCKKSPackedValue();
            auto tmp_b = plaintextInt->GetCKKSPackedValue();
            std::stringstream buffer;
            buffer << tmp_b << " - we get: " << tmp_a;
            checkEquality(tmp_a, tmp_b, epsHigh, failmsg + " ReEncrypt integer plaintext " + buffer.str());

            Ciphertext<Element> ciphertext2 = cc->Encrypt(kp.publicKey, plaintextInt);
            Ciphertext<Element> reCiphertext2 = cc->ReEncrypt(ciphertext2, evalKey, kp.publicKey);
            Plaintext plaintextIntNew2;
            cc->Decrypt(newKp.secretKey, reCiphertext2, &plaintextIntNew2);
            plaintextIntNew2->SetLength(plaintextInt->GetLength());
            tmp_a = plaintextIntNew2->GetCKKSPackedValue();
            tmp_b = plaintextInt->GetCKKSPackedValue();
            std::stringstream buffer2;
            buffer2 << tmp_b << " - we get: " << tmp_a;
            checkEquality(tmp_a, tmp_b, epsHigh, failmsg + " HRA-secure ReEncrypt integer plaintext " + buffer2.str());
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

    void UnitTest_EvalPoly(const TEST_CASE_UTCKKSRNS& testData, const std::string& failmsg = std::string()) {
        try {
            CryptoContext<Element> cc(UnitTestGenerateContext(testData.params));

            // Encode inputs as CKKS inputs.
            std::vector<std::complex<double>> input{ 0.5, 0.7, 0.9, 0.95, 0.93 };
            const size_t encodedLength = input.size();

            // with only positive coefficients
            // x^16 + x^11 + 2 x^9 + x^8 + x^6 + 1.25 x^3 + 0.75*x + 0.15
            std::vector<double> coefficients1{ 0.15, 0.75, 0, 1.25, 0, 0, 1, 0, 1, 2, 0, 1, 0, 0, 0, 0, 1 };
            // x^16 + x^11 + 2 x^9 - x^8 + x^6 + 1.25 x^3 - 0.75*x + 0.15
            // with negative coefficients
            std::vector<double> coefficients2{ 0.15, -0.75, 0, 1.25, 0, 0, 1, 0, -1, 2, 0, 1, 0, 0, 0, 0, 1 };
            // x^16
            // power function
            std::vector<double> coefficients3{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
            // x^16 + x^11 + 2 x^9 - x^8 + x^6 - 1.25 x^5 + 1.25 x^3 - 1.75*x + 0.15
            // with negative coefficients with magnitude greater than 1
            std::vector<double> coefficients4{ 0.15, -1.75, 0, 1.25, 0, -1.25, 1, 0, -1, 2, 0, 1, 0, 0, 0, 0, 1 };
            // x + x^2 - x^3
            // low-degree function to check linear implementation
            std::vector<double> coefficients5{ 0, 1, 1, -1 };

            Plaintext plaintext1 = cc->MakeCKKSPackedPlaintext(input);

            std::vector<std::complex<double>> output1{ 0.705191, 1.38285, 3.97211, 5.60216, 4.86358 };
            Plaintext plaintextResult1 = cc->MakeCKKSPackedPlaintext(output1);

            std::vector<std::complex<double>> output2{ -0.0526215, 0.217555, 1.76118, 2.85032, 2.34941 };
            Plaintext plaintextResult2 = cc->MakeCKKSPackedPlaintext(output2);

            std::vector<std::complex<double>> output3{ 0.0000152588, 0.00332329, 0.185302, 0.440127, 0.313132 };
            Plaintext plaintextResult3 = cc->MakeCKKSPackedPlaintext(output3);

            std::vector<std::complex<double>> output4{ -0.59168396, -0.69253274, 0.12306489, 0.93308964, 0.54980166 };
            Plaintext plaintextResult4 = cc->MakeCKKSPackedPlaintext(output4);

            std::vector<std::complex<double>> output5{ 0.625, 0.847, 0.9809999999, 0.995125, 0.990543 };
            Plaintext plaintextResult5 = cc->MakeCKKSPackedPlaintext(output5);

            // Generate encryption keys
            KeyPair<Element> kp = cc->KeyGen();
            // Generate multiplication keys
            cc->EvalMultKeyGen(kp.secretKey);

            // Encrypt plaintexts
            Ciphertext<Element> ciphertext1 = cc->Encrypt(kp.publicKey, plaintext1);

            /* Testing EvalPoly
             */
            Ciphertext<Element> cResult1 = cc->EvalPoly(ciphertext1, coefficients1);
            Plaintext results1;
            cc->Decrypt(kp.secretKey, cResult1, &results1);
            results1->SetLength(encodedLength);
            std::stringstream buffer1;
            buffer1 << "should be: " << plaintextResult1->GetCKKSPackedValue() << " - we get: " << results1->GetCKKSPackedValue();
            checkEquality(plaintextResult1->GetCKKSPackedValue(), results1->GetCKKSPackedValue(), epsHigh,
                failmsg + " EvalPoly with positive coefficients failed: " + buffer1.str());

            Ciphertext<Element> cResult2 = cc->EvalPoly(ciphertext1, coefficients2);
            Plaintext results2;
            cc->Decrypt(kp.secretKey, cResult2, &results2);
            results2->SetLength(encodedLength);
            std::stringstream buffer2;
            buffer2 << "should be: " << plaintextResult2->GetCKKSPackedValue() << " - we get: " << results2->GetCKKSPackedValue();
            checkEquality(plaintextResult2->GetCKKSPackedValue(), results2->GetCKKSPackedValue(), epsHigh,
                failmsg + " EvalPoly with negative coefficients failed: " + buffer2.str());

            Ciphertext<Element> cResult3 = cc->EvalPoly(ciphertext1, coefficients3);
            Plaintext results3;
            cc->Decrypt(kp.secretKey, cResult3, &results3);
            results3->SetLength(encodedLength);
            std::stringstream buffer3;
            buffer3 << "should be: " << plaintextResult3->GetCKKSPackedValue() << " - we get: " << results3->GetCKKSPackedValue();
            checkEquality(plaintextResult3->GetCKKSPackedValue(), results3->GetCKKSPackedValue(), epsHigh,
                failmsg + " EvalPoly for a power function failed: " + buffer3.str());

            Ciphertext<Element> cResult4 = cc->EvalPoly(ciphertext1, coefficients4);
            Plaintext results4;
            cc->Decrypt(kp.secretKey, cResult4, &results4);
            results4->SetLength(encodedLength);
            std::stringstream buffer4;
            buffer4 << "should be: " << plaintextResult4->GetCKKSPackedValue() << " - we get: " << results4->GetCKKSPackedValue();
            checkEquality(plaintextResult4->GetCKKSPackedValue(), results4->GetCKKSPackedValue(), epsHigh,
                failmsg + " EvalPoly for negative coefficients with magnitude > 1 failed: " + buffer4.str());

            Ciphertext<Element> cResult5 = cc->EvalPoly(ciphertext1, coefficients5);
            Plaintext results5;
            cc->Decrypt(kp.secretKey, cResult5, &results5);
            results5->SetLength(encodedLength);
            std::stringstream buffer5;
            buffer5 << "should be: " << plaintextResult5->GetCKKSPackedValue() << " - we get: " << results5->GetCKKSPackedValue();
            checkEquality(plaintextResult5->GetCKKSPackedValue(), results5->GetCKKSPackedValue(), epsHigh,
                failmsg + " EvalPoly for low-degree polynomial failed: " + buffer5.str());
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

    /***
     * Tests whether metadata is carried over for several operations in CKKS
     */
    void UnitTest_Metadata(const TEST_CASE_UTCKKSRNS& testData, const std::string& failmsg = std::string()) {
        try {
            CryptoContext<Element> cc(UnitTestGenerateContext(testData.params));

            Plaintext plaintext1 = cc->MakeCKKSPackedPlaintext(vectorOfInts0_7);
            Plaintext plaintext2 = cc->MakeCKKSPackedPlaintext(vectorOfInts0_7neg);

            // Generate encryption keys
            KeyPair<Element> kp = cc->KeyGen();
            // Generate multiplication keys
            cc->EvalMultKeyGen(kp.secretKey);
            // Generate rotation keys for offsets +2 (left rotate) and -2 (right rotate)
            cc->EvalAtIndexKeyGen(kp.secretKey, { 2, -2 });
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
            auto addCCValTest = MetadataTest::GetMetadata<Element>(cAddCC);
            EXPECT_EQ(val1->GetMetadata(), addCCValTest->GetMetadata())
                << "Ciphertext metadata mismatch in EvalAdd(ctx,ctx)";

            // Checking if metadata is carried over in EvalAdd(ctx,ctx)
            Ciphertext<Element> ciphertext1Clone = ciphertext1->Clone();
            cc->EvalAddInPlace(ciphertext1, ciphertext2);
            auto addCCInPlaceValTest =
                MetadataTest::GetMetadata<Element>(ciphertext1Clone);
            EXPECT_EQ(val1->GetMetadata(), addCCInPlaceValTest->GetMetadata())
                << "Ciphertext metadata mismatch in EvalAddInPlace(ctx,ctx)";

            // Checking if metadata is carried over in EvalAdd(ctx,ptx)
            Ciphertext<Element> cAddCP = cc->EvalAdd(ciphertext1, plaintext1);
            auto addCPValTest = MetadataTest::GetMetadata<Element>(cAddCP);
            EXPECT_EQ(val1->GetMetadata(), addCPValTest->GetMetadata())
                << "Ciphertext metadata mismatch in EvalAdd(ctx,ptx)";

            // Checking if metadata is carried over in EvalAdd(ctx,double)
            Ciphertext<Element> cAddCD = cc->EvalAdd(ciphertext1, 2.0);
            auto addCDValTest = MetadataTest::GetMetadata<Element>(cAddCD);
            EXPECT_EQ(val1->GetMetadata(), addCDValTest->GetMetadata())
                << "Ciphertext metadata mismatch in EvalAdd(ctx,double)";

            // Checking if metadata is carried over in EvalSub(ctx,ctx)
            Ciphertext<Element> cSubCC = cc->EvalSub(ciphertext1, ciphertext2);
            auto subCCValTest = MetadataTest::GetMetadata<Element>(cSubCC);
            EXPECT_EQ(val1->GetMetadata(), subCCValTest->GetMetadata())
                << "Ciphertext metadata mismatch in EvalSub(ctx,ctx)";

            // Checking if metadata is carried over in EvalSub(ctx,ptx)
            Ciphertext<Element> cSubCP = cc->EvalSub(ciphertext1, plaintext1);
            auto subCPValTest = MetadataTest::GetMetadata<Element>(cSubCP);
            EXPECT_EQ(val1->GetMetadata(), subCPValTest->GetMetadata())
                << "Ciphertext metadata mismatch in EvalSub(ctx,ptx)";

            // Checking if metadata is carried over in EvalSub(ctx,double)
            Ciphertext<Element> cSubCD = cc->EvalSub(ciphertext1, 2.0);
            auto subCDValTest = MetadataTest::GetMetadata<Element>(cSubCD);
            EXPECT_EQ(val1->GetMetadata(), subCDValTest->GetMetadata())
                << "Ciphertext metadata mismatch in EvalSub(ctx,double)";

            // Checking if metadata is carried over in EvalMult(ctx,ctx)
            Ciphertext<Element> cMultCC = cc->EvalMult(ciphertext1, ciphertext2);
            auto multCCValTest = MetadataTest::GetMetadata<Element>(cMultCC);
            EXPECT_EQ(val1->GetMetadata(), multCCValTest->GetMetadata())
                << "Ciphertext metadata mismatch in EvalMult(ctx,ctx)";

            // Checking if metadata is carried over in EvalMult(ctx,ptx)
            Ciphertext<Element> cMultCP = cc->EvalMult(ciphertext1, plaintext1);
            auto multCPValTest = MetadataTest::GetMetadata<Element>(cMultCP);
            EXPECT_EQ(val1->GetMetadata(), multCPValTest->GetMetadata())
                << "Ciphertext metadata mismatch in EvalMult(ctx,ptx)";

            // Checking if metadata is carried over in EvalMult(ctx,double)
            Ciphertext<Element> cMultCD = cc->EvalMult(ciphertext1, 2.0);
            auto multCDValTest = MetadataTest::GetMetadata<Element>(cMultCD);
            EXPECT_EQ(val1->GetMetadata(), multCDValTest->GetMetadata())
                << "Ciphertext metadata mismatch in EvalMult(ctx,double)";

            // Checking if metadata is carried over in EvalAtIndex +2 (left rotate)
            auto cAtIndex2 = cc->EvalAtIndex(ciphertext1, 2);
            auto atIndex2ValTest = MetadataTest::GetMetadata<Element>(cAtIndex2);
            EXPECT_EQ(val1->GetMetadata(), atIndex2ValTest->GetMetadata())
                << "Ciphertext metadata mismatch in EvalAtIndex +2";

            // Checking if metadata is carried over in EvalAtIndex -2 (right rotate)
            auto cAtIndexMinus2 = cc->EvalAtIndex(ciphertext1, -2);
            auto atIndexMinus2ValTest =
                MetadataTest::GetMetadata<Element>(cAtIndexMinus2);
            EXPECT_EQ(val1->GetMetadata(), atIndexMinus2ValTest->GetMetadata())
                << "Ciphertext metadata mismatch in EvalAtIndex -2";

            uint32_t N = cc->GetRingDimension();
            uint32_t M = N << 1;

            // Checking if metadata is carried over EvalFastRotate +2 (left rotate)
            auto cPrecomp1 = cc->EvalFastRotationPrecompute(ciphertext1);
            auto cFastRot2 = cc->EvalFastRotation(ciphertext1, 2, M, cPrecomp1);
            auto fastRot2ValTest = MetadataTest::GetMetadata<Element>(cFastRot2);
            EXPECT_EQ(val1->GetMetadata(), fastRot2ValTest->GetMetadata())
                << "Ciphertext metadata mismatch in EvalFastRotation +2";

            // Checking if metadata is carried over EvalFastRotate -2 (right rotate)
            auto cFastRotMinus2 = cc->EvalFastRotation(ciphertext1, -2, M, cPrecomp1);
            auto fastRotMinus2ValTest =
                MetadataTest::GetMetadata<Element>(cFastRotMinus2);
            EXPECT_EQ(val1->GetMetadata(), fastRotMinus2ValTest->GetMetadata())
                << "Ciphertext metadata mismatch in EvalFastRotation -2";

            std::vector<double> weights(2);
            for (int i = 0; i < 2; i++) weights[i] = i;

            std::vector<ConstCiphertext<Element>> ciphertexts{ ciphertext1, ciphertext2 };

            // Checking if metadata is carried over in EvalLinearWSum
            auto cLWS = cc->EvalLinearWSum(ciphertexts, weights);
            auto lwsValTest = MetadataTest::GetMetadata<Element>(cLWS);
            EXPECT_EQ(val1->GetMetadata(), lwsValTest->GetMetadata())
                << "Ciphertext metadata mismatch in EvalLinearWSum";

            // Checking if metadata is carried over in EvalSum
            auto cSum = cc->EvalSum(ciphertext1, VECTOR_SIZE);
            auto sumValTest = MetadataTest::GetMetadata<Element>(cSum);
            EXPECT_EQ(val1->GetMetadata(), sumValTest->GetMetadata())
                << "Ciphertext metadata mismatch in EvalSum";
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
TEST_P(UTCKKSRNS, CKKSRNS) {
    setupSignals();
    auto test = GetParam();

    if (test.testCaseType == ADD_PACKED)
        UnitTest_Add_Packed(test, test.buildTestName());
    else if (test.testCaseType == MULT_PACKED)
        UnitTest_Mult_Packed(test, test.buildTestName());
    else if (test.testCaseType == SCALE_FACTOR_ADJUSTMENTS)
        UnitTest_ScaleFactorAdjustments(test, test.buildTestName());
    else if (test.testCaseType == AUTO_LEVEL_REDUCE)
        UnitTest_AutoLevelReduce(test, test.buildTestName());
    else if (test.testCaseType == COMPRESS)
        UnitTest_Compress(test, test.buildTestName());
    else if (test.testCaseType == EVAL_FAST_ROTATION)
        UnitTest_EvalFastRotation(test, test.buildTestName());
    else if (test.testCaseType == EVALATINDEX)
        UnitTest_EvalAtIndex(test, test.buildTestName());
    else if (test.testCaseType == EVALMERGE)
        UnitTest_EvalMerge(test, test.buildTestName());
    else if (test.testCaseType == EVAL_LINEAR_WSUM)
        UnitTest_EvalLinearWSum(test, test.buildTestName());
    else if (test.testCaseType == RE_ENCRYPTION)
        UnitTest_ReEncryption(test, test.buildTestName());
    else if (test.testCaseType == EVAL_POLY)
        UnitTest_EvalPoly(test, test.buildTestName());
    else if (test.testCaseType == METADATA)
        UnitTest_Metadata(test, test.buildTestName());
}

INSTANTIATE_TEST_SUITE_P(UnitTests, UTCKKSRNS, ::testing::ValuesIn(testCases), testName);

