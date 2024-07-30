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
#include "UnitTestMetadataTest.h"

#include <iostream>
#include <vector>
#include "gtest/gtest.h"

using namespace lbcrypto;

//===========================================================================================================
enum TEST_CASE_TYPE {
    ADD_PACKED_UTBGVRNS = 0,
    MULT_PACKED_UTBGVRNS,
    EVALATINDEX_UTBGVRNS,
    EVALMERGE_UTBGVRNS,
    RE_ENCRYPTION_UTBGVRNS,
    AUTO_LEVEL_REDUCE_UTBGVRNS,
    COMPRESS_UTBGVRNS,
    EVAL_FAST_ROTATION_UTBGVRNS,
    METADATA_UTBGVRNS,
    CRYPTOPARAMS_VALIDATION_UTBGVRNS,
};

static std::ostream& operator<<(std::ostream& os, const TEST_CASE_TYPE& type) {
    std::string typeName;
    switch (type) {
        case ADD_PACKED_UTBGVRNS:
            typeName = "ADD_PACKED_UTBGVRNS";
            break;
        case MULT_PACKED_UTBGVRNS:
            typeName = "MULT_PACKED_UTBGVRNS";
            break;
        case EVALATINDEX_UTBGVRNS:
            typeName = "EVALATINDEX_UTBGVRNS";
            break;
        case EVALMERGE_UTBGVRNS:
            typeName = "EVALMERGE_UTBGVRNS";
            break;
        case RE_ENCRYPTION_UTBGVRNS:
            typeName = "RE_ENCRYPTION_UTBGVRNS";
            break;
        case AUTO_LEVEL_REDUCE_UTBGVRNS:
            typeName = "AUTO_LEVEL_REDUCE_UTBGVRNS";
            break;
        case COMPRESS_UTBGVRNS:
            typeName = "COMPRESS_UTBGVRNS";
            break;
        case EVAL_FAST_ROTATION_UTBGVRNS:
            typeName = "EVAL_FAST_ROTATION_UTBGVRNS";
            break;
        case METADATA_UTBGVRNS:
            typeName = "METADATA_UTBGVRNS";
            break;
        case CRYPTOPARAMS_VALIDATION_UTBGVRNS:
            typeName = "CRYPTOPARAMS_VALIDATION_UTBGVRNS";
            break;
        default:
            typeName = "UNKNOWN_UTBGVRNS";
            break;
    }
    return os << typeName;
}
//===========================================================================================================
struct TEST_CASE_UTBGVRNS {
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
static auto testName = [](const testing::TestParamInfo<TEST_CASE_UTBGVRNS>& test) {
    return test.param.buildTestName();
};

static std::ostream& operator<<(std::ostream& os, const TEST_CASE_UTBGVRNS& test) {
    return os << test.toString();
}
//===========================================================================================================
/***
 * SIZEMODULI: bit-length of the moduli composing the ciphertext modulus (or scaling factor bits).
 *             Should fit into a machine word, i.e., less than 64.
 * DSIZE:      The bit decomposition count used in BV relinearization.
 * PTM:        The plaintext modulus.
 * BATCH:      The length of the packed vectors to be used with CKKS.
 */
constexpr usint RING_DIM        = 512;
constexpr usint MULT_DEPTH      = 7;
constexpr usint MAX_RELIN_DEG   = 2;
constexpr usint DSIZE           = 0;
constexpr usint BV_DSIZE        = 4;
constexpr usint PTM             = 65537;
constexpr usint BATCH           = 16;
constexpr usint FIRST_MOD_SIZE  = 0;
constexpr SecurityLevel SEC_LVL = HEStd_NotSet;

// clang-format off
static std::vector<TEST_CASE_UTBGVRNS> testCasesUTBGVRNS = {
    // TestType,          Descr,  Scheme,        RDim,     MultDepth,  SModSize,   DSize,    BatchSz, SecKeyDist, MaxRelinSkDeg, FModSize,       SecLvl,  KSTech, ScalTech,        LDigits, PtMod, StdDev,   EvalAddCt, KSCt, MultTech, EncTech, PREMode
    { ADD_PACKED_UTBGVRNS, "01", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       BV_DSIZE, BATCH,   DFLT,       MAX_RELIN_DEG, DFLT,           SEC_LVL, BV,     FLEXIBLEAUTO,    DFLT,    PTM,   DFLT,     DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { ADD_PACKED_UTBGVRNS, "02", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       BV_DSIZE, BATCH,   DFLT,       MAX_RELIN_DEG, FIRST_MOD_SIZE, SEC_LVL, BV,     FIXEDMANUAL,     DFLT,    PTM,   DFLT,     DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { ADD_PACKED_UTBGVRNS, "03", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       BV_DSIZE, BATCH,   DFLT,       MAX_RELIN_DEG, DFLT,           SEC_LVL, BV,     FIXEDAUTO,       DFLT,    PTM,   DFLT,     DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { ADD_PACKED_UTBGVRNS, "04", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       BV_DSIZE, BATCH,   DFLT,       MAX_RELIN_DEG, DFLT,           SEC_LVL, BV,     FLEXIBLEAUTOEXT, DFLT,    PTM,   DFLT,     DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { ADD_PACKED_UTBGVRNS, "05", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       DSIZE,    BATCH,   DFLT,       MAX_RELIN_DEG, DFLT,           SEC_LVL, HYBRID, FLEXIBLEAUTO,    DFLT,    PTM,   DFLT,     DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { ADD_PACKED_UTBGVRNS, "06", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       DSIZE,    BATCH,   DFLT,       MAX_RELIN_DEG, FIRST_MOD_SIZE, SEC_LVL, HYBRID, FIXEDMANUAL,     DFLT,    PTM,   DFLT,     DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { ADD_PACKED_UTBGVRNS, "07", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       DSIZE,    BATCH,   DFLT,       MAX_RELIN_DEG, DFLT,           SEC_LVL, HYBRID, FIXEDAUTO,       DFLT,    PTM,   DFLT,     DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { ADD_PACKED_UTBGVRNS, "08", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       DSIZE,    BATCH,   DFLT,       MAX_RELIN_DEG, DFLT,           SEC_LVL, HYBRID, FLEXIBLEAUTOEXT, DFLT,    PTM,   DFLT,     DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    /// tests the scenario when plaintext modulus * cyclotomic order > 2^32
    { ADD_PACKED_UTBGVRNS, "09", {BGVRNS_SCHEME,    32768,          3, DFLT,       DSIZE,    BATCH,   DFLT,       MAX_RELIN_DEG, FIRST_MOD_SIZE, SEC_LVL, HYBRID, FIXEDMANUAL,     DFLT,    PTM,   DFLT,     DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { ADD_PACKED_UTBGVRNS, "10", {BGVRNS_SCHEME,    32768,          3, DFLT,       DSIZE,    BATCH,   DFLT,       MAX_RELIN_DEG, DFLT,           SEC_LVL, HYBRID, FIXEDAUTO,       DFLT,    PTM,   DFLT,     DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    // ==========================================
    // TestType,           Descr,  Scheme,        RDim,     MultDepth,  SModSize,   DSize,    BatchSz, SecKeyDist, MaxRelinSkDeg, FModSize,       SecLvl,  KSTech, ScalTech,        LDigits, PtMod, StdDev, EvalAddCt, KSCt, MultTech, EncTech, PREMode
    { MULT_PACKED_UTBGVRNS, "01", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       BV_DSIZE, BATCH,   DFLT,       MAX_RELIN_DEG, DFLT,           SEC_LVL, BV,     FLEXIBLEAUTO,    DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { MULT_PACKED_UTBGVRNS, "02", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       BV_DSIZE, BATCH,   DFLT,       MAX_RELIN_DEG, FIRST_MOD_SIZE, SEC_LVL, BV,     FIXEDMANUAL,     DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { MULT_PACKED_UTBGVRNS, "03", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       BV_DSIZE, BATCH,   DFLT,       MAX_RELIN_DEG, DFLT,           SEC_LVL, BV,     FIXEDAUTO,       DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { MULT_PACKED_UTBGVRNS, "04", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       BV_DSIZE, BATCH,   DFLT,       MAX_RELIN_DEG, DFLT,           SEC_LVL, BV,     FLEXIBLEAUTOEXT, DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { MULT_PACKED_UTBGVRNS, "05", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       DSIZE,    BATCH,   DFLT,       MAX_RELIN_DEG, DFLT,           SEC_LVL, HYBRID, FLEXIBLEAUTO,    DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { MULT_PACKED_UTBGVRNS, "06", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       DSIZE,    BATCH,   DFLT,       MAX_RELIN_DEG, FIRST_MOD_SIZE, SEC_LVL, HYBRID, FIXEDMANUAL,     DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { MULT_PACKED_UTBGVRNS, "07", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       DSIZE,    BATCH,   DFLT,       MAX_RELIN_DEG, DFLT,           SEC_LVL, HYBRID, FIXEDAUTO,       DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { MULT_PACKED_UTBGVRNS, "08", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       DSIZE,    BATCH,   DFLT,       MAX_RELIN_DEG, DFLT,           SEC_LVL, HYBRID, FLEXIBLEAUTOEXT, DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    // ==========================================
    // TestType,           Descr,  Scheme,        RDim,     MultDepth,  SModSize,   DSize,    BatchSz, SecKeyDist, MaxRelinSkDeg, FModSize,       SecLvl,  KSTech, ScalTech,        LDigits, PtMod, StdDev, EvalAddCt, KSCt, MultTech, EncTech, PREMode
    { EVALATINDEX_UTBGVRNS, "01", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       BV_DSIZE, BATCH,   DFLT,       MAX_RELIN_DEG, DFLT,           SEC_LVL, BV,     FLEXIBLEAUTO,    DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { EVALATINDEX_UTBGVRNS, "02", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       BV_DSIZE, BATCH,   DFLT,       MAX_RELIN_DEG, FIRST_MOD_SIZE, SEC_LVL, BV,     FIXEDMANUAL,     DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { EVALATINDEX_UTBGVRNS, "03", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       BV_DSIZE, BATCH,   DFLT,       MAX_RELIN_DEG, DFLT,           SEC_LVL, BV,     FIXEDAUTO,       DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { EVALATINDEX_UTBGVRNS, "04", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       BV_DSIZE, BATCH,   DFLT,       MAX_RELIN_DEG, DFLT,           SEC_LVL, BV,     FLEXIBLEAUTOEXT, DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { EVALATINDEX_UTBGVRNS, "05", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       DSIZE,    BATCH,   DFLT,       MAX_RELIN_DEG, DFLT,           SEC_LVL, HYBRID, FLEXIBLEAUTO,    DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { EVALATINDEX_UTBGVRNS, "06", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       DSIZE,    BATCH,   DFLT,       MAX_RELIN_DEG, FIRST_MOD_SIZE, SEC_LVL, HYBRID, FIXEDMANUAL,     DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { EVALATINDEX_UTBGVRNS, "07", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       DSIZE,    BATCH,   DFLT,       MAX_RELIN_DEG, DFLT,           SEC_LVL, HYBRID, FIXEDAUTO,       DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { EVALATINDEX_UTBGVRNS, "08", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       DSIZE,    BATCH,   DFLT,       MAX_RELIN_DEG, DFLT,           SEC_LVL, HYBRID, FLEXIBLEAUTOEXT, DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    // ==========================================
    // TestType,         Descr,  Scheme,        RDim,     MultDepth,  SModSize,   DSize,    BatchSz, SecKeyDist, MaxRelinSkDeg, FModSize,       SecLvl,  KSTech, ScalTech,        LDigits, PtMod, StdDev, EvalAddCt, KSCt, MultTech, EncTech, PREMode
    { EVALMERGE_UTBGVRNS, "01", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       BV_DSIZE, BATCH,   DFLT,       MAX_RELIN_DEG, DFLT,           SEC_LVL, BV,     FLEXIBLEAUTO,    DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { EVALMERGE_UTBGVRNS, "02", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       BV_DSIZE, BATCH,   DFLT,       MAX_RELIN_DEG, FIRST_MOD_SIZE, SEC_LVL, BV,     FIXEDMANUAL,     DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { EVALMERGE_UTBGVRNS, "03", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       BV_DSIZE, BATCH,   DFLT,       MAX_RELIN_DEG, DFLT,           SEC_LVL, BV,     FIXEDAUTO,       DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { EVALMERGE_UTBGVRNS, "04", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       BV_DSIZE, BATCH,   DFLT,       MAX_RELIN_DEG, DFLT,           SEC_LVL, BV,     FLEXIBLEAUTOEXT, DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { EVALMERGE_UTBGVRNS, "05", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       DSIZE,    BATCH,   DFLT,       MAX_RELIN_DEG, DFLT,           SEC_LVL, HYBRID, FLEXIBLEAUTO,    DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { EVALMERGE_UTBGVRNS, "06", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       DSIZE,    BATCH,   DFLT,       MAX_RELIN_DEG, FIRST_MOD_SIZE, SEC_LVL, HYBRID, FIXEDMANUAL,     DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { EVALMERGE_UTBGVRNS, "07", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       DSIZE,    BATCH,   DFLT,       MAX_RELIN_DEG, DFLT,           SEC_LVL, HYBRID, FIXEDAUTO,       DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { EVALMERGE_UTBGVRNS, "08", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       DSIZE,    BATCH,   DFLT,       MAX_RELIN_DEG, DFLT,           SEC_LVL, HYBRID, FLEXIBLEAUTOEXT, DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    // ==========================================
    // TestType,             Descr,  Scheme,        RDim,     MultDepth,  SModSize,   DSize,    BatchSz, SecKeyDist, MaxRelinSkDeg, FModSize,       SecLvl,  KSTech, ScalTech,        LDigits, PtMod, StdDev, EvalAddCt, KSCt, MultTech, EncTech, PREMode
    { RE_ENCRYPTION_UTBGVRNS, "01", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       BV_DSIZE, BATCH,   DFLT,       MAX_RELIN_DEG, DFLT,           SEC_LVL, BV,     FLEXIBLEAUTO,    DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { RE_ENCRYPTION_UTBGVRNS, "02", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       BV_DSIZE, BATCH,   DFLT,       MAX_RELIN_DEG, FIRST_MOD_SIZE, SEC_LVL, BV,     FIXEDMANUAL,     DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { RE_ENCRYPTION_UTBGVRNS, "03", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       BV_DSIZE, BATCH,   DFLT,       MAX_RELIN_DEG, DFLT,           SEC_LVL, BV,     FIXEDAUTO,       DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { RE_ENCRYPTION_UTBGVRNS, "04", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       BV_DSIZE, BATCH,   DFLT,       MAX_RELIN_DEG, DFLT,           SEC_LVL, BV,     FLEXIBLEAUTOEXT, DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { RE_ENCRYPTION_UTBGVRNS, "05", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       DSIZE,    BATCH,   DFLT,       MAX_RELIN_DEG, DFLT,           SEC_LVL, HYBRID, FLEXIBLEAUTO,    DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,     DFLT,    INDCPA}, },
    { RE_ENCRYPTION_UTBGVRNS, "06", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       DSIZE,    BATCH,   DFLT,       MAX_RELIN_DEG, FIRST_MOD_SIZE, SEC_LVL, HYBRID, FIXEDMANUAL,     DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,     DFLT,    INDCPA}, },
    { RE_ENCRYPTION_UTBGVRNS, "07", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       DSIZE,    BATCH,   DFLT,       MAX_RELIN_DEG, DFLT,           SEC_LVL, HYBRID, FIXEDAUTO,       DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,     DFLT,    INDCPA}, },
    { RE_ENCRYPTION_UTBGVRNS, "08", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       DSIZE,    BATCH,   DFLT,       MAX_RELIN_DEG, DFLT,           SEC_LVL, HYBRID, FLEXIBLEAUTOEXT, DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,     DFLT,    INDCPA}, },
    // ==========================================
    // TestType,                 Descr,  Scheme,        RDim,     MultDepth,  SModSize,   DSize,    BatchSz, SecKeyDist, MaxRelinSkDeg, FModSize,       SecLvl,  KSTech, ScalTech,        LDigits, PtMod, StdDev,   EvalAddCt, KSCt, MultTech, EncTech, PREMode
    { AUTO_LEVEL_REDUCE_UTBGVRNS, "01", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       BV_DSIZE, BATCH,   DFLT,       MAX_RELIN_DEG, DFLT,           SEC_LVL, BV,     FLEXIBLEAUTO,    DFLT,    PTM,   DFLT,     DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { AUTO_LEVEL_REDUCE_UTBGVRNS, "02", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       BV_DSIZE, BATCH,   DFLT,       MAX_RELIN_DEG, FIRST_MOD_SIZE, SEC_LVL, BV,     FIXEDMANUAL,     DFLT,    PTM,   DFLT,     DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { AUTO_LEVEL_REDUCE_UTBGVRNS, "03", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       BV_DSIZE, BATCH,   DFLT,       MAX_RELIN_DEG, DFLT,           SEC_LVL, BV,     FIXEDAUTO,       DFLT,    PTM,   DFLT,     DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { AUTO_LEVEL_REDUCE_UTBGVRNS, "04", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       BV_DSIZE, BATCH,   DFLT,       MAX_RELIN_DEG, DFLT,           SEC_LVL, BV,     FLEXIBLEAUTOEXT, DFLT,    PTM,   DFLT,     DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { AUTO_LEVEL_REDUCE_UTBGVRNS, "05", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       DSIZE,    BATCH,   DFLT,       MAX_RELIN_DEG, DFLT,           SEC_LVL, HYBRID, FLEXIBLEAUTO,    DFLT,    PTM,   DFLT,     DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { AUTO_LEVEL_REDUCE_UTBGVRNS, "06", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       DSIZE,    BATCH,   DFLT,       MAX_RELIN_DEG, FIRST_MOD_SIZE, SEC_LVL, HYBRID, FIXEDMANUAL,     DFLT,    PTM,   DFLT,     DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { AUTO_LEVEL_REDUCE_UTBGVRNS, "07", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       DSIZE,    BATCH,   DFLT,       MAX_RELIN_DEG, DFLT,           SEC_LVL, HYBRID, FIXEDAUTO,       DFLT,    PTM,   DFLT,     DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { AUTO_LEVEL_REDUCE_UTBGVRNS, "08", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       DSIZE,    BATCH,   DFLT,       MAX_RELIN_DEG, DFLT,           SEC_LVL, HYBRID, FLEXIBLEAUTOEXT, DFLT,    PTM,   DFLT,     DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    // ==========================================
    // TestType,        Descr,  Scheme,        RDim,     MultDepth,  SModSize,   DSize,    BatchSz, SecKeyDist, MaxRelinSkDeg, FModSize,       SecLvl,  KSTech, ScalTech,        LDigits, PtMod, StdDev,   EvalAddCt, KSCt, MultTech, EncTech, PREMode
    { COMPRESS_UTBGVRNS, "01", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       BV_DSIZE, BATCH,   DFLT,       MAX_RELIN_DEG, DFLT,           SEC_LVL, BV,     FLEXIBLEAUTO,    DFLT,    PTM,   DFLT,     DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { COMPRESS_UTBGVRNS, "02", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       BV_DSIZE, BATCH,   DFLT,       MAX_RELIN_DEG, FIRST_MOD_SIZE, SEC_LVL, BV,     FIXEDMANUAL,     DFLT,    PTM,   DFLT,     DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { COMPRESS_UTBGVRNS, "03", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       BV_DSIZE, BATCH,   DFLT,       MAX_RELIN_DEG, DFLT,           SEC_LVL, BV,     FIXEDAUTO,       DFLT,    PTM,   DFLT,     DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { COMPRESS_UTBGVRNS, "04", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       BV_DSIZE, BATCH,   DFLT,       MAX_RELIN_DEG, DFLT,           SEC_LVL, BV,     FLEXIBLEAUTOEXT, DFLT,    PTM,   DFLT,     DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { COMPRESS_UTBGVRNS, "05", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       DSIZE,    BATCH,   DFLT,       MAX_RELIN_DEG, DFLT,           SEC_LVL, HYBRID, FLEXIBLEAUTO,    DFLT,    PTM,   DFLT,     DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { COMPRESS_UTBGVRNS, "06", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       DSIZE,    BATCH,   DFLT,       MAX_RELIN_DEG, FIRST_MOD_SIZE, SEC_LVL, HYBRID, FIXEDMANUAL,     DFLT,    PTM,   DFLT,     DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { COMPRESS_UTBGVRNS, "07", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       DSIZE,    BATCH,   DFLT,       MAX_RELIN_DEG, DFLT,           SEC_LVL, HYBRID, FIXEDAUTO,       DFLT,    PTM,   DFLT,     DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { COMPRESS_UTBGVRNS, "08", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       DSIZE,    BATCH,   DFLT,       MAX_RELIN_DEG, DFLT,           SEC_LVL, HYBRID, FLEXIBLEAUTOEXT, DFLT,    PTM,   DFLT,     DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    // ==========================================
    // TestType,                  Descr,  Scheme,        RDim,     MultDepth,  SModSize,   DSize,    BatchSz, SecKeyDist, MaxRelinSkDeg, FModSize,       SecLvl,  KSTech, ScalTech,        LDigits, PtMod, StdDev,   EvalAddCt, KSCt, MultTech, EncTech, PREMode
    { EVAL_FAST_ROTATION_UTBGVRNS, "01", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       BV_DSIZE, BATCH,   DFLT,       MAX_RELIN_DEG, DFLT,           SEC_LVL, BV,     FLEXIBLEAUTO,    DFLT,    PTM,   DFLT,     DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { EVAL_FAST_ROTATION_UTBGVRNS, "02", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       BV_DSIZE, BATCH,   DFLT,       MAX_RELIN_DEG, FIRST_MOD_SIZE, SEC_LVL, BV,     FIXEDMANUAL,     DFLT,    PTM,   DFLT,     DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { EVAL_FAST_ROTATION_UTBGVRNS, "03", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       BV_DSIZE, BATCH,   DFLT,       MAX_RELIN_DEG, DFLT,           SEC_LVL, BV,     FIXEDAUTO,       DFLT,    PTM,   DFLT,     DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { EVAL_FAST_ROTATION_UTBGVRNS, "04", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       BV_DSIZE, BATCH,   DFLT,       MAX_RELIN_DEG, DFLT,           SEC_LVL, BV,     FLEXIBLEAUTOEXT, DFLT,    PTM,   DFLT,     DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { EVAL_FAST_ROTATION_UTBGVRNS, "05", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       DSIZE,    BATCH,   DFLT,       MAX_RELIN_DEG, DFLT,           SEC_LVL, HYBRID, FLEXIBLEAUTO,    DFLT,    PTM,   DFLT,     DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { EVAL_FAST_ROTATION_UTBGVRNS, "06", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       DSIZE,    BATCH,   DFLT,       MAX_RELIN_DEG, FIRST_MOD_SIZE, SEC_LVL, HYBRID, FIXEDMANUAL,     DFLT,    PTM,   DFLT,     DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { EVAL_FAST_ROTATION_UTBGVRNS, "07", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       DSIZE,    BATCH,   DFLT,       MAX_RELIN_DEG, DFLT,           SEC_LVL, HYBRID, FIXEDAUTO,       DFLT,    PTM,   DFLT,     DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { EVAL_FAST_ROTATION_UTBGVRNS, "08", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       DSIZE,    BATCH,   DFLT,       MAX_RELIN_DEG, DFLT,           SEC_LVL, HYBRID, FLEXIBLEAUTOEXT, DFLT,    PTM,   DFLT,     DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    // ==========================================
    // TestType,        Descr,  Scheme,        RDim,     MultDepth,  SModSize,   DSize,    BatchSz, SecKeyDist, MaxRelinSkDeg, FModSize,       SecLvl,  KSTech, ScalTech,        LDigits, PtMod, StdDev,   EvalAddCt, KSCt, MultTech, EncTech, PREMode
    { METADATA_UTBGVRNS, "01", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       BV_DSIZE, BATCH,   DFLT,       MAX_RELIN_DEG, DFLT,           SEC_LVL, BV,     FLEXIBLEAUTO,    DFLT,    PTM,   DFLT,     DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { METADATA_UTBGVRNS, "02", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       BV_DSIZE, BATCH,   DFLT,       MAX_RELIN_DEG, FIRST_MOD_SIZE, SEC_LVL, BV,     FIXEDMANUAL,     DFLT,    PTM,   DFLT,     DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { METADATA_UTBGVRNS, "03", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       BV_DSIZE, BATCH,   DFLT,       MAX_RELIN_DEG, DFLT,           SEC_LVL, BV,     FIXEDAUTO,       DFLT,    PTM,   DFLT,     DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { METADATA_UTBGVRNS, "04", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       BV_DSIZE, BATCH,   DFLT,       MAX_RELIN_DEG, DFLT,           SEC_LVL, BV,     FLEXIBLEAUTOEXT, DFLT,    PTM,   DFLT,     DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { METADATA_UTBGVRNS, "05", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       DSIZE,    BATCH,   DFLT,       MAX_RELIN_DEG, DFLT,           SEC_LVL, HYBRID, FLEXIBLEAUTO,    DFLT,    PTM,   DFLT,     DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { METADATA_UTBGVRNS, "06", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       DSIZE,    BATCH,   DFLT,       MAX_RELIN_DEG, FIRST_MOD_SIZE, SEC_LVL, HYBRID, FIXEDMANUAL,     DFLT,    PTM,   DFLT,     DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { METADATA_UTBGVRNS, "07", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       DSIZE,    BATCH,   DFLT,       MAX_RELIN_DEG, DFLT,           SEC_LVL, HYBRID, FIXEDAUTO,       DFLT,    PTM,   DFLT,     DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { METADATA_UTBGVRNS, "08", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       DSIZE,    BATCH,   DFLT,       MAX_RELIN_DEG, DFLT,           SEC_LVL, HYBRID, FLEXIBLEAUTOEXT, DFLT,    PTM,   DFLT,     DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    // ==========================================
    // TestType,                       Descr,  Scheme,        RDim,     MultDepth,  SModSize,   DSize,    BatchSz, SecKeyDist, MaxRelinSkDeg, FModSize,       SecLvl,  KSTech, ScalTech,        LDigits, PtMod, StdDev,   EvalAddCt, KSCt, MultTech, EncTech, PREMode
    { CRYPTOPARAMS_VALIDATION_UTBGVRNS, "01", {BGVRNS_SCHEME, 3,        MULT_DEPTH, DFLT,       BV_DSIZE, BATCH,   DFLT,       MAX_RELIN_DEG, DFLT,           SEC_LVL, BV,     FLEXIBLEAUTO,    DFLT,    PTM,   DFLT,     DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { CRYPTOPARAMS_VALIDATION_UTBGVRNS, "02", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       BV_DSIZE, BATCH,   DFLT,       MAX_RELIN_DEG, 60,             SEC_LVL, BV,     FIXEDAUTO,       DFLT,    PTM,   DFLT,     DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { CRYPTOPARAMS_VALIDATION_UTBGVRNS, "03", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       BV_DSIZE, BATCH,   DFLT,       MAX_RELIN_DEG, DFLT,           SEC_LVL, BV,     NORESCALE,       DFLT,    PTM,   DFLT,     DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
};
// clang-format on
//===========================================================================================================

class UTBGVRNS : public ::testing::TestWithParam<TEST_CASE_UTBGVRNS> {
    using Element = DCRTPoly;

    // the size for all vectors remains const - 8 elements
    const usint VECTOR_SIZE = 8;

    // The precision after which we consider two values equal. Necessary for the checkEquality() calls
    const double eps = EPSILON;

    const std::vector<int64_t> vectorOfInts0_7{0, 1, 2, 3, 4, 5, 6, 7};
    const std::vector<int64_t> vectorOfInts0_7neg{0, -1, -2, -3, -4, -5, -6, -7};
    const std::vector<int64_t> vectorOfInts7_0{7, 6, 5, 4, 3, 2, 1, 0};

    const std::vector<int64_t> vectorOfInts1_8{1, 2, 3, 4, 5, 6, 7, 8};
    const std::vector<int64_t> vectorOfInts1_8neg{-1, -2, -3, -4, -5, -6, -7, -8};
    const std::vector<int64_t> vectorOfInts8_1{8, 7, 6, 5, 4, 3, 2, 1};

    const std::vector<int64_t> vectorOfInts1s{1, 1, 1, 1, 1, 1, 1, 1};  // all 1's

protected:
    void SetUp() {}

    void TearDown() {
        CryptoContextFactory<DCRTPoly>::ReleaseAllContexts();
    }

    void UnitTest_Add_Packed(const TEST_CASE_UTBGVRNS& testData, const std::string& failmsg = std::string()) {
        try {
            CryptoContext<Element> cc(UnitTestGenerateContext(testData.params));

            std::vector<int64_t> vectorOfInts1(vectorOfInts0_7);
            Plaintext plaintext1 = cc->MakePackedPlaintext(vectorOfInts1);

            std::vector<int64_t> negativeInts1(vectorOfInts0_7neg);
            Plaintext negatives1 = cc->MakePackedPlaintext(negativeInts1);

            std::vector<int64_t> vectorOfInts2(vectorOfInts7_0);
            Plaintext plaintext2 = cc->MakePackedPlaintext(vectorOfInts2);

            std::vector<int64_t> vectorOfIntsAdd{7, 7, 7, 7, 7, 7, 7, 7};  // all 7's
            Plaintext plaintextAdd = cc->MakePackedPlaintext(vectorOfIntsAdd);

            // std::vector<int64_t> vectorOfIntsSub = { -7,-5,-3,-1,1,3,5,7 };
            std::vector<int64_t> vectorOfIntsSub(VECTOR_SIZE);
            for (usint i = 0; i < VECTOR_SIZE; i++) {
                vectorOfIntsSub[i] = (int64_t)(2 * i) - VECTOR_SIZE + 1;
            }
            Plaintext plaintextSub = cc->MakePackedPlaintext(vectorOfIntsSub);

            // Generate encryption keys
            KeyPair<Element> kp = cc->KeyGen();

            // Encrypt plaintexts
            Ciphertext<Element> ciphertext1 = cc->Encrypt(kp.publicKey, plaintext1);
            Ciphertext<Element> ciphertext2 = cc->Encrypt(kp.publicKey, plaintext2);
            Ciphertext<Element> cResult;
            Plaintext results;

            // Testing EvalAdd
            cResult = cc->EvalAdd(ciphertext1, ciphertext2);
            cc->Decrypt(kp.secretKey, cResult, &results);
            results->SetLength(plaintextAdd->GetLength());
            checkEquality(plaintextAdd->GetPackedValue(), results->GetPackedValue(), eps, failmsg + " EvalAdd fails");

            // Testing EvalAddInPlace
            Ciphertext<Element> ciphertext1_clone = ciphertext1->Clone();
            cc->EvalAddInPlace(ciphertext1_clone, ciphertext2);
            cc->Decrypt(kp.secretKey, ciphertext1_clone, &results);
            results->SetLength(plaintextAdd->GetLength());
            checkEquality(plaintextAdd->GetPackedValue(), results->GetPackedValue(), eps,
                          failmsg + " EvalAddInPlace fails");

            // Testing operator+
            cResult = ciphertext1 + ciphertext2;
            cc->Decrypt(kp.secretKey, cResult, &results);
            results->SetLength(plaintextAdd->GetLength());
            checkEquality(plaintextAdd->GetPackedValue(), results->GetPackedValue(), eps, failmsg + " operator+ fails");

            // Testing operator+=
            Ciphertext<Element> caddInplace(ciphertext1);
            caddInplace += ciphertext2;
            cc->Decrypt(kp.secretKey, caddInplace, &results);
            results->SetLength(plaintextAdd->GetLength());
            checkEquality(plaintextAdd->GetPackedValue(), results->GetPackedValue(), eps,
                          failmsg + " operator+= fails");

            // Testing EvalSub
            cResult = cc->EvalSub(ciphertext1, ciphertext2);
            cc->Decrypt(kp.secretKey, cResult, &results);
            results->SetLength(plaintextSub->GetLength());
            checkEquality(plaintextSub->GetPackedValue(), results->GetPackedValue(), eps, failmsg + " EvalSub fails");

            // Testing operator-
            cResult = ciphertext1 - ciphertext2;
            cc->Decrypt(kp.secretKey, cResult, &results);
            results->SetLength(plaintextSub->GetLength());
            checkEquality(plaintextSub->GetPackedValue(), results->GetPackedValue(), eps, failmsg + " operator- fails");

            // Testing operator-=
            Ciphertext<Element> csubInplace(ciphertext1);
            csubInplace -= ciphertext2;
            cc->Decrypt(kp.secretKey, csubInplace, &results);
            results->SetLength(plaintextSub->GetLength());
            checkEquality(plaintextSub->GetPackedValue(), results->GetPackedValue(), eps,
                          failmsg + " operator-= fails");

            // Testing EvalAdd ciphertext + plaintext
            cResult = cc->EvalAdd(ciphertext1, plaintext2);
            cc->Decrypt(kp.secretKey, cResult, &results);
            results->SetLength(plaintextAdd->GetLength());
            checkEquality(plaintextAdd->GetPackedValue(), results->GetPackedValue(), eps,
                          failmsg + " EvalAdd Ct and Pt fails");

            // Testing EvalSub ciphertext - plaintext
            cResult = cc->EvalSub(ciphertext1, plaintext2);
            cc->Decrypt(kp.secretKey, cResult, &results);
            results->SetLength(plaintextSub->GetLength());
            checkEquality(plaintextSub->GetPackedValue(), results->GetPackedValue(), eps,
                          failmsg + " EvalSub Ct and Pt fails");

            // Testing EvalNegate
            cResult = cc->EvalNegate(ciphertext1);
            cc->Decrypt(kp.secretKey, cResult, &results);
            results->SetLength(negatives1->GetLength());
            checkEquality(negatives1->GetPackedValue(), results->GetPackedValue(), eps, failmsg + " EvalNegate fails");
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

    void UnitTest_Mult_Packed(const TEST_CASE_UTBGVRNS& testData, const std::string& failmsg = std::string()) {
        try {
            CryptoContext<Element> cc(UnitTestGenerateContext(testData.params));

            std::vector<int64_t> vectorOfInts1(vectorOfInts0_7);
            Plaintext plaintext1 = cc->MakePackedPlaintext(vectorOfInts1);

            std::vector<int64_t> vectorOfInts2(vectorOfInts7_0);
            Plaintext plaintext2 = cc->MakePackedPlaintext(vectorOfInts2);

            // vectorOfIntsMult = { 0,6,10,12,12,10,6,0 };
            std::vector<int64_t> vectorOfIntsMult(VECTOR_SIZE);
            for (usint i = 0; i < VECTOR_SIZE; i++) {
                vectorOfIntsMult[i] = i * VECTOR_SIZE - i * i - i;
            }
            Plaintext plaintextMult = cc->MakePackedPlaintext(vectorOfIntsMult);

            // Generate encryption keys
            KeyPair<Element> kp = cc->KeyGen();
            // Generate multiplication keys
            cc->EvalMultKeyGen(kp.secretKey);

            // Encrypt plaintexts
            Ciphertext<Element> ciphertext1 = cc->Encrypt(kp.publicKey, plaintext1);
            Ciphertext<Element> ciphertext2 = cc->Encrypt(kp.publicKey, plaintext2);
            Ciphertext<Element> cResult;
            Plaintext results;

            // Testing EvalMult
            cc->EvalMult(ciphertext1, plaintext1);
            cc->EvalMult(ciphertext2, plaintext2);
            cResult = cc->EvalMult(ciphertext1, ciphertext2);
            cc->Decrypt(kp.secretKey, cResult, &results);
            results->SetLength(plaintextMult->GetLength());
            checkEquality(plaintextMult->GetPackedValue(), results->GetPackedValue(), eps, failmsg + " EvalMult fails");

            // Testing operator*
            cResult = ciphertext1 * ciphertext2;
            cc->Decrypt(kp.secretKey, cResult, &results);
            results->SetLength(plaintextMult->GetLength());
            checkEquality(plaintextMult->GetPackedValue(), results->GetPackedValue(), eps,
                          failmsg + " operator* fails");

            // Testing operator*=
            Ciphertext<Element> cmultInplace(ciphertext1);
            cmultInplace *= ciphertext2;
            cc->Decrypt(kp.secretKey, cmultInplace, &results);
            results->SetLength(plaintextMult->GetLength());
            checkEquality(plaintextMult->GetPackedValue(), results->GetPackedValue(), eps,
                          failmsg + " operator*= fails");

            // Testing EvalMult ciphertext * plaintext
            cResult = cc->EvalMult(ciphertext1, plaintext2);
            cc->Decrypt(kp.secretKey, cResult, &results);
            results->SetLength(plaintextMult->GetLength());
            checkEquality(plaintextMult->GetPackedValue(), results->GetPackedValue(), eps,
                          failmsg + " EvalMult Ct and Pt fails");

            // Testing EvalMultNoRelin ciphertext * ciphertext
            cResult = cc->EvalMultNoRelin(ciphertext1, ciphertext2);
            cc->Decrypt(kp.secretKey, cResult, &results);
            results->SetLength(plaintextMult->GetLength());
            checkEquality(plaintextMult->GetPackedValue(), results->GetPackedValue(), eps,
                          failmsg + " EvalMultNoRelin Ct and Ct fails");
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

    void UnitTest_EvalAtIndex(const TEST_CASE_UTBGVRNS& testData, const std::string& failmsg = std::string()) {
        try {
            CryptoContext<Element> cc(UnitTestGenerateContext(testData.params));

            std::vector<int64_t> vectorOfInts1(vectorOfInts1_8);
            Plaintext plaintext1 = cc->MakePackedPlaintext(vectorOfInts1);

            std::vector<int64_t> vOnes(vectorOfInts1s);
            Plaintext pOnes = cc->MakePackedPlaintext(vOnes);

            // vIntsRightShift2 = { 0,0,1,2,3,4,5,6 };
            std::vector<int64_t> vIntsRightShift2(VECTOR_SIZE);
            for (usint i = 0; i < VECTOR_SIZE; i++) {
                vIntsRightShift2[i] = (i >= 2) ? vectorOfInts1[i - 2] : 0;
            }
            Plaintext plaintextRight2 = cc->MakePackedPlaintext(vIntsRightShift2);

            // vIntsLeftShift2 = { 3,4,5,6,7,8,0,0 };
            std::vector<int64_t> vIntsLeftShift2(VECTOR_SIZE);
            for (usint i = 0; i < VECTOR_SIZE; i++) {
                vIntsLeftShift2[i] = (i < VECTOR_SIZE - 2) ? vectorOfInts1[i + 2] : 0;
            }
            Plaintext plaintextLeft2 = cc->MakePackedPlaintext(vIntsLeftShift2);

            // Generate encryption keys
            KeyPair<Element> kp = cc->KeyGen();
            // Generate multiplication keys
            cc->EvalMultKeyGen(kp.secretKey);
            // Generate rotation keys for offsets +2 (left shift) and -2 (right shift)
            cc->EvalAtIndexKeyGen(kp.secretKey, {2, -2});

            // Encrypt plaintexts
            Ciphertext<Element> ciphertext1 = cc->Encrypt(kp.publicKey, plaintext1);
            Ciphertext<Element> cOnes       = cc->Encrypt(kp.publicKey, pOnes);
            Ciphertext<Element> cResult;
            Plaintext results;

            /* First, do one multiplication and apply the rotation to the result.
             * This helps hide the rotation noise and get the correct result without
             * using a smaller digit size in BV (when creating the crypto context cc).
             */
            ciphertext1 *= cOnes;

            // Testing EvalAtIndex +2
            cResult = cc->EvalAtIndex(ciphertext1, 2);
            cc->Decrypt(kp.secretKey, cResult, &results);
            results->SetLength(plaintextLeft2->GetLength());
            checkEquality(plaintextLeft2->GetPackedValue(), results->GetPackedValue(), eps,
                          failmsg + " EvalAtIndex(+2) fails");

            // Testing EvalAtIndex -2
            cResult = cc->EvalAtIndex(ciphertext1, -2);
            cc->Decrypt(kp.secretKey, cResult, &results);
            results->SetLength(plaintextRight2->GetLength());
            checkEquality(plaintextRight2->GetPackedValue(), results->GetPackedValue(), eps,
                          failmsg + " EvalAtIndex(-2) fails");
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

    void UnitTest_EvalMerge(const TEST_CASE_UTBGVRNS& testData, const std::string& failmsg = std::string()) {
        try {
            CryptoContext<Element> cc(UnitTestGenerateContext(testData.params));

            // v* = { i,0,0,0,0,0,0,0 };
            std::vector<int64_t> vOne{1, 0, 0, 0, 0, 0, 0, 0};
            std::vector<int64_t> vTwo{2, 0, 0, 0, 0, 0, 0, 0};
            std::vector<int64_t> vThree{3, 0, 0, 0, 0, 0, 0, 0};
            std::vector<int64_t> vFour{4, 0, 0, 0, 0, 0, 0, 0};
            std::vector<int64_t> vFive{5, 0, 0, 0, 0, 0, 0, 0};
            std::vector<int64_t> vSix{6, 0, 0, 0, 0, 0, 0, 0};
            std::vector<int64_t> vSeven{7, 0, 0, 0, 0, 0, 0, 0};
            std::vector<int64_t> vEight{8, 0, 0, 0, 0, 0, 0, 0};
            Plaintext pOne   = cc->MakePackedPlaintext(vOne);
            Plaintext pTwo   = cc->MakePackedPlaintext(vTwo);
            Plaintext pThree = cc->MakePackedPlaintext(vThree);
            Plaintext pFour  = cc->MakePackedPlaintext(vFour);
            Plaintext pFive  = cc->MakePackedPlaintext(vFive);
            Plaintext pSix   = cc->MakePackedPlaintext(vSix);
            Plaintext pSeven = cc->MakePackedPlaintext(vSeven);
            Plaintext pEight = cc->MakePackedPlaintext(vEight);

            std::vector<int64_t> vMerged(vectorOfInts1_8);
            Plaintext pMerged = cc->MakePackedPlaintext(vMerged);

            std::vector<int64_t> vOnes(vectorOfInts1s);
            Plaintext pOnes = cc->MakePackedPlaintext(vOnes);

            // Generate encryption keys
            KeyPair<Element> kp = cc->KeyGen();
            // Generate multiplication keys
            cc->EvalMultKeyGen(kp.secretKey);
            // Generate rotation keys for all right rotations 1 to 8.
            std::vector<int32_t> indexList{-1, -2, -3, -4, -5, -6, -7, -8};
            cc->EvalAtIndexKeyGen(kp.secretKey, indexList);

            // Encrypt plaintexts
            Ciphertext<Element> cOnes = cc->Encrypt(kp.publicKey, pOnes);
            std::vector<Ciphertext<Element>> ciphertexts;

            // Here, we perform the same trick (mult with one) as in
            // UnitTest_EvalAtiIndex.
            ciphertexts.push_back(cc->Encrypt(kp.publicKey, pOne) * cOnes);
            ciphertexts.push_back(cc->Encrypt(kp.publicKey, pTwo) * cOnes);
            ciphertexts.push_back(cc->Encrypt(kp.publicKey, pThree) * cOnes);
            ciphertexts.push_back(cc->Encrypt(kp.publicKey, pFour) * cOnes);
            ciphertexts.push_back(cc->Encrypt(kp.publicKey, pFive) * cOnes);
            ciphertexts.push_back(cc->Encrypt(kp.publicKey, pSix) * cOnes);
            ciphertexts.push_back(cc->Encrypt(kp.publicKey, pSeven) * cOnes);
            ciphertexts.push_back(cc->Encrypt(kp.publicKey, pEight) * cOnes);
            Plaintext results;

            // Testing EvalMerge
            auto cResult = cc->EvalMerge(ciphertexts);
            cc->Decrypt(kp.secretKey, cResult, &results);
            results->SetLength(pMerged->GetLength());
            checkEquality(pMerged->GetPackedValue(), results->GetPackedValue(), eps, failmsg + " EvalMerge fails");
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

    void UnitTest_ReEncryption(const TEST_CASE_UTBGVRNS& testData, const std::string& failmsg = std::string()) {
        try {
            CryptoContext<Element> cc(UnitTestGenerateContext(testData.params));

            auto ptm                = 10;
            size_t reEncryptVecSize = 128;

            std::vector<int64_t> intvec;
            for (size_t ii = 0; ii < reEncryptVecSize; ii++) {
                intvec.push_back((rand() % (ptm / 2)) * (rand() % 2 ? 1 : -1));  // NOLINT
            }
            Plaintext plaintextInt = cc->MakePackedPlaintext(intvec);

            KeyPair<Element> kp = cc->KeyGen();
            EXPECT_EQ(kp.good(), true) << failmsg << " key generation for scalar encrypt/decrypt failed";

            KeyPair<Element> newKp = cc->KeyGen();
            EXPECT_EQ(newKp.good(), true) << failmsg << " second key generation for scalar encrypt/decrypt failed";

            // This generates the keys which are used to perform the key switching.
            EvalKey<Element> evalKey = cc->ReKeyGen(kp.secretKey, newKp.publicKey);

            Ciphertext<Element> ciphertext   = cc->Encrypt(kp.publicKey, plaintextInt);
            Ciphertext<Element> reCiphertext = cc->ReEncrypt(ciphertext, evalKey);
            Plaintext plaintextIntNew;
            cc->Decrypt(newKp.secretKey, reCiphertext, &plaintextIntNew);
            plaintextIntNew->SetLength(plaintextInt->GetLength());
            auto tmp_a = plaintextIntNew->GetPackedValue();
            auto tmp_b = plaintextInt->GetPackedValue();
            std::stringstream buffer;
            buffer << tmp_b << " - we get: " << tmp_a << std::endl;
            checkEquality(tmp_a, tmp_b, eps, failmsg + " ReEncrypt integer plaintext " + buffer.str());

            Ciphertext<Element> ciphertext2   = cc->Encrypt(kp.publicKey, plaintextInt);
            Ciphertext<Element> reCiphertext2 = cc->ReEncrypt(ciphertext2, evalKey, kp.publicKey);
            Plaintext plaintextIntNew2;
            cc->Decrypt(newKp.secretKey, reCiphertext2, &plaintextIntNew2);
            plaintextIntNew2->SetLength(plaintextInt->GetLength());
            tmp_a = plaintextIntNew2->GetPackedValue();
            tmp_b = plaintextInt->GetPackedValue();
            std::stringstream buffer2;
            buffer2 << tmp_b << " - we get: " << tmp_a << std::endl;
            checkEquality(tmp_a, tmp_b, eps, failmsg + " HRA-secure ReEncrypt integer plaintext " + buffer2.str());
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

    void UnitTest_AutoLevelReduce(const TEST_CASE_UTBGVRNS& testData, const std::string& failmsg = std::string()) {
        try {
            CryptoContext<Element> cc(UnitTestGenerateContext(testData.params));

            std::vector<int64_t> vectorOfInts1(vectorOfInts0_7);
            Plaintext plaintext1 = cc->MakePackedPlaintext(vectorOfInts1);

            std::vector<int64_t> vectorOfInts2(vectorOfInts7_0);
            Plaintext plaintext2 = cc->MakePackedPlaintext(vectorOfInts2);

            std::vector<int64_t> pCtMult(VECTOR_SIZE);
            std::vector<int64_t> pCtMult3(VECTOR_SIZE);
            std::vector<int64_t> pCt3(VECTOR_SIZE);
            std::vector<int64_t> pCt3_b(VECTOR_SIZE);
            std::vector<int64_t> pCt4(VECTOR_SIZE);
            std::vector<int64_t> pCt5(VECTOR_SIZE);
            std::vector<int64_t> pCt6(VECTOR_SIZE);
            std::vector<int64_t> pCt7(VECTOR_SIZE);
            std::vector<int64_t> pCt_5(VECTOR_SIZE);
            std::vector<int64_t> pCt_6(VECTOR_SIZE);
            std::vector<int64_t> pCt_7(VECTOR_SIZE);
            std::vector<int64_t> pCt8(VECTOR_SIZE);
            std::vector<int64_t> pCt9(VECTOR_SIZE);
            std::vector<int64_t> pCt10(VECTOR_SIZE);
            std::vector<int64_t> pCt11(VECTOR_SIZE);
            std::vector<int64_t> pCt12(VECTOR_SIZE);
            std::vector<int64_t> pCt13(VECTOR_SIZE);
            std::vector<int64_t> pCt14(VECTOR_SIZE);
            for (usint i = 0; i < VECTOR_SIZE; i++) {
                pCtMult[i] = vectorOfInts1[i] * vectorOfInts2[i];
                pCt3[i]    = pCtMult[i] + vectorOfInts1[i];
                pCt4[i]    = pCtMult[i] - vectorOfInts1[i];
                pCt5[i]    = pCtMult[i] * vectorOfInts1[i];
                pCt6[i]    = vectorOfInts1[i] + pCtMult[i];
                pCt7[i]    = vectorOfInts1[i] - pCtMult[i];
                auto tmp =
                    (vectorOfInts1[i] * vectorOfInts1[i] + vectorOfInts1[i] * vectorOfInts1[i]) * vectorOfInts1[i];
                pCt_5[i]    = tmp + vectorOfInts2[i];
                pCt_6[i]    = tmp - vectorOfInts2[i];
                pCt_7[i]    = tmp * vectorOfInts2[i];
                pCt8[i]     = vectorOfInts1[i] * pCtMult[i];
                pCtMult3[i] = pCtMult[i] * vectorOfInts1[i] * vectorOfInts1[i];
                pCt9[i]     = pCtMult3[i] + vectorOfInts1[i];
                pCt10[i]    = pCtMult3[i] - vectorOfInts1[i];
                pCt11[i]    = pCtMult3[i] * vectorOfInts1[i];
                pCt12[i]    = vectorOfInts1[i] + pCtMult3[i];
                pCt13[i]    = vectorOfInts1[i] - pCtMult3[i];
                pCt14[i]    = vectorOfInts1[i] * pCtMult3[i];
            }
            Plaintext plaintextCt3  = cc->MakePackedPlaintext(pCt3);
            Plaintext plaintextCt4  = cc->MakePackedPlaintext(pCt4);
            Plaintext plaintextCt5  = cc->MakePackedPlaintext(pCt5);
            Plaintext plaintextCt6  = cc->MakePackedPlaintext(pCt6);
            Plaintext plaintextCt7  = cc->MakePackedPlaintext(pCt7);
            Plaintext plaintextCt_5 = cc->MakePackedPlaintext(pCt_5);
            Plaintext plaintextCt_6 = cc->MakePackedPlaintext(pCt_6);
            Plaintext plaintextCt_7 = cc->MakePackedPlaintext(pCt_7);
            Plaintext plaintextCt8  = cc->MakePackedPlaintext(pCt8);
            Plaintext plaintextCt9  = cc->MakePackedPlaintext(pCt9);
            Plaintext plaintextCt10 = cc->MakePackedPlaintext(pCt10);
            Plaintext plaintextCt11 = cc->MakePackedPlaintext(pCt11);
            Plaintext plaintextCt12 = cc->MakePackedPlaintext(pCt12);
            Plaintext plaintextCt13 = cc->MakePackedPlaintext(pCt13);
            Plaintext plaintextCt14 = cc->MakePackedPlaintext(pCt14);

            // Generate encryption keys
            KeyPair<Element> kp = cc->KeyGen();
            // Generate multiplication keys
            cc->EvalMultKeyGen(kp.secretKey);

            // Encrypt plaintexts
            Ciphertext<Element> ct  = cc->Encrypt(kp.publicKey, plaintext1);
            Ciphertext<Element> ct2 = cc->Encrypt(kp.publicKey, plaintext2);
            Ciphertext<Element> cResult;
            Plaintext results;

            auto ctMul                     = cc->EvalMult(ct, ct2);
            auto ctRed                     = cc->ModReduce(ctMul);
            Ciphertext<Element> ctRedClone = ctRed->Clone();

            auto ct3 = cc->EvalAdd(ctRed, ct);  // Addition with tower diff = 1
            cc->Decrypt(kp.secretKey, ct3, &results);
            results->SetLength(plaintextCt3->GetLength());
            checkEquality(plaintextCt3->GetPackedValue(), results->GetPackedValue(), eps,
                          failmsg + " addition with tower diff = 1 fails");

            cc->EvalAddInPlace(ctRedClone, ct);  // In-place addition with tower diff = 1
            cc->Decrypt(kp.secretKey, ctRedClone, &results);
            results->SetLength(plaintextCt3->GetLength());
            checkEquality(plaintextCt3->GetPackedValue(), results->GetPackedValue(), eps,
                          failmsg + " in-place addition with tower diff = 1 fails");

            auto ct4 = cc->EvalSub(ctRed, ct);  // Subtraction with tower diff = 1
            cc->Decrypt(kp.secretKey, ct4, &results);
            results->SetLength(plaintextCt4->GetLength());
            checkEquality(plaintextCt4->GetPackedValue(), results->GetPackedValue(), eps,
                          failmsg + " subtraction with tower diff = 1 fails");

            auto ct5 = cc->EvalMult(ctRed, ct);  // Multiplication with tower diff = 1
            cc->Decrypt(kp.secretKey, ct5, &results);
            results->SetLength(plaintextCt5->GetLength());
            checkEquality(plaintextCt5->GetPackedValue(), results->GetPackedValue(), eps,
                          failmsg + " multiplication with tower diff = 1 fails");

            auto ct6 = cc->EvalAdd(ct, ctRed);  // Addition with tower diff = 1 (inputs reversed)
            cc->Decrypt(kp.secretKey, ct6, &results);
            results->SetLength(plaintextCt6->GetLength());
            checkEquality(plaintextCt6->GetPackedValue(), results->GetPackedValue(), eps,
                          failmsg + " addition (reverse) with tower diff = 1 fails");

            // In-place addition with tower diff = 1 (inputs reversed)
            auto ct_clone = ct->Clone();
            cc->EvalAddInPlace(ct_clone, ctRed);
            cc->Decrypt(kp.secretKey, ct_clone, &results);
            results->SetLength(plaintextCt6->GetLength());
            checkEquality(plaintextCt6->GetPackedValue(), results->GetPackedValue(), eps,
                          failmsg + " in-place addition (reverse) with tower diff = 1 fails");

            auto ct7 = cc->EvalSub(ct, ctRed);  // Subtraction with tower diff = 1 (inputs reversed)
            cc->Decrypt(kp.secretKey, ct7, &results);
            results->SetLength(plaintextCt7->GetLength());
            checkEquality(plaintextCt7->GetPackedValue(), results->GetPackedValue(), eps,
                          failmsg + " subtraction (reverse) with tower diff = 1 fails");

            auto ct8 = cc->EvalMult(ct, ctRed);  // Multiplication with tower diff = 1 (inputs reversed)
            cc->Decrypt(kp.secretKey, ct8, &results);
            results->SetLength(plaintextCt8->GetLength());
            checkEquality(plaintextCt8->GetPackedValue(), results->GetPackedValue(), eps,
                          failmsg + " multiplication (reverse) with tower diff = 1 fails");

            auto ctMul2       = cc->EvalMult(ctRed, ct);
            auto ctRed2       = cc->ModReduce(ctMul2);
            auto ctMul3       = cc->EvalMult(ctRed2, ct);
            auto ctRed3       = cc->ModReduce(ctMul3);
            auto ctRed3_clone = ctRed3->Clone();

            auto ct9 = cc->EvalAdd(ctRed3, ct);  // Addition with more than 1 level difference
            cc->Decrypt(kp.secretKey, ct9, &results);
            results->SetLength(plaintextCt9->GetLength());
            checkEquality(plaintextCt9->GetPackedValue(), results->GetPackedValue(), eps,
                          failmsg + " addition with tower diff > 1 fails");

            // In-place Addition with more than 1 level difference
            cc->EvalAddInPlace(ctRed3_clone, ct);
            cc->Decrypt(kp.secretKey, ctRed3_clone, &results);
            results->SetLength(plaintextCt9->GetLength());
            checkEquality(plaintextCt9->GetPackedValue(), results->GetPackedValue(), eps,
                          failmsg + " in-place addition with tower diff > 1 fails");

            auto ct10 = cc->EvalSub(ctRed3, ct);  // Subtraction with more than 1 level difference
            cc->Decrypt(kp.secretKey, ct10, &results);
            results->SetLength(plaintextCt10->GetLength());
            checkEquality(plaintextCt10->GetPackedValue(), results->GetPackedValue(), eps,
                          failmsg + " subtraction with tower diff > 1 fails");

            auto ct11 = cc->EvalMult(ctRed3, ct);  // Multiplication with more than 1 level difference
            cc->Decrypt(kp.secretKey, ct11, &results);
            results->SetLength(plaintextCt11->GetLength());
            checkEquality(plaintextCt11->GetPackedValue(), results->GetPackedValue(), eps,
                          failmsg + " multiplication with tower diff > 1 fails");

            // Addition with more than 1 level difference (inputs reversed)
            auto ct12 = cc->EvalAdd(ct, ctRed3);
            cc->Decrypt(kp.secretKey, ct12, &results);
            results->SetLength(plaintextCt12->GetLength());
            checkEquality(plaintextCt12->GetPackedValue(), results->GetPackedValue(), eps,
                          failmsg + " addition (reverse) with tower diff > 1 fails");

            // In-place addition with more than 1 level difference (inputs reversed)
            auto ctClone = ct->Clone();
            cc->EvalAddInPlace(ctClone, ctRed3);
            cc->Decrypt(kp.secretKey, ctClone, &results);
            results->SetLength(plaintextCt12->GetLength());
            checkEquality(plaintextCt12->GetPackedValue(), results->GetPackedValue(), eps,
                          failmsg + " in-place addition (reverse) with tower diff > 1 fails");

            auto ct13 = cc->EvalSub(ct, ctRed3);  // Subtraction with more than 1 level difference (inputs reversed)
            cc->Decrypt(kp.secretKey, ct13, &results);
            results->SetLength(plaintextCt13->GetLength());
            checkEquality(plaintextCt13->GetPackedValue(), results->GetPackedValue(), eps,
                          failmsg + " subtraction (reverse) with tower diff > 1 fails");

            auto ct14 = cc->EvalMult(ct, ctRed3);  // Multiplication with more than 1 level difference (inputs reversed)
            cc->Decrypt(kp.secretKey, ct14, &results);
            results->SetLength(plaintextCt14->GetLength());
            checkEquality(plaintextCt14->GetPackedValue(), results->GetPackedValue(), eps,
                          failmsg + " multiplication (reverse) with tower diff > 1 fails");

            // This scenario tests for operations on
            // ciphertext and plaintext that differ on
            // both scaling factor and number of towers.
            auto ct_1 = cc->EvalMult(ct, plaintext1);
            auto ct_2 = cc->EvalAdd(ct_1, ct_1);
            auto ct_3 = cc->ModReduce(ct_2);
            auto ct_4 = cc->EvalMult(ct_3, plaintext1);
            auto ct_5 = cc->EvalAdd(ct_4, plaintext2);   // Addition with plaintext and tower diff = 1
            auto ct_6 = cc->EvalSub(ct_4, plaintext2);   // Subtraction with plaintext and tower diff = 1
            auto ct_7 = cc->EvalMult(ct_4, plaintext2);  // Multiplication with plaintext and tower diff = 1
            cc->Decrypt(kp.secretKey, ct_5, &results);
            results->SetLength(plaintextCt_5->GetLength());
            checkEquality(plaintextCt_5->GetPackedValue(), results->GetPackedValue(), eps,
                          failmsg + " addition with plaintext and tower diff = 1 fails");

            cc->Decrypt(kp.secretKey, ct_6, &results);
            results->SetLength(plaintextCt_6->GetLength());
            checkEquality(plaintextCt_6->GetPackedValue(), results->GetPackedValue(), eps,
                          failmsg + " subtraction with plaintext and tower diff = 1 fails");

            cc->Decrypt(kp.secretKey, ct_7, &results);
            results->SetLength(plaintextCt_7->GetLength());
            checkEquality(plaintextCt_7->GetPackedValue(), results->GetPackedValue(), eps,
                          failmsg + " multiplication with plaintext and tower diff = 1 fails");
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

    void UnitTest_Compress(const TEST_CASE_UTBGVRNS& testData, const std::string& failmsg = std::string()) {
        try {
            CryptoContext<Element> cc(UnitTestGenerateContext(testData.params));

            std::vector<int64_t> vectorOfInts(vectorOfInts0_7);
            Plaintext plaintext = cc->MakePackedPlaintext(vectorOfInts);

            // Generate encryption keys
            KeyPair<Element> kp = cc->KeyGen();
            // Generate multiplication keys
            cc->EvalMultKeyGen(kp.secretKey);

            // Encrypt plaintexts
            Ciphertext<Element> ct = cc->Encrypt(kp.publicKey, plaintext);
            ct *= ct;
            Ciphertext<Element> cResult;
            Plaintext result;
            Plaintext resultCompressed;
            auto algo           = cc->GetScheme();
            size_t targetTowers = (testData.params.scalTech == FLEXIBLEAUTOEXT) ? 2 : 1;
            auto ctCompressed   = algo->Compress(ct, targetTowers);

            size_t towersLeft = ctCompressed->GetElements()[0].GetNumOfElements();
            EXPECT_TRUE(towersLeft == targetTowers) << " compress fails";

            cc->Decrypt(kp.secretKey, ct, &result);
            cc->Decrypt(kp.secretKey, ctCompressed, &resultCompressed);
            checkEquality(result->GetPackedValue(), resultCompressed->GetPackedValue(), eps,
                          failmsg + " compress fails");
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

    void UnitTest_EvalFastRotation(const TEST_CASE_UTBGVRNS& testData, const std::string& failmsg = std::string()) {
        try {
            CryptoContext<Element> cc(UnitTestGenerateContext(testData.params));

            std::vector<int64_t> vectorOfInts1(vectorOfInts1_8);
            Plaintext plaintext1 = cc->MakePackedPlaintext(vectorOfInts1);

            std::vector<int64_t> vOnes(vectorOfInts1s);
            Plaintext pOnes = cc->MakePackedPlaintext(vOnes);

            // vIntsRightShift2 = { 0,0,1,2,3,4,5,6 };
            std::vector<int64_t> vIntsRightShift2(VECTOR_SIZE);
            for (usint i = 0; i < VECTOR_SIZE; i++) {
                vIntsRightShift2[i] = (i >= 2) ? vectorOfInts1[i - 2] : 0;
            }
            Plaintext plaintextRight2 = cc->MakePackedPlaintext(vIntsRightShift2);

            // vIntsLeftShift2 = { 3,4,5,6,7,8,0,0 };
            std::vector<int64_t> vIntsLeftShift2(VECTOR_SIZE);
            for (usint i = 0; i < VECTOR_SIZE; i++) {
                vIntsLeftShift2[i] = (i < VECTOR_SIZE - 2) ? vectorOfInts1[i + 2] : 0;
            }
            Plaintext plaintextLeft2 = cc->MakePackedPlaintext(vIntsLeftShift2);

            // Generate encryption keys
            KeyPair<Element> kp = cc->KeyGen();
            // Generate multiplication keys
            cc->EvalMultKeyGen(kp.secretKey);
            // Generate rotation keys for offsets +2 (left shift) and -2 (right shift)
            cc->EvalAtIndexKeyGen(kp.secretKey, {2, -2});

            // Encrypt plaintexts
            Ciphertext<Element> ciphertext1 = cc->Encrypt(kp.publicKey, plaintext1);
            Ciphertext<Element> cOnes       = cc->Encrypt(kp.publicKey, pOnes);
            Ciphertext<Element> cResult;
            Plaintext results;

            /* First, do one multiplication and apply the rotation to the result.
             * This helps hide the rotation noise and get the correct result without
             * using a smaller digit size in BV (when creating the crypto context cc).
             */
            ciphertext1 *= cOnes;

            auto decompose = cc->EvalFastRotationPrecompute(ciphertext1);

            usint m = cc->GetCryptoParameters()->GetElementParams()->GetCyclotomicOrder();
            // Testing EvalAtIndex +2
            cResult = cc->EvalFastRotation(ciphertext1, 2, m, decompose);
            cc->Decrypt(kp.secretKey, cResult, &results);
            results->SetLength(plaintextLeft2->GetLength());
            checkEquality(plaintextLeft2->GetPackedValue(), results->GetPackedValue(), eps,
                          failmsg + " EvalAtIndex(+2) fails");

            // Testing EvalAtIndex -2
            cResult = cc->EvalFastRotation(ciphertext1, -2, m, decompose);
            cc->Decrypt(kp.secretKey, cResult, &results);
            results->SetLength(plaintextRight2->GetLength());
            checkEquality(plaintextRight2->GetPackedValue(), results->GetPackedValue(), eps,
                          failmsg + " EvalAtIndex(-2) fails");
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

    void UnitTest_Metadata(const TEST_CASE_UTBGVRNS& testData, const std::string& failmsg = std::string()) {
        try {
            CryptoContext<Element> cc(UnitTestGenerateContext(testData.params));

            std::vector<int64_t> input1(vectorOfInts0_7);
            Plaintext plaintext1 = cc->MakePackedPlaintext(input1);

            std::vector<int64_t> input2(vectorOfInts0_7neg);
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
            for (int i = 0; i < 2; i++)
                weights[i] = i;

            std::vector<Ciphertext<Element>> ciphertexts(2);
            ciphertexts[0] = ciphertext1;
            ciphertexts[1] = ciphertext2;

            // Checking if metadata is carried over in EvalSum
            auto cSum       = cc->EvalSum(ciphertext1, VECTOR_SIZE);
            auto sumValTest = MetadataTest::GetMetadata<Element>(cSum);
            EXPECT_EQ(val1->GetMetadata(), sumValTest->GetMetadata()) << "Ciphertext metadata mismatch in EvalSum";
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

    void UnitTest_CryptoparamsValidation(const TEST_CASE_UTBGVRNS& testData,
                                         const std::string& failmsg = std::string()) {
        try {
            CryptoContext<Element> cc(UnitTestGenerateContext(testData.params));

            // make it fail
            EXPECT_EQ(0, 1);
        }
        catch (OpenFHEException& e) {
            // expected an exception
            EXPECT_TRUE(1 == 1) << failmsg;
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
TEST_P(UTBGVRNS, BGVRNS) {
    setupSignals();
    auto test = GetParam();

    switch (test.testCaseType) {
        case ADD_PACKED_UTBGVRNS:
            UnitTest_Add_Packed(test, test.buildTestName());
            break;
        case MULT_PACKED_UTBGVRNS:
            UnitTest_Mult_Packed(test, test.buildTestName());
            break;
        case EVALATINDEX_UTBGVRNS:
            UnitTest_EvalAtIndex(test, test.buildTestName());
            break;
        case EVALMERGE_UTBGVRNS:
            UnitTest_EvalMerge(test, test.buildTestName());
            break;
        case RE_ENCRYPTION_UTBGVRNS:
            UnitTest_ReEncryption(test, test.buildTestName());
            break;
        case AUTO_LEVEL_REDUCE_UTBGVRNS:
            UnitTest_AutoLevelReduce(test, test.buildTestName());
            break;
        case COMPRESS_UTBGVRNS:
            UnitTest_Compress(test, test.buildTestName());
            break;
        case EVAL_FAST_ROTATION_UTBGVRNS:
            UnitTest_EvalFastRotation(test, test.buildTestName());
            break;
        case METADATA_UTBGVRNS:
            UnitTest_Metadata(test, test.buildTestName());
            break;
        case CRYPTOPARAMS_VALIDATION_UTBGVRNS:
            UnitTest_CryptoparamsValidation(test, test.buildTestName());
            break;
        default:
            break;
    }
}

INSTANTIATE_TEST_SUITE_P(UnitTests, UTBGVRNS, ::testing::ValuesIn(testCasesUTBGVRNS), testName);
