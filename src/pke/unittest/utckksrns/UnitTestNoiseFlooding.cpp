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

#include <cmath>
#include <complex>
#include <cstdint>
#include <functional>
#include <iostream>
#include <iterator>
#include <memory>
#include <sstream>
#include <string>
#include <vector>

#include "UnitTestCCParams.h"
#include "UnitTestCryptoContext.h"
#include "UnitTestUtils.h"
#include "gen-cryptocontext.h"
#include "gtest/gtest.h"
#include "scheme/ckksrns/gen-cryptocontext-ckksrns.h"

using namespace lbcrypto;

//===========================================================================================================
enum TEST_CASE_TYPE : int {
    NOISE_ESTIMATION,
    FULL_NOISE_FLOODING,
    MULTIPARTY_NOISE_FLOODING,
    FLOODING_VARIANCE,
    MULTIPARTY_FLOODING_VARIANCE,
    ESTIMATION_WITH_RESCALE,
    PKE_ONLY_DECRYPT,
    MULTIPARTY_ONLY_DECRYPT,
    TOO_FEW_LIMBS,
    DEGREE_GUARD
};

static std::ostream& operator<<(std::ostream& os, const TEST_CASE_TYPE& type) {
    std::string typeName;
    switch (type) {
        case NOISE_ESTIMATION:
            typeName = "NOISE_ESTIMATION";
            break;
        case FULL_NOISE_FLOODING:
            typeName = "FULL_NOISE_FLOODING";
            break;
        case MULTIPARTY_NOISE_FLOODING:
            typeName = "MULTIPARTY_NOISE_FLOODING";
            break;
        case FLOODING_VARIANCE:
            typeName = "FLOODING_VARIANCE";
            break;
        case MULTIPARTY_FLOODING_VARIANCE:
            typeName = "MULTIPARTY_FLOODING_VARIANCE";
            break;
        case ESTIMATION_WITH_RESCALE:
            typeName = "ESTIMATION_WITH_RESCALE";
            break;
        case PKE_ONLY_DECRYPT:
            typeName = "PKE_ONLY_DECRYPT";
            break;
        case MULTIPARTY_ONLY_DECRYPT:
            typeName = "MULTIPARTY_ONLY_DECRYPT";
            break;
        case TOO_FEW_LIMBS:
            typeName = "TOO_FEW_LIMBS";
            break;
        case DEGREE_GUARD:
            typeName = "DEGREE_GUARD";
            break;
        default:
            typeName = "UNKNOWN";
            break;
    }
    return os << typeName;
}
//===========================================================================================================
struct TEST_CASE_UTCKKSRNS_NOISE_FLOODING {
    TEST_CASE_TYPE testCaseType;
    // test case description - MUST BE UNIQUE
    std::string description;

    UnitTestCCParams params;

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
static auto testName = [](const testing::TestParamInfo<TEST_CASE_UTCKKSRNS_NOISE_FLOODING>& test) {
    return test.param.buildTestName();
};

static std::ostream& operator<<(std::ostream& os, const TEST_CASE_UTCKKSRNS_NOISE_FLOODING& test) {
    return os << test.toString();
}
//===========================================================================================================
constexpr uint32_t MULT_DEPTH = 25;
constexpr uint32_t RDIM = 512;
constexpr uint32_t NUM_LRG_DIGS = 3;
constexpr uint32_t SMODSIZE = 59;
constexpr uint32_t FMODSIZE = 60;
#if NATIVEINT == 64
// composite scaling with compositeDegree = 2: each scaling factor is a product of two primes
constexpr uint32_t COMPOSITE_SMODSIZE = 59;
constexpr uint32_t COMPOSITE_FMODSIZE = 60;
constexpr uint32_t COMPOSITE_REGWORDSIZE = 32;
#endif
// Noise estimates (log2) of the test circuits, measured in EXEC_NOISE_ESTIMATION mode with the parameters above.
// They include the rescale that decryption applies to a ciphertext with a pending rescale.
constexpr double NOISE_ESTIMATE_FLEX_AUTO_EXT = 2.4;
constexpr double NOISE_ESTIMATE = 5.8;
#if NATIVEINT != 128
constexpr double MP_NOISE_ESTIMATE_FLEX_AUTO_EXT = 2;
#endif
constexpr double MP_NOISE_ESTIMATE = 3.5;

// clang-format off
static std::vector<TEST_CASE_UTCKKSRNS_NOISE_FLOODING> testCases = {
    // TestType,       Descr, Scheme,          RDim, MultDepth,  SModSize,     DSize, BatchSz, SecKeyDist,      MaxRelinSkDeg, FModSize,  SecLvl,       KSTech, ScalTech,        LDigits,      PtMod, StdDev, EvalAddCt, KSCt, MultTech, EncTech, PREMode, MultipartyMode, DecryptionNoiseMode,    ExecutionMode,         NoiseEstimate
    { NOISE_ESTIMATION, "01", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,     DFLT,  DFLT,    UNIFORM_TERNARY, DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FIXEDAUTO,       NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT,           NOISE_FLOODING_DECRYPT, EXEC_NOISE_ESTIMATION, DFLT}},
    { NOISE_ESTIMATION, "02", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,     DFLT,  DFLT,    SPARSE_TERNARY,  DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FIXEDAUTO,       NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT,           NOISE_FLOODING_DECRYPT, EXEC_NOISE_ESTIMATION, DFLT}},
    { NOISE_ESTIMATION, "03", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,     DFLT,  DFLT,    UNIFORM_TERNARY, DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FIXEDMANUAL,     NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT,           NOISE_FLOODING_DECRYPT, EXEC_NOISE_ESTIMATION, DFLT}},
    { NOISE_ESTIMATION, "04", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,     DFLT,  DFLT,    SPARSE_TERNARY,  DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FIXEDMANUAL,     NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT,           NOISE_FLOODING_DECRYPT, EXEC_NOISE_ESTIMATION, DFLT}},
#if NATIVEINT != 128
    { NOISE_ESTIMATION, "05", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,     DFLT,  DFLT,    SPARSE_TERNARY,  DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FLEXIBLEAUTO,    NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT,           NOISE_FLOODING_DECRYPT, EXEC_NOISE_ESTIMATION, DFLT}},
    { NOISE_ESTIMATION, "06", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,     DFLT,  DFLT,    UNIFORM_TERNARY, DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FLEXIBLEAUTO,    NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT,           NOISE_FLOODING_DECRYPT, EXEC_NOISE_ESTIMATION, DFLT}},
    { NOISE_ESTIMATION, "07", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,     DFLT,  DFLT,    SPARSE_TERNARY,  DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FLEXIBLEAUTOEXT, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT,           NOISE_FLOODING_DECRYPT, EXEC_NOISE_ESTIMATION, DFLT}},
    { NOISE_ESTIMATION, "08", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,     DFLT,  DFLT,    UNIFORM_TERNARY, DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FLEXIBLEAUTOEXT, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT,           NOISE_FLOODING_DECRYPT, EXEC_NOISE_ESTIMATION, DFLT}},
#endif
    // TestType,          Descr, Scheme,          RDim, MultDepth,  SModSize,     DSize, BatchSz, SecKeyDist,      MaxRelinSkDeg, FModSize,  SecLvl,       KSTech, ScalTech,        LDigits,      PtMod, StdDev, EvalAddCt, KSCt, MultTech, EncTech, PREMode, MultipartyMode, DecryptionNoiseMode,    ExecutionMode,   NoiseEstimate
    { FULL_NOISE_FLOODING, "01", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,     DFLT,  DFLT,    UNIFORM_TERNARY, DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FIXEDAUTO,       NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT,           NOISE_FLOODING_DECRYPT, EXEC_EVALUATION, NOISE_ESTIMATE}},
    { FULL_NOISE_FLOODING, "02", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,     DFLT,  DFLT,    SPARSE_TERNARY,  DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FIXEDAUTO,       NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT,           NOISE_FLOODING_DECRYPT, EXEC_EVALUATION, NOISE_ESTIMATE}},
    { FULL_NOISE_FLOODING, "03", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,     DFLT,  DFLT,    UNIFORM_TERNARY, DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FIXEDMANUAL,     NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT,           NOISE_FLOODING_DECRYPT, EXEC_EVALUATION, NOISE_ESTIMATE}},
    { FULL_NOISE_FLOODING, "04", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,     DFLT,  DFLT,    SPARSE_TERNARY,  DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FIXEDMANUAL,     NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT,           NOISE_FLOODING_DECRYPT, EXEC_EVALUATION, NOISE_ESTIMATE}},
#if NATIVEINT != 128
    { FULL_NOISE_FLOODING, "05", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,     DFLT,  DFLT,    SPARSE_TERNARY,  DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FLEXIBLEAUTO,    NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT,           NOISE_FLOODING_DECRYPT, EXEC_EVALUATION, NOISE_ESTIMATE}},
    { FULL_NOISE_FLOODING, "06", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,     DFLT,  DFLT,    UNIFORM_TERNARY, DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FLEXIBLEAUTO,    NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT,           NOISE_FLOODING_DECRYPT, EXEC_EVALUATION, NOISE_ESTIMATE}},
    { FULL_NOISE_FLOODING, "07", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,     DFLT,  DFLT,    SPARSE_TERNARY,  DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FLEXIBLEAUTOEXT, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT,           NOISE_FLOODING_DECRYPT, EXEC_EVALUATION, NOISE_ESTIMATE_FLEX_AUTO_EXT}},
    { FULL_NOISE_FLOODING, "08", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,     DFLT,  DFLT,    UNIFORM_TERNARY, DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FLEXIBLEAUTOEXT, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT,           NOISE_FLOODING_DECRYPT, EXEC_EVALUATION, NOISE_ESTIMATE_FLEX_AUTO_EXT}},
#endif
    // TestType,                Descr, Scheme,          RDim, MultDepth,  SModSize,     DSize, BatchSz, SecKeyDist,      MaxRelinSkDeg, FModSize,  SecLvl,       KSTech, ScalTech,        LDigits,      PtMod, StdDev, EvalAddCt, KSCt, MultTech, EncTech, PREMode, MultipartyMode, DecryptionNoiseMode,    ExecutionMode,
    { MULTIPARTY_NOISE_FLOODING, "01", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,     DFLT,  DFLT,    UNIFORM_TERNARY, DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FIXEDAUTO,       NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT,           NOISE_FLOODING_DECRYPT, EXEC_EVALUATION, MP_NOISE_ESTIMATE}},
    { MULTIPARTY_NOISE_FLOODING, "02", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,     DFLT,  DFLT,    SPARSE_TERNARY,  DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FIXEDAUTO,       NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT,           NOISE_FLOODING_DECRYPT, EXEC_EVALUATION, MP_NOISE_ESTIMATE}},
    { MULTIPARTY_NOISE_FLOODING, "03", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,     DFLT,  DFLT,    UNIFORM_TERNARY, DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FIXEDMANUAL,     NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT,           NOISE_FLOODING_DECRYPT, EXEC_EVALUATION, MP_NOISE_ESTIMATE}},
    { MULTIPARTY_NOISE_FLOODING, "04", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,     DFLT,  DFLT,    SPARSE_TERNARY,  DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FIXEDMANUAL,     NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT,           NOISE_FLOODING_DECRYPT, EXEC_EVALUATION, MP_NOISE_ESTIMATE}},
#if NATIVEINT != 128
    { MULTIPARTY_NOISE_FLOODING, "05", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,     DFLT,  DFLT,    SPARSE_TERNARY,  DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FLEXIBLEAUTO,    NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT,           NOISE_FLOODING_DECRYPT, EXEC_EVALUATION, MP_NOISE_ESTIMATE}},
    { MULTIPARTY_NOISE_FLOODING, "06", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,     DFLT,  DFLT,    UNIFORM_TERNARY, DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FLEXIBLEAUTO,    NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT,           NOISE_FLOODING_DECRYPT, EXEC_EVALUATION, MP_NOISE_ESTIMATE}},
    { MULTIPARTY_NOISE_FLOODING, "07", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,     DFLT,  DFLT,    SPARSE_TERNARY,  DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FLEXIBLEAUTOEXT, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT,           NOISE_FLOODING_DECRYPT, EXEC_EVALUATION, MP_NOISE_ESTIMATE_FLEX_AUTO_EXT}},
    { MULTIPARTY_NOISE_FLOODING, "08", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,     DFLT,  DFLT,    UNIFORM_TERNARY, DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FLEXIBLEAUTOEXT, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT,           NOISE_FLOODING_DECRYPT, EXEC_EVALUATION, MP_NOISE_ESTIMATE_FLEX_AUTO_EXT}},

#endif
    // TestType,           Descr, Scheme,          RDim, MultDepth,  SModSize,     DSize, BatchSz, SecKeyDist,      MaxRelinSkDeg, FModSize,  SecLvl,       KSTech, ScalTech,        LDigits,      PtMod, StdDev, EvalAddCt, KSCt, MultTech, EncTech, PREMode, MultipartyMode, DecryptionNoiseMode,    ExecutionMode,
    { FLOODING_VARIANCE,    "01", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,     DFLT,  DFLT,    UNIFORM_TERNARY, DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FIXEDAUTO,       NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT,           NOISE_FLOODING_DECRYPT, EXEC_EVALUATION, NOISE_ESTIMATE}},
    { FLOODING_VARIANCE,    "02", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,     DFLT,  DFLT,    UNIFORM_TERNARY, DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FIXEDMANUAL,     NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT,           NOISE_FLOODING_DECRYPT, EXEC_EVALUATION, NOISE_ESTIMATE}},
#if NATIVEINT != 128
    { FLOODING_VARIANCE,    "03", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,     DFLT,  DFLT,    UNIFORM_TERNARY, DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FLEXIBLEAUTO,    NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT,           NOISE_FLOODING_DECRYPT, EXEC_EVALUATION, NOISE_ESTIMATE}},
    { FLOODING_VARIANCE,    "04", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,     DFLT,  DFLT,    UNIFORM_TERNARY, DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FLEXIBLEAUTOEXT, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT,           NOISE_FLOODING_DECRYPT, EXEC_EVALUATION, NOISE_ESTIMATE_FLEX_AUTO_EXT}},
#endif
#if NATIVEINT == 64
    // composite scaling: every rescale drops compositeDegree = 2 towers
    { FLOODING_VARIANCE, "05", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, COMPOSITE_SMODSIZE, DFLT,  DFLT,    UNIFORM_TERNARY, DFLT,          COMPOSITE_FMODSIZE, HEStd_NotSet, HYBRID, COMPOSITESCALINGMANUAL, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT,           NOISE_FLOODING_DECRYPT, EXEC_EVALUATION, NOISE_ESTIMATE, COMPOSITE_REGWORDSIZE, 2}},
#endif
    // threshold decryption of a ciphertext with a pending rescale, repeated to measure the flooding noise
    { MULTIPARTY_FLOODING_VARIANCE, "01", {CKKSRNS_SCHEME, RDIM, 1,          SMODSIZE,     DFLT,  DFLT,    UNIFORM_TERNARY, DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FIXEDAUTO,       DFLT,         DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT,           NOISE_FLOODING_DECRYPT, EXEC_EVALUATION, MP_NOISE_ESTIMATE}},
#if NATIVEINT != 128
    { MULTIPARTY_FLOODING_VARIANCE, "02", {CKKSRNS_SCHEME, RDIM, 1,          SMODSIZE,     DFLT,  DFLT,    UNIFORM_TERNARY, DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FLEXIBLEAUTOEXT, DFLT,         DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT,           NOISE_FLOODING_DECRYPT, EXEC_EVALUATION, MP_NOISE_ESTIMATE_FLEX_AUTO_EXT}},
#endif
    // the noise estimate of a ciphertext with a pending rescale has to include the rescale done by decryption
    { ESTIMATION_WITH_RESCALE, "01", {CKKSRNS_SCHEME, RDIM, 1,          SMODSIZE,     DFLT,  DFLT,    UNIFORM_TERNARY, DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FIXEDAUTO,       DFLT,         DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT,           NOISE_FLOODING_DECRYPT, EXEC_NOISE_ESTIMATION, DFLT}},
#if NATIVEINT != 128
    { ESTIMATION_WITH_RESCALE, "02", {CKKSRNS_SCHEME, RDIM, 1,          SMODSIZE,     DFLT,  DFLT,    UNIFORM_TERNARY, DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FLEXIBLEAUTOEXT, DFLT,         DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT,           NOISE_FLOODING_DECRYPT, EXEC_NOISE_ESTIMATION, DFLT}},
#endif
    // decryption of a ciphertext with a pending rescale in a context that does not enable LEVELEDSHE
    { PKE_ONLY_DECRYPT, "01", {CKKSRNS_SCHEME, RDIM, 1,          SMODSIZE,     DFLT,  DFLT,    UNIFORM_TERNARY, DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FIXEDAUTO,       DFLT,         DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT,           NOISE_FLOODING_DECRYPT, EXEC_EVALUATION, NOISE_ESTIMATE}},
    { MULTIPARTY_ONLY_DECRYPT, "01", {CKKSRNS_SCHEME, RDIM, 1,          SMODSIZE,     DFLT,  DFLT,    UNIFORM_TERNARY, DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FIXEDAUTO,       DFLT,         DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT,           NOISE_FLOODING_DECRYPT, EXEC_EVALUATION, MP_NOISE_ESTIMATE}},
#if NATIVEINT != 128
    // a fresh FLEXIBLEAUTOEXT ciphertext has noise scaling degree 2
    { PKE_ONLY_DECRYPT, "02", {CKKSRNS_SCHEME, RDIM, 1,          SMODSIZE,     DFLT,  DFLT,    UNIFORM_TERNARY, DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FLEXIBLEAUTOEXT, DFLT,         DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT,           NOISE_FLOODING_DECRYPT, EXEC_EVALUATION, NOISE_ESTIMATE_FLEX_AUTO_EXT}},
    { MULTIPARTY_ONLY_DECRYPT, "02", {CKKSRNS_SCHEME, RDIM, 1,          SMODSIZE,     DFLT,  DFLT,    UNIFORM_TERNARY, DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FLEXIBLEAUTOEXT, DFLT,         DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT,           NOISE_FLOODING_DECRYPT, EXEC_EVALUATION, MP_NOISE_ESTIMATE_FLEX_AUTO_EXT}},
#endif
    // failure paths: no tower left for the rescale (multiplicative depth 0), and a direct scheme-level Decrypt
    { TOO_FEW_LIMBS, "01", {CKKSRNS_SCHEME, RDIM, 0,          SMODSIZE,     DFLT,  DFLT,    UNIFORM_TERNARY, DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FIXEDMANUAL,     DFLT,         DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT,           NOISE_FLOODING_DECRYPT, EXEC_EVALUATION, NOISE_ESTIMATE}},
    { DEGREE_GUARD, "01", {CKKSRNS_SCHEME, RDIM, 1,          SMODSIZE,     DFLT,  DFLT,    UNIFORM_TERNARY, DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FIXEDMANUAL,     DFLT,         DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT,           NOISE_FLOODING_DECRYPT, EXEC_EVALUATION, NOISE_ESTIMATE}},
};
// clang-format on
//===========================================================================================================
class UTCKKSRNS_NOISE_FLOODING : public ::testing::TestWithParam<TEST_CASE_UTCKKSRNS_NOISE_FLOODING> {
    using Element = DCRTPoly;

    // The precision after which we consider two values equal.
    // This is necessary because CKKS works for approximate numbers.
    const double eps = 0.0001;
    const double buffer = 1;

    Ciphertext<DCRTPoly> EncryptedComputation(CryptoContext<DCRTPoly>& cryptoContext, PublicKey<DCRTPoly> publicKey) {
        // Encoding and encryption of inputs
        // Generate random input
        std::vector<double> vec1 = {0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8};
        std::vector<double> vec2 = {1, 1, 0, 0, 1, 0, 0, 1};

        // Encoding as plaintexts and encrypt
        Plaintext ptxt1 = cryptoContext->MakeCKKSPackedPlaintext(vec1);
        Plaintext ptxt2 = cryptoContext->MakeCKKSPackedPlaintext(vec2);
        Ciphertext<DCRTPoly> ciph1 = cryptoContext->Encrypt(publicKey, ptxt1);
        Ciphertext<DCRTPoly> ciph2 = cryptoContext->Encrypt(publicKey, ptxt2);

        Ciphertext<DCRTPoly> ciphMult = cryptoContext->EvalMult(ciph1, ciph2);
        cryptoContext->ModReduceInPlace(ciphMult);
        Ciphertext<DCRTPoly> ciphMult2 = cryptoContext->EvalMult(ciphMult, ciph1);
        cryptoContext->ModReduceInPlace(ciphMult2);
        Ciphertext<DCRTPoly> ciphResult = cryptoContext->EvalAdd(ciphMult2, ciph2);

        return ciphResult;
    }

    Ciphertext<DCRTPoly> EncryptedMultipartyComputation(CryptoContext<DCRTPoly>& cryptoContext,
                                                        PublicKey<DCRTPoly> publicKey) {
        // Encoding and encryption of inputs
        // Generate random input
        std::vector<double> vec1 = {0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8};
        std::vector<double> vec2 = {1, 1, 0, 0, 1, 0, 0, 1};

        // Encoding as plaintexts and encrypt
        Plaintext ptxt1 = cryptoContext->MakeCKKSPackedPlaintext(vec1);
        Plaintext ptxt2 = cryptoContext->MakeCKKSPackedPlaintext(vec2);
        Ciphertext<DCRTPoly> ciph1 = cryptoContext->Encrypt(publicKey, ptxt1);
        Ciphertext<DCRTPoly> ciph2 = cryptoContext->Encrypt(publicKey, ptxt2);

        Ciphertext<DCRTPoly> ciphMult = cryptoContext->EvalMult(ciph1, ciph2);
        return ciphMult;
    }

    void GenerateMultipartyKeys(CryptoContext<DCRTPoly>& cryptoContext, KeyPair<DCRTPoly> kp1, KeyPair<DCRTPoly> kp2) {
        auto evalMultKey = cryptoContext->KeySwitchGen(kp1.secretKey, kp1.secretKey);
        auto evalMultKey2 = cryptoContext->MultiKeySwitchGen(kp2.secretKey, kp2.secretKey, evalMultKey);
        auto evalMultAB = cryptoContext->MultiAddEvalKeys(evalMultKey, evalMultKey2, kp2.publicKey->GetKeyTag());
        auto evalMultBAB = cryptoContext->MultiMultEvalKey(kp2.secretKey, evalMultAB, kp2.publicKey->GetKeyTag());
        auto evalMultAAB = cryptoContext->MultiMultEvalKey(kp1.secretKey, evalMultAB, kp2.publicKey->GetKeyTag());
        auto evalMultFinal = cryptoContext->MultiAddEvalMultKeys(evalMultAAB, evalMultBAB, evalMultAB->GetKeyTag());
        cryptoContext->InsertEvalMultKey({evalMultFinal});
    }

    // Sample mean and standard deviation of slot 0 over repeated decryptions of the same ciphertext;
    // decrypt() returns the decrypted plaintext.
    template <typename DecryptFn>
    static void SlotZeroStats(DecryptFn&& decrypt, double& mean, double& stddev) {
        const size_t reps = 100;
        std::vector<double> samples;
        samples.reserve(reps);
        for (size_t i = 0; i < reps; ++i) {
            Plaintext result = decrypt();
            result->SetLength(8);
            samples.push_back(result->GetCKKSPackedValue()[0].real());
        }
        mean = 0;
        for (double s : samples)
            mean += s;
        mean /= reps;
        double var = 0;
        for (double s : samples)
            var += (s - mean) * (s - mean);
        stddev = std::sqrt(var / (reps - 1));
    }

    // Predicted deviation of a decrypted slot: the flooding noise of floodingStd per coefficient spreads over the
    // ring dimension in the slot domain and is divided by one scaling factor during decoding. Every party of a
    // threshold decryption adds its own flooding noise.
    static double ExpectedFloodingStd(const CryptoContext<DCRTPoly>& cc, uint32_t numParties = 1) {
        const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersRNS>(cc->GetCryptoParameters());
        double floodingStd = cryptoParams->GetFloodingDistributionParameter();
        double scalingFactor = std::pow(2.0, static_cast<double>(cc->GetEncodingParams()->GetPlaintextModulus()));
        return std::sqrt(static_cast<double>(numParties)) * floodingStd *
               std::sqrt(static_cast<double>(cc->GetRingDimension())) / scalingFactor;
    }

    // A plaintext that encrypts to a ciphertext with noise scaling degree 2. A fresh FLEXIBLEAUTOEXT plaintext
    // already has degree 2; for the other scaling techniques the degree is requested explicitly.
    static Plaintext MakeDegree2Plaintext(const CryptoContext<DCRTPoly>& cc, const std::vector<double>& vec,
                                          ScalingTechnique scalTech) {
        return (scalTech == FLEXIBLEAUTOEXT) ? cc->MakeCKKSPackedPlaintext(vec) : cc->MakeCKKSPackedPlaintext(vec, 2);
    }

    // Generates the context of a test case without enabling any feature. UnitTestGenerateContext enables all of
    // them, which hides a decryption path that depends on a feature the application did not enable.
    static CryptoContext<DCRTPoly> GenerateContextWithoutFeatures(const UnitTestCCParams& params) {
        CCParams<CryptoContextCKKSRNS> parameters;
        parameters.SetRingDim(static_cast<uint32_t>(params.ringDimension));
        parameters.SetMultiplicativeDepth(static_cast<uint32_t>(params.multiplicativeDepth));
        parameters.SetScalingModSize(static_cast<uint32_t>(params.scalingModSize));
        parameters.SetFirstModSize(static_cast<uint32_t>(params.firstModSize));
        parameters.SetSecurityLevel(static_cast<SecurityLevel>(static_cast<int>(params.securityLevel)));
        parameters.SetSecretKeyDist(static_cast<SecretKeyDist>(static_cast<int>(params.secretKeyDist)));
        parameters.SetKeySwitchTechnique(static_cast<KeySwitchTechnique>(static_cast<int>(params.ksTech)));
        parameters.SetScalingTechnique(static_cast<ScalingTechnique>(static_cast<int>(params.scalTech)));
        if (!isDefaultValue(params.numLargeDigits))
            parameters.SetNumLargeDigits(static_cast<uint32_t>(params.numLargeDigits));
        parameters.SetDecryptionNoiseMode(
                static_cast<DecryptionNoiseMode>(static_cast<int>(params.decryptionNoiseMode)));
        parameters.SetExecutionMode(static_cast<ExecutionMode>(static_cast<int>(params.executionMode)));
        parameters.SetNoiseEstimate(params.noiseEstimate);
        return GenCryptoContext(parameters);
    }

  protected:
    void SetUp() {
        OpenFHEParallelControls.UnitTestStart();
    }

    void TearDown() {
        CryptoContextFactory<DCRTPoly>::ReleaseAllContexts();
        OpenFHEParallelControls.UnitTestStop();
    }

    void UnitTest_NoiseEstimation(const TEST_CASE_UTCKKSRNS_NOISE_FLOODING& testData,
                                  const std::string& failmsg = std::string()) {
        try {
            CryptoContext<DCRTPoly> cc(UnitTestGenerateContext(testData.params));
            cc->Enable(PKE);
            cc->Enable(LEVELEDSHE);

            auto keyPair = cc->KeyGen();
            cc->EvalMultKeyGen(keyPair.secretKey);

            auto noiseCiphertext = EncryptedComputation(cc, keyPair.publicKey);

            Plaintext noisePlaintext;
            cc->Decrypt(keyPair.secretKey, noiseCiphertext, &noisePlaintext);
            double noise = noisePlaintext->GetLogError();
            double expectedNoise =
                    testData.params.scalTech == FLEXIBLEAUTOEXT ? NOISE_ESTIMATE_FLEX_AUTO_EXT : NOISE_ESTIMATE;
            EXPECT_TRUE(checkEquality(noise, expectedNoise, buffer)) << failmsg + " CKKS Noise estimation fails";
        } catch (std::exception& e) {
            std::cerr << "Exception thrown from " << __func__ << "(): " << e.what() << std::endl;
            // make it fail
            EXPECT_TRUE(0 == 1) << failmsg;
        } catch (...) {
            UNIT_TEST_HANDLE_ALL_EXCEPTIONS;
        }
    }
    void UnitTest_FullNoiseFlooding(const TEST_CASE_UTCKKSRNS_NOISE_FLOODING& testData,
                                    const std::string& failmsg = std::string()) {
        CryptoContext<DCRTPoly> cc(UnitTestGenerateContext(testData.params));
        cc->Enable(PKE);
        cc->Enable(LEVELEDSHE);

        auto keyPair = cc->KeyGen();
        cc->EvalMultKeyGen(keyPair.secretKey);

        auto ciphertextResult = EncryptedComputation(cc, keyPair.publicKey);

        Plaintext result;
        cc->Decrypt(keyPair.secretKey, ciphertextResult, &result);
        size_t vecSize = 8;
        result->SetLength(vecSize);

        std::vector<std::complex<double>> expectedResult = {1.01, 1.04, 0, 0, 1.25, 0, 0, 1.64};

        checkEquality(result->GetCKKSPackedValue(), expectedResult, eps, failmsg + " Noise flooding computation fails");
    }

    void UnitTest_FloodingVariance(const TEST_CASE_UTCKKSRNS_NOISE_FLOODING& testData,
                                   const std::string& failmsg = std::string()) {
        try {
            CryptoContext<DCRTPoly> cc(UnitTestGenerateContext(testData.params));
            cc->Enable(PKE);
            cc->Enable(LEVELEDSHE);

            auto keyPair = cc->KeyGen();
            cc->EvalMultKeyGen(keyPair.secretKey);

            // a circuit whose output carries a pending rescale (noise scaling degree 2) under every
            // scaling technique; the flooding noise of such an output is suppressed during decoding
            // unless the ciphertext is rescaled before the noise is added
            std::vector<double> vec1 = {0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8};
            std::vector<double> vec2 = {1, 1, 0, 0, 1, 0, 0, 1};
            Ciphertext<DCRTPoly> ciph1 = cc->Encrypt(keyPair.publicKey, cc->MakeCKKSPackedPlaintext(vec1));
            Ciphertext<DCRTPoly> ciph2 = cc->Encrypt(keyPair.publicKey, cc->MakeCKKSPackedPlaintext(vec2));
            Ciphertext<DCRTPoly> ciphMult = cc->EvalMult(ciph1, ciph2);
            cc->ModReduceInPlace(ciphMult);  // rescales under FIXEDMANUAL only
            Ciphertext<DCRTPoly> ciphertext = cc->EvalMult(ciphMult, ciph1);
            EXPECT_EQ(ciphertext->GetNoiseScaleDeg(), 2u) << failmsg + " ciphertext does not carry a pending rescale";

            double mean = 0, stddev = 0;
            SlotZeroStats(
                    [&]() {
                        Plaintext result;
                        cc->Decrypt(keyPair.secretKey, ciphertext, &result);
                        return result;
                    },
                    mean, stddev);

            // the flooding-off deviation is several orders of magnitude below the predicted one
            double expectedStd = ExpectedFloodingStd(cc);

            EXPECT_GT(stddev, expectedStd / 8) << failmsg + " flooding noise is missing from repeated decryptions";
            EXPECT_LT(stddev, expectedStd * 8) << failmsg + " flooding noise is much larger than calibrated";
            // slot 0 of the computation is 0.1 * 1 * 0.1; the flooding noise must not destroy accuracy
            EXPECT_NEAR(mean, 0.01, 0.0001) << failmsg + " decrypted value is inaccurate";
        } catch (std::exception& e) {
            std::cerr << "Exception thrown from " << __func__ << "(): " << e.what() << std::endl;
            // make it fail
            EXPECT_TRUE(0 == 1) << failmsg;
        } catch (...) {
            UNIT_TEST_HANDLE_ALL_EXCEPTIONS;
        }
    }

    void UnitTest_MultipartyFloodingVariance(const TEST_CASE_UTCKKSRNS_NOISE_FLOODING& testData,
                                             const std::string& failmsg = std::string()) {
        try {
            CryptoContext<DCRTPoly> cc(UnitTestGenerateContext(testData.params));
            cc->Enable(PKE);
            cc->Enable(LEVELEDSHE);
            cc->Enable(MULTIPARTY);

            auto kp1 = cc->KeyGen();
            KeyPair<Element> kp2 = cc->MultipartyKeyGen(kp1.publicKey, false, true);
            GenerateMultipartyKeys(cc, kp1, kp2);
            auto pubKeyForEncryption = cc->MultiAddPubKeys(kp1.publicKey, kp2.publicKey, kp2.publicKey->GetKeyTag());

            // the output of EvalMult carries a pending rescale under every scaling technique
            auto ciphertext = EncryptedMultipartyComputation(cc, pubKeyForEncryption);
            EXPECT_EQ(ciphertext->GetNoiseScaleDeg(), 2u) << failmsg + " ciphertext does not carry a pending rescale";

            double mean = 0, stddev = 0;
            SlotZeroStats(
                    [&]() {
                        Plaintext result;
                        auto partial1 = cc->MultipartyDecryptLead({ciphertext}, kp1.secretKey);
                        auto partial2 = cc->MultipartyDecryptMain({ciphertext}, kp2.secretKey);
                        cc->MultipartyDecryptFusion({partial1[0], partial2[0]}, &result);
                        return result;
                    },
                    mean, stddev);

            // both parties add flooding noise to their decryption shares
            double expectedStd = ExpectedFloodingStd(cc, 2);

            EXPECT_GT(stddev, expectedStd / 8) << failmsg + " flooding noise is missing from repeated decryptions";
            EXPECT_LT(stddev, expectedStd * 8) << failmsg + " flooding noise is much larger than calibrated";
            // slot 0 of the computation is 0.1 * 1; the flooding noise must not destroy accuracy
            EXPECT_NEAR(mean, 0.1, 0.0001) << failmsg + " decrypted value is inaccurate";
        } catch (std::exception& e) {
            std::cerr << "Exception thrown from " << __func__ << "(): " << e.what() << std::endl;
            // make it fail
            EXPECT_TRUE(0 == 1) << failmsg;
        } catch (...) {
            UNIT_TEST_HANDLE_ALL_EXCEPTIONS;
        }
    }

    void UnitTest_EstimationWithRescale(const TEST_CASE_UTCKKSRNS_NOISE_FLOODING& testData,
                                        const std::string& failmsg = std::string()) {
        try {
            CryptoContext<DCRTPoly> cc(UnitTestGenerateContext(testData.params));
            cc->Enable(PKE);
            cc->Enable(LEVELEDSHE);

            auto keyPair = cc->KeyGen();
            cc->EvalMultKeyGen(keyPair.secretKey);

            // The rescale adds a rounding error that does not depend on the encrypted values, while the noise of
            // a product scales with its inputs. With inputs near 0.01 the rounding error dominates, and an
            // estimate taken without the rescale is several bits too low. With inputs near 1 the two are
            // comparable at this ring dimension and the gap is below the tolerance, so that case only checks
            // that the estimates agree.
            for (double magnitude : {1.0, 0.01}) {
                std::vector<double> vec1 = {0.5, 0.6, 0.7, 0.8, 0.9, 1.0, 0.7, 0.8};
                std::vector<double> vec2 = {0.9, 0.8, 0.7, 0.6, 0.5, 0.6, 0.7, 1.0};
                for (size_t i = 0; i < vec1.size(); ++i) {
                    vec1[i] *= magnitude;
                    vec2[i] *= magnitude;
                }
                Ciphertext<DCRTPoly> ciph1 = cc->Encrypt(keyPair.publicKey, cc->MakeCKKSPackedPlaintext(vec1));
                Ciphertext<DCRTPoly> ciph2 = cc->Encrypt(keyPair.publicKey, cc->MakeCKKSPackedPlaintext(vec2));
                // the output of EvalMult carries a pending rescale under every scaling technique
                Ciphertext<DCRTPoly> pending = cc->EvalMult(ciph1, ciph2);
                EXPECT_EQ(pending->GetNoiseScaleDeg(), 2u) << failmsg + " ciphertext does not carry a pending rescale";

                // the reference is rescaled with the internal operation: the public ModReduceInPlace does
                // nothing under the automatic scaling techniques
                Ciphertext<DCRTPoly> rescaled = pending->Clone();
                cc->GetScheme()->ModReduceInternalInPlace(rescaled, 1);
                EXPECT_EQ(rescaled->GetNoiseScaleDeg(), 1u) << failmsg + " reference ciphertext was not rescaled";

                Plaintext ptPending, ptRescaled;
                cc->Decrypt(keyPair.secretKey, pending, &ptPending);
                cc->Decrypt(keyPair.secretKey, rescaled, &ptRescaled);

                EXPECT_NEAR(ptPending->GetLogError(), ptRescaled->GetLogError(), 1.0)
                        << failmsg + " noise estimate does not include the rescale for inputs near " +
                                   std::to_string(magnitude);
                // the estimate is reported for the ciphertext that decryption rescaled
                EXPECT_EQ(ptPending->GetLevel(), ptRescaled->GetLevel()) << failmsg + " unexpected plaintext level";
                EXPECT_EQ(ptPending->GetNoiseScaleDeg(), 1u) << failmsg + " unexpected plaintext degree";
            }
        } catch (std::exception& e) {
            std::cerr << "Exception thrown from " << __func__ << "(): " << e.what() << std::endl;
            // make it fail
            EXPECT_TRUE(0 == 1) << failmsg;
        } catch (...) {
            UNIT_TEST_HANDLE_ALL_EXCEPTIONS;
        }
    }

    void UnitTest_PKEOnlyDecrypt(const TEST_CASE_UTCKKSRNS_NOISE_FLOODING& testData,
                                 const std::string& failmsg = std::string()) {
        try {
            CryptoContext<DCRTPoly> cc(GenerateContextWithoutFeatures(testData.params));
            // LEVELEDSHE is not enabled: decryption must not depend on it for its internal rescale
            cc->Enable(PKE);
            EXPECT_FALSE(cc->GetScheme()->IsFeatureEnabled(LEVELEDSHE)) << failmsg + " LEVELEDSHE is enabled";

            auto keyPair = cc->KeyGen();

            std::vector<double> vec = {0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8};
            Plaintext ptxt = MakeDegree2Plaintext(cc, vec, static_cast<ScalingTechnique>(testData.params.scalTech));
            Ciphertext<DCRTPoly> ciphertext = cc->Encrypt(keyPair.publicKey, ptxt);
            EXPECT_EQ(ciphertext->GetNoiseScaleDeg(), 2u) << failmsg + " ciphertext does not carry a pending rescale";

            Plaintext result;
            cc->Decrypt(keyPair.secretKey, ciphertext, &result);
            result->SetLength(vec.size());
            EXPECT_EQ(result->GetNoiseScaleDeg(), 1u) << failmsg + " ciphertext was not rescaled by decryption";

            std::vector<std::complex<double>> expectedResult(vec.begin(), vec.end());
            checkEquality(result->GetCKKSPackedValue(), expectedResult, eps, failmsg + " PKE-only decryption fails");
        } catch (std::exception& e) {
            std::cerr << "Exception thrown from " << __func__ << "(): " << e.what() << std::endl;
            // make it fail
            EXPECT_TRUE(0 == 1) << failmsg;
        } catch (...) {
            UNIT_TEST_HANDLE_ALL_EXCEPTIONS;
        }
    }

    void UnitTest_MultipartyOnlyDecrypt(const TEST_CASE_UTCKKSRNS_NOISE_FLOODING& testData,
                                        const std::string& failmsg = std::string()) {
        try {
            CryptoContext<DCRTPoly> cc(GenerateContextWithoutFeatures(testData.params));
            // LEVELEDSHE is not enabled: threshold decryption must not depend on it for its internal rescale
            cc->Enable(PKE);
            cc->Enable(MULTIPARTY);
            EXPECT_FALSE(cc->GetScheme()->IsFeatureEnabled(LEVELEDSHE)) << failmsg + " LEVELEDSHE is enabled";

            auto kp1 = cc->KeyGen();
            KeyPair<Element> kp2 = cc->MultipartyKeyGen(kp1.publicKey);

            std::vector<double> vec = {0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8};
            Plaintext ptxt = MakeDegree2Plaintext(cc, vec, static_cast<ScalingTechnique>(testData.params.scalTech));
            // the public key of the last party is the joint public key
            Ciphertext<DCRTPoly> ciphertext = cc->Encrypt(kp2.publicKey, ptxt);
            EXPECT_EQ(ciphertext->GetNoiseScaleDeg(), 2u) << failmsg + " ciphertext does not carry a pending rescale";

            Plaintext result;
            auto partial1 = cc->MultipartyDecryptLead({ciphertext}, kp1.secretKey);
            auto partial2 = cc->MultipartyDecryptMain({ciphertext}, kp2.secretKey);
            EXPECT_EQ(partial1[0]->GetNoiseScaleDeg(), 1u) << failmsg + " lead share was not rescaled";
            EXPECT_EQ(partial2[0]->GetNoiseScaleDeg(), 1u) << failmsg + " main share was not rescaled";
            cc->MultipartyDecryptFusion({partial1[0], partial2[0]}, &result);
            result->SetLength(vec.size());

            std::vector<std::complex<double>> expectedResult(vec.begin(), vec.end());
            checkEquality(result->GetCKKSPackedValue(), expectedResult, eps,
                          failmsg + " threshold decryption without LEVELEDSHE fails");
        } catch (std::exception& e) {
            std::cerr << "Exception thrown from " << __func__ << "(): " << e.what() << std::endl;
            // make it fail
            EXPECT_TRUE(0 == 1) << failmsg;
        } catch (...) {
            UNIT_TEST_HANDLE_ALL_EXCEPTIONS;
        }
    }

    void UnitTest_TooFewLimbs(const TEST_CASE_UTCKKSRNS_NOISE_FLOODING& testData,
                              const std::string& failmsg = std::string()) {
        try {
            // multiplicative depth 0: a single tower, so nothing can be dropped by the rescale
            CryptoContext<DCRTPoly> cc(GenerateContextWithoutFeatures(testData.params));
            cc->Enable(PKE);
            cc->Enable(MULTIPARTY);

            auto kp1 = cc->KeyGen();
            KeyPair<Element> kp2 = cc->MultipartyKeyGen(kp1.publicKey);

            std::vector<double> vec = {0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8};
            Plaintext ptxt = cc->MakeCKKSPackedPlaintext(vec, 2);

            Ciphertext<DCRTPoly> ciphertext = cc->Encrypt(kp1.publicKey, ptxt);
            EXPECT_EQ(ciphertext->GetNoiseScaleDeg(), 2u) << failmsg + " ciphertext does not carry a pending rescale";
            EXPECT_EQ(ciphertext->GetElements()[0].GetNumOfElements(), 1u) << failmsg + " expected a single tower";
            // the rescale of a single tower would throw on its own; the message tells the dedicated check apart
            auto expectTooFewLimbs = [&](const std::function<void()>& decrypt, const std::string& name) {
                try {
                    decrypt();
                    ADD_FAILURE() << failmsg + " " + name + " did not throw";
                } catch (const OpenFHEException& e) {
                    EXPECT_NE(std::string(e.what()).find("not enough RNS limbs remain"), std::string::npos)
                            << failmsg + " " + name + " threw an unexpected exception: " + e.what();
                }
            };

            Plaintext result;
            expectTooFewLimbs([&]() { cc->Decrypt(kp1.secretKey, ciphertext, &result); }, "Decrypt");

            Ciphertext<DCRTPoly> ciphertextJoint = cc->Encrypt(kp2.publicKey, ptxt);
            expectTooFewLimbs([&]() { cc->MultipartyDecryptLead({ciphertextJoint}, kp1.secretKey); },
                              "MultipartyDecryptLead");
            expectTooFewLimbs([&]() { cc->MultipartyDecryptMain({ciphertextJoint}, kp2.secretKey); },
                              "MultipartyDecryptMain");
        } catch (std::exception& e) {
            std::cerr << "Exception thrown from " << __func__ << "(): " << e.what() << std::endl;
            // make it fail
            EXPECT_TRUE(0 == 1) << failmsg;
        } catch (...) {
            UNIT_TEST_HANDLE_ALL_EXCEPTIONS;
        }
    }

    void UnitTest_DegreeGuard(const TEST_CASE_UTCKKSRNS_NOISE_FLOODING& testData,
                              const std::string& failmsg = std::string()) {
        try {
            CryptoContext<DCRTPoly> cc(GenerateContextWithoutFeatures(testData.params));
            cc->Enable(PKE);

            auto keyPair = cc->KeyGen();

            std::vector<double> vec = {0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8};
            ConstCiphertext<DCRTPoly> pending = cc->Encrypt(keyPair.publicKey, cc->MakeCKKSPackedPlaintext(vec, 2));
            ConstCiphertext<DCRTPoly> fresh = cc->Encrypt(keyPair.publicKey, cc->MakeCKKSPackedPlaintext(vec));
            EXPECT_EQ(pending->GetNoiseScaleDeg(), 2u) << failmsg + " ciphertext does not carry a pending rescale";

            // the scheme-level Decrypt does not rescale, so it has to reject a pending rescale in flooding mode
            Poly poly;
            EXPECT_THROW(cc->GetScheme()->Decrypt(pending, keyPair.secretKey, &poly), OpenFHEException)
                    << failmsg + " scheme-level Decrypt accepted a ciphertext with a pending rescale";
            EXPECT_NO_THROW(cc->GetScheme()->Decrypt(fresh, keyPair.secretKey, &poly))
                    << failmsg + " scheme-level Decrypt rejected a ciphertext without a pending rescale";
        } catch (std::exception& e) {
            std::cerr << "Exception thrown from " << __func__ << "(): " << e.what() << std::endl;
            // make it fail
            EXPECT_TRUE(0 == 1) << failmsg;
        } catch (...) {
            UNIT_TEST_HANDLE_ALL_EXCEPTIONS;
        }
    }

    void UnitTest_MultipartyNoiseFlooding(const TEST_CASE_UTCKKSRNS_NOISE_FLOODING& testData,
                                          const std::string& failmsg = std::string()) {
        CryptoContext<DCRTPoly> cc(UnitTestGenerateContext(testData.params));
        cc->Enable(PKE);
        cc->Enable(LEVELEDSHE);
        cc->Enable(MULTIPARTY);

        auto kp1 = cc->KeyGen();
        KeyPair<Element> kp2 = cc->MultipartyKeyGen(kp1.publicKey, false, true);
        GenerateMultipartyKeys(cc, kp1, kp2);
        auto pubKeyForEncryption = cc->MultiAddPubKeys(kp1.publicKey, kp2.publicKey, kp2.publicKey->GetKeyTag());

        auto ciphertextResult = EncryptedMultipartyComputation(cc, pubKeyForEncryption);

        Plaintext result;
        auto ciphertextPartial1 = cc->MultipartyDecryptLead({ciphertextResult}, kp1.secretKey);
        auto ciphertextPartial2 = cc->MultipartyDecryptMain({ciphertextResult}, kp2.secretKey);
        std::vector<Ciphertext<Element>> partialCiphertextVecMult{ciphertextPartial1[0], ciphertextPartial2[0]};
        cc->MultipartyDecryptFusion(partialCiphertextVecMult, &result);
        size_t vecSize = 8;
        result->SetLength(vecSize);

        std::vector<std::complex<double>> expectedResult = {0.1, 0.2, 0, 0, 0.5, 0, 0, 0.8};

        checkEquality(result->GetCKKSPackedValue(), expectedResult, eps, failmsg + " Noise flooding computation fails");
    }
};

//===========================================================================================================
TEST_P(UTCKKSRNS_NOISE_FLOODING, CKKSRNS) {
    setupSignals();
    auto test = GetParam();

    switch (test.testCaseType) {
        case NOISE_ESTIMATION:
            UnitTest_NoiseEstimation(test, test.buildTestName());
            break;
        case FULL_NOISE_FLOODING:
            UnitTest_FullNoiseFlooding(test, test.buildTestName());
            break;
        case MULTIPARTY_NOISE_FLOODING:
            UnitTest_MultipartyNoiseFlooding(test, test.buildTestName());
            break;
        case FLOODING_VARIANCE:
            UnitTest_FloodingVariance(test, test.buildTestName());
            break;
        case MULTIPARTY_FLOODING_VARIANCE:
            UnitTest_MultipartyFloodingVariance(test, test.buildTestName());
            break;
        case ESTIMATION_WITH_RESCALE:
            UnitTest_EstimationWithRescale(test, test.buildTestName());
            break;
        case PKE_ONLY_DECRYPT:
            UnitTest_PKEOnlyDecrypt(test, test.buildTestName());
            break;
        case MULTIPARTY_ONLY_DECRYPT:
            UnitTest_MultipartyOnlyDecrypt(test, test.buildTestName());
            break;
        case TOO_FEW_LIMBS:
            UnitTest_TooFewLimbs(test, test.buildTestName());
            break;
        case DEGREE_GUARD:
            UnitTest_DegreeGuard(test, test.buildTestName());
            break;
        default:
            break;
    }
}

INSTANTIATE_TEST_SUITE_P(UnitTests, UTCKKSRNS_NOISE_FLOODING, ::testing::ValuesIn(testCases), testName);
