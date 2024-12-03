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

using namespace lbcrypto;

//===========================================================================================================
enum TEST_CASE_TYPE {
    EVAL_MULT_ERROR_HANDLING = 0,
    EVAL_MULT_MANY_ERROR_HANDLING,
    RELIN_TEST,
};

static std::ostream& operator<<(std::ostream& os, const TEST_CASE_TYPE& type) {
    std::string typeName;
    switch (type) {
        case EVAL_MULT_ERROR_HANDLING:
            typeName = "EVAL_MULT_ERROR_HANDLING";
            break;
        case EVAL_MULT_MANY_ERROR_HANDLING:
            typeName = "EVAL_MULT_MANY_ERROR_HANDLING";
            break;
        case RELIN_TEST:
            typeName = "RELIN_TEST";
            break;
        default:
            typeName = "UNKNOWN";
            break;
    }
    return os << typeName;
}

enum TEST_CASE_ERROR {
    SUCCESS = 0,
    INVALID_MAX_DEPTH,
    INVALID_PRIVATE_KEY,
    INVALID_PUBLIC_KEY,
    INVALID_PLAINTEXT_ENCRYPT,
    INVALID_CIPHERTEXT_ERROR1,
    INVALID_CIPHERTEXT_ERROR2,
    INVALID_CIPHERTEXT_ERROR3,
    INVALID_CIPHERTEXT_ERROR_MANY,
    INVALID_CIPHERTEXT_DECRYPT,
    INVALID_PLAINTEXT_DECRYPT,
    INVALID_PRIVATE_KEY_DECRYPT,
    INVALID_CIPHER_TEXT_LIST_MANY
};

struct TEST_CASE_UTGENERAL_EVALMULT {
    TEST_CASE_TYPE testCaseType;
    // test case description - MUST BE UNIQUE
    std::string description;

    UnitTestCCParams params;

    // additional test case data
    TEST_CASE_ERROR error;

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
static auto testName = [](const testing::TestParamInfo<TEST_CASE_UTGENERAL_EVALMULT>& test) {
    return test.param.buildTestName();
};

static std::ostream& operator<<(std::ostream& os, const TEST_CASE_UTGENERAL_EVALMULT& test) {
    return os << test.toString();
}
//===========================================================================================================
#if NATIVEINT == 128 && !defined(__EMSCRIPTEN__)
constexpr usint SCALE = 78;
#else
constexpr usint SCALE = 50;
#endif
constexpr usint RING_DIM        = 16;
constexpr usint BATCH           = 8;
constexpr usint MULT_DEPTH      = 4;
constexpr SecurityLevel SEC_LVL = HEStd_NotSet;
constexpr usint PTM             = 65537;

// clang-format off
static std::vector<TEST_CASE_UTGENERAL_EVALMULT> testCasesUTGENERAL_EVALMULT = {
//    TestType,               Descr,   Scheme,         RDim,     MultDepth,  SModSize, DSize,BatchSz, SecKeyDist, MaxRelinSkDeg, FModSize, SecLvl,  KSTech, ScalTech,        LDigits, PtMod, StdDev, EvalAddCt, KSCt, MultTech, EncTech, PREMode,  Error
    { EVAL_MULT_ERROR_HANDLING, "01", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SCALE,    DFLT, BATCH,   DFLT,       3,             DFLT,     SEC_LVL, DFLT,   FIXEDMANUAL,     DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    SUCCESS },
    { EVAL_MULT_ERROR_HANDLING, "02", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SCALE,    DFLT, BATCH,   DFLT,       3,             DFLT,     SEC_LVL, DFLT,   FIXEDMANUAL,     DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    INVALID_PRIVATE_KEY },
    { EVAL_MULT_ERROR_HANDLING, "03", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SCALE,    DFLT, BATCH,   DFLT,       3,             DFLT,     SEC_LVL, DFLT,   FIXEDMANUAL,     DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    INVALID_PUBLIC_KEY },
    { EVAL_MULT_ERROR_HANDLING, "04", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SCALE,    DFLT, BATCH,   DFLT,       3,             DFLT,     SEC_LVL, DFLT,   FIXEDMANUAL,     DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    INVALID_PLAINTEXT_ENCRYPT },
    { EVAL_MULT_ERROR_HANDLING, "05", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SCALE,    DFLT, BATCH,   DFLT,       3,             DFLT,     SEC_LVL, DFLT,   FIXEDMANUAL,     DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    INVALID_CIPHERTEXT_ERROR1 },
    { EVAL_MULT_ERROR_HANDLING, "06", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SCALE,    DFLT, BATCH,   DFLT,       3,             DFLT,     SEC_LVL, DFLT,   FIXEDMANUAL,     DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    INVALID_CIPHERTEXT_ERROR2 },
    { EVAL_MULT_ERROR_HANDLING, "07", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SCALE,    DFLT, BATCH,   DFLT,       3,             DFLT,     SEC_LVL, DFLT,   FIXEDMANUAL,     DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    INVALID_CIPHERTEXT_ERROR3 },
    { EVAL_MULT_ERROR_HANDLING, "08", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SCALE,    DFLT, BATCH,   DFLT,       3,             DFLT,     SEC_LVL, DFLT,   FIXEDMANUAL,     DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    INVALID_CIPHERTEXT_DECRYPT },
    { EVAL_MULT_ERROR_HANDLING, "09", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SCALE,    DFLT, BATCH,   DFLT,       3,             DFLT,     SEC_LVL, DFLT,   FIXEDMANUAL,     DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    INVALID_PLAINTEXT_DECRYPT },
    { EVAL_MULT_ERROR_HANDLING, "10", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SCALE,    DFLT, BATCH,   DFLT,       3,             DFLT,     SEC_LVL, DFLT,   FIXEDMANUAL,     DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    INVALID_PRIVATE_KEY_DECRYPT },
    // ==========================================
    { EVAL_MULT_ERROR_HANDLING, "11", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SCALE,    DFLT, BATCH,   DFLT,       3,             DFLT,     SEC_LVL, DFLT,   FIXEDAUTO,       DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    SUCCESS },
    { EVAL_MULT_ERROR_HANDLING, "12", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SCALE,    DFLT, BATCH,   DFLT,       3,             DFLT,     SEC_LVL, DFLT,   FIXEDAUTO,       DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    INVALID_PRIVATE_KEY },
    { EVAL_MULT_ERROR_HANDLING, "13", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SCALE,    DFLT, BATCH,   DFLT,       3,             DFLT,     SEC_LVL, DFLT,   FIXEDAUTO,       DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    INVALID_PUBLIC_KEY },
    { EVAL_MULT_ERROR_HANDLING, "14", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SCALE,    DFLT, BATCH,   DFLT,       3,             DFLT,     SEC_LVL, DFLT,   FIXEDAUTO,       DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    INVALID_PLAINTEXT_ENCRYPT },
    { EVAL_MULT_ERROR_HANDLING, "15", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SCALE,    DFLT, BATCH,   DFLT,       3,             DFLT,     SEC_LVL, DFLT,   FIXEDAUTO,       DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    INVALID_CIPHERTEXT_ERROR1 },
    { EVAL_MULT_ERROR_HANDLING, "16", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SCALE,    DFLT, BATCH,   DFLT,       3,             DFLT,     SEC_LVL, DFLT,   FIXEDAUTO,       DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    INVALID_CIPHERTEXT_ERROR2 },
    { EVAL_MULT_ERROR_HANDLING, "17", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SCALE,    DFLT, BATCH,   DFLT,       3,             DFLT,     SEC_LVL, DFLT,   FIXEDAUTO,       DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    INVALID_CIPHERTEXT_ERROR3 },
    { EVAL_MULT_ERROR_HANDLING, "18", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SCALE,    DFLT, BATCH,   DFLT,       3,             DFLT,     SEC_LVL, DFLT,   FIXEDAUTO,       DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    INVALID_CIPHERTEXT_DECRYPT },
    { EVAL_MULT_ERROR_HANDLING, "19", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SCALE,    DFLT, BATCH,   DFLT,       3,             DFLT,     SEC_LVL, DFLT,   FIXEDAUTO,       DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    INVALID_PLAINTEXT_DECRYPT },
    { EVAL_MULT_ERROR_HANDLING, "20", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SCALE,    DFLT, BATCH,   DFLT,       3,             DFLT,     SEC_LVL, DFLT,   FIXEDAUTO,       DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    INVALID_PRIVATE_KEY_DECRYPT },
#if NATIVEINT != 128
    { EVAL_MULT_ERROR_HANDLING, "21", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SCALE,    DFLT, BATCH,   DFLT,       3,             DFLT,     SEC_LVL, DFLT,   FLEXIBLEAUTO,    DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    SUCCESS },
    { EVAL_MULT_ERROR_HANDLING, "22", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SCALE,    DFLT, BATCH,   DFLT,       3,             DFLT,     SEC_LVL, DFLT,   FLEXIBLEAUTO,    DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    INVALID_PRIVATE_KEY },
    { EVAL_MULT_ERROR_HANDLING, "23", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SCALE,    DFLT, BATCH,   DFLT,       3,             DFLT,     SEC_LVL, DFLT,   FLEXIBLEAUTO,    DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    INVALID_PUBLIC_KEY },
    { EVAL_MULT_ERROR_HANDLING, "24", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SCALE,    DFLT, BATCH,   DFLT,       3,             DFLT,     SEC_LVL, DFLT,   FLEXIBLEAUTO,    DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    INVALID_PLAINTEXT_ENCRYPT },
    { EVAL_MULT_ERROR_HANDLING, "25", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SCALE,    DFLT, BATCH,   DFLT,       3,             DFLT,     SEC_LVL, DFLT,   FLEXIBLEAUTO,    DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    INVALID_CIPHERTEXT_ERROR1 },
    { EVAL_MULT_ERROR_HANDLING, "26", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SCALE,    DFLT, BATCH,   DFLT,       3,             DFLT,     SEC_LVL, DFLT,   FLEXIBLEAUTO,    DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    INVALID_CIPHERTEXT_ERROR2 },
    { EVAL_MULT_ERROR_HANDLING, "27", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SCALE,    DFLT, BATCH,   DFLT,       3,             DFLT,     SEC_LVL, DFLT,   FLEXIBLEAUTO,    DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    INVALID_CIPHERTEXT_ERROR3 },
    { EVAL_MULT_ERROR_HANDLING, "28", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SCALE,    DFLT, BATCH,   DFLT,       3,             DFLT,     SEC_LVL, DFLT,   FLEXIBLEAUTO,    DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    INVALID_CIPHERTEXT_DECRYPT },
    { EVAL_MULT_ERROR_HANDLING, "29", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SCALE,    DFLT, BATCH,   DFLT,       3,             DFLT,     SEC_LVL, DFLT,   FLEXIBLEAUTO,    DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    INVALID_PLAINTEXT_DECRYPT },
    { EVAL_MULT_ERROR_HANDLING, "30", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SCALE,    DFLT, BATCH,   DFLT,       3,             DFLT,     SEC_LVL, DFLT,   FLEXIBLEAUTO,    DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    INVALID_PRIVATE_KEY_DECRYPT },
    // ==========================================
    { EVAL_MULT_ERROR_HANDLING, "31", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SCALE,    DFLT, BATCH,   DFLT,       3,             DFLT,     SEC_LVL, DFLT,   FLEXIBLEAUTOEXT, DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    SUCCESS },
    { EVAL_MULT_ERROR_HANDLING, "32", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SCALE,    DFLT, BATCH,   DFLT,       3,             DFLT,     SEC_LVL, DFLT,   FLEXIBLEAUTOEXT, DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    INVALID_PRIVATE_KEY },
    { EVAL_MULT_ERROR_HANDLING, "33", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SCALE,    DFLT, BATCH,   DFLT,       3,             DFLT,     SEC_LVL, DFLT,   FLEXIBLEAUTOEXT, DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    INVALID_PUBLIC_KEY },
    { EVAL_MULT_ERROR_HANDLING, "34", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SCALE,    DFLT, BATCH,   DFLT,       3,             DFLT,     SEC_LVL, DFLT,   FLEXIBLEAUTOEXT, DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    INVALID_PLAINTEXT_ENCRYPT },
    { EVAL_MULT_ERROR_HANDLING, "35", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SCALE,    DFLT, BATCH,   DFLT,       3,             DFLT,     SEC_LVL, DFLT,   FLEXIBLEAUTOEXT, DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    INVALID_CIPHERTEXT_ERROR1 },
    { EVAL_MULT_ERROR_HANDLING, "36", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SCALE,    DFLT, BATCH,   DFLT,       3,             DFLT,     SEC_LVL, DFLT,   FLEXIBLEAUTOEXT, DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    INVALID_CIPHERTEXT_ERROR2 },
    { EVAL_MULT_ERROR_HANDLING, "37", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SCALE,    DFLT, BATCH,   DFLT,       3,             DFLT,     SEC_LVL, DFLT,   FLEXIBLEAUTOEXT, DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    INVALID_CIPHERTEXT_ERROR3 },
    { EVAL_MULT_ERROR_HANDLING, "38", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SCALE,    DFLT, BATCH,   DFLT,       3,             DFLT,     SEC_LVL, DFLT,   FLEXIBLEAUTOEXT, DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    INVALID_CIPHERTEXT_DECRYPT },
    { EVAL_MULT_ERROR_HANDLING, "39", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SCALE,    DFLT, BATCH,   DFLT,       3,             DFLT,     SEC_LVL, DFLT,   FLEXIBLEAUTOEXT, DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    INVALID_PLAINTEXT_DECRYPT },
    { EVAL_MULT_ERROR_HANDLING, "40", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SCALE,    DFLT, BATCH,   DFLT,       3,             DFLT,     SEC_LVL, DFLT,   FLEXIBLEAUTOEXT, DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    INVALID_PRIVATE_KEY_DECRYPT },
#endif
    // ==========================================
    // TestType,               Descr,  Scheme,        RDim,     MultDepth,  SModSize, DSize,BatchSz, SecKeyDist, MaxRelinSkDeg, FModSize, SecLvl,  KSTech, ScalTech,        LDigits, PtMod, StdDev, EvalAddCt, KSCt, MultTech, EncTech, PREMode,  Error
    { EVAL_MULT_ERROR_HANDLING, "41", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,     DFLT, BATCH,   DFLT,       4,             DFLT,     SEC_LVL, DFLT,   FIXEDMANUAL,     DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    SUCCESS },
    { EVAL_MULT_ERROR_HANDLING, "42", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,     DFLT, BATCH,   DFLT,       4,             DFLT,     SEC_LVL, DFLT,   FIXEDMANUAL,     DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    INVALID_PRIVATE_KEY },
    { EVAL_MULT_ERROR_HANDLING, "43", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,     DFLT, BATCH,   DFLT,       4,             DFLT,     SEC_LVL, DFLT,   FIXEDMANUAL,     DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    INVALID_PUBLIC_KEY },
    { EVAL_MULT_ERROR_HANDLING, "44", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,     DFLT, BATCH,   DFLT,       4,             DFLT,     SEC_LVL, DFLT,   FIXEDMANUAL,     DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    INVALID_PLAINTEXT_ENCRYPT },
    { EVAL_MULT_ERROR_HANDLING, "45", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,     DFLT, BATCH,   DFLT,       4,             DFLT,     SEC_LVL, DFLT,   FIXEDMANUAL,     DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    INVALID_CIPHERTEXT_ERROR1 },
    { EVAL_MULT_ERROR_HANDLING, "46", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,     DFLT, BATCH,   DFLT,       4,             DFLT,     SEC_LVL, DFLT,   FIXEDMANUAL,     DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    INVALID_CIPHERTEXT_ERROR2 },
    { EVAL_MULT_ERROR_HANDLING, "47", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,     DFLT, BATCH,   DFLT,       4,             DFLT,     SEC_LVL, DFLT,   FIXEDMANUAL,     DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    INVALID_CIPHERTEXT_ERROR3 },
    { EVAL_MULT_ERROR_HANDLING, "48", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,     DFLT, BATCH,   DFLT,       4,             DFLT,     SEC_LVL, DFLT,   FIXEDMANUAL,     DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    INVALID_CIPHERTEXT_DECRYPT },
    { EVAL_MULT_ERROR_HANDLING, "49", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,     DFLT, BATCH,   DFLT,       4,             DFLT,     SEC_LVL, DFLT,   FIXEDMANUAL,     DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    INVALID_PLAINTEXT_DECRYPT },
    // ==========================================
    { EVAL_MULT_ERROR_HANDLING, "50", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,     DFLT, BATCH,   DFLT,       4,             DFLT,     SEC_LVL, DFLT,   FIXEDAUTO,       DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    INVALID_PRIVATE_KEY_DECRYPT },
    { EVAL_MULT_ERROR_HANDLING, "51", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,     DFLT, BATCH,   DFLT,       4,             DFLT,     SEC_LVL, DFLT,   FIXEDAUTO,       DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    SUCCESS },
    { EVAL_MULT_ERROR_HANDLING, "52", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,     DFLT, BATCH,   DFLT,       4,             DFLT,     SEC_LVL, DFLT,   FIXEDAUTO,       DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    INVALID_PRIVATE_KEY },
    { EVAL_MULT_ERROR_HANDLING, "53", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,     DFLT, BATCH,   DFLT,       4,             DFLT,     SEC_LVL, DFLT,   FIXEDAUTO,       DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    INVALID_PUBLIC_KEY },
    { EVAL_MULT_ERROR_HANDLING, "54", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,     DFLT, BATCH,   DFLT,       4,             DFLT,     SEC_LVL, DFLT,   FIXEDAUTO,       DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    INVALID_PLAINTEXT_ENCRYPT },
    { EVAL_MULT_ERROR_HANDLING, "55", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,     DFLT, BATCH,   DFLT,       4,             DFLT,     SEC_LVL, DFLT,   FIXEDAUTO,       DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    INVALID_CIPHERTEXT_ERROR1 },
    { EVAL_MULT_ERROR_HANDLING, "56", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,     DFLT, BATCH,   DFLT,       4,             DFLT,     SEC_LVL, DFLT,   FIXEDAUTO,       DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    INVALID_CIPHERTEXT_ERROR2 },
    { EVAL_MULT_ERROR_HANDLING, "57", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,     DFLT, BATCH,   DFLT,       4,             DFLT,     SEC_LVL, DFLT,   FIXEDAUTO,       DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    INVALID_CIPHERTEXT_ERROR3 },
    { EVAL_MULT_ERROR_HANDLING, "58", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,     DFLT, BATCH,   DFLT,       4,             DFLT,     SEC_LVL, DFLT,   FIXEDAUTO,       DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    INVALID_CIPHERTEXT_DECRYPT },
    { EVAL_MULT_ERROR_HANDLING, "59", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,     DFLT, BATCH,   DFLT,       4,             DFLT,     SEC_LVL, DFLT,   FIXEDAUTO,       DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    INVALID_PLAINTEXT_DECRYPT },
    // ==========================================
    { EVAL_MULT_ERROR_HANDLING, "60", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,     DFLT, BATCH,   DFLT,       4,             DFLT,     SEC_LVL, DFLT,   FLEXIBLEAUTO,    DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    INVALID_PRIVATE_KEY_DECRYPT },
    { EVAL_MULT_ERROR_HANDLING, "61", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,     DFLT, BATCH,   DFLT,       4,             DFLT,     SEC_LVL, DFLT,   FLEXIBLEAUTO,    DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    SUCCESS },
    { EVAL_MULT_ERROR_HANDLING, "62", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,     DFLT, BATCH,   DFLT,       4,             DFLT,     SEC_LVL, DFLT,   FLEXIBLEAUTO,    DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    INVALID_PRIVATE_KEY },
    { EVAL_MULT_ERROR_HANDLING, "63", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,     DFLT, BATCH,   DFLT,       4,             DFLT,     SEC_LVL, DFLT,   FLEXIBLEAUTO,    DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    INVALID_PUBLIC_KEY },
    { EVAL_MULT_ERROR_HANDLING, "64", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,     DFLT, BATCH,   DFLT,       4,             DFLT,     SEC_LVL, DFLT,   FLEXIBLEAUTO,    DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    INVALID_PLAINTEXT_ENCRYPT },
    { EVAL_MULT_ERROR_HANDLING, "65", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,     DFLT, BATCH,   DFLT,       4,             DFLT,     SEC_LVL, DFLT,   FLEXIBLEAUTO,    DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    INVALID_CIPHERTEXT_ERROR1 },
    { EVAL_MULT_ERROR_HANDLING, "66", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,     DFLT, BATCH,   DFLT,       4,             DFLT,     SEC_LVL, DFLT,   FLEXIBLEAUTO,    DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    INVALID_CIPHERTEXT_ERROR2 },
    { EVAL_MULT_ERROR_HANDLING, "67", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,     DFLT, BATCH,   DFLT,       4,             DFLT,     SEC_LVL, DFLT,   FLEXIBLEAUTO,    DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    INVALID_CIPHERTEXT_ERROR3 },
    { EVAL_MULT_ERROR_HANDLING, "68", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,     DFLT, BATCH,   DFLT,       4,             DFLT,     SEC_LVL, DFLT,   FLEXIBLEAUTO,    DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    INVALID_CIPHERTEXT_DECRYPT },
    { EVAL_MULT_ERROR_HANDLING, "69", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,     DFLT, BATCH,   DFLT,       4,             DFLT,     SEC_LVL, DFLT,   FLEXIBLEAUTO,    DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    INVALID_PLAINTEXT_DECRYPT },
    // ==========================================
    { EVAL_MULT_ERROR_HANDLING, "70", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,     DFLT, BATCH,   DFLT,       4,             DFLT,     SEC_LVL, DFLT,   FLEXIBLEAUTOEXT, DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    INVALID_PRIVATE_KEY_DECRYPT },
    { EVAL_MULT_ERROR_HANDLING, "71", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,     DFLT, BATCH,   DFLT,       4,             DFLT,     SEC_LVL, DFLT,   FLEXIBLEAUTOEXT, DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    SUCCESS },
    { EVAL_MULT_ERROR_HANDLING, "72", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,     DFLT, BATCH,   DFLT,       4,             DFLT,     SEC_LVL, DFLT,   FLEXIBLEAUTOEXT, DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    INVALID_PRIVATE_KEY },
    { EVAL_MULT_ERROR_HANDLING, "73", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,     DFLT, BATCH,   DFLT,       4,             DFLT,     SEC_LVL, DFLT,   FLEXIBLEAUTOEXT, DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    INVALID_PUBLIC_KEY },
    { EVAL_MULT_ERROR_HANDLING, "74", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,     DFLT, BATCH,   DFLT,       4,             DFLT,     SEC_LVL, DFLT,   FLEXIBLEAUTOEXT, DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    INVALID_PLAINTEXT_ENCRYPT },
    { EVAL_MULT_ERROR_HANDLING, "75", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,     DFLT, BATCH,   DFLT,       4,             DFLT,     SEC_LVL, DFLT,   FLEXIBLEAUTOEXT, DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    INVALID_CIPHERTEXT_ERROR1 },
    { EVAL_MULT_ERROR_HANDLING, "76", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,     DFLT, BATCH,   DFLT,       4,             DFLT,     SEC_LVL, DFLT,   FLEXIBLEAUTOEXT, DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    INVALID_CIPHERTEXT_ERROR2 },
    { EVAL_MULT_ERROR_HANDLING, "77", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,     DFLT, BATCH,   DFLT,       4,             DFLT,     SEC_LVL, DFLT,   FLEXIBLEAUTOEXT, DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    INVALID_CIPHERTEXT_ERROR3 },
    { EVAL_MULT_ERROR_HANDLING, "78", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,     DFLT, BATCH,   DFLT,       4,             DFLT,     SEC_LVL, DFLT,   FLEXIBLEAUTOEXT, DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    INVALID_CIPHERTEXT_DECRYPT },
    { EVAL_MULT_ERROR_HANDLING, "79", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,     DFLT, BATCH,   DFLT,       4,             DFLT,     SEC_LVL, DFLT,   FLEXIBLEAUTOEXT, DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    INVALID_PLAINTEXT_DECRYPT },
    { EVAL_MULT_ERROR_HANDLING, "80", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,     DFLT, BATCH,   DFLT,       4,             DFLT,     SEC_LVL, DFLT,   FLEXIBLEAUTOEXT, DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT},    INVALID_PRIVATE_KEY_DECRYPT },
    // ==========================================
    // TestType,                    Descr,  Scheme,        RDim,     MultDepth,  SModSize, DSize,BatchSz, SecKeyDist, MaxRelinSkDeg, FModSize, SecLvl,  KSTech, ScalTech, LDigits, PtMod, StdDev, EvalAddCt, KSCt, MultTech, EncTech,     PREMode,  Error
    { EVAL_MULT_MANY_ERROR_HANDLING, "01", {BFVRNS_SCHEME, DFLT,     DFLT,       60,       DFLT, DFLT,    DFLT,       4,             DFLT,     SEC_LVL, DFLT,   DFLT,     DFLT,    256,   4,      DFLT,      DFLT, DFLT,     STANDARD,    DFLT},    SUCCESS },
    { EVAL_MULT_MANY_ERROR_HANDLING, "02", {BFVRNS_SCHEME, DFLT,     DFLT,       60,       DFLT, DFLT,    DFLT,       3,             DFLT,     SEC_LVL, DFLT,   DFLT,     DFLT,    256,   4,      DFLT,      DFLT, DFLT,     STANDARD,    DFLT},    INVALID_MAX_DEPTH },
    { EVAL_MULT_MANY_ERROR_HANDLING, "03", {BFVRNS_SCHEME, DFLT,     DFLT,       60,       DFLT, DFLT,    DFLT,       4,             DFLT,     SEC_LVL, DFLT,   DFLT,     DFLT,    256,   4,      DFLT,      DFLT, DFLT,     STANDARD,    DFLT},    INVALID_PRIVATE_KEY },
    { EVAL_MULT_MANY_ERROR_HANDLING, "04", {BFVRNS_SCHEME, DFLT,     DFLT,       60,       DFLT, DFLT,    DFLT,       4,             DFLT,     SEC_LVL, DFLT,   DFLT,     DFLT,    256,   4,      DFLT,      DFLT, DFLT,     STANDARD,    DFLT},    INVALID_PUBLIC_KEY },
    { EVAL_MULT_MANY_ERROR_HANDLING, "05", {BFVRNS_SCHEME, DFLT,     DFLT,       60,       DFLT, DFLT,    DFLT,       4,             DFLT,     SEC_LVL, DFLT,   DFLT,     DFLT,    256,   4,      DFLT,      DFLT, DFLT,     STANDARD,    DFLT},    INVALID_PLAINTEXT_ENCRYPT },
    { EVAL_MULT_MANY_ERROR_HANDLING, "06", {BFVRNS_SCHEME, DFLT,     DFLT,       60,       DFLT, DFLT,    DFLT,       4,             DFLT,     SEC_LVL, DFLT,   DFLT,     DFLT,    256,   4,      DFLT,      DFLT, DFLT,     STANDARD,    DFLT},    INVALID_CIPHERTEXT_ERROR1 },
    { EVAL_MULT_MANY_ERROR_HANDLING, "07", {BFVRNS_SCHEME, DFLT,     DFLT,       60,       DFLT, DFLT,    DFLT,       4,             DFLT,     SEC_LVL, DFLT,   DFLT,     DFLT,    256,   4,      DFLT,      DFLT, DFLT,     STANDARD,    DFLT},    INVALID_CIPHERTEXT_ERROR2 },
    { EVAL_MULT_MANY_ERROR_HANDLING, "08", {BFVRNS_SCHEME, DFLT,     DFLT,       60,       DFLT, DFLT,    DFLT,       4,             DFLT,     SEC_LVL, DFLT,   DFLT,     DFLT,    256,   4,      DFLT,      DFLT, DFLT,     STANDARD,    DFLT},    INVALID_CIPHERTEXT_ERROR3 },
    { EVAL_MULT_MANY_ERROR_HANDLING, "09", {BFVRNS_SCHEME, DFLT,     DFLT,       60,       DFLT, DFLT,    DFLT,       4,             DFLT,     SEC_LVL, DFLT,   DFLT,     DFLT,    256,   4,      DFLT,      DFLT, DFLT,     STANDARD,    DFLT},    INVALID_CIPHERTEXT_ERROR_MANY },
    { EVAL_MULT_MANY_ERROR_HANDLING, "10", {BFVRNS_SCHEME, DFLT,     DFLT,       60,       DFLT, DFLT,    DFLT,       4,             DFLT,     SEC_LVL, DFLT,   DFLT,     DFLT,    256,   4,      DFLT,      DFLT, DFLT,     STANDARD,    DFLT},    INVALID_CIPHERTEXT_DECRYPT },
    { EVAL_MULT_MANY_ERROR_HANDLING, "11", {BFVRNS_SCHEME, DFLT,     DFLT,       60,       DFLT, DFLT,    DFLT,       4,             DFLT,     SEC_LVL, DFLT,   DFLT,     DFLT,    256,   4,      DFLT,      DFLT, DFLT,     STANDARD,    DFLT},    INVALID_PLAINTEXT_DECRYPT },
    { EVAL_MULT_MANY_ERROR_HANDLING, "12", {BFVRNS_SCHEME, DFLT,     DFLT,       60,       DFLT, DFLT,    DFLT,       4,             DFLT,     SEC_LVL, DFLT,   DFLT,     DFLT,    256,   4,      DFLT,      DFLT, DFLT,     STANDARD,    DFLT},    INVALID_PRIVATE_KEY_DECRYPT },
    { EVAL_MULT_MANY_ERROR_HANDLING, "13", {BFVRNS_SCHEME, DFLT,     DFLT,       60,       DFLT, DFLT,    DFLT,       4,             DFLT,     SEC_LVL, DFLT,   DFLT,     DFLT,    256,   4,      DFLT,      DFLT, DFLT,     STANDARD,    DFLT},    INVALID_CIPHER_TEXT_LIST_MANY },
    { EVAL_MULT_MANY_ERROR_HANDLING, "14", {BFVRNS_SCHEME, DFLT,     DFLT,       60,       DFLT, DFLT,    DFLT,       4,             DFLT,     SEC_LVL, DFLT,   DFLT,     DFLT,    256,   4,      DFLT,      DFLT, DFLT,     EXTENDED,    DFLT},    SUCCESS },
    { EVAL_MULT_MANY_ERROR_HANDLING, "15", {BFVRNS_SCHEME, DFLT,     DFLT,       60,       DFLT, DFLT,    DFLT,       3,             DFLT,     SEC_LVL, DFLT,   DFLT,     DFLT,    256,   4,      DFLT,      DFLT, DFLT,     EXTENDED,    DFLT},    INVALID_MAX_DEPTH },
    { EVAL_MULT_MANY_ERROR_HANDLING, "16", {BFVRNS_SCHEME, DFLT,     DFLT,       60,       DFLT, DFLT,    DFLT,       4,             DFLT,     SEC_LVL, DFLT,   DFLT,     DFLT,    256,   4,      DFLT,      DFLT, DFLT,     EXTENDED,    DFLT},    INVALID_PRIVATE_KEY },
    { EVAL_MULT_MANY_ERROR_HANDLING, "17", {BFVRNS_SCHEME, DFLT,     DFLT,       60,       DFLT, DFLT,    DFLT,       4,             DFLT,     SEC_LVL, DFLT,   DFLT,     DFLT,    256,   4,      DFLT,      DFLT, DFLT,     EXTENDED,    DFLT},    INVALID_PUBLIC_KEY },
    { EVAL_MULT_MANY_ERROR_HANDLING, "18", {BFVRNS_SCHEME, DFLT,     DFLT,       60,       DFLT, DFLT,    DFLT,       4,             DFLT,     SEC_LVL, DFLT,   DFLT,     DFLT,    256,   4,      DFLT,      DFLT, DFLT,     EXTENDED,    DFLT},    INVALID_PLAINTEXT_ENCRYPT },
    { EVAL_MULT_MANY_ERROR_HANDLING, "19", {BFVRNS_SCHEME, DFLT,     DFLT,       60,       DFLT, DFLT,    DFLT,       4,             DFLT,     SEC_LVL, DFLT,   DFLT,     DFLT,    256,   4,      DFLT,      DFLT, DFLT,     EXTENDED,    DFLT},    INVALID_CIPHERTEXT_ERROR1 },
    { EVAL_MULT_MANY_ERROR_HANDLING, "20", {BFVRNS_SCHEME, DFLT,     DFLT,       60,       DFLT, DFLT,    DFLT,       4,             DFLT,     SEC_LVL, DFLT,   DFLT,     DFLT,    256,   4,      DFLT,      DFLT, DFLT,     EXTENDED,    DFLT},    INVALID_CIPHERTEXT_ERROR2 },
    { EVAL_MULT_MANY_ERROR_HANDLING, "21", {BFVRNS_SCHEME, DFLT,     DFLT,       60,       DFLT, DFLT,    DFLT,       4,             DFLT,     SEC_LVL, DFLT,   DFLT,     DFLT,    256,   4,      DFLT,      DFLT, DFLT,     EXTENDED,    DFLT},    INVALID_CIPHERTEXT_ERROR3 },
    { EVAL_MULT_MANY_ERROR_HANDLING, "22", {BFVRNS_SCHEME, DFLT,     DFLT,       60,       DFLT, DFLT,    DFLT,       4,             DFLT,     SEC_LVL, DFLT,   DFLT,     DFLT,    256,   4,      DFLT,      DFLT, DFLT,     EXTENDED,    DFLT},    INVALID_CIPHERTEXT_ERROR_MANY },
    { EVAL_MULT_MANY_ERROR_HANDLING, "23", {BFVRNS_SCHEME, DFLT,     DFLT,       60,       DFLT, DFLT,    DFLT,       4,             DFLT,     SEC_LVL, DFLT,   DFLT,     DFLT,    256,   4,      DFLT,      DFLT, DFLT,     EXTENDED,    DFLT},    INVALID_CIPHERTEXT_DECRYPT },
    { EVAL_MULT_MANY_ERROR_HANDLING, "24", {BFVRNS_SCHEME, DFLT,     DFLT,       60,       DFLT, DFLT,    DFLT,       4,             DFLT,     SEC_LVL, DFLT,   DFLT,     DFLT,    256,   4,      DFLT,      DFLT, DFLT,     EXTENDED,    DFLT},    INVALID_PLAINTEXT_DECRYPT },
    { EVAL_MULT_MANY_ERROR_HANDLING, "25", {BFVRNS_SCHEME, DFLT,     DFLT,       60,       DFLT, DFLT,    DFLT,       4,             DFLT,     SEC_LVL, DFLT,   DFLT,     DFLT,    256,   4,      DFLT,      DFLT, DFLT,     EXTENDED,    DFLT},    INVALID_PRIVATE_KEY_DECRYPT },
    { EVAL_MULT_MANY_ERROR_HANDLING, "26", {BFVRNS_SCHEME, DFLT,     DFLT,       60,       DFLT, DFLT,    DFLT,       4,             DFLT,     SEC_LVL, DFLT,   DFLT,     DFLT,    256,   4,      DFLT,      DFLT, DFLT,     EXTENDED,    DFLT},    INVALID_CIPHER_TEXT_LIST_MANY },
    // ==========================================
    // TestType, Descr,  Scheme,         RDim,     MultDepth,  SModSize, DSize,BatchSz, SecKeyDist, MaxRelinSkDeg, FModSize, SecLvl,  KSTech, ScalTech,        LDigits, PtMod, StdDev, EvalAddCt, KSCt, MultTech, EncTech, PREMode
    { RELIN_TEST, "01", {BGVRNS_SCHEME,  RING_DIM, MULT_DEPTH, DFLT,     DFLT, DFLT,    DFLT,       4,             DFLT,     SEC_LVL, DFLT,   FIXEDMANUAL,     DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { RELIN_TEST, "02", {BGVRNS_SCHEME,  RING_DIM, MULT_DEPTH, DFLT,     DFLT, DFLT,    DFLT,       4,             DFLT,     SEC_LVL, DFLT,   FIXEDAUTO,       DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { RELIN_TEST, "03", {BGVRNS_SCHEME,  RING_DIM, MULT_DEPTH, DFLT,     DFLT, DFLT,    DFLT,       4,             DFLT,     SEC_LVL, DFLT,   FLEXIBLEAUTO,    DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { RELIN_TEST, "04", {BGVRNS_SCHEME,  RING_DIM, MULT_DEPTH, DFLT,     DFLT, DFLT,    DFLT,       4,             DFLT,     SEC_LVL, DFLT,   FLEXIBLEAUTOEXT, DFLT,    PTM,   DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { RELIN_TEST, "05", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SCALE,    DFLT, BATCH,   DFLT,       3,             DFLT,     SEC_LVL, DFLT,   FIXEDMANUAL,     DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { RELIN_TEST, "06", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SCALE,    DFLT, BATCH,   DFLT,       3,             DFLT,     SEC_LVL, DFLT,   FIXEDAUTO,       DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
#if NATIVEINT != 128
    { RELIN_TEST, "07", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SCALE,    DFLT, BATCH,   DFLT,       3,             DFLT,     SEC_LVL, DFLT,   FLEXIBLEAUTO,    DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { RELIN_TEST, "08", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SCALE,    DFLT, BATCH,   DFLT,       3,             DFLT,     SEC_LVL, DFLT,   FLEXIBLEAUTOEXT, DFLT,    DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
#endif
    // ==========================================
};
// clang-format on
//===========================================================================================================

class UTGENERAL_EVALMULT : public ::testing::TestWithParam<TEST_CASE_UTGENERAL_EVALMULT> {
    using Element    = DCRTPoly;
    const double eps = EPSILON;

protected:
    void SetUp() {}

    void TearDown() {
        PackedEncoding::Destroy();
        CryptoContextFactory<DCRTPoly>::ReleaseAllContexts();
    }

    void UnitTest_EvalMultManyErrorHandling(const TEST_CASE_UTGENERAL_EVALMULT& testData,
                                            const std::string& failmsg = std::string()) {
        try {
            CryptoContext<Element> cryptoContext(UnitTestGenerateContext(testData.params));

            ////////////////////////////////////////////////////////////
            // Perform the key generation operation.
            ////////////////////////////////////////////////////////////
            auto keyPair = cryptoContext->KeyGen();
            ASSERT_TRUE(keyPair.good()) << "Key generation failed!";
            // Create evaluation key vector to be used in keyswitching
            if (INVALID_PRIVATE_KEY == testData.error)
                cryptoContext->EvalMultKeysGen(nullptr);
            else
                cryptoContext->EvalMultKeysGen(keyPair.secretKey);

            ////////////////////////////////////////////////////////////
            // Plaintext
            ////////////////////////////////////////////////////////////

            std::vector<int64_t> vectorOfInts1 = {5, 4, 3, 2, 1, 0, 5, 4, 3, 2, 1, 0};
            std::vector<int64_t> vectorOfInts2 = {2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
            std::vector<int64_t> vectorOfInts3 = {3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
            std::vector<int64_t> vectorOfInts4 = {4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

            std::vector<int64_t> vectorOfInts5 = {10, 8, 6, 4, 2, 0, 10, 8, 6, 4, 2, 0};
            std::vector<int64_t> vectorOfInts6 = {30, 24, 18, 12, 6, 0, 30, 24, 18, 12, 6, 0};
            std::vector<int64_t> vectorOfInts7 = {120, 96, 72, 48, 24, 0, 120, 96, 72, 48, 24, 0};
            Plaintext plaintext1               = cryptoContext->MakeCoefPackedPlaintext(vectorOfInts1);
            Plaintext plaintext2               = cryptoContext->MakeCoefPackedPlaintext(vectorOfInts2);
            Plaintext plaintext3               = cryptoContext->MakeCoefPackedPlaintext(vectorOfInts3);
            Plaintext plaintext4               = cryptoContext->MakeCoefPackedPlaintext(vectorOfInts4);

            Plaintext plaintextResult1 = cryptoContext->MakeCoefPackedPlaintext(vectorOfInts5);
            Plaintext plaintextResult2 = cryptoContext->MakeCoefPackedPlaintext(vectorOfInts6);
            Plaintext plaintextResult3 = cryptoContext->MakeCoefPackedPlaintext(vectorOfInts7);

            ////////////////////////////////////////////////////////////
            // Encryption
            ////////////////////////////////////////////////////////////
            auto ciphertext1 = (INVALID_PUBLIC_KEY == testData.error) ?
                                   cryptoContext->Encrypt(static_cast<const PublicKey<Element>>(nullptr), plaintext1) :
                                   cryptoContext->Encrypt(keyPair.publicKey, plaintext1);
            auto ciphertext2 = (INVALID_PLAINTEXT_ENCRYPT == testData.error) ?
                                   cryptoContext->Encrypt(keyPair.publicKey, nullptr) :
                                   cryptoContext->Encrypt(keyPair.publicKey, plaintext2);
            auto ciphertext3 = cryptoContext->Encrypt(keyPair.publicKey, plaintext3);
            auto ciphertext4 = cryptoContext->Encrypt(keyPair.publicKey, plaintext4);

            ////////////////////////////////////////////////////////////
            // EvalMult Operation
            ////////////////////////////////////////////////////////////
            // Perform consecutive multiplications and do a keyswtiching at the end.
            auto ciphertextMul12 = (INVALID_CIPHERTEXT_ERROR1 == testData.error) ?
                                       cryptoContext->EvalMultNoRelin(nullptr, ciphertext2) :
                                       cryptoContext->EvalMultNoRelin(ciphertext1, ciphertext2);
            auto ciphertextMul123 = (INVALID_CIPHERTEXT_ERROR2 == testData.error) ?
                                        cryptoContext->EvalMultNoRelin(ciphertextMul12, nullptr) :
                                        cryptoContext->EvalMultNoRelin(ciphertextMul12, ciphertext3);
            Ciphertext<Element> ciphertextMul1234 = nullptr;
            if (INVALID_CIPHERTEXT_ERROR3 == testData.error)
                ciphertextMul1234 = cryptoContext->EvalMultAndRelinearize(nullptr, ciphertext4);
            else if (INVALID_CIPHERTEXT_ERROR_MANY == testData.error)
                ciphertextMul1234 = cryptoContext->EvalMultAndRelinearize(ciphertextMul123, nullptr);
            else
                ciphertextMul1234 = cryptoContext->EvalMultAndRelinearize(ciphertextMul123, ciphertext4);

            ////////////////////////////////////////////////////////////
            // Decryption of multiplicative results with and without keyswtiching (depends
            // on the level)
            ////////////////////////////////////////////////////////////
            Plaintext plaintextMul1;
            Plaintext plaintextMul2;
            Plaintext plaintextMul3;
            if (INVALID_CIPHERTEXT_DECRYPT == testData.error)
                cryptoContext->Decrypt(keyPair.secretKey, nullptr, &plaintextMul1);
            else if (INVALID_PLAINTEXT_DECRYPT == testData.error)
                cryptoContext->Decrypt(keyPair.secretKey, ciphertextMul12, nullptr);
            else if (INVALID_PRIVATE_KEY_DECRYPT == testData.error)
                cryptoContext->Decrypt(nullptr, ciphertextMul12, &plaintextMul1);
            else
                cryptoContext->Decrypt(keyPair.secretKey, ciphertextMul12, &plaintextMul1);

            cryptoContext->Decrypt(keyPair.secretKey, ciphertextMul123, &plaintextMul2);
            cryptoContext->Decrypt(keyPair.secretKey, ciphertextMul1234, &plaintextMul3);
            ////////////////////////////////////////////////////////////
            // Prepare EvalMultMany
            ////////////////////////////////////////////////////////////
            std::vector<Ciphertext<Element>> cipherTextList = {ciphertext1, ciphertext2, ciphertext3, ciphertext4};

            ////////////////////////////////////////////////////////////
            // Compute EvalMultMany
            ////////////////////////////////////////////////////////////
            auto ciphertextMul12345 = (INVALID_CIPHER_TEXT_LIST_MANY == testData.error) ?
                                          cryptoContext->EvalMultMany(std::vector<Ciphertext<Element>>()) :
                                          cryptoContext->EvalMultMany(cipherTextList);

            ////////////////////////////////////////////////////////////
            // Decrypt EvalMultMany
            ////////////////////////////////////////////////////////////
            Plaintext plaintextMulMany;
            cryptoContext->Decrypt(keyPair.secretKey, ciphertextMul12345, &plaintextMulMany);

            plaintextResult1->SetLength(plaintextMul1->GetLength());
            plaintextResult2->SetLength(plaintextMul2->GetLength());
            plaintextResult3->SetLength(plaintextMul3->GetLength());

            std::string errMsg("EvalMult gives incorrect results");
            checkEquality(plaintextMul1->GetCoefPackedValue(), plaintextResult1->GetCoefPackedValue(), eps, errMsg);

            errMsg = "EvalMultAndRelinearize gives incorrect results";
            checkEquality(plaintextMul2->GetCoefPackedValue(), plaintextResult2->GetCoefPackedValue(), eps, errMsg);

            errMsg = "EvalMultAndRelinearize gives incorrect results";
            checkEquality(plaintextMul3->GetCoefPackedValue(), plaintextResult3->GetCoefPackedValue(), eps, errMsg);

            errMsg = "EvalMultAndRelinearize gives incorrect results";
            checkEquality(plaintextMulMany->GetCoefPackedValue(), plaintextResult3->GetCoefPackedValue(), eps, errMsg);

            if (SUCCESS != testData.error) {
                // make it fail
                EXPECT_EQ(0, 1);
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
            UNIT_TEST_HANDLE_ALL_EXCEPTIONS;
        }
    }

    void UnitTest_EvalMultErrorHandling(const TEST_CASE_UTGENERAL_EVALMULT& testData,
                                        const std::string& failmsg = std::string()) {
        try {
            CryptoContext<Element> cryptoContext(UnitTestGenerateContext(testData.params));

            ////////////////////////////////////////////////////////////
            // Perform the key generation operation.
            ////////////////////////////////////////////////////////////
            auto keyPair = cryptoContext->KeyGen();
            ASSERT_TRUE(keyPair.good()) << "Key generation failed!";
            // Create evaluation key vector to be used in keyswitching
            if (INVALID_PRIVATE_KEY == testData.error)
                cryptoContext->EvalMultKeyGen(nullptr);
            else
                cryptoContext->EvalMultKeyGen(keyPair.secretKey);

            ////////////////////////////////////////////////////////////
            // Plaintext
            ////////////////////////////////////////////////////////////
            Plaintext plaintext1(nullptr);
            Plaintext plaintext2(nullptr);

            Plaintext plaintextResult(nullptr);
            if (CKKSRNS_SCHEME == testData.params.schemeId) {
                std::vector<std::complex<double>> vectorOfInts1 = {0, 1, 2, 3, 4, 5, 6, 7};
                std::vector<std::complex<double>> vectorOfInts2 = {7, 6, 5, 4, 3, 2, 1, 0};

                plaintext1 = cryptoContext->MakeCKKSPackedPlaintext(vectorOfInts1);
                plaintext2 = cryptoContext->MakeCKKSPackedPlaintext(vectorOfInts2);

                std::vector<std::complex<double>> vectorOfIntsResult = {0, 6, 10, 12, 12, 10, 6, 0};

                plaintextResult = cryptoContext->MakeCKKSPackedPlaintext(vectorOfIntsResult);
            }
            else {
                std::vector<int64_t> vectorOfInts1 = {0, 1, 2, 3, 4, 5, 6, 7};
                std::vector<int64_t> vectorOfInts2 = {7, 6, 5, 4, 3, 2, 1, 0};

                plaintext1 = cryptoContext->MakePackedPlaintext(vectorOfInts1);
                plaintext2 = cryptoContext->MakePackedPlaintext(vectorOfInts2);

                std::vector<int64_t> vectorOfIntsResult = {0, 6, 10, 12, 12, 10, 6, 0};

                plaintextResult = cryptoContext->MakePackedPlaintext(vectorOfIntsResult);
            }

            ////////////////////////////////////////////////////////////
            // Encryption
            ////////////////////////////////////////////////////////////
            auto ciphertext1 = (INVALID_PUBLIC_KEY == testData.error) ?
                                   cryptoContext->Encrypt(static_cast<const PublicKey<Element>>(nullptr), plaintext1) :
                                   cryptoContext->Encrypt(keyPair.publicKey, plaintext1);
            auto ciphertext2 = (INVALID_PLAINTEXT_ENCRYPT == testData.error) ?
                                   cryptoContext->Encrypt(keyPair.publicKey, nullptr) :
                                   cryptoContext->Encrypt(keyPair.publicKey, plaintext2);

            ////////////////////////////////////////////////////////////
            // EvalMult Operation
            ////////////////////////////////////////////////////////////
            // Perform consecutive multiplications and do a keyswtiching at the end.
            Ciphertext<Element> ciphertextMul12 = nullptr;
            if (INVALID_CIPHERTEXT_ERROR1 == testData.error)
                ciphertextMul12 = cryptoContext->EvalMultNoRelin(nullptr, ciphertext2);
            else if (INVALID_CIPHERTEXT_ERROR2 == testData.error)
                ciphertextMul12 = cryptoContext->EvalMultNoRelin(ciphertext1, nullptr);
            else
                ciphertextMul12 = cryptoContext->EvalMultNoRelin(ciphertext1, ciphertext2);

            Ciphertext<Element> ciphertextMult = (INVALID_CIPHERTEXT_ERROR3 == testData.error) ?
                                                     cryptoContext->Relinearize(nullptr) :
                                                     cryptoContext->Relinearize(ciphertextMul12);

            ////////////////////////////////////////////////////////////
            // Decryption of multiplicative results with and without keyswtiching (depends
            // on the level)
            ////////////////////////////////////////////////////////////
            Plaintext plaintextMult;
            if (INVALID_CIPHERTEXT_DECRYPT == testData.error)
                cryptoContext->Decrypt(keyPair.secretKey, nullptr, &plaintextMult);
            else if (INVALID_PLAINTEXT_DECRYPT == testData.error)
                cryptoContext->Decrypt(keyPair.secretKey, ciphertextMult, nullptr);
            else if (INVALID_PRIVATE_KEY_DECRYPT == testData.error)
                cryptoContext->Decrypt(nullptr, ciphertextMult, &plaintextMult);
            else
                cryptoContext->Decrypt(keyPair.secretKey, ciphertextMult, &plaintextMult);

            plaintextResult->SetLength(plaintextMult->GetLength());

            std::string errMsg(failmsg);
            if (CKKSRNS_SCHEME == testData.params.schemeId)
                checkEquality(plaintextMult->GetCKKSPackedValue(), plaintextResult->GetCKKSPackedValue(), eps, errMsg);
            else
                checkEquality(plaintextMult->GetPackedValue(), plaintextResult->GetPackedValue(), eps, errMsg);

            if (SUCCESS != testData.error) {
                // make it fail
                EXPECT_EQ(0, 1);
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
            UNIT_TEST_HANDLE_ALL_EXCEPTIONS;
        }
    }

    void UnitTest_Relinearization(const TEST_CASE_UTGENERAL_EVALMULT& testData,
                                  const std::string& failmsg = std::string()) {
        try {
            CryptoContext<Element> cryptoContext(UnitTestGenerateContext(testData.params));

            ////////////////////////////////////////////////////////////
            // Perform the key generation operation.
            ////////////////////////////////////////////////////////////
            auto keyPair = cryptoContext->KeyGen();
            ASSERT_TRUE(keyPair.good()) << "Key generation failed!";
            // Create evaluation key vector to be used in keyswitching
            cryptoContext->EvalMultKeysGen(keyPair.secretKey);

            ////////////////////////////////////////////////////////////
            // Plaintext
            ////////////////////////////////////////////////////////////
            Plaintext plaintext1(nullptr);
            Plaintext plaintext2(nullptr);

            Plaintext plaintextResult(nullptr);
            Plaintext plaintextResult2(nullptr);
            if (CKKSRNS_SCHEME == testData.params.schemeId) {
                std::vector<std::complex<double>> vectorOfInts1 = {0, 1, 2, 3, 4, 5, 6, 7};
                std::vector<std::complex<double>> vectorOfInts2 = {7, 6, 5, 4, 3, 2, 1, 0};

                plaintext1 = cryptoContext->MakeCKKSPackedPlaintext(vectorOfInts1);
                plaintext2 = cryptoContext->MakeCKKSPackedPlaintext(vectorOfInts2);

                std::vector<std::complex<double>> vectorOfIntsResult  = {0, 6, 10, 12, 12, 10, 6, 0};
                std::vector<std::complex<double>> vectorOfIntsResult2 = {0, 6, 20, 36, 48, 50, 36, 0};

                plaintextResult  = cryptoContext->MakeCKKSPackedPlaintext(vectorOfIntsResult);
                plaintextResult2 = cryptoContext->MakeCKKSPackedPlaintext(vectorOfIntsResult2);
            }
            else {
                std::vector<int64_t> vectorOfInts1 = {0, 1, 2, 3, 4, 5, 6, 7};
                std::vector<int64_t> vectorOfInts2 = {7, 6, 5, 4, 3, 2, 1, 0};

                plaintext1 = cryptoContext->MakePackedPlaintext(vectorOfInts1);
                plaintext2 = cryptoContext->MakePackedPlaintext(vectorOfInts2);

                std::vector<int64_t> vectorOfIntsResult  = {0, 6, 10, 12, 12, 10, 6, 0};
                std::vector<int64_t> vectorOfIntsResult2 = {0, 6, 20, 36, 48, 50, 36, 0};

                plaintextResult  = cryptoContext->MakePackedPlaintext(vectorOfIntsResult);
                plaintextResult2 = cryptoContext->MakePackedPlaintext(vectorOfIntsResult2);
            }
            ////////////////////////////////////////////////////////////
            // Encryption
            ////////////////////////////////////////////////////////////
            auto ciphertext1 = cryptoContext->Encrypt(keyPair.publicKey, plaintext1);
            auto ciphertext2 = cryptoContext->Encrypt(keyPair.publicKey, plaintext2);

            ////////////////////////////////////////////////////////////
            // EvalMult Operation
            ////////////////////////////////////////////////////////////
            // Perform consecutive multiplications and do a keyswtiching at the end.
            auto ciphertextMul12 = cryptoContext->EvalMultNoRelin(ciphertext1, ciphertext2);
            auto ciphertextMult  = cryptoContext->Relinearize(ciphertextMul12);

            ////////////////////////////////////////////////////////////
            // Decryption of multiplicative results with and without keyswtiching (depends
            // on the level)
            ////////////////////////////////////////////////////////////
            Plaintext plaintextMult;
            cryptoContext->Decrypt(keyPair.secretKey, ciphertextMult, &plaintextMult);
            plaintextMult->SetLength(plaintextResult->GetLength());

            std::string errMsg = failmsg + " Relinearization after one multiplication failed.";
            if (CKKSRNS_SCHEME == testData.params.schemeId)
                checkEquality(plaintextMult->GetCKKSPackedValue(), plaintextResult->GetCKKSPackedValue(), eps, errMsg);
            else
                checkEquality(plaintextMult->GetPackedValue(), plaintextResult->GetPackedValue(), eps, errMsg);

            ciphertextMult = ciphertextMul12;
            cryptoContext->Relinearize(ciphertextMult);
            cryptoContext->Decrypt(keyPair.secretKey, ciphertextMult, &plaintextMult);
            plaintextMult->SetLength(plaintextResult->GetLength());

            errMsg = failmsg + " In-place relinearization after one multiplication failed.";
            if (CKKSRNS_SCHEME == testData.params.schemeId)
                checkEquality(plaintextMult->GetCKKSPackedValue(), plaintextResult->GetCKKSPackedValue(), eps, errMsg);
            else
                checkEquality(plaintextMult->GetPackedValue(), plaintextResult->GetPackedValue(), eps, errMsg);

            // Perform consecutive multiplications and do a keyswtiching at the end.
            auto ciphertextMul123 = cryptoContext->EvalMultNoRelin(ciphertext1, ciphertextMul12);
            auto ciphertextMult2  = cryptoContext->Relinearize(ciphertextMul123);

            ////////////////////////////////////////////////////////////
            // Decryption of multiplicative results with and without keyswtiching (depends
            // on the level)
            ////////////////////////////////////////////////////////////
            Plaintext plaintextMult2;
            cryptoContext->Decrypt(keyPair.secretKey, ciphertextMult2, &plaintextMult2);
            plaintextMult2->SetLength(plaintextResult2->GetLength());

            errMsg = failmsg + " Relinearization after two multiplications failed.";
            if (CKKSRNS_SCHEME == testData.params.schemeId)
                checkEquality(plaintextMult2->GetCKKSPackedValue(), plaintextResult2->GetCKKSPackedValue(), eps,
                              errMsg);
            else
                checkEquality(plaintextMult2->GetPackedValue(), plaintextResult2->GetPackedValue(), eps, errMsg);

            ciphertextMult2 = ciphertextMul123;
            cryptoContext->Relinearize(ciphertextMult2);
            cryptoContext->Decrypt(keyPair.secretKey, ciphertextMult2, &plaintextMult2);
            plaintextMult2->SetLength(plaintextResult2->GetLength());

            errMsg = failmsg + " In-place relinearization after two multiplications failed.";
            if (CKKSRNS_SCHEME == testData.params.schemeId)
                checkEquality(plaintextMult2->GetCKKSPackedValue(), plaintextResult2->GetCKKSPackedValue(), eps,
                              errMsg);
            else
                checkEquality(plaintextMult2->GetPackedValue(), plaintextResult2->GetPackedValue(), eps, errMsg);
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
TEST_P(UTGENERAL_EVALMULT, EvalMult) {
    setupSignals();
    auto test = GetParam();

    switch (test.testCaseType) {
        case EVAL_MULT_ERROR_HANDLING:
            UnitTest_EvalMultErrorHandling(test, test.buildTestName());
            break;
        case EVAL_MULT_MANY_ERROR_HANDLING:
            UnitTest_EvalMultManyErrorHandling(test, test.buildTestName());
            break;
        case RELIN_TEST:
            UnitTest_Relinearization(test, test.buildTestName());
            break;
        default:
            break;
    }
}

INSTANTIATE_TEST_SUITE_P(UnitTests, UTGENERAL_EVALMULT, ::testing::ValuesIn(testCasesUTGENERAL_EVALMULT), testName);
