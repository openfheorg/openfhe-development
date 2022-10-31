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

#include "openfhe.h"
#include "UnitTestUtils.h"
#include "UnitTestCCParams.h"
#include "UnitTestCryptoContext.h"
#include "utils/demangle.h"
#include "scheme/ckksrns/ckksrns-utils.h"
#include "scheme/ckksrns/cryptocontext-ckksrns.h"

#include <iostream>
#include <vector>
#include "gtest/gtest.h"
#include <cxxabi.h>
#include <iterator>

using namespace lbcrypto;

//===========================================================================================================
enum TEST_CASE_TYPE { NOISE_ESTIMATION, FULL_NOISE_FLOODING };

static std::ostream& operator<<(std::ostream& os, const TEST_CASE_TYPE& type) {
    std::string typeName;
    switch (type) {
        case NOISE_ESTIMATION:
            typeName = "NOISE_ESTIMATION";
            break;
        case FULL_NOISE_FLOODING:
            typeName = "FULL_NOISE_FLOODING";
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
constexpr uint32_t MULT_DEPTH   = 25;
constexpr uint32_t RDIM         = 512;
constexpr uint32_t NUM_LRG_DIGS = 3;

#if NATIVEINT == 128
constexpr uint32_t SMODSIZE = 78;
constexpr uint32_t FMODSIZE = 89;
#else
constexpr uint32_t SMODSIZE = 59;
constexpr uint32_t FMODSIZE = 60;
#endif

// clang-format off
static std::vector<TEST_CASE_UTCKKSRNS_NOISE_FLOODING> testCases = {
    // TestType,       Descr, Scheme,          RDim, MultDepth,  SModSize,     DSize, BatchSz, SecKeyDist,      MaxRelinSkDeg, FModSize,  SecLvl,       KSTech, ScalTech,        LDigits,      PtMod, StdDev, EvalAddCt, KSCt, MultTech, EncTech, PREMode, MultipartyMode, DecryptionNoiseMode
    { NOISE_ESTIMATION, "01", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,     DFLT,  DFLT,    UNIFORM_TERNARY, DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FIXEDAUTO,       NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT,           NOISE_FLOODING_DECRYPT}},
    { NOISE_ESTIMATION, "02", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,     DFLT,  DFLT,    SPARSE_TERNARY,  DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FIXEDAUTO,       NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT,           NOISE_FLOODING_DECRYPT}},
    { NOISE_ESTIMATION, "03", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,     DFLT,  DFLT,    UNIFORM_TERNARY, DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FIXEDMANUAL,     NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT,           NOISE_FLOODING_DECRYPT}},
    { NOISE_ESTIMATION, "04", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,     DFLT,  DFLT,    SPARSE_TERNARY,  DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FIXEDMANUAL,     NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT,           NOISE_FLOODING_DECRYPT}},
#if NATIVEINT != 128
    { NOISE_ESTIMATION, "05", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,     DFLT,  DFLT,    SPARSE_TERNARY,  DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FLEXIBLEAUTO,    NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT,           NOISE_FLOODING_DECRYPT}},
    { NOISE_ESTIMATION, "06", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,     DFLT,  DFLT,    UNIFORM_TERNARY, DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FLEXIBLEAUTO,    NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT,           NOISE_FLOODING_DECRYPT}},
    { NOISE_ESTIMATION, "07", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,     DFLT,  DFLT,    SPARSE_TERNARY,  DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FLEXIBLEAUTOEXT, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT,           NOISE_FLOODING_DECRYPT}},
    { NOISE_ESTIMATION, "08", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,     DFLT,  DFLT,    UNIFORM_TERNARY, DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FLEXIBLEAUTOEXT, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT,           NOISE_FLOODING_DECRYPT}},
#endif
    // TestType,          Descr, Scheme,          RDim, MultDepth,  SModSize,     DSize, BatchSz, SecKeyDist,      MaxRelinSkDeg, FModSize,  SecLvl,       KSTech, ScalTech,        LDigits,      PtMod, StdDev, EvalAddCt, KSCt, MultTech, EncTech, PREMode, MultipartyMode, DecryptionNoiseMode
    { FULL_NOISE_FLOODING, "01", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,     DFLT,  DFLT,    UNIFORM_TERNARY, DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FIXEDAUTO,       NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT,           NOISE_FLOODING_DECRYPT}},
    { FULL_NOISE_FLOODING, "02", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,     DFLT,  DFLT,    SPARSE_TERNARY,  DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FIXEDAUTO,       NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT,           NOISE_FLOODING_DECRYPT}},
    { FULL_NOISE_FLOODING, "03", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,     DFLT,  DFLT,    UNIFORM_TERNARY, DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FIXEDMANUAL,     NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT,           NOISE_FLOODING_DECRYPT}},
    { FULL_NOISE_FLOODING, "04", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,     DFLT,  DFLT,    SPARSE_TERNARY,  DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FIXEDMANUAL,     NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT,           NOISE_FLOODING_DECRYPT}},
#if NATIVEINT != 128
    { FULL_NOISE_FLOODING, "05", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,     DFLT,  DFLT,    SPARSE_TERNARY,  DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FLEXIBLEAUTO,    NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT,           NOISE_FLOODING_DECRYPT}},
    { FULL_NOISE_FLOODING, "06", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,     DFLT,  DFLT,    UNIFORM_TERNARY, DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FLEXIBLEAUTO,    NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT,           NOISE_FLOODING_DECRYPT}},
    { FULL_NOISE_FLOODING, "07", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,     DFLT,  DFLT,    SPARSE_TERNARY,  DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FLEXIBLEAUTOEXT, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT,           NOISE_FLOODING_DECRYPT}},
    { FULL_NOISE_FLOODING, "08", {CKKSRNS_SCHEME, RDIM, MULT_DEPTH, SMODSIZE,     DFLT,  DFLT,    UNIFORM_TERNARY, DFLT,          FMODSIZE,  HEStd_NotSet, HYBRID, FLEXIBLEAUTOEXT, NUM_LRG_DIGS, DFLT,  DFLT,   DFLT,      DFLT, DFLT,     DFLT,    DFLT,    DFLT,           NOISE_FLOODING_DECRYPT}},

#endif
};
// clang-format on
//===========================================================================================================
class UTCKKSRNS_NOISE_FLOODING : public ::testing::TestWithParam<TEST_CASE_UTCKKSRNS_NOISE_FLOODING> {
    using Element = DCRTPoly;

    // The precision after which we consider two values equal.
    // This is necessary because CKKS works for approximate numbers.
    const double eps    = 0.0001;
    const double buffer = 3;

    Ciphertext<DCRTPoly> EncryptedComputation(CryptoContext<DCRTPoly>& cryptoContext, PublicKey<DCRTPoly> publicKey) {
        // Encoding and encryption of inputs
        // Generate random input
        std::vector<double> vec1 = {0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8};
        std::vector<double> vec2 = {1, 1, 0, 0, 1, 0, 0, 1};

        // Encoding as plaintexts and encrypt
        Plaintext ptxt1            = cryptoContext->MakeCKKSPackedPlaintext(vec1);
        Plaintext ptxt2            = cryptoContext->MakeCKKSPackedPlaintext(vec2);
        Ciphertext<DCRTPoly> ciph1 = cryptoContext->Encrypt(publicKey, ptxt1);
        Ciphertext<DCRTPoly> ciph2 = cryptoContext->Encrypt(publicKey, ptxt2);

        Ciphertext<DCRTPoly> ciphMult = cryptoContext->EvalMult(ciph1, ciph2);
        cryptoContext->ModReduceInPlace(ciphMult);
        Ciphertext<DCRTPoly> ciphMult2 = cryptoContext->EvalMult(ciphMult, ciph1);
        cryptoContext->ModReduceInPlace(ciphMult2);
        Ciphertext<DCRTPoly> ciphResult = cryptoContext->EvalAdd(ciphMult2, ciph2);

        return ciphResult;
    }

protected:
    void SetUp() {}

    void TearDown() {
        CryptoContextFactory<DCRTPoly>::ReleaseAllContexts();
    }

    void UnitTest_NoiseEstimation(const TEST_CASE_UTCKKSRNS_NOISE_FLOODING& testData,
                                  const std::string& failmsg = std::string()) {
        try {
            CCParams<CryptoContextCKKSRNS> parametersNoiseEstimation;
            setCryptoContextParametersFromUnitTestCCParams(testData.params, parametersNoiseEstimation);
            parametersNoiseEstimation.SetDecryptionNoiseMode(NOISE_FLOODING_DECRYPT);
            parametersNoiseEstimation.SetExecutionMode(EXEC_NOISE_ESTIMATION);

            auto cryptoContextNoiseEstimation = GenCryptoContext(parametersNoiseEstimation);
            cryptoContextNoiseEstimation->Enable(PKE);
            cryptoContextNoiseEstimation->Enable(LEVELEDSHE);

            auto keyPairNoiseEstimation = cryptoContextNoiseEstimation->KeyGen();
            cryptoContextNoiseEstimation->EvalMultKeyGen(keyPairNoiseEstimation.secretKey);

            auto noiseCiphertext = EncryptedComputation(cryptoContextNoiseEstimation, keyPairNoiseEstimation.publicKey);

            Plaintext noisePlaintext;
            cryptoContextNoiseEstimation->Decrypt(keyPairNoiseEstimation.secretKey, noiseCiphertext, &noisePlaintext);
            noisePlaintext->SetLength(1);
            double noise         = noisePlaintext->GetCKKSPackedValue()[0].real();
            double expectedNoise = 20.9827;
            EXPECT_TRUE(checkEquality(noise, expectedNoise, buffer)) << failmsg + " CKKS Noise estimation fails";
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
    void UnitTest_FullNoiseFlooding(const TEST_CASE_UTCKKSRNS_NOISE_FLOODING& testData,
                                    const std::string& failmsg = std::string()) {
        // ----------------------- Setup first CryptoContext -----------------------------
        // Phase 1 will be for noise estimation.
        // -------------------------------------------------------------------------------
        CCParams<CryptoContextCKKSRNS> parametersNoiseEstimation;
        setCryptoContextParametersFromUnitTestCCParams(testData.params, parametersNoiseEstimation);
        parametersNoiseEstimation.SetDecryptionNoiseMode(NOISE_FLOODING_DECRYPT);
        parametersNoiseEstimation.SetExecutionMode(EXEC_NOISE_ESTIMATION);

        auto cryptoContextNoiseEstimation = GenCryptoContext(parametersNoiseEstimation);
        cryptoContextNoiseEstimation->Enable(PKE);
        cryptoContextNoiseEstimation->Enable(LEVELEDSHE);

        auto keyPairNoiseEstimation = cryptoContextNoiseEstimation->KeyGen();
        cryptoContextNoiseEstimation->EvalMultKeyGen(keyPairNoiseEstimation.secretKey);

        auto noiseCiphertext = EncryptedComputation(cryptoContextNoiseEstimation, keyPairNoiseEstimation.publicKey);

        Plaintext noisePlaintext;
        cryptoContextNoiseEstimation->Decrypt(keyPairNoiseEstimation.secretKey, noiseCiphertext, &noisePlaintext);
        noisePlaintext->SetLength(1);
        double noise = noisePlaintext->GetCKKSPackedValue()[0].real();

        // ----------------------- Setup second CryptoContext -----------------------------
        // Phase 2 will be for the actual evaluation.
        // IMPORTANT: We must use a different public/private key pair here to achieve the
        // security guarantees for noise flooding.
        // -------------------------------------------------------------------------------
        CCParams<CryptoContextCKKSRNS> parametersEvaluation;
        setCryptoContextParametersFromUnitTestCCParams(testData.params, parametersEvaluation);
        parametersEvaluation.SetDecryptionNoiseMode(NOISE_FLOODING_DECRYPT);
        parametersEvaluation.SetExecutionMode(EXEC_EVALUATION);
        parametersEvaluation.SetNoiseEstimate(noise);

        auto cryptoContextEvaluation = GenCryptoContext(parametersEvaluation);
        cryptoContextEvaluation->Enable(PKE);
        cryptoContextEvaluation->Enable(LEVELEDSHE);

        auto keyPairEvaluation = cryptoContextEvaluation->KeyGen();
        cryptoContextEvaluation->EvalMultKeyGen(keyPairEvaluation.secretKey);

        auto ciphertextResult = EncryptedComputation(cryptoContextEvaluation, keyPairEvaluation.publicKey);

        Plaintext result;
        cryptoContextEvaluation->Decrypt(keyPairEvaluation.secretKey, ciphertextResult, &result);
        size_t vecSize = 8;
        result->SetLength(vecSize);

        std::vector<std::complex<double>> expectedResult = {1.01, 1.04, 0, 0, 1.25, 0, 0, 1.64};

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
        default:
            break;
    }
}

INSTANTIATE_TEST_SUITE_P(UnitTests, UTCKKSRNS_NOISE_FLOODING, ::testing::ValuesIn(testCases), testName);
