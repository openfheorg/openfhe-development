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

#include "ciphertext-ser.h"
#include "cryptocontext-ser.h"
#include "key/key-ser.h"
#include "scheme/bgvrns/bgvrns-ser.h"

#include "UnitTestUtils.h"
#include "UnitTestSer.h"
#include "UnitTestCCParams.h"
#include "UnitTestCryptoContext.h"
#include "utils/exception.h"
#include "globals.h"  // for SERIALIZE_PRECOMPUTE

#include "include/gtest/gtest.h"
#include <iostream>
#include <sstream>
#include <vector>
#include <cxxabi.h>
#include "utils/demangle.h"

using namespace lbcrypto;

//===========================================================================================================
enum TEST_CASE_TYPE {
    CONTEXT = 0,
    KEYS_AND_CIPHERTEXTS,
};

static std::ostream& operator<<(std::ostream& os, const TEST_CASE_TYPE& type) {
    std::string typeName;
    switch (type) {
        case CONTEXT:
            typeName = "CONTEXT";
            break;
        case KEYS_AND_CIPHERTEXTS:
            typeName = "KEYS_AND_CIPHERTEXTS";
            break;
        default:
            typeName = "UNKNOWN";
            break;
    }
    return os << typeName;
}
//===========================================================================================================
struct TEST_CASE_UTBGVRNS_SER {
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
static auto testName = [](const testing::TestParamInfo<TEST_CASE_UTBGVRNS_SER>& test) {
    return test.param.buildTestName();
};

static std::ostream& operator<<(std::ostream& os, const TEST_CASE_UTBGVRNS_SER& test) {
    return os << test.toString();
}
//===========================================================================================================
/***
 * SIZEMODULI: bit-length of the moduli composing the ciphertext modulus (size of each co-prime in bits or
 *             scaling factor bits).
 * 		       Should fit into a machine word, i.e., less than 64.
 * DSIZE:      The bit decomposition count used in relinearization.
 *  	       Use 0 to go with max possible. Use small values (3-4?) if you need rotations before any multiplications.
 * PTM:        The plaintext modulus.
 * BATCH:      The length of the packed vectors to be used with CKKS.
 */
constexpr usint RING_DIM        = 32;
constexpr usint MULT_DEPTH      = 3;
constexpr usint MAX_RELIN_DEG   = 2;
constexpr usint DSIZE           = 4;
constexpr usint PTM             = 65537;
constexpr usint BATCH           = 16;
constexpr usint FIRST_MOD_SIZE  = 60;
constexpr SecurityLevel SEC_LVL = HEStd_NotSet;
// TODO (dsuponit): are there any changes under this condition - #if NATIVEINT != 128?

// clang-format off
static std::vector<TEST_CASE_UTBGVRNS_SER> testCases = {
    // TestType, Descr, Scheme,      RDim,     MultDepth,  SModSize,   DSize, BatchSz, SecKeyDist, MaxRelinSkDeg, FModSize,       SecLvl,  KSTech, ScalTech,        LDigits, PtMod, StdDev,   EvalAddCt, KSCt, MultTech, EncTech, PREMode
    { CONTEXT, "01", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       DSIZE, BATCH,   DFLT,       MAX_RELIN_DEG, FIRST_MOD_SIZE, SEC_LVL, BV,     FLEXIBLEAUTO,    DFLT,    PTM,   DFLT,     DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { CONTEXT, "02", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       DSIZE, BATCH,   DFLT,       MAX_RELIN_DEG, FIRST_MOD_SIZE, SEC_LVL, BV,     FIXEDMANUAL,     DFLT,    PTM,   DFLT,     DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { CONTEXT, "03", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       DSIZE, BATCH,   DFLT,       MAX_RELIN_DEG, FIRST_MOD_SIZE, SEC_LVL, BV,     FIXEDAUTO,       DFLT,    PTM,   DFLT,     DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { CONTEXT, "04", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       DSIZE, BATCH,   DFLT,       MAX_RELIN_DEG, FIRST_MOD_SIZE, SEC_LVL, BV,     FLEXIBLEAUTOEXT, DFLT,    PTM,   DFLT,     DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { CONTEXT, "05", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       DSIZE, BATCH,   DFLT,       MAX_RELIN_DEG, FIRST_MOD_SIZE, SEC_LVL, HYBRID, FLEXIBLEAUTO,    DFLT,    PTM,   DFLT,     DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { CONTEXT, "06", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       DSIZE, BATCH,   DFLT,       MAX_RELIN_DEG, FIRST_MOD_SIZE, SEC_LVL, HYBRID, FIXEDMANUAL,     DFLT,    PTM,   DFLT,     DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { CONTEXT, "07", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       DSIZE, BATCH,   DFLT,       MAX_RELIN_DEG, FIRST_MOD_SIZE, SEC_LVL, HYBRID, FIXEDAUTO,       DFLT,    PTM,   DFLT,     DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { CONTEXT, "08", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       DSIZE, BATCH,   DFLT,       MAX_RELIN_DEG, FIRST_MOD_SIZE, SEC_LVL, HYBRID, FLEXIBLEAUTOEXT, DFLT,    PTM,   DFLT,     DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    // ==========================================
    // TestType,           Descr, Scheme,         RDim,     MultDepth,  SModSize,   DSize, BatchSz, SecKeyDist, MaxRelinSkDeg, FModSize,       SecLvl,  KSTech, ScalTech,        LDigits, PtMod, StdDev,   EvalAddCt, KSCt, MultTech, EncTech, PREMode
    { KEYS_AND_CIPHERTEXTS, "01", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       0,     BATCH,   DFLT,       MAX_RELIN_DEG, FIRST_MOD_SIZE, SEC_LVL, HYBRID, FLEXIBLEAUTO,    DFLT,    PTM,   DFLT,     DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { KEYS_AND_CIPHERTEXTS, "02", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       0,     BATCH,   DFLT,       MAX_RELIN_DEG, FIRST_MOD_SIZE, SEC_LVL, HYBRID, FIXEDMANUAL,     DFLT,    PTM,   DFLT,     DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { KEYS_AND_CIPHERTEXTS, "03", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       0,     BATCH,   DFLT,       MAX_RELIN_DEG, FIRST_MOD_SIZE, SEC_LVL, HYBRID, FIXEDAUTO,       DFLT,    PTM,   DFLT,     DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { KEYS_AND_CIPHERTEXTS, "04", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       0,     BATCH,   DFLT,       MAX_RELIN_DEG, FIRST_MOD_SIZE, SEC_LVL, HYBRID, FLEXIBLEAUTOEXT, DFLT,    PTM,   DFLT,     DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { KEYS_AND_CIPHERTEXTS, "05", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       0,     BATCH,   DFLT,       MAX_RELIN_DEG, FIRST_MOD_SIZE, SEC_LVL, HYBRID, FLEXIBLEAUTO,    DFLT,    PTM,   DFLT,     DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { KEYS_AND_CIPHERTEXTS, "06", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       0,     BATCH,   DFLT,       MAX_RELIN_DEG, FIRST_MOD_SIZE, SEC_LVL, HYBRID, FIXEDMANUAL,     DFLT,    PTM,   DFLT,     DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { KEYS_AND_CIPHERTEXTS, "07", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       0,     BATCH,   DFLT,       MAX_RELIN_DEG, FIRST_MOD_SIZE, SEC_LVL, HYBRID, FIXEDAUTO,       DFLT,    PTM,   DFLT,     DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { KEYS_AND_CIPHERTEXTS, "08", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       0,     BATCH,   DFLT,       MAX_RELIN_DEG, FIRST_MOD_SIZE, SEC_LVL, HYBRID, FLEXIBLEAUTOEXT, DFLT,    PTM,   DFLT,     DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { KEYS_AND_CIPHERTEXTS, "09", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       DSIZE, BATCH,   DFLT,       MAX_RELIN_DEG, FIRST_MOD_SIZE, SEC_LVL, BV,     FLEXIBLEAUTO,    DFLT,    PTM,   DFLT,     DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { KEYS_AND_CIPHERTEXTS, "10", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       DSIZE, BATCH,   DFLT,       MAX_RELIN_DEG, FIRST_MOD_SIZE, SEC_LVL, BV,     FIXEDMANUAL,     DFLT,    PTM,   DFLT,     DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { KEYS_AND_CIPHERTEXTS, "11", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       DSIZE, BATCH,   DFLT,       MAX_RELIN_DEG, FIRST_MOD_SIZE, SEC_LVL, BV,     FIXEDAUTO,       DFLT,    PTM,   DFLT,     DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { KEYS_AND_CIPHERTEXTS, "12", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       DSIZE, BATCH,   DFLT,       MAX_RELIN_DEG, FIRST_MOD_SIZE, SEC_LVL, BV,     FLEXIBLEAUTOEXT, DFLT,    PTM,   DFLT,     DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { KEYS_AND_CIPHERTEXTS, "13", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       DSIZE, BATCH,   DFLT,       MAX_RELIN_DEG, FIRST_MOD_SIZE, SEC_LVL, BV,     FLEXIBLEAUTO,    DFLT,    PTM,   DFLT,     DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { KEYS_AND_CIPHERTEXTS, "14", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       DSIZE, BATCH,   DFLT,       MAX_RELIN_DEG, FIRST_MOD_SIZE, SEC_LVL, BV,     FIXEDMANUAL,     DFLT,    PTM,   DFLT,     DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { KEYS_AND_CIPHERTEXTS, "15", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       DSIZE, BATCH,   DFLT,       MAX_RELIN_DEG, FIRST_MOD_SIZE, SEC_LVL, BV,     FIXEDAUTO,       DFLT,    PTM,   DFLT,     DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { KEYS_AND_CIPHERTEXTS, "16", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, DFLT,       DSIZE, BATCH,   DFLT,       MAX_RELIN_DEG, FIRST_MOD_SIZE, SEC_LVL, BV,     FLEXIBLEAUTOEXT, DFLT,    PTM,   DFLT,     DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    // ==========================================
};
// clang-format on
//===========================================================================================================
class UTBGVRNS_SER : public ::testing::TestWithParam<TEST_CASE_UTBGVRNS_SER> {
    using Element    = DCRTPoly;
    const double eps = EPSILON;

protected:
    void SetUp() {}

    void TearDown() {
        CryptoContextFactory<DCRTPoly>::ReleaseAllContexts();
    }

    void UnitTestContext(const TEST_CASE_UTBGVRNS_SER& testData, const std::string& failmsg = std::string()) {
        CryptoContext<Element> cc(UnitTestGenerateContext(testData.params));

        UnitTestContextWithSertype(cc, SerType::JSON, "json");
        UnitTestContextWithSertype(cc, SerType::BINARY, "binary");
    }

    template <typename ST>
    void TestKeysAndCiphertexts(const TEST_CASE_UTBGVRNS_SER& testData, const ST& sertype,
                                const std::string& failmsg = std::string()) {
        try {
            CryptoContext<Element> cc(UnitTestGenerateContext(testData.params));

            OPENFHE_DEBUG_FLAG(false);

            CryptoContextImpl<DCRTPoly>::ClearEvalMultKeys();
            CryptoContextImpl<DCRTPoly>::ClearEvalSumKeys();
            CryptoContextImpl<DCRTPoly>::ClearEvalAutomorphismKeys();

            // // The batch size for our tests.
            int vecSize = 10;

            OPENFHE_DEBUG("step 0");
            {
                std::stringstream s;
                Serial::Serialize(cc, s, sertype);
                ASSERT_TRUE(CryptoContextFactory<DCRTPoly>::GetContextCount() == 1);
                CryptoContextFactory<DCRTPoly>::ReleaseAllContexts();
                ASSERT_TRUE(CryptoContextFactory<DCRTPoly>::GetContextCount() == 0);
                Serial::Deserialize(cc, s, sertype);

                ASSERT_TRUE(cc) << "Deser failed";
                ASSERT_TRUE(CryptoContextFactory<DCRTPoly>::GetContextCount() == 1);
            }

            DisablePrecomputeCRTTablesAfterDeserializaton();
            KeyPair<DCRTPoly> kp = cc->KeyGen();
            KeyPair<DCRTPoly> kpnew;

            // Update the batchSize from the default value
            const auto cryptoParamsBGVrns =
                std::dynamic_pointer_cast<CryptoParametersBGVRNS>(kp.publicKey->GetCryptoParameters());

            EncodingParams encodingParamsNew(
                std::make_shared<EncodingParamsImpl>(cc->GetEncodingParams()->GetPlaintextModulus(), vecSize));
            cryptoParamsBGVrns->SetEncodingParams(encodingParamsNew);

            OPENFHE_DEBUG("step 1");
            {
                std::stringstream s;
                Serial::Serialize(kp.publicKey, s, sertype);
                Serial::Deserialize(kpnew.publicKey, s, sertype);
                EXPECT_EQ(*kp.publicKey, *kpnew.publicKey) << "Public key mismatch after ser/deser";
            }
            OPENFHE_DEBUG("step 2");
            {
                std::stringstream s;
                Serial::Serialize(kp.secretKey, s, sertype);
                Serial::Deserialize(kpnew.secretKey, s, sertype);
                EXPECT_EQ(*kp.secretKey, *kpnew.secretKey) << "Secret key mismatch after ser/deser";
            }
            OPENFHE_DEBUG("step 3");
            std::vector<int64_t> vals       = {1, 3, 5, 7, 9, 2, 4, 6, 8, 11};
            Plaintext plaintextShort        = cc->MakePackedPlaintext(vals);
            Ciphertext<DCRTPoly> ciphertext = cc->Encrypt(kp.publicKey, plaintextShort);

            OPENFHE_DEBUG("step 4");
            Ciphertext<DCRTPoly> newC;
            {
                std::stringstream s;
                Serial::Serialize(ciphertext, s, sertype);
                Serial::Deserialize(newC, s, sertype);
                EXPECT_EQ(*ciphertext, *newC) << "Ciphertext mismatch";
            }

            OPENFHE_DEBUG("step 5");
            Plaintext plaintextShortNew;
            cc->Decrypt(kp.secretKey, newC, &plaintextShortNew);
            plaintextShortNew->SetLength(plaintextShort->GetLength());

            std::stringstream bufferShort;
            bufferShort << "should be: " << plaintextShortNew->GetPackedValue()
                        << " - we get: " << plaintextShort->GetPackedValue();
            checkEquality(plaintextShortNew->GetPackedValue(), plaintextShort->GetPackedValue(), eps,
                          failmsg + " Decrypted serialization test fails" + bufferShort.str());

            OPENFHE_DEBUG("step 6");
            KeyPair<DCRTPoly> kp2 = cc->KeyGen();

            cc->EvalMultKeyGen(kp.secretKey);
            cc->EvalMultKeyGen(kp2.secretKey);
            cc->EvalSumKeyGen(kp.secretKey);
            cc->EvalSumKeyGen(kp2.secretKey);

            OPENFHE_DEBUG("step 7");
            // serialize a bunch of mult keys
            std::stringstream ser0;
            EXPECT_EQ(CryptoContextImpl<DCRTPoly>::SerializeEvalMultKey(ser0, sertype, kp.secretKey->GetKeyTag()), true)
                << "single eval mult key ser fails";
            std::stringstream ser2a;
            EXPECT_EQ(CryptoContextImpl<DCRTPoly>::SerializeEvalMultKey(ser2a, sertype, cc), true)
                << "context 1 eval mult key ser fails";
            std::stringstream ser3;
            EXPECT_EQ(CryptoContextImpl<DCRTPoly>::SerializeEvalMultKey(ser3, sertype), true)
                << "all context eval mult key ser fails";

            OPENFHE_DEBUG("step 8");
            // serialize a bunch of sum keys
            std::stringstream aser0;
            EXPECT_EQ(CryptoContextImpl<DCRTPoly>::SerializeEvalSumKey(aser0, sertype, kp.secretKey->GetKeyTag()), true)
                << "single eval sum key ser fails";
            std::stringstream aser2a;
            EXPECT_EQ(CryptoContextImpl<DCRTPoly>::SerializeEvalSumKey(aser2a, sertype, cc), true)
                << "single ctx eval sum key ser fails";
            std::stringstream aser3;
            EXPECT_EQ(CryptoContextImpl<DCRTPoly>::SerializeEvalSumKey(aser3, sertype), true)
                << "all eval sum key ser fails";

            OPENFHE_DEBUG("step 9");
            cc.reset();

            // test mult deserialize
            CryptoContextImpl<DCRTPoly>::ClearEvalMultKeys();
            CryptoContextImpl<DCRTPoly>::ClearEvalSumKeys();
            CryptoContextFactory<DCRTPoly>::ReleaseAllContexts();
            EXPECT_EQ(CryptoContextFactory<DCRTPoly>::GetContextCount(), 0) << "after release" << std::endl;

            std::vector<EvalKey<DCRTPoly>> evalMultKeys;
            CryptoContextImpl<DCRTPoly>::DeserializeEvalMultKey(ser0, sertype);
            EXPECT_EQ(CryptoContextFactory<DCRTPoly>::GetContextCount(), 1) << "one-key deser, context";
            EXPECT_EQ(CryptoContextImpl<DCRTPoly>::GetAllEvalMultKeys().size(), 1U) << "one-key deser, keys";

            CryptoContextImpl<DCRTPoly>::ClearEvalMultKeys();
            CryptoContextImpl<DCRTPoly>::ClearEvalSumKeys();
            CryptoContextFactory<DCRTPoly>::ReleaseAllContexts();

            CryptoContextImpl<DCRTPoly>::DeserializeEvalMultKey(ser2a, sertype);
            EXPECT_EQ(CryptoContextFactory<DCRTPoly>::GetContextCount(), 1) << "one-ctx deser, context";
            EXPECT_EQ(CryptoContextImpl<DCRTPoly>::GetAllEvalMultKeys().size(), 2U) << "one-ctx deser, keys";

            CryptoContextImpl<DCRTPoly>::ClearEvalMultKeys();
            CryptoContextImpl<DCRTPoly>::ClearEvalSumKeys();
            CryptoContextFactory<DCRTPoly>::ReleaseAllContexts();

            CryptoContextImpl<DCRTPoly>::DeserializeEvalMultKey(ser3, sertype);
            EXPECT_EQ(CryptoContextFactory<DCRTPoly>::GetContextCount(), 1) << "all-key deser, context";
            EXPECT_EQ(CryptoContextImpl<DCRTPoly>::GetAllEvalMultKeys().size(), 2U) << "all-key deser, keys";

            OPENFHE_DEBUG("step 10");
            // test sum deserialize

            CryptoContextImpl<DCRTPoly>::ClearEvalMultKeys();
            CryptoContextImpl<DCRTPoly>::ClearEvalSumKeys();
            CryptoContextFactory<DCRTPoly>::ReleaseAllContexts();

            CryptoContextImpl<DCRTPoly>::DeserializeEvalSumKey(aser0, sertype);
            EXPECT_EQ(CryptoContextFactory<DCRTPoly>::GetContextCount(), 1) << "one-key deser, context";
            EXPECT_EQ(CryptoContextImpl<DCRTPoly>::GetAllEvalSumKeys().size(), 1U) << "one-key deser, keys";

            CryptoContextImpl<DCRTPoly>::ClearEvalMultKeys();
            CryptoContextImpl<DCRTPoly>::ClearEvalSumKeys();
            CryptoContextFactory<DCRTPoly>::ReleaseAllContexts();

            CryptoContextImpl<DCRTPoly>::DeserializeEvalSumKey(aser2a, sertype);
            EXPECT_EQ(CryptoContextFactory<DCRTPoly>::GetContextCount(), 1) << "one-ctx deser, context";
            EXPECT_EQ(CryptoContextImpl<DCRTPoly>::GetAllEvalSumKeys().size(), 2U) << "one-ctx deser, keys";

            CryptoContextImpl<DCRTPoly>::ClearEvalMultKeys();
            CryptoContextImpl<DCRTPoly>::ClearEvalSumKeys();
            CryptoContextFactory<DCRTPoly>::ReleaseAllContexts();

            CryptoContextImpl<DCRTPoly>::DeserializeEvalSumKey(aser3, sertype);
            EXPECT_EQ(CryptoContextFactory<DCRTPoly>::GetContextCount(), 1) << "all-key deser, context";
            EXPECT_EQ(CryptoContextImpl<DCRTPoly>::GetAllEvalSumKeys().size(), 2U) << "all-key deser, keys";

            // ending cleanup
            EnablePrecomputeCRTTablesAfterDeserializaton();
            CryptoContextImpl<DCRTPoly>::ClearEvalMultKeys();
            CryptoContextImpl<DCRTPoly>::ClearEvalSumKeys();
            CryptoContextImpl<DCRTPoly>::ClearEvalAutomorphismKeys();
            CryptoContextFactory<DCRTPoly>::ReleaseAllContexts();
        }
        catch (std::exception& e) {
            EnablePrecomputeCRTTablesAfterDeserializaton();
            std::cerr << "Exception thrown from " << __func__ << "(): " << e.what() << std::endl;
            // make it fail
            EXPECT_TRUE(0 == 1) << failmsg;
        }
        catch (...) {
            EnablePrecomputeCRTTablesAfterDeserializaton();
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

    void UnitTestKeysAndCiphertexts(const TEST_CASE_UTBGVRNS_SER& testData,
                                    const std::string& failmsg = std::string()) {
        TestKeysAndCiphertexts(testData, SerType::JSON, "json");
        TestKeysAndCiphertexts(testData, SerType::BINARY, "binary");
    }
};
//===========================================================================================================
TEST_P(UTBGVRNS_SER, BGVSer) {
    setupSignals();
    auto test = GetParam();

    if (test.testCaseType == CONTEXT)
        UnitTestContext(test, test.buildTestName());
    else if (test.testCaseType == KEYS_AND_CIPHERTEXTS)
        UnitTestKeysAndCiphertexts(test, test.buildTestName());
}

INSTANTIATE_TEST_SUITE_P(UnitTests, UTBGVRNS_SER, ::testing::ValuesIn(testCases), testName);
