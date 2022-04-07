#if 0 // TODO uncomment test after merge to github
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
#include "UnitTestSer.h"
#include "UnitTestCCParams.h"
#include "UnitTestCryptoContext.h"

#include <iostream>
#include <vector>
#include "gtest/gtest.h"
#include <cxxabi.h>

#include "ciphertext-ser.h"
#include "cryptocontext-ser.h"
#include "scheme/ckksrns/ckksrns-ser.h"
#include "globals.h" // for SERIALIZE_PRECOMPUTE


using namespace lbcrypto;

//===========================================================================================================
enum TEST_CASE_TYPE {
    CONTEXT_WITH_SERTYPE = 0,
    KEYS_AND_CIPHERTEXTS,
    NO_CRT_TABLES,
};

static std::ostream& operator<<(std::ostream& os, const TEST_CASE_TYPE& type) {
    std::string typeName;
    switch (type) {
    case CONTEXT_WITH_SERTYPE:
        typeName = "CONTEXT_WITH_SERTYPE";
        break;
    case KEYS_AND_CIPHERTEXTS:
        typeName = "KEYS_AND_CIPHERTEXTS";
        break;
    case NO_CRT_TABLES:
        typeName = "NO_CRT_TABLES";
        break;
    default:
        typeName = "UNKNOWN";
        break;
    }
    return os << typeName;
}
//===========================================================================================================
struct TEST_CASE {
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
static auto testName = [](const testing::TestParamInfo<TEST_CASE>& test) {
    return test.param.buildTestName();
};

static std::ostream& operator<<(std::ostream& os, const TEST_CASE& test) {
    return os << test.toString();
}
//===========================================================================================================
/* *
 * ORDER: Cyclotomic order. Must be a power of 2 for CKKS. RING_DIM = ORDER/2
 * NUMPRIME: Number of co-primes comprising the ciphertext modulus.
 *          It is equal to the desired depth of the computation. MultDepth = NUMPRIME - 1
 * SCALE: Scaling parameter 2^p. Also, Size of each co-prime in bits.
 *       Should fit into a machine word, i.e., less than 64.
 * RELIN: The bit decomposition count used in relinearization.
 *      Use 0 to go with max possible. Use small values (3-4?)
 *       if you need rotations before any multiplications.
 * BATCH: The length of the packed vectors to be used with CKKS.
 */
constexpr usint RING_DIM = 512;
constexpr usint SCALE    = 50;
constexpr usint MULT_DEPTH = 3;
constexpr usint RELIN    = 20;
constexpr usint BATCH    = 8;
// clang-format off
static std::vector<TEST_CASE> testCases = {
    // TestType,            Descr, Scheme,        RDim,     MultDepth,  SFBits, RWin,  BatchSz, Mode,       Depth, MDepth, ModSize, SecLvl,       KSTech, RSTech,       LDigits, PtMod, StdDev, EvalAddCt, EvalMultCt, KSCt, MultTech
    { CONTEXT_WITH_SERTYPE, "1", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SCALE,  RELIN, BATCH,   OPTIMIZED,  DFLT,  DFLT,   DFLT,    HEStd_NotSet, BV,     FIXEDMANUAL,  DFLT,    DFLT,  DFLT,   DFLT,      DFLT,       DFLT, DFLT}, },
    { CONTEXT_WITH_SERTYPE, "2", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SCALE,  RELIN, BATCH,   OPTIMIZED,  DFLT,  DFLT,   DFLT,    HEStd_NotSet, BV,     FIXEDAUTO,    DFLT,    DFLT,  DFLT,   DFLT,      DFLT,       DFLT, DFLT}, },
    { CONTEXT_WITH_SERTYPE, "3", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SCALE,  RELIN, BATCH,   OPTIMIZED,  DFLT,  DFLT,   DFLT,    HEStd_NotSet, HYBRID, FIXEDMANUAL,  DFLT,    DFLT,  DFLT,   DFLT,      DFLT,       DFLT, DFLT}, },
    { CONTEXT_WITH_SERTYPE, "4", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SCALE,  RELIN, BATCH,   OPTIMIZED,  DFLT,  DFLT,   DFLT,    HEStd_NotSet, HYBRID, FIXEDAUTO,    DFLT,    DFLT,  DFLT,   DFLT,      DFLT,       DFLT, DFLT}, },
#if NATIVEINT != 128
    { CONTEXT_WITH_SERTYPE, "5", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SCALE,  RELIN, BATCH,   OPTIMIZED,  DFLT,  DFLT,   DFLT,    HEStd_NotSet, BV,     FLEXIBLEAUTO, DFLT,    DFLT,  DFLT,   DFLT,      DFLT,       DFLT, DFLT}, },
    { CONTEXT_WITH_SERTYPE, "6", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SCALE,  RELIN, BATCH,   OPTIMIZED,  DFLT,  DFLT,   DFLT,    HEStd_NotSet, HYBRID, FLEXIBLEAUTO, DFLT,    DFLT,  DFLT,   DFLT,      DFLT,       DFLT, DFLT}, },
#endif
    // ==========================================
    // TestType,            Descr, Scheme,        RDim,     MultDepth,  SFBits, RWin,  BatchSz, Mode,       Depth, MDepth, ModSize, SecLvl,       KSTech, RSTech,       LDigits, PtMod, StdDev, EvalAddCt, EvalMultCt, KSCt, MultTech
    { KEYS_AND_CIPHERTEXTS, "1", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SCALE,  RELIN, BATCH,   OPTIMIZED,  DFLT,  DFLT,   DFLT,    HEStd_NotSet, BV,     FIXEDMANUAL,  DFLT,    DFLT,  DFLT,   DFLT,      DFLT,       DFLT, DFLT}, },
    { KEYS_AND_CIPHERTEXTS, "2", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SCALE,  RELIN, BATCH,   OPTIMIZED,  DFLT,  DFLT,   DFLT,    HEStd_NotSet, BV,     FIXEDAUTO,    DFLT,    DFLT,  DFLT,   DFLT,      DFLT,       DFLT, DFLT}, },
    { KEYS_AND_CIPHERTEXTS, "3", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SCALE,  RELIN, BATCH,   OPTIMIZED,  DFLT,  DFLT,   DFLT,    HEStd_NotSet, HYBRID, FIXEDMANUAL,  DFLT,    DFLT,  DFLT,   DFLT,      DFLT,       DFLT, DFLT}, },
    { KEYS_AND_CIPHERTEXTS, "4", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SCALE,  RELIN, BATCH,   OPTIMIZED,  DFLT,  DFLT,   DFLT,    HEStd_NotSet, HYBRID, FIXEDAUTO,    DFLT,    DFLT,  DFLT,   DFLT,      DFLT,       DFLT, DFLT}, },
#if NATIVEINT != 128
    { KEYS_AND_CIPHERTEXTS, "5", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SCALE,  RELIN, BATCH,   OPTIMIZED,  DFLT,  DFLT,   DFLT,    HEStd_NotSet, BV,     FLEXIBLEAUTO, DFLT,    DFLT,  DFLT,   DFLT,      DFLT,       DFLT, DFLT}, },
    { KEYS_AND_CIPHERTEXTS, "6", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SCALE,  RELIN, BATCH,   OPTIMIZED,  DFLT,  DFLT,   DFLT,    HEStd_NotSet, HYBRID, FLEXIBLEAUTO, DFLT,    DFLT,  DFLT,   DFLT,      DFLT,       DFLT, DFLT}, },
#endif
    // ==========================================
    // TestType,            Descr,  Scheme,        RDim,     MultDepth,  SFBits, RWin,  BatchSz, Mode,       Depth, MDepth, ModSize, SecLvl,       KSTech, RSTech,       LDigits, PtMod, StdDev, EvalAddCt, EvalMultCt, KSCt, MultTech
    { KEYS_AND_CIPHERTEXTS, "7",  {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SCALE,  0,     BATCH,   OPTIMIZED,  DFLT,  DFLT,   DFLT,    HEStd_NotSet, BV,     FIXEDMANUAL,  DFLT,    DFLT,  DFLT,   DFLT,      DFLT,       DFLT, DFLT}, },
    { KEYS_AND_CIPHERTEXTS, "8",  {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SCALE,  0,     BATCH,   OPTIMIZED,  DFLT,  DFLT,   DFLT,    HEStd_NotSet, BV,     FIXEDAUTO,    DFLT,    DFLT,  DFLT,   DFLT,      DFLT,       DFLT, DFLT}, },
    { KEYS_AND_CIPHERTEXTS, "9",  {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SCALE,  0,     BATCH,   OPTIMIZED,  DFLT,  DFLT,   DFLT,    HEStd_NotSet, HYBRID, FIXEDMANUAL,  DFLT,    DFLT,  DFLT,   DFLT,      DFLT,       DFLT, DFLT}, },
    { KEYS_AND_CIPHERTEXTS, "10", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SCALE,  0,     BATCH,   OPTIMIZED,  DFLT,  DFLT,   DFLT,    HEStd_NotSet, HYBRID, FIXEDAUTO,    DFLT,    DFLT,  DFLT,   DFLT,      DFLT,       DFLT, DFLT}, },
#if NATIVEINT != 128
    { KEYS_AND_CIPHERTEXTS, "11", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SCALE,  0,     BATCH,   OPTIMIZED,  DFLT,  DFLT,   DFLT,    HEStd_NotSet, BV,     FLEXIBLEAUTO, DFLT,    DFLT,  DFLT,   DFLT,      DFLT,       DFLT, DFLT}, },
    { KEYS_AND_CIPHERTEXTS, "12", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SCALE,  0,     BATCH,   OPTIMIZED,  DFLT,  DFLT,   DFLT,    HEStd_NotSet, HYBRID, FLEXIBLEAUTO, DFLT,    DFLT,  DFLT,   DFLT,      DFLT,       DFLT, DFLT}, },
#endif
    // ==========================================
    // TestType,    Descr,  Scheme,        RDim,     MultDepth,  SFBits, RWin,  BatchSz, Mode,       Depth, MDepth, ModSize, SecLvl,       KSTech, RSTech,       LDigits, PtMod, StdDev, EvalAddCt, EvalMultCt, KSCt, MultTech
    { NO_CRT_TABLES, "1", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SCALE,  0,     BATCH,   OPTIMIZED,  DFLT,  DFLT,   DFLT,    HEStd_NotSet, BV,     FIXEDMANUAL,  DFLT,    DFLT,  DFLT,   DFLT,      DFLT,       DFLT, DFLT}, },
    { NO_CRT_TABLES, "2", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SCALE,  0,     BATCH,   OPTIMIZED,  DFLT,  DFLT,   DFLT,    HEStd_NotSet, BV,     FIXEDAUTO,    DFLT,    DFLT,  DFLT,   DFLT,      DFLT,       DFLT, DFLT}, },
    { NO_CRT_TABLES, "3", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SCALE,  0,     BATCH,   OPTIMIZED,  DFLT,  DFLT,   DFLT,    HEStd_NotSet, HYBRID, FIXEDMANUAL,  DFLT,    DFLT,  DFLT,   DFLT,      DFLT,       DFLT, DFLT}, },
    { NO_CRT_TABLES, "4", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SCALE,  0,     BATCH,   OPTIMIZED,  DFLT,  DFLT,   DFLT,    HEStd_NotSet, HYBRID, FIXEDAUTO,    DFLT,    DFLT,  DFLT,   DFLT,      DFLT,       DFLT, DFLT}, },
#if NATIVEINT != 128
    { NO_CRT_TABLES, "5", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SCALE,  0,     BATCH,   OPTIMIZED,  DFLT,  DFLT,   DFLT,    HEStd_NotSet, BV,     FLEXIBLEAUTO, DFLT,    DFLT,  DFLT,   DFLT,      DFLT,       DFLT, DFLT}, },
    { NO_CRT_TABLES, "6", {CKKSRNS_SCHEME, RING_DIM, MULT_DEPTH, SCALE,  0,     BATCH,   OPTIMIZED,  DFLT,  DFLT,   DFLT,    HEStd_NotSet, HYBRID, FLEXIBLEAUTO, DFLT,    DFLT,  DFLT,   DFLT,      DFLT,       DFLT, DFLT}, },
#endif
    // ==========================================
};
// clang-format on
//===========================================================================================================
class UTCKKSSer : public ::testing::TestWithParam<TEST_CASE> {
    using Element = DCRTPoly;
    const double eps = EPSILON;

protected:
    void SetUp() {}

    void TearDown() {
        CryptoContextFactory<DCRTPoly>::ReleaseAllContexts();
    }

    void UnitTestContext(const TEST_CASE& testData, const string& failmsg = std::string()) {
        CryptoContext<Element> cc(UnitTestGenerateContext(testData.params));

        UnitTestContextWithSertype(cc, SerType::JSON, "json");
        UnitTestContextWithSertype(cc, SerType::BINARY, "binary");
    }

    template <typename ST>
    void TestKeysAndCiphertexts(const TEST_CASE& testData, const ST& sertype, const string& failmsg = std::string()) {
        try {
            CryptoContext<Element> cc(UnitTestGenerateContext(testData.params));

            DEBUG_FLAG(false);

            CryptoContextImpl<DCRTPoly>::ClearEvalMultKeys();
            CryptoContextImpl<DCRTPoly>::ClearEvalSumKeys();
            CryptoContextImpl<DCRTPoly>::ClearEvalAutomorphismKeys();

            DEBUG("step 0");
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

            KeyPair<DCRTPoly> kp = cc->KeyGen();
            KeyPair<DCRTPoly> kpnew;

            DEBUG("step 1");
            {
                std::stringstream s;
                Serial::Serialize(kp.publicKey, s, sertype);
                Serial::Deserialize(kpnew.publicKey, s, sertype);
                EXPECT_EQ(*kp.publicKey, *kpnew.publicKey) << "Public key mismatch after ser/deser";
            }
            DEBUG("step 2");
            {
                std::stringstream s;
                Serial::Serialize(kp.secretKey, s, sertype);
                Serial::Deserialize(kpnew.secretKey, s, sertype);
                EXPECT_EQ(*kp.secretKey, *kpnew.secretKey) << "Secret key mismatch after ser/deser";
            }
            DEBUG("step 3");
            vector<std::complex<double>> vals = { 1.0, 3.0, 5.0, 7.0, 9.0,
                                                 2.0, 4.0, 6.0, 8.0, 11.0 };
            Plaintext plaintextShort = cc->MakeCKKSPackedPlaintext(vals);
            Plaintext plaintextShortL2D2 = cc->MakeCKKSPackedPlaintext(vals, 2, 2);
            Ciphertext<DCRTPoly> ciphertext = cc->Encrypt(kp.publicKey, plaintextShort);
            Ciphertext<DCRTPoly> ciphertextL2D2 = cc->Encrypt(kp.publicKey, plaintextShortL2D2);

            DEBUG("step 4");
            Ciphertext<DCRTPoly> newC;
            Ciphertext<DCRTPoly> newCL2D2;
            {
                std::stringstream s;
                Serial::Serialize(ciphertext, s, sertype);
                Serial::Deserialize(newC, s, sertype);
                std::stringstream s2;
                Serial::Serialize(ciphertextL2D2, s2, sertype);
                Serial::Deserialize(newCL2D2, s2, sertype);
                EXPECT_EQ(*ciphertext, *newC) << "Ciphertext mismatch";
                EXPECT_EQ(*ciphertextL2D2, *newCL2D2) << "Ciphertext mismatch";
            }

            DEBUG("step 5");
            Plaintext plaintextShortNew;
            Plaintext plaintextShortNewL2D2;
            cc->Decrypt(kp.secretKey, newC, &plaintextShortNew);
            cc->Decrypt(kp.secretKey, newCL2D2, &plaintextShortNewL2D2);

            checkEquality(plaintextShortNew->GetCKKSPackedValue(), plaintextShort->GetCKKSPackedValue(), eps,
                failmsg + " Decrypted serialization test fails");
            checkEquality(plaintextShortNewL2D2->GetCKKSPackedValue(), plaintextShort->GetCKKSPackedValue(), eps,
                failmsg + " Decrypted serialization test fails (level 2, depth 2)");

            DEBUG("step 6");
            KeyPair<DCRTPoly> kp2 = cc->KeyGen();

            cc->EvalMultKeyGen(kp.secretKey);
            cc->EvalMultKeyGen(kp2.secretKey);
            cc->EvalSumKeyGen(kp.secretKey);
            cc->EvalSumKeyGen(kp2.secretKey);

            DEBUG("step 7");
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

            DEBUG("step 8");
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

            DEBUG("step 9");
            cc.reset();

            // test mult deserialize
            CryptoContextImpl<DCRTPoly>::ClearEvalMultKeys();
            CryptoContextImpl<DCRTPoly>::ClearEvalSumKeys();
            CryptoContextFactory<DCRTPoly>::ReleaseAllContexts();
            EXPECT_EQ(CryptoContextFactory<DCRTPoly>::GetContextCount(), 0) << "after release";

            vector<EvalKey<DCRTPoly>> evalMultKeys;
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

            DEBUG("step 10");
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
            CryptoContextImpl<DCRTPoly>::ClearEvalMultKeys();
            CryptoContextImpl<DCRTPoly>::ClearEvalSumKeys();
            CryptoContextImpl<DCRTPoly>::ClearEvalAutomorphismKeys();
            CryptoContextFactory<DCRTPoly>::ReleaseAllContexts();
        }
        catch (std::exception& e) {
            std::cerr << "Exception thrown from " << __func__ << "(): " << e.what() << std::endl;
            // make it fail
            EXPECT_TRUE(0 == 1) << failmsg;
        }
        catch (...) {
            int status = 0;
            char* name = __cxxabiv1::__cxa_demangle(__cxxabiv1::__cxa_current_exception_type()->name(), NULL, NULL, &status);
            std::cerr << "Unknown exception of type \"" << name << "\" thrown from " << __func__ << "()" << std::endl;
            std::free(name);
            // make it fail
            EXPECT_TRUE(0 == 1) << failmsg;
        }
    }
    void UnitTestKeysAndCiphertexts(const TEST_CASE& testData, const string& failmsg = std::string()) {
        TestKeysAndCiphertexts(testData, SerType::JSON, "json");
        TestKeysAndCiphertexts(testData, SerType::BINARY, "binary");
    }

    template <typename ST>
    void TestDecryptionSerNoCRTTables(const TEST_CASE& testData, const ST& sertype, const string& failmsg = std::string()) {
        try {
            CryptoContext<Element> cc(UnitTestGenerateContext(testData.params));

            KeyPair<Element> kp = cc->KeyGen();

            vector<std::complex<double>> vals = { 1.0, 3.0, 5.0, 7.0, 9.0,
                                                 2.0, 4.0, 6.0, 8.0, 11.0 };
            Plaintext plaintextShort = cc->MakeCKKSPackedPlaintext(vals);
            Ciphertext<DCRTPoly> ciphertext = cc->Encrypt(kp.publicKey, plaintextShort);

            std::stringstream s;
            Serial::Serialize(cc, s, sertype);

            CryptoContextFactory<Element>::ReleaseAllContexts();
            SERIALIZE_PRECOMPUTE = false;

            CryptoContext<Element> newcc;

            Serial::Deserialize(newcc, s, sertype);

            ASSERT_TRUE(newcc) << failmsg << " Deserialize failed";

            s.str("");
            s.clear();
            Serial::Serialize(kp.publicKey, s, sertype);

            PublicKey<Element> newPub;
            Serial::Deserialize(newPub, s, sertype);
            ASSERT_TRUE(newPub) << failmsg << " Key deserialize failed";

            s.str("");
            s.clear();
            Serial::Serialize(ciphertext, s, sertype);

            Ciphertext<DCRTPoly> newC;
            Serial::Deserialize(newC, s, sertype);
            ASSERT_TRUE(newC) << failmsg << " ciphertext deserialize failed";

            Plaintext result;
            cc->Decrypt(kp.secretKey, newC, &result);
            result->SetLength(plaintextShort->GetLength());
            checkEquality(plaintextShort->GetCKKSPackedValue(), result->GetCKKSPackedValue(), eps,
                failmsg + " Decryption Failed");
        }
        catch (std::exception& e) {
            std::cerr << "Exception thrown from " << __func__ << "(): " << e.what() << std::endl;
            // make it fail
            EXPECT_TRUE(0 == 1) << failmsg;
        }
        catch (...) {
            int status = 0;
            char* name = __cxxabiv1::__cxa_demangle(__cxxabiv1::__cxa_current_exception_type()->name(), NULL, NULL, &status);
            std::cerr << "Unknown exception of type \"" << name << "\" thrown from " << __func__ << "()" << std::endl;
            std::free(name);
            // make it fail
            EXPECT_TRUE(0 == 1) << failmsg;
        }
    }
    void UnitTestDecryptionSerNoCRTTables(const TEST_CASE& testData, const string& failmsg = std::string()) {
        TestDecryptionSerNoCRTTables(testData, SerType::JSON, "json");
        TestDecryptionSerNoCRTTables(testData, SerType::BINARY, "binary");
    }

};
//===========================================================================================================
TEST_P(UTCKKSSer, CKKSSer) {
    setupSignals();
    auto test = GetParam();

    if (test.testCaseType == CONTEXT_WITH_SERTYPE)
        UnitTestContext(test, test.buildTestName());
    else if (test.testCaseType == KEYS_AND_CIPHERTEXTS)
        UnitTestKeysAndCiphertexts(test, test.buildTestName());
    else if (test.testCaseType == NO_CRT_TABLES)
        UnitTestDecryptionSerNoCRTTables(test, test.buildTestName());
}

INSTANTIATE_TEST_SUITE_P(UnitTests, UTCKKSSer, ::testing::ValuesIn(testCases), testName);

#endif
