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

#include "ciphertext-ser.h"
#include "cryptocontext-ser.h"
#include "key/key-ser.h"
#include "scheme/bgvrns/bgvrns-ser.h"

#include "UnitTestUtils.h"
#include "UnitTestSer.h"
#include "UnitTestCCParams.h"
#include "UnitTestCryptoContext.h"
#include "utils/exception.h"

#include "include/gtest/gtest.h"
#include <iostream>
#include <sstream>
#include <vector>
#include <cxxabi.h>


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
/***
 * ORDER:      Cyclotomic order. Must be a power of 2 for BGVrns. RING_DIM = cyclOrder / 2
 * SIZEMODULI: bit-length of the moduli composing the ciphertext modulus (size of each co-prime in bits or
 *             scaling factor bits).
 * 		       Should fit into a machine word, i.e., less than 64.
 * NUMPRIME:   Number of towers comprising the ciphertext modulus. It is equal to the desired depth of the computation.
 *             MultDepth = NUMPRIME - 1
 * RELIN:      The bit decomposition count used in relinearization.
 *  	       Use 0 to go with max possible. Use small values (3-4?) if you need rotations before any multiplications.
 * PTM:        The plaintext modulus.
 * BATCH:      The length of the packed vectors to be used with CKKS.
 */
constexpr usint ORDER = 1024;  // 16384;
constexpr usint RING_DIM = ORDER / 2;
constexpr usint NUMPRIME = 4;
constexpr usint MULT_DEPTH = NUMPRIME - 1;
constexpr usint MAX_DEPTH = 1;
constexpr usint SIZEMODULI = 50; // scaling factor bits
constexpr usint RELIN = 20;
constexpr usint PTM = 65537;
constexpr usint BATCH = 16;
constexpr usint FIRST_MOD_SIZE = 60;
constexpr double STD_DEV = 3.2;
constexpr SecurityLevel SEC_LVL = HEStd_NotSet;
// TODO (dsuponit): are there any changes under this condition - #if NATIVEINT != 128?

static std::vector<TEST_CASE> testCases = {
    // TestType, Descr, Scheme,     RDim,     MultDepth,  SFBits,     RWin,  BatchSz, Mode, Depth, MDepth,    ModSize,        SecLvl,  KSTech, RSTech,       LDigits, PtMod, StdDev,   EvalAddCt, EvalMultCt, KSCt, MultTech
    { CONTEXT, "1", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, SIZEMODULI, RELIN, BATCH,   DFLT, DFLT,  MAX_DEPTH, FIRST_MOD_SIZE, SEC_LVL, BV,     FLEXIBLEAUTO, DFLT,    PTM,   STD_DEV,  DFLT,      DFLT,       DFLT, DFLT}, },
    { CONTEXT, "2", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, SIZEMODULI, RELIN, BATCH,   DFLT, DFLT,  MAX_DEPTH, FIRST_MOD_SIZE, SEC_LVL, BV,     FIXEDMANUAL,  DFLT,    PTM,   STD_DEV,  DFLT,      DFLT,       DFLT, DFLT}, },
    { CONTEXT, "3", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, SIZEMODULI, RELIN, BATCH,   DFLT, DFLT,  MAX_DEPTH, FIRST_MOD_SIZE, SEC_LVL, HYBRID, FLEXIBLEAUTO, DFLT,    PTM,   STD_DEV,  DFLT,      DFLT,       DFLT, DFLT}, },
    { CONTEXT, "4", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, SIZEMODULI, RELIN, BATCH,   DFLT, DFLT,  MAX_DEPTH, FIRST_MOD_SIZE, SEC_LVL, HYBRID, FIXEDMANUAL,  DFLT,    PTM,   STD_DEV,  DFLT,      DFLT,       DFLT, DFLT}, },
    // ==========================================
    // TestType,          Descr, Scheme,         RDim,     MultDepth,  SFBits,     RWin,  BatchSz, Mode, Depth, MDepth,    ModSize,        SecLvl,  KSTech, RSTech,       LDigits, PtMod, StdDev,   EvalAddCt, EvalMultCt, KSCt, MultTech
    { KEYS_AND_CIPHERTEXTS, "1", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, SIZEMODULI, RELIN, BATCH,   DFLT, DFLT,  MAX_DEPTH, FIRST_MOD_SIZE, SEC_LVL, BV,     FLEXIBLEAUTO, DFLT,    PTM,   STD_DEV,  DFLT,      DFLT,       DFLT, DFLT}, },
    { KEYS_AND_CIPHERTEXTS, "2", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, SIZEMODULI, RELIN, BATCH,   DFLT, DFLT,  MAX_DEPTH, FIRST_MOD_SIZE, SEC_LVL, BV,     FIXEDMANUAL,  DFLT,    PTM,   STD_DEV,  DFLT,      DFLT,       DFLT, DFLT}, },
    { KEYS_AND_CIPHERTEXTS, "3", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, SIZEMODULI, RELIN, BATCH,   DFLT, DFLT,  MAX_DEPTH, FIRST_MOD_SIZE, SEC_LVL, HYBRID, FLEXIBLEAUTO, DFLT,    PTM,   STD_DEV,  DFLT,      DFLT,       DFLT, DFLT}, },
    { KEYS_AND_CIPHERTEXTS, "4", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, SIZEMODULI, RELIN, BATCH,   DFLT, DFLT,  MAX_DEPTH, FIRST_MOD_SIZE, SEC_LVL, HYBRID, FIXEDMANUAL,  DFLT,    PTM,   STD_DEV,  DFLT,      DFLT,       DFLT, DFLT}, },
    { KEYS_AND_CIPHERTEXTS, "5", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, SIZEMODULI, 0,     BATCH,   DFLT, DFLT,  MAX_DEPTH, FIRST_MOD_SIZE, SEC_LVL, BV,     FLEXIBLEAUTO, DFLT,    PTM,   STD_DEV,  DFLT,      DFLT,       DFLT, DFLT}, },
    { KEYS_AND_CIPHERTEXTS, "6", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, SIZEMODULI, 0,     BATCH,   DFLT, DFLT,  MAX_DEPTH, FIRST_MOD_SIZE, SEC_LVL, BV,     FIXEDMANUAL,  DFLT,    PTM,   STD_DEV,  DFLT,      DFLT,       DFLT, DFLT}, },
    { KEYS_AND_CIPHERTEXTS, "7", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, SIZEMODULI, 0,     BATCH,   DFLT, DFLT,  MAX_DEPTH, FIRST_MOD_SIZE, SEC_LVL, HYBRID, FLEXIBLEAUTO, DFLT,    PTM,   STD_DEV,  DFLT,      DFLT,       DFLT, DFLT}, },
    { KEYS_AND_CIPHERTEXTS, "8", {BGVRNS_SCHEME, RING_DIM, MULT_DEPTH, SIZEMODULI, 0,     BATCH,   DFLT, DFLT,  MAX_DEPTH, FIRST_MOD_SIZE, SEC_LVL, HYBRID, FIXEDMANUAL,  DFLT,    PTM,   STD_DEV,  DFLT,      DFLT,       DFLT, DFLT}, },
    // ==========================================
};
//===========================================================================================================
class UTBGVRNS_SER : public ::testing::TestWithParam<TEST_CASE> {
    using Element = DCRTPoly;
    const double eps = EPSILON;

protected:
    void SetUp() {}

    void TearDown() {
        CryptoContextFactory<DCRTPoly>::ReleaseAllContexts();
    }

    void UnitTestContext(const TEST_CASE& testData, const std::string& failmsg = std::string()) {
        CryptoContext<Element> cc(UnitTestGenerateContext(testData.params));

        UnitTestContextWithSertype(cc, SerType::JSON, "json");
        UnitTestContextWithSertype(cc, SerType::BINARY, "binary");
    }

    template <typename ST>
    void TestKeysAndCiphertexts(const TEST_CASE& testData, const ST& sertype, const std::string& failmsg = std::string()) {
        try {
            CryptoContext<Element> cc(UnitTestGenerateContext(testData.params));

            DEBUG_FLAG(false);

            CryptoContextImpl<DCRTPoly>::ClearEvalMultKeys();
            CryptoContextImpl<DCRTPoly>::ClearEvalSumKeys();
            CryptoContextImpl<DCRTPoly>::ClearEvalAutomorphismKeys();

            // // The batch size for our tests.
            int vecSize = 10;

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

            // Update the batchSize from the default value
            const auto cryptoParamsBGVrns =
                std::static_pointer_cast<CryptoParametersBGVRNS>(kp.publicKey->GetCryptoParameters());

            EncodingParams encodingParamsNew(
                std::make_shared<EncodingParamsImpl>(cc->GetEncodingParams()->GetPlaintextModulus(), vecSize));
            cryptoParamsBGVrns->SetEncodingParams(encodingParamsNew);

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
            std::vector<int64_t> vals = { 1, 3, 5, 7, 9, 2, 4, 6, 8, 11 };
            Plaintext plaintextShort = cc->MakePackedPlaintext(vals);
            Ciphertext<DCRTPoly> ciphertext = cc->Encrypt(kp.publicKey, plaintextShort);

            DEBUG("step 4");
            Ciphertext<DCRTPoly> newC;
            {
                std::stringstream s;
                Serial::Serialize(ciphertext, s, sertype);
                Serial::Deserialize(newC, s, sertype);
                EXPECT_EQ(*ciphertext, *newC) << "Ciphertext mismatch";
            }

            DEBUG("step 5");
            Plaintext plaintextShortNew;
            cc->Decrypt(kp.secretKey, newC, &plaintextShortNew);

            checkEquality(plaintextShortNew->GetPackedValue(), plaintextShort->GetPackedValue(), eps,
                failmsg + " Decrypted serialization test fails");

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

#endif
