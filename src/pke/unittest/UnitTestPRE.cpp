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

/*
  unit tests for the PRE capabilities
 */
#include "UnitTestUtils.h"
#include "UnitTestCCParams.h"
#include "UnitTestCryptoContext.h"
#include "utils/exception.h"

#include "gtest/gtest.h"
#include <iostream>
#include <vector>


using namespace lbcrypto;

//===========================================================================================================
enum TEST_CASE_TYPE {
    RE_ENCRYPT = 0,
};

static std::ostream& operator<<(std::ostream& os, const TEST_CASE_TYPE& type) {
    std::string typeName;
    switch (type) {
    case RE_ENCRYPT:
        typeName = "RE_ENCRYPT";
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
const usint PTMOD    = 256;
const usint BATCH    = 16;
const usint SBITS    = 60;
const usint RWIN     = 20;
const double STD_DEV = 3.2;
// clang-format off
static std::vector<TEST_CASE> testCases = {
    // TestType,  Descr, Scheme,       RDim, MultDepth, SFBits, RWin, BatchSz, Mode,      Depth, MDepth, ModSize, SecLvl, KSTech, RSTech, LDigits, PtMod, StdDev,  EvalAddCt, EvalMultCt, KSCt, MultTech
    { RE_ENCRYPT, "1", {BFVRNS_SCHEME, DFLT, DFLT,      SBITS,  RWIN, BATCH,   OPTIMIZED, DFLT,  DFLT,   DFLT,    DFLT,   DFLT,   DFLT,   DFLT,    PTMOD, STD_DEV, DFLT,      2,          DFLT, HPS},  },
    { RE_ENCRYPT, "2", {BFVRNS_SCHEME, DFLT, DFLT,      SBITS,  RWIN, BATCH,   RLWE,      DFLT,  DFLT,   DFLT,    DFLT,   DFLT,   DFLT,   DFLT,    PTMOD, STD_DEV, DFLT,      2,          DFLT, HPS},  },
    { RE_ENCRYPT, "3", {BFVRNS_SCHEME, DFLT, DFLT,      SBITS,  RWIN, BATCH,   OPTIMIZED, DFLT,  DFLT,   DFLT,    DFLT,   DFLT,   DFLT,   DFLT,    PTMOD, STD_DEV, DFLT,      2,          DFLT, BEHZ}, },
    { RE_ENCRYPT, "4", {BFVRNS_SCHEME, DFLT, DFLT,      SBITS,  RWIN, BATCH,   RLWE,      DFLT,  DFLT,   DFLT,    DFLT,   DFLT,   DFLT,   DFLT,    PTMOD, STD_DEV, DFLT,      2,          DFLT, BEHZ}, },
    // ==========================================
};
// clang-format on

class ReEncrypt : public ::testing::TestWithParam<TEST_CASE> {
    using Element = DCRTPoly;

protected:
    void SetUp() {}

    void TearDown() {
        CryptoContextFactory<DCRTPoly>::ReleaseAllContexts();
    }

    void ReEncryption(const TEST_CASE& testData, const std::string& failmsg = std::string()) {
        try {
            CryptoContext<Element> cc(UnitTestGenerateContext(testData.params));

            size_t vecSize = cc->GetRingDimension();

            auto randchar = []() -> char {
                const char charset[] =
                    "0123456789"
                    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                    "abcdefghijklmnopqrstuvwxyz";
                const size_t max_index = (sizeof(charset) - 1);
                return charset[rand() % max_index];
            };

            std::string shortStr(vecSize / 2, 0);
            std::generate_n(shortStr.begin(), vecSize / 2, randchar);
            Plaintext plaintextShort = cc->MakeStringPlaintext(shortStr);

            std::string fullStr(vecSize, 0);
            std::generate_n(fullStr.begin(), vecSize, randchar);
            Plaintext plaintextFull = cc->MakeStringPlaintext(fullStr);

            auto ptm = cc->GetCryptoParameters()->GetPlaintextModulus();

            std::vector<int64_t> intvec;
            for (size_t ii = 0; ii < vecSize; ii++)
                intvec.push_back((rand() % (ptm / 2)) * (rand() % 2 ? 1 : -1));
            Plaintext plaintextInt = cc->MakeCoefPackedPlaintext(intvec);

            KeyPair<Element> kp = cc->KeyGen();
            EXPECT_EQ(kp.good(), true)
                << failmsg << " key generation for scalar encrypt/decrypt failed";

            KeyPair<Element> newKp = cc->KeyGen();
            EXPECT_EQ(newKp.good(), true)
                << failmsg << " second key generation for scalar encrypt/decrypt failed";

            // This generates the keys which are used to perform the key switching.
            EvalKey<Element> evalKey;
            evalKey = cc->ReKeyGen(kp.secretKey, newKp.publicKey);

            Ciphertext<Element> ciphertext = cc->Encrypt(kp.publicKey, plaintextShort);
            Plaintext plaintextShortNew;
            Ciphertext<Element> reCiphertext = cc->ReEncrypt(ciphertext, evalKey);
            DecryptResult result = cc->Decrypt(newKp.secretKey, reCiphertext, &plaintextShortNew);
            EXPECT_EQ(plaintextShortNew->GetStringValue(), plaintextShort->GetStringValue())
                << failmsg << " ReEncrypt short string plaintext with padding";

            Ciphertext<Element> ciphertext2 = cc->Encrypt(kp.publicKey, plaintextFull);
            Plaintext plaintextFullNew;
            Ciphertext<Element> reCiphertext2 = cc->ReEncrypt(ciphertext2, evalKey);
            result = cc->Decrypt(newKp.secretKey, reCiphertext2, &plaintextFullNew);
            EXPECT_EQ(plaintextFullNew->GetStringValue(), plaintextFull->GetStringValue())
                << failmsg << " ReEncrypt full string plaintext";

            Ciphertext<Element> ciphertext4 = cc->Encrypt(kp.publicKey, plaintextInt);
            Plaintext plaintextIntNew;
            Ciphertext<Element> reCiphertext4 = cc->ReEncrypt(ciphertext4, evalKey);
            result = cc->Decrypt(newKp.secretKey, reCiphertext4, &plaintextIntNew);
            EXPECT_EQ(plaintextIntNew->GetCoefPackedValue(), plaintextInt->GetCoefPackedValue())
                << failmsg << " ReEncrypt integer plaintext";

            Ciphertext<Element> ciphertext5 = cc->Encrypt(kp.publicKey, plaintextShort);
            Plaintext plaintextShortNew2;
            Ciphertext<Element> reCiphertext5 = cc->ReEncrypt(ciphertext5, evalKey, kp.publicKey);
            result = cc->Decrypt(newKp.secretKey, reCiphertext5, &plaintextShortNew2);
            EXPECT_EQ(plaintextShortNew2->GetStringValue(), plaintextShort->GetStringValue())
                << failmsg << " HRA-secure ReEncrypt short string plaintext with padding";

            Ciphertext<Element> ciphertext6 = cc->Encrypt(kp.publicKey, plaintextFull);
            Plaintext plaintextFullNew2;
            Ciphertext<Element> reCiphertext6 = cc->ReEncrypt(ciphertext6, evalKey, kp.publicKey);
            result = cc->Decrypt(newKp.secretKey, reCiphertext6, &plaintextFullNew2);
            EXPECT_EQ(plaintextFullNew2->GetStringValue(), plaintextFull->GetStringValue())
                << failmsg << " HRA-secure ReEncrypt full string plaintext";

            Ciphertext<Element> ciphertext7 = cc->Encrypt(kp.publicKey, plaintextInt);
            Plaintext plaintextIntNew2;
            Ciphertext<Element> reCiphertext7 = cc->ReEncrypt(ciphertext7, evalKey, kp.publicKey);
            result = cc->Decrypt(newKp.secretKey, reCiphertext7, &plaintextIntNew2);
            EXPECT_EQ(plaintextIntNew2->GetCoefPackedValue(), plaintextInt->GetCoefPackedValue())
                << failmsg << " HRA-secure ReEncrypt integer plaintext";
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

};

//===========================================================================================================
TEST_P(ReEncrypt, PRE) {
    setupSignals();
    auto test = GetParam();
    if (test.testCaseType == RE_ENCRYPT)
        ReEncryption(test, test.buildTestName());
}

INSTANTIATE_TEST_SUITE_P(UnitTests, ReEncrypt, ::testing::ValuesIn(testCases), testName);

#endif
