//==================================================================================
// BSD 2-Clause License
//
// Copyright (c) 2014-2023, NJIT, Duality Technologies Inc. and other contributors
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
#include "BaseTestCase.h"
#include "UnitTestReadCSVData.h"
#include "UnitTestUtils.h"
#include "UnitTestCCParams.h"
#include "UnitTestCryptoContext.h"

#include <iostream>
#include <vector>
#include <unordered_map>
#include "gtest/gtest.h"
#include <cxxabi.h>
#include "utils/demangle.h"

using namespace lbcrypto;
class Params;

//===========================================================================================================
enum TEST_CASE_TYPE {
    INTERACTIVE_MP_BOOT = 0,
    INTERACTIVE_MP_BOOT_CHEBYSHEV,
};
static TEST_CASE_TYPE convertStringToCaseType(const std::string& str) {
    const std::unordered_map<std::string, TEST_CASE_TYPE> stringToCaseType = {
        {"INTERACTIVE_MP_BOOT", INTERACTIVE_MP_BOOT}, {"INTERACTIVE_MP_BOOT_CHEBYSHEV", INTERACTIVE_MP_BOOT_CHEBYSHEV}};
    auto search = stringToCaseType.find(str);
    if (stringToCaseType.end() != search) {
        return search->second;
    }
    OPENFHE_THROW(config_error, std::string("Can not convert ") + str + "to test case");
}
static std::ostream& operator<<(std::ostream& os, const TEST_CASE_TYPE& type) {
    const std::unordered_map<TEST_CASE_TYPE, std::string> caseTypeToString = {
        {INTERACTIVE_MP_BOOT, "INTERACTIVE_MP_BOOT"}, {INTERACTIVE_MP_BOOT_CHEBYSHEV, "INTERACTIVE_MP_BOOT_CHEBYSHEV"}};
    auto search = caseTypeToString.find(type);
    if (caseTypeToString.end() != search) {
        return os << search->second;
    }
    OPENFHE_THROW(config_error, "Unknown test case");
}
//===========================================================================================================
struct TEST_CASE_UTCKKSRNS_INTERACTIVE_BOOT : public BaseTestCase {
    TEST_CASE_TYPE testCaseType;
    // test case description - MUST BE UNIQUE
    std::string description;

    // additional test case data
    uint32_t numParties;

    std::string buildTestName() const {
        std::stringstream ss;
        ss << testCaseType << "_" << description;
        return ss.str();
    }
    std::string toString() const {
        std::stringstream ss;
        ss << "[testCase: " << testCaseType << "], [description: " << description
           << "], [params: " << getCryptoContextParamOverrides() << "], [numParties: " << numParties << "] ";
        return ss.str();
    }
};

// this lambda provides a name to be printed for every test run by INSTANTIATE_TEST_SUITE_P.
// the name MUST be constructed from digits, letters and '_' only
static auto testName = [](const testing::TestParamInfo<TEST_CASE_UTCKKSRNS_INTERACTIVE_BOOT>& testParamInfo) {
    return testParamInfo.param.buildTestName();
};

static std::ostream& operator<<(std::ostream& os, const TEST_CASE_UTCKKSRNS_INTERACTIVE_BOOT& test) {
    return os << test.toString();
}
//===========================================================================================================
static std::vector<TEST_CASE_UTCKKSRNS_INTERACTIVE_BOOT> getTestData(std::string fileName) {
    // TODO: add a new test data file for NATIVEINT == 128
    std::string testDataFileName(createDataFileName(fileName));
    std::vector<std::vector<std::string>> fileRows(readDataFile(testDataFileName));
    size_t numRows = fileRows.size();

    std::vector<TEST_CASE_UTCKKSRNS_INTERACTIVE_BOOT> allData;
    allData.reserve(numRows);

    for (const std::vector<std::string>& vec : fileRows) {
        TEST_CASE_UTCKKSRNS_INTERACTIVE_BOOT testCase;

        auto it               = vec.begin();
        testCase.testCaseType = convertStringToCaseType(*it);
        testCase.description  = *(++it);

        // size_t numOverrides = testCase.populateCryptoContextParams(++it);
        size_t numOverrides = testCase.setCryptoContextParamsOverrides(++it);

        it += numOverrides;
        if (it != vec.end()) {
            // process additional test date
            testCase.numParties = static_cast<uint32_t>(std::stoul(*it));
        }

        allData.push_back(std::move(testCase));
    }
    return allData;
}
//===========================================================================================================
static std::vector<TEST_CASE_UTCKKSRNS_INTERACTIVE_BOOT> testCasesUTCKKSRNS_INTERACTIVE_BOOT = getTestData(__FILE__);
//===========================================================================================================

class UTCKKSRNS_INTERACTIVE_BOOT : public ::testing::TestWithParam<TEST_CASE_UTCKKSRNS_INTERACTIVE_BOOT> {
    using Element = DCRTPoly;
    // The precision after which we consider two values equal as CKKS works for approximate numbers.
    const double eps = 0.0001;

    /**
     * Party is a utility class defining a party involved in the collective bootstrapping protocol
     */
    struct Party {
        uint32_t id;               // unique party identifier starting from 0
        KeyPair<Element> kpShard;  // key-pair shard (pk, sk_i)
    };

protected:
    void SetUp() {}

    void TearDown() {
        PackedEncoding::Destroy();
        CryptoContextFactory<Element>::ReleaseAllContexts();
    }

    void UnitTest_MultiPartyBoot(const TEST_CASE_UTCKKSRNS_INTERACTIVE_BOOT& testData,
                                 const std::string& failmsg = std::string()) {
        try {
            CryptoContext<Element> cc(UnitTestGenerateContext(testData));

            // Initialization - Assuming numParties (n) of parties P0 is the leading party
            // generate the joint public key for (s_0 + s_1 + ... + s_n)
            std::vector<Party> parties(testData.numParties);
            parties[0].id      = 0;
            parties[0].kpShard = cc->KeyGen();
            if (!parties[0].kpShard.good())
                OPENFHE_THROW(openfhe_error, std::string("Key generation failed for party ") + std::to_string(0));
            for (usint i = 1; i < parties.size(); i++) {
                parties[i].id      = i;
                parties[i].kpShard = cc->MultipartyKeyGen(parties[0].kpShard.publicKey);
                if (!parties[i].kpShard.good())
                    OPENFHE_THROW(openfhe_error, std::string("Key generation failed for party ") + std::to_string(i));
            }

            // Generate the collective public key
            std::vector<PrivateKey<Element>> secretKeys;
            for (const auto& party : parties) {
                secretKeys.push_back(party.kpShard.secretKey);
            }

            // Joint public key
            KeyPair<Element> kpMultiparty =
                cc->MultipartyKeyGen(secretKeys);  // This is the same core key generation operation.

            // Prepare input vector
            const std::vector<std::complex<double>> inVec{-0.9, -0.8, 0.2, 0.4};
            Plaintext ptxt = cc->MakeCKKSPackedPlaintext(inVec);

            // Encryption
            Ciphertext<Element> inCtxt = cc->Encrypt(kpMultiparty.publicKey, ptxt);

            // Compressing ctxt to the smallest possible number of towers
            inCtxt = cc->IntMPBootAdjustScale(inCtxt);

            ///////////////////////////////////////////////////////////////////////////////////////////////////////////
            // INTERACTIVE BOOTSTRAPPING
            ///////////////////////////////////////////////////////////////////////////////////////////////////////////
            // Leading party (P0) generates a Common Random Poly (aCtxt) at max coefficient modulus (QNumPrime).
            // a is sampled at random uniformly from R_{Q}
            Ciphertext<Element> aCtxt = cc->IntMPBootRandomElementGen(parties[0].kpShard.publicKey);

            // Each party generates its own shares: maskedDecryptionShare (h_{0,i}, h_{1,i}) and reEncryptionShare
            std::vector<std::vector<Ciphertext<Element>>> sharesPairVec;

            // Make a copy of input ciphertext and remove the first element (c0), we only c1 for IntMPBootDecrypt
            auto c1 = inCtxt->Clone();
            c1->GetElements().erase(c1->GetElements().begin());
            for (const auto& party : parties) {
                sharesPairVec.push_back(cc->IntMPBootDecrypt(party.kpShard.secretKey, c1, aCtxt));
            }

            // P0 finalizes the protocol by aggregating the shares and reEncrypting the results
            auto aggregatedSharesPair = cc->IntMPBootAdd(sharesPairVec);
            // Make sure you provide the non-striped ciphertext (inCtxt) in IntMPBootEncrypt
            auto outCtxt = cc->IntMPBootEncrypt(parties[0].kpShard.publicKey, aggregatedSharesPair, aCtxt, inCtxt);
            ///////////////////////////////////////////////////////////////////////////////////////////////////////////
            // END OF INTERACTIVE BOOTSTRAPPING
            ///////////////////////////////////////////////////////////////////////////////////////////////////////////

            // Distributed (interactive) decryption
            std::vector<Ciphertext<Element>> partialCiphertextVec;
            partialCiphertextVec.push_back(cc->MultipartyDecryptLead({outCtxt}, parties[0].kpShard.secretKey)[0]);
            for (usint i = 1; i < parties.size(); i++) {
                partialCiphertextVec.push_back(cc->MultipartyDecryptMain({outCtxt}, parties[i].kpShard.secretKey)[0]);
            }

            // Check the results
            Plaintext resultPtxt;
            cc->MultipartyDecryptFusion(partialCiphertextVec, &resultPtxt);
            resultPtxt->SetLength(inVec.size());
            checkEquality(ptxt->GetCKKSPackedValue(), resultPtxt->GetCKKSPackedValue(), eps,
                          failmsg + " Interactive multiparty bootstrapping fails");
        }
        catch (std::exception& e) {
            std::cerr << "Exception thrown from " << __func__ << "(): " << e.what() << std::endl;
            // make it fail
            EXPECT_TRUE(0 == 1) << failmsg;
        }
        catch (...) {
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
    void UnitTest_MultiPartyBootChebyshev(const TEST_CASE_UTCKKSRNS_INTERACTIVE_BOOT& testData,
                                          const std::string& failmsg = std::string()) {
        try {
            CryptoContext<DCRTPoly> cc(UnitTestGenerateContext(testData));

            // Initialize Public Key Containers
            KeyPair<DCRTPoly> kp1;  // Party 1
            KeyPair<DCRTPoly> kp2;  // Party 2
            KeyPair<DCRTPoly> kp3;  // Lead party 3: encrypts and finalizes the bootstrapping protocol

            ////////////////////////////////////////////////////////////
            // Key Generation Operation
            ////////////////////////////////////////////////////////////
            kp1 = cc->KeyGen();
            if (!kp1.good())
                OPENFHE_THROW(openfhe_error, std::string("Key generation failed"));
            // Generate evalmult key
            auto evalMultKey = cc->KeySwitchGen(kp1.secretKey, kp1.secretKey);

            // Generate evalsum key
            cc->EvalSumKeyGen(kp1.secretKey);
            auto evalSumKeys =
                std::make_shared<std::map<usint, EvalKey<DCRTPoly>>>(cc->GetEvalSumKeyMap(kp1.secretKey->GetKeyTag()));

            kp2 = cc->MultipartyKeyGen(kp1.publicKey);
            if (!kp2.good())
                OPENFHE_THROW(openfhe_error, std::string("Key generation failed"));
            auto evalMultKey2    = cc->MultiKeySwitchGen(kp2.secretKey, kp2.secretKey, evalMultKey);
            auto evalMultAB      = cc->MultiAddEvalKeys(evalMultKey, evalMultKey2, kp2.publicKey->GetKeyTag());
            auto evalMultBAB     = cc->MultiMultEvalKey(kp2.secretKey, evalMultAB, kp2.publicKey->GetKeyTag());
            auto evalSumKeysB    = cc->MultiEvalSumKeyGen(kp2.secretKey, evalSumKeys, kp2.publicKey->GetKeyTag());
            auto evalSumKeysJoin = cc->MultiAddEvalSumKeys(evalSumKeys, evalSumKeysB, kp2.publicKey->GetKeyTag());
            cc->InsertEvalSumKey(evalSumKeysJoin);
            auto evalMultAAB   = cc->MultiMultEvalKey(kp1.secretKey, evalMultAB, kp2.publicKey->GetKeyTag());
            auto evalMultFinal = cc->MultiAddEvalMultKeys(evalMultAAB, evalMultBAB, evalMultAB->GetKeyTag());
            cc->InsertEvalMultKey({evalMultFinal});

            kp3 = cc->MultipartyKeyGen(kp2.publicKey);
            if (!kp3.good())
                OPENFHE_THROW(openfhe_error, std::string("Key generation failed"));
            auto evalMultKey3   = cc->MultiKeySwitchGen(kp3.secretKey, kp3.secretKey, evalMultKey);
            auto evalMultABC    = cc->MultiAddEvalKeys(evalMultAB, evalMultKey3, kp3.publicKey->GetKeyTag());
            auto evalMultBABC   = cc->MultiMultEvalKey(kp2.secretKey, evalMultABC, kp3.publicKey->GetKeyTag());
            auto evalMultAABC   = cc->MultiMultEvalKey(kp1.secretKey, evalMultABC, kp3.publicKey->GetKeyTag());
            auto evalMultCABC   = cc->MultiMultEvalKey(kp3.secretKey, evalMultABC, kp3.publicKey->GetKeyTag());
            auto evalMultABABC  = cc->MultiAddEvalMultKeys(evalMultBABC, evalMultAABC, evalMultBABC->GetKeyTag());
            auto evalMultFinal2 = cc->MultiAddEvalMultKeys(evalMultABABC, evalMultCABC, evalMultCABC->GetKeyTag());
            cc->InsertEvalMultKey({evalMultFinal2});

            auto evalSumKeysC     = cc->MultiEvalSumKeyGen(kp3.secretKey, evalSumKeys, kp3.publicKey->GetKeyTag());
            auto evalSumKeysJoin2 = cc->MultiAddEvalSumKeys(evalSumKeys, evalSumKeysC, kp3.publicKey->GetKeyTag());
            cc->InsertEvalSumKey(evalSumKeysJoin2);

            const std::vector<std::complex<double>> input{-4.0, -3.0, -2.0, -1.0, 0.0, 1.0, 2.0, 3.0, 4.0};
            const std::vector<double> coefficients{1.0, 0.558971,     0.0, -0.0943712,   0.0, 0.0215023,
                                                   0.0, -0.00505348,  0.0, 0.00119324,   0.0, -0.000281928,
                                                   0.0, 0.0000664347, 0.0, -0.0000148709};

            Plaintext pt1 = cc->MakeCKKSPackedPlaintext(input);
            auto ct1      = cc->Encrypt(kp3.publicKey, pt1);
            double a      = -4;
            double b      = 4;
            ct1           = cc->EvalChebyshevSeries(ct1, coefficients, a, b);

            // INTERACTIVE BOOTSTRAPPING
            ct1 = cc->IntMPBootAdjustScale(ct1);

            // Leading party (party 3) generates a Common Random Poly (crp) at max coefficient modulus (QNumPrime).
            // a is sampled at random uniformly from R_{Q}
            auto crp = cc->IntMPBootRandomElementGen(kp3.publicKey);
            // extract c1 - element-wise
            auto c1 = ct1->Clone();
            c1->GetElements().erase(c1->GetElements().begin());

            // masked decryption on the client: c1 = a*s1
            // Each party generates its own shares: maskedDecryptionShare and reEncryptionShare
            // (h_{0,i}, h_{1,i}) = (masked decryption share, re-encryption share)
            // we use a vector inseat of std::pair for Python API compatibility
            std::vector<Ciphertext<DCRTPoly>> sharesPair1 = cc->IntMPBootDecrypt(kp1.secretKey, c1, crp);
            std::vector<Ciphertext<DCRTPoly>> sharesPair2 = cc->IntMPBootDecrypt(kp2.secretKey, c1, crp);
            std::vector<Ciphertext<DCRTPoly>> sharesPair3 = cc->IntMPBootDecrypt(kp3.secretKey, c1, crp);

            std::vector<std::vector<Ciphertext<DCRTPoly>>> sharesPairVec{sharesPair1, sharesPair2, sharesPair3};

            // Party 3 finalizes the protocol by aggregating the shares and reEncrypting the results
            auto aggregatedSharesPair = cc->IntMPBootAdd(sharesPairVec);
            auto ciphertextOutput     = cc->IntMPBootEncrypt(kp3.publicKey, aggregatedSharesPair, crp, ct1);

            // END OF INTERACTIVE BOOTSTRAPPING

            // distributed decryption
            auto ciphertextPartial1 = cc->MultipartyDecryptMain({ciphertextOutput}, kp1.secretKey);
            auto ciphertextPartial2 = cc->MultipartyDecryptMain({ciphertextOutput}, kp2.secretKey);
            auto ciphertextPartial3 = cc->MultipartyDecryptLead({ciphertextOutput}, kp3.secretKey);
            std::vector<Ciphertext<DCRTPoly>> partialCiphertextVec{ciphertextPartial1[0], ciphertextPartial2[0],
                                                                   ciphertextPartial3[0]};

            Plaintext plaintextMultiparty;
            cc->MultipartyDecryptFusion(partialCiphertextVec, &plaintextMultiparty);
            plaintextMultiparty->SetLength(input.size());

            const std::vector<std::complex<double>> result1{0.0179885, 0.0474289, 0.119205, 0.268936, 0.5,
                                                            0.731064,  0.880795,  0.952571, 0.982011};
            Plaintext plaintextResult1 = cc->MakeCKKSPackedPlaintext(result1);
            checkEquality(plaintextResult1->GetCKKSPackedValue(), plaintextMultiparty->GetCKKSPackedValue(), eps,
                          failmsg + " Interactive multiparty bootstrapping Chebyshev fails");
        }
        catch (std::exception& e) {
            std::cerr << "Exception thrown from " << __func__ << "(): " << e.what() << std::endl;
            // make it fail
            EXPECT_TRUE(0 == 1) << failmsg;
        }
        catch (...) {
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
};

//===========================================================================================================
TEST_P(UTCKKSRNS_INTERACTIVE_BOOT, InteractiveBoot) {
    setupSignals();
    auto test = GetParam();

    if (!test.skipTest()) {
        switch (test.testCaseType) {
            case INTERACTIVE_MP_BOOT:
                UnitTest_MultiPartyBoot(test, test.buildTestName());
                break;
            case INTERACTIVE_MP_BOOT_CHEBYSHEV:
                UnitTest_MultiPartyBootChebyshev(test, test.buildTestName());
                break;
            default:
                break;
        }
    }
}

INSTANTIATE_TEST_SUITE_P(UnitTests, UTCKKSRNS_INTERACTIVE_BOOT,
                         ::testing::ValuesIn(testCasesUTCKKSRNS_INTERACTIVE_BOOT), testName);
