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
    BGVRNS_AUTOMORPHISM = 0,
    EVAL_AT_INDX_PACKED_ARRAY,
    EVAL_SUM_PACKED_ARRAY,
};
TEST_CASE_TYPE convertStringToCaseType(const std::string& str) {
    const std::unordered_map<std::string, TEST_CASE_TYPE> stringToCaseType = {
        {"BGVRNS_AUTOMORPHISM", BGVRNS_AUTOMORPHISM},
        {"EVAL_AT_INDX_PACKED_ARRAY", EVAL_AT_INDX_PACKED_ARRAY},
        {"EVAL_SUM_PACKED_ARRAY", EVAL_SUM_PACKED_ARRAY}};
    auto search = stringToCaseType.find(str);
    if (stringToCaseType.end() != search) {
        return search->second;
    }
    OPENFHE_THROW(std::string("Can not convert ") + str + "to test case");
}
static std::ostream& operator<<(std::ostream& os, const TEST_CASE_TYPE& type) {
    const std::unordered_map<TEST_CASE_TYPE, std::string> caseTypeToString = {
        {BGVRNS_AUTOMORPHISM, "BGVRNS_AUTOMORPHISM"},
        {EVAL_AT_INDX_PACKED_ARRAY, "EVAL_AT_INDX_PACKED_ARRAY"},
        {EVAL_SUM_PACKED_ARRAY, "EVAL_SUM_PACKED_ARRAY"}};
    auto search = caseTypeToString.find(type);
    if (caseTypeToString.end() != search) {
        return os << search->second;
    }
    OPENFHE_THROW("Unknown test case");
}
//===========================================================================================================
enum TEST_CASE_ERROR {
    SUCCESS = 0,
    CORNER_CASES,
    INVALID_INPUT_DATA,
    INVALID_PRIVATE_KEY,
    INVALID_PUBLIC_KEY,
    INVALID_EVAL_KEY,
    INVALID_INDEX,
    INVALID_BATCH_SIZE,
    NO_KEY_GEN_CALL
};
TEST_CASE_ERROR convertStringToCaseError(const std::string& str) {
    std::unordered_map<std::string, TEST_CASE_ERROR> stringToError = {
        {"SUCCESS", SUCCESS},
        {"CORNER_CASES", CORNER_CASES},
        {"INVALID_INPUT_DATA", INVALID_INPUT_DATA},
        {"INVALID_PRIVATE_KEY", INVALID_PRIVATE_KEY},
        {"INVALID_PUBLIC_KEY", INVALID_PUBLIC_KEY},
        {"INVALID_EVAL_KEY", INVALID_EVAL_KEY},
        {"INVALID_INDEX", INVALID_INDEX},
        {"INVALID_BATCH_SIZE", INVALID_BATCH_SIZE},
        {"NO_KEY_GEN_CALL", NO_KEY_GEN_CALL},
    };
    auto search = stringToError.find(str);
    if (stringToError.end() != search) {
        return search->second;
    }
    OPENFHE_THROW(std::string("Can not convert ") + str + "to test case error");
}
//===========================================================================================================
struct TEST_CASE_UTBGVRNS_AUTOMORPHISM : public BaseTestCase {
    TEST_CASE_TYPE testCaseType;
    // test case description - MUST BE UNIQUE
    std::string description;

    // additional test case data
    TEST_CASE_ERROR error;
    std::vector<uint32_t> indexList;

    std::string buildTestName() const {
        std::stringstream ss;
        ss << testCaseType << "_" << description;
        return ss.str();
    }
    std::string toString() const {
        std::stringstream ss;
        ss << "[testCase: " << testCaseType << "], [description: " << description
           << "], [params: " << getCryptoContextParamOverrides() << "], [error: " << error
           << "], [indexList: " << indexList << "] ";
        return ss.str();
    }
};

// this lambda provides a name to be printed for every test run by INSTANTIATE_TEST_SUITE_P.
// the name MUST be constructed from digits, letters and '_' only
static auto testName = [](const testing::TestParamInfo<TEST_CASE_UTBGVRNS_AUTOMORPHISM>& testParamInfo) {
    return testParamInfo.param.buildTestName();
};

static std::ostream& operator<<(std::ostream& os, const TEST_CASE_UTBGVRNS_AUTOMORPHISM& test) {
    return os << test.toString();
}
//===========================================================================================================
std::vector<TEST_CASE_UTBGVRNS_AUTOMORPHISM> getTestData(std::string fileName) {
    // TODO: add a new test data file for NATIVEINT == 128
    std::string testDataFileName(createDataFileName(fileName));
    std::vector<std::vector<std::string>> fileRows(readDataFile(testDataFileName));
    size_t numRows = fileRows.size();

    std::vector<TEST_CASE_UTBGVRNS_AUTOMORPHISM> allData;
    allData.reserve(numRows);

    for (const std::vector<std::string>& vec : fileRows) {
        TEST_CASE_UTBGVRNS_AUTOMORPHISM testCase;

        auto it               = vec.begin();
        testCase.testCaseType = convertStringToCaseType(*it);
        testCase.description  = *(++it);

        // size_t numOverrides = testCase.populateCryptoContextParams(++it);
        size_t numOverrides = testCase.setCryptoContextParamsOverrides(++it);

        it += numOverrides;
        if (it != vec.end()) {
            // process TEST_CASE_ERROR
            testCase.error = convertStringToCaseError(*it);
            if (++it != vec.end()) {
                // process list of indices
                std::string indexListStr(*it);
                if (!isEmpty(indexListStr)) {
                    std::vector<std::string> indices = tokenize(indexListStr, '|');
                    for (std::string& i : indices) {
                        testCase.indexList.push_back(static_cast<uint32_t>(std::stoul(i)));
                    }
                }
            }
        }

        allData.push_back(std::move(testCase));
    }
    return allData;
}
//===========================================================================================================
static std::vector<TEST_CASE_UTBGVRNS_AUTOMORPHISM> testCasesUTBGVRNS_AUTOMORPHISM = getTestData(__FILE__);
//===========================================================================================================

class UTBGVRNS_AUTOMORPHISM : public ::testing::TestWithParam<TEST_CASE_UTBGVRNS_AUTOMORPHISM> {
    using Element    = DCRTPoly;
    const double eps = EPSILON;

    const std::vector<int64_t> vector8{1, 2, 3, 4, 5, 6, 7, 8};
    const std::vector<int64_t> vectorFailure{1, 2, 3, 4};
    const usint invalidIndexAutomorphism = 4;
    const int64_t vector8Sum             = std::accumulate(vector8.begin(), vector8.end(), int64_t(0));  // 36

protected:
    void SetUp() {}

    void TearDown() {
        PackedEncoding::Destroy();
        CryptoContextFactory<DCRTPoly>::ReleaseAllContexts();
    }

    void UnitTest_AutomorphismPackedArray(const TEST_CASE_UTBGVRNS_AUTOMORPHISM& testData,
                                          const std::string& failmsg = std::string()) {
        for (auto index : testData.indexList) {
            try {
                CryptoContext<Element> cc(UnitTestGenerateContext(testData));

                // Initialize the public key containers.
                KeyPair<Element> kp = cc->KeyGen();

                index                         = (INVALID_INDEX == testData.error) ? invalidIndexAutomorphism : index;
                std::vector<int64_t> inputVec = (INVALID_INPUT_DATA == testData.error) ? vectorFailure : vector8;
                Plaintext intArray            = cc->MakePackedPlaintext(inputVec);

                Ciphertext<Element> ciphertext =
                    (INVALID_PUBLIC_KEY == testData.error) ?
                        cc->Encrypt(static_cast<const PublicKey<Element>>(nullptr), intArray) :
                        cc->Encrypt(kp.publicKey, intArray);

                std::vector<usint> indexList(testData.indexList);

                auto evalKeys =
                    (INVALID_PRIVATE_KEY == testData.error) ?
                        cc->EvalAutomorphismKeyGen(static_cast<const PrivateKey<Element>>(nullptr), indexList) :
                        cc->EvalAutomorphismKeyGen(kp.secretKey, indexList);

                std::map<usint, EvalKey<Element>> emptyEvalKeys;
                Ciphertext<Element> p1 = (INVALID_EVAL_KEY == testData.error) ?
                                             cc->EvalAutomorphism(ciphertext, index, emptyEvalKeys) :
                                             cc->EvalAutomorphism(ciphertext, index, *evalKeys);

                Plaintext intArrayNew;
                cc->Decrypt(kp.secretKey, p1, &intArrayNew);

                std::string errMsg(" for index[" + std::to_string(index) + "]");
                switch (testData.error) {
                    case SUCCESS:
                        // should not fail
                        EXPECT_TRUE(CheckAutomorphism(intArrayNew->GetPackedValue(), vector8)) << errMsg;
                        break;
                    case INVALID_INPUT_DATA:
                        // should fail
                        EXPECT_FALSE(CheckAutomorphism(intArrayNew->GetPackedValue(), vector8)) << errMsg;
                        break;
                    default:
                        // make it fail
                        std::cerr << __func__ << " failed " << errMsg << std::endl;
                        EXPECT_EQ(0, 1);
                        break;
                }
            }
            catch (std::exception& e) {
                switch (testData.error) {
                    case SUCCESS:
                    case INVALID_INPUT_DATA:
                        std::cerr << "Exception thrown from " << __func__ << "(): " << e.what() << std::endl;
                        // make it fail
                        EXPECT_EQ(0, 1);
                        break;
                    default:
                        EXPECT_EQ(1, 1);
                        break;
                }
            }
            catch (...) {
#if defined EMSCRIPTEN
                std::string name("EMSCRIPTEN_UNKNOWN");
#else
                std::string name(demangle(__cxxabiv1::__cxa_current_exception_type()->name()));
#endif
                std::cerr << "Unknown exception of type \"" << name << "\" thrown from " << __func__ << "()"
                          << std::endl;
                // make it fail
                EXPECT_TRUE(0 == 1) << failmsg;
            }
        }
    }

    void UnitTest_EvalAtIndexPackedArray(const TEST_CASE_UTBGVRNS_AUTOMORPHISM& testData,
                                         const std::string& failmsg = std::string()) {
        for (auto index : testData.indexList) {
            try {
                CryptoContext<Element> cc(UnitTestGenerateContext(testData));

                // Initialize the public key containers.
                KeyPair<Element> kp = cc->KeyGen();

                std::vector<int64_t> inputVec = (INVALID_INPUT_DATA == testData.error) ? vectorFailure : vector8;
                Plaintext intArray            = cc->MakePackedPlaintext(inputVec);

                if (NO_KEY_GEN_CALL != testData.error) {
                    std::vector<int32_t> indices{(int32_t)index, (int32_t)-index};
                    if (INVALID_PRIVATE_KEY == testData.error)
                        cc->EvalAtIndexKeyGen(static_cast<const PrivateKey<Element>>(nullptr), indices);
                    else
                        cc->EvalAtIndexKeyGen(kp.secretKey, indices);
                }

                Ciphertext<Element> ciphertext =
                    (INVALID_PUBLIC_KEY == testData.error) ?
                        cc->Encrypt(static_cast<const PublicKey<Element>>(nullptr), intArray) :
                        cc->Encrypt(kp.publicKey, intArray);

                if (INVALID_INDEX == testData.error)
                    index = invalidIndexAutomorphism;
                Ciphertext<Element> p1 = cc->EvalAtIndex(ciphertext, index);
                Ciphertext<Element> p2 = cc->EvalAtIndex(p1, -index);

                Plaintext intArrayNew;
                cc->Decrypt(kp.secretKey, p2, &intArrayNew);
                intArrayNew->SetLength(inputVec.size());

                std::string errMsg(" for index[" + std::to_string(index) + "]");
                switch (testData.error) {
                    case SUCCESS:
                    case CORNER_CASES:
                        // should not fail
                        checkEquality(intArrayNew->GetPackedValue(), vector8, eps, errMsg);
                        break;
                    case INVALID_INPUT_DATA:
                        // should fail
                        EXPECT_FALSE(checkEquality(intArrayNew->GetPackedValue(), vector8)) << errMsg;
                        break;
                    default:
                        // make it fail
                        std::cerr << __func__ << " failed " << errMsg << std::endl;
                        EXPECT_EQ(0, 1);
                        break;
                }
            }
            catch (std::exception& e) {
                switch (testData.error) {
                    case SUCCESS:
                    case CORNER_CASES:
                    case INVALID_INPUT_DATA:
                        std::cerr << "Exception thrown from " << __func__ << "(): " << e.what() << std::endl;
                        // make it fail
                        EXPECT_EQ(0, 1);
                        break;
                    default:
                        EXPECT_EQ(1, 1);
                        break;
                }
            }
            catch (...) {
#if defined EMSCRIPTEN
                std::string name("EMSCRIPTEN_UNKNOWN");
#else
                std::string name(demangle(__cxxabiv1::__cxa_current_exception_type()->name()));
#endif
                std::cerr << "Unknown exception of type \"" << name << "\" thrown from " << __func__ << "()"
                          << std::endl;
                // make it fail
                EXPECT_TRUE(0 == 1) << failmsg;
            }
        }
    }

    void UnitTest_EvalSumPackedArray(const TEST_CASE_UTBGVRNS_AUTOMORPHISM& testData,
                                     const std::string& failmsg = std::string()) {
        try {
            CryptoContext<Element> cc(UnitTestGenerateContext(testData));

            // Initialize the public key containers.
            KeyPair<Element> kp = cc->KeyGen();

            std::vector<int64_t> inputVec = vector8;
            Plaintext intArray            = cc->MakePackedPlaintext(inputVec);

            if (NO_KEY_GEN_CALL != testData.error) {
                if (INVALID_PRIVATE_KEY == testData.error)
                    cc->EvalSumKeyGen(static_cast<const PrivateKey<Element>>(nullptr));
                else
                    cc->EvalSumKeyGen(kp.secretKey);
            }

            Ciphertext<Element> ciphertext = (INVALID_PUBLIC_KEY == testData.error) ?
                                                 cc->Encrypt(static_cast<const PublicKey<Element>>(nullptr), intArray) :
                                                 cc->Encrypt(kp.publicKey, intArray);

            uint32_t batchSize     = 8;
            uint32_t batchSz       = (INVALID_BATCH_SIZE == testData.error) ? (batchSize * 1000) : batchSize;
            Ciphertext<Element> p1 = cc->EvalSum(ciphertext, batchSz);

            Plaintext intArrayNew;
            cc->Decrypt(kp.secretKey, p1, &intArrayNew);

            switch (testData.error) {
                case SUCCESS:
                    // should not fail
                    EXPECT_TRUE(checkEquality(intArrayNew->GetPackedValue()[0], vector8Sum));
                    break;
                default:
                    // make it fail
                    std::cerr << __func__ << " failed" << std::endl;
                    EXPECT_EQ(0, 1);
                    break;
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
TEST_P(UTBGVRNS_AUTOMORPHISM, Automorphism) {
    setupSignals();
    auto test = GetParam();

    switch (test.testCaseType) {
        case BGVRNS_AUTOMORPHISM:
            UnitTest_AutomorphismPackedArray(test, test.buildTestName());
            break;
        case EVAL_AT_INDX_PACKED_ARRAY:
            UnitTest_EvalAtIndexPackedArray(test, test.buildTestName());
            break;
        case EVAL_SUM_PACKED_ARRAY:
            UnitTest_EvalSumPackedArray(test, test.buildTestName());
            break;
        default:
            break;
    }
}

INSTANTIATE_TEST_SUITE_P(UnitTests, UTBGVRNS_AUTOMORPHISM, ::testing::ValuesIn(testCasesUTBGVRNS_AUTOMORPHISM),
                         testName);
