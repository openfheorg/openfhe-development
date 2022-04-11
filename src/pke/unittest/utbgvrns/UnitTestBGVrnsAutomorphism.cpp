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
  for all transform testing
 */

#include "scheme/bfvrns/cryptocontext-bfvrns.h"
#include "scheme/bgvrns/cryptocontext-bgvrns.h"
#include "scheme/ckksrns/cryptocontext-ckksrns.h"
#include "gen-cryptocontext.h"

#include <algorithm>
#include <iostream>
#include <vector>
#include "UnitTestUtils.h"
#include "gtest/gtest.h"

//#include "cryptocontext.h"


#include "encoding/encodings.h"

#include "utils/debug.h"

using namespace lbcrypto;

namespace {
class UTBGVRNS_AUTOMORPHISM : public ::testing::Test {
 protected:
  void SetUp() {}

  void TearDown() {
    CryptoContextFactory<DCRTPoly>::ReleaseAllContexts();
  }

 public:
};

const std::vector<int64_t> vector8  {1, 2, 3, 4, 5, 6, 7, 8};
const std::vector<int64_t> vector10 {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
const std::vector<int64_t> vectorFailure {1, 2, 3, 4};
const std::vector<usint> initIndexList {3, 5, 7, 9, 11, 13, 15};
const usint invalidIndexAutomorphism = 4;
const std::vector<std::complex<double>> vectorComplexFailure { 1.0, 2.0, 3.0, 4.0 };
const std::vector<std::complex<double>> vector8Complex{ 1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0 };
const std::complex<double> vector8ComplexSum = std::accumulate(vector8Complex.begin(), vector8Complex.end(), std::complex<double>(0)); // 36.0;
const int64_t vector8Sum = std::accumulate(vector8.begin(), vector8.end(), int64_t(0)); // 36

enum TEST_ESTIMATED_RESULT {
    SUCCESS,
    INVALID_INPUT_DATA,
    INVALID_PRIVATE_KEY,
    INVALID_PUBLIC_KEY,
    INVALID_EVAL_KEY,
    INVALID_INDEX,
    INVALID_BATCH_SIZE,
    NO_KEY_GEN_CALL
};

} // anonymous namespace

//================================================================================================

// declaration for Automorphism Test on BGV scheme with polynomial operation in
// powerof 2 cyclotomics.
std::vector<int64_t> BGVrnsAutomorphismPackedArray(usint i,
                                                TEST_ESTIMATED_RESULT testResult = SUCCESS) {
  using Element = DCRTPoly;

  CCParams<CryptoContextBGVRNS> parameters;
  parameters.SetMultiplicativeDepth(1);
  parameters.SetPlaintextModulus(17);
  parameters.SetSecurityLevel(HEStd_NotSet);
  parameters.SetStandardDeviation(3.2);
  parameters.SetKeySwitchTechnique(BV);
  parameters.SetRingDim(8);
  parameters.SetRelinWindow(1);
  parameters.SetRescalingTechnique(FIXEDAUTO);

  CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);
  // Enable features that you wish to use
  cc->Enable(PKE);
  cc->Enable(KEYSWITCH);
  cc->Enable(LEVELEDSHE);
  cc->Enable(ADVANCEDSHE);

  // Initialize the public key containers.
  KeyPair<Element> kp = cc->KeyGen();

  i = (INVALID_INDEX == testResult) ?  invalidIndexAutomorphism : i;
  std::vector<int64_t> inputVec = (INVALID_INPUT_DATA == testResult) ? vectorFailure : vector8;
  Plaintext intArray = cc->MakePackedPlaintext(inputVec);

  Ciphertext<Element> ciphertext = (INVALID_PUBLIC_KEY == testResult) ?
      cc->Encrypt(static_cast<const PublicKey<Element>>(nullptr), intArray) :
      cc->Encrypt(kp.publicKey, intArray);

  std::vector<usint> indexList(initIndexList);

  auto evalKeys = (INVALID_PRIVATE_KEY == testResult) ?
      cc->EvalAutomorphismKeyGen(static_cast<const PrivateKey<Element>>(nullptr), indexList) :
      cc->EvalAutomorphismKeyGen(kp.secretKey, indexList);

  std::map<usint, EvalKey<Element>> emptyEvalKeys;
  Ciphertext<Element> p1 = (INVALID_EVAL_KEY == testResult) ?
    cc->EvalAutomorphism(ciphertext, i, emptyEvalKeys) :
    cc->EvalAutomorphism(ciphertext, i, *evalKeys);

  Plaintext intArrayNew;
  cc->Decrypt(kp.secretKey, p1, &intArrayNew);
  return intArrayNew->GetPackedValue();
}


TEST_F(UTBGVRNS_AUTOMORPHISM, Test_BGVrns_Automorphism_PowerOf2) {
  PackedEncoding::Destroy();

  for (auto index : initIndexList) {
    auto morphedVector = BGVrnsAutomorphismPackedArray(index);
    EXPECT_TRUE(CheckAutomorphism(morphedVector, vector8));
  }
}

TEST_F(UTBGVRNS_AUTOMORPHISM, Test_BGVrns_Automorphism_PowerOf2_INVALID_INPUT_DATA) {
  PackedEncoding::Destroy();

  for (auto index : initIndexList) {
    auto morphedVector = BGVrnsAutomorphismPackedArray(index, INVALID_INPUT_DATA);
    EXPECT_FALSE(CheckAutomorphism(morphedVector, vector8));
  }
}

TEST_F(UTBGVRNS_AUTOMORPHISM, Test_BGVrns_Automorphism_PowerOf2_INVALID_PRIVATE_KEY) {
  PackedEncoding::Destroy();

  try {
    for (auto index : initIndexList) {
      auto morphedVector = BGVrnsAutomorphismPackedArray(index, INVALID_PRIVATE_KEY);
      EXPECT_EQ(0, 1);
    }
  }
  catch(const exception& e) {
    //std::cout << "Test_BGVrns_Automorphism_PowerOf2_INVALID_PRIVATE_KEY exception: " << e.what() << std::endl;
    EXPECT_EQ(1, 1);
  }
}

TEST_F(UTBGVRNS_AUTOMORPHISM, Test_BGVrns_Automorphism_PowerOf2_INVALID_PUBLIC_KEY) {
  PackedEncoding::Destroy();

  try {
    for (auto index : initIndexList) {
      auto morphedVector = BGVrnsAutomorphismPackedArray(index, INVALID_PUBLIC_KEY);
      EXPECT_EQ(0, 1);
    }
  }
  catch(const exception& e) {
    //std::cout << "Test_BGVrns_Automorphism_PowerOf2_INVALID_PUBLIC_KEY exception: " << e.what() << std::endl;
    EXPECT_EQ(1, 1);
  }
}

TEST_F(UTBGVRNS_AUTOMORPHISM, Test_BGVrns_Automorphism_PowerOf2_INVALID_EVAL_KEY) {
  PackedEncoding::Destroy();

  try {
    for (auto index : initIndexList) {
      auto morphedVector = BGVrnsAutomorphismPackedArray(index, INVALID_EVAL_KEY);
      EXPECT_EQ(0, 1);
    }
  }
  catch(const exception& e) {
    //std::cout << "Test_BGVrns_Automorphism_PowerOf2_INVALID_EVAL_KEY exception: " << e.what() << std::endl;
    EXPECT_EQ(1, 1);
  }
}

TEST_F(UTBGVRNS_AUTOMORPHISM, Test_BGVrns_Automorphism_PowerOf2_INVALID_INDEX) {
  PackedEncoding::Destroy();

  try {
    for (auto index : initIndexList) {
      auto morphedVector = BGVrnsAutomorphismPackedArray(index, INVALID_INDEX);
      EXPECT_EQ(0, 1);
    }
  }
  catch(const exception& e) {
    //std::cout << "Test_BGVrns_Automorphism_PowerOf2_INVALID_INDEX exception: " << e.what() << std::endl;
    EXPECT_EQ(1, 1);
  }
}

//================================================================================================

std::vector<int64_t> BGVrnsEvalAtIndexPackedArray(usint i,
                                                  TEST_ESTIMATED_RESULT testResult = SUCCESS) {
  using Element = DCRTPoly;
  CCParams<CryptoContextBGVRNS> parameters;
  parameters.SetMultiplicativeDepth(1);
  parameters.SetPlaintextModulus(65537);
  parameters.SetRescalingTechnique(FIXEDAUTO);

  CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);
  cc->Enable(PKE);
  cc->Enable(KEYSWITCH);
  cc->Enable(LEVELEDSHE);
  cc->Enable(ADVANCEDSHE);

  // Initialize the public key containers.
  KeyPair<Element> kp = cc->KeyGen();

  int index = i;
  std::vector<int64_t> inputVec = (INVALID_INPUT_DATA == testResult) ? vectorFailure : vector8;
  Plaintext intArray = cc->MakePackedPlaintext(inputVec);

  if( NO_KEY_GEN_CALL != testResult )
  {
    std::vector<int32_t> indices { index, -index };
    if( INVALID_PRIVATE_KEY == testResult )
      cc->EvalAtIndexKeyGen(static_cast<const PrivateKey<Element>>(nullptr), indices);
    else
      cc->EvalAtIndexKeyGen(kp.secretKey, indices);
  }

  Ciphertext<Element> ciphertext = (INVALID_PUBLIC_KEY == testResult) ?
      cc->Encrypt(static_cast<const PublicKey<Element>>(nullptr), intArray) :
      cc->Encrypt(kp.publicKey, intArray);

  if( INVALID_INDEX == testResult )
    index = invalidIndexAutomorphism;
  Ciphertext<Element> p1 = cc->EvalAtIndex(ciphertext, index);
  Ciphertext<Element> p2 = cc->EvalAtIndex(p1, -index);

  Plaintext intArrayNew;
  cc->Decrypt(kp.secretKey, p2, &intArrayNew);
  intArrayNew->SetLength(inputVec.size());

  return intArrayNew->GetPackedValue();
}

//================================================================================================

TEST_F(UTBGVRNS_AUTOMORPHISM, Test_BGVrns_EvalAtIndex) {
  PackedEncoding::Destroy();

  for (auto index : initIndexList) {
    auto morphedVector = BGVrnsEvalAtIndexPackedArray(index);
    EXPECT_TRUE(checkEquality(morphedVector, vector8));
  }
}

TEST_F(UTBGVRNS_AUTOMORPHISM, Test_BGVrns_EvalAtIndex_CORNER_CASES) {
    PackedEncoding::Destroy();

    // Rotation with index at 0 should result in nothing happening and thus
    // The checkEquality should be true. Currently there is a bug in the code
    // however and this is not the case.
    static const std::vector<usint> cornerCaseIndexList{ 0 };

    for (auto index : cornerCaseIndexList) {
        auto morphedVector = BGVrnsEvalAtIndexPackedArray(index);
        EXPECT_TRUE(checkEquality(morphedVector, vector8));
    }
}

TEST_F(UTBGVRNS_AUTOMORPHISM, Test_BGVrns_EvalAtIndex_INVALID_INPUT_DATA) {
  PackedEncoding::Destroy();

  for (auto index : initIndexList) {
    auto morphedVector = BGVrnsEvalAtIndexPackedArray(index, INVALID_INPUT_DATA);
    EXPECT_FALSE(checkEquality(morphedVector, vector8));
  }
}

TEST_F(UTBGVRNS_AUTOMORPHISM, Test_BGVrns_EvalAtIndex_INVALID_PRIVATE_KEY) {
  PackedEncoding::Destroy();

  try {
    for (auto index : initIndexList) {
      auto morphedVector = BGVrnsEvalAtIndexPackedArray(index, INVALID_PRIVATE_KEY);
      EXPECT_EQ(0, 1);
    }
  }
  catch(const exception& e) {
    //std::cout << "Test_BGVrns_EvalAtIndex_INVALID_PRIVATE_KEY exception: " << e.what() << std::endl;
    EXPECT_EQ(1, 1);
  }
}

TEST_F(UTBGVRNS_AUTOMORPHISM, Test_BGVrns_EvalAtIndex_INVALID_PUBLIC_KEY) {
  PackedEncoding::Destroy();

  try {
    for (auto index : initIndexList) {
      auto morphedVector = BGVrnsEvalAtIndexPackedArray(index, INVALID_PUBLIC_KEY);
      EXPECT_EQ(0, 1);
    }
  }
  catch(const exception& e) {
    //std::cout << "Test_BGVrns_EvalAtIndex_INVALID_PUBLIC_KEY exception: " << e.what() << std::endl;
    EXPECT_EQ(1, 1);
  }
}

TEST_F(UTBGVRNS_AUTOMORPHISM, Test_BGVrns_EvalAtIndex_NO_KEY_GEN_CALL) {
  PackedEncoding::Destroy();

  try {
    auto morphedVector = BGVrnsEvalAtIndexPackedArray(1, NO_KEY_GEN_CALL);
    EXPECT_EQ(0, 1);
  }
  catch(const exception& e) {
    //std::cout << "Test_BGVrns_EvalAtIndex_NO_KEY_GEN_CALL exception: " << e.what() << std::endl;
    EXPECT_EQ(1, 1);
  }
}

//================================================================================================

std::vector<int64_t> BGVrnsEvalSumPackedArray(usint i,
                                              TEST_ESTIMATED_RESULT testResult = SUCCESS) {
  using Element = DCRTPoly;
  CCParams<CryptoContextBGVRNS> parameters;
  parameters.SetMultiplicativeDepth(1);
  parameters.SetPlaintextModulus(65537);
  parameters.SetRescalingTechnique(FIXEDAUTO);

  CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);
  cc->Enable(PKE);
  cc->Enable(KEYSWITCH);
  cc->Enable(LEVELEDSHE);
  cc->Enable(ADVANCEDSHE);

  // Initialize the public key containers.
  KeyPair<Element> kp = cc->KeyGen();

  std::vector<int64_t> inputVec = vector8;
  Plaintext intArray = cc->MakePackedPlaintext(inputVec);

  if( NO_KEY_GEN_CALL != testResult )
  {
    if( INVALID_PRIVATE_KEY == testResult )
      cc->EvalSumKeyGen(static_cast<const PrivateKey<Element>>(nullptr));
    else
      cc->EvalSumKeyGen(kp.secretKey);
  }

  Ciphertext<Element> ciphertext = (INVALID_PUBLIC_KEY == testResult) ?
      cc->Encrypt(static_cast<const PublicKey<Element>>(nullptr), intArray) :
      cc->Encrypt(kp.publicKey, intArray);

  uint32_t batchSize = 8;
  uint32_t batchSz = (INVALID_BATCH_SIZE == testResult) ?  (batchSize*1000) : batchSize;
  Ciphertext<Element> p1 = cc->EvalSum(ciphertext, batchSz);

  Plaintext intArrayNew;
  cc->Decrypt(kp.secretKey, p1, &intArrayNew);

  return intArrayNew->GetPackedValue();
}

//================================================================================================

TEST_F(UTBGVRNS_AUTOMORPHISM, Test_BGVrns_EvalSum) {
  PackedEncoding::Destroy();

  auto morphedVector = BGVrnsEvalSumPackedArray(0);
  EXPECT_TRUE(checkEquality(morphedVector[0], vector8Sum));
}

TEST_F(UTBGVRNS_AUTOMORPHISM, Test_BGVrns_EvalSum_INVALID_PRIVATE_KEY) {
  PackedEncoding::Destroy();

  try {
    auto morphedVector = BGVrnsEvalSumPackedArray(0, INVALID_PRIVATE_KEY);
    EXPECT_EQ(0, 1);
  }
  catch(const exception& e) {
    //std::cout << "Test_BGVrns_EvalSum_INVALID_PRIVATE_KEY exception: " << e.what() << std::endl;
    EXPECT_EQ(1, 1);
  }
}

TEST_F(UTBGVRNS_AUTOMORPHISM, Test_BGVrns_EvalSum_INVALID_PUBLIC_KEY) {
  PackedEncoding::Destroy();

  try {
    auto morphedVector = BGVrnsEvalSumPackedArray(0, INVALID_PUBLIC_KEY);
    EXPECT_EQ(0, 1);
  }
  catch(const exception& e) {
    //std::cout << "Test_BGVrns_EvalSum_INVALID_PUBLIC_KEY exception: " << e.what() << std::endl;
    EXPECT_EQ(1, 1);
  }
}

TEST_F(UTBGVRNS_AUTOMORPHISM, Test_BGVrns_EvalSum_INVALID_BATCH_SIZE) {
  PackedEncoding::Destroy();

  try {
    auto morphedVector = BGVrnsEvalSumPackedArray(0, INVALID_BATCH_SIZE);
    EXPECT_EQ(0, 1);
  }
  catch(const exception& e) {
    //std::cout << "Test_BGVrns_EvalSum_INVALID_BATCH_SIZE exception: " << e.what() << std::endl;
    EXPECT_EQ(1, 1);
  }
}

TEST_F(UTBGVRNS_AUTOMORPHISM, Test_BGVrns_EvalSum_NO_KEY_GEN_CALL) {
  PackedEncoding::Destroy();

  try {
    auto morphedVector = BGVrnsEvalSumPackedArray(0, NO_KEY_GEN_CALL);
    EXPECT_EQ(0, 1);
  }
  catch(const exception& e) {
    //std::cout << "Test_BGVrns_EvalSum_NO_KEY_GEN_CALL exception: " << e.what() << std::endl;
    EXPECT_EQ(1, 1);
  }
}
//================================================================================================

