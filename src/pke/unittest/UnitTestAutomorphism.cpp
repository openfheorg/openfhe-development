// @file UnitTestAutomorphism for all transform testing
// @author TPOC: contact@palisade-crypto.org
//
// @copyright Copyright (c) 2019, New Jersey Institute of Technology (NJIT)
// All rights reserved.
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
// 1. Redistributions of source code must retain the above copyright notice,
// this list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright notice,
// this list of conditions and the following disclaimer in the documentation
// and/or other materials provided with the distribution. THIS SOFTWARE IS
// PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR
// IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO
// EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
// INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
// LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
// ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#include <algorithm>
#include <iostream>
#include <vector>
#include "UnitTestUtils.h"
#include "gtest/gtest.h"

#include "cryptocontext.h"

#include "encoding/encodings.h"

#include "utils/debug.h"

using namespace std;
using namespace lbcrypto;

namespace {
class UTAUTOMORPHISM : public ::testing::Test {
 protected:
  void SetUp() {}

  void TearDown() {
    CryptoContextFactory<Poly>::ReleaseAllContexts();
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

// declaration for Automorphism Test on Null scheme with polynomial operation in
// power of 2 cyclotomics.
std::vector<int64_t> NullAutomorphismPackedArray(usint i,
                                                 TEST_ESTIMATED_RESULT testResult = SUCCESS) {
  using Element = Poly;
  usint m = 16;
  BigInteger q("67108913");
  // BigInteger rootOfUnity("61564");
  usint plaintextModulus = 17;

  // float stdDev = 4;

  // auto params = std::make_shared<ILParams>(m, q, rootOfUnity);

  CryptoContext<Element> cc =
      CryptoContextFactory<Element>::genCryptoContextNull(m, plaintextModulus);

  cc->Enable(ENCRYPTION);
  cc->Enable(SHE);

  // Initialize the public key containers.
  LPKeyPair<Element> kp = cc->KeyGen();

  i = (INVALID_INDEX == testResult) ?  invalidIndexAutomorphism : i;
  std::vector<int64_t> inputVec = (INVALID_INPUT_DATA == testResult) ? vectorFailure : vector8;
  Plaintext intArray = cc->MakePackedPlaintext(inputVec);

  Ciphertext<Element> ciphertext = (INVALID_PUBLIC_KEY == testResult) ?
                                    cc->Encrypt(nullptr, intArray) : cc->Encrypt(kp.publicKey, intArray);

  std::vector<usint> indexList(initIndexList);

  auto evalKeys = (INVALID_PRIVATE_KEY == testResult) ?
    cc->EvalAutomorphismKeyGen(kp.publicKey, nullptr, indexList) :
    cc->EvalAutomorphismKeyGen(kp.publicKey, kp.secretKey, indexList);

  std::map<usint, LPEvalKey<Element>> emptyEvalKeys;
  Ciphertext<Element> p1 = (INVALID_EVAL_KEY == testResult) ?
    cc->EvalAutomorphism(ciphertext, i, emptyEvalKeys) :
    cc->EvalAutomorphism(ciphertext, i, *evalKeys);

  Plaintext intArrayNew;
  cc->Decrypt(kp.secretKey, p1, &intArrayNew);

  return intArrayNew->GetPackedValue();
}

// declaration for Automorphism Test on BGV scheme with polynomial operation in
// powerof 2 cyclotomics.
std::vector<int64_t> BGVrnsAutomorphismPackedArray(usint i,
                                                TEST_ESTIMATED_RESULT testResult = SUCCESS) {
  using Element = DCRTPoly;
  // Set the main parameters
  int plaintextModulus = 17;
  double sigma = 3.2;
  SecurityLevel securityLevel = HEStd_NotSet;
  uint32_t depth = 1;

  // Instantiate the crypto context
  CryptoContext<DCRTPoly> cc =
      CryptoContextFactory<DCRTPoly>::genCryptoContextBGVrns(
          depth, plaintextModulus, securityLevel, sigma, 2, OPTIMIZED, BV, 8, 0, 0, 0, 1);

  // Enable features that you wish to use
  cc->Enable(ENCRYPTION);
  cc->Enable(SHE);
  cc->Enable(LEVELEDSHE);

  // Initialize the public key containers.
  LPKeyPair<Element> kp = cc->KeyGen();

  i = (INVALID_INDEX == testResult) ?  invalidIndexAutomorphism : i;
  std::vector<int64_t> inputVec = (INVALID_INPUT_DATA == testResult) ? vectorFailure : vector8;
  Plaintext intArray = cc->MakePackedPlaintext(inputVec);

  Ciphertext<Element> ciphertext = (INVALID_PUBLIC_KEY == testResult) ?
                                    cc->Encrypt(nullptr, intArray) : cc->Encrypt(kp.publicKey, intArray);

  std::vector<usint> indexList(initIndexList);

  auto evalKeys = (INVALID_PRIVATE_KEY == testResult) ?
    cc->EvalAutomorphismKeyGen(nullptr, indexList) : cc->EvalAutomorphismKeyGen(kp.secretKey, indexList);

  std::map<usint, LPEvalKey<Element>> emptyEvalKeys;
  Ciphertext<Element> p1 = (INVALID_EVAL_KEY == testResult) ?
    cc->EvalAutomorphism(ciphertext, i, emptyEvalKeys) :
    cc->EvalAutomorphism(ciphertext, i, *evalKeys);

  Plaintext intArrayNew;
  cc->Decrypt(kp.secretKey, p1, &intArrayNew);
  return intArrayNew->GetPackedValue();
}

// declaration for Automorphism Test on BFV scheme with polynomial operation in
// power of 2 cyclotomics.
std::vector<int64_t> BFVAutomorphismPackedArray(usint i,
                                                TEST_ESTIMATED_RESULT testResult = SUCCESS) {
  using Element = Poly;
  usint m = 16;
  BigInteger q("67108913");
  BigInteger rootOfUnity("61564");
  usint plaintextModulus = 17;
  usint relWindow = 1;
  float stdDev = 4;

  BigInteger BBIPlaintextModulus(plaintextModulus);
  BigInteger delta(q.DividedBy(BBIPlaintextModulus));

  auto params = std::make_shared<ILParams>(m, q, rootOfUnity);
  CryptoContext<Element> cc = CryptoContextFactory<Element>::genCryptoContextBFV(
      params, plaintextModulus, relWindow, stdDev, delta.ToString());

  cc->Enable(ENCRYPTION);
  cc->Enable(SHE);

  // Initialize the public key containers.
  LPKeyPair<Element> kp = cc->KeyGen();

  i = (INVALID_INDEX == testResult) ?  invalidIndexAutomorphism : i;
  std::vector<int64_t> inputVec = (INVALID_INPUT_DATA == testResult) ? vectorFailure : vector8;
  Plaintext intArray = cc->MakePackedPlaintext(inputVec);

  Ciphertext<Element> ciphertext = (INVALID_PUBLIC_KEY == testResult) ?
                                    cc->Encrypt(nullptr, intArray) : cc->Encrypt(kp.publicKey, intArray);

  std::vector<usint> indexList(initIndexList);

  auto evalKeys = (INVALID_PRIVATE_KEY == testResult) ?
    cc->EvalAutomorphismKeyGen(nullptr, indexList) : cc->EvalAutomorphismKeyGen(kp.secretKey, indexList);

  std::map<usint, LPEvalKey<Element>> emptyEvalKeys;
  Ciphertext<Element> p1 = (INVALID_EVAL_KEY == testResult) ?
    cc->EvalAutomorphism(ciphertext, i, emptyEvalKeys) :
    cc->EvalAutomorphism(ciphertext, i, *evalKeys);

  Plaintext intArrayNew;
  cc->Decrypt(kp.secretKey, p1, &intArrayNew);

  return intArrayNew->GetPackedValue();
}

// declaration for Automorphism Test on BFVrns scheme with polynomial operation
// in power of 2 cyclotomics.
std::vector<int64_t> BFVrnsAutomorphismPackedArray(usint i,
                                                   TEST_ESTIMATED_RESULT testResult = SUCCESS) {
  using Element = DCRTPoly;
  PlaintextModulus p = 65537;
  double sigma = 4;
  double rootHermiteFactor = 1.006;

  EncodingParams encodingParams(std::make_shared<EncodingParamsImpl>(p));

  // Set Crypto Parameters
  CryptoContext<Element> cc =
      CryptoContextFactory<Element>::genCryptoContextBFVrns(
          encodingParams, rootHermiteFactor, sigma, 0, 1, 0, OPTIMIZED, 2);

  cc->Enable(ENCRYPTION);
  cc->Enable(SHE);

  // Initialize the public key containers.
  LPKeyPair<Element> kp = cc->KeyGen();

  i = (INVALID_INDEX == testResult) ?  invalidIndexAutomorphism : i;
  std::vector<int64_t> inputVec = (INVALID_INPUT_DATA == testResult) ? vectorFailure : vector8;
  Plaintext intArray = cc->MakePackedPlaintext(inputVec);

  Ciphertext<Element> ciphertext = (INVALID_PUBLIC_KEY == testResult) ?
                                    cc->Encrypt(nullptr, intArray) : cc->Encrypt(kp.publicKey, intArray);

  std::vector<usint> indexList(initIndexList);

  auto evalKeys = (INVALID_PRIVATE_KEY == testResult) ?
    cc->EvalAutomorphismKeyGen(nullptr, indexList) : cc->EvalAutomorphismKeyGen(kp.secretKey, indexList);

  std::map<usint, LPEvalKey<Element>> emptyEvalKeys;
  Ciphertext<Element> p1 = (INVALID_EVAL_KEY == testResult) ?
    cc->EvalAutomorphism(ciphertext, i, emptyEvalKeys) :
    cc->EvalAutomorphism(ciphertext, i, *evalKeys);

  Plaintext intArrayNew;
  cc->Decrypt(kp.secretKey, p1, &intArrayNew);

  return intArrayNew->GetPackedValue();
}
//================================================================================================
TEST_F(UTAUTOMORPHISM, Test_Null_Automorphism_PowerOf2) {
  PackedEncoding::Destroy();

  for (auto index : initIndexList) {
    auto morphedVector = NullAutomorphismPackedArray(index);
    EXPECT_TRUE(CheckAutomorphism(morphedVector, vector8));
  }
}

TEST_F(UTAUTOMORPHISM, Test_Null_Automorphism_PowerOf2_INVALID_INPUT_DATA) {
  PackedEncoding::Destroy();

  for (auto index : initIndexList) {
    auto morphedVector = NullAutomorphismPackedArray(index, INVALID_INPUT_DATA);
    EXPECT_FALSE(CheckAutomorphism(morphedVector, vector8));
  }
}

TEST_F(UTAUTOMORPHISM, Test_Null_Automorphism_PowerOf2_INVALID_PRIVATE_KEY) {
  PackedEncoding::Destroy();

  try {
    for (auto index : initIndexList) {
      auto morphedVector = NullAutomorphismPackedArray(index, INVALID_PRIVATE_KEY);
      EXPECT_EQ(0, 1);
    }
  }
  catch(const exception& e) {
    //std::cout << "Test_Null_Automorphism_PowerOf2_INVALID_PRIVATE_KEY exception: " << e.what() << std::endl;
    EXPECT_EQ(1, 1);
  }
}

TEST_F(UTAUTOMORPHISM, Test_Null_Automorphism_PowerOf2_INVALID_PUBLIC_KEY) {
  PackedEncoding::Destroy();

  try {
    for (auto index : initIndexList) {
      auto morphedVector = NullAutomorphismPackedArray(index, INVALID_PUBLIC_KEY);
      EXPECT_EQ(0, 1);
    }
  }
  catch(const exception& e) {
    //std::cout << "Test_Null_Automorphism_PowerOf2_INVALID_PUBLIC_KEY exception: " << e.what() << std::endl;
    EXPECT_EQ(1, 1);
  }
}

TEST_F(UTAUTOMORPHISM, Test_Null_Automorphism_PowerOf2_INVALID_EVAL_KEY) {
  PackedEncoding::Destroy();

  try {
    for (auto index : initIndexList) {
      auto morphedVector = NullAutomorphismPackedArray(index, INVALID_EVAL_KEY);
      EXPECT_EQ(0, 1);
    }
  }
  catch(const exception& e) {
    //std::cout << "Test_Null_Automorphism_PowerOf2_INVALID_EVAL_KEY exception: " << e.what() << std::endl;
    EXPECT_EQ(1, 1);
  }
}

TEST_F(UTAUTOMORPHISM, Test_Null_Automorphism_PowerOf2_INVALID_INDEX) {
  PackedEncoding::Destroy();

  try {
    for (auto index : initIndexList) {
      auto morphedVector = NullAutomorphismPackedArray(index, INVALID_INDEX);
      EXPECT_EQ(0, 1);
    }
  }
  catch(const exception& e) {
    //std::cout << "Test_Null_Automorphism_PowerOf2_INVALID_INDEX exception: " << e.what() << std::endl;
    EXPECT_EQ(1, 1);
  }
}
//================================================================================================
TEST_F(UTAUTOMORPHISM, Test_BGVrns_Automorphism_PowerOf2) {
  PackedEncoding::Destroy();

  for (auto index : initIndexList) {
    auto morphedVector = BGVrnsAutomorphismPackedArray(index);
    EXPECT_TRUE(CheckAutomorphism(morphedVector, vector8));
  }
}

TEST_F(UTAUTOMORPHISM, Test_BGVrns_Automorphism_PowerOf2_INVALID_INPUT_DATA) {
  PackedEncoding::Destroy();

  for (auto index : initIndexList) {
    auto morphedVector = BGVrnsAutomorphismPackedArray(index, INVALID_INPUT_DATA);
    EXPECT_FALSE(CheckAutomorphism(morphedVector, vector8));
  }
}

TEST_F(UTAUTOMORPHISM, Test_BGVrns_Automorphism_PowerOf2_INVALID_PRIVATE_KEY) {
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

TEST_F(UTAUTOMORPHISM, Test_BGVrns_Automorphism_PowerOf2_INVALID_PUBLIC_KEY) {
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

TEST_F(UTAUTOMORPHISM, Test_BGVrns_Automorphism_PowerOf2_INVALID_EVAL_KEY) {
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

TEST_F(UTAUTOMORPHISM, Test_BGVrns_Automorphism_PowerOf2_INVALID_INDEX) {
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
TEST_F(UTAUTOMORPHISM, Test_BFV_Automorphism_PowerOf2) {
  PackedEncoding::Destroy();

  for (auto index : initIndexList) {
    auto morphedVector = BFVAutomorphismPackedArray(index);
    EXPECT_TRUE(CheckAutomorphism(morphedVector, vector8));
  }
}

TEST_F(UTAUTOMORPHISM, Test_BFV_Automorphism_PowerOf2_INVALID_INPUT_DATA) {
  PackedEncoding::Destroy();

  for (auto index : initIndexList) {
    auto morphedVector = BFVAutomorphismPackedArray(index, INVALID_INPUT_DATA);
    EXPECT_FALSE(CheckAutomorphism(morphedVector, vector8));
  }
}

TEST_F(UTAUTOMORPHISM, Test_BFV_Automorphism_PowerOf2_INVALID_PRIVATE_KEY) {
  PackedEncoding::Destroy();

  try {
    for (auto index : initIndexList) {
      auto morphedVector = BFVAutomorphismPackedArray(index, INVALID_PRIVATE_KEY);
      EXPECT_EQ(0, 1);
    }
  }
  catch(const exception& e) {
    //std::cout << "Test_BFV_Automorphism_PowerOf2_INVALID_PRIVATE_KEY exception: " << e.what() << std::endl;
    EXPECT_EQ(1, 1);
  }
}

TEST_F(UTAUTOMORPHISM, Test_BFV_Automorphism_PowerOf2_INVALID_PUBLIC_KEY) {
  PackedEncoding::Destroy();

  try {
    for (auto index : initIndexList) {
      auto morphedVector = BFVAutomorphismPackedArray(index, INVALID_PUBLIC_KEY);
      EXPECT_EQ(0, 1);
    }
  }
  catch(const exception& e) {
    //std::cout << "Test_BFV_Automorphism_PowerOf2_INVALID_PUBLIC_KEY exception: " << e.what() << std::endl;
    EXPECT_EQ(1, 1);
  }
}

TEST_F(UTAUTOMORPHISM, Test_BFV_Automorphism_PowerOf2_INVALID_EVAL_KEY) {
  PackedEncoding::Destroy();

  try {
    for (auto index : initIndexList) {
      auto morphedVector = BFVAutomorphismPackedArray(index, INVALID_EVAL_KEY);
      EXPECT_EQ(0, 1);
    }
  }
  catch(const exception& e) {
    //std::cout << "Test_BFV_Automorphism_PowerOf2_INVALID_EVAL_KEY exception: " << e.what() << std::endl;
    EXPECT_EQ(1, 1);
  }
}

TEST_F(UTAUTOMORPHISM, Test_BFV_Automorphism_PowerOf2_INVALID_INDEX) {
  PackedEncoding::Destroy();

  try {
    for (auto index : initIndexList) {
      auto morphedVector = BFVAutomorphismPackedArray(index, INVALID_INDEX);
      EXPECT_EQ(0, 1);
    }
  }
  catch(const exception& e) {
    //std::cout << "Test_BFV_Automorphism_PowerOf2_INVALID_INDEX exception: " << e.what() << std::endl;
    EXPECT_EQ(1, 1);
  }
}
//================================================================================================
TEST_F(UTAUTOMORPHISM, Test_BFVrns_Automorphism_PowerOf2) {
  PackedEncoding::Destroy();

  for (auto index : initIndexList) {
    auto morphedVector = BFVrnsAutomorphismPackedArray(index);
    EXPECT_TRUE(CheckAutomorphism(morphedVector, vector8));
  }
}

TEST_F(UTAUTOMORPHISM, Test_BFVrns_Automorphism_PowerOf2_INVALID_INPUT_DATA) {
  PackedEncoding::Destroy();

  for (auto index : initIndexList) {
    auto morphedVector = BFVrnsAutomorphismPackedArray(index, INVALID_INPUT_DATA);
    EXPECT_FALSE(CheckAutomorphism(morphedVector, vector8));
  }
}

TEST_F(UTAUTOMORPHISM, Test_BFVrns_Automorphism_PowerOf2_INVALID_PRIVATE_KEY) {
  PackedEncoding::Destroy();

  try {
    for (auto index : initIndexList) {
      auto morphedVector = BFVrnsAutomorphismPackedArray(index, INVALID_PRIVATE_KEY);
      EXPECT_EQ(0, 1);
    }
  }
  catch(const exception& e) {
    //std::cout << "Test_BFVrns_Automorphism_PowerOf2_INVALID_PRIVATE_KEY exception: " << e.what() << std::endl;
    EXPECT_EQ(1, 1);
  }
}

TEST_F(UTAUTOMORPHISM, Test_BFVrns_Automorphism_PowerOf2_INVALID_PUBLIC_KEY) {
  PackedEncoding::Destroy();

  try {
    for (auto index : initIndexList) {
      auto morphedVector = BFVrnsAutomorphismPackedArray(index, INVALID_PUBLIC_KEY);
      EXPECT_EQ(0, 1);
    }
  }
  catch(const exception& e) {
    //std::cout << "Test_BFVrns_Automorphism_PowerOf2_INVALID_PUBLIC_KEY exception: " << e.what() << std::endl;
    EXPECT_EQ(1, 1);
  }
}

TEST_F(UTAUTOMORPHISM, Test_BFVrns_Automorphism_PowerOf2_INVALID_EVAL_KEY) {
  PackedEncoding::Destroy();

  try {
    for (auto index : initIndexList) {
      auto morphedVector = BFVrnsAutomorphismPackedArray(index, INVALID_EVAL_KEY);
      EXPECT_EQ(0, 1);
    }
  }
  catch(const exception& e) {
    //std::cout << "Test_BFVrns_Automorphism_PowerOf2_INVALID_EVAL_KEY exception: " << e.what() << std::endl;
    EXPECT_EQ(1, 1);
  }
}

TEST_F(UTAUTOMORPHISM, Test_BFVrns_Automorphism_PowerOf2_INVALID_INDEX) {
  PackedEncoding::Destroy();

  try {
    for (auto index : initIndexList) {
      auto morphedVector = BFVrnsAutomorphismPackedArray(index, INVALID_INDEX);
      EXPECT_EQ(0, 1);
    }
  }
  catch(const exception& e) {
    //std::cout << "Test_BFVrns_Automorphism_PowerOf2_INVALID_INDEX exception: " << e.what() << std::endl;
    EXPECT_EQ(1, 1);
  }
}
//================================================================================================
TEST_F(UTAUTOMORPHISM, Test_BFV_Automorphism_Arb) { EXPECT_EQ(1, 1); }
//================================================================================================
std::vector<std::complex<double>> CKKSEvalAtIndexPackedArray(usint i,
                                                             TEST_ESTIMATED_RESULT testResult = SUCCESS) {
  using Element = DCRTPoly;
  uint32_t multDepth = 1;
  uint32_t scaleFactorBits = 50;
  uint32_t batchSize = 8;
  SecurityLevel securityLevel = HEStd_NotSet;
  usint ringDim = 16;
  CryptoContext<Element> cc = CryptoContextFactory<Element>::genCryptoContextCKKS(multDepth,
                                                                                  scaleFactorBits,
                                                                                  batchSize,
                                                                                  securityLevel,
                                                                                  ringDim);

  cc->Enable(ENCRYPTION);
  cc->Enable(SHE);

  // Initialize the public key containers.
  LPKeyPair<Element> kp = cc->KeyGen();

  int index = i;
  std::vector<std::complex<double>> inputVec = (INVALID_INPUT_DATA == testResult) ?
                                                vectorComplexFailure : vector8Complex;
  Plaintext intArray = cc->MakeCKKSPackedPlaintext(inputVec);
  //intArray->SetLength(inputVec.size());

  std::vector<int32_t> indices { index, -index };
  if (NO_KEY_GEN_CALL != testResult) {
    if (INVALID_PRIVATE_KEY == testResult) {
      cc->EvalAtIndexKeyGen(nullptr, indices);
    } else {
      cc->EvalAtIndexKeyGen(kp.secretKey, indices);
    }
  }

  Ciphertext<Element> ciphertext = (INVALID_PUBLIC_KEY == testResult) ?
                                    cc->Encrypt(nullptr, intArray) : cc->Encrypt(kp.publicKey, intArray);

  if( INVALID_INDEX == testResult ) {
    index = invalidIndexAutomorphism;
  }

  Ciphertext<Element> p1 = cc->EvalAtIndex(ciphertext, index);
  Ciphertext<Element> p2 = cc->EvalAtIndex(p1, -index);

  Plaintext intArrayNew;
  cc->Decrypt(kp.secretKey, p2, &intArrayNew);

  intArrayNew->SetLength(inputVec.size());

  return intArrayNew->GetCKKSPackedValue();
}
//================================================================================================
TEST_F(UTAUTOMORPHISM, Test_CKKS_EvalAtIndex) {
  PackedEncoding::Destroy();

  for (auto index : initIndexList) {
    auto morphedVector = CKKSEvalAtIndexPackedArray(index);
    EXPECT_TRUE(checkEquality(morphedVector, vector8Complex));
  }
}

TEST_F(UTAUTOMORPHISM, Test_CKKS_EvalAtIndex_CORNER_CASES) {
  PackedEncoding::Destroy();

  // Rotation with index at 0 should result in nothing happening and thus
  // The checkEquality should be true. Currently there is a bug in the code
  // however and this is not the case.
  static const std::vector<usint> cornerCaseIndexList {0};

  for (auto index : cornerCaseIndexList) {
    auto morphedVector = CKKSEvalAtIndexPackedArray(index);
    EXPECT_TRUE(checkEquality(morphedVector, vector8Complex));
  }
}

TEST_F(UTAUTOMORPHISM, Test_CKKS_EvalAtIndex_INVALID_INPUT_DATA) {
  PackedEncoding::Destroy();

  for (auto index : initIndexList) {
    auto morphedVector = CKKSEvalAtIndexPackedArray(index, INVALID_INPUT_DATA);
    EXPECT_FALSE(checkEquality(morphedVector, vector8Complex));
  }
}

TEST_F(UTAUTOMORPHISM, Test_CKKS_EvalAtIndex_INVALID_PRIVATE_KEY) {
  PackedEncoding::Destroy();

  try {
    for (auto index : initIndexList) {
      auto morphedVector = CKKSEvalAtIndexPackedArray(index, INVALID_PRIVATE_KEY);
      EXPECT_EQ(0, 1);
    }
  }
  catch(const exception& e) {
    //std::cout << "Test_CKKS_EvalAtIndex_INVALID_PRIVATE_KEY exception: " << e.what() << std::endl;
    EXPECT_EQ(1, 1);
  }
}

TEST_F(UTAUTOMORPHISM, Test_CKKS_EvalAtIndex_INVALID_PUBLIC_KEY) {
  PackedEncoding::Destroy();

  try {
    for (auto index : initIndexList) {
      auto morphedVector = CKKSEvalAtIndexPackedArray(index, INVALID_PUBLIC_KEY);
      EXPECT_EQ(0, 1);
    }
  }
  catch(const exception& e) {
    //std::cout << "Test_CKKS_EvalAtIndex_INVALID_PUBLIC_KEY exception: " << e.what() << std::endl;
    EXPECT_EQ(1, 1);
  }
}

TEST_F(UTAUTOMORPHISM, Test_CKKS_EvalAtIndex_NO_KEY_GEN_CALL) {
  PackedEncoding::Destroy();

  try {
    for (auto index : initIndexList) {
      auto morphedVector = CKKSEvalAtIndexPackedArray(index, NO_KEY_GEN_CALL);
      EXPECT_EQ(0, 1);
    }
  }
  catch(const exception& e) {
    //std::cout << "Test_CKKS_EvalAtIndex_NO_KEY_GEN_CALL exception: " << e.what() << std::endl;
    EXPECT_EQ(1, 1);
  }
}

TEST_F(UTAUTOMORPHISM, Test_CKKS_EvalAtIndex_INVALID_INDEX) {
  PackedEncoding::Destroy();

  try {
    for (auto index : initIndexList) {
      auto morphedVector = CKKSEvalAtIndexPackedArray(index, INVALID_INDEX);
      EXPECT_EQ(0, 1);
    }
  }
  catch(const exception& e) {
    //std::cout << "Test_CKKS_EvalAtIndex_INVALID_INDEX exception: " << e.what() << std::endl;
    EXPECT_EQ(1, 1);
  }
}
//================================================================================================
std::vector<std::complex<double>> CKKSEvalSumPackedArray(usint i,
                                                         TEST_ESTIMATED_RESULT testResult = SUCCESS) {
  using Element = DCRTPoly;
  uint32_t multDepth = 1;
  uint32_t scaleFactorBits = 50;
  uint32_t batchSize = 8;
  SecurityLevel securityLevel = HEStd_NotSet;
  usint ringDim = 16;
  CryptoContext<Element> cc = CryptoContextFactory<Element>::genCryptoContextCKKS(multDepth,
                                                                                  scaleFactorBits,
                                                                                  batchSize,
                                                                                  securityLevel,
                                                                                  ringDim);

  cc->Enable(ENCRYPTION);
  cc->Enable(SHE);

  // Initialize the public key containers.
  LPKeyPair<Element> kp = cc->KeyGen();

  std::vector<std::complex<double>> inputVec = vector8Complex;
  Plaintext intArray = cc->MakeCKKSPackedPlaintext(inputVec);

  if( NO_KEY_GEN_CALL != testResult )
  {
    if( INVALID_PRIVATE_KEY == testResult )
      cc->EvalSumKeyGen(nullptr);
    else
      cc->EvalSumKeyGen(kp.secretKey);
  }

  Ciphertext<Element> ciphertext = (INVALID_PUBLIC_KEY == testResult) ?
                                    cc->Encrypt(nullptr, intArray) : cc->Encrypt(kp.publicKey, intArray);

  uint32_t batchSz = (INVALID_BATCH_SIZE == testResult) ?  (batchSize*2) : batchSize;
  Ciphertext<Element> p1 = cc->EvalSum(ciphertext, batchSz);

  Plaintext intArrayNew;
  cc->Decrypt(kp.secretKey, p1, &intArrayNew);

  return intArrayNew->GetCKKSPackedValue();
}
//================================================================================================
TEST_F(UTAUTOMORPHISM, Test_CKKS_EvalSum) {
  PackedEncoding::Destroy();

  auto morphedVector = CKKSEvalSumPackedArray(0);
  EXPECT_TRUE(checkEquality(morphedVector[0], vector8ComplexSum));
}

TEST_F(UTAUTOMORPHISM, Test_CKKS_EvalSum_INVALID_PRIVATE_KEY) {
  PackedEncoding::Destroy();

  try {
    auto morphedVector = CKKSEvalSumPackedArray(0, INVALID_PRIVATE_KEY);
    EXPECT_EQ(0, 1);
  }
  catch(const exception& e) {
    //std::cout << "Test_CKKS_EvalSum_INVALID_PRIVATE_KEY exception: " << e.what() << std::endl;
    EXPECT_EQ(1, 1);
  }
}

TEST_F(UTAUTOMORPHISM, Test_CKKS_EvalSum_INVALID_PUBLIC_KEY) {
  PackedEncoding::Destroy();

  try {
    auto morphedVector = CKKSEvalSumPackedArray(0, INVALID_PUBLIC_KEY);
    EXPECT_EQ(0, 1);
  }
  catch(const exception& e) {
    //std::cout << "Test_CKKS_EvalSum_INVALID_PUBLIC_KEY exception: " << e.what() << std::endl;
    EXPECT_EQ(1, 1);
  }
}

TEST_F(UTAUTOMORPHISM, Test_CKKS_EvalSum_INVALID_BATCH_SIZE) {
  PackedEncoding::Destroy();

  try {
    auto morphedVector = CKKSEvalSumPackedArray(0, INVALID_BATCH_SIZE);
    EXPECT_EQ(0, 1);
  }
  catch(const exception& e) {
    //std::cout << "Test_CKKS_EvalSum_INVALID_BATCH_SIZE exception: " << e.what() << std::endl;
    EXPECT_EQ(1, 1);
  }
}

TEST_F(UTAUTOMORPHISM, Test_CKKS_EvalSum_NO_KEY_GEN_CALL) {
  PackedEncoding::Destroy();

  try {
    auto morphedVector = CKKSEvalSumPackedArray(0, NO_KEY_GEN_CALL);
    EXPECT_EQ(0, 1);
  }
  catch(const exception& e) {
    //std::cout << "Test_CKKS_EvalSum_NO_KEY_GEN_CALL exception: " << e.what() << std::endl;
    EXPECT_EQ(1, 1);
  }
}
//================================================================================================
std::vector<int64_t> BGVrnsEvalAtIndexPackedArray(usint i,
                                                  TEST_ESTIMATED_RESULT testResult = SUCCESS) {
  using Element = DCRTPoly;
  uint32_t depth = 1;
  int plaintextModulus = 65537;

  CryptoContext<Element> cc = CryptoContextFactory<Element>::genCryptoContextBGVrns(depth, plaintextModulus);

  cc->Enable(ENCRYPTION);
  cc->Enable(SHE);

  // Initialize the public key containers.
  LPKeyPair<Element> kp = cc->KeyGen();

  int index = i;
  std::vector<int64_t> inputVec = (INVALID_INPUT_DATA == testResult) ? vectorFailure : vector8;
  Plaintext intArray = cc->MakePackedPlaintext(inputVec);

  if( NO_KEY_GEN_CALL != testResult )
  {
    std::vector<int32_t> indices { index, -index };
    if( INVALID_PRIVATE_KEY == testResult )
      cc->EvalAtIndexKeyGen(nullptr, indices);
    else
      cc->EvalAtIndexKeyGen(kp.secretKey, indices);
  }

  Ciphertext<Element> ciphertext = (INVALID_PUBLIC_KEY == testResult) ?
                                    cc->Encrypt(nullptr, intArray) : cc->Encrypt(kp.publicKey, intArray);

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
TEST_F(UTAUTOMORPHISM, Test_BGVrns_EvalAtIndex) {
  PackedEncoding::Destroy();

  for (auto index : initIndexList) {
    auto morphedVector = BGVrnsEvalAtIndexPackedArray(index);
    EXPECT_TRUE(checkEquality(morphedVector, vector8));
  }
}

TEST_F(UTAUTOMORPHISM, Test_BGVrns_EvalAtIndex_CORNER_CASES) {
  PackedEncoding::Destroy();

  // Rotation with index at 0 should result in nothing happening and thus
  // The checkEquality should be true. Currently there is a bug in the code
  // however and this is not the case.
  static const std::vector<usint> cornerCaseIndexList {0};

  for (auto index : cornerCaseIndexList) {
    auto morphedVector = BGVrnsEvalAtIndexPackedArray(index);
    EXPECT_TRUE(checkEquality(morphedVector, vector8));
  }
}

TEST_F(UTAUTOMORPHISM, Test_BGVrns_EvalAtIndex_INVALID_INPUT_DATA) {
  PackedEncoding::Destroy();

  for (auto index : initIndexList) {
    auto morphedVector = BGVrnsEvalAtIndexPackedArray(index, INVALID_INPUT_DATA);
    EXPECT_FALSE(checkEquality(morphedVector, vector8));
  }
}

TEST_F(UTAUTOMORPHISM, Test_BGVrns_EvalAtIndex_INVALID_PRIVATE_KEY) {
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

TEST_F(UTAUTOMORPHISM, Test_BGVrns_EvalAtIndex_INVALID_PUBLIC_KEY) {
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

TEST_F(UTAUTOMORPHISM, Test_BGVrns_EvalAtIndex_NO_KEY_GEN_CALL) {
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
  uint32_t depth = 1;
  int plaintextModulus = 65537;

  CryptoContext<Element> cc = CryptoContextFactory<Element>::genCryptoContextBGVrns(depth, plaintextModulus);

  cc->Enable(ENCRYPTION);
  cc->Enable(SHE);

  // Initialize the public key containers.
  LPKeyPair<Element> kp = cc->KeyGen();

  std::vector<int64_t> inputVec = vector8;
  Plaintext intArray = cc->MakePackedPlaintext(inputVec);

  if( NO_KEY_GEN_CALL != testResult )
  {
    if( INVALID_PRIVATE_KEY == testResult )
      cc->EvalSumKeyGen(nullptr);
    else
      cc->EvalSumKeyGen(kp.secretKey);
  }

  Ciphertext<Element> ciphertext = (INVALID_PUBLIC_KEY == testResult) ?
                                    cc->Encrypt(nullptr, intArray) : cc->Encrypt(kp.publicKey, intArray);

  uint32_t batchSize = 8;
  uint32_t batchSz = (INVALID_BATCH_SIZE == testResult) ?  (batchSize*1000) : batchSize;
  Ciphertext<Element> p1 = cc->EvalSum(ciphertext, batchSz);

  Plaintext intArrayNew;
  cc->Decrypt(kp.secretKey, p1, &intArrayNew);

  return intArrayNew->GetPackedValue();
}
//================================================================================================
TEST_F(UTAUTOMORPHISM, Test_BGVrns_EvalSum) {
  PackedEncoding::Destroy();

  auto morphedVector = BGVrnsEvalSumPackedArray(0);
  EXPECT_TRUE(checkEquality(morphedVector[0], vector8Sum));
}

TEST_F(UTAUTOMORPHISM, Test_BGVrns_EvalSum_INVALID_PRIVATE_KEY) {
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

TEST_F(UTAUTOMORPHISM, Test_BGVrns_EvalSum_INVALID_PUBLIC_KEY) {
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

TEST_F(UTAUTOMORPHISM, Test_BGVrns_EvalSum_INVALID_BATCH_SIZE) {
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

TEST_F(UTAUTOMORPHISM, Test_BGVrns_EvalSum_NO_KEY_GEN_CALL) {
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
