// @file
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

#include <iostream>
#include <list>
#include <vector>
#include "gtest/gtest.h"

#include "cryptocontextgen.h"
#include "cryptocontexthelper.h"
#include "palisade.h"
#include "utils/testcasegen.h"

using namespace std;
using namespace lbcrypto;

class UTSHE : public ::testing::Test {
 public:
  const usint m = 32;
  UTSHE() {}
  ~UTSHE() {}

 protected:
  void SetUp() {}

  void TearDown() {
    CryptoContextFactory<Poly>::ReleaseAllContexts();
    CryptoContextFactory<DCRTPoly>::ReleaseAllContexts();
  }
};

// This file unit tests the SHE capabilities for all schemes, using all known
// elements

// TODO NativePoly SHE tests no bueno on Mult
// GENERATE_PKE_TEST_CASE(x, y, NativePoly, BFV_rlwe, ORD, PTM)
// GENERATE_PKE_TEST_CASE(x, y, NativePoly, BFV_opt, ORD, PTM)

#define GENERATE_TEST_CASES_FUNC(x, y, ORD, PTM)                   \
  GENERATE_PKE_TEST_CASE(x, y, Poly, Null, ORD, PTM)               \
  GENERATE_PKE_TEST_CASE(x, y, Poly, BGVrns_rlwe, ORD, PTM)        \
  GENERATE_PKE_TEST_CASE(x, y, Poly, BGVrns_opt, ORD, PTM)         \
  GENERATE_PKE_TEST_CASE(x, y, Poly, BFV_rlwe, ORD, PTM)           \
  GENERATE_PKE_TEST_CASE(x, y, Poly, BFVrns_rlwe, ORD, PTM)        \
  GENERATE_PKE_TEST_CASE(x, y, Poly, BFVrns_opt, ORD, PTM)         \
  GENERATE_PKE_TEST_CASE(x, y, Poly, BFVrnsB_rlwe, ORD, PTM)       \
  GENERATE_PKE_TEST_CASE(x, y, Poly, BFVrnsB_opt, ORD, PTM)        \
  GENERATE_PKE_TEST_CASE(x, y, NativePoly, Null, ORD, PTM)         \
  GENERATE_PKE_TEST_CASE(x, y, NativePoly, BGVrns_rlwe, ORD, PTM)  \
  GENERATE_PKE_TEST_CASE(x, y, NativePoly, BGVrns_opt, ORD, PTM)   \
  GENERATE_PKE_TEST_CASE(x, y, NativePoly, BFVrns_rlwe, ORD, PTM)  \
  GENERATE_PKE_TEST_CASE(x, y, NativePoly, BFVrns_opt, ORD, PTM)   \
  GENERATE_PKE_TEST_CASE(x, y, NativePoly, BFVrnsB_rlwe, ORD, PTM) \
  GENERATE_PKE_TEST_CASE(x, y, NativePoly, BFVrnsB_opt, ORD, PTM)  \
  GENERATE_PKE_TEST_CASE(x, y, DCRTPoly, Null, ORD, PTM)           \
  GENERATE_PKE_TEST_CASE(x, y, DCRTPoly, BGVrns_rlwe, ORD, PTM)    \
  GENERATE_PKE_TEST_CASE(x, y, DCRTPoly, BGVrns_opt, ORD, PTM)     \
  GENERATE_PKE_TEST_CASE(x, y, DCRTPoly, BFVrns_rlwe, ORD, PTM)    \
  GENERATE_PKE_TEST_CASE(x, y, DCRTPoly, BFVrns_opt, ORD, PTM)     \
  GENERATE_PKE_TEST_CASE(x, y, DCRTPoly, BFVrnsB_rlwe, ORD, PTM)   \
  GENERATE_PKE_TEST_CASE(x, y, DCRTPoly, BFVrnsB_opt, ORD, PTM)    \
  GENERATE_PKE_TEST_CASE(x, y, Poly, BFV_opt, ORD, PTM)

// For EvalAtIndex
#define GENERATE_TEST_CASES_FUNC_EVALATINDEX(x, y, ORD, PTM)       \
  GENERATE_PKE_TEST_CASE(x, y, Poly, Null, ORD, PTM)               \
  GENERATE_PKE_TEST_CASE(x, y, Poly, BGVrns_rlwe, ORD, PTM)        \
  GENERATE_PKE_TEST_CASE(x, y, Poly, BGVrns_opt, ORD, PTM)         \
  GENERATE_PKE_TEST_CASE(x, y, Poly, BFV_rlwe, ORD, PTM)           \
  GENERATE_PKE_TEST_CASE(x, y, Poly, BFVrns_rlwe, ORD, PTM)        \
  GENERATE_PKE_TEST_CASE(x, y, Poly, BFVrns_opt, ORD, PTM)         \
  GENERATE_PKE_TEST_CASE(x, y, Poly, BFVrnsB_rlwe, ORD, PTM)       \
  GENERATE_PKE_TEST_CASE(x, y, Poly, BFVrnsB_opt, ORD, PTM)        \
  GENERATE_PKE_TEST_CASE(x, y, NativePoly, Null, ORD, PTM)         \
  GENERATE_PKE_TEST_CASE(x, y, NativePoly, BGVrns_rlwe, ORD, PTM)  \
  GENERATE_PKE_TEST_CASE(x, y, NativePoly, BGVrns_opt, ORD, PTM)   \
  GENERATE_PKE_TEST_CASE(x, y, NativePoly, BFVrns_rlwe, ORD, PTM)  \
  GENERATE_PKE_TEST_CASE(x, y, NativePoly, BFVrns_opt, ORD, PTM)   \
  GENERATE_PKE_TEST_CASE(x, y, NativePoly, BFVrnsB_rlwe, ORD, PTM) \
  GENERATE_PKE_TEST_CASE(x, y, NativePoly, BFVrnsB_opt, ORD, PTM)  \
  GENERATE_PKE_TEST_CASE(x, y, DCRTPoly, Null, ORD, PTM)           \
  GENERATE_PKE_TEST_CASE(x, y, DCRTPoly, BGVrns_rlwe, ORD, PTM)    \
  GENERATE_PKE_TEST_CASE(x, y, DCRTPoly, BGVrns_opt, ORD, PTM)     \
  GENERATE_PKE_TEST_CASE(x, y, DCRTPoly, BFVrns_rlwe, ORD, PTM)    \
  GENERATE_PKE_TEST_CASE(x, y, DCRTPoly, BFVrns_opt, ORD, PTM)     \
  GENERATE_PKE_TEST_CASE(x, y, DCRTPoly, BFVrnsB_rlwe, ORD, PTM)   \
  GENERATE_PKE_TEST_CASE(x, y, DCRTPoly, BFVrnsB_opt, ORD, PTM)    \
  GENERATE_PKE_TEST_CASE(x, y, Poly, BFV_opt, ORD, PTM)

// For EvalSum
#define GENERATE_TEST_CASES_FUNC_EVALSUM(x, y, ORD, PTM)         \
  GENERATE_PKE_TEST_CASE(x, y, DCRTPoly, BFVrns_rlwe, ORD, PTM)  \
  GENERATE_PKE_TEST_CASE(x, y, DCRTPoly, BFVrns_opt, ORD, PTM)   \
  GENERATE_PKE_TEST_CASE(x, y, DCRTPoly, BFVrnsB_rlwe, ORD, PTM) \
  GENERATE_PKE_TEST_CASE(x, y, DCRTPoly, BFVrnsB_opt, ORD, PTM)

// For metadata
#define GENERATE_TEST_CASES_FUNC_METADATA(x, y, ORD, PTM)        \
  GENERATE_PKE_TEST_CASE(x, y, DCRTPoly, BFVrns_rlwe, ORD, PTM)  \
  GENERATE_PKE_TEST_CASE(x, y, DCRTPoly, BFVrns_opt, ORD, PTM)   \
  GENERATE_PKE_TEST_CASE(x, y, DCRTPoly, BFVrnsB_rlwe, ORD, PTM) \
  GENERATE_PKE_TEST_CASE(x, y, DCRTPoly, BFVrnsB_opt, ORD, PTM)  \
  GENERATE_PKE_TEST_CASE(x, y, DCRTPoly, BGVrns_rlwe, ORD, PTM)  \
  GENERATE_PKE_TEST_CASE(x, y, DCRTPoly, BGVrns_opt, ORD, PTM)

static vector<string> AllSchemes({"Null", "BFV", /*"BFVrns"*/});
typedef ::testing::Types<Poly, DCRTPoly, NativePoly> EncryptElementTypes;

// NOTE the SHE tests are all based on these
static const usint ORDER = 32;
static const usint PTMOD = 64;

template <class Element>
static void UnitTest_Add_Packed(const CryptoContext<Element> cc,
                                const string& failmsg) {
  std::vector<int64_t> vectorOfInts1 = {1, 0, 3, 1, 0, 1, 2, 1};
  Plaintext plaintext1 = cc->MakeCoefPackedPlaintext(vectorOfInts1);

  std::vector<int64_t> vectorOfInts2 = {2, 1, 3, 2, 2, 1, 3, 0};
  Plaintext plaintext2 = cc->MakeCoefPackedPlaintext(vectorOfInts2);

  std::vector<int64_t> vectorOfIntsAdd = {3, 1, 6, 3, 2, 2, 5, 1};
  Plaintext plaintextAdd = cc->MakeCoefPackedPlaintext(vectorOfIntsAdd);

  std::vector<int64_t> vectorOfIntsSub = {-1, -1, 0, -1, -2, 0, -1, 1};
  Plaintext plaintextSub = cc->MakeCoefPackedPlaintext(vectorOfIntsSub);

  LPKeyPair<Element> kp = cc->KeyGen();
  Ciphertext<Element> ciphertext1 = cc->Encrypt(kp.publicKey, plaintext1);
  Ciphertext<Element> ciphertext2 = cc->Encrypt(kp.publicKey, plaintext2);

  Ciphertext<Element> cResult;
  Plaintext results;

  cResult = cc->EvalAdd(ciphertext1, ciphertext2);
  cc->Decrypt(kp.secretKey, cResult, &results);
  results->SetLength(plaintextAdd->GetLength());
  EXPECT_EQ(plaintextAdd->GetCoefPackedValue(), results->GetCoefPackedValue())
      << failmsg << " EvalAdd fails";

  auto ct1_clone = ciphertext1->Clone();
  cc->EvalAddInPlace(ct1_clone, ciphertext2);
  cc->Decrypt(kp.secretKey, ct1_clone, &results);
  results->SetLength(plaintextAdd->GetLength());
  EXPECT_EQ(plaintextAdd->GetCoefPackedValue(), results->GetCoefPackedValue())
      << failmsg << " EvalAddInPlace fails";

  cResult = ciphertext1 + ciphertext2;
  cc->Decrypt(kp.secretKey, cResult, &results);
  results->SetLength(plaintextAdd->GetLength());
  EXPECT_EQ(plaintextAdd->GetCoefPackedValue(), results->GetCoefPackedValue())
      << failmsg << " operator+ fails";

  Ciphertext<Element> caddInplace = ciphertext1->Clone();
  caddInplace += ciphertext2;
  cc->Decrypt(kp.secretKey, caddInplace, &results);
  results->SetLength(plaintextAdd->GetLength());
  EXPECT_EQ(plaintextAdd->GetCoefPackedValue(), results->GetCoefPackedValue())
      << failmsg << " operator+= fails";

  cResult = cc->EvalSub(ciphertext1, ciphertext2);
  cc->Decrypt(kp.secretKey, cResult, &results);
  results->SetLength(plaintextSub->GetLength());
  EXPECT_EQ(plaintextSub->GetCoefPackedValue(), results->GetCoefPackedValue())
      << failmsg << " EvalSub fails";

  cResult = ciphertext1 - ciphertext2;
  cc->Decrypt(kp.secretKey, cResult, &results);
  results->SetLength(plaintextSub->GetLength());
  EXPECT_EQ(plaintextSub->GetCoefPackedValue(), results->GetCoefPackedValue())
      << failmsg << " operator- fails";

  Ciphertext<Element> csubInplace = ciphertext1->Clone();
  csubInplace -= ciphertext2;
  cc->Decrypt(kp.secretKey, csubInplace, &results);
  results->SetLength(plaintextSub->GetLength());
  EXPECT_EQ(plaintextSub->GetCoefPackedValue(), results->GetCoefPackedValue())
      << failmsg << " operator-= fails";

  cResult = cc->EvalAdd(ciphertext1, plaintext2);
  cc->Decrypt(kp.secretKey, cResult, &results);
  results->SetLength(plaintextAdd->GetLength());
  EXPECT_EQ(plaintextAdd->GetCoefPackedValue(), results->GetCoefPackedValue())
      << failmsg << " EvalAdd Ct and Pt fails";

  cResult = cc->EvalSub(ciphertext1, plaintext2);
  cc->Decrypt(kp.secretKey, cResult, &results);
  results->SetLength(plaintextSub->GetLength());
  EXPECT_EQ(plaintextSub->GetCoefPackedValue(), results->GetCoefPackedValue())
      << failmsg << " EvalSub Ct and Pt fails";
}

GENERATE_TEST_CASES_FUNC(UTSHE, UnitTest_Add_Packed, ORDER, PTMOD)

template <class Element>
static void UnitTest_Mult_CoefPacked(const CryptoContext<Element> cc,
                                     const string& failmsg) {
  std::vector<int64_t> vectorOfInts1 = {1, 0, 3, 1, 0, 1, 2, 1};
  Plaintext plaintext1 = cc->MakeCoefPackedPlaintext(vectorOfInts1);

  std::vector<int64_t> vectorOfInts2 = {2, 1, 3, 2, 2, 1, 3, 0};
  Plaintext plaintext2 = cc->MakeCoefPackedPlaintext(vectorOfInts2);

  // For cyclotomic order != 16, the expected result is the convolution of
  // vectorOfInt21 and vectorOfInts2
  std::vector<int64_t> vectorOfIntsMultLong = {2,  1,  9,  7, 12, 12, 16,
                                               12, 19, 12, 7, 7,  7,  3};
  std::vector<int64_t> vectorOfIntsMult = {-17, -11, 2, 0, 5, 9, 16, 12};

  Plaintext intArray1 = cc->MakeCoefPackedPlaintext(vectorOfInts1);

  Plaintext intArray2 = cc->MakeCoefPackedPlaintext(vectorOfInts2);

  Plaintext intArrayExpected = cc->MakeCoefPackedPlaintext(
      cc->GetCyclotomicOrder() == 16 ? vectorOfIntsMult : vectorOfIntsMultLong);

  // Initialize the public key containers.
  LPKeyPair<Element> kp = cc->KeyGen();

  Ciphertext<Element> ciphertext1 = cc->Encrypt(kp.publicKey, intArray1);

  Ciphertext<Element> ciphertext2 = cc->Encrypt(kp.publicKey, intArray2);

  cc->EvalMultKeyGen(kp.secretKey);

  Ciphertext<Element> cResult;
  Plaintext results;

  cResult = cc->EvalMult(ciphertext1, ciphertext2);
  cc->Decrypt(kp.secretKey, cResult, &results);
  results->SetLength(intArrayExpected->GetLength());
  EXPECT_EQ(intArrayExpected->GetCoefPackedValue(),
            results->GetCoefPackedValue())
      << failmsg << " EvalMult fails";

  cResult = ciphertext1 * ciphertext2;
  cc->Decrypt(kp.secretKey, cResult, &results);
  results->SetLength(intArrayExpected->GetLength());
  EXPECT_EQ(intArrayExpected->GetCoefPackedValue(),
            results->GetCoefPackedValue())
      << failmsg << " operator* fails";

  Ciphertext<Element> cmulInplace = ciphertext1->Clone();
  cmulInplace *= ciphertext2;
  cc->Decrypt(kp.secretKey, cmulInplace, &results);
  results->SetLength(intArrayExpected->GetLength());
  EXPECT_EQ(intArrayExpected->GetCoefPackedValue(),
            results->GetCoefPackedValue())
      << failmsg << " operator*= fails";

  cResult = cc->EvalMult(ciphertext1, plaintext2);
  cc->Decrypt(kp.secretKey, cResult, &results);
  results->SetLength(intArrayExpected->GetLength());
  EXPECT_EQ(intArrayExpected->GetCoefPackedValue(),
            results->GetCoefPackedValue())
      << failmsg << " EvalMult Ct and Pt fails";
}

GENERATE_TEST_CASES_FUNC(UTSHE, UnitTest_Mult_CoefPacked, ORDER, PTMOD)

template <class Element>
static void UnitTest_Mult_Packed(const CryptoContext<Element> cc,
                                 const string& failmsg) {
  std::vector<int64_t> vectorOfInts1 = {1, 0, 3, 1, 0, 1, 2, 1};
  Plaintext plaintext1 = cc->MakePackedPlaintext(vectorOfInts1);

  std::vector<int64_t> vectorOfInts2 = {2, 1, 3, 2, 2, 1, 3, 1};
  Plaintext plaintext2 = cc->MakePackedPlaintext(vectorOfInts2);

  // For cyclotomic order != 16, the expected result is the convolution of
  // vectorOfInt21 and vectorOfInts2
  std::vector<int64_t> vectorOfIntsMult = {2, 0, 9, 2, 0, 1, 6, 1};

  Plaintext intArray1 = cc->MakePackedPlaintext(vectorOfInts1);

  Plaintext intArray2 = cc->MakePackedPlaintext(vectorOfInts2);

  Plaintext intArrayExpected = cc->MakePackedPlaintext(vectorOfIntsMult);

  // Initialize the public key containers.
  LPKeyPair<Element> kp = cc->KeyGen();

  Ciphertext<Element> ciphertext1 = cc->Encrypt(kp.publicKey, intArray1);

  Ciphertext<Element> ciphertext2 = cc->Encrypt(kp.publicKey, intArray2);

  cc->EvalMultKeyGen(kp.secretKey);

  Ciphertext<Element> cResult;
  Plaintext results;

  cResult = cc->EvalMult(ciphertext1, ciphertext2);
  cc->Decrypt(kp.secretKey, cResult, &results);
  results->SetLength(intArrayExpected->GetLength());
  EXPECT_EQ(intArrayExpected->GetPackedValue(), results->GetPackedValue())
      << failmsg << " EvalMult fails";

  cResult = ciphertext1 * ciphertext2;
  cc->Decrypt(kp.secretKey, cResult, &results);
  results->SetLength(intArrayExpected->GetLength());
  EXPECT_EQ(intArrayExpected->GetPackedValue(), results->GetPackedValue())
      << failmsg << " operator* fails";

  Ciphertext<Element> cmulInplace = ciphertext1->Clone();
  cmulInplace *= ciphertext2;
  cc->Decrypt(kp.secretKey, cmulInplace, &results);
  results->SetLength(intArrayExpected->GetLength());
  EXPECT_EQ(intArrayExpected->GetPackedValue(), results->GetPackedValue())
      << failmsg << " operator*= fails";

  cResult = cc->EvalMult(ciphertext1, plaintext2);
  cc->Decrypt(kp.secretKey, cResult, &results);
  results->SetLength(intArrayExpected->GetLength());
  EXPECT_EQ(intArrayExpected->GetPackedValue(), results->GetPackedValue())
      << failmsg << " EvalMult Ct and Pt fails";
}

GENERATE_TEST_CASES_FUNC_EVALATINDEX(UTSHE, UnitTest_Mult_Packed, 512, 65537)

template <class Element>
static void UnitTest_EvalAtIndex(const CryptoContext<Element> cc,
                                 const string& failmsg) {
  std::vector<int64_t> vectorOfInts1 = {1, 2,  3,  4,  5,  6,  7,  8,
                                        9, 10, 11, 12, 13, 14, 15, 16};
  Plaintext plaintext1 = cc->MakePackedPlaintext(vectorOfInts1);

  // Expected results after evaluating EvalAtIndex(3) and EvalAtIndex(-3)
  std::vector<int64_t> vectorOfIntsPlus3 = {4,  5,  6,  7,  8,  9, 10, 11,
                                            12, 13, 14, 15, 16, 0, 0,  0};
  std::vector<int64_t> vectorOfIntsMinus3 = {0, 0, 0, 1, 2,  3,  4,  5,
                                             6, 7, 8, 9, 10, 11, 12, 13};

  Plaintext intArray1 = cc->MakePackedPlaintext(vectorOfInts1);

  Plaintext intArrayPlus3 = cc->MakePackedPlaintext(vectorOfIntsPlus3);
  Plaintext intArrayMinus3 = cc->MakePackedPlaintext(vectorOfIntsMinus3);

  // Initialize the public key containers.
  LPKeyPair<Element> kp = cc->KeyGen();

  Ciphertext<Element> ciphertext1 = cc->Encrypt(kp.publicKey, intArray1);

  cc->EvalAtIndexKeyGen(kp.secretKey, {3, -3});

  Ciphertext<Element> cResult1 = cc->EvalAtIndex(ciphertext1, 3);

  Ciphertext<Element> cResult2 = cc->EvalAtIndex(ciphertext1, -3);

  Plaintext results1;

  Plaintext results2;

  cc->Decrypt(kp.secretKey, cResult1, &results1);

  cc->Decrypt(kp.secretKey, cResult2, &results2);

  results1->SetLength(intArrayPlus3->GetLength());
  EXPECT_EQ(intArrayPlus3->GetPackedValue(), results1->GetPackedValue())
      << failmsg << " EvalAtIndex(3) fails";

  results2->SetLength(intArrayMinus3->GetLength());
  EXPECT_EQ(intArrayMinus3->GetPackedValue(), results2->GetPackedValue())
      << failmsg << " EvalAtIndex(-3) fails";
}

GENERATE_TEST_CASES_FUNC_EVALATINDEX(UTSHE, UnitTest_EvalAtIndex, 512, 65537)

template <class Element>
static void UnitTest_EvalMerge(const CryptoContext<Element> cc,
                               const string& failmsg) {
  // Initialize the public key containers.
  LPKeyPair<Element> kp = cc->KeyGen();

  std::vector<Ciphertext<Element>> ciphertexts;

  std::vector<int64_t> vectorOfInts1 = {32, 0, 0, 0, 0, 0, 0, 0, 0, 0};
  Plaintext intArray1 = cc->MakePackedPlaintext(vectorOfInts1);
  ciphertexts.push_back(cc->Encrypt(kp.publicKey, intArray1));

  std::vector<int64_t> vectorOfInts2 = {2, 0, 0, 0, 0, 0, 0, 0, 0, 0};
  Plaintext intArray2 = cc->MakePackedPlaintext(vectorOfInts2);
  ciphertexts.push_back(cc->Encrypt(kp.publicKey, intArray2));

  std::vector<int64_t> vectorOfInts3 = {4, 0, 0, 0, 0, 0, 0, 0, 0, 0};
  Plaintext intArray3 = cc->MakePackedPlaintext(vectorOfInts3);
  ciphertexts.push_back(cc->Encrypt(kp.publicKey, intArray3));

  std::vector<int64_t> vectorOfInts4 = {8, 0, 0, 0, 0, 0, 0, 0, 0, 0};
  Plaintext intArray4 = cc->MakePackedPlaintext(vectorOfInts4);
  ciphertexts.push_back(cc->Encrypt(kp.publicKey, intArray4));

  std::vector<int64_t> vectorOfInts5 = {16, 0, 0, 0, 0, 0, 0, 0, 0, 0};
  Plaintext intArray5 = cc->MakePackedPlaintext(vectorOfInts5);
  ciphertexts.push_back(cc->Encrypt(kp.publicKey, intArray5));

  // Expected results after evaluating EvalAtIndex(3) and EvalAtIndex(-3)
  std::vector<int64_t> vectorMerged = {32, 2, 4, 8, 16, 0, 0, 0};
  Plaintext intArrayMerged = cc->MakePackedPlaintext(vectorMerged);

  vector<int32_t> indexList = {-1, -2, -3, -4, -5};

  cc->EvalAtIndexKeyGen(kp.secretKey, indexList);

  auto mergedCiphertext = cc->EvalMerge(ciphertexts);

  Plaintext results1;

  cc->Decrypt(kp.secretKey, mergedCiphertext, &results1);

  results1->SetLength(intArrayMerged->GetLength());
  EXPECT_EQ(intArrayMerged->GetPackedValue(), results1->GetPackedValue())
      << failmsg << " EvalMerge fails";
}

GENERATE_TEST_CASES_FUNC_EVALATINDEX(UTSHE, UnitTest_EvalMerge, 512, 65537)

template <class Element>
static void UnitTest_EvalSum(const CryptoContext<Element> cc,
                             const string& failmsg) {
  // Initialize the public key containers.
  LPKeyPair<Element> kp = cc->KeyGen();

  std::vector<Ciphertext<Element>> ciphertexts;

  uint32_t n = cc->GetRingDimension();

  std::vector<int64_t> vectorOfInts1 = {1, 2, 3, 4, 5, 6, 7, 8};
  uint32_t dim = vectorOfInts1.size();
  vectorOfInts1.resize(n);
  for (uint32_t i = dim; i < n; i++) vectorOfInts1[i] = vectorOfInts1[i % dim];
  Plaintext intArray1 = cc->MakePackedPlaintext(vectorOfInts1);
  auto ct1 = cc->Encrypt(kp.publicKey, intArray1);

  cc->EvalSumKeyGen(kp.secretKey);

  auto ctsum1 = cc->EvalSum(ct1, 1);
  auto ctsum2 = cc->EvalSum(ct1, 2);
  auto ctsum3 = cc->EvalSum(ct1, 8);

  std::vector<int64_t> vectorOfInts2 = {3, 5, 7, 9, 11, 13, 15, 9};
  vectorOfInts2.resize(n);
  for (uint32_t i = dim; i < n; i++) vectorOfInts2[i] = vectorOfInts2[i % dim];
  Plaintext intArray2 = cc->MakePackedPlaintext(vectorOfInts2);

  std::vector<int64_t> vectorOfIntsAll = {36, 36, 36, 36, 36, 36, 36, 36};
  vectorOfIntsAll.resize(n);
  for (uint32_t i = dim; i < n; i++)
    vectorOfIntsAll[i] = vectorOfIntsAll[i % dim];
  Plaintext intArrayAll = cc->MakePackedPlaintext(vectorOfIntsAll);

  Plaintext results1;
  cc->Decrypt(kp.secretKey, ctsum1, &results1);
  Plaintext results2;
  cc->Decrypt(kp.secretKey, ctsum2, &results2);
  Plaintext results3;
  cc->Decrypt(kp.secretKey, ctsum3, &results3);

  intArray1->SetLength(dim);
  intArray2->SetLength(dim);
  intArrayAll->SetLength(dim);
  results1->SetLength(dim);
  results2->SetLength(dim);
  results3->SetLength(dim);

  EXPECT_EQ(intArray1->GetPackedValue(), results1->GetPackedValue())
      << failmsg << " EvalSum for batch size = 1 failed";
  EXPECT_EQ(intArray2->GetPackedValue(), results2->GetPackedValue())
      << failmsg << " EvalSum for batch size = 2 failed";
  EXPECT_EQ(intArrayAll->GetPackedValue(), results3->GetPackedValue())
      << failmsg << " EvalSum for batch size = 8 failed";
}

GENERATE_TEST_CASES_FUNC_EVALSUM(UTSHE, UnitTest_EvalSum, 512, 65537)

/**
 * Tests whether metadata is carried over for several operations
 */
template <typename Element>
static void UnitTest_Metadata(const CryptoContext<Element> cc,
                              const string& failmsg) {
  int vecSize = 8;

  // input 1 = { 0,1,2,3,4,5,6,7 };
  // input 2 = { 0,-1,-2,-3,-4,-5,-6,-7 };
  std::vector<int64_t> input1(vecSize);
  std::vector<int64_t> input2(vecSize);
  for (int i = 0; i < vecSize; i++) {
    input1[i] = i;
    input2[i] = -i;
  }
  Plaintext plaintext1 = cc->MakePackedPlaintext(input1);
  Plaintext plaintext2 = cc->MakePackedPlaintext(input2);

  // Generate encryption keys
  LPKeyPair<Element> kp = cc->KeyGen();
  // Generate multiplication keys
  cc->EvalMultKeyGen(kp.secretKey);
  // Generate rotation keys for offsets +2 (left rotate) and -2 (right rotate)
  cc->EvalAtIndexKeyGen(kp.secretKey, {2, -2});
  // Generate keys for EvalSum
  cc->EvalSumKeyGen(kp.secretKey);

  // Encrypt plaintexts
  Ciphertext<Element> ciphertext1 = cc->Encrypt(kp.publicKey, plaintext1);
  Ciphertext<Element> ciphertext2 = cc->Encrypt(kp.publicKey, plaintext2);
  Plaintext results;

  // Populating metadata map in ciphertexts
  auto val1 = make_shared<MetadataTest>();
  val1->SetMetadata("ciphertext1");
  MetadataTest::StoreMetadata<Element>(ciphertext1, val1);
  auto val2 = make_shared<MetadataTest>();
  val2->SetMetadata("ciphertext2");
  MetadataTest::StoreMetadata<Element>(ciphertext2, val2);

  // Checking if metadata is carried over in EvalAdd(ctx,ctx)
  Ciphertext<Element> cAddCC = cc->EvalAdd(ciphertext1, ciphertext2);
  auto addCCValTest = MetadataTest::GetMetadata<Element>(cAddCC);
  EXPECT_EQ(val1->GetMetadata(), addCCValTest->GetMetadata())
      << "Ciphertext metadata mismatch in EvalAdd(ctx,ctx)";

  // Checking if metadata is carried over in EvalAddInPlace(ctx,ctx)
  Ciphertext<Element> ciphertext1_clone = ciphertext1->Clone();
  cc->EvalAddInPlace(ciphertext1_clone, ciphertext2);
  auto addCCInPlaceValTest = MetadataTest::GetMetadata<Element>(ciphertext1_clone);
  EXPECT_EQ(val1->GetMetadata(), addCCInPlaceValTest->GetMetadata())
      << "Ciphertext metadata mismatch in EvalAddInPlace(ctx,ctx)";

  // Checking if metadata is carried over in EvalAdd(ctx,ptx)
  Ciphertext<Element> cAddCP = cc->EvalAdd(ciphertext1, plaintext1);
  auto addCPValTest = MetadataTest::GetMetadata<Element>(cAddCP);
  EXPECT_EQ(val1->GetMetadata(), addCPValTest->GetMetadata())
      << "Ciphertext metadata mismatch in EvalAdd(ctx,ptx)";

  // Checking if metadata is carried over in EvalSub(ctx,ctx)
  Ciphertext<Element> cSubCC = cc->EvalSub(ciphertext1, ciphertext2);
  auto subCCValTest = MetadataTest::GetMetadata<Element>(cSubCC);
  EXPECT_EQ(val1->GetMetadata(), subCCValTest->GetMetadata())
      << "Ciphertext metadata mismatch in EvalSub(ctx,ctx)";

  // Checking if metadata is carried over in EvalSub(ctx,ptx)
  Ciphertext<Element> cSubCP = cc->EvalSub(ciphertext1, plaintext1);
  auto subCPValTest = MetadataTest::GetMetadata<Element>(cSubCP);
  EXPECT_EQ(val1->GetMetadata(), subCPValTest->GetMetadata())
      << "Ciphertext metadata mismatch in EvalSub(ctx,ptx)";

  // Checking if metadata is carried over in EvalMult(ctx,ctx)
  Ciphertext<Element> cMultCC = cc->EvalMult(ciphertext1, ciphertext2);
  auto multCCValTest = MetadataTest::GetMetadata<Element>(cMultCC);
  EXPECT_EQ(val1->GetMetadata(), multCCValTest->GetMetadata())
      << "Ciphertext metadata mismatch in EvalMult(ctx,ctx)";

  // Checking if metadata is carried over in EvalMult(ctx,ptx)
  Ciphertext<Element> cMultCP = cc->EvalMult(ciphertext1, plaintext1);
  auto multCPValTest = MetadataTest::GetMetadata<Element>(cMultCP);
  EXPECT_EQ(val1->GetMetadata(), multCPValTest->GetMetadata())
      << "Ciphertext metadata mismatch in EvalMult(ctx,ptx)";

  // Checking if metadata is carried over in EvalAtIndex +2 (left rotate)
  auto cAtIndex2 = cc->EvalAtIndex(ciphertext1, 2);
  auto atIndex2ValTest = MetadataTest::GetMetadata<Element>(cAtIndex2);
  EXPECT_EQ(val1->GetMetadata(), atIndex2ValTest->GetMetadata())
      << "Ciphertext metadata mismatch in EvalAtIndex +2";

  // Checking if metadata is carried over in EvalAtIndex -2 (right rotate)
  auto cAtIndexMinus2 = cc->EvalAtIndex(ciphertext1, -2);
  auto atIndexMinus2ValTest =
      MetadataTest::GetMetadata<Element>(cAtIndexMinus2);
  EXPECT_EQ(val1->GetMetadata(), atIndexMinus2ValTest->GetMetadata())
      << "Ciphertext metadata mismatch in EvalAtIndex -2";

  vector<double> weights(2);
  for (int i = 0; i < 2; i++) weights[i] = i;

  vector<Ciphertext<Element>> ciphertexts(2);
  ciphertexts[0] = ciphertext1;
  ciphertexts[1] = ciphertext2;
}

GENERATE_TEST_CASES_FUNC_METADATA(UTSHE, UnitTest_Metadata, 512, 65537)

TEST_F(UTSHE, UnitTest_EvalSum_BFVrns_All) {
  uint32_t batchSize = 1 << 12;

  EncodingParams encodingParams(std::make_shared<EncodingParamsImpl>(65537));
  encodingParams->SetBatchSize(batchSize);
  CryptoContext<DCRTPoly> cc =
      CryptoContextFactory<DCRTPoly>::genCryptoContextBFVrns(
          encodingParams, HEStd_128_classic, 3.2, 0, 2, 0, OPTIMIZED, 2, 20, 60,
          batchSize);
  cc->Enable(ENCRYPTION);
  cc->Enable(SHE);

  // Initialize the public key containers.
  LPKeyPair<DCRTPoly> kp = cc->KeyGen();

  std::vector<Ciphertext<DCRTPoly>> ciphertexts;

  uint32_t n = cc->GetRingDimension();

  std::vector<int64_t> vectorOfInts1 = {1, 2, 3, 4, 5, 6, 7, 8};
  uint32_t dim = vectorOfInts1.size();
  vectorOfInts1.resize(n);
  for (uint32_t i = n - dim; i < n; i++) vectorOfInts1[i] = i;

  Plaintext intArray1 = cc->MakePackedPlaintext(vectorOfInts1);

  std::vector<int64_t> vectorOfIntsAll = {32768, 32768, 32768, 32768,
                                          32768, 32768, 32768, 32768};
  Plaintext intArrayAll = cc->MakePackedPlaintext(vectorOfIntsAll);

  auto ct1 = cc->Encrypt(kp.publicKey, intArray1);

  cc->EvalSumKeyGen(kp.secretKey);

  auto ctsum1 = cc->EvalSum(ct1, batchSize);

  Plaintext results1;
  cc->Decrypt(kp.secretKey, ctsum1, &results1);

  intArrayAll->SetLength(dim);
  results1->SetLength(dim);

  EXPECT_EQ(intArrayAll->GetPackedValue(), results1->GetPackedValue())
      << " BFVrns EvalSum for batch size = All failed";
}

TEST_F(UTSHE, keyswitch_SingleCRT) {
  usint m = 512;

  float stdDev = 4;

  shared_ptr<DCRTPoly::Params> params =
      ElemParamFactory::GenElemParams<DCRTPoly::Params>(m, 50);

  CryptoContext<DCRTPoly> cc =
      CryptoContextFactory<DCRTPoly>::genCryptoContextBGVrns(params, 256, 1, stdDev);
  cc->Enable(ENCRYPTION);
  cc->Enable(SHE);

  Plaintext plaintext =
      cc->MakeStringPlaintext("I am good, what are you?! 32 ch");

  LPKeyPair<DCRTPoly> kp = cc->KeyGen();

  Ciphertext<DCRTPoly> ciphertext = cc->Encrypt(kp.publicKey, plaintext);

  LPKeyPair<DCRTPoly> kp2 = cc->KeyGen();

  LPEvalKey<DCRTPoly> keySwitchHint;
  keySwitchHint = cc->KeySwitchGen(kp.secretKey, kp2.secretKey);

  Ciphertext<DCRTPoly> newCt = cc->KeySwitch(keySwitchHint, ciphertext);

  Plaintext plaintextNew;

  cc->Decrypt(kp2.secretKey, newCt, &plaintextNew);

  EXPECT_EQ(plaintext->GetStringValue(), plaintextNew->GetStringValue());
}

TEST_F(UTSHE, keyswitch_ModReduce_DCRT) {
  usint m = 512;

  float stdDev = 4;
  usint size = 4;
  usint plaintextmodulus = 256;
  usint relinWindow = 1;

  shared_ptr<ILDCRTParams<BigInteger>> params =
      GenerateDCRTParams<BigInteger>(m, size, 30);

  CryptoContext<DCRTPoly> cc =
      CryptoContextFactory<DCRTPoly>::genCryptoContextBGVrns(
          params, plaintextmodulus, relinWindow, stdDev);

  Plaintext plaintext =
      cc->MakeStringPlaintext("I am good, what are you?! 32 ch");

  cc->Enable(ENCRYPTION);
  cc->Enable(LEVELEDSHE);
  cc->Enable(SHE);

  LPKeyPair<DCRTPoly> kp = cc->KeyGen();

  Ciphertext<DCRTPoly> ciphertext = cc->Encrypt(kp.publicKey, plaintext);

  LPKeyPair<DCRTPoly> kp2 = cc->KeyGen();

  LPEvalKey<DCRTPoly> keySwitchHint;
  keySwitchHint = cc->KeySwitchGen(kp.secretKey, kp2.secretKey);

  Ciphertext<DCRTPoly> newCt = cc->KeySwitch(keySwitchHint, ciphertext);

  Plaintext plaintextNewKeySwitch;

  cc->Decrypt(kp2.secretKey, newCt, &plaintextNewKeySwitch);

  EXPECT_EQ(plaintext->GetStringValue(),
            plaintextNewKeySwitch->GetStringValue())
      << "Key-Switched Decrypt fails";

  /**************************KEYSWITCH TEST END******************************/
  /**************************MODREDUCE TEST BEGIN******************************/

  cc->ModReduceInPlace(newCt);
  DCRTPoly sk2PrivateElement(kp2.secretKey->GetPrivateElement());
  sk2PrivateElement.DropLastElement();
  kp2.secretKey->SetPrivateElement(sk2PrivateElement);

  Plaintext plaintextNewModReduce;

  cc->Decrypt(kp2.secretKey, newCt, &plaintextNewModReduce);

  EXPECT_EQ(plaintext->GetStringValue(),
            plaintextNewModReduce->GetStringValue())
      << "Mod Reduced Decrypt fails";
}
