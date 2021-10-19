// @file UnitTestCKKS.cpp - Unit tests for the CKKS scheme
//
// @copyright Copyright (c) 2019, Duality Technologies Inc.
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

#include <ctime>
#include <iostream>
#include <list>
#include <vector>
#include "UnitTestUtils.h"
#include "gtest/gtest.h"

#include "cryptocontext.h"
#include "cryptocontextgen.h"
#include "cryptocontexthelper.h"
#include "palisade.h"
#include "utils/testcasegen.h"

using namespace std;
using namespace lbcrypto;

class UTBGVrns : public ::testing::Test {
 public:
  const usint m = 16;
  UTBGVrns() {}
  ~UTBGVrns() {}

 protected:
  void SetUp() {}

  void TearDown() {
    CryptoContextFactory<Poly>::ReleaseAllContexts();
    CryptoContextFactory<DCRTPoly>::ReleaseAllContexts();
  }
};

#define GENERATE_TEST_CASES_FUNC_BV(x, y, ORD, PTM, SIZEMODULI, NUMPRIME,      \
                                    RELIN, BATCH)                              \
  GENERATE_BGVrns_TEST_CASE(x, y, DCRTPoly, BGVrns, ORD, PTM, SIZEMODULI,      \
                            NUMPRIME, RELIN, BV, BATCH, APPROXRESCALE, MANUAL) \
      GENERATE_BGVrns_TEST_CASE(x, y, DCRTPoly, BGVrns, ORD, PTM, SIZEMODULI,  \
                                NUMPRIME, RELIN, BV, BATCH, APPROXRESCALE,     \
                                AUTO)

#define GENERATE_TEST_CASES_FUNC_GHS(x, y, ORD, PTM, SIZEMODULI, NUMPRIME,    \
                                     RELIN, BATCH)                            \
  GENERATE_BGVrns_TEST_CASE(x, y, DCRTPoly, BGVrns, ORD, PTM, SIZEMODULI,     \
                            NUMPRIME, RELIN, GHS, BATCH, APPROXRESCALE,       \
                            MANUAL)                                           \
      GENERATE_BGVrns_TEST_CASE(x, y, DCRTPoly, BGVrns, ORD, PTM, SIZEMODULI, \
                                NUMPRIME, RELIN, GHS, BATCH, APPROXRESCALE,   \
                                AUTO)

#define GENERATE_TEST_CASES_FUNC_HYBRID(x, y, ORD, PTM, SIZEMODULI, NUMPRIME,  \
                                        RELIN, BATCH)                          \
  GENERATE_BGVrns_TEST_CASE(x, y, DCRTPoly, BGVrns, ORD, PTM, SIZEMODULI,      \
                            NUMPRIME, RELIN, HYBRID, BATCH, APPROXRESCALE,     \
                            MANUAL)                                            \
      GENERATE_BGVrns_TEST_CASE(x, y, DCRTPoly, BGVrns, ORD, PTM, SIZEMODULI,  \
                                NUMPRIME, RELIN, HYBRID, BATCH, APPROXRESCALE, \
                                AUTO)

/* *
 * ORDER: Cyclotomic order. Must be a power of 2 for BGVrns.
 * NUMPRIME: Number of towers comprising the ciphertext modulus.
 * SIZEMODULI: bit-length of the moduli composing the ciphertext modulus.
 * 		  Should fit into a machine word, i.e., less than 64.
 * RELIN: The bit decomposition count used in BV relinearization.
 * PTM: The plaintext modulus.
 */
static const usint ORDER = 1024;  // 16384;
static const usint SIZEMODULI = 50;
static const usint NUMPRIME = 8;
static const usint RELIN = 0;
static const usint PTM = 65537;
static const usint BATCH = 16;

/**
 * Tests whether addition for BGVrns works properly.
 */
template <class Element>
static void UnitTest_Add_Packed(const CryptoContext<Element> cc,
                                const string& failmsg) {
  int vecSize = 8;

  const auto cryptoParams =
      std::static_pointer_cast<LPCryptoParametersBGVrns<DCRTPoly>>(
          cc->GetCryptoParameters());

  // vectorOfInts1 = { 0,1,2,3,4,5,6,7 };
  std::vector<int64_t> vectorOfInts1(vecSize);
  std::vector<int64_t> negativeInts1(vecSize);
  for (int i = 0; i < vecSize; i++) {
    vectorOfInts1[i] = i;
    negativeInts1[i] = -i;
  }
  Plaintext plaintext1 = cc->MakePackedPlaintext(vectorOfInts1);
  Plaintext negatives1 = cc->MakePackedPlaintext(negativeInts1);

  // vectorOfInts2 = { 7,6,5,4,3,2,1,0 };
  std::vector<int64_t> vectorOfInts2(vecSize);
  for (int i = 0; i < vecSize; i++) {
    vectorOfInts2[i] = vecSize - i - 1;
  }
  Plaintext plaintext2 = cc->MakePackedPlaintext(vectorOfInts2);

  // vectorOfIntsAdd = { 7,7,7,7,7,7,7,7 };
  std::vector<int64_t> vectorOfIntsAdd(vecSize);
  for (int i = 0; i < vecSize; i++) {
    vectorOfIntsAdd[i] = vecSize - 1;
  }
  Plaintext plaintextAdd = cc->MakePackedPlaintext(vectorOfIntsAdd);

  // vectorOfIntsSub = { -7,-5,-3,-1,1,3,5,7 };
  std::vector<int64_t> vectorOfIntsSub(vecSize);
  for (int i = 0; i < vecSize; i++) {
    vectorOfIntsSub[i] = 2 * i - vecSize + 1;
  }
  Plaintext plaintextSub = cc->MakePackedPlaintext(vectorOfIntsSub);

  // Generate encryption keys
  LPKeyPair<Element> kp = cc->KeyGen();

  // Encrypt plaintexts
  Ciphertext<Element> ciphertext1 = cc->Encrypt(kp.publicKey, plaintext1);
  Ciphertext<Element> ciphertext2 = cc->Encrypt(kp.publicKey, plaintext2);
  Ciphertext<Element> cResult;
  Plaintext results;

  /* Testing EvalAdd
   */
  cResult = cc->EvalAdd(ciphertext1, ciphertext2);
  cc->Decrypt(kp.secretKey, cResult, &results);
  results->SetLength(plaintextAdd->GetLength());
  auto tmp_a = plaintextAdd->GetPackedValue();
  auto tmp_b = results->GetPackedValue();
  checkEquality(tmp_a, tmp_b, failmsg + " EvalAdd fails");

  /* Testing EvalAddInPlace
   */
  Ciphertext<Element> ciphertext1_clone = ciphertext1->Clone();
  cc->EvalAddInPlace(ciphertext1_clone, ciphertext2);
  cc->Decrypt(kp.secretKey, ciphertext1_clone, &results);
  results->SetLength(plaintextAdd->GetLength());
  tmp_a = plaintextAdd->GetPackedValue();
  tmp_b = results->GetPackedValue();
  checkEquality(tmp_a, tmp_b, failmsg + " EvalAddInPlace fails");

  /* Testing operator+
   */
  cResult = ciphertext1 + ciphertext2;
  cc->Decrypt(kp.secretKey, cResult, &results);
  results->SetLength(plaintextAdd->GetLength());
  tmp_a = plaintextAdd->GetPackedValue();
  tmp_b = results->GetPackedValue();
  checkEquality(tmp_a, tmp_b, failmsg + " operator+ fails");

  /* Testing operator+=
   */
  Ciphertext<Element> caddInplace(ciphertext1);
  caddInplace += ciphertext2;
  cc->Decrypt(kp.secretKey, caddInplace, &results);
  results->SetLength(plaintextAdd->GetLength());
  tmp_a = plaintextAdd->GetPackedValue();
  tmp_b = results->GetPackedValue();
  checkEquality(tmp_a, tmp_b, failmsg + " operator+= fails");

  /* Testing EvalSub
   */
  cResult = cc->EvalSub(ciphertext1, ciphertext2);
  cc->Decrypt(kp.secretKey, cResult, &results);
  results->SetLength(plaintextSub->GetLength());
  tmp_a = plaintextSub->GetPackedValue();
  tmp_b = results->GetPackedValue();
  checkEquality(tmp_a, tmp_b, failmsg + " EvalSub fails");

  /* Testing operator-
   */
  cResult = ciphertext1 - ciphertext2;
  cc->Decrypt(kp.secretKey, cResult, &results);
  results->SetLength(plaintextSub->GetLength());
  tmp_a = plaintextSub->GetPackedValue();
  tmp_b = results->GetPackedValue();
  checkEquality(tmp_a, tmp_b, failmsg + " operator- fails");

  /* Testing operator-=
   */
  Ciphertext<Element> csubInplace(ciphertext1);
  csubInplace -= ciphertext2;
  cc->Decrypt(kp.secretKey, csubInplace, &results);
  results->SetLength(plaintextSub->GetLength());
  tmp_a = plaintextSub->GetPackedValue();
  tmp_b = results->GetPackedValue();
  checkEquality(tmp_a, tmp_b, failmsg + " operator-= fails");

  /* Testing EvalAdd ciphertext + plaintext
   */
  cResult = cc->EvalAdd(ciphertext1, plaintext2);
  cc->Decrypt(kp.secretKey, cResult, &results);
  results->SetLength(plaintextAdd->GetLength());
  tmp_a = plaintextAdd->GetPackedValue();
  tmp_b = results->GetPackedValue();
  checkEquality(tmp_a, tmp_b, failmsg + " EvalAdd Ct and Pt fails");

  /* Testing EvalSub ciphertext - plaintext
   */
  cResult = cc->EvalSub(ciphertext1, plaintext2);
  cc->Decrypt(kp.secretKey, cResult, &results);
  results->SetLength(plaintextSub->GetLength());
  tmp_a = plaintextSub->GetPackedValue();
  tmp_b = results->GetPackedValue();
  checkEquality(tmp_a, tmp_b,
                failmsg + " EvalSub Ct and Pt fails fails");

  /* Testing EvalNegate
   */
  cResult = cc->EvalNegate(ciphertext1);
  cc->Decrypt(kp.secretKey, cResult, &results);
  results->SetLength(negatives1->GetLength());
  tmp_a = negatives1->GetPackedValue();
  tmp_b = results->GetPackedValue();
  checkEquality(tmp_a, tmp_b, failmsg + " EvalNegate fails");
}

GENERATE_TEST_CASES_FUNC_BV(UTBGVrns, UnitTest_Add_Packed, ORDER, PTM,
                            SIZEMODULI, NUMPRIME, RELIN, BATCH)
GENERATE_TEST_CASES_FUNC_GHS(UTBGVrns, UnitTest_Add_Packed, ORDER, PTM,
                             SIZEMODULI, NUMPRIME, RELIN, BATCH)
GENERATE_TEST_CASES_FUNC_HYBRID(UTBGVrns, UnitTest_Add_Packed, ORDER, PTM,
                                SIZEMODULI, NUMPRIME, RELIN, BATCH)

/**
 * Tests whether multiplication for BGVrns works properly.
 */
template <class Element>
static void UnitTest_Mult_Packed(const CryptoContext<Element> cc,
                                 const string& failmsg) {
  int vecSize = 8;

  const auto cryptoParams =
      std::dynamic_pointer_cast<LPCryptoParametersBGVrns<DCRTPoly>>(
          cc->GetCryptoParameters());

  // vectorOfInts1 = { 0,1,2,3,4,5,6,7 };
  std::vector<int64_t> vectorOfInts1(vecSize);
  for (int i = 0; i < vecSize; i++) {
    vectorOfInts1[i] = i;
  }
  Plaintext plaintext1 = cc->MakePackedPlaintext(vectorOfInts1);

  // vectorOfInts2 = { 7,6,5,4,3,2,1,0 };
  std::vector<int64_t> vectorOfInts2(vecSize);
  for (int i = 0; i < vecSize; i++) {
    vectorOfInts2[i] = vecSize - i - 1;
  }
  Plaintext plaintext2 = cc->MakePackedPlaintext(vectorOfInts2);

  // vectorOfIntsMult = { 0,6,10,12,12,10,6,0 };
  std::vector<int64_t> vectorOfIntsMult(vecSize);
  for (int i = 0; i < vecSize; i++) {
    vectorOfIntsMult[i] = i * vecSize - i * i - i;
  }
  Plaintext plaintextMult = cc->MakePackedPlaintext(vectorOfIntsMult);

  // Generate encryption keys
  LPKeyPair<Element> kp = cc->KeyGen();
  // Generate multiplication keys
  cc->EvalMultKeyGen(kp.secretKey);

  // Encrypt plaintexts
  Ciphertext<Element> ciphertext1 = cc->Encrypt(kp.publicKey, plaintext1);
  Ciphertext<Element> ciphertext2 = cc->Encrypt(kp.publicKey, plaintext2);
  Ciphertext<Element> cResult;
  Plaintext results;

  /* Testing EvalMult
   */
  cc->EvalMult(ciphertext1, plaintext1);
  cc->EvalMult(ciphertext2, plaintext2);
  cResult = cc->EvalMult(ciphertext1, ciphertext2);
  cc->Decrypt(kp.secretKey, cResult, &results);
  results->SetLength(plaintextMult->GetLength());
  auto tmp_a = plaintextMult->GetPackedValue();
  auto tmp_b = results->GetPackedValue();

  // std::stringstream buffer;
  // buffer << "p1: " << plaintext1 << ", p2: " << plaintext2 << ", expect: "
  // << tmp_a << " - we get: " << tmp_b << endl;
  // checkApproximateEquality(tmp_a, tmp_b, vecSize, eps, failmsg + " EvalMult
  // fails" + buffer.str());
  checkEquality(tmp_a, tmp_b, failmsg + " EvalMult fails");

  /* Testing operator*
   */
  cResult = ciphertext1 * ciphertext2;
  cc->Decrypt(kp.secretKey, cResult, &results);
  results->SetLength(plaintextMult->GetLength());
  tmp_a = plaintextMult->GetPackedValue();
  tmp_b = results->GetPackedValue();
  checkEquality(tmp_a, tmp_b, failmsg + " operator* fails");

  /* Testing operator*=
   */
  Ciphertext<Element> cmultInplace(ciphertext1);
  cmultInplace *= ciphertext2;
  cc->Decrypt(kp.secretKey, cmultInplace, &results);
  results->SetLength(plaintextMult->GetLength());
  tmp_a = plaintextMult->GetPackedValue();
  tmp_b = results->GetPackedValue();
  checkEquality(tmp_a, tmp_b, failmsg + " operator*= fails");

  /* Testing EvalMult ciphertext * plaintext
   */
  cResult = cc->EvalMult(ciphertext1, plaintext2);
  cc->Decrypt(kp.secretKey, cResult, &results);
  results->SetLength(plaintextMult->GetLength());
  tmp_a = plaintextMult->GetPackedValue();
  tmp_b = results->GetPackedValue();
  checkEquality(tmp_a, tmp_b, failmsg + " EvalMult Ct and Pt fails");

  /* Testing EvalMultNoRelin ciphertext * ciphertext
   */
  cResult = cc->EvalMultNoRelin(ciphertext1, ciphertext2);
  cc->Decrypt(kp.secretKey, cResult, &results);
  results->SetLength(plaintextMult->GetLength());
  tmp_a = plaintextMult->GetPackedValue();
  tmp_b = results->GetPackedValue();
  checkEquality(tmp_a, tmp_b,
                failmsg + " EvalMultNoRelin Ct and Ct fails");
}

GENERATE_TEST_CASES_FUNC_BV(UTBGVrns, UnitTest_Mult_Packed, ORDER, PTM,
                            SIZEMODULI, NUMPRIME, RELIN, BATCH)
GENERATE_TEST_CASES_FUNC_GHS(UTBGVrns, UnitTest_Mult_Packed, ORDER, PTM,
                             SIZEMODULI, NUMPRIME, RELIN, BATCH)
GENERATE_TEST_CASES_FUNC_HYBRID(UTBGVrns, UnitTest_Mult_Packed, ORDER, PTM,
                                SIZEMODULI, NUMPRIME, RELIN, BATCH)

/**
 * Tests whether EvalAtIndex for BGVrns works properly.
 */
template <class Element>
static void UnitTest_EvalAtIndex(const CryptoContext<Element> cc,
                                 const string& failmsg) {
  int vecSize = 8;

  const auto cryptoParams =
      std::static_pointer_cast<LPCryptoParametersBGVrns<DCRTPoly>>(
          cc->GetCryptoParameters());

  // vectorOfInts1 = { 1,2,3,4,5,6,7,8 };
  std::vector<int64_t> vectorOfInts1(vecSize);
  for (int i = 0; i < vecSize; i++) {
    vectorOfInts1[i] = i + 1;
  }
  Plaintext plaintext1 = cc->MakePackedPlaintext(vectorOfInts1);

  // vOnes = { 1,1,1,1,1,1,1,1 };
  std::vector<int64_t> vOnes(vecSize);
  for (int i = 0; i < vecSize; i++) {
    vOnes[i] = 1;
  }
  Plaintext pOnes = cc->MakePackedPlaintext(vOnes);

  // vIntsRightShift2 = { 0,0,1,2,3,4,5,6 };
  std::vector<int64_t> vIntsRightShift2(vecSize);
  for (int i = 0; i < vecSize; i++) {
    vIntsRightShift2[i] = (i >= 2) ? vectorOfInts1[i - 2] : 0;
  }
  Plaintext plaintextRight2 = cc->MakePackedPlaintext(vIntsRightShift2);

  // vIntsLeftShift2 = { 3,4,5,6,7,8,0,0 };
  std::vector<int64_t> vIntsLeftShift2(vecSize);
  for (int i = 0; i < vecSize; i++) {
    vIntsLeftShift2[i] = (i < vecSize - 2) ? vectorOfInts1[i + 2] : 0;
  }
  Plaintext plaintextLeft2 = cc->MakePackedPlaintext(vIntsLeftShift2);

  // Generate encryption keys
  LPKeyPair<Element> kp = cc->KeyGen();
  // Generate multiplication keys
  cc->EvalMultKeyGen(kp.secretKey);
  // Generate rotation keys for offsets +2 (left shift) and -2 (right shift)
  cc->EvalAtIndexKeyGen(kp.secretKey, {2, -2});

  // Encrypt plaintexts
  Ciphertext<Element> ciphertext1 = cc->Encrypt(kp.publicKey, plaintext1);
  Ciphertext<Element> cOnes = cc->Encrypt(kp.publicKey, pOnes);
  Ciphertext<Element> cResult;
  Plaintext results;

  /* First, do one multiplication and apply the rotation to the result.
   * This helps hide the rotation noise and get the correct result without
   * using a smaller relinWindow in BV (when creating the crypto context cc).
   */
  ciphertext1 *= cOnes;

  /* Testing EvalAtIndex +2
   */
  cResult = cc->EvalAtIndex(ciphertext1, 2);
  cc->Decrypt(kp.secretKey, cResult, &results);
  results->SetLength(plaintextLeft2->GetLength());
  auto tmp_a = plaintextLeft2->GetPackedValue();
  auto tmp_b = results->GetPackedValue();
  checkEquality(tmp_a, tmp_b, failmsg + " EvalAtIndex(+2) fails");

  /* Testing EvalAtIndex -2
   */
  cResult = cc->EvalAtIndex(ciphertext1, -2);
  cc->Decrypt(kp.secretKey, cResult, &results);
  results->SetLength(plaintextRight2->GetLength());
  tmp_a = plaintextRight2->GetPackedValue();
  tmp_b = results->GetPackedValue();
  checkEquality(tmp_a, tmp_b, failmsg + " EvalAtIndex(-2) fails");
}

GENERATE_TEST_CASES_FUNC_BV(UTBGVrns, UnitTest_EvalAtIndex, ORDER, PTM,
                            SIZEMODULI, NUMPRIME, RELIN, BATCH)
GENERATE_TEST_CASES_FUNC_GHS(UTBGVrns, UnitTest_EvalAtIndex, ORDER, PTM,
                             SIZEMODULI, NUMPRIME, RELIN, BATCH)
GENERATE_TEST_CASES_FUNC_HYBRID(UTBGVrns, UnitTest_EvalAtIndex, ORDER, PTM,
                                SIZEMODULI, NUMPRIME, RELIN, BATCH)

/**
 * Tests whether EvalMerge for BGVrns works properly.
 */
template <class Element>
static void UnitTest_EvalMerge(const CryptoContext<Element> cc,
                               const string& failmsg) {
  int vecSize = 8;

  const auto cryptoParams =
      std::static_pointer_cast<LPCryptoParametersBGVrns<DCRTPoly>>(
          cc->GetCryptoParameters());

  // v* = { i,0,0,0,0,0,0,0 };
  std::vector<int64_t> vOne(vecSize);
  std::vector<int64_t> vTwo(vecSize);
  std::vector<int64_t> vThree(vecSize);
  std::vector<int64_t> vFour(vecSize);
  std::vector<int64_t> vFive(vecSize);
  std::vector<int64_t> vSix(vecSize);
  std::vector<int64_t> vSeven(vecSize);
  std::vector<int64_t> vEight(vecSize);
  for (int i = 0; i < vecSize; i++) {
    vOne[i] = (i == 0) ? 1 : 0;
    vTwo[i] = (i == 0) ? 2 : 0;
    vThree[i] = (i == 0) ? 3 : 0;
    vFour[i] = (i == 0) ? 4 : 0;
    vFive[i] = (i == 0) ? 5 : 0;
    vSix[i] = (i == 0) ? 6 : 0;
    vSeven[i] = (i == 0) ? 7 : 0;
    vEight[i] = (i == 0) ? 8 : 0;
  }
  Plaintext pOne = cc->MakePackedPlaintext(vOne);
  Plaintext pTwo = cc->MakePackedPlaintext(vTwo);
  Plaintext pThree = cc->MakePackedPlaintext(vThree);
  Plaintext pFour = cc->MakePackedPlaintext(vFour);
  Plaintext pFive = cc->MakePackedPlaintext(vFive);
  Plaintext pSix = cc->MakePackedPlaintext(vSix);
  Plaintext pSeven = cc->MakePackedPlaintext(vSeven);
  Plaintext pEight = cc->MakePackedPlaintext(vEight);

  // vMerged = { 1,2,3,4,5,6,7,8 };
  std::vector<int64_t> vMerged(vecSize);
  for (int i = 0; i < vecSize; i++) {
    vMerged[i] = i + 1;
  }
  Plaintext pMerged = cc->MakePackedPlaintext(vMerged);

  std::vector<int64_t> vOnes(vecSize);
  for (int i = 0; i < vecSize; i++) {
    vOnes[i] = 1;
  }
  Plaintext pOnes = cc->MakePackedPlaintext(vOnes);

  // Generate encryption keys
  LPKeyPair<Element> kp = cc->KeyGen();
  // Generate multiplication keys
  cc->EvalMultKeyGen(kp.secretKey);
  // Generate rotation keys for all right rotations 1 to 8.
  vector<int32_t> indexList = {-1, -2, -3, -4, -5, -6, -7, -8};
  cc->EvalAtIndexKeyGen(kp.secretKey, indexList);

  // Encrypt plaintexts
  Ciphertext<Element> cOnes = cc->Encrypt(kp.publicKey, pOnes);
  std::vector<Ciphertext<Element>> ciphertexts;

  // Here, we perform the same trick (mult with one) as in
  // UnitTest_EvalAtiIndex.
  ciphertexts.push_back(cc->Encrypt(kp.publicKey, pOne) * cOnes);
  ciphertexts.push_back(cc->Encrypt(kp.publicKey, pTwo) * cOnes);
  ciphertexts.push_back(cc->Encrypt(kp.publicKey, pThree) * cOnes);
  ciphertexts.push_back(cc->Encrypt(kp.publicKey, pFour) * cOnes);
  ciphertexts.push_back(cc->Encrypt(kp.publicKey, pFive) * cOnes);
  ciphertexts.push_back(cc->Encrypt(kp.publicKey, pSix) * cOnes);
  ciphertexts.push_back(cc->Encrypt(kp.publicKey, pSeven) * cOnes);
  ciphertexts.push_back(cc->Encrypt(kp.publicKey, pEight) * cOnes);
  Plaintext results;

  /* Testing EvalMerge
   */
  auto cResult = cc->EvalMerge(ciphertexts);
  cc->Decrypt(kp.secretKey, cResult, &results);
  results->SetLength(pMerged->GetLength());
  auto tmp_a = pMerged->GetPackedValue();
  auto tmp_b = results->GetPackedValue();
  checkEquality(tmp_a, tmp_b, failmsg + " EvalMerge fails");
}

GENERATE_TEST_CASES_FUNC_BV(UTBGVrns, UnitTest_EvalMerge, ORDER, PTM,
                            SIZEMODULI, NUMPRIME, RELIN, BATCH)
GENERATE_TEST_CASES_FUNC_GHS(UTBGVrns, UnitTest_EvalMerge, ORDER, PTM,
                             SIZEMODULI, NUMPRIME, RELIN, BATCH)
GENERATE_TEST_CASES_FUNC_HYBRID(UTBGVrns, UnitTest_EvalMerge, ORDER, PTM,
                                SIZEMODULI, NUMPRIME, RELIN, BATCH)

template <typename Element>
static void UnitTest_ReEncryption(const CryptoContext<Element> cc,
                                  const string& failmsg) {
  size_t vecSize = 128;

  auto ptm = 10;

  std::vector<int64_t> intvec;
  for (size_t ii = 0; ii < vecSize; ii++) {
    intvec.push_back((rand() % (ptm / 2)) * (rand() % 2 ? 1 : -1));
  }
  Plaintext plaintextInt = cc->MakePackedPlaintext(intvec);

  LPKeyPair<Element> kp = cc->KeyGen();
  EXPECT_EQ(kp.good(), true)
      << failmsg << " key generation for scalar encrypt/decrypt failed";

  LPKeyPair<Element> newKp = cc->KeyGen();
  EXPECT_EQ(newKp.good(), true)
      << failmsg << " second key generation for scalar encrypt/decrypt failed";

  // This generates the keys which are used to perform the key switching.
  LPEvalKey<Element> evalKey;
  evalKey = cc->ReKeyGen(newKp.publicKey, kp.secretKey);

  Ciphertext<Element> ciphertext = cc->Encrypt(kp.publicKey, plaintextInt);
  Plaintext plaintextIntNew;
  Ciphertext<Element> reCiphertext = cc->ReEncrypt(evalKey, ciphertext);
  cc->Decrypt(newKp.secretKey, reCiphertext, &plaintextIntNew);
  plaintextIntNew->SetLength(plaintextInt->GetLength());
  auto tmp_a = plaintextIntNew->GetPackedValue();
  auto tmp_b = plaintextInt->GetPackedValue();
  stringstream buffer;
  buffer << tmp_b << " - we get: " << tmp_a << endl;
  checkEquality(tmp_a, tmp_b,
                failmsg + " ReEncrypt integer plaintext " + buffer.str());

  stringstream buffer2;
  Ciphertext<Element> ciphertext2 = cc->Encrypt(kp.publicKey, plaintextInt);
  Plaintext plaintextIntNew2;
  Ciphertext<Element> reCiphertext2 =
      cc->ReEncrypt(evalKey, ciphertext2, kp.publicKey);
  cc->Decrypt(newKp.secretKey, reCiphertext2, &plaintextIntNew2);
  plaintextIntNew2->SetLength(plaintextInt->GetLength());
  tmp_a = plaintextIntNew2->GetPackedValue();
  tmp_b = plaintextInt->GetPackedValue();
  buffer2 << tmp_b << " - we get: " << tmp_a << endl;
  checkEquality(
      tmp_a, tmp_b,
      failmsg + " HRA-secure ReEncrypt integer plaintext " + buffer2.str());
}

GENERATE_TEST_CASES_FUNC_BV(UTBGVrns, UnitTest_ReEncryption, ORDER, PTM,
                            SIZEMODULI, NUMPRIME, RELIN, BATCH)

template <typename Element>
static void UnitTest_AutoLevelReduce(const CryptoContext<Element> cc,
                                     const string& failmsg) {
  int vecSize = 8;

  const auto cryptoParams =
      std::static_pointer_cast<LPCryptoParametersBGVrns<DCRTPoly>>(
          cc->GetCryptoParameters());

  // vectorOfInts1 = { 0,1,2,3,4,5,6,7 };
  std::vector<int64_t> vectorOfInts1(vecSize);
  for (int i = 0; i < vecSize; i++) {
    vectorOfInts1[i] = i;
  }
  Plaintext plaintext1 = cc->MakePackedPlaintext(vectorOfInts1);

  // vectorOfInts2 = { 7,6,5,4,3,2,1,0 };
  std::vector<int64_t> vectorOfInts2(vecSize);
  for (int i = 0; i < vecSize; i++) {
    vectorOfInts2[i] = vecSize - i - 1;
  }
  Plaintext plaintext2 = cc->MakePackedPlaintext(vectorOfInts2);

  std::vector<int64_t> pCtMult(vecSize);
  std::vector<int64_t> pCtMult3(vecSize);
  std::vector<int64_t> pCt3(vecSize);
  std::vector<int64_t> pCt3_b(vecSize);
  std::vector<int64_t> pCt4(vecSize);
  std::vector<int64_t> pCt5(vecSize);
  std::vector<int64_t> pCt6(vecSize);
  std::vector<int64_t> pCt7(vecSize);
  std::vector<int64_t> pCt_5(vecSize);
  std::vector<int64_t> pCt_6(vecSize);
  std::vector<int64_t> pCt_7(vecSize);
  std::vector<int64_t> pCt8(vecSize);
  std::vector<int64_t> pCt9(vecSize);
  std::vector<int64_t> pCt10(vecSize);
  std::vector<int64_t> pCt11(vecSize);
  std::vector<int64_t> pCt12(vecSize);
  std::vector<int64_t> pCt13(vecSize);
  std::vector<int64_t> pCt14(vecSize);
  for (int i = 0; i < vecSize; i++) {
    pCtMult[i] = vectorOfInts1[i] * vectorOfInts2[i];
    pCt3[i] = pCtMult[i] + vectorOfInts1[i];
    pCt4[i] = pCtMult[i] - vectorOfInts1[i];
    pCt5[i] = pCtMult[i] * vectorOfInts1[i];
    pCt6[i] = vectorOfInts1[i] + pCtMult[i];
    pCt7[i] = vectorOfInts1[i] - pCtMult[i];
    auto tmp = (vectorOfInts1[i] * vectorOfInts1[i] +
                vectorOfInts1[i] * vectorOfInts1[i]) *
               vectorOfInts1[i];
    pCt_5[i] = tmp + vectorOfInts2[i];
    pCt_6[i] = tmp - vectorOfInts2[i];
    pCt_7[i] = tmp * vectorOfInts2[i];
    pCt8[i] = vectorOfInts1[i] * pCtMult[i];
    pCtMult3[i] = pCtMult[i] * vectorOfInts1[i] * vectorOfInts1[i];
    pCt9[i] = pCtMult3[i] + vectorOfInts1[i];
    pCt10[i] = pCtMult3[i] - vectorOfInts1[i];
    pCt11[i] = pCtMult3[i] * vectorOfInts1[i];
    pCt12[i] = vectorOfInts1[i] + pCtMult3[i];
    pCt13[i] = vectorOfInts1[i] - pCtMult3[i];
    pCt14[i] = vectorOfInts1[i] * pCtMult3[i];
  }
  Plaintext plaintextCt3 = cc->MakePackedPlaintext(pCt3);
  Plaintext plaintextCt4 = cc->MakePackedPlaintext(pCt4);
  Plaintext plaintextCt5 = cc->MakePackedPlaintext(pCt5);
  Plaintext plaintextCt6 = cc->MakePackedPlaintext(pCt6);
  Plaintext plaintextCt7 = cc->MakePackedPlaintext(pCt7);
  Plaintext plaintextCt_5 = cc->MakePackedPlaintext(pCt_5);
  Plaintext plaintextCt_6 = cc->MakePackedPlaintext(pCt_6);
  Plaintext plaintextCt_7 = cc->MakePackedPlaintext(pCt_7);
  Plaintext plaintextCt8 = cc->MakePackedPlaintext(pCt8);
  Plaintext plaintextCt9 = cc->MakePackedPlaintext(pCt9);
  Plaintext plaintextCt10 = cc->MakePackedPlaintext(pCt10);
  Plaintext plaintextCt11 = cc->MakePackedPlaintext(pCt11);
  Plaintext plaintextCt12 = cc->MakePackedPlaintext(pCt12);
  Plaintext plaintextCt13 = cc->MakePackedPlaintext(pCt13);
  Plaintext plaintextCt14 = cc->MakePackedPlaintext(pCt14);

  // Generate encryption keys
  LPKeyPair<Element> kp = cc->KeyGen();
  // Generate multiplication keys
  cc->EvalMultKeyGen(kp.secretKey);

  // Encrypt plaintexts
  Ciphertext<Element> ct = cc->Encrypt(kp.publicKey, plaintext1);
  Ciphertext<Element> ct2 = cc->Encrypt(kp.publicKey, plaintext2);
  Ciphertext<Element> cResult;
  Plaintext results;

  auto ctMul = cc->EvalMult(ct, ct2);
  auto ctRed = cc->ModReduce(ctMul);
  Ciphertext<Element> ctRedClone =  ctRed->Clone();

  auto ct3 = cc->EvalAdd(ctRed, ct);  // Addition with tower diff = 1
  cc->Decrypt(kp.secretKey, ct3, &results);
  results->SetLength(plaintextCt3->GetLength());
  auto tmp_a = plaintextCt3->GetPackedValue();
  auto tmp_b = results->GetPackedValue();
  checkEquality(tmp_a, tmp_b, failmsg + " addition with tower diff = 1 fails");

  cc->EvalAddInPlace(ctRedClone, ct);  // In-place addition with tower diff = 1
  cc->Decrypt(kp.secretKey, ctRedClone, &results);
  results->SetLength(plaintextCt3->GetLength());
  tmp_a = plaintextCt3->GetPackedValue();
  tmp_b = results->GetPackedValue();
  checkEquality(tmp_a, tmp_b, failmsg + " in-place addition with tower diff = 1 fails");

  auto ct4 = cc->EvalSub(ctRed, ct);  // Subtraction with tower diff = 1
  cc->Decrypt(kp.secretKey, ct4, &results);
  results->SetLength(plaintextCt4->GetLength());
  tmp_a = plaintextCt4->GetPackedValue();
  tmp_b = results->GetPackedValue();
  checkEquality(tmp_a, tmp_b, failmsg + " subtraction with tower diff = 1 fails");

  auto ct5 = cc->EvalMult(ctRed, ct);  // Multiplication with tower diff = 1
  cc->Decrypt(kp.secretKey, ct5, &results);
  results->SetLength(plaintextCt5->GetLength());
  tmp_a = plaintextCt5->GetPackedValue();
  tmp_b = results->GetPackedValue();
  checkEquality(
      tmp_a, tmp_b, failmsg + " multiplication with tower diff = 1 fails");

  auto ct6 =
      cc->EvalAdd(ct, ctRed);  // Addition with tower diff = 1 (inputs reversed)
  cc->Decrypt(kp.secretKey, ct6, &results);
  results->SetLength(plaintextCt6->GetLength());
  tmp_a = plaintextCt6->GetPackedValue();
  tmp_b = results->GetPackedValue();
  checkEquality(
      tmp_a, tmp_b,
      failmsg + " addition (reverse) with tower diff = 1 fails");

  // In-place addition with tower diff = 1 (inputs reversed)
  auto ct_clone = ct->Clone();
  cc->EvalAddInPlace(ct_clone, ctRed);
  cc->Decrypt(kp.secretKey, ct_clone, &results);
  results->SetLength(plaintextCt6->GetLength());
  tmp_a = plaintextCt6->GetPackedValue();
  tmp_b = results->GetPackedValue();
  checkEquality(
      tmp_a, tmp_b,
      failmsg + " in-place addition (reverse) with tower diff = 1 fails");

  auto ct7 = cc->EvalSub(
      ct, ctRed);  // Subtraction with tower diff = 1 (inputs reversed)
  cc->Decrypt(kp.secretKey, ct7, &results);
  results->SetLength(plaintextCt7->GetLength());
  tmp_a = plaintextCt7->GetPackedValue();
  tmp_b = results->GetPackedValue();
  checkEquality(
      tmp_a, tmp_b, failmsg + " subtraction (reverse) with tower diff = 1 fails");

  auto ct8 = cc->EvalMult(
      ct, ctRed);  // Multiplication with tower diff = 1 (inputs reversed)
  cc->Decrypt(kp.secretKey, ct8, &results);
  results->SetLength(plaintextCt8->GetLength());
  tmp_a = plaintextCt8->GetPackedValue();
  tmp_b = results->GetPackedValue();
  checkEquality(
      tmp_a, tmp_b,failmsg + " multiplication (reverse) with tower diff = 1 fails");

  auto ctMul2 = cc->EvalMult(ctRed, ct);
  auto ctRed2 = cc->ModReduce(ctMul2);
  auto ctMul3 = cc->EvalMult(ctRed2, ct);
  auto ctRed3 = cc->ModReduce(ctMul3);
  auto ctRed3_clone = ctRed3->Clone();

  auto ct9 =
      cc->EvalAdd(ctRed3, ct);  // Addition with more than 1 level difference
  cc->Decrypt(kp.secretKey, ct9, &results);
  results->SetLength(plaintextCt9->GetLength());
  tmp_a = plaintextCt9->GetPackedValue();
  tmp_b = results->GetPackedValue();
  checkEquality(tmp_a, tmp_b, failmsg + " addition with tower diff > 1 fails");

  // In-place Addition with more than 1 level difference
  cc->EvalAddInPlace(ctRed3_clone, ct);
  cc->Decrypt(kp.secretKey, ctRed3_clone, &results);
  results->SetLength(plaintextCt9->GetLength());
  tmp_a = plaintextCt9->GetPackedValue();
  tmp_b = results->GetPackedValue();
  checkEquality(tmp_a, tmp_b, failmsg + " in-place addition with tower diff > 1 fails");


  auto ct10 =
      cc->EvalSub(ctRed3, ct);  // Subtraction with more than 1 level difference
  cc->Decrypt(kp.secretKey, ct10, &results);
  results->SetLength(plaintextCt10->GetLength());
  tmp_a = plaintextCt10->GetPackedValue();
  tmp_b = results->GetPackedValue();
  checkEquality(tmp_a, tmp_b, failmsg + " subtraction with tower diff > 1 fails");

  auto ct11 = cc->EvalMult(
      ctRed3, ct);  // Multiplication with more than 1 level difference
  cc->Decrypt(kp.secretKey, ct11, &results);
  results->SetLength(plaintextCt11->GetLength());
  tmp_a = plaintextCt11->GetPackedValue();
  tmp_b = results->GetPackedValue();
  checkEquality(
      tmp_a, tmp_b, failmsg + " multiplication with tower diff > 1 fails");

  // Addition with more than 1 level difference (inputs reversed)
  auto ct12 = cc->EvalAdd(ct, ctRed3);
  cc->Decrypt(kp.secretKey, ct12, &results);
  results->SetLength(plaintextCt12->GetLength());
  tmp_a = plaintextCt12->GetPackedValue();
  tmp_b = results->GetPackedValue();
  checkEquality(
      tmp_a, tmp_b, failmsg + " addition (reverse) with tower diff > 1 fails");

  // In-place addition with more than 1 level difference (inputs reversed)
  auto ctClone = ct->Clone();
  cc->EvalAddInPlace(ctClone, ctRed3);
  cc->Decrypt(kp.secretKey, ctClone, &results);
  results->SetLength(plaintextCt12->GetLength());
  tmp_a = plaintextCt12->GetPackedValue();
  tmp_b = results->GetPackedValue();
  checkEquality(
      tmp_a, tmp_b, failmsg + " in-place addition (reverse) with tower diff > 1 fails");

  auto ct13 = cc->EvalSub(ct, ctRed3);  // Subtraction with more than 1 level
                                        // difference (inputs reversed)
  cc->Decrypt(kp.secretKey, ct13, &results);
  results->SetLength(plaintextCt13->GetLength());
  tmp_a = plaintextCt13->GetPackedValue();
  tmp_b = results->GetPackedValue();
  checkEquality(
      tmp_a, tmp_b, failmsg + " subtraction (reverse) with tower diff > 1 fails");

  auto ct14 = cc->EvalMult(ct, ctRed3);  // Multiplication with more than 1
                                         // level difference (inputs reversed)
  cc->Decrypt(kp.secretKey, ct14, &results);
  results->SetLength(plaintextCt14->GetLength());
  tmp_a = plaintextCt14->GetPackedValue();
  tmp_b = results->GetPackedValue();
  checkEquality(
      tmp_a, tmp_b, failmsg + " multiplication (reverse) with tower diff > 1 fails");

  // This scenario tests for operations on
  // ciphertext and plaintext that differ on
  // both scaling factor and number of towers.
  auto ct_1 = cc->EvalMult(ct, plaintext1);
  auto ct_2 = cc->EvalAdd(ct_1, ct_1);
  auto ct_3 = cc->ModReduce(ct_2);
  auto ct_4 = cc->EvalMult(ct_3, plaintext1);
  auto ct_5 = cc->EvalAdd(
      ct_4, plaintext2);  // Addition with plaintext and tower diff = 1
  auto ct_6 = cc->EvalSub(
      ct_4, plaintext2);  // Subtraction with plaintext and tower diff = 1
  auto ct_7 = cc->EvalMult(
      ct_4, plaintext2);  // Multiplication with plaintext and tower diff = 1
  cc->Decrypt(kp.secretKey, ct_5, &results);
  results->SetLength(plaintextCt_5->GetLength());
  tmp_a = plaintextCt_5->GetPackedValue();
  tmp_b = results->GetPackedValue();
  checkEquality(
      tmp_a, tmp_b,
      failmsg + " addition with plaintext and tower diff = 1 fails");

  cc->Decrypt(kp.secretKey, ct_6, &results);
  results->SetLength(plaintextCt_6->GetLength());
  tmp_a = plaintextCt_6->GetPackedValue();
  tmp_b = results->GetPackedValue();
  checkEquality(
      tmp_a, tmp_b, failmsg + " subtraction with plaintext and tower diff = 1 fails");

  cc->Decrypt(kp.secretKey, ct_7, &results);
  results->SetLength(plaintextCt_7->GetLength());
  tmp_a = plaintextCt_7->GetPackedValue();
  tmp_b = results->GetPackedValue();
  checkEquality(
      tmp_a, tmp_b, failmsg + " multiplication with plaintext and tower diff = 1 fails");
}

GENERATE_TEST_CASES_FUNC_BV(UTBGVrns, UnitTest_AutoLevelReduce, ORDER, PTM, SIZEMODULI,
			    NUMPRIME, RELIN, BATCH)
GENERATE_TEST_CASES_FUNC_GHS(UTBGVrns, UnitTest_AutoLevelReduce, ORDER, PTM,
			     SIZEMODULI, NUMPRIME, RELIN, BATCH)
GENERATE_TEST_CASES_FUNC_HYBRID(UTBGVrns, UnitTest_AutoLevelReduce, ORDER, PTM,
				SIZEMODULI, NUMPRIME, RELIN, BATCH)

template <typename Element>
static void UnitTest_Compress(const CryptoContext<Element> cc,
                              const string& failmsg) {
  int vecSize = 8;
  size_t targetTowers = 1;

  const auto cryptoParams =
      std::static_pointer_cast<LPCryptoParametersBGVrns<DCRTPoly>>(
          cc->GetCryptoParameters());

  // vectorOfInts1 = { 0,1,2,3,4,5,6,7 };
  std::vector<int64_t> vectorOfInts(vecSize);
  for (int i = 0; i < vecSize; i++) {
    vectorOfInts[i] = i;
  }
  Plaintext plaintext = cc->MakePackedPlaintext(vectorOfInts);

  // Generate encryption keys
  LPKeyPair<Element> kp = cc->KeyGen();
  // Generate multiplication keys
  cc->EvalMultKeyGen(kp.secretKey);

  // Encrypt plaintexts
  Ciphertext<Element> ct = cc->Encrypt(kp.publicKey, plaintext);
  ct *= ct;
  Ciphertext<Element> cResult;
  Plaintext result;
  Plaintext resultCompressed;
  auto algo = cc->GetEncryptionAlgorithm();
  auto ctCompressed = algo->Compress(ct, targetTowers);

  size_t towersLeft = ctCompressed->GetElements()[0].GetNumOfElements();
  EXPECT_TRUE(towersLeft == targetTowers) << " compress fails";

  cc->Decrypt(kp.secretKey, ct, &result);
  cc->Decrypt(kp.secretKey, ctCompressed, &resultCompressed);
  auto tmp_a = result->GetPackedValue();
  auto tmp_b = resultCompressed->GetPackedValue();
  checkEquality(tmp_a, tmp_b, failmsg + " compress fails");
}

GENERATE_TEST_CASES_FUNC_BV(UTBGVrns, UnitTest_Compress, ORDER, PTM, SIZEMODULI,
                            NUMPRIME, RELIN, BATCH)
GENERATE_TEST_CASES_FUNC_GHS(UTBGVrns, UnitTest_Compress, ORDER, PTM,
                             SIZEMODULI, NUMPRIME, RELIN, BATCH)
GENERATE_TEST_CASES_FUNC_HYBRID(UTBGVrns, UnitTest_Compress, ORDER, PTM,
                                SIZEMODULI, NUMPRIME, RELIN, BATCH)

/**
 * Tests whether EvalFastRotation for BGVrns works properly.
 */
template <class Element>
static void UnitTest_EvalFastRotation(const CryptoContext<Element> cc,
                                      const string& failmsg) {
  int vecSize = 8;

  const auto cryptoParams =
      std::static_pointer_cast<LPCryptoParametersBGVrns<DCRTPoly>>(
          cc->GetCryptoParameters());

  // vectorOfInts1 = { 1,2,3,4,5,6,7,8 };
  std::vector<int64_t> vectorOfInts1(vecSize);
  for (int i = 0; i < vecSize; i++) {
    vectorOfInts1[i] = i + 1;
  }
  Plaintext plaintext1 = cc->MakePackedPlaintext(vectorOfInts1);

  // vOnes = { 1,1,1,1,1,1,1,1 };
  std::vector<int64_t> vOnes(vecSize);
  for (int i = 0; i < vecSize; i++) {
    vOnes[i] = 1;
  }
  Plaintext pOnes = cc->MakePackedPlaintext(vOnes);

  // vIntsRightShift2 = { 0,0,1,2,3,4,5,6 };
  std::vector<int64_t> vIntsRightShift2(vecSize);
  for (int i = 0; i < vecSize; i++) {
    vIntsRightShift2[i] = (i >= 2) ? vectorOfInts1[i - 2] : 0;
  }
  Plaintext plaintextRight2 = cc->MakePackedPlaintext(vIntsRightShift2);

  // vIntsLeftShift2 = { 3,4,5,6,7,8,0,0 };
  std::vector<int64_t> vIntsLeftShift2(vecSize);
  for (int i = 0; i < vecSize; i++) {
    vIntsLeftShift2[i] = (i < vecSize - 2) ? vectorOfInts1[i + 2] : 0;
  }
  Plaintext plaintextLeft2 = cc->MakePackedPlaintext(vIntsLeftShift2);

  // Generate encryption keys
  LPKeyPair<Element> kp = cc->KeyGen();
  // Generate multiplication keys
  cc->EvalMultKeyGen(kp.secretKey);
  // Generate rotation keys for offsets +2 (left shift) and -2 (right shift)
  cc->EvalAtIndexKeyGen(kp.secretKey, {2, -2});

  // Encrypt plaintexts
  Ciphertext<Element> ciphertext1 = cc->Encrypt(kp.publicKey, plaintext1);
  Ciphertext<Element> cOnes = cc->Encrypt(kp.publicKey, pOnes);
  Ciphertext<Element> cResult;
  Plaintext results;

  /* First, do one multiplication and apply the rotation to the result.
   * This helps hide the rotation noise and get the correct result without
   * using a smaller relinWindow in BV (when creating the crypto context cc).
   */
  ciphertext1 *= cOnes;

  auto decompose = cc->EvalFastRotationPrecompute(ciphertext1);

  usint m = cc->GetCryptoParameters()->GetElementParams()->GetCyclotomicOrder();
  /* Testing EvalAtIndex +2
   */

  cResult = cc->EvalFastRotation(ciphertext1, 2, m, decompose);
  cc->Decrypt(kp.secretKey, cResult, &results);
  results->SetLength(plaintextLeft2->GetLength());
  auto tmp_a = plaintextLeft2->GetPackedValue();
  auto tmp_b = results->GetPackedValue();
  checkEquality(tmp_a, tmp_b, failmsg + " EvalAtIndex(+2) fails");

  /* Testing EvalAtIndex -2
   */
  cResult = cc->EvalFastRotation(ciphertext1, -2, m, decompose);
  cc->Decrypt(kp.secretKey, cResult, &results);
  results->SetLength(plaintextRight2->GetLength());
  tmp_a = plaintextRight2->GetPackedValue();
  tmp_b = results->GetPackedValue();
  checkEquality(tmp_a, tmp_b, failmsg + " EvalAtIndex(-2) fails");
}

GENERATE_TEST_CASES_FUNC_BV(UTBGVrns, UnitTest_EvalFastRotation, ORDER, PTM,
                            SIZEMODULI, NUMPRIME, RELIN, BATCH)
GENERATE_TEST_CASES_FUNC_GHS(UTBGVrns, UnitTest_EvalFastRotation, ORDER, PTM,
                             SIZEMODULI, NUMPRIME, RELIN, BATCH)
GENERATE_TEST_CASES_FUNC_HYBRID(UTBGVrns, UnitTest_EvalFastRotation, ORDER, PTM,
                                SIZEMODULI, NUMPRIME, RELIN, BATCH)

/**
 * Tests whether metadata is carried over for several operations in BGVrns
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

  // Checking if metadata is carried over in EvalSum
  auto cSum = cc->EvalSum(ciphertext1, vecSize);
  auto sumValTest = MetadataTest::GetMetadata<Element>(cSum);
  EXPECT_EQ(val1->GetMetadata(), sumValTest->GetMetadata())
      << "Ciphertext metadata mismatch in EvalSum";
}

GENERATE_TEST_CASES_FUNC_BV(UTBGVrns, UnitTest_Metadata, ORDER, PTM, SIZEMODULI,
                            NUMPRIME, RELIN, BATCH)
GENERATE_TEST_CASES_FUNC_GHS(UTBGVrns, UnitTest_Metadata, ORDER, PTM,
                             SIZEMODULI, NUMPRIME, RELIN, BATCH)
GENERATE_TEST_CASES_FUNC_HYBRID(UTBGVrns, UnitTest_Metadata, ORDER, PTM,
                                SIZEMODULI, NUMPRIME, RELIN, BATCH)
