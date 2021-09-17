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
#include <vector>
#include "gtest/gtest.h"

#include "cryptocontextgen.h"
#include "cryptocontexthelper.h"
#include "utils/testcasegen.h"
#include "palisade.h"

using namespace std;
using namespace lbcrypto;

class UTMultiparty : public ::testing::Test {
 public:
  const usint m = 16;
  UTMultiparty() {}
  ~UTMultiparty() {}

 protected:
  void SetUp() {}

  void TearDown() {
    CryptoContextFactory<Poly>::ReleaseAllContexts();
    CryptoContextFactory<DCRTPoly>::ReleaseAllContexts();
  }
};

#if NATIVEINT == 128
// This file unit tests the SHE capabilities for the CKKS scheme
#define GENERATE_CKKS_TEST_CASES_FUNC(x, y, ORD, SCALE, NUMPRIME, RELIN,     \
                                      BATCH)                                 \
  GENERATE_CKKS_TEST_CASE(x, y, DCRTPoly, CKKS, ORD, SCALE, NUMPRIME, RELIN, \
                          BATCH, BV, APPROXRESCALE)                          \
  GENERATE_CKKS_TEST_CASE(x, y, DCRTPoly, CKKS, ORD, SCALE, NUMPRIME, RELIN, \
                          BATCH, BV, APPROXAUTO)                             \
  GENERATE_CKKS_TEST_CASE(x, y, DCRTPoly, CKKS, ORD, SCALE, NUMPRIME, RELIN, \
                          BATCH, HYBRID, APPROXRESCALE)                      \
  GENERATE_CKKS_TEST_CASE(x, y, DCRTPoly, CKKS, ORD, SCALE, NUMPRIME, RELIN, \
                          BATCH, HYBRID, APPROXAUTO)                         \
  GENERATE_CKKS_TEST_CASE(x, y, DCRTPoly, CKKS, ORD, SCALE, NUMPRIME, RELIN, \
                          BATCH, GHS, APPROXRESCALE)                         \
  GENERATE_CKKS_TEST_CASE(x, y, DCRTPoly, CKKS, ORD, SCALE, NUMPRIME, RELIN, \
                          BATCH, GHS, APPROXAUTO)
#else
// This file unit tests the SHE capabilities for the CKKS scheme
#define GENERATE_CKKS_TEST_CASES_FUNC(x, y, ORD, SCALE, NUMPRIME, RELIN,     \
                                      BATCH)                                 \
  GENERATE_CKKS_TEST_CASE(x, y, DCRTPoly, CKKS, ORD, SCALE, NUMPRIME, RELIN, \
                          BATCH, BV, APPROXRESCALE)                          \
  GENERATE_CKKS_TEST_CASE(x, y, DCRTPoly, CKKS, ORD, SCALE, NUMPRIME, RELIN, \
                          BATCH, BV, EXACTRESCALE)                           \
  GENERATE_CKKS_TEST_CASE(x, y, DCRTPoly, CKKS, ORD, SCALE, NUMPRIME, RELIN, \
                          BATCH, BV, APPROXAUTO)                             \
  GENERATE_CKKS_TEST_CASE(x, y, DCRTPoly, CKKS, ORD, SCALE, NUMPRIME, RELIN, \
                          BATCH, HYBRID, APPROXRESCALE)                      \
  GENERATE_CKKS_TEST_CASE(x, y, DCRTPoly, CKKS, ORD, SCALE, NUMPRIME, RELIN, \
                          BATCH, HYBRID, EXACTRESCALE)                       \
  GENERATE_CKKS_TEST_CASE(x, y, DCRTPoly, CKKS, ORD, SCALE, NUMPRIME, RELIN, \
                          BATCH, HYBRID, APPROXAUTO)                         \
  GENERATE_CKKS_TEST_CASE(x, y, DCRTPoly, CKKS, ORD, SCALE, NUMPRIME, RELIN, \
                          BATCH, GHS, APPROXRESCALE)                         \
  GENERATE_CKKS_TEST_CASE(x, y, DCRTPoly, CKKS, ORD, SCALE, NUMPRIME, RELIN, \
                          BATCH, GHS, EXACTRESCALE)                          \
  GENERATE_CKKS_TEST_CASE(x, y, DCRTPoly, CKKS, ORD, SCALE, NUMPRIME, RELIN, \
                          BATCH, GHS, APPROXAUTO)
#endif

#define GENERATE_TEST_CASES_FUNC_RNS(x, y, ORD, PTM, BATCH)                    \
  GENERATE_PKE_TEST_CASE(x, y, DCRTPoly, BFVrns_rlwe, ORD, PTM)                \
  GENERATE_PKE_TEST_CASE(x, y, DCRTPoly, BFVrns_opt, ORD, PTM)                 \
  GENERATE_PKE_TEST_CASE(x, y, DCRTPoly, BFVrnsB_rlwe, ORD, PTM)               \
  GENERATE_PKE_TEST_CASE(x, y, DCRTPoly, BFVrnsB_opt, ORD, PTM)                \
  GENERATE_BGVrns_TEST_CASE(x, y, DCRTPoly, BGVrns_rlwe, ORD, PTM, SIZEMODULI, \
                            NUMPRIME, RELIN, BV, BATCH, APPROXRESCALE, MANUAL) \
      GENERATE_BGVrns_TEST_CASE(                                               \
          x, y, DCRTPoly, BGVrns_opt, ORD, PTM, SIZEMODULI, NUMPRIME, RELIN,   \
          BV, BATCH, APPROXRESCALE,                                            \
          MANUAL) GENERATE_BGVrns_TEST_CASE(x, y, DCRTPoly, BGVrns_rlwe, ORD,  \
                                            PTM, SIZEMODULI, NUMPRIME, RELIN,  \
                                            GHS, BATCH, APPROXRESCALE, MANUAL) \
          GENERATE_BGVrns_TEST_CASE(x, y, DCRTPoly, BGVrns_opt, ORD, PTM,      \
                                    SIZEMODULI, NUMPRIME, RELIN, GHS, BATCH,   \
                                    APPROXRESCALE, MANUAL)                     \
              GENERATE_BGVrns_TEST_CASE(x, y, DCRTPoly, BGVrns_rlwe, ORD, PTM, \
                                        SIZEMODULI, NUMPRIME, RELIN, HYBRID,   \
                                        BATCH, APPROXRESCALE, MANUAL)          \
                  GENERATE_BGVrns_TEST_CASE(                                   \
                      x, y, DCRTPoly, BGVrns_opt, ORD, PTM, SIZEMODULI,        \
                      NUMPRIME, RELIN, HYBRID, BATCH, APPROXRESCALE, MANUAL)

#define GENERATE_TEST_CASES_FUNC_MP(x, y, ORD, PTM)      \
  GENERATE_PKE_TEST_CASE(x, y, Poly, BFV_rlwe, ORD, PTM) \
  GENERATE_PKE_TEST_CASE(x, y, Poly, BFV_opt, ORD, PTM)

/* *
 * ORDER: Cyclotomic order. Must be a power of 2 for CKKS.
 * NUMPRIME: Number of co-primes comprising the ciphertext modulus.
 * 		     It is equal to the desired depth of the computation.
 * SCALE: Scaling parameter 2^p. Also, Size of each co-prime in bits.
 * 		  Should fit into a machine word, i.e., less than 64.
 * RELIN: The bit decomposition count used in relinearization.
 *  	  Use 0 to go with max possible. Use small values (3-4?)
 * 		  if you need rotations before any multiplications.
 * BATCH: The length of the packed vectors to be used with CKKS.
 */
static const usint ORDER = 4096;
static const usint SCALE = 50;
static const usint NUMPRIME = 3;
static const usint RELIN = 3;
static const usint BATCH = 16;
static const usint SIZEMODULI = 50;

/**
 * This function checks whether vectors of approximate numbers a and b are
 * equal. This is useful for CKKS tests, because numbers are approximate, so
 * results will never be exactly as expected.
 *
 * @param vectorSize The length of the two vectors.
 * @param epsilon Minimum precision to consider a and b equal.
 * 			E.g., a={0.1, 0.123} and b={0.1, 0.124} are equal for
 * epsilon = 0.01, but different for epsilon = 0.001.
 * @param failmsg Debug message to display upon failure.
 */
static void checkApproximateEquality(const std::vector<std::complex<double>>& a,
                                     const std::vector<std::complex<double>>& b,
                                     int vectorSize, double epsilon,
                                     const string& failmsg) {
  std::vector<std::complex<double>> allTrue(vectorSize);
  std::vector<std::complex<double>> tmp(vectorSize);
  for (int i = 0; i < vectorSize; i++) {
    allTrue[i] = 1;
    tmp[i] = abs(a[i] - b[i]) <= epsilon;
  }
  EXPECT_TRUE(tmp == allTrue) << failmsg;
}

template <class Element>
static void UnitTest_MultiPartyCKKS(const CryptoContext<Element> cc1,
                                    const string& failmsg) {
  CryptoContext<Element> cc =
      std::static_pointer_cast<CryptoContextImpl<Element>>(cc1);

  double eps = 0.0001;

  LPKeyPair<DCRTPoly> kp1;
  LPKeyPair<DCRTPoly> kp2;
  LPKeyPair<DCRTPoly> kpMultiparty;

  kp1 = cc->KeyGen();

  std::vector<int32_t> indices = {2};

  auto evalMultKey = cc->KeySwitchGen(kp1.secretKey, kp1.secretKey);
  cc->EvalSumKeyGen(kp1.secretKey);
  auto evalSumKeys = std::make_shared<std::map<usint, LPEvalKey<DCRTPoly>>>(
      cc->GetEvalSumKeyMap(kp1.secretKey->GetKeyTag()));
  cc->EvalAtIndexKeyGen(kp1.secretKey, indices);
  auto evalAtIndexKeys = std::make_shared<std::map<usint, LPEvalKey<DCRTPoly>>>(
      cc->GetEvalAutomorphismKeyMap(kp1.secretKey->GetKeyTag()));

  kp2 = cc->MultipartyKeyGen(kp1.publicKey);
  auto evalMultKey2 =
      cc->MultiKeySwitchGen(kp2.secretKey, kp2.secretKey, evalMultKey);

  auto evalMultAB = cc->MultiAddEvalKeys(evalMultKey, evalMultKey2,
                                         kp2.publicKey->GetKeyTag());

  auto evalMultBAB = cc->MultiMultEvalKey(evalMultAB, kp2.secretKey,
                                          kp2.publicKey->GetKeyTag());

  auto evalSumKeysB = cc->MultiEvalSumKeyGen(kp2.secretKey, evalSumKeys,
                                             kp2.publicKey->GetKeyTag());
  auto evalSumKeysJoin = cc->MultiAddEvalSumKeys(evalSumKeys, evalSumKeysB,
                                                 kp2.publicKey->GetKeyTag());
  cc->InsertEvalSumKey(evalSumKeysJoin);

  auto evalAtIndexKeysB = cc->MultiEvalAtIndexKeyGen(
      kp2.secretKey, evalAtIndexKeys, indices, kp2.publicKey->GetKeyTag());
  auto evalAtIndexKeysJoin = cc->MultiAddEvalAutomorphismKeys(
      evalAtIndexKeys, evalAtIndexKeysB, kp2.publicKey->GetKeyTag());
  cc->InsertEvalAutomorphismKey(evalAtIndexKeysJoin);

  auto evalMultAAB = cc->MultiMultEvalKey(evalMultAB, kp1.secretKey,
                                          kp2.publicKey->GetKeyTag());
  auto evalMultFinal = cc->MultiAddEvalMultKeys(evalMultAAB, evalMultBAB,
                                                evalMultAB->GetKeyTag());
  cc->InsertEvalMultKey({evalMultFinal});

  vector<LPPrivateKey<DCRTPoly>> secretKeys;
  secretKeys.push_back(kp1.secretKey);
  secretKeys.push_back(kp2.secretKey);

  kpMultiparty = cc->MultipartyKeyGen(secretKeys);

  if (!kpMultiparty.good()) {
    std::cout << "Key generation failed!" << std::endl;
    exit(1);
  }

  ////////////////////////////////////////////////////////////
  // Encode source data
  ////////////////////////////////////////////////////////////
  std::vector<std::complex<double>> vectorOfInts1 = {1, 2, 3, 4, 5, 6,
                                                     5, 4, 3, 2, 1, 0};
  std::vector<std::complex<double>> vectorOfInts2 = {1, 0, 0, 1, 1, 0,
                                                     0, 0, 0, 0, 0, 0};
  std::vector<std::complex<double>> vectorOfInts3 = {2, 2, 3, 4,  5, 6,
                                                     7, 8, 9, 10, 0, 0};

  size_t encodedLength = vectorOfInts1.size();
  std::vector<std::complex<double>> sumInput(encodedLength, {0, 0});
  std::vector<std::complex<double>> multInput(encodedLength, {0, 0});
  std::vector<std::complex<double>> evalSumInput(encodedLength, {0, 0});
  std::vector<std::complex<double>> rotateInput(encodedLength, {0, 0});

  for (usint i = 0; i < encodedLength; i++) {
    sumInput[i] = vectorOfInts1[i] + vectorOfInts2[i] + vectorOfInts3[i];
    multInput[i] = vectorOfInts1[i] * vectorOfInts3[i];
    if (i == 0)
      evalSumInput[encodedLength - i - 1] =
          vectorOfInts3[encodedLength - i - 1];
    else
      evalSumInput[encodedLength - i - 1] =
          evalSumInput[encodedLength - i] +
          vectorOfInts3[encodedLength - i - 1];
    if (i + indices[0] > encodedLength - 1)
      rotateInput[i] = 0;
    else
      rotateInput[i] = vectorOfInts1[i + indices[0]];
  }

  Plaintext plaintext1 = cc->MakeCKKSPackedPlaintext(vectorOfInts1);
  Plaintext plaintext2 = cc->MakeCKKSPackedPlaintext(vectorOfInts2);
  Plaintext plaintext3 = cc->MakeCKKSPackedPlaintext(vectorOfInts3);
  Plaintext plaintextSumInput = cc->MakeCKKSPackedPlaintext(sumInput);
  Plaintext plaintextMultInput = cc->MakeCKKSPackedPlaintext(multInput);
  Plaintext plaintextEvalSumInput = cc->MakeCKKSPackedPlaintext(evalSumInput);
  Plaintext plaintextRotateInput = cc->MakeCKKSPackedPlaintext(rotateInput);

  ////////////////////////////////////////////////////////////
  // Encryption
  ////////////////////////////////////////////////////////////
  Ciphertext<DCRTPoly> ciphertext1 = cc->Encrypt(kp2.publicKey, plaintext1);
  Ciphertext<DCRTPoly> ciphertext2 = cc->Encrypt(kp2.publicKey, plaintext2);
  Ciphertext<DCRTPoly> ciphertext3 = cc->Encrypt(kp2.publicKey, plaintext3);

  ////////////////////////////////////////////////////////////
  // EvalAdd Operation on Re-Encrypted Data
  ////////////////////////////////////////////////////////////
  Ciphertext<DCRTPoly> ciphertextAdd12 = cc->EvalAdd(ciphertext1, ciphertext2);
  Ciphertext<DCRTPoly> ciphertextAdd123 =
      cc->EvalAdd(ciphertextAdd12, ciphertext3);

  auto ciphertextMultTemp = cc->EvalMult(ciphertext1, ciphertext3);
  auto ciphertextMult = cc->ModReduce(ciphertextMultTemp);
  auto ciphertextEvalSum = cc->EvalSum(ciphertext3, BATCH);
  ciphertext1 = cc->EvalMult(ciphertext1, 1);
  auto ciphertextRotate = cc->EvalAtIndex(ciphertext1, indices[0]);

  ////////////////////////////////////////////////////////////
  // Decryption after Accumulation Operation on Encrypted Data
  ////////////////////////////////////////////////////////////
  Plaintext plaintextAddNew;
  cc->Decrypt(kpMultiparty.secretKey, ciphertextAdd123, &plaintextAddNew);
  plaintextAddNew->SetLength(plaintext1->GetLength());

  auto tmp_a = plaintextAddNew->GetCKKSPackedValue();
  auto tmp_b = plaintextSumInput->GetCKKSPackedValue();
  checkApproximateEquality(tmp_a, tmp_b, encodedLength, eps,
                           failmsg + " accumulation failed");

  Plaintext plaintextMult;
  cc->Decrypt(kpMultiparty.secretKey, ciphertextMult, &plaintextMult);
  plaintextMult->SetLength(plaintext1->GetLength());

  tmp_a = plaintextMult->GetCKKSPackedValue();
  tmp_b = plaintextMultInput->GetCKKSPackedValue();
  checkApproximateEquality(tmp_a, tmp_b, encodedLength, eps,
                           failmsg + " multiplication failed");

  Plaintext plaintextRotate;
  cc->Decrypt(kpMultiparty.secretKey, ciphertextRotate, &plaintextRotate);
  plaintextRotate->SetLength(plaintext1->GetLength());

  tmp_a = plaintextRotate->GetCKKSPackedValue();
  tmp_b = plaintextRotateInput->GetCKKSPackedValue();
  checkApproximateEquality(tmp_a, tmp_b, encodedLength, eps,
                           failmsg + " rotation failed");

  ////////////////////////////////////////////////////////////
  // Decryption after Accumulation Operation on Encrypted Data with Multiparty
  ////////////////////////////////////////////////////////////
  Plaintext plaintextMultipartyNew;

  const shared_ptr<LPCryptoParameters<DCRTPoly>> cryptoParams =
      kp1.secretKey->GetCryptoParameters();
  const shared_ptr<typename DCRTPoly::Params> elementParams =
      cryptoParams->GetElementParams();

  auto ciphertextPartial1 =
      cc->MultipartyDecryptLead(kp1.secretKey, {ciphertextAdd123});
  auto ciphertextPartial2 =
      cc->MultipartyDecryptMain(kp2.secretKey, {ciphertextAdd123});

  vector<Ciphertext<DCRTPoly>> partialCiphertextVec;
  partialCiphertextVec.push_back(ciphertextPartial1[0]);
  partialCiphertextVec.push_back(ciphertextPartial2[0]);

  cc->MultipartyDecryptFusion(partialCiphertextVec, &plaintextMultipartyNew);
  plaintextMultipartyNew->SetLength(plaintext1->GetLength());

  tmp_a = plaintextMultipartyNew->GetCKKSPackedValue();
  tmp_b = plaintextSumInput->GetCKKSPackedValue();
  checkApproximateEquality(tmp_a, tmp_b, encodedLength, eps,
                           failmsg + " Multiparty accumulation failed");

  Plaintext plaintextMultipartyMult;
  ciphertextPartial1 =
      cc->MultipartyDecryptLead(kp1.secretKey, {ciphertextMult});
  ciphertextPartial2 =
      cc->MultipartyDecryptMain(kp2.secretKey, {ciphertextMult});

  vector<Ciphertext<DCRTPoly>> partialCiphertextVecMult;
  partialCiphertextVecMult.push_back(ciphertextPartial1[0]);
  partialCiphertextVecMult.push_back(ciphertextPartial2[0]);

  cc->MultipartyDecryptFusion(partialCiphertextVecMult,
                              &plaintextMultipartyMult);
  plaintextMultipartyMult->SetLength(plaintext1->GetLength());

  tmp_a = plaintextMultipartyMult->GetCKKSPackedValue();
  tmp_b = plaintextMultInput->GetCKKSPackedValue();
  checkApproximateEquality(tmp_a, tmp_b, encodedLength, eps,
                           failmsg + " Multiparty multiplication failed");

  Plaintext plaintextMultipartyEvalSum;
  ciphertextPartial1 =
      cc->MultipartyDecryptLead(kp1.secretKey, {ciphertextEvalSum});
  ciphertextPartial2 =
      cc->MultipartyDecryptMain(kp2.secretKey, {ciphertextEvalSum});

  vector<Ciphertext<DCRTPoly>> partialCiphertextVecEvalSum;
  partialCiphertextVecEvalSum.push_back(ciphertextPartial1[0]);
  partialCiphertextVecEvalSum.push_back(ciphertextPartial2[0]);

  cc->MultipartyDecryptFusion(partialCiphertextVecEvalSum,
                              &plaintextMultipartyEvalSum);
  plaintextMultipartyEvalSum->SetLength(plaintext1->GetLength());

  tmp_a = plaintextMultipartyEvalSum->GetCKKSPackedValue();
  tmp_b = plaintextEvalSumInput->GetCKKSPackedValue();
  checkApproximateEquality(tmp_a, tmp_b, encodedLength, eps,
                           failmsg + " Multiparty eval sum failed");

  Plaintext plaintextMultipartyRotate;
  ciphertextPartial1 =
      cc->MultipartyDecryptLead(kp1.secretKey, {ciphertextRotate});
  ciphertextPartial2 =
      cc->MultipartyDecryptMain(kp2.secretKey, {ciphertextRotate});

  vector<Ciphertext<DCRTPoly>> partialCiphertextVecRotate;
  partialCiphertextVecRotate.push_back(ciphertextPartial1[0]);
  partialCiphertextVecRotate.push_back(ciphertextPartial2[0]);

  cc->MultipartyDecryptFusion(partialCiphertextVecRotate,
                              &plaintextMultipartyRotate);
  plaintextMultipartyRotate->SetLength(plaintext1->GetLength());

  tmp_a = plaintextMultipartyRotate->GetCKKSPackedValue();
  tmp_b = plaintextRotateInput->GetCKKSPackedValue();
  checkApproximateEquality(tmp_a, tmp_b, encodedLength, eps,
                           failmsg + " Multiparty rotation failed");
}

GENERATE_CKKS_TEST_CASES_FUNC(UTMultiparty, UnitTest_MultiPartyCKKS, ORDER,
                              SCALE, NUMPRIME, RELIN, BATCH)

template <class Element>
static void UnitTest_MultiPartyCKKS_Star(const CryptoContext<Element> cc1,
                                         const string& failmsg) {
  CryptoContext<Element> cc =
      std::static_pointer_cast<CryptoContextImpl<Element>>(cc1);

  double eps = 0.0001;

  LPKeyPair<DCRTPoly> kp1;
  LPKeyPair<DCRTPoly> kp2;
  LPKeyPair<DCRTPoly> kpMultiparty;
  LPPublicKey<DCRTPoly> pubKey;

  kp1 = cc->KeyGen();

  std::vector<int32_t> indices = {2};

  auto evalMultKey = cc->KeySwitchGen(kp1.secretKey, kp1.secretKey);
  cc->EvalSumKeyGen(kp1.secretKey);
  auto evalSumKeys = std::make_shared<std::map<usint, LPEvalKey<DCRTPoly>>>(
      cc->GetEvalSumKeyMap(kp1.secretKey->GetKeyTag()));
  cc->EvalAtIndexKeyGen(kp1.secretKey, indices);
  auto evalAtIndexKeys = std::make_shared<std::map<usint, LPEvalKey<DCRTPoly>>>(
      cc->GetEvalAutomorphismKeyMap(kp1.secretKey->GetKeyTag()));

  kp2 = cc->MultipartyKeyGen(kp1.publicKey, false, true);

  pubKey = cc->MultiAddPubKeys(kp1.publicKey, kp2.publicKey,
                               kp2.publicKey->GetKeyTag());

  auto evalMultKey2 =
      cc->MultiKeySwitchGen(kp2.secretKey, kp2.secretKey, evalMultKey);

  auto evalMultAB = cc->MultiAddEvalKeys(evalMultKey, evalMultKey2,
                                         kp2.publicKey->GetKeyTag());

  auto evalMultBAB = cc->MultiMultEvalKey(evalMultAB, kp2.secretKey,
                                          kp2.publicKey->GetKeyTag());

  auto evalSumKeysB = cc->MultiEvalSumKeyGen(kp2.secretKey, evalSumKeys,
                                             kp2.publicKey->GetKeyTag());
  auto evalSumKeysJoin = cc->MultiAddEvalSumKeys(evalSumKeys, evalSumKeysB,
                                                 kp2.publicKey->GetKeyTag());
  cc->InsertEvalSumKey(evalSumKeysJoin);

  auto evalAtIndexKeysB = cc->MultiEvalAtIndexKeyGen(
      kp2.secretKey, evalAtIndexKeys, indices, kp2.publicKey->GetKeyTag());
  auto evalAtIndexKeysJoin = cc->MultiAddEvalAutomorphismKeys(
      evalAtIndexKeys, evalAtIndexKeysB, kp2.publicKey->GetKeyTag());
  cc->InsertEvalAutomorphismKey(evalAtIndexKeysJoin);

  auto evalMultAAB = cc->MultiMultEvalKey(evalMultAB, kp1.secretKey,
                                          kp2.publicKey->GetKeyTag());
  auto evalMultFinal = cc->MultiAddEvalMultKeys(evalMultAAB, evalMultBAB,
                                                evalMultAB->GetKeyTag());
  cc->InsertEvalMultKey({evalMultFinal});

  vector<LPPrivateKey<DCRTPoly>> secretKeys;
  secretKeys.push_back(kp1.secretKey);
  secretKeys.push_back(kp2.secretKey);

  kpMultiparty = cc->MultipartyKeyGen(secretKeys);

  if (!kpMultiparty.good()) {
    std::cout << "Key generation failed!" << std::endl;
    exit(1);
  }

  ////////////////////////////////////////////////////////////
  // Encode source data
  ////////////////////////////////////////////////////////////
  std::vector<std::complex<double>> vectorOfInts1 = {1, 2, 3, 4, 5, 6,
                                                     5, 4, 3, 2, 1, 0};
  std::vector<std::complex<double>> vectorOfInts2 = {1, 0, 0, 1, 1, 0,
                                                     0, 0, 0, 0, 0, 0};
  std::vector<std::complex<double>> vectorOfInts3 = {2, 2, 3, 4,  5, 6,
                                                     7, 8, 9, 10, 0, 0};

  size_t encodedLength = vectorOfInts1.size();
  std::vector<std::complex<double>> sumInput(encodedLength, {0, 0});
  std::vector<std::complex<double>> multInput(encodedLength, {0, 0});
  std::vector<std::complex<double>> evalSumInput(encodedLength, {0, 0});
  std::vector<std::complex<double>> rotateInput(encodedLength, {0, 0});

  for (usint i = 0; i < encodedLength; i++) {
    sumInput[i] = vectorOfInts1[i] + vectorOfInts2[i] + vectorOfInts3[i];
    multInput[i] = vectorOfInts1[i] * vectorOfInts3[i];
    if (i == 0)
      evalSumInput[encodedLength - i - 1] =
          vectorOfInts3[encodedLength - i - 1];
    else
      evalSumInput[encodedLength - i - 1] =
          evalSumInput[encodedLength - i] +
          vectorOfInts3[encodedLength - i - 1];
    if (i + indices[0] > encodedLength - 1)
      rotateInput[i] = 0;
    else
      rotateInput[i] = vectorOfInts1[i + indices[0]];
  }

  Plaintext plaintext1 = cc->MakeCKKSPackedPlaintext(vectorOfInts1);
  Plaintext plaintext2 = cc->MakeCKKSPackedPlaintext(vectorOfInts2);
  Plaintext plaintext3 = cc->MakeCKKSPackedPlaintext(vectorOfInts3);
  Plaintext plaintextSumInput = cc->MakeCKKSPackedPlaintext(sumInput);
  Plaintext plaintextMultInput = cc->MakeCKKSPackedPlaintext(multInput);
  Plaintext plaintextEvalSumInput = cc->MakeCKKSPackedPlaintext(evalSumInput);
  Plaintext plaintextRotateInput = cc->MakeCKKSPackedPlaintext(rotateInput);

  ////////////////////////////////////////////////////////////
  // Encryption
  ////////////////////////////////////////////////////////////
  Ciphertext<DCRTPoly> ciphertext1 = cc->Encrypt(pubKey, plaintext1);
  Ciphertext<DCRTPoly> ciphertext2 = cc->Encrypt(pubKey, plaintext2);
  Ciphertext<DCRTPoly> ciphertext3 = cc->Encrypt(pubKey, plaintext3);

  ////////////////////////////////////////////////////////////
  // EvalAdd Operation on Re-Encrypted Data
  ////////////////////////////////////////////////////////////
  Ciphertext<DCRTPoly> ciphertextAdd12 = cc->EvalAdd(ciphertext1, ciphertext2);
  Ciphertext<DCRTPoly> ciphertextAdd123 =
      cc->EvalAdd(ciphertextAdd12, ciphertext3);

  auto ciphertextMultTemp = cc->EvalMult(ciphertext1, ciphertext3);
  auto ciphertextMult = cc->ModReduce(ciphertextMultTemp);
  auto ciphertextEvalSum = cc->EvalSum(ciphertext3, BATCH);
  ciphertext1 = cc->EvalMult(ciphertext1, 1);
  auto ciphertextRotate = cc->EvalAtIndex(ciphertext1, indices[0]);

  ////////////////////////////////////////////////////////////
  // Decryption after Accumulation Operation on Encrypted Data
  ////////////////////////////////////////////////////////////
  Plaintext plaintextAddNew;
  cc->Decrypt(kpMultiparty.secretKey, ciphertextAdd123, &plaintextAddNew);
  plaintextAddNew->SetLength(plaintext1->GetLength());

  auto tmp_a = plaintextAddNew->GetCKKSPackedValue();
  auto tmp_b = plaintextSumInput->GetCKKSPackedValue();
  checkApproximateEquality(tmp_a, tmp_b, encodedLength, eps,
                           failmsg + " accumulation failed");

  Plaintext plaintextMult;
  cc->Decrypt(kpMultiparty.secretKey, ciphertextMult, &plaintextMult);
  plaintextMult->SetLength(plaintext1->GetLength());

  tmp_a = plaintextMult->GetCKKSPackedValue();
  tmp_b = plaintextMultInput->GetCKKSPackedValue();
  checkApproximateEquality(tmp_a, tmp_b, encodedLength, eps,
                           failmsg + " multiplication failed");

  Plaintext plaintextRotate;
  cc->Decrypt(kpMultiparty.secretKey, ciphertextRotate, &plaintextRotate);
  plaintextRotate->SetLength(plaintext1->GetLength());

  tmp_a = plaintextRotate->GetCKKSPackedValue();
  tmp_b = plaintextRotateInput->GetCKKSPackedValue();
  checkApproximateEquality(tmp_a, tmp_b, encodedLength, eps,
                           failmsg + " rotation failed");

  ////////////////////////////////////////////////////////////
  // Decryption after Accumulation Operation on Encrypted Data with Multiparty
  ////////////////////////////////////////////////////////////
  Plaintext plaintextMultipartyNew;

  const shared_ptr<LPCryptoParameters<DCRTPoly>> cryptoParams =
      kp1.secretKey->GetCryptoParameters();
  const shared_ptr<typename DCRTPoly::Params> elementParams =
      cryptoParams->GetElementParams();

  auto ciphertextPartial1 =
      cc->MultipartyDecryptLead(kp1.secretKey, {ciphertextAdd123});
  auto ciphertextPartial2 =
      cc->MultipartyDecryptMain(kp2.secretKey, {ciphertextAdd123});

  vector<Ciphertext<DCRTPoly>> partialCiphertextVec;
  partialCiphertextVec.push_back(ciphertextPartial1[0]);
  partialCiphertextVec.push_back(ciphertextPartial2[0]);

  cc->MultipartyDecryptFusion(partialCiphertextVec, &plaintextMultipartyNew);
  plaintextMultipartyNew->SetLength(plaintext1->GetLength());

  tmp_a = plaintextMultipartyNew->GetCKKSPackedValue();
  tmp_b = plaintextSumInput->GetCKKSPackedValue();
  checkApproximateEquality(tmp_a, tmp_b, encodedLength, eps,
                           failmsg + " Multiparty accumulation failed");

  Plaintext plaintextMultipartyMult;
  ciphertextPartial1 =
      cc->MultipartyDecryptLead(kp1.secretKey, {ciphertextMult});
  ciphertextPartial2 =
      cc->MultipartyDecryptMain(kp2.secretKey, {ciphertextMult});

  vector<Ciphertext<DCRTPoly>> partialCiphertextVecMult;
  partialCiphertextVecMult.push_back(ciphertextPartial1[0]);
  partialCiphertextVecMult.push_back(ciphertextPartial2[0]);

  cc->MultipartyDecryptFusion(partialCiphertextVecMult,
                              &plaintextMultipartyMult);
  plaintextMultipartyMult->SetLength(plaintext1->GetLength());

  tmp_a = plaintextMultipartyMult->GetCKKSPackedValue();
  tmp_b = plaintextMultInput->GetCKKSPackedValue();
  checkApproximateEquality(tmp_a, tmp_b, encodedLength, eps,
                           failmsg + " Multiparty multiplication failed");

  Plaintext plaintextMultipartyEvalSum;
  ciphertextPartial1 =
      cc->MultipartyDecryptLead(kp1.secretKey, {ciphertextEvalSum});
  ciphertextPartial2 =
      cc->MultipartyDecryptMain(kp2.secretKey, {ciphertextEvalSum});

  vector<Ciphertext<DCRTPoly>> partialCiphertextVecEvalSum;
  partialCiphertextVecEvalSum.push_back(ciphertextPartial1[0]);
  partialCiphertextVecEvalSum.push_back(ciphertextPartial2[0]);

  cc->MultipartyDecryptFusion(partialCiphertextVecEvalSum,
                              &plaintextMultipartyEvalSum);
  plaintextMultipartyEvalSum->SetLength(plaintext1->GetLength());

  tmp_a = plaintextMultipartyEvalSum->GetCKKSPackedValue();
  tmp_b = plaintextEvalSumInput->GetCKKSPackedValue();
  checkApproximateEquality(tmp_a, tmp_b, encodedLength, eps,
                           failmsg + " Multiparty eval sum failed");

  Plaintext plaintextMultipartyRotate;
  ciphertextPartial1 =
      cc->MultipartyDecryptLead(kp1.secretKey, {ciphertextRotate});
  ciphertextPartial2 =
      cc->MultipartyDecryptMain(kp2.secretKey, {ciphertextRotate});

  vector<Ciphertext<DCRTPoly>> partialCiphertextVecRotate;
  partialCiphertextVecRotate.push_back(ciphertextPartial1[0]);
  partialCiphertextVecRotate.push_back(ciphertextPartial2[0]);

  cc->MultipartyDecryptFusion(partialCiphertextVecRotate,
                              &plaintextMultipartyRotate);
  plaintextMultipartyRotate->SetLength(plaintext1->GetLength());

  tmp_a = plaintextMultipartyRotate->GetCKKSPackedValue();
  tmp_b = plaintextRotateInput->GetCKKSPackedValue();
  checkApproximateEquality(tmp_a, tmp_b, encodedLength, eps,
                           failmsg + " Multiparty rotation failed");
}

GENERATE_CKKS_TEST_CASES_FUNC(UTMultiparty, UnitTest_MultiPartyCKKS_Star, ORDER,
                              SCALE, NUMPRIME, RELIN, BATCH)

template <class Element>
static void UnitTest_MultiParty(const CryptoContext<Element> cc1,
                                const string& failmsg) {
  CryptoContext<Element> cc =
      std::static_pointer_cast<CryptoContextImpl<Element>>(cc1);

  cc->Enable(MULTIPARTY);

  LPKeyPair<Element> kp1;
  LPKeyPair<Element> kp2;
  LPKeyPair<Element> kpMultiparty;

  kp1 = cc->KeyGen();

  std::vector<int32_t> indices = {2};

  auto evalMultKey = cc->KeySwitchGen(kp1.secretKey, kp1.secretKey);
  cc->EvalSumKeyGen(kp1.secretKey);
  cc->EvalAtIndexKeyGen(kp1.secretKey, indices);
  auto evalSumKeys = std::make_shared<std::map<usint, LPEvalKey<Element>>>(
      cc->GetEvalSumKeyMap(kp1.secretKey->GetKeyTag()));
  auto evalAtIndexKeys = std::make_shared<std::map<usint, LPEvalKey<Element>>>(
      cc->GetEvalAutomorphismKeyMap(kp1.secretKey->GetKeyTag()));
  kp2 = cc->MultipartyKeyGen(kp1.publicKey);
  auto evalMultKey2 =
      cc->MultiKeySwitchGen(kp2.secretKey, kp2.secretKey, evalMultKey);
  auto evalMultAB = cc->MultiAddEvalKeys(evalMultKey, evalMultKey2,
                                         kp2.publicKey->GetKeyTag());
  auto evalMultBAB = cc->MultiMultEvalKey(evalMultAB, kp2.secretKey,
                                          kp2.publicKey->GetKeyTag());
  auto evalSumKeysB = cc->MultiEvalSumKeyGen(kp2.secretKey, evalSumKeys,
                                             kp2.publicKey->GetKeyTag());
  auto evalSumKeysJoin = cc->MultiAddEvalSumKeys(evalSumKeys, evalSumKeysB,
                                                 kp2.publicKey->GetKeyTag());
  cc->InsertEvalSumKey(evalSumKeysJoin);

  auto evalAtIndexKeysB = cc->MultiEvalAtIndexKeyGen(
      kp2.secretKey, evalAtIndexKeys, indices, kp2.publicKey->GetKeyTag());
  auto evalAtIndexKeysJoin = cc->MultiAddEvalAutomorphismKeys(
      evalAtIndexKeys, evalAtIndexKeysB, kp2.publicKey->GetKeyTag());
  cc->InsertEvalAutomorphismKey(evalAtIndexKeysJoin);

  auto evalMultAAB = cc->MultiMultEvalKey(evalMultAB, kp1.secretKey,
                                          kp2.publicKey->GetKeyTag());
  auto evalMultFinal = cc->MultiAddEvalMultKeys(evalMultAAB, evalMultBAB,
                                                kp2.publicKey->GetKeyTag());
  cc->InsertEvalMultKey({evalMultFinal});

  vector<LPPrivateKey<Element>> secretKeys;
  secretKeys.push_back(kp1.secretKey);
  secretKeys.push_back(kp2.secretKey);

  kpMultiparty = cc->MultipartyKeyGen(secretKeys);

  if (!kpMultiparty.good()) {
    std::cout << "Key generation failed!" << std::endl;
    exit(1);
  }

  ////////////////////////////////////////////////////////////
  // Encode source data
  ////////////////////////////////////////////////////////////
  std::vector<int64_t> vectorOfInts1 = {1, 2, 3, 4, 5, 6, 5, 4, 3, 2, 1, 0};
  std::vector<int64_t> vectorOfInts2 = {1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0};
  std::vector<int64_t> vectorOfInts3 = {2, 2, 3, 4, 5, 6, 7, 8, 9, 10, 0, 0};

  size_t encodedLength = vectorOfInts1.size();
  std::vector<int64_t> sumInput(encodedLength, 0);
  std::vector<int64_t> multInput(encodedLength, 0);
  std::vector<int64_t> evalSumInput(encodedLength, 0);
  std::vector<int64_t> rotateInput(encodedLength, 0);

  for (usint i = 0; i < encodedLength; i++) {
    sumInput[i] = vectorOfInts1[i] + vectorOfInts2[i] + vectorOfInts3[i];
    multInput[i] = vectorOfInts1[i] * vectorOfInts3[i];
    if (i == 0)
      evalSumInput[encodedLength - i - 1] =
          vectorOfInts3[encodedLength - i - 1];
    else
      evalSumInput[encodedLength - i - 1] =
          evalSumInput[encodedLength - i] +
          vectorOfInts3[encodedLength - i - 1];
    if (i + indices[0] > encodedLength - 1)
      rotateInput[i] = 0;
    else
      rotateInput[i] = vectorOfInts1[i + indices[0]];
  }

  Plaintext plaintext1 = cc->MakePackedPlaintext(vectorOfInts1);
  Plaintext plaintext2 = cc->MakePackedPlaintext(vectorOfInts2);
  Plaintext plaintext3 = cc->MakePackedPlaintext(vectorOfInts3);
  Plaintext plaintextSumInput = cc->MakePackedPlaintext(sumInput);
  Plaintext plaintextMultInput = cc->MakePackedPlaintext(multInput);
  Plaintext plaintextEvalSumInput = cc->MakePackedPlaintext(evalSumInput);
  Plaintext plaintextRotateInput = cc->MakePackedPlaintext(rotateInput);

  ////////////////////////////////////////////////////////////
  // Encryption
  ////////////////////////////////////////////////////////////
  Ciphertext<Element> ciphertext1;
  Ciphertext<Element> ciphertext2;
  Ciphertext<Element> ciphertext3;

  ciphertext1 = cc->Encrypt(kp2.publicKey, plaintext1);
  ciphertext2 = cc->Encrypt(kp2.publicKey, plaintext2);
  ciphertext3 = cc->Encrypt(kp2.publicKey, plaintext3);

  ////////////////////////////////////////////////////////////
  // EvalAdd Operation on Re-Encrypted Data
  ////////////////////////////////////////////////////////////

  Ciphertext<Element> ciphertextAdd12;
  Ciphertext<Element> ciphertextAdd123;

  ciphertextAdd12 = cc->EvalAdd(ciphertext1, ciphertext2);
  ciphertextAdd123 = cc->EvalAdd(ciphertextAdd12, ciphertext3);

  auto ciphertextMult = cc->EvalMult(ciphertext1, ciphertext3);
  auto ciphertextEvalSum = cc->EvalSum(ciphertext3, BATCH);
  auto ciphertextRotate = cc->EvalAtIndex(ciphertext1, indices[0]);

  ////////////////////////////////////////////////////////////
  // Decryption after Accumulation Operation on Encrypted Data
  ////////////////////////////////////////////////////////////
  Plaintext plaintextAddNew;
  cc->Decrypt(kpMultiparty.secretKey, ciphertextAdd123, &plaintextAddNew);
  plaintextAddNew->SetLength(plaintext1->GetLength());

  auto tmp_a = plaintextAddNew->GetPackedValue();
  auto tmp_b = plaintextSumInput->GetPackedValue();
  EXPECT_EQ(tmp_a, tmp_b) << failmsg << " accumulation fails";

  Plaintext plaintextMult;
  cc->Decrypt(kpMultiparty.secretKey, ciphertextMult, &plaintextMult);
  plaintextMult->SetLength(plaintext1->GetLength());

  tmp_a = plaintextMult->GetPackedValue();
  tmp_b = plaintextMultInput->GetPackedValue();
  EXPECT_EQ(tmp_a, tmp_b) << failmsg << " multiplication fails";

  Plaintext plaintextRotate;
  cc->Decrypt(kpMultiparty.secretKey, ciphertextRotate, &plaintextRotate);
  plaintextRotate->SetLength(plaintext1->GetLength());

  tmp_a = plaintextRotate->GetPackedValue();
  tmp_b = plaintextRotateInput->GetPackedValue();
  EXPECT_EQ(tmp_a, tmp_b) << failmsg << "rotation fails";

  ////////////////////////////////////////////////////////////
  // Decryption after Accumulation Operation on Encrypted Data with Multiparty
  ////////////////////////////////////////////////////////////

  Plaintext plaintextAddNew1;
  Plaintext plaintextAddNew2;
  Plaintext plaintextAddNew3;
  Element partialPlaintext1;
  Element partialPlaintext2;
  Element partialPlaintext3;
  Plaintext plaintextMultipartyNew;

  const shared_ptr<LPCryptoParameters<Element>> cryptoParams =
      kp1.secretKey->GetCryptoParameters();
  const shared_ptr<typename Element::Params> elementParams =
      cryptoParams->GetElementParams();

  auto ciphertextPartial1 =
      cc->MultipartyDecryptLead(kp1.secretKey, {ciphertextAdd123});

  auto ciphertextPartial2 =
      cc->MultipartyDecryptMain(kp2.secretKey, {ciphertextAdd123});

  vector<Ciphertext<Element>> partialCiphertextVec;
  partialCiphertextVec.push_back(ciphertextPartial1[0]);
  partialCiphertextVec.push_back(ciphertextPartial2[0]);

  cc->MultipartyDecryptFusion(partialCiphertextVec, &plaintextMultipartyNew);
  plaintextMultipartyNew->SetLength(plaintext1->GetLength());

  tmp_a = plaintextMultipartyNew->GetPackedValue();
  tmp_b = plaintextSumInput->GetPackedValue();
  EXPECT_EQ(tmp_a, tmp_b) << failmsg << " Multiparty accumulation fails";

  Plaintext plaintextMultipartyMult;
  ciphertextPartial1 =
      cc->MultipartyDecryptLead(kp1.secretKey, {ciphertextMult});
  ciphertextPartial2 =
      cc->MultipartyDecryptMain(kp2.secretKey, {ciphertextMult});

  vector<Ciphertext<Element>> partialCiphertextVecMult;
  partialCiphertextVecMult.push_back(ciphertextPartial1[0]);
  partialCiphertextVecMult.push_back(ciphertextPartial2[0]);

  cc->MultipartyDecryptFusion(partialCiphertextVecMult,
                              &plaintextMultipartyMult);
  plaintextMultipartyMult->SetLength(plaintext1->GetLength());

  tmp_a = plaintextMultipartyMult->GetPackedValue();
  tmp_b = plaintextMultInput->GetPackedValue();
  EXPECT_EQ(tmp_a, tmp_b) << failmsg << " Multiparty multiplication fails";

  Plaintext plaintextMultipartyRotate;
  ciphertextPartial1 =
      cc->MultipartyDecryptLead(kp1.secretKey, {ciphertextRotate});
  ciphertextPartial2 =
      cc->MultipartyDecryptMain(kp2.secretKey, {ciphertextRotate});

  vector<Ciphertext<Element>> partialCiphertextVecRotate;
  partialCiphertextVecRotate.push_back(ciphertextPartial1[0]);
  partialCiphertextVecRotate.push_back(ciphertextPartial2[0]);

  cc->MultipartyDecryptFusion(partialCiphertextVecRotate,
                              &plaintextMultipartyRotate);
  plaintextMultipartyRotate->SetLength(plaintext1->GetLength());

  tmp_a = plaintextMultipartyRotate->GetPackedValue();
  tmp_b = plaintextRotateInput->GetPackedValue();

  EXPECT_EQ(tmp_a, tmp_b) << failmsg << " Multiparty rotation fails";

  Plaintext plaintextMultipartyEvalSum;
  ciphertextPartial1 =
      cc->MultipartyDecryptLead(kp1.secretKey, {ciphertextEvalSum});
  ciphertextPartial2 =
      cc->MultipartyDecryptMain(kp2.secretKey, {ciphertextEvalSum});

  vector<Ciphertext<DCRTPoly>> partialCiphertextVecEvalSum;
  partialCiphertextVecEvalSum.push_back(ciphertextPartial1[0]);
  partialCiphertextVecEvalSum.push_back(ciphertextPartial2[0]);

  cc->MultipartyDecryptFusion(partialCiphertextVecEvalSum,
                              &plaintextMultipartyEvalSum);
  plaintextMultipartyEvalSum->SetLength(plaintext1->GetLength());

  tmp_a = plaintextMultipartyEvalSum->GetPackedValue();
  tmp_b = plaintextEvalSumInput->GetPackedValue();
  EXPECT_EQ(tmp_a, tmp_b) << failmsg << " Multiparty eval sum fails";
}

GENERATE_TEST_CASES_FUNC_RNS(UTMultiparty, UnitTest_MultiParty, 512 /*ORDER*/,
                             65537 /*PTM*/, BATCH)

template <class Element>
static void UnitTest_MultiParty_Star(const CryptoContext<Element> cc1,
                                     const string& failmsg) {
  CryptoContext<Element> cc =
      std::static_pointer_cast<CryptoContextImpl<Element>>(cc1);

  cc->Enable(MULTIPARTY);

  LPKeyPair<Element> kp1;
  LPKeyPair<Element> kp2;
  LPKeyPair<Element> kpMultiparty;
  LPPublicKey<Element> pubKey;

  kp1 = cc->KeyGen();

  std::vector<int32_t> indices = {2};

  auto evalMultKey = cc->KeySwitchGen(kp1.secretKey, kp1.secretKey);
  cc->EvalSumKeyGen(kp1.secretKey);
  cc->EvalAtIndexKeyGen(kp1.secretKey, indices);
  auto evalSumKeys = std::make_shared<std::map<usint, LPEvalKey<Element>>>(
      cc->GetEvalSumKeyMap(kp1.secretKey->GetKeyTag()));
  auto evalAtIndexKeys = std::make_shared<std::map<usint, LPEvalKey<Element>>>(
      cc->GetEvalAutomorphismKeyMap(kp1.secretKey->GetKeyTag()));
  kp2 = cc->MultipartyKeyGen(kp1.publicKey, false, true);

  pubKey = cc->MultiAddPubKeys(kp1.publicKey, kp2.publicKey,
                               kp2.publicKey->GetKeyTag());

  auto evalMultKey2 =
      cc->MultiKeySwitchGen(kp2.secretKey, kp2.secretKey, evalMultKey);
  auto evalMultAB = cc->MultiAddEvalKeys(evalMultKey, evalMultKey2,
                                         kp2.publicKey->GetKeyTag());
  auto evalMultBAB = cc->MultiMultEvalKey(evalMultAB, kp2.secretKey,
                                          kp2.publicKey->GetKeyTag());
  auto evalSumKeysB = cc->MultiEvalSumKeyGen(kp2.secretKey, evalSumKeys,
                                             kp2.publicKey->GetKeyTag());
  auto evalSumKeysJoin = cc->MultiAddEvalSumKeys(evalSumKeys, evalSumKeysB,
                                                 kp2.publicKey->GetKeyTag());
  cc->InsertEvalSumKey(evalSumKeysJoin);

  auto evalAtIndexKeysB = cc->MultiEvalAtIndexKeyGen(
      kp2.secretKey, evalAtIndexKeys, indices, kp2.publicKey->GetKeyTag());
  auto evalAtIndexKeysJoin = cc->MultiAddEvalAutomorphismKeys(
      evalAtIndexKeys, evalAtIndexKeysB, kp2.publicKey->GetKeyTag());
  cc->InsertEvalAutomorphismKey(evalAtIndexKeysJoin);

  auto evalMultAAB = cc->MultiMultEvalKey(evalMultAB, kp1.secretKey,
                                          kp2.publicKey->GetKeyTag());
  auto evalMultFinal = cc->MultiAddEvalMultKeys(evalMultAAB, evalMultBAB,
                                                kp2.publicKey->GetKeyTag());
  cc->InsertEvalMultKey({evalMultFinal});

  vector<LPPrivateKey<Element>> secretKeys;
  secretKeys.push_back(kp1.secretKey);
  secretKeys.push_back(kp2.secretKey);

  kpMultiparty = cc->MultipartyKeyGen(secretKeys);

  if (!kpMultiparty.good()) {
    std::cout << "Key generation failed!" << std::endl;
    exit(1);
  }

  ////////////////////////////////////////////////////////////
  // Encode source data
  ////////////////////////////////////////////////////////////
  std::vector<int64_t> vectorOfInts1 = {1, 2, 3, 4, 5, 6, 5, 4, 3, 2, 1, 0};
  std::vector<int64_t> vectorOfInts2 = {1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0};
  std::vector<int64_t> vectorOfInts3 = {2, 2, 3, 4, 5, 6, 7, 8, 9, 10, 0, 0};

  size_t encodedLength = vectorOfInts1.size();
  std::vector<int64_t> sumInput(encodedLength, 0);
  std::vector<int64_t> multInput(encodedLength, 0);
  std::vector<int64_t> evalSumInput(encodedLength, 0);
  std::vector<int64_t> rotateInput(encodedLength, 0);

  for (usint i = 0; i < encodedLength; i++) {
    sumInput[i] = vectorOfInts1[i] + vectorOfInts2[i] + vectorOfInts3[i];
    multInput[i] = vectorOfInts1[i] * vectorOfInts3[i];
    if (i == 0)
      evalSumInput[encodedLength - i - 1] =
          vectorOfInts3[encodedLength - i - 1];
    else
      evalSumInput[encodedLength - i - 1] =
          evalSumInput[encodedLength - i] +
          vectorOfInts3[encodedLength - i - 1];
    if (i + indices[0] > encodedLength - 1)
      rotateInput[i] = 0;
    else
      rotateInput[i] = vectorOfInts1[i + indices[0]];
  }

  Plaintext plaintext1 = cc->MakePackedPlaintext(vectorOfInts1);
  Plaintext plaintext2 = cc->MakePackedPlaintext(vectorOfInts2);
  Plaintext plaintext3 = cc->MakePackedPlaintext(vectorOfInts3);
  Plaintext plaintextSumInput = cc->MakePackedPlaintext(sumInput);
  Plaintext plaintextMultInput = cc->MakePackedPlaintext(multInput);
  Plaintext plaintextEvalSumInput = cc->MakePackedPlaintext(evalSumInput);
  Plaintext plaintextRotateInput = cc->MakePackedPlaintext(rotateInput);

  ////////////////////////////////////////////////////////////
  // Encryption
  ////////////////////////////////////////////////////////////
  Ciphertext<Element> ciphertext1;
  Ciphertext<Element> ciphertext2;
  Ciphertext<Element> ciphertext3;

  ciphertext1 = cc->Encrypt(pubKey, plaintext1);
  ciphertext2 = cc->Encrypt(pubKey, plaintext2);
  ciphertext3 = cc->Encrypt(pubKey, plaintext3);

  ////////////////////////////////////////////////////////////
  // EvalAdd Operation on Re-Encrypted Data
  ////////////////////////////////////////////////////////////

  Ciphertext<Element> ciphertextAdd12;
  Ciphertext<Element> ciphertextAdd123;

  ciphertextAdd12 = cc->EvalAdd(ciphertext1, ciphertext2);
  ciphertextAdd123 = cc->EvalAdd(ciphertextAdd12, ciphertext3);

  auto ciphertextMult = cc->EvalMult(ciphertext1, ciphertext3);
  auto ciphertextEvalSum = cc->EvalSum(ciphertext3, BATCH);
  auto ciphertextRotate = cc->EvalAtIndex(ciphertext1, indices[0]);

  ////////////////////////////////////////////////////////////
  // Decryption after Accumulation Operation on Encrypted Data
  ////////////////////////////////////////////////////////////
  Plaintext plaintextAddNew;
  cc->Decrypt(kpMultiparty.secretKey, ciphertextAdd123, &plaintextAddNew);
  plaintextAddNew->SetLength(plaintext1->GetLength());

  auto tmp_a = plaintextAddNew->GetPackedValue();
  auto tmp_b = plaintextSumInput->GetPackedValue();
  EXPECT_EQ(tmp_a, tmp_b) << failmsg << " accumulation fails";

  Plaintext plaintextMult;
  cc->Decrypt(kpMultiparty.secretKey, ciphertextMult, &plaintextMult);
  plaintextMult->SetLength(plaintext1->GetLength());

  tmp_a = plaintextMult->GetPackedValue();
  tmp_b = plaintextMultInput->GetPackedValue();
  EXPECT_EQ(tmp_a, tmp_b) << failmsg << " multiplication fails";

  Plaintext plaintextRotate;
  cc->Decrypt(kpMultiparty.secretKey, ciphertextRotate, &plaintextRotate);
  plaintextRotate->SetLength(plaintext1->GetLength());

  tmp_a = plaintextRotate->GetPackedValue();
  tmp_b = plaintextRotateInput->GetPackedValue();
  EXPECT_EQ(tmp_a, tmp_b) << failmsg << "rotation fails";

  ////////////////////////////////////////////////////////////
  // Decryption after Accumulation Operation on Encrypted Data with Multiparty
  ////////////////////////////////////////////////////////////

  Plaintext plaintextAddNew1;
  Plaintext plaintextAddNew2;
  Plaintext plaintextAddNew3;
  Element partialPlaintext1;
  Element partialPlaintext2;
  Element partialPlaintext3;
  Plaintext plaintextMultipartyNew;

  const shared_ptr<LPCryptoParameters<Element>> cryptoParams =
      kp1.secretKey->GetCryptoParameters();
  const shared_ptr<typename Element::Params> elementParams =
      cryptoParams->GetElementParams();

  auto ciphertextPartial1 =
      cc->MultipartyDecryptLead(kp1.secretKey, {ciphertextAdd123});

  auto ciphertextPartial2 =
      cc->MultipartyDecryptMain(kp2.secretKey, {ciphertextAdd123});

  vector<Ciphertext<Element>> partialCiphertextVec;
  partialCiphertextVec.push_back(ciphertextPartial1[0]);
  partialCiphertextVec.push_back(ciphertextPartial2[0]);

  cc->MultipartyDecryptFusion(partialCiphertextVec, &plaintextMultipartyNew);
  plaintextMultipartyNew->SetLength(plaintext1->GetLength());

  tmp_a = plaintextMultipartyNew->GetPackedValue();
  tmp_b = plaintextSumInput->GetPackedValue();
  EXPECT_EQ(tmp_a, tmp_b) << failmsg << " Multiparty accumulation fails";

  if (cc->getSchemeId() == "BGVrns")
    ciphertextMult = cc->Compress(ciphertextMult,1);

  Plaintext plaintextMultipartyMult;
  ciphertextPartial1 =
      cc->MultipartyDecryptLead(kp1.secretKey, {ciphertextMult});
  ciphertextPartial2 =
      cc->MultipartyDecryptMain(kp2.secretKey, {ciphertextMult});

  vector<Ciphertext<Element>> partialCiphertextVecMult;
  partialCiphertextVecMult.push_back(ciphertextPartial1[0]);
  partialCiphertextVecMult.push_back(ciphertextPartial2[0]);

  cc->MultipartyDecryptFusion(partialCiphertextVecMult,
                              &plaintextMultipartyMult);
  plaintextMultipartyMult->SetLength(plaintext1->GetLength());

  tmp_a = plaintextMultipartyMult->GetPackedValue();
  tmp_b = plaintextMultInput->GetPackedValue();
  EXPECT_EQ(tmp_a, tmp_b) << failmsg << " Multiparty multiplication fails";

  Plaintext plaintextMultipartyRotate;
  ciphertextPartial1 =
      cc->MultipartyDecryptLead(kp1.secretKey, {ciphertextRotate});
  ciphertextPartial2 =
      cc->MultipartyDecryptMain(kp2.secretKey, {ciphertextRotate});

  vector<Ciphertext<Element>> partialCiphertextVecRotate;
  partialCiphertextVecRotate.push_back(ciphertextPartial1[0]);
  partialCiphertextVecRotate.push_back(ciphertextPartial2[0]);

  cc->MultipartyDecryptFusion(partialCiphertextVecRotate,
                              &plaintextMultipartyRotate);
  plaintextMultipartyRotate->SetLength(plaintext1->GetLength());

  tmp_a = plaintextMultipartyRotate->GetPackedValue();
  tmp_b = plaintextRotateInput->GetPackedValue();

  EXPECT_EQ(tmp_a, tmp_b) << failmsg << " Multiparty rotation fails";

  Plaintext plaintextMultipartyEvalSum;
  ciphertextPartial1 =
      cc->MultipartyDecryptLead(kp1.secretKey, {ciphertextEvalSum});
  ciphertextPartial2 =
      cc->MultipartyDecryptMain(kp2.secretKey, {ciphertextEvalSum});

  vector<Ciphertext<DCRTPoly>> partialCiphertextVecEvalSum;
  partialCiphertextVecEvalSum.push_back(ciphertextPartial1[0]);
  partialCiphertextVecEvalSum.push_back(ciphertextPartial2[0]);

  cc->MultipartyDecryptFusion(partialCiphertextVecEvalSum,
                              &plaintextMultipartyEvalSum);
  plaintextMultipartyEvalSum->SetLength(plaintext1->GetLength());

  tmp_a = plaintextMultipartyEvalSum->GetPackedValue();
  tmp_b = plaintextEvalSumInput->GetPackedValue();
  EXPECT_EQ(tmp_a, tmp_b) << failmsg << " Multiparty eval sum fails";
}

GENERATE_TEST_CASES_FUNC_RNS(UTMultiparty, UnitTest_MultiParty_Star,
                             512 /*ORDER*/, 65537 /*PTM*/, BATCH)

template <class Element>
static void UnitTest_MultiParty_MP(const CryptoContext<Element> cc1,
                                   const string& failmsg) {
  CryptoContext<Element> cc =
      std::static_pointer_cast<CryptoContextImpl<Element>>(cc1);

  cc->Enable(MULTIPARTY);

  LPKeyPair<Element> kp1;
  LPKeyPair<Element> kp2;
  LPKeyPair<Element> kpMultiparty;

  kp1 = cc->KeyGen();

  std::vector<int32_t> indices = {2};

  auto evalMultKey = cc->KeySwitchGen(kp1.secretKey, kp1.secretKey);
  cc->EvalAtIndexKeyGen(kp1.secretKey, indices);
  auto evalAtIndexKeys = std::make_shared<std::map<usint, LPEvalKey<Element>>>(
      cc->GetEvalAutomorphismKeyMap(kp1.secretKey->GetKeyTag()));

  kp2 = cc->MultipartyKeyGen(kp1.publicKey);
  auto evalMultKey2 =
      cc->MultiKeySwitchGen(kp2.secretKey, kp2.secretKey, evalMultKey);
  auto evalMultAB = cc->MultiAddEvalKeys(evalMultKey, evalMultKey2,
                                         kp2.publicKey->GetKeyTag());

  auto evalMultBAB = cc->MultiMultEvalKey(evalMultAB, kp2.secretKey,
                                          kp2.publicKey->GetKeyTag());

  auto evalAtIndexKeysB = cc->MultiEvalAtIndexKeyGen(
      kp2.secretKey, evalAtIndexKeys, indices, kp2.publicKey->GetKeyTag());
  auto evalAtIndexKeysJoin = cc->MultiAddEvalAutomorphismKeys(
      evalAtIndexKeys, evalAtIndexKeysB, kp2.publicKey->GetKeyTag());
  cc->InsertEvalAutomorphismKey(evalAtIndexKeysJoin);

  auto evalMultAAB = cc->MultiMultEvalKey(evalMultAB, kp1.secretKey,
                                          kp2.publicKey->GetKeyTag());
  auto evalMultFinal = cc->MultiAddEvalMultKeys(evalMultAAB, evalMultBAB,
                                                kp2.publicKey->GetKeyTag());
  cc->InsertEvalMultKey({evalMultFinal});

  vector<LPPrivateKey<Element>> secretKeys;
  secretKeys.push_back(kp1.secretKey);
  secretKeys.push_back(kp2.secretKey);

  kpMultiparty = cc->MultipartyKeyGen(secretKeys);

  if (!kpMultiparty.good()) {
    std::cout << "Key generation failed!" << std::endl;
    exit(1);
  }

  ////////////////////////////////////////////////////////////
  // Encode source data
  ////////////////////////////////////////////////////////////
  std::vector<int64_t> vectorOfInts1 = {1, 2, 3, 4, 5, 6, 5, 4, 3, 2, 1, 0};
  std::vector<int64_t> vectorOfInts2 = {1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0};
  std::vector<int64_t> vectorOfInts3 = {2, 2, 3, 4, 5, 6, 7, 8, 9, 10, 0, 0};

  size_t encodedLength = vectorOfInts1.size();
  std::vector<int64_t> sumInput(encodedLength, 0);
  std::vector<int64_t> multInput(encodedLength, 0);
  std::vector<int64_t> evalSumInput(encodedLength, 0);
  std::vector<int64_t> rotateInput(encodedLength, 0);

  for (usint i = 0; i < encodedLength; i++) {
    sumInput[i] = vectorOfInts1[i] + vectorOfInts2[i] + vectorOfInts3[i];
    multInput[i] = vectorOfInts1[i] * vectorOfInts3[i];
    if (i == 0)
      evalSumInput[encodedLength - i - 1] =
          vectorOfInts3[encodedLength - i - 1];
    else
      evalSumInput[encodedLength - i - 1] =
          evalSumInput[encodedLength - i] +
          vectorOfInts3[encodedLength - i - 1];
    if (i + indices[0] > encodedLength - 1)
      rotateInput[i] = 0;
    else
      rotateInput[i] = vectorOfInts1[i + indices[0]];
  }

  Plaintext plaintext1 = cc->MakePackedPlaintext(vectorOfInts1);
  Plaintext plaintext2 = cc->MakePackedPlaintext(vectorOfInts2);
  Plaintext plaintext3 = cc->MakePackedPlaintext(vectorOfInts3);
  Plaintext plaintextSumInput = cc->MakePackedPlaintext(sumInput);
  Plaintext plaintextMultInput = cc->MakePackedPlaintext(multInput);
  Plaintext plaintextRotateInput = cc->MakePackedPlaintext(rotateInput);

  ////////////////////////////////////////////////////////////
  // Encryption
  ////////////////////////////////////////////////////////////
  Ciphertext<Element> ciphertext1;
  Ciphertext<Element> ciphertext2;
  Ciphertext<Element> ciphertext3;

  ciphertext1 = cc->Encrypt(kp2.publicKey, plaintext1);
  ciphertext2 = cc->Encrypt(kp2.publicKey, plaintext2);
  ciphertext3 = cc->Encrypt(kp2.publicKey, plaintext3);

  ////////////////////////////////////////////////////////////
  // EvalAdd Operation on Re-Encrypted Data
  ////////////////////////////////////////////////////////////

  Ciphertext<Element> ciphertextAdd12;
  Ciphertext<Element> ciphertextAdd123;

  ciphertextAdd12 = cc->EvalAdd(ciphertext1, ciphertext2);
  ciphertextAdd123 = cc->EvalAdd(ciphertextAdd12, ciphertext3);

  auto ciphertextMult = cc->EvalMult(ciphertext1, ciphertext3);
  auto ciphertextRotate = cc->EvalAtIndex(ciphertext1, indices[0]);

  ////////////////////////////////////////////////////////////
  // Decryption after Accumulation Operation on Encrypted Data
  ////////////////////////////////////////////////////////////
  Plaintext plaintextAddNew;
  cc->Decrypt(kpMultiparty.secretKey, ciphertextAdd123, &plaintextAddNew);
  plaintextAddNew->SetLength(plaintext1->GetLength());

  auto tmp_a = plaintextAddNew->GetPackedValue();
  auto tmp_b = plaintextSumInput->GetPackedValue();
  EXPECT_EQ(tmp_a, tmp_b) << failmsg << " accumulation fails";

  Plaintext plaintextMult;
  cc->Decrypt(kpMultiparty.secretKey, ciphertextMult, &plaintextMult);
  plaintextMult->SetLength(plaintext1->GetLength());

  tmp_a = plaintextMult->GetPackedValue();
  tmp_b = plaintextMultInput->GetPackedValue();
  EXPECT_EQ(tmp_a, tmp_b) << failmsg << " multiplication fails";

  Plaintext plaintextRotate;
  cc->Decrypt(kpMultiparty.secretKey, ciphertextRotate, &plaintextRotate);
  plaintextRotate->SetLength(plaintext1->GetLength());

  tmp_a = plaintextRotate->GetPackedValue();
  tmp_b = plaintextRotateInput->GetPackedValue();
  EXPECT_EQ(tmp_a, tmp_b) << failmsg << "rotation fails";

  ////////////////////////////////////////////////////////////
  // Decryption after Accumulation Operation on Encrypted Data with Multiparty
  ////////////////////////////////////////////////////////////

  Plaintext plaintextAddNew1;
  Plaintext plaintextAddNew2;
  Plaintext plaintextAddNew3;
  Element partialPlaintext1;
  Element partialPlaintext2;
  Element partialPlaintext3;
  Plaintext plaintextMultipartyNew;

  const shared_ptr<LPCryptoParameters<Element>> cryptoParams =
      kp1.secretKey->GetCryptoParameters();
  const shared_ptr<typename Element::Params> elementParams =
      cryptoParams->GetElementParams();

  auto ciphertextPartial1 =
      cc->MultipartyDecryptLead(kp1.secretKey, {ciphertextAdd123});

  auto ciphertextPartial2 =
      cc->MultipartyDecryptMain(kp2.secretKey, {ciphertextAdd123});

  vector<Ciphertext<Element>> partialCiphertextVec;
  partialCiphertextVec.push_back(ciphertextPartial1[0]);
  partialCiphertextVec.push_back(ciphertextPartial2[0]);

  cc->MultipartyDecryptFusion(partialCiphertextVec, &plaintextMultipartyNew);
  plaintextMultipartyNew->SetLength(plaintext1->GetLength());

  tmp_a = plaintextMultipartyNew->GetPackedValue();
  tmp_b = plaintextSumInput->GetPackedValue();
  EXPECT_EQ(tmp_a, tmp_b) << failmsg << " Multiparty accumulation fails";

  if (cc->getSchemeId() == "BGVrns")
    ciphertextMult = cc->Compress(ciphertextMult,1);

  Plaintext plaintextMultipartyMult;
  ciphertextPartial1 =
      cc->MultipartyDecryptLead(kp1.secretKey, {ciphertextMult});
  ciphertextPartial2 =
      cc->MultipartyDecryptMain(kp2.secretKey, {ciphertextMult});

  vector<Ciphertext<Element>> partialCiphertextVecMult;
  partialCiphertextVecMult.push_back(ciphertextPartial1[0]);
  partialCiphertextVecMult.push_back(ciphertextPartial2[0]);

  cc->MultipartyDecryptFusion(partialCiphertextVecMult,
                              &plaintextMultipartyMult);
  plaintextMultipartyMult->SetLength(plaintext1->GetLength());

  tmp_a = plaintextMultipartyMult->GetPackedValue();
  tmp_b = plaintextMultInput->GetPackedValue();
  EXPECT_EQ(tmp_a, tmp_b) << failmsg << " Multiparty multiplication fails";

  Plaintext plaintextMultipartyRotate;
  ciphertextPartial1 =
      cc->MultipartyDecryptLead(kp1.secretKey, {ciphertextRotate});
  ciphertextPartial2 =
      cc->MultipartyDecryptMain(kp2.secretKey, {ciphertextRotate});

  vector<Ciphertext<Element>> partialCiphertextVecRotate;
  partialCiphertextVecRotate.push_back(ciphertextPartial1[0]);
  partialCiphertextVecRotate.push_back(ciphertextPartial2[0]);

  cc->MultipartyDecryptFusion(partialCiphertextVecRotate,
                              &plaintextMultipartyRotate);
  plaintextMultipartyRotate->SetLength(plaintext1->GetLength());

  tmp_a = plaintextMultipartyRotate->GetPackedValue();
  tmp_b = plaintextRotateInput->GetPackedValue();

  EXPECT_EQ(tmp_a, tmp_b) << failmsg << " Multiparty rotation fails";
}

GENERATE_TEST_CASES_FUNC_MP(UTMultiparty, UnitTest_MultiParty_MP, 512 /*ORDER*/,
                            65537 /*PTM*/)

template <class Element>
void UnitTestMultiparty(CryptoContext<Element> cc) {
  // Initialize Public Key Containers
  LPKeyPair<Element> kp1;
  LPKeyPair<Element> kp2;
  LPKeyPair<Element> kp3;

  LPKeyPair<Element> kpMultiparty;

  LPEvalKey<Element> evalKey1;
  LPEvalKey<Element> evalKey2;
  LPEvalKey<Element> evalKey3;

  ////////////////////////////////////////////////////////////
  // Perform Key Generation Operation
  ////////////////////////////////////////////////////////////

  kp1 = cc->KeyGen();
  kp2 = cc->MultipartyKeyGen(kp1.publicKey, false, true);
  kp3 = cc->MultipartyKeyGen(kp1.publicKey, false, true);

  ASSERT_TRUE(kp1.good()) << "Key generation failed!";
  ASSERT_TRUE(kp2.good()) << "Key generation failed!";
  ASSERT_TRUE(kp3.good()) << "Key generation failed!";

  ////////////////////////////////////////////////////////////
  // Perform the second key generation operation.
  // This generates the keys which should be able to decrypt the ciphertext
  // after the re-encryption operation.
  ////////////////////////////////////////////////////////////

  vector<LPPrivateKey<Element>> secretKeys;
  secretKeys.push_back(kp1.secretKey);
  secretKeys.push_back(kp2.secretKey);
  secretKeys.push_back(kp3.secretKey);

  kpMultiparty = cc->MultipartyKeyGen(
      secretKeys);  // This is the same core key generation operation.

  ASSERT_TRUE(kpMultiparty.good()) << "Key generation failed!";

  ////////////////////////////////////////////////////////////
  // Perform the proxy re-encryption key generation operation.
  // This generates the keys which are used to perform the key switching.
  ////////////////////////////////////////////////////////////

  evalKey1 = cc->ReKeyGen(kpMultiparty.publicKey, kp1.secretKey);
  evalKey2 = cc->ReKeyGen(kpMultiparty.publicKey, kp2.secretKey);
  evalKey3 = cc->ReKeyGen(kpMultiparty.publicKey, kp3.secretKey);

  ////////////////////////////////////////////////////////////
  // Encode source data
  ////////////////////////////////////////////////////////////
  std::vector<int64_t> vectorOfInts1 = {1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0};
  std::vector<int64_t> vectorOfInts2 = {1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0};
  std::vector<int64_t> vectorOfInts3 = {1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0};
  Plaintext plaintext1 = cc->MakeCoefPackedPlaintext(vectorOfInts1);
  Plaintext plaintext2 = cc->MakeCoefPackedPlaintext(vectorOfInts2);
  Plaintext plaintext3 = cc->MakeCoefPackedPlaintext(vectorOfInts3);

  std::vector<int64_t> vectorOfIntsSum(vectorOfInts1.size());

  int64_t half(cc->GetCryptoParameters()->GetPlaintextModulus() >> 1);

  for (size_t i = 0; i < vectorOfInts1.size(); i++) {
    int64_t value = (vectorOfInts1[i] + vectorOfInts2[i] + vectorOfInts3[i]) %
                    cc->GetCryptoParameters()->GetPlaintextModulus();
    if (value > half)
      value = value - cc->GetCryptoParameters()->GetPlaintextModulus();
    vectorOfIntsSum[i] = value;
  }

  ////////////////////////////////////////////////////////////
  // Encryption
  ////////////////////////////////////////////////////////////

  Ciphertext<Element> ciphertext1;
  Ciphertext<Element> ciphertext2;
  Ciphertext<Element> ciphertext3;

  ciphertext1 = cc->Encrypt(kp1.publicKey, plaintext1);
  ciphertext2 = cc->Encrypt(kp2.publicKey, plaintext2);
  ciphertext3 = cc->Encrypt(kp3.publicKey, plaintext3);

  ////////////////////////////////////////////////////////////
  // Re-Encryption
  ////////////////////////////////////////////////////////////

  Ciphertext<Element> ciphertext1New;
  Ciphertext<Element> ciphertext2New;
  Ciphertext<Element> ciphertext3New;

  ciphertext1New = cc->ReEncrypt(evalKey1, ciphertext1);
  ciphertext2New = cc->ReEncrypt(evalKey2, ciphertext2);
  ciphertext3New = cc->ReEncrypt(evalKey3, ciphertext3);

  ////////////////////////////////////////////////////////////
  // EvalAdd Operation on Re-Encrypted Data
  ////////////////////////////////////////////////////////////

  Ciphertext<Element> ciphertextAddNew12;
  Ciphertext<Element> ciphertextAddNew;

  ciphertextAddNew12 = cc->EvalAdd(ciphertext1New, ciphertext2New);
  ciphertextAddNew = cc->EvalAdd(ciphertextAddNew12, ciphertext3New);

  ////////////////////////////////////////////////////////////
  // Decryption after Accumulation Operation on Re-Encrypted Data
  ////////////////////////////////////////////////////////////

  Plaintext plaintextAddNew;

  cc->Decrypt(kpMultiparty.secretKey, ciphertextAddNew, &plaintextAddNew);

  plaintextAddNew->SetLength(plaintext1->GetLength());

  ////////////////////////////////////////////////////////////
  // Decryption after Accumulation Operation on Re-Encrypted Data with
  // Multiparty
  ////////////////////////////////////////////////////////////

  Plaintext plaintextAddNew1;
  Plaintext plaintextAddNew2;
  Plaintext plaintextAddNew3;

  Element partialPlaintext1;
  Element partialPlaintext2;
  Element partialPlaintext3;

  Plaintext plaintextMultipartyNew;

  const shared_ptr<LPCryptoParameters<Element>> cryptoParams =
      kp1.secretKey->GetCryptoParameters();
  const shared_ptr<typename Element::Params> elementParams =
      cryptoParams->GetElementParams();

  auto ciphertextPartial1 =
      cc->MultipartyDecryptLead(kp1.secretKey, {ciphertextAddNew});
  auto ciphertextPartial2 =
      cc->MultipartyDecryptMain(kp2.secretKey, {ciphertextAddNew});
  auto ciphertextPartial3 =
      cc->MultipartyDecryptMain(kp3.secretKey, {ciphertextAddNew});

  vector<Ciphertext<Element>> partialCiphertextVec;
  partialCiphertextVec.push_back(ciphertextPartial1[0]);
  partialCiphertextVec.push_back(ciphertextPartial2[0]);
  partialCiphertextVec.push_back(ciphertextPartial3[0]);

  cc->MultipartyDecryptFusion(partialCiphertextVec, &plaintextMultipartyNew);

  plaintextMultipartyNew->SetLength(plaintext1->GetLength());

  EXPECT_EQ(vectorOfIntsSum, plaintextMultipartyNew->GetCoefPackedValue())
      << "Multiparty: Does not match plaintext addition.";
  EXPECT_EQ(plaintextAddNew->GetCoefPackedValue(),
            plaintextMultipartyNew->GetCoefPackedValue())
      << "Multiparty: Does not match the results of direction encryption.";
}

TEST_F(UTMultiparty, BFVrns_RLWE_DCRTPoly_Multiparty_pri) {
  CryptoContext<DCRTPoly> cc = GenCryptoContextBFVrns<DCRTPoly>(4, RLWE);
  cc->Enable(ENCRYPTION);
  cc->Enable(SHE);
  cc->Enable(PRE);
  cc->Enable(MULTIPARTY);
  UnitTestMultiparty<DCRTPoly>(cc);
}

TEST_F(UTMultiparty, BFVrns2_OPTIMIZED_DCRTPoly_Multiparty_pri) {
  CryptoContext<DCRTPoly> cc = GenCryptoContextBFVrns<DCRTPoly>(16, OPTIMIZED);
  cc->Enable(ENCRYPTION);
  cc->Enable(SHE);
  cc->Enable(PRE);
  cc->Enable(MULTIPARTY);
  UnitTestMultiparty<DCRTPoly>(cc);
}

TEST_F(UTMultiparty, BFVrnsB_RLWE_DCRTPoly_Multiparty_pri) {
  CryptoContext<DCRTPoly> cc = GenCryptoContextBFVrnsB<DCRTPoly>(4, RLWE);
  cc->Enable(ENCRYPTION);
  cc->Enable(SHE);
  cc->Enable(PRE);
  cc->Enable(MULTIPARTY);
  UnitTestMultiparty<DCRTPoly>(cc);
}

TEST_F(UTMultiparty, BFVrnsB2_OPTIMIZED_DCRTPoly_Multiparty_pri) {
  CryptoContext<DCRTPoly> cc = GenCryptoContextBFVrnsB<DCRTPoly>(16, OPTIMIZED);
  cc->Enable(ENCRYPTION);
  cc->Enable(SHE);
  cc->Enable(PRE);
  cc->Enable(MULTIPARTY);
  UnitTestMultiparty<DCRTPoly>(cc);
}

static inline void RunTestUsingContext(const string& input) {
  CryptoContext<Poly> cc = CryptoContextHelper::getNewContext(input);
  cc->Enable(ENCRYPTION);
  cc->Enable(SHE);
  cc->Enable(PRE);
  cc->Enable(MULTIPARTY);
  UnitTestMultiparty<Poly>(cc);
}

TEST_F(UTMultiparty, BFV1_Poly_Multiparty_pri) { RunTestUsingContext("BFV1"); }

TEST_F(UTMultiparty, BFV2_Poly_Multiparty_pri) { RunTestUsingContext("BFV2"); }

TEST_F(UTMultiparty, Null_Poly_Multiparty_pri) { RunTestUsingContext("Null"); }

TEST_F(UTMultiparty, Null2_Poly_Multiparty_pri) {
  RunTestUsingContext("Null2");
}
