// @file
// @author TPOC: palisade@njit.edu
//
// @copyright Copyright (c) 2017, New Jersey Institute of Technology (NJIT)
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
#include "gtest/gtest.h"

#include "cryptocontext.h"
#include "cryptocontextgen.h"
#include "cryptocontexthelper.h"
#include "palisade.h"
#include "utils/testcasegen.h"

#include "ciphertext-ser.h"
#include "cryptocontext-ser.h"
#include "pubkeylp-ser.h"
#include "scheme/ckks/ckks-ser.h"

using namespace std;
using namespace lbcrypto;

class UTCKKSSer : public ::testing::Test {
 public:
  UTCKKSSer() {}
  ~UTCKKSSer() {}

 protected:
  void SetUp() {}

  void TearDown() { CryptoContextFactory<DCRTPoly>::ReleaseAllContexts(); }
};

#if NATIVEINT == 128
// This file unit tests the SHE capabilities for the CKKS scheme
#define GENERATE_TEST_CASES_FUNC(x, y, ORD, SCALE, NUMPRIME, RELIN, BATCH)   \
  GENERATE_CKKS_TEST_CASE(x, y, DCRTPoly, CKKS, ORD, SCALE, NUMPRIME, RELIN, \
                          BATCH, BV, APPROXRESCALE)                          \
  GENERATE_CKKS_TEST_CASE(x, y, DCRTPoly, CKKS, ORD, SCALE, NUMPRIME, RELIN, \
                          BATCH, GHS, APPROXRESCALE)                         \
  GENERATE_CKKS_TEST_CASE(x, y, DCRTPoly, CKKS, ORD, SCALE, NUMPRIME, RELIN, \
                          BATCH, HYBRID, APPROXRESCALE)                      \
  GENERATE_CKKS_TEST_CASE(x, y, DCRTPoly, CKKS, ORD, SCALE, NUMPRIME, RELIN, \
                          BATCH, BV, APPROXAUTO)                             \
  GENERATE_CKKS_TEST_CASE(x, y, DCRTPoly, CKKS, ORD, SCALE, NUMPRIME, RELIN, \
                          BATCH, GHS, APPROXAUTO)                            \
  GENERATE_CKKS_TEST_CASE(x, y, DCRTPoly, CKKS, ORD, SCALE, NUMPRIME, RELIN, \
                          BATCH, HYBRID, APPROXAUTO)
#else
// This file unit tests the SHE capabilities for the CKKS scheme
#define GENERATE_TEST_CASES_FUNC(x, y, ORD, SCALE, NUMPRIME, RELIN, BATCH)   \
  GENERATE_CKKS_TEST_CASE(x, y, DCRTPoly, CKKS, ORD, SCALE, NUMPRIME, RELIN, \
                          BATCH, BV, APPROXRESCALE)                          \
  GENERATE_CKKS_TEST_CASE(x, y, DCRTPoly, CKKS, ORD, SCALE, NUMPRIME, RELIN, \
                          BATCH, GHS, APPROXRESCALE)                         \
  GENERATE_CKKS_TEST_CASE(x, y, DCRTPoly, CKKS, ORD, SCALE, NUMPRIME, RELIN, \
                          BATCH, HYBRID, APPROXRESCALE)                      \
  GENERATE_CKKS_TEST_CASE(x, y, DCRTPoly, CKKS, ORD, SCALE, NUMPRIME, RELIN, \
                          BATCH, BV, APPROXAUTO)                             \
  GENERATE_CKKS_TEST_CASE(x, y, DCRTPoly, CKKS, ORD, SCALE, NUMPRIME, RELIN, \
                          BATCH, GHS, APPROXAUTO)                            \
  GENERATE_CKKS_TEST_CASE(x, y, DCRTPoly, CKKS, ORD, SCALE, NUMPRIME, RELIN, \
                          BATCH, HYBRID, APPROXAUTO)                         \
  GENERATE_CKKS_TEST_CASE(x, y, DCRTPoly, CKKS, ORD, SCALE, NUMPRIME, RELIN, \
                          BATCH, BV, EXACTRESCALE)                           \
  GENERATE_CKKS_TEST_CASE(x, y, DCRTPoly, CKKS, ORD, SCALE, NUMPRIME, RELIN, \
                          BATCH, GHS, EXACTRESCALE)                          \
  GENERATE_CKKS_TEST_CASE(x, y, DCRTPoly, CKKS, ORD, SCALE, NUMPRIME, RELIN, \
                          BATCH, HYBRID, EXACTRESCALE)
#endif

/* *
 * ORDER: Cyclotomic order. Must be a power of 2 for CKKS.
 * NUMPRIME: Number of co-primes comprising the ciphertext modulus.
 *          It is equal to the desired depth of the computation.
 * SCALE: Scaling parameter 2^p. Also, Size of each co-prime in bits.
 *       Should fit into a machine word, i.e., less than 64.
 * RELIN: The bit decomposition count used in relinearization.
 *      Use 0 to go with max possible. Use small values (3-4?)
 *       if you need rotations before any multiplications.
 * BATCH: The length of the packed vectors to be used with CKKS.
 */
static const usint ORDER = 1024;  // 16384;
static const usint SCALE = 50;
static const usint NUMPRIME = 4;
static const usint RELIN = 20;
static const usint BATCH = 8;

/**
 * This function checks whether vectors of approximate numbers a and b are
 * equal. This is useful for CKKS tests, because numbers are approximate, so
 * results will never be exactly as expected.
 *
 * @param vectorSize The length of the two vectors.
 * @param epsilon Minimum precision to consider a and b equal.
 *       E.g., a={0.1, 0.123} and b={0.1, 0.124} are equal for
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

template <typename T, typename ST>
static void UnitTestContextWithSertype(CryptoContext<T> cc, const ST& sertype,
                                       string msg) {
  LPKeyPair<T> kp = cc->KeyGen();

  try {
    cc->EvalMultKeyGen(kp.secretKey);
  } catch (...) {
  }

  try {
    cc->EvalSumKeyGen(kp.secretKey, kp.publicKey);
  } catch (...) {
  }

  stringstream s;
  Serial::Serialize(cc, s, sertype);

  // std::cerr << " Output " << s.str() << std::endl;

  CryptoContext<T> newcc;

  Serial::Deserialize(newcc, s, sertype);

  ASSERT_TRUE(newcc) << msg << " Deserialize failed";

  EXPECT_EQ(*cc, *newcc) << msg << " Mismatched context";

  EXPECT_EQ(*cc->GetEncryptionAlgorithm(), *newcc->GetEncryptionAlgorithm())
      << msg << " Scheme mismatch after ser/deser";
  EXPECT_EQ(*cc->GetCryptoParameters(), *newcc->GetCryptoParameters())
      << msg << " Crypto parms mismatch after ser/deser";
  EXPECT_EQ(*cc->GetEncodingParams(), *newcc->GetEncodingParams())
      << msg << " Encoding parms mismatch after ser/deser";
  EXPECT_EQ(cc->GetEncryptionAlgorithm()->GetEnabled(),
            newcc->GetEncryptionAlgorithm()->GetEnabled())
      << msg << " Enabled features mismatch after ser/deser";

  s.str("");
  s.clear();
  Serial::Serialize(kp.publicKey, s, sertype);

  LPPublicKey<T> newPub;
  Serial::Deserialize(newPub, s, sertype);
  ASSERT_TRUE(newPub) << msg << " Key deserialize failed";

  EXPECT_EQ(*kp.publicKey, *newPub) << msg << " Key mismatch";

  CryptoContext<T> newccFromkey = newPub->GetCryptoContext();
  EXPECT_EQ(*cc, *newccFromkey) << msg << " Key deser has wrong context";
}

template <typename T>
static void UnitTestContext(CryptoContext<T> cc, const string& failmsg) {
  UnitTestContextWithSertype(cc, SerType::JSON, "json");
  UnitTestContextWithSertype(cc, SerType::BINARY, "binary");
}

GENERATE_TEST_CASES_FUNC(UTCKKSSer, UnitTestContext, ORDER, SCALE, NUMPRIME,
                         RELIN, BATCH)

template <typename T, typename ST>
static void TestKeysAndCiphertexts(CryptoContext<T> cc, const ST& sertype,
                                   const string& failmsg) {
  DEBUG_FLAG(false);

  CryptoContextImpl<DCRTPoly>::ClearEvalMultKeys();
  CryptoContextImpl<DCRTPoly>::ClearEvalSumKeys();
  CryptoContextImpl<DCRTPoly>::ClearEvalAutomorphismKeys();

  // The batch size for our tests.
  int vecSize = 10;
  // The precision after which we consider two values equal.
  // This is necessary because CKKS works for approximate numbers.
  double eps = 0.0001;

  DEBUG("step 0");
  {
    stringstream s;
    Serial::Serialize(cc, s, sertype);
    ASSERT_TRUE(CryptoContextFactory<DCRTPoly>::GetContextCount() == 1);
    CryptoContextFactory<DCRTPoly>::ReleaseAllContexts();
    ASSERT_TRUE(CryptoContextFactory<DCRTPoly>::GetContextCount() == 0);
    Serial::Deserialize(cc, s, sertype);

    ASSERT_TRUE(cc) << "Deser failed";
    ASSERT_TRUE(CryptoContextFactory<DCRTPoly>::GetContextCount() == 1);
  }

  LPKeyPair<DCRTPoly> kp = cc->KeyGen();
  LPKeyPair<DCRTPoly> kpnew;

  DEBUG("step 1");
  {
    stringstream s;
    Serial::Serialize(kp.publicKey, s, sertype);
    Serial::Deserialize(kpnew.publicKey, s, sertype);
    EXPECT_EQ(*kp.publicKey, *kpnew.publicKey)
        << "Public key mismatch after ser/deser";
  }
  DEBUG("step 2");
  {
    stringstream s;
    Serial::Serialize(kp.secretKey, s, sertype);
    Serial::Deserialize(kpnew.secretKey, s, sertype);
    EXPECT_EQ(*kp.secretKey, *kpnew.secretKey)
        << "Secret key mismatch after ser/deser";
  }
  DEBUG("step 3");
  vector<std::complex<double>> vals = {1.0, 3.0, 5.0, 7.0, 9.0,
                                       2.0, 4.0, 6.0, 8.0, 11.0};
  Plaintext plaintextShort = cc->MakeCKKSPackedPlaintext(vals);
  Plaintext plaintextShortL2D2 = cc->MakeCKKSPackedPlaintext(vals, 2, 2);
  Ciphertext<DCRTPoly> ciphertext = cc->Encrypt(kp.publicKey, plaintextShort);
  Ciphertext<DCRTPoly> ciphertextL2D2 =
      cc->Encrypt(kp.publicKey, plaintextShortL2D2);

  DEBUG("step 4");
  Ciphertext<DCRTPoly> newC;
  Ciphertext<DCRTPoly> newCL2D2;
  {
    stringstream s;
    Serial::Serialize(ciphertext, s, sertype);
    Serial::Deserialize(newC, s, sertype);
    stringstream s2;
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

  checkApproximateEquality(plaintextShortNew->GetCKKSPackedValue(),
                           plaintextShort->GetCKKSPackedValue(), vecSize, eps,
                           failmsg + " Decrypted serialization test fails");
  checkApproximateEquality(
      plaintextShortNewL2D2->GetCKKSPackedValue(),
      plaintextShort->GetCKKSPackedValue(), vecSize, eps,
      failmsg + " Decrypted serialization test fails (level 2, depth 2)");

  DEBUG("step 6");
  LPKeyPair<DCRTPoly> kp2 = cc->KeyGen();

  cc->EvalMultKeyGen(kp.secretKey);
  cc->EvalMultKeyGen(kp2.secretKey);
  cc->EvalSumKeyGen(kp.secretKey);
  cc->EvalSumKeyGen(kp2.secretKey);

  DEBUG("step 7");
  // serialize a bunch of mult keys
  stringstream ser0;
  EXPECT_EQ(CryptoContextImpl<DCRTPoly>::SerializeEvalMultKey(
                ser0, sertype, kp.secretKey->GetKeyTag()),
            true)
      << "single eval mult key ser fails";
  stringstream ser2a;
  EXPECT_EQ(
      CryptoContextImpl<DCRTPoly>::SerializeEvalMultKey(ser2a, sertype, cc),
      true)
      << "context 1 eval mult key ser fails";
  stringstream ser3;
  EXPECT_EQ(CryptoContextImpl<DCRTPoly>::SerializeEvalMultKey(ser3, sertype),
            true)
      << "all context eval mult key ser fails";

  DEBUG("step 8");
  // serialize a bunch of sum keys
  stringstream aser0;
  EXPECT_EQ(CryptoContextImpl<DCRTPoly>::SerializeEvalSumKey(
                aser0, sertype, kp.secretKey->GetKeyTag()),
            true)
      << "single eval sum key ser fails";
  stringstream aser2a;
  EXPECT_EQ(
      CryptoContextImpl<DCRTPoly>::SerializeEvalSumKey(aser2a, sertype, cc),
      true)
      << "single ctx eval sum key ser fails";
  stringstream aser3;
  EXPECT_EQ(CryptoContextImpl<DCRTPoly>::SerializeEvalSumKey(aser3, sertype),
            true)
      << "all eval sum key ser fails";

  DEBUG("step 9");
  cc.reset();

  // test mult deserialize
  CryptoContextImpl<DCRTPoly>::ClearEvalMultKeys();
  CryptoContextImpl<DCRTPoly>::ClearEvalSumKeys();
  CryptoContextFactory<DCRTPoly>::ReleaseAllContexts();
  EXPECT_EQ(CryptoContextFactory<DCRTPoly>::GetContextCount(), 0)
      << "after release" << endl;

  vector<LPEvalKey<DCRTPoly>> evalMultKeys;
  CryptoContextImpl<DCRTPoly>::DeserializeEvalMultKey(ser0, sertype);
  EXPECT_EQ(CryptoContextFactory<DCRTPoly>::GetContextCount(), 1)
      << "one-key deser, context";
  EXPECT_EQ(CryptoContextImpl<DCRTPoly>::GetAllEvalMultKeys().size(), 1U)
      << "one-key deser, keys";

  CryptoContextImpl<DCRTPoly>::ClearEvalMultKeys();
  CryptoContextImpl<DCRTPoly>::ClearEvalSumKeys();
  CryptoContextFactory<DCRTPoly>::ReleaseAllContexts();

  CryptoContextImpl<DCRTPoly>::DeserializeEvalMultKey(ser2a, sertype);
  EXPECT_EQ(CryptoContextFactory<DCRTPoly>::GetContextCount(), 1)
      << "one-ctx deser, context";
  EXPECT_EQ(CryptoContextImpl<DCRTPoly>::GetAllEvalMultKeys().size(), 2U)
      << "one-ctx deser, keys";

  CryptoContextImpl<DCRTPoly>::ClearEvalMultKeys();
  CryptoContextImpl<DCRTPoly>::ClearEvalSumKeys();
  CryptoContextFactory<DCRTPoly>::ReleaseAllContexts();

  CryptoContextImpl<DCRTPoly>::DeserializeEvalMultKey(ser3, sertype);
  EXPECT_EQ(CryptoContextFactory<DCRTPoly>::GetContextCount(), 1)
      << "all-key deser, context";
  EXPECT_EQ(CryptoContextImpl<DCRTPoly>::GetAllEvalMultKeys().size(), 2U)
      << "all-key deser, keys";

  DEBUG("step 10");
  // test sum deserialize

  CryptoContextImpl<DCRTPoly>::ClearEvalMultKeys();
  CryptoContextImpl<DCRTPoly>::ClearEvalSumKeys();
  CryptoContextFactory<DCRTPoly>::ReleaseAllContexts();

  CryptoContextImpl<DCRTPoly>::DeserializeEvalSumKey(aser0, sertype);
  EXPECT_EQ(CryptoContextFactory<DCRTPoly>::GetContextCount(), 1)
      << "one-key deser, context";
  EXPECT_EQ(CryptoContextImpl<DCRTPoly>::GetAllEvalSumKeys().size(), 1U)
      << "one-key deser, keys";

  CryptoContextImpl<DCRTPoly>::ClearEvalMultKeys();
  CryptoContextImpl<DCRTPoly>::ClearEvalSumKeys();
  CryptoContextFactory<DCRTPoly>::ReleaseAllContexts();

  CryptoContextImpl<DCRTPoly>::DeserializeEvalSumKey(aser2a, sertype);
  EXPECT_EQ(CryptoContextFactory<DCRTPoly>::GetContextCount(), 1)
      << "one-ctx deser, context";
  EXPECT_EQ(CryptoContextImpl<DCRTPoly>::GetAllEvalSumKeys().size(), 2U)
      << "one-ctx deser, keys";

  CryptoContextImpl<DCRTPoly>::ClearEvalMultKeys();
  CryptoContextImpl<DCRTPoly>::ClearEvalSumKeys();
  CryptoContextFactory<DCRTPoly>::ReleaseAllContexts();

  CryptoContextImpl<DCRTPoly>::DeserializeEvalSumKey(aser3, sertype);
  EXPECT_EQ(CryptoContextFactory<DCRTPoly>::GetContextCount(), 1)
      << "all-key deser, context";
  EXPECT_EQ(CryptoContextImpl<DCRTPoly>::GetAllEvalSumKeys().size(), 2U)
      << "all-key deser, keys";

  // ending cleanup
  CryptoContextImpl<DCRTPoly>::ClearEvalMultKeys();
  CryptoContextImpl<DCRTPoly>::ClearEvalSumKeys();
  CryptoContextImpl<DCRTPoly>::ClearEvalAutomorphismKeys();
  CryptoContextFactory<DCRTPoly>::ReleaseAllContexts();
}

template <typename T, typename ST>
static void TestDecryptionSerNoCRTTables(CryptoContext<T> cc, const ST& sertype,
                                         string msg) {
  LPKeyPair<T> kp = cc->KeyGen();

  vector<std::complex<double>> vals = {1.0, 3.0, 5.0, 7.0, 9.0,
                                       2.0, 4.0, 6.0, 8.0, 11.0};
  Plaintext plaintextShort = cc->MakeCKKSPackedPlaintext(vals);
  Ciphertext<DCRTPoly> ciphertext = cc->Encrypt(kp.publicKey, plaintextShort);
  double eps = 0.000000001;

  stringstream s;
  Serial::Serialize(cc, s, sertype);

  CryptoContextFactory<T>::ReleaseAllContexts();
  SERIALIZE_PRECOMPUTE = false;

  CryptoContext<T> newcc;

  Serial::Deserialize(newcc, s, sertype);

  ASSERT_TRUE(newcc) << msg << " Deserialize failed";

  s.str("");
  s.clear();
  Serial::Serialize(kp.publicKey, s, sertype);

  LPPublicKey<T> newPub;
  Serial::Deserialize(newPub, s, sertype);
  ASSERT_TRUE(newPub) << msg << " Key deserialize failed";

  s.str("");
  s.clear();
  Serial::Serialize(ciphertext, s, sertype);

  Ciphertext<DCRTPoly> newC;
  Serial::Deserialize(newC, s, sertype);
  ASSERT_TRUE(newC) << msg << " ciphertext deserialize failed";

  Plaintext result;
  cc->Decrypt(kp.secretKey, newC, &result);
  result->SetLength(plaintextShort->GetLength());
  auto tmp_a = plaintextShort->GetCKKSPackedValue();
  auto tmp_b = result->GetCKKSPackedValue();
  checkApproximateEquality(tmp_a, tmp_b, uint64_t(vals.size()), eps,
                           msg + " Decryption Failed");
}

template <typename T>
static void UnitTestKeysAndCiphertextsRelin0JSON(CryptoContext<T> cc,
                                                 const string& failmsg) {
  TestKeysAndCiphertexts(cc, SerType::JSON, "json");
}

template <typename T>
static void UnitTestKeysAndCiphertextsRelin0BINARY(CryptoContext<T> cc,
                                                   const string& failmsg) {
  TestKeysAndCiphertexts(cc, SerType::BINARY, "binary");
}

template <typename T>
static void UnitTestKeysAndCiphertextsRelin20JSON(CryptoContext<T> cc,
                                                  const string& failmsg) {
  TestKeysAndCiphertexts(cc, SerType::JSON, "json");
}

template <typename T>
static void UnitTestKeysAndCiphertextsRelin20BINARY(CryptoContext<T> cc,
                                                    const string& failmsg) {
  TestKeysAndCiphertexts(cc, SerType::BINARY, "binary");
}

template <typename T>
static void UnitTestDecryptionSerNoCRTTablesJSON(CryptoContext<T> cc,
                                                 const string& failmsg) {
  TestDecryptionSerNoCRTTables(cc, SerType::JSON, "json");
}

template <typename T>
static void UnitTestDecryptionSerNoCRTTablesBINARY(CryptoContext<T> cc,
                                                   const string& failmsg) {
  TestDecryptionSerNoCRTTables(cc, SerType::BINARY, "binary");
}

GENERATE_TEST_CASES_FUNC(UTCKKSSer, UnitTestKeysAndCiphertextsRelin0JSON, ORDER,
                         SCALE, NUMPRIME, 0, BATCH)
GENERATE_TEST_CASES_FUNC(UTCKKSSer, UnitTestKeysAndCiphertextsRelin0BINARY,
                         ORDER, SCALE, NUMPRIME, 0, BATCH)

GENERATE_TEST_CASES_FUNC(UTCKKSSer, UnitTestKeysAndCiphertextsRelin20JSON,
                         ORDER, SCALE, NUMPRIME, 20, BATCH)
GENERATE_TEST_CASES_FUNC(UTCKKSSer, UnitTestKeysAndCiphertextsRelin20BINARY,
                         ORDER, SCALE, NUMPRIME, 20, BATCH)

GENERATE_TEST_CASES_FUNC(UTCKKSSer, UnitTestDecryptionSerNoCRTTablesJSON, ORDER,
                         SCALE, NUMPRIME, 0, BATCH)
GENERATE_TEST_CASES_FUNC(UTCKKSSer, UnitTestDecryptionSerNoCRTTablesBINARY,
                         ORDER, SCALE, NUMPRIME, 0, BATCH)
