// @file UniTestSerializeBGVrns.cpp
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
#include "scheme/bgvrns/bgvrns-ser.h"

using namespace std;
using namespace lbcrypto;

class UTBGVrnsSer : public ::testing::Test {
 public:
  UTBGVrnsSer() {}
  ~UTBGVrnsSer() {}

 protected:
  void SetUp() {}

  void TearDown() { CryptoContextFactory<DCRTPoly>::ReleaseAllContexts(); }
};

// This file unit tests the SHE capabilities for the BGVrns scheme
#define GENERATE_TEST_CASES_FUNC(x, y, ORD, PTM, SIZEMODULI, NUMPRIME, RELIN,  \
                                 BATCH)                                        \
  GENERATE_BGVrns_TEST_CASE(x, y, DCRTPoly, BGVrns, ORD, PTM, SIZEMODULI,      \
                            NUMPRIME, RELIN, BV, BATCH, APPROXRESCALE, MANUAL) \
      GENERATE_BGVrns_TEST_CASE(x, y, DCRTPoly, BGVrns, ORD, PTM, SIZEMODULI,  \
                                NUMPRIME, RELIN, BV, BATCH, APPROXRESCALE,     \
                                AUTO)                                          \
          GENERATE_BGVrns_TEST_CASE(x, y, DCRTPoly, BGVrns, ORD, PTM,          \
                                    SIZEMODULI, NUMPRIME, RELIN, GHS, BATCH,   \
                                    APPROXRESCALE, MANUAL)                     \
              GENERATE_BGVrns_TEST_CASE(x, y, DCRTPoly, BGVrns, ORD, PTM,      \
                                        SIZEMODULI, NUMPRIME, RELIN, GHS,      \
                                        BATCH, APPROXRESCALE, AUTO)            \
                  GENERATE_BGVrns_TEST_CASE(                                   \
                      x, y, DCRTPoly, BGVrns, ORD, PTM, SIZEMODULI, NUMPRIME,  \
                      RELIN, HYBRID, BATCH, APPROXRESCALE, MANUAL)             \
                      GENERATE_BGVrns_TEST_CASE(                               \
                          x, y, DCRTPoly, BGVrns, ORD, PTM, SIZEMODULI,        \
                          NUMPRIME, RELIN, HYBRID, BATCH, APPROXRESCALE, AUTO)

/* *
 * ORDER: Cyclotomic order. Must be a power of 2 for CKKS.
 * NUMPRIME: Number of co-primes comprising the ciphertext modulus.
 * 		     It is equal to the desired depth of the computation.
 * SIZEMODULI: Size of each co-prime in bits.
 * 		  Should fit into a machine word, i.e., less than 64.
 * RELIN: The bit decomposition count used in relinearization.
 *  	  Use 0 to go with max possible. Use small values (3-4?)
 * 		  if you need rotations before any multiplications.
 * PTM: The plaintext modulus.
 */
static const usint ORDER = 1024;  // 16384;
static const usint SIZEMODULI = 50;
static const usint NUMPRIME = 4;
static const usint RELIN = 20;
static const usint PTM = 65537;
static const usint BATCH = 16;

/**
 * This function checks whether vectors of numbers a and b are equal.
 *
 * @param vectorSize The length of the two vectors.
 * @param failmsg Debug message to display upon failure.
 */
static void checkEquality(const std::vector<int64_t>& a,
                          const std::vector<int64_t>& b, int vectorSize,
                          const string& failmsg) {
  std::vector<usint> allTrue(vectorSize);
  std::vector<usint> tmp(vectorSize);
  for (int i = 0; i < vectorSize; i++) {
    allTrue[i] = 1;
    tmp[i] = (a[i] == b[i]);
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

GENERATE_TEST_CASES_FUNC(UTBGVrnsSer, UnitTestContext, ORDER, PTM, SIZEMODULI,
                         NUMPRIME, RELIN, BATCH)

template <typename T, typename ST>
static void TestKeysAndCiphertexts(CryptoContext<T> cc, const ST& sertype,
                                   const string& failmsg) {
  DEBUG_FLAG(false);

  CryptoContextImpl<DCRTPoly>::ClearEvalMultKeys();
  CryptoContextImpl<DCRTPoly>::ClearEvalSumKeys();
  CryptoContextImpl<DCRTPoly>::ClearEvalAutomorphismKeys();

  // // The batch size for our tests.
  int vecSize = 10;

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

  // Update the batchSize from the default value
  const auto cryptoParamsBGVrns =
      std::static_pointer_cast<LPCryptoParametersBGVrns<DCRTPoly>>(
          kp.publicKey->GetCryptoParameters());

  EncodingParams encodingParamsNew(std::make_shared<EncodingParamsImpl>(
      cc->GetEncodingParams()->GetPlaintextModulus(), vecSize));
  cryptoParamsBGVrns->SetEncodingParams(encodingParamsNew);

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
  vector<int64_t> vals = {1, 3, 5, 7, 9, 2, 4, 6, 8, 11};
  Plaintext plaintextShort = cc->MakePackedPlaintext(vals);
  Ciphertext<DCRTPoly> ciphertext = cc->Encrypt(kp.publicKey, plaintextShort);

  DEBUG("step 4");
  Ciphertext<DCRTPoly> newC;
  {
    stringstream s;
    Serial::Serialize(ciphertext, s, sertype);
    Serial::Deserialize(newC, s, sertype);
    EXPECT_EQ(*ciphertext, *newC) << "Ciphertext mismatch";
  }

  DEBUG("step 5");
  Plaintext plaintextShortNew;
  cc->Decrypt(kp.secretKey, newC, &plaintextShortNew);

  checkEquality(plaintextShortNew->GetPackedValue(),
                plaintextShort->GetPackedValue(), vecSize,
                failmsg + " Decrypted serialization test fails");

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

GENERATE_TEST_CASES_FUNC(UTBGVrnsSer, UnitTestKeysAndCiphertextsRelin0JSON,
                         ORDER, PTM, SIZEMODULI, NUMPRIME, 0, BATCH)
GENERATE_TEST_CASES_FUNC(UTBGVrnsSer, UnitTestKeysAndCiphertextsRelin0BINARY,
                         ORDER, PTM, SIZEMODULI, NUMPRIME, 0, BATCH)

GENERATE_TEST_CASES_FUNC(UTBGVrnsSer, UnitTestKeysAndCiphertextsRelin20JSON,
                         ORDER, PTM, SIZEMODULI, NUMPRIME, 20, BATCH)
GENERATE_TEST_CASES_FUNC(UTBGVrnsSer, UnitTestKeysAndCiphertextsRelin20BINARY,
                         ORDER, PTM, SIZEMODULI, NUMPRIME, 20, BATCH)
