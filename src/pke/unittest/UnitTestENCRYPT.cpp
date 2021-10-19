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
#include "cryptocontextparametersets.h"
#include "palisade.h"
#include "utils/testcasegen.h"

using namespace std;
using namespace lbcrypto;

// This file unit tests the ENCRYPTION capabilities for all schemes, using all
// known elements

class Encrypt_Decrypt : public ::testing::Test {
 public:
  virtual ~Encrypt_Decrypt() {}

 protected:
  void SetUp() {}

  void TearDown() {
    CryptoContextFactory<NativePoly>::ReleaseAllContexts();
    CryptoContextFactory<Poly>::ReleaseAllContexts();
    CryptoContextFactory<DCRTPoly>::ReleaseAllContexts();
  }
};

#define GENERATE_TEST_CASES_FUNC(x, y, ORD, PTM)                   \
  GENERATE_PKE_TEST_CASE(x, y, Poly, Null, ORD, PTM)               \
  GENERATE_PKE_TEST_CASE(x, y, Poly, BGVrns_rlwe, ORD, PTM)        \
  GENERATE_PKE_TEST_CASE(x, y, Poly, BGVrns_opt, ORD, PTM)         \
  GENERATE_PKE_TEST_CASE(x, y, Poly, BFV_rlwe, ORD, PTM)           \
  GENERATE_PKE_TEST_CASE(x, y, Poly, BFV_opt, ORD, PTM)            \
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
  GENERATE_PKE_TEST_CASE(x, y, DCRTPoly, BFVrnsB_opt, ORD, PTM)

template <typename Element>
void EncryptionString(const CryptoContext<Element> cc, const string& failmsg) {
  string value =
      "You keep using that word. I do not think it means what you think it "
      "means";
  Plaintext plaintext =
      CryptoContextImpl<Element>::MakePlaintext(String, cc, value);

  LPKeyPair<Element> kp = cc->KeyGen();
  EXPECT_EQ(kp.good(), true)
      << failmsg << " key generation for string encrypt/decrypt failed";

  Ciphertext<Element> ciphertext = cc->Encrypt(kp.publicKey, plaintext);
  Plaintext plaintextNew;
  cc->Decrypt(kp.secretKey, ciphertext, &plaintextNew);
  EXPECT_EQ(*plaintext, *plaintextNew)
      << failmsg << " string encrypt/decrypt failed";
}

GENERATE_TEST_CASES_FUNC(Encrypt_Decrypt, EncryptionString, 512, 256)

template <typename Element>
void EncryptionCoefPacked(const CryptoContext<Element> cc,
                          const string& failmsg) {
  size_t intSize = cc->GetRingDimension();
  auto ptm = cc->GetCryptoParameters()->GetPlaintextModulus();
  int half = ptm / 2;

  vector<int64_t> intvec;
  for (size_t ii = 0; ii < intSize; ii++) intvec.push_back(rand() % half);
  Plaintext plaintextInt = cc->MakeCoefPackedPlaintext(intvec);

  vector<int64_t> sintvec;
  for (size_t ii = 0; ii < intSize; ii++) {
    int rnum = rand() % half;
    if (rand() % 2) rnum *= -1;
    sintvec.push_back(rnum);
  }
  Plaintext plaintextSInt = cc->MakeCoefPackedPlaintext(sintvec);

  LPKeyPair<Element> kp = cc->KeyGen();
  EXPECT_EQ(kp.good(), true)
      << failmsg << " key generation for coef packed encrypt/decrypt failed";

  Ciphertext<Element> ciphertext4 = cc->Encrypt(kp.publicKey, plaintextInt);
  Plaintext plaintextIntNew;
  cc->Decrypt(kp.secretKey, ciphertext4, &plaintextIntNew);
  EXPECT_EQ(*plaintextIntNew, *plaintextInt)
      << failmsg << "coef packed encrypt/decrypt failed for integer plaintext";

  Ciphertext<Element> ciphertext5 = cc->Encrypt(kp.publicKey, plaintextSInt);
  Plaintext plaintextSIntNew;
  cc->Decrypt(kp.secretKey, ciphertext5, &plaintextSIntNew);
  EXPECT_EQ(*plaintextSIntNew, *plaintextSInt)
      << failmsg
      << "coef packed encrypt/decrypt failed for signed integer plaintext";
}

GENERATE_TEST_CASES_FUNC(Encrypt_Decrypt, EncryptionCoefPacked, 128, 512)
