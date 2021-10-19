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

#include <cmath>

#include <iostream>
#include <vector>

#include "gtest/gtest.h"

#include "cryptocontext.h"

#include "encoding/encodings.h"

#include "lattice/elemparamfactory.h"
#include "utils/debug.h"
#include "utils/parmfactory.h"

using namespace std;
using namespace lbcrypto;

using TYPE = DCRTPoly;
// A new one of these is created for each test
class UTSHEAdvanced : public testing::Test {
 public:
  UTSHEAdvanced() {}

  void SetUp() {}

  void TearDown() {
    CryptoContextFactory<Poly>::ReleaseAllContexts();
    CryptoContextFactory<DCRTPoly>::ReleaseAllContexts();
  }
};

#if !defined(_MSC_VER)

TEST_F(UTSHEAdvanced, test_eval_mult_single_crt) {
  usint m = 16;
  usint relin = 1;
  float stdDev = 4;
  PlaintextModulus ptm = 20;

  shared_ptr<TYPE::Params> parms =
      ElemParamFactory::GenElemParams<TYPE::Params>(m, 50);

  CryptoContext<TYPE> cc = CryptoContextFactory<TYPE>::genCryptoContextBGVrns(
      parms, ptm, relin, stdDev);
  cc->Enable(ENCRYPTION);
  cc->Enable(SHE);
  cc->Enable(LEVELEDSHE);

  // Initialize the public key containers.
  LPKeyPair<TYPE> kp;

  std::vector<int64_t> vectorOfInts1 = {2};
  Plaintext intArray1 = cc->MakeCoefPackedPlaintext(vectorOfInts1);

  std::vector<int64_t> vectorOfInts2 = {3};
  Plaintext intArray2 = cc->MakeCoefPackedPlaintext(vectorOfInts2);

  kp = cc->KeyGen();
  cc->EvalMultKeyGen(kp.secretKey);

  Ciphertext<TYPE> ciphertext1;
  Ciphertext<TYPE> ciphertext2;

  ciphertext1 = cc->Encrypt(kp.publicKey, intArray1);
  ciphertext2 = cc->Encrypt(kp.publicKey, intArray2);

  Ciphertext<TYPE> cResult = cc->EvalMult(ciphertext1, ciphertext2);

  LPKeyPair<TYPE> newKp = cc->KeyGen();

  LPEvalKey<TYPE> keySwitchHint2 =
      cc->KeySwitchGen(kp.secretKey, newKp.secretKey);

  cc->KeySwitchInPlace(keySwitchHint2, cResult);

  Plaintext results;

  cc->Decrypt(newKp.secretKey, cResult, &results);

  EXPECT_EQ(results->GetCoefPackedValue().at(0), 6);
}

TEST_F(UTSHEAdvanced, test_eval_add_single_crt) {
  DEBUG_FLAG(false);
  usint m = 16;
  PlaintextModulus ptm = 20;

  float stdDev = 4;

  shared_ptr<TYPE::Params> parms =
      ElemParamFactory::GenElemParams<TYPE::Params>(m);

  CryptoContext<TYPE> cc =
      CryptoContextFactory<TYPE>::genCryptoContextBGVrns(parms, ptm, 1, stdDev);

  cc->Enable(ENCRYPTION);
  cc->Enable(SHE);
  cc->Enable(LEVELEDSHE);

  // Initialize the public key containers.
  LPKeyPair<TYPE> kp;

  DEBUG("Filling 1");
  std::vector<int64_t> vectorOfInts1 = {2, 3, 1, 4};
  Plaintext intArray1 = cc->MakeCoefPackedPlaintext(vectorOfInts1);

  DEBUG("Filling 2");
  std::vector<int64_t> vectorOfInts2 = {3, 6, 3, 1};
  Plaintext intArray2 = cc->MakeCoefPackedPlaintext(vectorOfInts2);

  DEBUG("getting pairs");
  kp = cc->KeyGen();

  DEBUG("got pairs");
  Ciphertext<TYPE> ciphertext1;
  Ciphertext<TYPE> ciphertext2;

  ciphertext1 = cc->Encrypt(kp.publicKey, intArray1);
  DEBUG("after crypt 1");
  ciphertext2 = cc->Encrypt(kp.publicKey, intArray2);
  DEBUG("after crypt 2");

  Ciphertext<TYPE> cResult;
  DEBUG("before EA");
  cResult = cc->EvalAdd(ciphertext1, ciphertext2);
  DEBUG("after");

  Ciphertext<TYPE> ciphertextResults({cResult});
  Plaintext results;

  cc->Decrypt(kp.secretKey, ciphertextResults, &results);

  EXPECT_EQ(5, results->GetCoefPackedValue().at(0));
  EXPECT_EQ(9, results->GetCoefPackedValue().at(1));
  EXPECT_EQ(4, results->GetCoefPackedValue().at(2));
  EXPECT_EQ(5, results->GetCoefPackedValue().at(3));
}

#endif
