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

#include <cmath>

#include <iostream>
#include <vector>

#include "gtest/gtest.h"

#include "cryptocontext.h"

#include "encoding/encodings.h"

#include "lattice/elemparamfactory.h"
#include "utils/debug.h"
#include "utils/parmfactory.h"
#include "scheme/bgvrns/cryptocontext-bgvrns.h"
#include "gen-cryptocontext.h"

using namespace lbcrypto;

using TYPE = DCRTPoly;
// A new one of these is created for each test
class UTSHEAdvanced : public testing::Test {
 public:
  UTSHEAdvanced() {}

  void SetUp() {}

  void TearDown() {
    CryptoContextFactory<DCRTPoly>::ReleaseAllContexts();
  }
};

#if !defined(_MSC_VER)

TEST_F(UTSHEAdvanced, test_eval_mult_single_crt) {
  CCParams<CryptoContextBGVRNS> parameters;
  parameters.SetCyclotomicOrder(16);
  parameters.SetScalingFactorBits(50);
  parameters.SetPlaintextModulus(20);
  parameters.SetRelinWindow(1);
  parameters.SetStandardDeviation(4);
  parameters.SetRescalingTechnique(FIXEDMANUAL);

  CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);
  cc->Enable(PKE);
  cc->Enable(KEYSWITCH);
  cc->Enable(LEVELEDSHE);

  // Initialize the public key containers.
  KeyPair<TYPE> kp;

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

  KeyPair<TYPE> newKp = cc->KeyGen();

  EvalKey<TYPE> keySwitchHint2 =
      cc->KeySwitchGen(kp.secretKey, newKp.secretKey);

  cc->KeySwitchInPlace(cResult, keySwitchHint2);

  Plaintext results;

  cc->Decrypt(newKp.secretKey, cResult, &results);

  EXPECT_EQ(results->GetCoefPackedValue().at(0), 6);
}

TEST_F(UTSHEAdvanced, test_eval_add_single_crt) {
  OPENFHE_DEBUG_FLAG(false);
  CCParams<CryptoContextBGVRNS> parameters;
  parameters.SetCyclotomicOrder(16);
  parameters.SetPlaintextModulus(20);
  parameters.SetRelinWindow(1);
  parameters.SetStandardDeviation(4);
  parameters.SetRescalingTechnique(FIXEDMANUAL);

  CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);
  cc->Enable(PKE);
  cc->Enable(KEYSWITCH);
  cc->Enable(LEVELEDSHE);

  // Initialize the public key containers.
  KeyPair<TYPE> kp;

  OPENFHE_DEBUG("Filling 1");
  std::vector<int64_t> vectorOfInts1 = {2, 3, 1, 4};
  Plaintext intArray1 = cc->MakeCoefPackedPlaintext(vectorOfInts1);

  OPENFHE_DEBUG("Filling 2");
  std::vector<int64_t> vectorOfInts2 = {3, 6, 3, 1};
  Plaintext intArray2 = cc->MakeCoefPackedPlaintext(vectorOfInts2);

  OPENFHE_DEBUG("getting pairs");
  kp = cc->KeyGen();

  OPENFHE_DEBUG("got pairs");
  Ciphertext<TYPE> ciphertext1;
  Ciphertext<TYPE> ciphertext2;

  ciphertext1 = cc->Encrypt(kp.publicKey, intArray1);
  OPENFHE_DEBUG("after crypt 1");
  ciphertext2 = cc->Encrypt(kp.publicKey, intArray2);
  OPENFHE_DEBUG("after crypt 2");

  Ciphertext<TYPE> cResult;
  OPENFHE_DEBUG("before EA");
  cResult = cc->EvalAdd(ciphertext1, ciphertext2);
  OPENFHE_DEBUG("after");

  Ciphertext<TYPE> ciphertextResults({cResult});
  Plaintext results;

  cc->Decrypt(kp.secretKey, ciphertextResults, &results);

  EXPECT_EQ(5, results->GetCoefPackedValue().at(0));
  EXPECT_EQ(9, results->GetCoefPackedValue().at(1));
  EXPECT_EQ(4, results->GetCoefPackedValue().at(2));
  EXPECT_EQ(5, results->GetCoefPackedValue().at(3));
}

#endif

