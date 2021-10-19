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

#include <fstream>
#include <iostream>
#include "gtest/gtest.h"

#include "cryptocontext.h"

#include "encoding/encodings.h"

#include "utils/debug.h"

using namespace std;
using namespace lbcrypto;

class UnitTestEvalMultMany : public ::testing::Test {
 protected:
  virtual void SetUp() {}

  virtual void TearDown() {}

 public:
};

static CryptoContext<Poly> MakeBFVPolyCC() {
  DEBUG_FLAG(false);
  DEBUG("in MakeBFVPolyCC");
  int relWindow = 8;
  int plaintextModulus = 256;
  double sigma = 4;
  double rootHermiteFactor = 1.6;

  // Set Crypto Parameters
  CryptoContext<Poly> cryptoContext =
      CryptoContextFactory<Poly>::genCryptoContextBFV(
          plaintextModulus, rootHermiteFactor, relWindow, sigma, 0, 3, 0,
          OPTIMIZED, 4);

  cryptoContext->Enable(ENCRYPTION);
  cryptoContext->Enable(SHE);
  DEBUG("DONEMakeBFVPolyCC");
  return cryptoContext;
}

static CryptoContext<DCRTPoly> MakeBFVrnsDCRTPolyCC() {
  int plaintextModulus = 256;
  double sigma = 4;
  double rootHermiteFactor = 1.03;

  // Set Crypto Parameters
  CryptoContext<DCRTPoly> cryptoContext =
      CryptoContextFactory<DCRTPoly>::genCryptoContextBFVrns(
          plaintextModulus, rootHermiteFactor, sigma, 0, 3, 0, OPTIMIZED, 4);

  cryptoContext->Enable(ENCRYPTION);
  cryptoContext->Enable(SHE);

  return cryptoContext;
}

template <typename Element>
static void RunEvalMultManyTest(CryptoContext<Element> cc, string msg);

// Tests EvalMult w/o keyswitching and EvalMultMany for BFV in the
// OPTIMIZED mode
TEST(UTBFVEVALMM, Poly_BFV_Eval_Mult_Many_Operations_VERY_LONG) {
  RunEvalMultManyTest(MakeBFVPolyCC(), "BFV");
}

// Tests EvalMult w/o keyswitching and EvalMultMany for BFVrns in the
// OPTIMIZED mode
TEST(UTBFVrnsEVALMM, Poly_BFVrns_Eval_Mult_Many_Operations) {
  RunEvalMultManyTest(MakeBFVrnsDCRTPolyCC(), "BFVrns");
}

template <typename Element>
static void RunEvalMultManyTest(CryptoContext<Element> cryptoContext,
                                string msg) {
  DEBUG_FLAG(false);
  ////////////////////////////////////////////////////////////
  // Perform the key generation operation.
  ////////////////////////////////////////////////////////////
  DEBUG("In RunEvalMultManyTest " << msg);
  auto keyPair = cryptoContext->KeyGen();
  DEBUG("keygen");
  ASSERT_TRUE(keyPair.good()) << "Key generation failed!";
  DEBUG("EvalMultKeysGen");
  // Create evaluation key vector to be used in keyswitching
  cryptoContext->EvalMultKeysGen(keyPair.secretKey);

  ////////////////////////////////////////////////////////////
  // Plaintext
  ////////////////////////////////////////////////////////////

  std::vector<int64_t> vectorOfInts1 = {5, 4, 3, 2, 1, 0, 5, 4, 3, 2, 1, 0};
  std::vector<int64_t> vectorOfInts2 = {2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
  std::vector<int64_t> vectorOfInts3 = {3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
  std::vector<int64_t> vectorOfInts4 = {4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

  std::vector<int64_t> vectorOfInts5 = {10, 8, 6, 4, 2, 0, 10, 8, 6, 4, 2, 0};
  std::vector<int64_t> vectorOfInts6 = {30, 24, 18, 12, 6, 0,
                                        30, 24, 18, 12, 6, 0};
  std::vector<int64_t> vectorOfInts7 = {120, 96, 72, 48, 24, 0,
                                        120, 96, 72, 48, 24, 0};
  DEBUG("MakeCoefPackedPlaintext");
  Plaintext plaintext1 = cryptoContext->MakeCoefPackedPlaintext(vectorOfInts1);
  Plaintext plaintext2 = cryptoContext->MakeCoefPackedPlaintext(vectorOfInts2);
  Plaintext plaintext3 = cryptoContext->MakeCoefPackedPlaintext(vectorOfInts3);
  Plaintext plaintext4 = cryptoContext->MakeCoefPackedPlaintext(vectorOfInts4);

  Plaintext plaintextResult1 =
      cryptoContext->MakeCoefPackedPlaintext(vectorOfInts5);
  Plaintext plaintextResult2 =
      cryptoContext->MakeCoefPackedPlaintext(vectorOfInts6);
  Plaintext plaintextResult3 =
      cryptoContext->MakeCoefPackedPlaintext(vectorOfInts7);

  ////////////////////////////////////////////////////////////
  // Encryption
  ////////////////////////////////////////////////////////////
  DEBUG("Encryption");
  auto ciphertext1 = cryptoContext->Encrypt(keyPair.publicKey, plaintext1);
  auto ciphertext2 = cryptoContext->Encrypt(keyPair.publicKey, plaintext2);
  auto ciphertext3 = cryptoContext->Encrypt(keyPair.publicKey, plaintext3);
  auto ciphertext4 = cryptoContext->Encrypt(keyPair.publicKey, plaintext4);

  ////////////////////////////////////////////////////////////
  // EvalMult Operation
  ////////////////////////////////////////////////////////////
  DEBUG("EvalMults");
  // Perform consecutive multiplications and do a keyswtiching at the end.
  auto ciphertextMul12 =
      cryptoContext->EvalMultNoRelin(ciphertext1, ciphertext2);
  auto ciphertextMul123 =
      cryptoContext->EvalMultNoRelin(ciphertextMul12, ciphertext3);
  auto ciphertextMul1234 =
      cryptoContext->EvalMultAndRelinearize(ciphertextMul123, ciphertext4);

  ////////////////////////////////////////////////////////////
  // Decryption of multiplicative results with and without keyswtiching (depends
  // on the level)
  ////////////////////////////////////////////////////////////

  Plaintext plaintextMul1;
  Plaintext plaintextMul2;
  Plaintext plaintextMul3;
  DEBUG("DECRYPTIO");
  cryptoContext->Decrypt(keyPair.secretKey, ciphertextMul12, &plaintextMul1);
  cryptoContext->Decrypt(keyPair.secretKey, ciphertextMul123, &plaintextMul2);
  cryptoContext->Decrypt(keyPair.secretKey, ciphertextMul1234, &plaintextMul3);

  ////////////////////////////////////////////////////////////
  // Prepare EvalMultMany
  ////////////////////////////////////////////////////////////

  vector<Ciphertext<Element>> cipherTextList;

  cipherTextList.push_back(ciphertext1);
  cipherTextList.push_back(ciphertext2);
  cipherTextList.push_back(ciphertext3);
  cipherTextList.push_back(ciphertext4);

  ////////////////////////////////////////////////////////////
  // Compute EvalMultMany
  ////////////////////////////////////////////////////////////

  auto ciphertextMul12345 = cryptoContext->EvalMultMany(cipherTextList);

  ////////////////////////////////////////////////////////////
  // Decrypt EvalMultMany
  ////////////////////////////////////////////////////////////

  Plaintext plaintextMulMany;
  cryptoContext->Decrypt(keyPair.secretKey, ciphertextMul12345,
                         &plaintextMulMany);

  plaintextResult1->SetLength(plaintextMul1->GetLength());
  plaintextResult2->SetLength(plaintextMul2->GetLength());
  plaintextResult3->SetLength(plaintextMul3->GetLength());

  EXPECT_EQ(*plaintextMul1, *plaintextResult1)
      << msg << ".EvalMult gives incorrect results.\n";
  EXPECT_EQ(*plaintextMul2, *plaintextResult2)
      << msg << ".EvalMult gives incorrect results.\n";
  EXPECT_EQ(*plaintextMul3, *plaintextResult3)
      << msg << ".EvalMultAndRelinearize gives incorrect results.\n";
  EXPECT_EQ(*plaintextMulMany, *plaintextResult3)
      << msg << ".EvalMultMany gives incorrect results.\n";
}
