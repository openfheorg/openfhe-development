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
#include <random>
#include <vector>
#include "gtest/gtest.h"

#include "cryptocontext.h"

#include "encoding/encodings.h"

#include "utils/debug.h"

using namespace std;
using namespace lbcrypto;

class UTEvalIP : public ::testing::Test {
 protected:
  void SetUp() {}

  void TearDown() {
    CryptoContextFactory<Poly>::ReleaseAllContexts();
    CryptoContextFactory<DCRTPoly>::ReleaseAllContexts();
  }

 public:
};

int64_t ArbBFVInnerProductPackedArray(std::vector<int64_t>& input1,
                                      std::vector<int64_t>& input2);

TEST_F(UTEvalIP, Test_BFV_EvalInnerProduct) {
  usint size = 10;
  std::vector<int64_t> input1(size, 0);
  std::vector<int64_t> input2(size, 0);
  usint limit = 15;
  usint plainttextMod = 2333;

  PRNG rand_engine(1);
  uniform_int_distribution<usint> dist(0, limit);

  auto gen = std::bind(dist, rand_engine);
  generate(input1.begin(), input1.end() - 2, gen);
  generate(input2.begin(), input2.end() - 2, gen);

  int64_t expectedResult =
      std::inner_product(input1.begin(), input1.end(), input2.begin(), 0);
  expectedResult %= plainttextMod;

  int64_t half = int64_t(plainttextMod) / 2;

  if (expectedResult > half) expectedResult -= plainttextMod;

  try {
    int64_t result = ArbBFVInnerProductPackedArray(input1, input2);

    EXPECT_EQ(result, expectedResult);
  } catch (const std::logic_error &e) {
    FAIL() << e.what();
  }
}

int64_t ArbBFVInnerProductPackedArray(std::vector<int64_t> &input1,
                                      std::vector<int64_t> &input2) {
  usint m = 22;
  PlaintextModulus p = 2333;  // we choose s.t. 2m|p-1 to leverage CRTArb
  BigInteger modulusQ("1152921504606847009");
  BigInteger modulusP(p);
  BigInteger rootOfUnity("1147559132892757400");

  BigInteger bigmodulus("42535295865117307932921825928971026753");
  BigInteger bigroot("13201431150704581233041184864526870950");

  auto cycloPoly = GetCyclotomicPolynomial<BigVector>(m, modulusQ);
  ChineseRemainderTransformArb<BigVector>::SetCylotomicPolynomial(cycloPoly,
                                                                  modulusQ);

  float stdDev = 4;
  auto params =
      std::make_shared<ILParams>(m, modulusQ, rootOfUnity, bigmodulus, bigroot);

  BigInteger bigEvalMultModulus("42535295865117307932921825928971026753");
  BigInteger bigEvalMultRootOfUnity("22649103892665819561201725524201801241");
  BigInteger bigEvalMultModulusAlt(
      "115792089237316195423570985008687907853269984665640564039457584007913129"
      "642241");
  BigInteger bigEvalMultRootOfUnityAlt(
      "378615503042744655685234439862468415306448471137816667281217177222856678"
      "62085");

  auto cycloPolyBig = GetCyclotomicPolynomial<BigVector>(m, bigEvalMultModulus);
  ChineseRemainderTransformArb<BigVector>::SetCylotomicPolynomial(
      cycloPolyBig, bigEvalMultModulus);

  usint batchSize = 8;

  EncodingParams encodingParams(std::make_shared<EncodingParamsImpl>(
      p, batchSize, PackedEncoding::GetAutomorphismGenerator(m)));

  PackedEncoding::SetParams(m, encodingParams);

  BigInteger delta(modulusQ.DividedBy(modulusP));

  CryptoContext<Poly> cc = CryptoContextFactory<Poly>::genCryptoContextBFV(
      params, encodingParams, 1, stdDev, delta.ToString(), OPTIMIZED,
      bigEvalMultModulus.ToString(), bigEvalMultRootOfUnity.ToString(), 1, 9,
      1.006, bigEvalMultModulusAlt.ToString(),
      bigEvalMultRootOfUnityAlt.ToString());

  cc->Enable(ENCRYPTION);
  cc->Enable(SHE);

  // Initialize the public key containers.
  LPKeyPair<Poly> kp = cc->KeyGen();

  Ciphertext<Poly> ciphertext1;
  Ciphertext<Poly> ciphertext2;

  std::vector<int64_t> vectorOfInts1 = std::move(input1);
  std::vector<int64_t> vectorOfInts2 = std::move(input2);

  Plaintext intArray1 = cc->MakePackedPlaintext(vectorOfInts1);
  Plaintext intArray2 = cc->MakePackedPlaintext(vectorOfInts2);

  cc->EvalSumKeyGen(kp.secretKey);
  cc->EvalMultKeyGen(kp.secretKey);

  ciphertext1 = cc->Encrypt(kp.publicKey, intArray1);
  ciphertext2 = cc->Encrypt(kp.publicKey, intArray2);

  auto result = cc->EvalInnerProduct(ciphertext1, ciphertext2, batchSize);

  Plaintext intArrayNew;

  cc->Decrypt(kp.secretKey, result, &intArrayNew);

  return intArrayNew->GetPackedValue()[0];
}
