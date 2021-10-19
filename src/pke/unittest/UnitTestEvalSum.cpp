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

class UTEvalSum : public ::testing::Test {
 protected:
  void SetUp() {}

  void TearDown() {
    CryptoContextFactory<Poly>::ReleaseAllContexts();
    CryptoContextFactory<DCRTPoly>::ReleaseAllContexts();
  }

 public:
};

int64_t ArbBFVEvalSumPackedArray(std::vector<int64_t> &clearVector,
                                 PlaintextModulus p);

void EvalSumSetup(std::vector<int64_t> &input, int64_t &expectedSum,
                  PlaintextModulus plaintextMod) {
  usint limit = 15;

  PRNG random_engine(1);
  uniform_int_distribution<usint> dist(0, limit);

  auto gen = std::bind(dist, random_engine);
  generate(input.begin(), input.end() - 2, gen);

  expectedSum = std::accumulate(input.begin(), input.end(), 0);

  expectedSum %= plaintextMod;

  int64_t half = int64_t(plaintextMod) / 2;

  if (expectedSum > half) expectedSum -= plaintextMod;
}

TEST_F(UTEvalSum, Test_BFV_EvalSum) {
  usint size = 10;
  std::vector<int64_t> input(size, 0);
  int64_t expectedSum;

  EvalSumSetup(input, expectedSum, 89);

  int64_t result = ArbBFVEvalSumPackedArray(input, 89);

  EXPECT_EQ(expectedSum, result);
}

int64_t ArbBFVEvalSumPackedArray(std::vector<int64_t> &clearVector,
                                 PlaintextModulus p) {
  usint m = 22;
  BigInteger modulusP(p);

  BigInteger modulusQ("955263939794561");
  BigInteger squareRootOfRoot("941018665059848");

  BigInteger bigmodulus("80899135611688102162227204937217");
  BigInteger bigroot("77936753846653065954043047918387");

  auto cycloPoly = GetCyclotomicPolynomial<BigVector>(m, modulusQ);
  ChineseRemainderTransformArb<BigVector>::SetCylotomicPolynomial(cycloPoly,
                                                                  modulusQ);

  float stdDev = 4;

  usint batchSize = 8;

  auto params = std::make_shared<ILParams>(m, modulusQ, squareRootOfRoot,
                                           bigmodulus, bigroot);

  EncodingParams encodingParams(std::make_shared<EncodingParamsImpl>(
      p, batchSize, PackedEncoding::GetAutomorphismGenerator(m)));

  PackedEncoding::SetParams(m, encodingParams);

  BigInteger delta(modulusQ.DividedBy(modulusP));

  CryptoContext<Poly> cc = CryptoContextFactory<Poly>::genCryptoContextBFV(
      params, encodingParams, 8, stdDev, delta.ToString());

  cc->Enable(ENCRYPTION);
  cc->Enable(SHE);

  // Initialize the public key containers.
  LPKeyPair<Poly> kp = cc->KeyGen();

  Ciphertext<Poly> ciphertext;

  std::vector<int64_t> vectorOfInts = std::move(clearVector);
  Plaintext intArray = cc->MakePackedPlaintext(vectorOfInts);

  cc->EvalSumKeyGen(kp.secretKey);

  ciphertext = cc->Encrypt(kp.publicKey, intArray);

  auto ciphertextSum = cc->EvalSum(ciphertext, batchSize);

  Plaintext intArrayNew;

  cc->Decrypt(kp.secretKey, ciphertextSum, &intArrayNew);

  return intArrayNew->GetPackedValue()[0];
}
