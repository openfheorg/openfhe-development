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

#include "cryptocontext.h"

#include "encoding/encodings.h"

#include "utils/debug.h"

using namespace std;
using namespace lbcrypto;

class UTBFVBATCHING : public ::testing::Test {
 protected:
  void SetUp() {}

  void TearDown() {
    CryptoContextFactory<Poly>::ReleaseAllContexts();
    CryptoContextFactory<DCRTPoly>::ReleaseAllContexts();
  }

 public:
};

TEST_F(UTBFVBATCHING, Poly_EVALMULT_Arb) {
  PackedEncoding::Destroy();

  usint m = 22;
  PlaintextModulus p = 89;  // we choose s.t. 2m|p-1 to leverage CRTArb
  BigInteger modulusQ("72385066601");
  BigInteger modulusP(p);
  BigInteger rootOfUnity("69414828251");
  BigInteger bigmodulus("77302754575416994210914689");
  BigInteger bigroot("76686504597021638023705542");

  auto cycloPoly = GetCyclotomicPolynomial<BigVector>(m, modulusQ);
  // ChineseRemainderTransformArb<BigVector>::PreCompute(m, modulusQ);
  ChineseRemainderTransformArb<BigVector>::SetCylotomicPolynomial(cycloPoly,
                                                                  modulusQ);

  float stdDev = 4;

  auto params =
      std::make_shared<ILParams>(m, modulusQ, rootOfUnity, bigmodulus, bigroot);

  BigInteger bigEvalMultModulus("37778931862957161710549");
  BigInteger bigEvalMultRootOfUnity("7161758688665914206613");
  BigInteger bigEvalMultModulusAlt(
      "1461501637330902918203684832716283019655932547329");
  BigInteger bigEvalMultRootOfUnityAlt(
      "570268124029534407621996591794583635795426001824");

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

  std::vector<int64_t> vectorOfInts1 = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
  std::vector<int64_t> vectorOfInts2 = {10, 9, 8, 7, 6, 5, 4, 3, 2, 1};

  Plaintext intArray1 = cc->MakePackedPlaintext(vectorOfInts1);
  Plaintext intArray2 = cc->MakePackedPlaintext(vectorOfInts2);

  std::vector<int64_t> vectorOfIntsMult;
  std::transform(vectorOfInts1.begin(), vectorOfInts1.end(),
                 vectorOfInts2.begin(), std::back_inserter(vectorOfIntsMult),
                 std::multiplies<usint>());

  ciphertext1 = cc->Encrypt(kp.publicKey, intArray1);
  ciphertext2 = cc->Encrypt(kp.publicKey, intArray2);

  cc->EvalMultKeyGen(kp.secretKey);

  auto ciphertextMult = cc->EvalMult(ciphertext1, ciphertext2);
  Plaintext intArrayNew;

  cc->Decrypt(kp.secretKey, ciphertextMult, &intArrayNew);

  EXPECT_EQ(intArrayNew->GetPackedValue(), vectorOfIntsMult);
}
