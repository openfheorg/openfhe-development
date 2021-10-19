// @file evalatindex.cpp  - Example of vector rotation.
// @author TPOC: contact@palisade-crypto.org
//
// @copyright Copyright (c) 2019, New Jersey Institute of Technology (NJIT))
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
//
// @section DESCRIPTION
// This code shows how the EvalAtIndex and EvalMerge operations work for
// different cyclotomic rings (both power-of-two and cyclic)
//

#include <fstream>
#include <iostream>
#include <iterator>
#include <random>

#include "palisade.h"

using namespace std;
using namespace lbcrypto;

void BFVrnsEvalAtIndex2n();
void CKKSEvalAtIndex2n();
void NullEvalAtIndex2n();
void BFVEvalAtIndexCyclic();
void BFVrnsEvalMerge2n();
void NullEvalMerge2n();

int main() {
  std::cout
      << "\nThis code shows how the EvalAtIndex and EvalMerge operations work "
         "for different cyclotomic rings (both power-of-two and cyclic).\n"
      << std::endl;

  std::cout << "\n========== BFVrns.EvalAtIndex - Power-of-Two Cyclotomics "
               "==========="
            << std::endl;

  BFVrnsEvalAtIndex2n();

  std::cout
      << "\n========== CKKS.EvalAtIndex - Power-of-Two Cyclotomics ==========="
      << std::endl;

  CKKSEvalAtIndex2n();

  std::cout
      << "\n========== Null.EvalAtIndex - Power-of-Two Cyclotomics ==========="
      << std::endl;

  NullEvalAtIndex2n();

  std::cout << "\n========== BFV.EvalAtIndex - Cyclic group ==========="
            << std::endl;

  BFVEvalAtIndexCyclic();

  std::cout
      << "\n========== BFVrns.EvalMerge - Power-of-Two Cyclotomics ==========="
      << std::endl;

  BFVrnsEvalMerge2n();

  std::cout
      << "\n========== Null.EvalMerge - Power-of-Two Cyclotomics ==========="
      << std::endl;

  NullEvalMerge2n();

  return 0;
}

void BFVrnsEvalAtIndex2n() {
  uint64_t p = 65537;
  double sigma = 3.2;
  double rootHermiteFactor = 1.006;

  CryptoContext<DCRTPoly> cc =
      CryptoContextFactory<DCRTPoly>::genCryptoContextBFVrns(
          p, rootHermiteFactor, sigma, 0, 1, 0, OPTIMIZED, 3);

  int32_t n =
      cc->GetCryptoParameters()->GetElementParams()->GetCyclotomicOrder() / 2;

  // enable features that you wish to use
  cc->Enable(ENCRYPTION);
  cc->Enable(SHE);

  // Initialize the public key containers.
  LPKeyPair<DCRTPoly> kp = cc->KeyGen();

  vector<int32_t> indexList = {2,     3,  4,  5,      6,      7,
                               8,     9,  10, -n + 2, -n + 3, n - 1,
                               n - 2, -1, -2, -3,     -4,     -5};

  cc->EvalAtIndexKeyGen(kp.secretKey, indexList);

  std::vector<int64_t> vectorOfInts = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
  vectorOfInts.resize(n);
  vectorOfInts[n - 1] = n;
  vectorOfInts[n - 2] = n - 1;
  vectorOfInts[n - 3] = n - 2;

  Plaintext intArray = cc->MakePackedPlaintext(vectorOfInts);

  auto ciphertext = cc->Encrypt(kp.publicKey, intArray);

  for (size_t i = 0; i < 18; i++) {
    auto permutedCiphertext = cc->EvalAtIndex(ciphertext, indexList[i]);

    Plaintext intArrayNew;

    cc->Decrypt(kp.secretKey, permutedCiphertext, &intArrayNew);

    intArrayNew->SetLength(10);

    std::cout << "Automorphed array - at index " << indexList[i] << ": "
              << *intArrayNew << std::endl;
  }
}

void CKKSEvalAtIndex2n() {
  usint m = 8192;

  usint init_size = 3;
  usint dcrtBits = 40;

  CryptoContext<DCRTPoly> cc =
      CryptoContextFactory<DCRTPoly>::genCryptoContextCKKSWithParamsGen(
          m, init_size, /*numPrimes*/
          dcrtBits, 10, /*relinWindow*/
          16,           /*batch size*/
          OPTIMIZED, 3 /*depth*/);

  int32_t n = m / 4;

  cc->Enable(ENCRYPTION);
  cc->Enable(SHE);
  cc->Enable(LEVELEDSHE);

  // Initialize the public key containers.
  LPKeyPair<DCRTPoly> kp = cc->KeyGen();

  vector<int32_t> indexList = {2,     3,  4,  5,      6,      7,
                               8,     9,  10, -n + 2, -n + 3, n - 1,
                               n - 2, -1, -2, -3,     -4,     -5};

  cc->EvalAtIndexKeyGen(kp.secretKey, indexList);

  std::vector<std::complex<double>> vectorOfInts = {1, 2, 3, 4, 5,
                                                    6, 7, 8, 9, 10};
  vectorOfInts.resize(n);
  vectorOfInts[n - 1] = n;
  vectorOfInts[n - 2] = n - 1;
  vectorOfInts[n - 3] = n - 2;

  Plaintext intArray = cc->MakeCKKSPackedPlaintext(vectorOfInts);

  auto ciphertext = cc->Encrypt(kp.publicKey, intArray);

  for (size_t i = 0; i < 18; i++) {
    auto permutedCiphertext = cc->EvalAtIndex(ciphertext, indexList[i]);

    Plaintext intArrayNew;

    cc->Decrypt(kp.secretKey, permutedCiphertext, &intArrayNew);

    intArrayNew->SetLength(10);

    std::cout << "Automorphed array - at index " << indexList[i] << ": "
              << *intArrayNew << std::endl;
  }
}

void NullEvalAtIndex2n() {
  uint64_t p = 65537;
  usint m = 8192;

  CryptoContext<Poly> cc =
      CryptoContextFactory<Poly>::genCryptoContextNull(m, p);

  int32_t n =
      cc->GetCryptoParameters()->GetElementParams()->GetCyclotomicOrder() / 2;

  // enable features that you wish to use
  cc->Enable(ENCRYPTION);
  cc->Enable(SHE);

  // Initialize the public key containers.
  LPKeyPair<Poly> kp = cc->KeyGen();

  vector<int32_t> indexList = {2,     3,  4,  5,      6,      7,
                               8,     9,  10, -n + 2, -n + 3, n - 1,
                               n - 2, -1, -2, -3,     -4,     -5};

  cc->EvalAtIndexKeyGen(kp.secretKey, indexList);

  std::vector<int64_t> vectorOfInts = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
  vectorOfInts.resize(n);
  vectorOfInts[n - 1] = n;
  vectorOfInts[n - 2] = n - 1;
  vectorOfInts[n - 3] = n - 2;

  Plaintext intArray = cc->MakePackedPlaintext(vectorOfInts);

  auto ciphertext = cc->Encrypt(kp.publicKey, intArray);

  for (size_t i = 0; i < 18; i++) {
    auto permutedCiphertext = cc->EvalAtIndex(ciphertext, indexList[i]);

    Plaintext intArrayNew;

    cc->Decrypt(kp.secretKey, permutedCiphertext, &intArrayNew);

    intArrayNew->SetLength(10);

    std::cout << "Automorphed array - at index " << indexList[i] << ": "
              << *intArrayNew << std::endl;
  }
}

void BFVEvalAtIndexCyclic() {
  usint m = 22;
  usint p = 2333;
  BigInteger modulusP(p);

  BigInteger modulusQ("955263939794561");
  BigInteger squareRootOfRoot("941018665059848");

  // usint n = GetTotient(m);
  BigInteger bigmodulus("80899135611688102162227204937217");
  BigInteger bigroot("77936753846653065954043047918387");

  auto cycloPoly = GetCyclotomicPolynomial<BigVector>(m, modulusQ);
  ChineseRemainderTransformArb<BigVector>::SetCylotomicPolynomial(cycloPoly,
                                                                  modulusQ);

  float stdDev = 4;

  auto params = std::make_shared<ILParams>(m, modulusQ, squareRootOfRoot,
                                           bigmodulus, bigroot);

  BigInteger delta(modulusQ.DividedBy(modulusP));

  EncodingParams encodingParams(std::make_shared<EncodingParamsImpl>(p));

  PackedEncoding::SetParams(m, encodingParams);

  CryptoContext<Poly> cc = CryptoContextFactory<Poly>::genCryptoContextBFV(
      params, encodingParams, 8, stdDev, delta.ToString());

  cc->Enable(ENCRYPTION);
  cc->Enable(SHE);

  // Initialize the public key containers.
  LPKeyPair<Poly> kp = cc->KeyGen();

  int32_t n = 10;

  vector<int32_t> indexList = {2, 3, 4, -n + 2, n, n - 1, n - 2, -1, -2};

  cc->EvalAtIndexKeyGen(kp.secretKey, indexList);

  std::vector<int64_t> vectorOfInts = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};

  Plaintext intArray = cc->MakePackedPlaintext(vectorOfInts);

  auto ciphertext = cc->Encrypt(kp.publicKey, intArray);

  for (size_t i = 0; i < 9; i++) {
    auto permutedCiphertext = cc->EvalAtIndex(ciphertext, indexList[i]);

    Plaintext intArrayNew;

    cc->Decrypt(kp.secretKey, permutedCiphertext, &intArrayNew);

    intArrayNew->SetLength(10);

    std::cout << "Automorphed array - at index " << indexList[i] << ": "
              << *intArrayNew << std::endl;
  }
}

void BFVrnsEvalMerge2n() {
  uint64_t p = 65537;
  double sigma = 3.2;
  double rootHermiteFactor = 1.006;

  CryptoContext<DCRTPoly> cc =
      CryptoContextFactory<DCRTPoly>::genCryptoContextBFVrns(
          p, rootHermiteFactor, sigma, 0, 2, 0, OPTIMIZED, 3);

  // enable features that you wish to use
  cc->Enable(ENCRYPTION);
  cc->Enable(SHE);

  // Initialize the public key containers.
  LPKeyPair<DCRTPoly> kp = cc->KeyGen();

  vector<int32_t> indexList = {-1, -2, -3, -4, -5};

  cc->EvalAtIndexKeyGen(kp.secretKey, indexList);

  std::vector<Ciphertext<DCRTPoly>> ciphertexts;

  std::vector<int64_t> vectorOfInts1 = {32, 2, 3, 4, 5, 6, 7, 8, 9, 10};
  Plaintext intArray1 = cc->MakePackedPlaintext(vectorOfInts1);
  ciphertexts.push_back(cc->Encrypt(kp.publicKey, intArray1));

  std::vector<int64_t> vectorOfInts2 = {2, 2, 3, 4, 5, 6, 7, 8, 9, 10};
  Plaintext intArray2 = cc->MakePackedPlaintext(vectorOfInts2);
  ciphertexts.push_back(cc->Encrypt(kp.publicKey, intArray2));

  std::vector<int64_t> vectorOfInts3 = {4, 2, 3, 4, 5, 6, 7, 8, 9, 10};
  Plaintext intArray3 = cc->MakePackedPlaintext(vectorOfInts3);
  ciphertexts.push_back(cc->Encrypt(kp.publicKey, intArray3));

  std::vector<int64_t> vectorOfInts4 = {8, 2, 3, 4, 5, 6, 7, 8, 9, 10};
  Plaintext intArray4 = cc->MakePackedPlaintext(vectorOfInts4);
  ciphertexts.push_back(cc->Encrypt(kp.publicKey, intArray4));

  std::vector<int64_t> vectorOfInts5 = {16, 2, 3, 4, 5, 6, 7, 8, 9, 10};
  Plaintext intArray5 = cc->MakePackedPlaintext(vectorOfInts5);
  ciphertexts.push_back(cc->Encrypt(kp.publicKey, intArray5));

  std::cout << "Input ciphertext " << *intArray1 << std::endl;
  std::cout << "Input ciphertext " << *intArray2 << std::endl;
  std::cout << "Input ciphertext " << *intArray3 << std::endl;
  std::cout << "Input ciphertext " << *intArray4 << std::endl;
  std::cout << "Input ciphertext " << *intArray5 << std::endl;

  auto mergedCiphertext = cc->EvalMerge(ciphertexts);

  Plaintext intArrayNew;

  cc->Decrypt(kp.secretKey, mergedCiphertext, &intArrayNew);

  intArrayNew->SetLength(10);

  std::cout << "\nMerged ciphertext " << *intArrayNew << std::endl;
}

void NullEvalMerge2n() {
  uint64_t p = 65537;
  usint m = 32;

  CryptoContext<Poly> cc =
      CryptoContextFactory<Poly>::genCryptoContextNull(m, p);

  // enable features that you wish to use
  cc->Enable(ENCRYPTION);
  cc->Enable(SHE);

  // Initialize the public key containers.
  LPKeyPair<Poly> kp = cc->KeyGen();

  vector<int32_t> indexList = {-1, -2, -3, -4, -5};

  cc->EvalAtIndexKeyGen(kp.secretKey, indexList);

  std::vector<Ciphertext<Poly>> ciphertexts;

  std::vector<int64_t> vectorOfInts1 = {32, 2, 3, 4, 5, 6, 7, 8, 9, 10};
  Plaintext intArray1 = cc->MakePackedPlaintext(vectorOfInts1);
  ciphertexts.push_back(cc->Encrypt(kp.publicKey, intArray1));

  std::vector<int64_t> vectorOfInts2 = {2, 2, 3, 4, 5, 6, 7, 8, 9, 10};
  Plaintext intArray2 = cc->MakePackedPlaintext(vectorOfInts2);
  ciphertexts.push_back(cc->Encrypt(kp.publicKey, intArray2));

  std::vector<int64_t> vectorOfInts3 = {4, 2, 3, 4, 5, 6, 7, 8, 9, 10};
  Plaintext intArray3 = cc->MakePackedPlaintext(vectorOfInts3);
  ciphertexts.push_back(cc->Encrypt(kp.publicKey, intArray3));

  std::vector<int64_t> vectorOfInts4 = {8, 2, 3, 4, 5, 6, 7, 8, 9, 10};
  Plaintext intArray4 = cc->MakePackedPlaintext(vectorOfInts4);
  ciphertexts.push_back(cc->Encrypt(kp.publicKey, intArray4));

  std::vector<int64_t> vectorOfInts5 = {16, 2, 3, 4, 5, 6, 7, 8, 9, 10};
  Plaintext intArray5 = cc->MakePackedPlaintext(vectorOfInts5);
  ciphertexts.push_back(cc->Encrypt(kp.publicKey, intArray5));

  std::cout << "Input ciphertext " << *intArray1 << std::endl;
  std::cout << "Input ciphertext " << *intArray2 << std::endl;
  std::cout << "Input ciphertext " << *intArray3 << std::endl;
  std::cout << "Input ciphertext " << *intArray4 << std::endl;
  std::cout << "Input ciphertext " << *intArray5 << std::endl;

  auto mergedCiphertext = cc->EvalMerge(ciphertexts);

  Plaintext intArrayNew;

  cc->Decrypt(kp.secretKey, mergedCiphertext, &intArrayNew);

  intArrayNew->SetLength(10);

  std::cout << "\nMerged ciphertext " << *intArrayNew << std::endl;
}
