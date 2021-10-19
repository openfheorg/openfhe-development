/*
 * @file lib-benchmark : library benchmark routines for comparison by build
 * @author TPOC: contact@palisade-crypto.org
 *
 * @copyright Copyright (c) 2019, New Jersey Institute of Technology (NJIT)
 * All rights reserved.
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution. THIS SOFTWARE IS
 * PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO
 * EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

/*
 * This file benchmarks a small number of operations in order to exercise large
 * pieces of the library
 */

#define PROFILE
#define _USE_MATH_DEFINES
#include "benchmark/benchmark.h"

#include <fstream>
#include <iostream>
#include <iterator>
#include <limits>
#include <random>

#include "palisade.h"

#include "cryptocontextgen.h"
#include "cryptocontexthelper.h"

#include "utils/debug.h"

using namespace std;
using namespace lbcrypto;

/*
 * Context setup utility methods
 */

CryptoContext<DCRTPoly> GenerateBFVrnsContext() {
  // Set the main parameters
  int plaintextModulus = 65537;
  double sigma = 3.2;
  SecurityLevel securityLevel = HEStd_128_classic;
  uint32_t depth = 1;

  // Instantiate the crypto context
  CryptoContext<DCRTPoly> cryptoContext =
      CryptoContextFactory<DCRTPoly>::genCryptoContextBFVrns(
          plaintextModulus, securityLevel, sigma, 0, depth, 0, OPTIMIZED);

  // Enable features that you wish to use
  cryptoContext->Enable(ENCRYPTION);
  cryptoContext->Enable(SHE);

  return cryptoContext;
}

CryptoContext<DCRTPoly> GenerateCKKSContext() {
  uint32_t multDepth = 1;
  uint32_t scaleFactorBits = 48;
  uint32_t batchSize = 8;
  SecurityLevel securityLevel = HEStd_128_classic;

  // The following call creates a CKKS crypto context based on the
  // arguments defined above.
  CryptoContext<DCRTPoly> cc =
      CryptoContextFactory<DCRTPoly>::genCryptoContextCKKS(
          multDepth, scaleFactorBits, batchSize, securityLevel, 0,
          APPROXRESCALE);

  cc->Enable(PKESchemeFeature::ENCRYPTION);
  cc->Enable(PKESchemeFeature::SHE);
  cc->Enable(PKESchemeFeature::LEVELEDSHE);

  return cc;
}

CryptoContext<DCRTPoly> GenerateBGVrnsContext() {
  // Set the main parameters
  int plaintextModulus = 65537;
  double sigma = 3.2;
  SecurityLevel securityLevel = HEStd_128_classic;
  uint32_t depth = 1;

  // Instantiate the crypto context
  CryptoContext<DCRTPoly> cryptoContext =
      CryptoContextFactory<DCRTPoly>::genCryptoContextBGVrns(
          depth, plaintextModulus, securityLevel, sigma, depth, OPTIMIZED,
          HYBRID, 0, 0, 0, 0, 0, 0, MANUAL);

  cryptoContext->Enable(ENCRYPTION);
  cryptoContext->Enable(SHE);
  cryptoContext->Enable(LEVELEDSHE);

  return cryptoContext;
}

void NTTTransform1024(benchmark::State &state) {
  usint m = 2048;
  usint phim = 1024;

  NativeInteger modulusQ("288230376151748609");
  NativeInteger rootOfUnity = RootOfUnity(m, modulusQ);

  DiscreteUniformGeneratorImpl<NativeVector> dug;
  dug.SetModulus(modulusQ);
  NativeVector x = dug.GenerateVector(phim);
  NativeVector X(phim);

  ChineseRemainderTransformFTT<NativeVector>::PreCompute(rootOfUnity, m,
                                                         modulusQ);

  while (state.KeepRunning()) {
    ChineseRemainderTransformFTT<NativeVector>::ForwardTransformToBitReverse(
        x, rootOfUnity, m, &X);
  }
}

BENCHMARK(NTTTransform1024)->Unit(benchmark::kMicrosecond);

void INTTTransform1024(benchmark::State &state) {
  usint m = 2048;
  usint phim = 1024;

  NativeInteger modulusQ("288230376151748609");
  NativeInteger rootOfUnity = RootOfUnity(m, modulusQ);

  DiscreteUniformGeneratorImpl<NativeVector> dug;
  dug.SetModulus(modulusQ);
  NativeVector x = dug.GenerateVector(phim);
  NativeVector X(phim);

  ChineseRemainderTransformFTT<NativeVector>::PreCompute(rootOfUnity, m,
                                                         modulusQ);

  while (state.KeepRunning()) {
    ChineseRemainderTransformFTT<NativeVector>::InverseTransformFromBitReverse(
        x, rootOfUnity, m, &X);
  }
}

BENCHMARK(INTTTransform1024)->Unit(benchmark::kMicrosecond);

void NTTTransform4096(benchmark::State &state) {
  usint m = 8192;
  usint phim = 4096;

  NativeInteger modulusQ("1152921496017387521");
  NativeInteger rootOfUnity = RootOfUnity(m, modulusQ);

  DiscreteUniformGeneratorImpl<NativeVector> dug;
  dug.SetModulus(modulusQ);
  NativeVector x = dug.GenerateVector(phim);
  NativeVector X(phim);

  ChineseRemainderTransformFTT<NativeVector>::PreCompute(rootOfUnity, m,
                                                         modulusQ);

  while (state.KeepRunning()) {
    ChineseRemainderTransformFTT<NativeVector>::ForwardTransformToBitReverse(
        x, rootOfUnity, m, &X);
  }
}

BENCHMARK(NTTTransform4096)->Unit(benchmark::kMicrosecond);

void INTTTransform4096(benchmark::State &state) {
  usint m = 8192;
  usint phim = 4096;

  NativeInteger modulusQ("1152921496017387521");
  NativeInteger rootOfUnity = RootOfUnity(m, modulusQ);

  DiscreteUniformGeneratorImpl<NativeVector> dug;
  dug.SetModulus(modulusQ);
  NativeVector x = dug.GenerateVector(phim);
  NativeVector X(phim);

  ChineseRemainderTransformFTT<NativeVector>::PreCompute(rootOfUnity, m,
                                                         modulusQ);

  while (state.KeepRunning()) {
    ChineseRemainderTransformFTT<NativeVector>::InverseTransformFromBitReverse(
        x, rootOfUnity, m, &X);
  }
}

BENCHMARK(INTTTransform4096)->Unit(benchmark::kMicrosecond);

void NTTTransformInPlace1024(benchmark::State &state) {
  usint m = 2048;
  usint phim = 1024;

  NativeInteger modulusQ("288230376151748609");
  NativeInteger rootOfUnity = RootOfUnity(m, modulusQ);

  DiscreteUniformGeneratorImpl<NativeVector> dug;
  dug.SetModulus(modulusQ);
  NativeVector x = dug.GenerateVector(phim);

  ChineseRemainderTransformFTT<NativeVector>::PreCompute(rootOfUnity, m,
                                                         modulusQ);

  while (state.KeepRunning()) {
    ChineseRemainderTransformFTT<
        NativeVector>::ForwardTransformToBitReverseInPlace(rootOfUnity, m, &x);
  }
}

BENCHMARK(NTTTransformInPlace1024)->Unit(benchmark::kMicrosecond);

void INTTTransformInPlace1024(benchmark::State &state) {
  usint m = 2048;
  usint phim = 1024;

  NativeInteger modulusQ("288230376151748609");
  NativeInteger rootOfUnity = RootOfUnity(m, modulusQ);

  DiscreteUniformGeneratorImpl<NativeVector> dug;
  dug.SetModulus(modulusQ);
  NativeVector x = dug.GenerateVector(phim);

  ChineseRemainderTransformFTT<NativeVector>::PreCompute(rootOfUnity, m,
                                                         modulusQ);

  while (state.KeepRunning()) {
    ChineseRemainderTransformFTT<
        NativeVector>::InverseTransformFromBitReverseInPlace(rootOfUnity, m,
                                                             &x);
  }
}

BENCHMARK(INTTTransformInPlace1024)->Unit(benchmark::kMicrosecond);

void NTTTransformInPlace4096(benchmark::State &state) {
  usint m = 8192;
  usint phim = 4096;

  NativeInteger modulusQ("1152921496017387521");
  NativeInteger rootOfUnity = RootOfUnity(m, modulusQ);

  DiscreteUniformGeneratorImpl<NativeVector> dug;
  dug.SetModulus(modulusQ);
  NativeVector x = dug.GenerateVector(phim);

  ChineseRemainderTransformFTT<NativeVector>::PreCompute(rootOfUnity, m,
                                                         modulusQ);

  while (state.KeepRunning()) {
    ChineseRemainderTransformFTT<
        NativeVector>::ForwardTransformToBitReverseInPlace(rootOfUnity, m, &x);
  }
}

BENCHMARK(NTTTransformInPlace4096)->Unit(benchmark::kMicrosecond);

void INTTTransformInPlace4096(benchmark::State &state) {
  usint m = 8192;
  usint phim = 4096;

  NativeInteger modulusQ("1152921496017387521");
  NativeInteger rootOfUnity = RootOfUnity(m, modulusQ);

  DiscreteUniformGeneratorImpl<NativeVector> dug;
  dug.SetModulus(modulusQ);
  NativeVector x = dug.GenerateVector(phim);
  NativeVector X(phim);

  ChineseRemainderTransformFTT<NativeVector>::PreCompute(rootOfUnity, m,
                                                         modulusQ);

  while (state.KeepRunning()) {
    ChineseRemainderTransformFTT<
        NativeVector>::InverseTransformFromBitReverseInPlace(rootOfUnity, m,
                                                             &x);
  }
}

BENCHMARK(INTTTransformInPlace4096)->Unit(benchmark::kMicrosecond);

/*
 * BFVrns benchmarks
 */

void BFVrns_KeyGen(benchmark::State &state) {
  CryptoContext<DCRTPoly> cryptoContext = GenerateBFVrnsContext();

  LPKeyPair<DCRTPoly> keyPair;

  while (state.KeepRunning()) {
    keyPair = cryptoContext->KeyGen();
  }
}

BENCHMARK(BFVrns_KeyGen)->Unit(benchmark::kMicrosecond);

void BFVrns_MultKeyGen(benchmark::State &state) {
  CryptoContext<DCRTPoly> cc = GenerateBFVrnsContext();

  LPKeyPair<DCRTPoly> keyPair;
  keyPair = cc->KeyGen();

  while (state.KeepRunning()) {
    cc->EvalMultKeyGen(keyPair.secretKey);
  }
}

BENCHMARK(BFVrns_MultKeyGen)->Unit(benchmark::kMicrosecond);

void BFVrns_EvalAtIndexKeyGen(benchmark::State &state) {
  CryptoContext<DCRTPoly> cc = GenerateBFVrnsContext();

  LPKeyPair<DCRTPoly> keyPair;
  keyPair = cc->KeyGen();

  std::vector<int32_t> indexList(1);
  for (usint i = 0; i < 1; i++) {
    indexList[i] = 1;
  }

  while (state.KeepRunning()) {
    cc->EvalAtIndexKeyGen(keyPair.secretKey, indexList);
  }
}

BENCHMARK(BFVrns_EvalAtIndexKeyGen)->Unit(benchmark::kMicrosecond);

void BFVrns_Encryption(benchmark::State &state) {
  CryptoContext<DCRTPoly> cryptoContext = GenerateBFVrnsContext();

  LPKeyPair<DCRTPoly> keyPair = cryptoContext->KeyGen();

  std::vector<int64_t> vectorOfInts1 = {1, 0, 1, 0, 1, 1, 1, 0, 1, 1, 1, 0};
  Plaintext plaintext1 = cryptoContext->MakePackedPlaintext(vectorOfInts1);

  while (state.KeepRunning()) {
    auto ciphertext1 = cryptoContext->Encrypt(keyPair.publicKey, plaintext1);
  }
}

BENCHMARK(BFVrns_Encryption)->Unit(benchmark::kMicrosecond);

void BFVrns_Decryption(benchmark::State &state) {
  CryptoContext<DCRTPoly> cryptoContext = GenerateBFVrnsContext();

  LPKeyPair<DCRTPoly> keyPair = cryptoContext->KeyGen();

  std::vector<int64_t> vectorOfInts1 = {1, 0, 1, 0, 1, 1, 1, 0, 1, 1, 1, 0};
  Plaintext plaintext1 = cryptoContext->MakePackedPlaintext(vectorOfInts1);

  auto ciphertext1 = cryptoContext->Encrypt(keyPair.publicKey, plaintext1);
  Plaintext plaintextDec1;

  while (state.KeepRunning()) {
    cryptoContext->Decrypt(keyPair.secretKey, ciphertext1, &plaintextDec1);
  }
}

BENCHMARK(BFVrns_Decryption)->Unit(benchmark::kMicrosecond);

void BFVrns_Add(benchmark::State &state) {
  CryptoContext<DCRTPoly> cc = GenerateBFVrnsContext();

  LPKeyPair<DCRTPoly> keyPair = cc->KeyGen();

  std::vector<int64_t> vectorOfInts1 = {1, 0, 1, 0, 1, 1, 1, 0, 1, 1, 1, 0};
  std::vector<int64_t> vectorOfInts2 = {0, 1, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1};

  auto plaintext1 = cc->MakePackedPlaintext(vectorOfInts1);
  auto plaintext2 = cc->MakePackedPlaintext(vectorOfInts2);

  auto ciphertext1 = cc->Encrypt(keyPair.publicKey, plaintext1);
  auto ciphertext2 = cc->Encrypt(keyPair.publicKey, plaintext2);

  while (state.KeepRunning()) {
    auto ciphertextAdd = cc->EvalAdd(ciphertext1, ciphertext2);
  }
}

BENCHMARK(BFVrns_Add)->Unit(benchmark::kMicrosecond);

void BFVrns_AddInPlace(benchmark::State &state) {
  CryptoContext<DCRTPoly> cc = GenerateBFVrnsContext();

  LPKeyPair<DCRTPoly> keyPair = cc->KeyGen();

  std::vector<int64_t> vectorOfInts1 = {1, 0, 1, 0, 1, 1, 1, 0, 1, 1, 1, 0};
  std::vector<int64_t> vectorOfInts2 = {0, 1, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1};

  auto plaintext1 = cc->MakePackedPlaintext(vectorOfInts1);
  auto plaintext2 = cc->MakePackedPlaintext(vectorOfInts2);

  auto ciphertext1 = cc->Encrypt(keyPair.publicKey, plaintext1);
  auto ciphertext2 = cc->Encrypt(keyPair.publicKey, plaintext2);

  while (state.KeepRunning()) {
    cc->EvalAddInPlace(ciphertext1, ciphertext2);
  }
}

BENCHMARK(BFVrns_AddInPlace)->Unit(benchmark::kMicrosecond);

void BFVrns_MultNoRelin(benchmark::State &state) {
  CryptoContext<DCRTPoly> cryptoContext = GenerateBFVrnsContext();

  LPKeyPair<DCRTPoly> keyPair = cryptoContext->KeyGen();

  std::vector<int64_t> vectorOfInts1 = {1, 0, 1, 0, 1, 1, 1, 0, 1, 1, 1, 0};
  Plaintext plaintext1 = cryptoContext->MakePackedPlaintext(vectorOfInts1);

  std::vector<int64_t> vectorOfInts2 = {1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 0};
  Plaintext plaintext2 = cryptoContext->MakePackedPlaintext(vectorOfInts2);

  auto ciphertext1 = cryptoContext->Encrypt(keyPair.publicKey, plaintext1);
  auto ciphertext2 = cryptoContext->Encrypt(keyPair.publicKey, plaintext2);

  while (state.KeepRunning()) {
    auto ciphertextMul =
        cryptoContext->EvalMultNoRelin(ciphertext1, ciphertext2);
  }
}

BENCHMARK(BFVrns_MultNoRelin)->Unit(benchmark::kMicrosecond);

void BFVrns_MultRelin(benchmark::State &state) {
  CryptoContext<DCRTPoly> cryptoContext = GenerateBFVrnsContext();

  LPKeyPair<DCRTPoly> keyPair = cryptoContext->KeyGen();
  cryptoContext->EvalMultKeyGen(keyPair.secretKey);

  std::vector<int64_t> vectorOfInts1 = {1, 0, 1, 0, 1, 1, 1, 0, 1, 1, 1, 0};
  Plaintext plaintext1 = cryptoContext->MakePackedPlaintext(vectorOfInts1);

  std::vector<int64_t> vectorOfInts2 = {1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 0};
  Plaintext plaintext2 = cryptoContext->MakePackedPlaintext(vectorOfInts2);

  auto ciphertext1 = cryptoContext->Encrypt(keyPair.publicKey, plaintext1);
  auto ciphertext2 = cryptoContext->Encrypt(keyPair.publicKey, plaintext2);

  while (state.KeepRunning()) {
    auto ciphertextMul = cryptoContext->EvalMult(ciphertext1, ciphertext2);
  }
}

BENCHMARK(BFVrns_MultRelin)->Unit(benchmark::kMicrosecond);

void BFVrns_EvalAtIndex(benchmark::State &state) {
  CryptoContext<DCRTPoly> cc = GenerateBFVrnsContext();

  LPKeyPair<DCRTPoly> keyPair = cc->KeyGen();
  cc->EvalMultKeyGen(keyPair.secretKey);

  std::vector<int32_t> indexList(1);
  for (usint i = 0; i < 1; i++) {
    indexList[i] = 1;
  }

  cc->EvalAtIndexKeyGen(keyPair.secretKey, indexList);

  std::vector<int64_t> vectorOfInts1 = {1, 0, 1, 0, 1, 1, 1, 0, 1, 1, 1, 0};
  std::vector<int64_t> vectorOfInts2 = {0, 1, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1};

  auto plaintext1 = cc->MakePackedPlaintext(vectorOfInts1);
  auto plaintext2 = cc->MakePackedPlaintext(vectorOfInts2);

  auto ciphertext1 = cc->Encrypt(keyPair.publicKey, plaintext1);
  auto ciphertext2 = cc->Encrypt(keyPair.publicKey, plaintext2);

  auto ciphertextMul = cc->EvalMult(ciphertext1, ciphertext2);

  while (state.KeepRunning()) {
    auto ciphertext3 = cc->EvalAtIndex(ciphertextMul, 1);
  }
}

BENCHMARK(BFVrns_EvalAtIndex)->Unit(benchmark::kMicrosecond);

/*
 * CKKS benchmarks
 * */

void CKKS_KeyGen(benchmark::State &state) {
  CryptoContext<DCRTPoly> cryptoContext = GenerateCKKSContext();

  LPKeyPair<DCRTPoly> keyPair;

  while (state.KeepRunning()) {
    keyPair = cryptoContext->KeyGen();
  }
}

BENCHMARK(CKKS_KeyGen)->Unit(benchmark::kMicrosecond);

void CKKS_MultKeyGen(benchmark::State &state) {
  CryptoContext<DCRTPoly> cc = GenerateCKKSContext();

  LPKeyPair<DCRTPoly> keyPair;
  keyPair = cc->KeyGen();

  while (state.KeepRunning()) {
    cc->EvalMultKeyGen(keyPair.secretKey);
  }
}

BENCHMARK(CKKS_MultKeyGen)->Unit(benchmark::kMicrosecond);

void CKKS_EvalAtIndexKeyGen(benchmark::State &state) {
  CryptoContext<DCRTPoly> cc = GenerateCKKSContext();

  LPKeyPair<DCRTPoly> keyPair;
  keyPair = cc->KeyGen();

  std::vector<int32_t> indexList(1);
  for (usint i = 0; i < 1; i++) {
    indexList[i] = 1;
  }

  while (state.KeepRunning()) {
    cc->EvalAtIndexKeyGen(keyPair.secretKey, indexList);
  }
}

BENCHMARK(CKKS_EvalAtIndexKeyGen)->Unit(benchmark::kMicrosecond);

void CKKS_Encryption(benchmark::State &state) {
  CryptoContext<DCRTPoly> cc = GenerateCKKSContext();

  LPKeyPair<DCRTPoly> keyPair = cc->KeyGen();

  usint slots = cc->GetEncodingParams()->GetBatchSize();
  std::vector<std::complex<double>> vectorOfInts(slots);
  for (usint i = 0; i < slots; i++) {
    vectorOfInts[i] = 1.001 * i;
  }

  auto plaintext = cc->MakeCKKSPackedPlaintext(vectorOfInts);

  while (state.KeepRunning()) {
    auto ciphertext = cc->Encrypt(keyPair.publicKey, plaintext);
  }
}

BENCHMARK(CKKS_Encryption)->Unit(benchmark::kMicrosecond);

void CKKS_Decryption(benchmark::State &state) {
  CryptoContext<DCRTPoly> cc = GenerateCKKSContext();

  LPKeyPair<DCRTPoly> keyPair = cc->KeyGen();

  usint slots = cc->GetEncodingParams()->GetBatchSize();
  std::vector<std::complex<double>> vectorOfInts1(slots);
  for (usint i = 0; i < slots; i++) {
    vectorOfInts1[i] = 1.001 * i;
  }

  auto plaintext1 = cc->MakeCKKSPackedPlaintext(vectorOfInts1);
  auto ciphertext1 = cc->Encrypt(keyPair.publicKey, plaintext1);
  ciphertext1 = cc->LevelReduce(ciphertext1, nullptr, 1);

  Plaintext plaintextDec1;

  while (state.KeepRunning()) {
    cc->Decrypt(keyPair.secretKey, ciphertext1, &plaintextDec1);
  }
}

BENCHMARK(CKKS_Decryption)->Unit(benchmark::kMicrosecond);

void CKKS_Add(benchmark::State &state) {
  CryptoContext<DCRTPoly> cc = GenerateCKKSContext();

  LPKeyPair<DCRTPoly> keyPair = cc->KeyGen();

  usint slots = cc->GetEncodingParams()->GetBatchSize();
  std::vector<std::complex<double>> vectorOfInts1(slots);
  for (usint i = 0; i < slots; i++) {
    vectorOfInts1[i] = 1.001 * i;
  }
  std::vector<std::complex<double>> vectorOfInts2(vectorOfInts1);

  auto plaintext1 = cc->MakeCKKSPackedPlaintext(vectorOfInts1);
  auto plaintext2 = cc->MakeCKKSPackedPlaintext(vectorOfInts2);

  auto ciphertext1 = cc->Encrypt(keyPair.publicKey, plaintext1);
  auto ciphertext2 = cc->Encrypt(keyPair.publicKey, plaintext2);

  while (state.KeepRunning()) {
    auto ciphertextAdd = cc->EvalAdd(ciphertext1, ciphertext2);
  }
}

BENCHMARK(CKKS_Add)->Unit(benchmark::kMicrosecond);

void CKKS_AddInPlace(benchmark::State &state) {
  CryptoContext<DCRTPoly> cc = GenerateCKKSContext();

  LPKeyPair<DCRTPoly> keyPair = cc->KeyGen();

  usint slots = cc->GetEncodingParams()->GetBatchSize();
  std::vector<std::complex<double>> vectorOfInts1(slots);
  for (usint i = 0; i < slots; i++) {
    vectorOfInts1[i] = 1.001 * i;
  }
  std::vector<std::complex<double>> vectorOfInts2(vectorOfInts1);

  auto plaintext1 = cc->MakeCKKSPackedPlaintext(vectorOfInts1);
  auto plaintext2 = cc->MakeCKKSPackedPlaintext(vectorOfInts2);

  auto ciphertext1 = cc->Encrypt(keyPair.publicKey, plaintext1);
  auto ciphertext2 = cc->Encrypt(keyPair.publicKey, plaintext2);

  while (state.KeepRunning()) {
    cc->EvalAddInPlace(ciphertext1, ciphertext2);
  }
}

BENCHMARK(CKKS_AddInPlace)->Unit(benchmark::kMicrosecond);

void CKKS_MultNoRelin(benchmark::State &state) {
  CryptoContext<DCRTPoly> cc = GenerateCKKSContext();

  LPKeyPair<DCRTPoly> keyPair = cc->KeyGen();

  usint slots = cc->GetEncodingParams()->GetBatchSize();
  std::vector<std::complex<double>> vectorOfInts1(slots);
  for (usint i = 0; i < slots; i++) {
    vectorOfInts1[i] = 1.001 * i;
  }
  std::vector<std::complex<double>> vectorOfInts2(vectorOfInts1);

  auto plaintext1 = cc->MakeCKKSPackedPlaintext(vectorOfInts1);
  auto plaintext2 = cc->MakeCKKSPackedPlaintext(vectorOfInts2);

  auto ciphertext1 = cc->Encrypt(keyPair.publicKey, plaintext1);
  auto ciphertext2 = cc->Encrypt(keyPair.publicKey, plaintext2);

  while (state.KeepRunning()) {
    auto ciphertextMul = cc->EvalMultNoRelin(ciphertext1, ciphertext2);
  }
}

BENCHMARK(CKKS_MultNoRelin)->Unit(benchmark::kMicrosecond);

void CKKS_MultRelin(benchmark::State &state) {
  CryptoContext<DCRTPoly> cc = GenerateCKKSContext();

  LPKeyPair<DCRTPoly> keyPair = cc->KeyGen();
  cc->EvalMultKeyGen(keyPair.secretKey);

  usint slots = cc->GetEncodingParams()->GetBatchSize();
  std::vector<std::complex<double>> vectorOfInts1(slots);
  for (usint i = 0; i < slots; i++) {
    vectorOfInts1[i] = 1.001 * i;
  }
  std::vector<std::complex<double>> vectorOfInts2(vectorOfInts1);

  auto plaintext1 = cc->MakeCKKSPackedPlaintext(vectorOfInts1);
  auto plaintext2 = cc->MakeCKKSPackedPlaintext(vectorOfInts2);

  auto ciphertext1 = cc->Encrypt(keyPair.publicKey, plaintext1);
  auto ciphertext2 = cc->Encrypt(keyPair.publicKey, plaintext2);

  while (state.KeepRunning()) {
    auto ciphertextMul = cc->EvalMult(ciphertext1, ciphertext2);
  }
}

BENCHMARK(CKKS_MultRelin)->Unit(benchmark::kMicrosecond);

void CKKS_Relin(benchmark::State &state) {
  CryptoContext<DCRTPoly> cc = GenerateCKKSContext();

  LPKeyPair<DCRTPoly> keyPair = cc->KeyGen();
  cc->EvalMultKeyGen(keyPair.secretKey);

  usint slots = cc->GetEncodingParams()->GetBatchSize();
  std::vector<std::complex<double>> vectorOfInts1(slots);
  for (usint i = 0; i < slots; i++) {
    vectorOfInts1[i] = 1.001 * i;
  }
  std::vector<std::complex<double>> vectorOfInts2(vectorOfInts1);

  auto plaintext1 = cc->MakeCKKSPackedPlaintext(vectorOfInts1);
  auto plaintext2 = cc->MakeCKKSPackedPlaintext(vectorOfInts2);

  auto ciphertext1 = cc->Encrypt(keyPair.publicKey, plaintext1);
  auto ciphertext2 = cc->Encrypt(keyPair.publicKey, plaintext2);

  auto ciphertextMul = cc->EvalMultNoRelin(ciphertext1, ciphertext2);

  while (state.KeepRunning()) {
    auto ciphertext3 = cc->Relinearize(ciphertextMul);
  }
}

BENCHMARK(CKKS_Relin)->Unit(benchmark::kMicrosecond);

void CKKS_RelinInPlace(benchmark::State &state) {
  CryptoContext<DCRTPoly> cc = GenerateCKKSContext();

  LPKeyPair<DCRTPoly> keyPair = cc->KeyGen();
  cc->EvalMultKeyGen(keyPair.secretKey);

  usint slots = cc->GetEncodingParams()->GetBatchSize();
  std::vector<std::complex<double>> vectorOfInts1(slots);
  for (usint i = 0; i < slots; i++) {
    vectorOfInts1[i] = 1.001 * i;
  }
  std::vector<std::complex<double>> vectorOfInts2(vectorOfInts1);

  auto plaintext1 = cc->MakeCKKSPackedPlaintext(vectorOfInts1);
  auto plaintext2 = cc->MakeCKKSPackedPlaintext(vectorOfInts2);

  auto ciphertext1 = cc->Encrypt(keyPair.publicKey, plaintext1);
  auto ciphertext2 = cc->Encrypt(keyPair.publicKey, plaintext2);

  auto ciphertextMul = cc->EvalMultNoRelin(ciphertext1, ciphertext2);
  auto ciphertextMulClone = ciphertextMul->Clone();

  while (state.KeepRunning()) {
    cc->RelinearizeInPlace(ciphertextMul);
    state.PauseTiming();
    ciphertextMul = ciphertextMulClone->Clone();
    state.ResumeTiming();
  }
}

BENCHMARK(CKKS_RelinInPlace)->Unit(benchmark::kMicrosecond);

void CKKS_Rescale(benchmark::State &state) {
  CryptoContext<DCRTPoly> cc = GenerateCKKSContext();

  LPKeyPair<DCRTPoly> keyPair = cc->KeyGen();
  cc->EvalMultKeyGen(keyPair.secretKey);

  usint slots = cc->GetEncodingParams()->GetBatchSize();
  std::vector<std::complex<double>> vectorOfInts1(slots);
  for (usint i = 0; i < slots; i++) {
    vectorOfInts1[i] = 1.001 * i;
  }
  std::vector<std::complex<double>> vectorOfInts2(vectorOfInts1);

  auto plaintext1 = cc->MakeCKKSPackedPlaintext(vectorOfInts1);
  auto plaintext2 = cc->MakeCKKSPackedPlaintext(vectorOfInts2);

  auto ciphertext1 = cc->Encrypt(keyPair.publicKey, plaintext1);
  auto ciphertext2 = cc->Encrypt(keyPair.publicKey, plaintext2);

  auto ciphertextMul = cc->EvalMult(ciphertext1, ciphertext2);

  while (state.KeepRunning()) {
    auto ciphertext3 = cc->ModReduce(ciphertextMul);
  }
}

BENCHMARK(CKKS_Rescale)->Unit(benchmark::kMicrosecond);

void CKKS_RescaleInPlace(benchmark::State &state) {
  CryptoContext<DCRTPoly> cc = GenerateCKKSContext();

  LPKeyPair<DCRTPoly> keyPair = cc->KeyGen();
  cc->EvalMultKeyGen(keyPair.secretKey);

  usint slots = cc->GetEncodingParams()->GetBatchSize();
  std::vector<std::complex<double>> vectorOfInts(slots);
  for (usint i = 0; i < slots; i++) {
    vectorOfInts[i] = 1.001 * i;
  }

  auto plaintext = cc->MakeCKKSPackedPlaintext(vectorOfInts);
  auto ciphertext = cc->Encrypt(keyPair.publicKey, plaintext);
  auto ciphertextMul = cc->EvalMult(ciphertext, ciphertext);
  auto ciphertextMulClone = ciphertextMul->Clone();

  while (state.KeepRunning()) {
    cc->ModReduceInPlace(ciphertextMul);
    state.PauseTiming();
    ciphertextMul = ciphertextMulClone->Clone();
    state.ResumeTiming();
  }
}

BENCHMARK(CKKS_RescaleInPlace)->Unit(benchmark::kMicrosecond);

void CKKS_EvalAtIndex(benchmark::State &state) {
  CryptoContext<DCRTPoly> cc = GenerateCKKSContext();

  LPKeyPair<DCRTPoly> keyPair = cc->KeyGen();
  cc->EvalMultKeyGen(keyPair.secretKey);

  std::vector<int32_t> indexList(1);
  for (usint i = 0; i < 1; i++) {
    indexList[i] = 1;
  }

  cc->EvalAtIndexKeyGen(keyPair.secretKey, indexList);

  usint slots = cc->GetEncodingParams()->GetBatchSize();
  std::vector<std::complex<double>> vectorOfInts1(slots);
  for (usint i = 0; i < slots; i++) {
    vectorOfInts1[i] = 1.001 * i;
  }
  std::vector<std::complex<double>> vectorOfInts2(vectorOfInts1);

  auto plaintext1 = cc->MakeCKKSPackedPlaintext(vectorOfInts1);
  auto plaintext2 = cc->MakeCKKSPackedPlaintext(vectorOfInts2);

  auto ciphertext1 = cc->Encrypt(keyPair.publicKey, plaintext1);
  auto ciphertext2 = cc->Encrypt(keyPair.publicKey, plaintext2);

  auto ciphertextMul = cc->EvalMult(ciphertext1, ciphertext2);

  while (state.KeepRunning()) {
    auto ciphertext3 = cc->EvalAtIndex(ciphertextMul, 1);
  }
}

BENCHMARK(CKKS_EvalAtIndex)->Unit(benchmark::kMicrosecond);

/*
 * BGVrns benchmarks
 * */

void BGVrns_KeyGen(benchmark::State &state) {
  CryptoContext<DCRTPoly> cryptoContext = GenerateBGVrnsContext();

  LPKeyPair<DCRTPoly> keyPair;

  while (state.KeepRunning()) {
    keyPair = cryptoContext->KeyGen();
  }
}

BENCHMARK(BGVrns_KeyGen)->Unit(benchmark::kMicrosecond);

void BGVrns_MultKeyGen(benchmark::State &state) {
  CryptoContext<DCRTPoly> cc = GenerateBGVrnsContext();

  LPKeyPair<DCRTPoly> keyPair;
  keyPair = cc->KeyGen();

  while (state.KeepRunning()) {
    cc->EvalMultKeyGen(keyPair.secretKey);
  }
}

BENCHMARK(BGVrns_MultKeyGen)->Unit(benchmark::kMicrosecond);

void BGVrns_EvalAtIndexKeyGen(benchmark::State &state) {
  CryptoContext<DCRTPoly> cc = GenerateBGVrnsContext();

  LPKeyPair<DCRTPoly> keyPair;
  keyPair = cc->KeyGen();

  std::vector<int32_t> indexList(1);
  for (usint i = 0; i < 1; i++) {
    indexList[i] = 1;
  }

  while (state.KeepRunning()) {
    cc->EvalAtIndexKeyGen(keyPair.secretKey, indexList);
  }
}

BENCHMARK(BGVrns_EvalAtIndexKeyGen)->Unit(benchmark::kMicrosecond);

void BGVrns_Encryption(benchmark::State &state) {
  CryptoContext<DCRTPoly> cryptoContext = GenerateBGVrnsContext();

  LPKeyPair<DCRTPoly> keyPair = cryptoContext->KeyGen();

  std::vector<int64_t> vectorOfInts = {1, 0, 1, 0, 1, 1, 1, 0, 1, 1, 1, 0};
  Plaintext plaintext = cryptoContext->MakePackedPlaintext(vectorOfInts);

  while (state.KeepRunning()) {
    auto ciphertext = cryptoContext->Encrypt(keyPair.publicKey, plaintext);
  }
}

BENCHMARK(BGVrns_Encryption)->Unit(benchmark::kMicrosecond);

void BGVrns_Decryption(benchmark::State &state) {
  CryptoContext<DCRTPoly> cc = GenerateBGVrnsContext();

  LPKeyPair<DCRTPoly> keyPair = cc->KeyGen();

  std::vector<int64_t> vectorOfInts = {1, 0, 1, 0, 1, 1, 1, 0, 1, 1, 1, 0};
  Plaintext plaintext = cc->MakePackedPlaintext(vectorOfInts);

  auto ciphertext = cc->Encrypt(keyPair.publicKey, plaintext);
  ciphertext = cc->ModReduce(ciphertext);  // TODO LevelReduce

  Plaintext plaintextDec;

  while (state.KeepRunning()) {
    cc->Decrypt(keyPair.secretKey, ciphertext, &plaintextDec);
  }
}

BENCHMARK(BGVrns_Decryption)->Unit(benchmark::kMicrosecond);

void BGVrns_Add(benchmark::State &state) {
  CryptoContext<DCRTPoly> cc = GenerateBGVrnsContext();

  LPKeyPair<DCRTPoly> keyPair = cc->KeyGen();

  std::vector<int64_t> vectorOfInts1 = {1, 0, 1, 0, 1, 1, 1, 0, 1, 1, 1, 0};
  std::vector<int64_t> vectorOfInts2 = {0, 1, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1};

  auto plaintext1 = cc->MakePackedPlaintext(vectorOfInts1);
  auto plaintext2 = cc->MakePackedPlaintext(vectorOfInts2);

  auto ciphertext1 = cc->Encrypt(keyPair.publicKey, plaintext1);
  auto ciphertext2 = cc->Encrypt(keyPair.publicKey, plaintext2);

  while (state.KeepRunning()) {
    auto ciphertextAdd = cc->EvalAdd(ciphertext1, ciphertext2);
  }
}

BENCHMARK(BGVrns_Add)->Unit(benchmark::kMicrosecond);

void BGVrns_AddInPlace(benchmark::State &state) {
  CryptoContext<DCRTPoly> cc = GenerateBGVrnsContext();

  LPKeyPair<DCRTPoly> keyPair = cc->KeyGen();

  std::vector<int64_t> vectorOfInts1 = {1, 0, 1, 0, 1, 1, 1, 0, 1, 1, 1, 0};
  std::vector<int64_t> vectorOfInts2 = {0, 1, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1};

  auto plaintext1 = cc->MakePackedPlaintext(vectorOfInts1);
  auto plaintext2 = cc->MakePackedPlaintext(vectorOfInts2);

  auto ciphertext1 = cc->Encrypt(keyPair.publicKey, plaintext1);
  auto ciphertext2 = cc->Encrypt(keyPair.publicKey, plaintext2);

  while (state.KeepRunning()) {
    cc->EvalAddInPlace(ciphertext1, ciphertext2);
  }
}

BENCHMARK(BGVrns_AddInPlace)->Unit(benchmark::kMicrosecond);

void BGVrns_MultNoRelin(benchmark::State &state) {
  CryptoContext<DCRTPoly> cc = GenerateBGVrnsContext();

  LPKeyPair<DCRTPoly> keyPair = cc->KeyGen();

  std::vector<int64_t> vectorOfInts1 = {1, 0, 1, 0, 1, 1, 1, 0, 1, 1, 1, 0};
  std::vector<int64_t> vectorOfInts2 = {0, 1, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1};

  auto plaintext1 = cc->MakePackedPlaintext(vectorOfInts1);
  auto plaintext2 = cc->MakePackedPlaintext(vectorOfInts2);

  auto ciphertext1 = cc->Encrypt(keyPair.publicKey, plaintext1);
  auto ciphertext2 = cc->Encrypt(keyPair.publicKey, plaintext2);

  while (state.KeepRunning()) {
    auto ciphertextMul = cc->EvalMultNoRelin(ciphertext1, ciphertext2);
  }
}

BENCHMARK(BGVrns_MultNoRelin)->Unit(benchmark::kMicrosecond);

void BGVrns_MultRelin(benchmark::State &state) {
  CryptoContext<DCRTPoly> cc = GenerateBGVrnsContext();

  LPKeyPair<DCRTPoly> keyPair = cc->KeyGen();
  cc->EvalMultKeyGen(keyPair.secretKey);

  std::vector<int64_t> vectorOfInts1 = {1, 0, 1, 0, 1, 1, 1, 0, 1, 1, 1, 0};
  std::vector<int64_t> vectorOfInts2 = {0, 1, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1};

  auto plaintext1 = cc->MakePackedPlaintext(vectorOfInts1);
  auto plaintext2 = cc->MakePackedPlaintext(vectorOfInts2);

  auto ciphertext1 = cc->Encrypt(keyPair.publicKey, plaintext1);
  auto ciphertext2 = cc->Encrypt(keyPair.publicKey, plaintext2);

  while (state.KeepRunning()) {
    auto ciphertextMul = cc->EvalMult(ciphertext1, ciphertext2);
  }
}

BENCHMARK(BGVrns_MultRelin)->Unit(benchmark::kMicrosecond);

void BGVrns_Relin(benchmark::State &state) {
  CryptoContext<DCRTPoly> cc = GenerateBGVrnsContext();

  LPKeyPair<DCRTPoly> keyPair = cc->KeyGen();
  cc->EvalMultKeyGen(keyPair.secretKey);

  std::vector<int64_t> vectorOfInts1 = {1, 0, 1, 0, 1, 1, 1, 0, 1, 1, 1, 0};
  std::vector<int64_t> vectorOfInts2 = {0, 1, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1};

  auto plaintext1 = cc->MakePackedPlaintext(vectorOfInts1);
  auto plaintext2 = cc->MakePackedPlaintext(vectorOfInts2);

  auto ciphertext1 = cc->Encrypt(keyPair.publicKey, plaintext1);
  auto ciphertext2 = cc->Encrypt(keyPair.publicKey, plaintext2);

  auto ciphertextMul = cc->EvalMultNoRelin(ciphertext1, ciphertext2);

  while (state.KeepRunning()) {
    auto ciphertext3 = cc->Relinearize(ciphertextMul);
  }
}

BENCHMARK(BGVrns_Relin)->Unit(benchmark::kMicrosecond);

void BGVrns_RelinInPlace(benchmark::State &state) {
  CryptoContext<DCRTPoly> cc = GenerateBGVrnsContext();

  LPKeyPair<DCRTPoly> keyPair = cc->KeyGen();
  cc->EvalMultKeyGen(keyPair.secretKey);

  std::vector<int64_t> vectorOfInts1 = {1, 0, 1, 0, 1, 1, 1, 0, 1, 1, 1, 0};
  std::vector<int64_t> vectorOfInts2 = {0, 1, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1};

  auto plaintext1 = cc->MakePackedPlaintext(vectorOfInts1);
  auto plaintext2 = cc->MakePackedPlaintext(vectorOfInts2);

  auto ciphertext1 = cc->Encrypt(keyPair.publicKey, plaintext1);
  auto ciphertext2 = cc->Encrypt(keyPair.publicKey, plaintext2);

  auto ciphertextMul = cc->EvalMultNoRelin(ciphertext1, ciphertext2);
  auto ciphertextMulClone = ciphertextMul->Clone();

  while (state.KeepRunning()) {
    cc->RelinearizeInPlace(ciphertextMul);
    state.PauseTiming();
    ciphertextMul = ciphertextMulClone->Clone();
    state.ResumeTiming();
  }
}

BENCHMARK(BGVrns_RelinInPlace)->Unit(benchmark::kMicrosecond);

void BGVrns_ModSwitch(benchmark::State &state) {
  CryptoContext<DCRTPoly> cc = GenerateBGVrnsContext();

  LPKeyPair<DCRTPoly> keyPair = cc->KeyGen();
  cc->EvalMultKeyGen(keyPair.secretKey);

  std::vector<int64_t> vectorOfInts1 = {1, 0, 1, 0, 1, 1, 1, 0, 1, 1, 1, 0};
  std::vector<int64_t> vectorOfInts2 = {0, 1, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1};

  auto plaintext1 = cc->MakePackedPlaintext(vectorOfInts1);
  auto plaintext2 = cc->MakePackedPlaintext(vectorOfInts2);

  auto ciphertext1 = cc->Encrypt(keyPair.publicKey, plaintext1);
  auto ciphertext2 = cc->Encrypt(keyPair.publicKey, plaintext2);

  auto ciphertextMul = cc->EvalMult(ciphertext1, ciphertext2);

  while (state.KeepRunning()) {
    auto ciphertext3 = cc->ModReduce(ciphertextMul);
  }
}

BENCHMARK(BGVrns_ModSwitch)->Unit(benchmark::kMicrosecond);

void BGVrns_ModSwitchInPlace(benchmark::State &state) {
  CryptoContext<DCRTPoly> cc = GenerateBGVrnsContext();

  LPKeyPair<DCRTPoly> keyPair = cc->KeyGen();
  cc->EvalMultKeyGen(keyPair.secretKey);

  std::vector<int64_t> vectorOfInts = {1, 0, 1, 0, 1, 1, 1, 0, 1, 1, 1, 0};

  auto plaintext = cc->MakePackedPlaintext(vectorOfInts);
  auto ciphertext = cc->Encrypt(keyPair.publicKey, plaintext);
  auto ciphertextMul = cc->EvalMult(ciphertext, ciphertext);
  auto ciphertextMulClone = ciphertextMul->Clone();

  while (state.KeepRunning()) {
    cc->ModReduceInPlace(ciphertextMul);
    state.PauseTiming();
    ciphertextMul = ciphertextMulClone->Clone();
    state.ResumeTiming();
  }
}

BENCHMARK(BGVrns_ModSwitchInPlace)->Unit(benchmark::kMicrosecond);

void BGVrns_EvalAtIndex(benchmark::State &state) {
  CryptoContext<DCRTPoly> cc = GenerateBGVrnsContext();

  LPKeyPair<DCRTPoly> keyPair = cc->KeyGen();
  cc->EvalMultKeyGen(keyPair.secretKey);

  std::vector<int32_t> indexList(1);
  for (usint i = 0; i < 1; i++) {
    indexList[i] = 1;
  }

  cc->EvalAtIndexKeyGen(keyPair.secretKey, indexList);

  std::vector<int64_t> vectorOfInts1 = {1, 0, 1, 0, 1, 1, 1, 0, 1, 1, 1, 0};
  std::vector<int64_t> vectorOfInts2 = {0, 1, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1};

  auto plaintext1 = cc->MakeCoefPackedPlaintext(vectorOfInts1);
  auto plaintext2 = cc->MakeCoefPackedPlaintext(vectorOfInts2);

  auto ciphertext1 = cc->Encrypt(keyPair.publicKey, plaintext1);
  auto ciphertext2 = cc->Encrypt(keyPair.publicKey, plaintext2);

  auto ciphertextMul = cc->EvalMult(ciphertext1, ciphertext2);

  while (state.KeepRunning()) {
    auto ciphertext3 = cc->EvalAtIndex(ciphertextMul, 1);
  }
}

BENCHMARK(BGVrns_EvalAtIndex)->Unit(benchmark::kMicrosecond);

BENCHMARK_MAIN();
