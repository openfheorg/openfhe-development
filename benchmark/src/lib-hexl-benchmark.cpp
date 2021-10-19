/*
 * @file lib-hexl-benchmark : library benchmark routines for comparison by build
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
 * pieces of the library using varying parameters. To view or edit the
 * parameter sets, see lib-hexl-util.h
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

#include "lib-hexl-util.h"

using namespace std;
using namespace lbcrypto;

void NTTTransform(benchmark::State &state) {
  usint phim = state.range(0);
  usint m = phim * 2;

  NativeInteger modulusQ("137438822401");
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

HEXL_NTT_BENCHMARK(NTTTransform);

void INTTTransform(benchmark::State &state) {
  usint phim = state.range(0);
  usint m = phim * 2;

  NativeInteger modulusQ("137438822401");
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

HEXL_NTT_BENCHMARK(INTTTransform);

void NTTTransformInPlace(benchmark::State &state) {
  usint phim = state.range(0);
  usint m = phim * 2;

  NativeInteger modulusQ("137438822401");
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

HEXL_NTT_BENCHMARK(NTTTransformInPlace);

void INTTTransformInPlace(benchmark::State &state) {
  usint phim = state.range(0);
  usint m = phim * 2;

  NativeInteger modulusQ("137438822401");
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

HEXL_NTT_BENCHMARK(INTTTransformInPlace);

/*
 * BFVrns benchmarks
 */

void BFVrns_KeyGen(benchmark::State &state) {
  CryptoContext<DCRTPoly> cc =
      GenerateBFVrnsContext(state.range(0), state.range(1));

  LPKeyPair<DCRTPoly> keyPair;

  while (state.KeepRunning()) {
    keyPair = cc->KeyGen();
  }
}

HEXL_BENCHMARK(BFVrns_KeyGen);

void BFVrns_MultKeyGen(benchmark::State &state) {
  CryptoContext<DCRTPoly> cc =
      GenerateBFVrnsContext(state.range(0), state.range(1));

  LPKeyPair<DCRTPoly> keyPair;
  keyPair = cc->KeyGen();

  while (state.KeepRunning()) {
    cc->EvalMultKeyGen(keyPair.secretKey);
  }
}

HEXL_BENCHMARK(BFVrns_MultKeyGen);

void BFVrns_EvalAtIndexKeyGen(benchmark::State &state) {
  CryptoContext<DCRTPoly> cc =
      GenerateBFVrnsContext(state.range(0), state.range(1));

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

HEXL_BENCHMARK(BFVrns_EvalAtIndexKeyGen);

void BFVrns_Encryption(benchmark::State &state) {
  CryptoContext<DCRTPoly> cc =
      GenerateBFVrnsContext(state.range(0), state.range(1));

  LPKeyPair<DCRTPoly> keyPair = cc->KeyGen();

  std::vector<int64_t> vectorOfInts1 = {1, 0, 1, 0, 1, 1, 1, 0, 1, 1, 1, 0};
  Plaintext plaintext1 = cc->MakePackedPlaintext(vectorOfInts1);

  while (state.KeepRunning()) {
    auto ciphertext1 = cc->Encrypt(keyPair.publicKey, plaintext1);
  }
}

HEXL_BENCHMARK(BFVrns_Encryption);

void BFVrns_Decryption(benchmark::State &state) {
  CryptoContext<DCRTPoly> cc =
      GenerateBFVrnsContext(state.range(0), state.range(1));

  LPKeyPair<DCRTPoly> keyPair = cc->KeyGen();

  std::vector<int64_t> vectorOfInts1 = {1, 0, 1, 0, 1, 1, 1, 0, 1, 1, 1, 0};
  Plaintext plaintext1 = cc->MakePackedPlaintext(vectorOfInts1);

  auto ciphertext1 = cc->Encrypt(keyPair.publicKey, plaintext1);
  Plaintext plaintextDec1;

  while (state.KeepRunning()) {
    cc->Decrypt(keyPair.secretKey, ciphertext1, &plaintextDec1);
  }
}

HEXL_BENCHMARK(BFVrns_Decryption);

void BFVrns_Add(benchmark::State &state) {
  CryptoContext<DCRTPoly> cc =
      GenerateBFVrnsContext(state.range(0), state.range(1));

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

HEXL_BENCHMARK(BFVrns_Add);

void BFVrns_AddInPlace(benchmark::State &state) {
  CryptoContext<DCRTPoly> cc =
      GenerateBFVrnsContext(state.range(0), state.range(1));

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

HEXL_BENCHMARK(BFVrns_AddInPlace);

void BFVrns_AddPlain(benchmark::State &state) {
  CryptoContext<DCRTPoly> cc =
      GenerateBFVrnsContext(state.range(0), state.range(1));

  LPKeyPair<DCRTPoly> keyPair = cc->KeyGen();

  std::vector<int64_t> vectorOfInts1 = {1, 0, 1, 0, 1, 1, 1, 0, 1, 1, 1, 0};
  Plaintext plaintext1 = cc->MakeCoefPackedPlaintext(vectorOfInts1);

  std::vector<int64_t> vectorOfInts2 = {1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 0};
  Plaintext plaintext2 = cc->MakeCoefPackedPlaintext(vectorOfInts2);

  auto ciphertext1 = cc->Encrypt(keyPair.publicKey, plaintext1);

  while (state.KeepRunning()) {
    auto ciphertextAdd = cc->EvalAdd(ciphertext1, plaintext2);
  }
}

HEXL_BENCHMARK(BFVrns_AddPlain);

void BFVrns_Negate(benchmark::State &state) {
  CryptoContext<DCRTPoly> cc =
      GenerateBFVrnsContext(state.range(0), state.range(1));

  LPKeyPair<DCRTPoly> keyPair = cc->KeyGen();

  std::vector<int64_t> vectorOfInts1 = {1, 0, 1, 0, 1, 1, 1, 0, 1, 1, 1, 0};
  Plaintext plaintext1 = cc->MakeCoefPackedPlaintext(vectorOfInts1);

  auto ciphertext1 = cc->Encrypt(keyPair.publicKey, plaintext1);

  while (state.KeepRunning()) {
    auto ciphertextNeg = cc->EvalNegate(ciphertext1);
  }
}

HEXL_BENCHMARK(BFVrns_Negate);

void BFVrns_Sub(benchmark::State &state) {
  CryptoContext<DCRTPoly> cc =
      GenerateBFVrnsContext(state.range(0), state.range(1));

  LPKeyPair<DCRTPoly> keyPair = cc->KeyGen();

  std::vector<int64_t> vectorOfInts1 = {1, 0, 1, 0, 1, 1, 1, 0, 1, 1, 1, 0};
  std::vector<int64_t> vectorOfInts2 = {0, 1, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1};

  auto plaintext1 = cc->MakeCoefPackedPlaintext(vectorOfInts1);
  auto plaintext2 = cc->MakeCoefPackedPlaintext(vectorOfInts2);

  auto ciphertext1 = cc->Encrypt(keyPair.publicKey, plaintext1);
  auto ciphertext2 = cc->Encrypt(keyPair.publicKey, plaintext2);

  while (state.KeepRunning()) {
    auto ciphertextSub = cc->EvalSub(ciphertext1, ciphertext2);
  }
}

HEXL_BENCHMARK(BFVrns_Sub);

void BFVrns_SubPlain(benchmark::State &state) {
  CryptoContext<DCRTPoly> cc =
      GenerateBFVrnsContext(state.range(0), state.range(1));

  LPKeyPair<DCRTPoly> keyPair = cc->KeyGen();

  std::vector<int64_t> vectorOfInts1 = {1, 0, 1, 0, 1, 1, 1, 0, 1, 1, 1, 0};
  Plaintext plaintext1 = cc->MakeCoefPackedPlaintext(vectorOfInts1);

  std::vector<int64_t> vectorOfInts2 = {1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 0};
  Plaintext plaintext2 = cc->MakeCoefPackedPlaintext(vectorOfInts2);

  auto ciphertext1 = cc->Encrypt(keyPair.publicKey, plaintext1);

  while (state.KeepRunning()) {
    auto ciphertextSub = cc->EvalSub(ciphertext1, plaintext2);
  }
}

HEXL_BENCHMARK(BFVrns_SubPlain);

void BFVrns_MultNoRelin(benchmark::State &state) {
  CryptoContext<DCRTPoly> cc =
      GenerateBFVrnsContext(state.range(0), state.range(1));

  LPKeyPair<DCRTPoly> keyPair = cc->KeyGen();

  std::vector<int64_t> vectorOfInts1 = {1, 0, 1, 0, 1, 1, 1, 0, 1, 1, 1, 0};
  Plaintext plaintext1 = cc->MakePackedPlaintext(vectorOfInts1);

  std::vector<int64_t> vectorOfInts2 = {1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 0};
  Plaintext plaintext2 = cc->MakePackedPlaintext(vectorOfInts2);

  auto ciphertext1 = cc->Encrypt(keyPair.publicKey, plaintext1);
  auto ciphertext2 = cc->Encrypt(keyPair.publicKey, plaintext2);

  while (state.KeepRunning()) {
    auto ciphertextMul = cc->EvalMultNoRelin(ciphertext1, ciphertext2);
  }
}

HEXL_BENCHMARK(BFVrns_MultNoRelin);

void BFVrns_MultRelin(benchmark::State &state) {
  CryptoContext<DCRTPoly> cc =
      GenerateBFVrnsContext(state.range(0), state.range(1));

  LPKeyPair<DCRTPoly> keyPair = cc->KeyGen();
  cc->EvalMultKeyGen(keyPair.secretKey);

  std::vector<int64_t> vectorOfInts1 = {1, 0, 1, 0, 1, 1, 1, 0, 1, 1, 1, 0};
  Plaintext plaintext1 = cc->MakePackedPlaintext(vectorOfInts1);

  std::vector<int64_t> vectorOfInts2 = {1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 0};
  Plaintext plaintext2 = cc->MakePackedPlaintext(vectorOfInts2);

  auto ciphertext1 = cc->Encrypt(keyPair.publicKey, plaintext1);
  auto ciphertext2 = cc->Encrypt(keyPair.publicKey, plaintext2);

  while (state.KeepRunning()) {
    auto ciphertextMul = cc->EvalMult(ciphertext1, ciphertext2);
  }
}

HEXL_BENCHMARK(BFVrns_MultRelin);

void BFVrns_MultPlain(benchmark::State &state) {
  CryptoContext<DCRTPoly> cc =
      GenerateBFVrnsContext(state.range(0), state.range(1));

  LPKeyPair<DCRTPoly> keyPair = cc->KeyGen();
  cc->EvalMultKeyGen(keyPair.secretKey);

  std::vector<int64_t> vectorOfInts1 = {1, 0, 1, 0, 1, 1, 1, 0, 1, 1, 1, 0};
  Plaintext plaintext1 = cc->MakeCoefPackedPlaintext(vectorOfInts1);

  std::vector<int64_t> vectorOfInts2 = {1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 0};
  Plaintext plaintext2 = cc->MakeCoefPackedPlaintext(vectorOfInts2);

  auto ciphertext1 = cc->Encrypt(keyPair.publicKey, plaintext1);

  while (state.KeepRunning()) {
    auto ciphertextMul = cc->EvalMult(ciphertext1, plaintext2);
  }
}

HEXL_BENCHMARK(BFVrns_MultPlain);

void BFVrns_EvalAtIndex(benchmark::State &state) {
  CryptoContext<DCRTPoly> cc =
      GenerateBFVrnsContext(state.range(0), state.range(1));

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

HEXL_BENCHMARK(BFVrns_EvalAtIndex);

/*
 * CKKS benchmarks
 * */

void CKKS_KeyGen(benchmark::State &state) {
  CryptoContext<DCRTPoly> cc =
      GenerateCKKSContext(state.range(0), state.range(1));

  LPKeyPair<DCRTPoly> keyPair;

  while (state.KeepRunning()) {
    keyPair = cc->KeyGen();
  }
}

HEXL_BENCHMARK(CKKS_KeyGen);

void CKKS_MultKeyGen(benchmark::State &state) {
  CryptoContext<DCRTPoly> cc =
      GenerateCKKSContext(state.range(0), state.range(1));

  LPKeyPair<DCRTPoly> keyPair;
  keyPair = cc->KeyGen();

  while (state.KeepRunning()) {
    cc->EvalMultKeyGen(keyPair.secretKey);
  }
}

HEXL_BENCHMARK(CKKS_MultKeyGen);

void CKKS_EvalAtIndexKeyGen(benchmark::State &state) {
  CryptoContext<DCRTPoly> cc =
      GenerateCKKSContext(state.range(0), state.range(1));

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

HEXL_BENCHMARK(CKKS_EvalAtIndexKeyGen);

void CKKS_Encryption(benchmark::State &state) {
  CryptoContext<DCRTPoly> cc =
      GenerateCKKSContext(state.range(0), state.range(1));

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

HEXL_BENCHMARK(CKKS_Encryption);

void CKKS_Decryption(benchmark::State &state) {
  CryptoContext<DCRTPoly> cc =
      GenerateCKKSContext(state.range(0), state.range(1));

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

HEXL_BENCHMARK(CKKS_Decryption);

void CKKS_Add(benchmark::State &state) {
  CryptoContext<DCRTPoly> cc =
      GenerateCKKSContext(state.range(0), state.range(1));

  LPKeyPair<DCRTPoly> keyPair = cc->KeyGen();

  usint slots = cc->GetEncodingParams()->GetBatchSize();
  std::vector<std::complex<double>> vectorOfInts1(slots);
  for (usint i = 0; i < slots; i++) {
    vectorOfInts1[i] = 1.001 * i;
  }
  std::vector<std::complex<double>> vectorOfInts2(slots);
  for (usint i = 0; i < slots; i++) {
    vectorOfInts2[i] = 1.001 * i;
  }

  auto plaintext1 = cc->MakeCKKSPackedPlaintext(vectorOfInts1);
  auto plaintext2 = cc->MakeCKKSPackedPlaintext(vectorOfInts2);

  auto ciphertext1 = cc->Encrypt(keyPair.publicKey, plaintext1);
  auto ciphertext2 = cc->Encrypt(keyPair.publicKey, plaintext2);

  while (state.KeepRunning()) {
    auto ciphertextAdd = cc->EvalAdd(ciphertext1, ciphertext2);
  }
}

HEXL_BENCHMARK(CKKS_Add);

void CKKS_AddInPlace(benchmark::State &state) {
  CryptoContext<DCRTPoly> cc =
      GenerateCKKSContext(state.range(0), state.range(1));

  LPKeyPair<DCRTPoly> keyPair = cc->KeyGen();

  usint slots = cc->GetEncodingParams()->GetBatchSize();
  std::vector<std::complex<double>> vectorOfInts1(slots);
  for (usint i = 0; i < slots; i++) {
    vectorOfInts1[i] = 1.001 * i;
  }
  std::vector<std::complex<double>> vectorOfInts2(slots);
  for (usint i = 0; i < slots; i++) {
    vectorOfInts2[i] = 1.001 * i;
  }

  auto plaintext1 = cc->MakeCKKSPackedPlaintext(vectorOfInts1);
  auto plaintext2 = cc->MakeCKKSPackedPlaintext(vectorOfInts2);

  auto ciphertext1 = cc->Encrypt(keyPair.publicKey, plaintext1);
  auto ciphertext2 = cc->Encrypt(keyPair.publicKey, plaintext2);

  while (state.KeepRunning()) {
    cc->EvalAddInPlace(ciphertext1, ciphertext2);
  }
}

HEXL_BENCHMARK(CKKS_AddInPlace);

void CKKS_AddPlain(benchmark::State &state) {
  CryptoContext<DCRTPoly> cc =
      GenerateCKKSContext(state.range(0), state.range(1));

  LPKeyPair<DCRTPoly> keyPair = cc->KeyGen();

  usint slots = cc->GetEncodingParams()->GetBatchSize();
  std::vector<std::complex<double>> vectorOfInts1(slots);
  for (usint i = 0; i < slots; i++) {
    vectorOfInts1[i] = 1.001 * i;
  }
  std::vector<std::complex<double>> vectorOfInts2(slots);
  for (usint i = 0; i < slots; i++) {
    vectorOfInts2[i] = 1.001 * i;
  }

  auto plaintext1 = cc->MakeCKKSPackedPlaintext(vectorOfInts1);
  auto plaintext2 = cc->MakeCKKSPackedPlaintext(vectorOfInts2);

  auto ciphertext1 = cc->Encrypt(keyPair.publicKey, plaintext1);

  while (state.KeepRunning()) {
    auto ciphertextAdd = cc->EvalAdd(ciphertext1, plaintext2);
  }
}

HEXL_BENCHMARK(CKKS_AddPlain);

void CKKS_Negate(benchmark::State &state) {
  CryptoContext<DCRTPoly> cc =
      GenerateCKKSContext(state.range(0), state.range(1));

  LPKeyPair<DCRTPoly> keyPair = cc->KeyGen();

  usint slots = cc->GetEncodingParams()->GetBatchSize();
  std::vector<std::complex<double>> vectorOfInts1(slots);
  for (usint i = 0; i < slots; i++) {
    vectorOfInts1[i] = 1.001 * i;
  }

  auto plaintext1 = cc->MakeCKKSPackedPlaintext(vectorOfInts1);
  auto ciphertext1 = cc->Encrypt(keyPair.publicKey, plaintext1);

  while (state.KeepRunning()) {
    auto ciphertextNeg = cc->EvalNegate(ciphertext1);
  }
}

HEXL_BENCHMARK(CKKS_Negate);

void CKKS_Sub(benchmark::State &state) {
  CryptoContext<DCRTPoly> cc =
      GenerateCKKSContext(state.range(0), state.range(1));

  LPKeyPair<DCRTPoly> keyPair = cc->KeyGen();

  usint slots = cc->GetEncodingParams()->GetBatchSize();
  std::vector<std::complex<double>> vectorOfInts1(slots);
  for (usint i = 0; i < slots; i++) {
    vectorOfInts1[i] = 1.001 * i;
  }
  std::vector<std::complex<double>> vectorOfInts2(slots);
  for (usint i = 0; i < slots; i++) {
    vectorOfInts2[i] = 1.001 * i;
  }

  auto plaintext1 = cc->MakeCKKSPackedPlaintext(vectorOfInts1);
  auto plaintext2 = cc->MakeCKKSPackedPlaintext(vectorOfInts2);

  auto ciphertext1 = cc->Encrypt(keyPair.publicKey, plaintext1);
  auto ciphertext2 = cc->Encrypt(keyPair.publicKey, plaintext2);

  while (state.KeepRunning()) {
    auto ciphertextSub = cc->EvalSub(ciphertext1, ciphertext2);
  }
}

HEXL_BENCHMARK(CKKS_Sub);

void CKKS_SubPlain(benchmark::State &state) {
  CryptoContext<DCRTPoly> cc =
      GenerateCKKSContext(state.range(0), state.range(1));

  LPKeyPair<DCRTPoly> keyPair = cc->KeyGen();

  usint slots = cc->GetEncodingParams()->GetBatchSize();
  std::vector<std::complex<double>> vectorOfInts1(slots);
  for (usint i = 0; i < slots; i++) {
    vectorOfInts1[i] = 1.001 * i;
  }
  std::vector<std::complex<double>> vectorOfInts2(slots);
  for (usint i = 0; i < slots; i++) {
    vectorOfInts2[i] = 1.001 * i;
  }

  auto plaintext1 = cc->MakeCKKSPackedPlaintext(vectorOfInts1);
  auto plaintext2 = cc->MakeCKKSPackedPlaintext(vectorOfInts2);

  auto ciphertext1 = cc->Encrypt(keyPair.publicKey, plaintext1);

  while (state.KeepRunning()) {
    auto ciphertextSub = cc->EvalSub(ciphertext1, plaintext2);
  }
}

HEXL_BENCHMARK(CKKS_SubPlain);

void CKKS_MultNoRelin(benchmark::State &state) {
  CryptoContext<DCRTPoly> cc =
      GenerateCKKSContext(state.range(0), state.range(1));

  LPKeyPair<DCRTPoly> keyPair = cc->KeyGen();

  usint slots = cc->GetEncodingParams()->GetBatchSize();
  std::vector<std::complex<double>> vectorOfInts1(slots);
  for (usint i = 0; i < slots; i++) {
    vectorOfInts1[i] = 1.001 * i;
  }
  std::vector<std::complex<double>> vectorOfInts2(slots);
  for (usint i = 0; i < slots; i++) {
    vectorOfInts2[i] = 1.001 * i;
  }

  auto plaintext1 = cc->MakeCKKSPackedPlaintext(vectorOfInts1);
  auto plaintext2 = cc->MakeCKKSPackedPlaintext(vectorOfInts2);

  auto ciphertext1 = cc->Encrypt(keyPair.publicKey, plaintext1);
  auto ciphertext2 = cc->Encrypt(keyPair.publicKey, plaintext2);

  while (state.KeepRunning()) {
    auto ciphertextMul = cc->EvalMultNoRelin(ciphertext1, ciphertext2);
  }
}

HEXL_BENCHMARK(CKKS_MultNoRelin);

void CKKS_MultRelin(benchmark::State &state) {
  CryptoContext<DCRTPoly> cc =
      GenerateCKKSContext(state.range(0), state.range(1));

  LPKeyPair<DCRTPoly> keyPair = cc->KeyGen();
  cc->EvalMultKeyGen(keyPair.secretKey);

  usint slots = cc->GetEncodingParams()->GetBatchSize();
  std::vector<std::complex<double>> vectorOfInts1(slots);
  for (usint i = 0; i < slots; i++) {
    vectorOfInts1[i] = 1.001 * i;
  }
  std::vector<std::complex<double>> vectorOfInts2(slots);
  for (usint i = 0; i < slots; i++) {
    vectorOfInts2[i] = 1.001 * i;
  }

  auto plaintext1 = cc->MakeCKKSPackedPlaintext(vectorOfInts1);
  auto plaintext2 = cc->MakeCKKSPackedPlaintext(vectorOfInts2);

  auto ciphertext1 = cc->Encrypt(keyPair.publicKey, plaintext1);
  auto ciphertext2 = cc->Encrypt(keyPair.publicKey, plaintext2);

  while (state.KeepRunning()) {
    auto ciphertextMul = cc->EvalMult(ciphertext1, ciphertext2);
  }
}

HEXL_BENCHMARK(CKKS_MultRelin);

void CKKS_MultPlain(benchmark::State &state) {
  CryptoContext<DCRTPoly> cc =
      GenerateCKKSContext(state.range(0), state.range(1));

  LPKeyPair<DCRTPoly> keyPair = cc->KeyGen();
  cc->EvalMultKeyGen(keyPair.secretKey);

  usint slots = cc->GetEncodingParams()->GetBatchSize();
  std::vector<std::complex<double>> vectorOfInts1(slots);
  for (usint i = 0; i < slots; i++) {
    vectorOfInts1[i] = 1.001 * i;
  }
  std::vector<std::complex<double>> vectorOfInts2(slots);
  for (usint i = 0; i < slots; i++) {
    vectorOfInts2[i] = 1.001 * i;
  }

  auto plaintext1 = cc->MakeCKKSPackedPlaintext(vectorOfInts1);
  auto plaintext2 = cc->MakeCKKSPackedPlaintext(vectorOfInts2);

  auto ciphertext1 = cc->Encrypt(keyPair.publicKey, plaintext1);

  while (state.KeepRunning()) {
    auto ciphertextMul = cc->EvalMult(ciphertext1, plaintext2);
  }
}

HEXL_BENCHMARK(CKKS_MultPlain);

void CKKS_Relin(benchmark::State &state) {
  CryptoContext<DCRTPoly> cc =
      GenerateCKKSContext(state.range(0), state.range(1));

  LPKeyPair<DCRTPoly> keyPair = cc->KeyGen();
  cc->EvalMultKeyGen(keyPair.secretKey);

  usint slots = cc->GetEncodingParams()->GetBatchSize();
  std::vector<std::complex<double>> vectorOfInts1(slots);
  for (usint i = 0; i < slots; i++) {
    vectorOfInts1[i] = 1.001 * i;
  }
  std::vector<std::complex<double>> vectorOfInts2(slots);
  for (usint i = 0; i < slots; i++) {
    vectorOfInts2[i] = 1.001 * i;
  }

  auto plaintext1 = cc->MakeCKKSPackedPlaintext(vectorOfInts1);
  auto plaintext2 = cc->MakeCKKSPackedPlaintext(vectorOfInts2);

  auto ciphertext1 = cc->Encrypt(keyPair.publicKey, plaintext1);
  auto ciphertext2 = cc->Encrypt(keyPair.publicKey, plaintext2);

  auto ciphertextMul = cc->EvalMultNoRelin(ciphertext1, ciphertext2);

  while (state.KeepRunning()) {
    auto ciphertext3 = cc->Relinearize(ciphertextMul);
  }
}

HEXL_BENCHMARK(CKKS_Relin);

void CKKS_Rescale(benchmark::State &state) {
  CryptoContext<DCRTPoly> cc =
      GenerateCKKSContext(state.range(0), state.range(1));

  LPKeyPair<DCRTPoly> keyPair = cc->KeyGen();
  cc->EvalMultKeyGen(keyPair.secretKey);

  usint slots = cc->GetEncodingParams()->GetBatchSize();
  std::vector<std::complex<double>> vectorOfInts1(slots);
  for (usint i = 0; i < slots; i++) {
    vectorOfInts1[i] = 1.001 * i;
  }
  std::vector<std::complex<double>> vectorOfInts2(slots);
  for (usint i = 0; i < slots; i++) {
    vectorOfInts2[i] = 1.001 * i;
  }

  auto plaintext1 = cc->MakeCKKSPackedPlaintext(vectorOfInts1);
  auto plaintext2 = cc->MakeCKKSPackedPlaintext(vectorOfInts2);

  auto ciphertext1 = cc->Encrypt(keyPair.publicKey, plaintext1);
  auto ciphertext2 = cc->Encrypt(keyPair.publicKey, plaintext2);

  auto ciphertextMul = cc->EvalMult(ciphertext1, ciphertext2);

  while (state.KeepRunning()) {
    auto ciphertext3 = cc->ModReduce(ciphertextMul);
  }
}

HEXL_BENCHMARK(CKKS_Rescale);

void CKKS_RescaleInPlace(benchmark::State &state) {
  CryptoContext<DCRTPoly> cc =
      GenerateCKKSContext(state.range(0), state.range(1));

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

HEXL_BENCHMARK(CKKS_RescaleInPlace);

void CKKS_EvalAtIndex(benchmark::State &state) {
  CryptoContext<DCRTPoly> cc =
      GenerateCKKSContext(state.range(0), state.range(1));

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
  std::vector<std::complex<double>> vectorOfInts2(slots);
  for (usint i = 0; i < slots; i++) {
    vectorOfInts2[i] = 1.001 * i;
  }

  auto plaintext1 = cc->MakeCKKSPackedPlaintext(vectorOfInts1);
  auto plaintext2 = cc->MakeCKKSPackedPlaintext(vectorOfInts2);

  auto ciphertext1 = cc->Encrypt(keyPair.publicKey, plaintext1);
  auto ciphertext2 = cc->Encrypt(keyPair.publicKey, plaintext2);

  auto ciphertextMul = cc->EvalMult(ciphertext1, ciphertext2);

  while (state.KeepRunning()) {
    auto ciphertext3 = cc->EvalAtIndex(ciphertextMul, 1);
  }
}

HEXL_BENCHMARK(CKKS_EvalAtIndex);

/*
 * BGVrns benchmarks
 * */

void BGVrns_KeyGen(benchmark::State &state) {
  CryptoContext<DCRTPoly> cc =
      GenerateBGVrnsContext(state.range(0), state.range(1));

  LPKeyPair<DCRTPoly> keyPair;

  while (state.KeepRunning()) {
    keyPair = cc->KeyGen();
  }
}

HEXL_BENCHMARK(BGVrns_KeyGen);

void BGVrns_MultKeyGen(benchmark::State &state) {
  CryptoContext<DCRTPoly> cc =
      GenerateBGVrnsContext(state.range(0), state.range(1));

  LPKeyPair<DCRTPoly> keyPair;
  keyPair = cc->KeyGen();

  while (state.KeepRunning()) {
    cc->EvalMultKeyGen(keyPair.secretKey);
  }
}

HEXL_BENCHMARK(BGVrns_MultKeyGen);

void BGVrns_EvalAtIndexKeyGen(benchmark::State &state) {
  CryptoContext<DCRTPoly> cc =
      GenerateBGVrnsContext(state.range(0), state.range(1));

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

HEXL_BENCHMARK(BGVrns_EvalAtIndexKeyGen);

void BGVrns_Encryption(benchmark::State &state) {
  CryptoContext<DCRTPoly> cc =
      GenerateBGVrnsContext(state.range(0), state.range(1));

  LPKeyPair<DCRTPoly> keyPair = cc->KeyGen();

  std::vector<int64_t> vectorOfInts = {1, 0, 1, 0, 1, 1, 1, 0, 1, 1, 1, 0};
  Plaintext plaintext = cc->MakePackedPlaintext(vectorOfInts);

  while (state.KeepRunning()) {
    auto ciphertext = cc->Encrypt(keyPair.publicKey, plaintext);
  }
}

HEXL_BENCHMARK(BGVrns_Encryption);

void BGVrns_Decryption(benchmark::State &state) {
  CryptoContext<DCRTPoly> cc =
      GenerateBGVrnsContext(state.range(0), state.range(1));

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

HEXL_BENCHMARK(BGVrns_Decryption);

void BGVrns_Add(benchmark::State &state) {
  CryptoContext<DCRTPoly> cc =
      GenerateBGVrnsContext(state.range(0), state.range(1));

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

HEXL_BENCHMARK(BGVrns_Add);

void BGVrns_AddInPlace(benchmark::State &state) {
  CryptoContext<DCRTPoly> cc =
      GenerateBGVrnsContext(state.range(0), state.range(1));

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

HEXL_BENCHMARK(BGVrns_AddInPlace);

void BGVrns_AddPlain(benchmark::State &state) {
  CryptoContext<DCRTPoly> cc =
      GenerateBGVrnsContext(state.range(0), state.range(1));

  LPKeyPair<DCRTPoly> keyPair = cc->KeyGen();

  std::vector<int64_t> vectorOfInts1 = {1, 0, 1, 0, 1, 1, 1, 0, 1, 1, 1, 0};
  std::vector<int64_t> vectorOfInts2 = {0, 1, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1};

  auto plaintext1 = cc->MakeCoefPackedPlaintext(vectorOfInts1);
  auto plaintext2 = cc->MakeCoefPackedPlaintext(vectorOfInts2);

  auto ciphertext1 = cc->Encrypt(keyPair.publicKey, plaintext1);

  while (state.KeepRunning()) {
    auto ciphertextAdd = cc->EvalAdd(ciphertext1, plaintext2);
  }
}

HEXL_BENCHMARK(BGVrns_AddPlain);

void BGVrns_Negate(benchmark::State &state) {
  CryptoContext<DCRTPoly> cc =
      GenerateBGVrnsContext(state.range(0), state.range(1));

  LPKeyPair<DCRTPoly> keyPair = cc->KeyGen();

  std::vector<int64_t> vectorOfInts1 = {1, 0, 1, 0, 1, 1, 1, 0, 1, 1, 1, 0};

  auto plaintext1 = cc->MakeCoefPackedPlaintext(vectorOfInts1);

  auto ciphertext1 = cc->Encrypt(keyPair.publicKey, plaintext1);

  while (state.KeepRunning()) {
    auto ciphertextNeg = cc->EvalNegate(ciphertext1);
  }
}

HEXL_BENCHMARK(BGVrns_Negate);

void BGVrns_Sub(benchmark::State &state) {
  CryptoContext<DCRTPoly> cc =
      GenerateBGVrnsContext(state.range(0), state.range(1));

  LPKeyPair<DCRTPoly> keyPair = cc->KeyGen();

  std::vector<int64_t> vectorOfInts1 = {1, 0, 1, 0, 1, 1, 1, 0, 1, 1, 1, 0};
  std::vector<int64_t> vectorOfInts2 = {0, 1, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1};

  auto plaintext1 = cc->MakeCoefPackedPlaintext(vectorOfInts1);
  auto plaintext2 = cc->MakeCoefPackedPlaintext(vectorOfInts2);

  auto ciphertext1 = cc->Encrypt(keyPair.publicKey, plaintext1);
  auto ciphertext2 = cc->Encrypt(keyPair.publicKey, plaintext2);

  while (state.KeepRunning()) {
    auto ciphertextSub = cc->EvalSub(ciphertext1, ciphertext2);
  }
}

HEXL_BENCHMARK(BGVrns_Sub);

void BGVrns_SubPlain(benchmark::State &state) {
  CryptoContext<DCRTPoly> cc =
      GenerateBGVrnsContext(state.range(0), state.range(1));

  LPKeyPair<DCRTPoly> keyPair = cc->KeyGen();

  std::vector<int64_t> vectorOfInts1 = {1, 0, 1, 0, 1, 1, 1, 0, 1, 1, 1, 0};
  std::vector<int64_t> vectorOfInts2 = {0, 1, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1};

  auto plaintext1 = cc->MakeCoefPackedPlaintext(vectorOfInts1);
  auto plaintext2 = cc->MakeCoefPackedPlaintext(vectorOfInts2);

  auto ciphertext1 = cc->Encrypt(keyPair.publicKey, plaintext1);

  while (state.KeepRunning()) {
    auto ciphertextSub = cc->EvalSub(ciphertext1, plaintext2);
  }
}

HEXL_BENCHMARK(BGVrns_SubPlain);

void BGVrns_MultNoRelin(benchmark::State &state) {
  CryptoContext<DCRTPoly> cc =
      GenerateBGVrnsContext(state.range(0), state.range(1));

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

HEXL_BENCHMARK(BGVrns_MultNoRelin);

void BGVrns_MultRelin(benchmark::State &state) {
  CryptoContext<DCRTPoly> cc =
      GenerateBGVrnsContext(state.range(0), state.range(1));

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

HEXL_BENCHMARK(BGVrns_MultRelin);

void BGVrns_MultPlain(benchmark::State &state) {
  CryptoContext<DCRTPoly> cc =
      GenerateBGVrnsContext(state.range(0), state.range(1));

  LPKeyPair<DCRTPoly> keyPair = cc->KeyGen();

  std::vector<int64_t> vectorOfInts1 = {1, 0, 1, 0, 1, 1, 1, 0, 1, 1, 1, 0};
  std::vector<int64_t> vectorOfInts2 = {0, 1, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1};

  auto plaintext1 = cc->MakeCoefPackedPlaintext(vectorOfInts1);
  auto plaintext2 = cc->MakeCoefPackedPlaintext(vectorOfInts2);

  auto ciphertext1 = cc->Encrypt(keyPair.publicKey, plaintext1);

  while (state.KeepRunning()) {
    auto ciphertextMul = cc->EvalMult(ciphertext1, plaintext2);
  }
}

HEXL_BENCHMARK(BGVrns_MultPlain);

void BGVrns_Relin(benchmark::State &state) {
  CryptoContext<DCRTPoly> cc =
      GenerateBGVrnsContext(state.range(0), state.range(1));

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

HEXL_BENCHMARK(BGVrns_Relin);

void BGVrns_ModSwitch(benchmark::State &state) {
  CryptoContext<DCRTPoly> cc =
      GenerateBGVrnsContext(state.range(0), state.range(1));

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

HEXL_BENCHMARK(BGVrns_ModSwitch);

void BGVrns_ModSwitchInPlace(benchmark::State &state) {
  CryptoContext<DCRTPoly> cc =
      GenerateBGVrnsContext(state.range(0), state.range(1));

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

HEXL_BENCHMARK(BGVrns_ModSwitchInPlace);

void BGVrns_EvalAtIndex(benchmark::State &state) {
  CryptoContext<DCRTPoly> cc =
      GenerateBGVrnsContext(state.range(0), state.range(1));

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

HEXL_BENCHMARK(BGVrns_EvalAtIndex);

BENCHMARK_MAIN();
