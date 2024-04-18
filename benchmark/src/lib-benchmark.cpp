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

/*
 * Main OpenFHE library benchmark that contains performance tests for standard operations in the following schemes:
 * BFVrns, CKKSrns, BGVrns. It also contains several performance tests for NTT and INTT transformations.
 */

#define _USE_MATH_DEFINES

#include "benchmark/benchmark.h"
#include "math/hal/basicint.h"
#include "scheme/ckksrns/gen-cryptocontext-ckksrns.h"
#include "scheme/bfvrns/gen-cryptocontext-bfvrns.h"
#include "scheme/bgvrns/gen-cryptocontext-bgvrns.h"
#include "gen-cryptocontext.h"

#include <fstream>
#include <iostream>
#include <iterator>
#include <limits>
#include <random>

using namespace lbcrypto;

/*
 * Context setup utility methods
 */

[[maybe_unused]] static void DepthArgs(benchmark::internal::Benchmark* b) {
    for (uint32_t d : {1, 2, 4, 6, 8, 10, 12})
        b->ArgName("depth")->Arg(d);
}

[[maybe_unused]] static CryptoContext<DCRTPoly> GenerateBFVrnsContext(uint32_t mdepth = 1) {
    CCParams<CryptoContextBFVRNS> parameters;
    parameters.SetPlaintextModulus(65537);
    parameters.SetScalingModSize(60);
    parameters.SetMultiplicativeDepth(mdepth);
    CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    return cc;
}

[[maybe_unused]] static CryptoContext<DCRTPoly> GenerateCKKSContext(uint32_t mdepth = 1) {
    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetScalingModSize(48);
    parameters.SetBatchSize(8);
    parameters.SetScalingTechnique(FIXEDMANUAL);
    parameters.SetMultiplicativeDepth(mdepth);
    auto cc = GenCryptoContext(parameters);
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    return cc;
}

[[maybe_unused]] static CryptoContext<DCRTPoly> GenerateBGVrnsContext(uint32_t mdepth = 1) {
    CCParams<CryptoContextBGVRNS> parameters;
    parameters.SetPlaintextModulus(65537);
    parameters.SetMaxRelinSkDeg(1);
    parameters.SetScalingTechnique(FIXEDMANUAL);
    parameters.SetMultiplicativeDepth(mdepth);
    CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    return cc;
}

/*
 * Native NTT benchmarks
 */

[[maybe_unused]] static void RingArgs(benchmark::internal::Benchmark* b) {
    for (uint32_t r : {1024, 4096, 8192})
        b->ArgName("ringdm")->Arg(r);
}

[[maybe_unused]] static void NativeNTT(benchmark::State& state) {
    uint32_t n = state.range(0);
    uint32_t m = n << 1;

    NativeInteger modulusQ(LastPrime<NativeInteger>(MAX_MODULUS_SIZE, m));
    NativeInteger rootOfUnity = RootOfUnity(m, modulusQ);

    DiscreteUniformGeneratorImpl<NativeVector> dug;
    NativeVector x = dug.GenerateVector(n, modulusQ);
    NativeVector X(n);

    ChineseRemainderTransformFTT<NativeVector> crtFTT;
    crtFTT.PreCompute(rootOfUnity, m, modulusQ);

    for (auto _ : state)
        crtFTT.ForwardTransformToBitReverse(x, rootOfUnity, m, &X);

    state.SetComplexityN(state.range(0));
}

[[maybe_unused]] static void NativeINTT(benchmark::State& state) {
    uint32_t n = state.range(0);
    uint32_t m = n << 1;

    NativeInteger modulusQ(LastPrime<NativeInteger>(MAX_MODULUS_SIZE, m));
    NativeInteger rootOfUnity = RootOfUnity(m, modulusQ);

    DiscreteUniformGeneratorImpl<NativeVector> dug;
    NativeVector x = dug.GenerateVector(n, modulusQ);
    NativeVector X(n);

    ChineseRemainderTransformFTT<NativeVector> crtFTT;
    crtFTT.PreCompute(rootOfUnity, m, modulusQ);

    for (auto _ : state)
        crtFTT.InverseTransformFromBitReverse(x, rootOfUnity, m, &X);

    state.SetComplexityN(state.range(0));
}

[[maybe_unused]] static void NativeNTTInPlace(benchmark::State& state) {
    uint32_t n = state.range(0);
    uint32_t m = n << 1;

    NativeInteger modulusQ(LastPrime<NativeInteger>(MAX_MODULUS_SIZE, m));
    NativeInteger rootOfUnity = RootOfUnity(m, modulusQ);

    DiscreteUniformGeneratorImpl<NativeVector> dug;
    NativeVector x = dug.GenerateVector(n, modulusQ);

    ChineseRemainderTransformFTT<NativeVector> crtFTT;
    crtFTT.PreCompute(rootOfUnity, m, modulusQ);

    for (auto _ : state)
        crtFTT.ForwardTransformToBitReverseInPlace(rootOfUnity, m, &x);

    state.SetComplexityN(state.range(0));
}

[[maybe_unused]] static void NativeINTTInPlace(benchmark::State& state) {
    uint32_t n = state.range(0);
    uint32_t m = n << 1;

    NativeInteger modulusQ(LastPrime<NativeInteger>(MAX_MODULUS_SIZE, m));
    NativeInteger rootOfUnity = RootOfUnity(m, modulusQ);

    DiscreteUniformGeneratorImpl<NativeVector> dug;
    NativeVector x = dug.GenerateVector(n, modulusQ);

    ChineseRemainderTransformFTT<NativeVector> crtFTT;
    crtFTT.PreCompute(rootOfUnity, m, modulusQ);

    for (auto _ : state)
        crtFTT.InverseTransformFromBitReverseInPlace(rootOfUnity, m, &x);

    state.SetComplexityN(state.range(0));
}

// BENCHMARK(NativeNTT)->Unit(benchmark::kMicrosecond)->RangeMultiplier(2)->Range(1<<10, 1<<16)->Complexity(benchmark::oAuto);
BENCHMARK(NativeNTT)->Unit(benchmark::kMicrosecond)->Apply(RingArgs);          // ->Complexity(benchmark::oAuto);
BENCHMARK(NativeINTT)->Unit(benchmark::kMicrosecond)->Apply(RingArgs);         // ->Complexity(benchmark::oAuto);
BENCHMARK(NativeNTTInPlace)->Unit(benchmark::kMicrosecond)->Apply(RingArgs);   // ->Complexity(benchmark::oAuto);
BENCHMARK(NativeINTTInPlace)->Unit(benchmark::kMicrosecond)->Apply(RingArgs);  // ->Complexity(benchmark::oAuto);

/*
 * BFVrns benchmarks
 */

void BFVrns_KeyGen(benchmark::State& state) {
    CryptoContext<DCRTPoly> cryptoContext = GenerateBFVrnsContext();

    KeyPair<DCRTPoly> keyPair;

    while (state.KeepRunning()) {
        keyPair = cryptoContext->KeyGen();
    }
}

BENCHMARK(BFVrns_KeyGen)->Unit(benchmark::kMicrosecond);

void BFVrns_MultKeyGen(benchmark::State& state) {
    CryptoContext<DCRTPoly> cc = GenerateBFVrnsContext();

    KeyPair<DCRTPoly> keyPair;
    keyPair = cc->KeyGen();

    while (state.KeepRunning()) {
        cc->EvalMultKeyGen(keyPair.secretKey);
    }
}

BENCHMARK(BFVrns_MultKeyGen)->Unit(benchmark::kMicrosecond);

// TODO: revisit this?
void BFVrns_EvalAtIndexKeyGen(benchmark::State& state) {
    CryptoContext<DCRTPoly> cc = GenerateBFVrnsContext();

    KeyPair<DCRTPoly> keyPair;
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

void BFVrns_Encryption(benchmark::State& state) {
    CryptoContext<DCRTPoly> cryptoContext = GenerateBFVrnsContext();

    KeyPair<DCRTPoly> keyPair = cryptoContext->KeyGen();

    std::vector<int64_t> vectorOfInts1 = {1, 0, 1, 0, 1, 1, 1, 0, 1, 1, 1, 0};
    Plaintext plaintext1               = cryptoContext->MakePackedPlaintext(vectorOfInts1);

    while (state.KeepRunning()) {
        auto ciphertext1 = cryptoContext->Encrypt(keyPair.publicKey, plaintext1);
    }
}

BENCHMARK(BFVrns_Encryption)->Unit(benchmark::kMicrosecond);

void BFVrns_Decryption(benchmark::State& state) {
    CryptoContext<DCRTPoly> cryptoContext = GenerateBFVrnsContext();

    KeyPair<DCRTPoly> keyPair = cryptoContext->KeyGen();

    std::vector<int64_t> vectorOfInts1 = {1, 0, 1, 0, 1, 1, 1, 0, 1, 1, 1, 0};
    Plaintext plaintext1               = cryptoContext->MakePackedPlaintext(vectorOfInts1);

    auto ciphertext1 = cryptoContext->Encrypt(keyPair.publicKey, plaintext1);
    Plaintext plaintextDec1;

    while (state.KeepRunning()) {
        cryptoContext->Decrypt(keyPair.secretKey, ciphertext1, &plaintextDec1);
    }
}

BENCHMARK(BFVrns_Decryption)->Unit(benchmark::kMicrosecond);

void BFVrns_Add(benchmark::State& state) {
    CryptoContext<DCRTPoly> cc = GenerateBFVrnsContext();

    KeyPair<DCRTPoly> keyPair = cc->KeyGen();

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

void BFVrns_AddInPlace(benchmark::State& state) {
    CryptoContext<DCRTPoly> cc = GenerateBFVrnsContext();

    KeyPair<DCRTPoly> keyPair = cc->KeyGen();

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

void BFVrns_MultNoRelin(benchmark::State& state) {
    CryptoContext<DCRTPoly> cryptoContext = GenerateBFVrnsContext(state.range(0));

    KeyPair<DCRTPoly> keyPair = cryptoContext->KeyGen();

    std::vector<int64_t> vectorOfInts1 = {1, 0, 1, 0, 1, 1, 1, 0, 1, 1, 1, 0};
    Plaintext plaintext1               = cryptoContext->MakePackedPlaintext(vectorOfInts1);

    std::vector<int64_t> vectorOfInts2 = {1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 0};
    Plaintext plaintext2               = cryptoContext->MakePackedPlaintext(vectorOfInts2);

    auto ciphertext1 = cryptoContext->Encrypt(keyPair.publicKey, plaintext1);
    auto ciphertext2 = cryptoContext->Encrypt(keyPair.publicKey, plaintext2);

    while (state.KeepRunning()) {
        auto ciphertextMul = cryptoContext->EvalMultNoRelin(ciphertext1, ciphertext2);
    }

    state.SetComplexityN(state.range(0));
}

BENCHMARK(BFVrns_MultNoRelin)->Unit(benchmark::kMicrosecond)->Apply(DepthArgs);  // ->Complexity(benchmark::oAuto);

void BFVrns_MultRelin(benchmark::State& state) {
    CryptoContext<DCRTPoly> cryptoContext = GenerateBFVrnsContext(state.range(0));

    KeyPair<DCRTPoly> keyPair = cryptoContext->KeyGen();
    cryptoContext->EvalMultKeyGen(keyPair.secretKey);

    std::vector<int64_t> vectorOfInts1 = {1, 0, 1, 0, 1, 1, 1, 0, 1, 1, 1, 0};
    Plaintext plaintext1               = cryptoContext->MakePackedPlaintext(vectorOfInts1);

    std::vector<int64_t> vectorOfInts2 = {1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 0};
    Plaintext plaintext2               = cryptoContext->MakePackedPlaintext(vectorOfInts2);

    auto ciphertext1 = cryptoContext->Encrypt(keyPair.publicKey, plaintext1);
    auto ciphertext2 = cryptoContext->Encrypt(keyPair.publicKey, plaintext2);

    while (state.KeepRunning()) {
        auto ciphertextMul = cryptoContext->EvalMult(ciphertext1, ciphertext2);
    }

    state.SetComplexityN(state.range(0));
}

BENCHMARK(BFVrns_MultRelin)->Unit(benchmark::kMicrosecond)->Apply(DepthArgs);  // ->Complexity(benchmark::oAuto);

void BFVrns_EvalAtIndex(benchmark::State& state) {
    CryptoContext<DCRTPoly> cc = GenerateBFVrnsContext();

    KeyPair<DCRTPoly> keyPair = cc->KeyGen();
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

void CKKSrns_KeyGen(benchmark::State& state) {
    CryptoContext<DCRTPoly> cryptoContext = GenerateCKKSContext();

    KeyPair<DCRTPoly> keyPair;

    while (state.KeepRunning()) {
        keyPair = cryptoContext->KeyGen();
    }
}

BENCHMARK(CKKSrns_KeyGen)->Unit(benchmark::kMicrosecond);

void CKKSrns_MultKeyGen(benchmark::State& state) {
    CryptoContext<DCRTPoly> cc = GenerateCKKSContext();

    KeyPair<DCRTPoly> keyPair;
    keyPair = cc->KeyGen();

    while (state.KeepRunning()) {
        cc->EvalMultKeyGen(keyPair.secretKey);
    }
}

BENCHMARK(CKKSrns_MultKeyGen)->Unit(benchmark::kMicrosecond);

void CKKSrns_EvalAtIndexKeyGen(benchmark::State& state) {
    CryptoContext<DCRTPoly> cc = GenerateCKKSContext();

    KeyPair<DCRTPoly> keyPair;
    keyPair = cc->KeyGen();

    std::vector<int32_t> indexList(1);
    for (usint i = 0; i < 1; i++) {
        indexList[i] = 1;
    }

    while (state.KeepRunning()) {
        cc->EvalAtIndexKeyGen(keyPair.secretKey, indexList);
    }
}

BENCHMARK(CKKSrns_EvalAtIndexKeyGen)->Unit(benchmark::kMicrosecond);

void CKKSrns_Encryption(benchmark::State& state) {
    CryptoContext<DCRTPoly> cc = GenerateCKKSContext();

    KeyPair<DCRTPoly> keyPair = cc->KeyGen();

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

BENCHMARK(CKKSrns_Encryption)->Unit(benchmark::kMicrosecond);

void CKKSrns_Decryption(benchmark::State& state) {
    CryptoContext<DCRTPoly> cc = GenerateCKKSContext();

    KeyPair<DCRTPoly> keyPair = cc->KeyGen();

    usint slots = cc->GetEncodingParams()->GetBatchSize();
    std::vector<std::complex<double>> vectorOfInts1(slots);
    for (usint i = 0; i < slots; i++) {
        vectorOfInts1[i] = 1.001 * i;
    }

    auto plaintext1  = cc->MakeCKKSPackedPlaintext(vectorOfInts1);
    auto ciphertext1 = cc->Encrypt(keyPair.publicKey, plaintext1);
    ciphertext1      = cc->LevelReduce(ciphertext1, nullptr, 1);

    Plaintext plaintextDec1;

    while (state.KeepRunning()) {
        cc->Decrypt(keyPair.secretKey, ciphertext1, &plaintextDec1);
    }
}

BENCHMARK(CKKSrns_Decryption)->Unit(benchmark::kMicrosecond);

void CKKSrns_Add(benchmark::State& state) {
    CryptoContext<DCRTPoly> cc = GenerateCKKSContext();

    KeyPair<DCRTPoly> keyPair = cc->KeyGen();

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

BENCHMARK(CKKSrns_Add)->Unit(benchmark::kMicrosecond);

void CKKSrns_AddInPlace(benchmark::State& state) {
    CryptoContext<DCRTPoly> cc = GenerateCKKSContext();

    KeyPair<DCRTPoly> keyPair = cc->KeyGen();

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

BENCHMARK(CKKSrns_AddInPlace)->Unit(benchmark::kMicrosecond);

void CKKSrns_MultNoRelin(benchmark::State& state) {
    CryptoContext<DCRTPoly> cc = GenerateCKKSContext(state.range(0));

    KeyPair<DCRTPoly> keyPair = cc->KeyGen();

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

    state.SetComplexityN(state.range(0));
}

BENCHMARK(CKKSrns_MultNoRelin)->Unit(benchmark::kMicrosecond)->Apply(DepthArgs);  // ->Complexity(benchmark::oAuto);

void CKKSrns_MultRelin(benchmark::State& state) {
    CryptoContext<DCRTPoly> cc = GenerateCKKSContext(state.range(0));

    KeyPair<DCRTPoly> keyPair = cc->KeyGen();
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

    state.SetComplexityN(state.range(0));
}

BENCHMARK(CKKSrns_MultRelin)->Unit(benchmark::kMicrosecond)->Apply(DepthArgs);  // ->Complexity(benchmark::oAuto);

void CKKSrns_Relin(benchmark::State& state) {
    CryptoContext<DCRTPoly> cc = GenerateCKKSContext();

    KeyPair<DCRTPoly> keyPair = cc->KeyGen();
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

BENCHMARK(CKKSrns_Relin)->Unit(benchmark::kMicrosecond);

void CKKSrns_RelinInPlace(benchmark::State& state) {
    CryptoContext<DCRTPoly> cc = GenerateCKKSContext();

    KeyPair<DCRTPoly> keyPair = cc->KeyGen();
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

    auto ciphertextMul      = cc->EvalMultNoRelin(ciphertext1, ciphertext2);
    auto ciphertextMulClone = ciphertextMul->Clone();

    while (state.KeepRunning()) {
        cc->RelinearizeInPlace(ciphertextMul);
        state.PauseTiming();
        ciphertextMul = ciphertextMulClone->Clone();
        state.ResumeTiming();
    }
}

BENCHMARK(CKKSrns_RelinInPlace)->Unit(benchmark::kMicrosecond);

void CKKSrns_Rescale(benchmark::State& state) {
    CryptoContext<DCRTPoly> cc = GenerateCKKSContext();

    KeyPair<DCRTPoly> keyPair = cc->KeyGen();
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

BENCHMARK(CKKSrns_Rescale)->Unit(benchmark::kMicrosecond);

void CKKSrns_RescaleInPlace(benchmark::State& state) {
    CryptoContext<DCRTPoly> cc = GenerateCKKSContext();

    KeyPair<DCRTPoly> keyPair = cc->KeyGen();
    cc->EvalMultKeyGen(keyPair.secretKey);

    usint slots = cc->GetEncodingParams()->GetBatchSize();
    std::vector<std::complex<double>> vectorOfInts(slots);
    for (usint i = 0; i < slots; i++) {
        vectorOfInts[i] = 1.001 * i;
    }

    auto plaintext          = cc->MakeCKKSPackedPlaintext(vectorOfInts);
    auto ciphertext         = cc->Encrypt(keyPair.publicKey, plaintext);
    auto ciphertextMul      = cc->EvalMult(ciphertext, ciphertext);
    auto ciphertextMulClone = ciphertextMul->Clone();

    while (state.KeepRunning()) {
        cc->ModReduceInPlace(ciphertextMul);
        state.PauseTiming();
        ciphertextMul = ciphertextMulClone->Clone();
        state.ResumeTiming();
    }
}

BENCHMARK(CKKSrns_RescaleInPlace)->Unit(benchmark::kMicrosecond);

void CKKSrns_EvalAtIndex(benchmark::State& state) {
    CryptoContext<DCRTPoly> cc = GenerateCKKSContext();

    KeyPair<DCRTPoly> keyPair = cc->KeyGen();
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

BENCHMARK(CKKSrns_EvalAtIndex)->Unit(benchmark::kMicrosecond);

/*
 * BGVrns benchmarks
 * */

void BGVrns_KeyGen(benchmark::State& state) {
    CryptoContext<DCRTPoly> cryptoContext = GenerateBGVrnsContext();

    KeyPair<DCRTPoly> keyPair;

    while (state.KeepRunning()) {
        keyPair = cryptoContext->KeyGen();
    }
}

BENCHMARK(BGVrns_KeyGen)->Unit(benchmark::kMicrosecond);

void BGVrns_MultKeyGen(benchmark::State& state) {
    CryptoContext<DCRTPoly> cc = GenerateBGVrnsContext();

    KeyPair<DCRTPoly> keyPair;
    keyPair = cc->KeyGen();

    while (state.KeepRunning()) {
        cc->EvalMultKeyGen(keyPair.secretKey);
    }
}

BENCHMARK(BGVrns_MultKeyGen)->Unit(benchmark::kMicrosecond);

void BGVrns_EvalAtIndexKeyGen(benchmark::State& state) {
    CryptoContext<DCRTPoly> cc = GenerateBGVrnsContext();

    KeyPair<DCRTPoly> keyPair;
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

void BGVrns_Encryption(benchmark::State& state) {
    CryptoContext<DCRTPoly> cryptoContext = GenerateBGVrnsContext();

    KeyPair<DCRTPoly> keyPair = cryptoContext->KeyGen();

    std::vector<int64_t> vectorOfInts = {1, 0, 1, 0, 1, 1, 1, 0, 1, 1, 1, 0};
    Plaintext plaintext               = cryptoContext->MakePackedPlaintext(vectorOfInts);

    while (state.KeepRunning()) {
        auto ciphertext = cryptoContext->Encrypt(keyPair.publicKey, plaintext);
    }
}

BENCHMARK(BGVrns_Encryption)->Unit(benchmark::kMicrosecond);

void BGVrns_Decryption(benchmark::State& state) {
    CryptoContext<DCRTPoly> cc = GenerateBGVrnsContext();

    KeyPair<DCRTPoly> keyPair = cc->KeyGen();

    std::vector<int64_t> vectorOfInts = {1, 0, 1, 0, 1, 1, 1, 0, 1, 1, 1, 0};
    Plaintext plaintext               = cc->MakePackedPlaintext(vectorOfInts);

    auto ciphertext = cc->Encrypt(keyPair.publicKey, plaintext);
    ciphertext      = cc->ModReduce(ciphertext);  // TODO LevelReduce

    Plaintext plaintextDec;

    while (state.KeepRunning()) {
        cc->Decrypt(keyPair.secretKey, ciphertext, &plaintextDec);
    }
}

BENCHMARK(BGVrns_Decryption)->Unit(benchmark::kMicrosecond);

void BGVrns_Add(benchmark::State& state) {
    CryptoContext<DCRTPoly> cc = GenerateBGVrnsContext();

    KeyPair<DCRTPoly> keyPair = cc->KeyGen();

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

void BGVrns_AddInPlace(benchmark::State& state) {
    CryptoContext<DCRTPoly> cc = GenerateBGVrnsContext();

    KeyPair<DCRTPoly> keyPair = cc->KeyGen();

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

void BGVrns_MultNoRelin(benchmark::State& state) {
    CryptoContext<DCRTPoly> cc = GenerateBGVrnsContext(state.range(0));

    KeyPair<DCRTPoly> keyPair = cc->KeyGen();

    std::vector<int64_t> vectorOfInts1 = {1, 0, 1, 0, 1, 1, 1, 0, 1, 1, 1, 0};
    std::vector<int64_t> vectorOfInts2 = {0, 1, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1};

    auto plaintext1 = cc->MakePackedPlaintext(vectorOfInts1);
    auto plaintext2 = cc->MakePackedPlaintext(vectorOfInts2);

    auto ciphertext1 = cc->Encrypt(keyPair.publicKey, plaintext1);
    auto ciphertext2 = cc->Encrypt(keyPair.publicKey, plaintext2);

    while (state.KeepRunning()) {
        auto ciphertextMul = cc->EvalMultNoRelin(ciphertext1, ciphertext2);
    }

    state.SetComplexityN(state.range(0));
}

BENCHMARK(BGVrns_MultNoRelin)->Unit(benchmark::kMicrosecond)->Apply(DepthArgs);  // ->Complexity(benchmark::oAuto);

void BGVrns_MultRelin(benchmark::State& state) {
    CryptoContext<DCRTPoly> cc = GenerateBGVrnsContext(state.range(0));

    KeyPair<DCRTPoly> keyPair = cc->KeyGen();
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

    state.SetComplexityN(state.range(0));
}

BENCHMARK(BGVrns_MultRelin)->Unit(benchmark::kMicrosecond)->Apply(DepthArgs);  // ->Complexity(benchmark::oAuto);

void BGVrns_Relin(benchmark::State& state) {
    CryptoContext<DCRTPoly> cc = GenerateBGVrnsContext();

    KeyPair<DCRTPoly> keyPair = cc->KeyGen();
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

void BGVrns_RelinInPlace(benchmark::State& state) {
    CryptoContext<DCRTPoly> cc = GenerateBGVrnsContext();

    KeyPair<DCRTPoly> keyPair = cc->KeyGen();
    cc->EvalMultKeyGen(keyPair.secretKey);

    std::vector<int64_t> vectorOfInts1 = {1, 0, 1, 0, 1, 1, 1, 0, 1, 1, 1, 0};
    std::vector<int64_t> vectorOfInts2 = {0, 1, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1};

    auto plaintext1 = cc->MakePackedPlaintext(vectorOfInts1);
    auto plaintext2 = cc->MakePackedPlaintext(vectorOfInts2);

    auto ciphertext1 = cc->Encrypt(keyPair.publicKey, plaintext1);
    auto ciphertext2 = cc->Encrypt(keyPair.publicKey, plaintext2);

    auto ciphertextMul      = cc->EvalMultNoRelin(ciphertext1, ciphertext2);
    auto ciphertextMulClone = ciphertextMul->Clone();

    while (state.KeepRunning()) {
        cc->RelinearizeInPlace(ciphertextMul);
        state.PauseTiming();
        ciphertextMul = ciphertextMulClone->Clone();
        state.ResumeTiming();
    }
}

BENCHMARK(BGVrns_RelinInPlace)->Unit(benchmark::kMicrosecond);

void BGVrns_ModSwitch(benchmark::State& state) {
    CryptoContext<DCRTPoly> cc = GenerateBGVrnsContext();

    KeyPair<DCRTPoly> keyPair = cc->KeyGen();
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

void BGVrns_ModSwitchInPlace(benchmark::State& state) {
    CryptoContext<DCRTPoly> cc = GenerateBGVrnsContext();

    KeyPair<DCRTPoly> keyPair = cc->KeyGen();
    cc->EvalMultKeyGen(keyPair.secretKey);

    std::vector<int64_t> vectorOfInts = {1, 0, 1, 0, 1, 1, 1, 0, 1, 1, 1, 0};

    auto plaintext          = cc->MakePackedPlaintext(vectorOfInts);
    auto ciphertext         = cc->Encrypt(keyPair.publicKey, plaintext);
    auto ciphertextMul      = cc->EvalMult(ciphertext, ciphertext);
    auto ciphertextMulClone = ciphertextMul->Clone();

    while (state.KeepRunning()) {
        cc->ModReduceInPlace(ciphertextMul);
        state.PauseTiming();
        ciphertextMul = ciphertextMulClone->Clone();
        state.ResumeTiming();
    }
}

BENCHMARK(BGVrns_ModSwitchInPlace)->Unit(benchmark::kMicrosecond);

void BGVrns_EvalAtIndex(benchmark::State& state) {
    CryptoContext<DCRTPoly> cc = GenerateBGVrnsContext();

    KeyPair<DCRTPoly> keyPair = cc->KeyGen();
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
