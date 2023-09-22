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
 * Compares the performance of BFV and BFV (default modes)
 * using EvalMultMany operation.
 */

#define PROFILE
#define _USE_MATH_DEFINES
#include "scheme/bfvrns/gen-cryptocontext-bfvrns.h"
#include "scheme/bgvrns/gen-cryptocontext-bgvrns.h"
#include "gen-cryptocontext.h"

#include "benchmark/benchmark.h"

#include <iostream>
#include <fstream>
#include <limits>
#include <iterator>
#include <random>

using namespace lbcrypto;

usint mult_depth = 3;

/*
 * Context setup utility methods
 */
CryptoContext<DCRTPoly> GenerateBFVrnsContext(usint ptm) {
    CCParams<CryptoContextBFVRNS> parameters;
    parameters.SetPlaintextModulus(ptm);
    parameters.SetMultiplicativeDepth(mult_depth);
    parameters.SetScalingModSize(60);
    parameters.SetKeySwitchTechnique(BV);

    CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);
    // enable features that you wish to use
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE);

    return cc;
}

CryptoContext<DCRTPoly> GenerateBGVrnsContext(usint ptm) {
    CCParams<CryptoContextBGVRNS> parameters;
    parameters.SetMultiplicativeDepth(mult_depth);
    parameters.SetPlaintextModulus(ptm);
    parameters.SetKeySwitchTechnique(BV);
    parameters.SetScalingTechnique(FIXEDMANUAL);

    CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE);

    return cc;
}

/*
 * BFVrns benchmarks
 */
void BFVrns_EvalMultManyP2(benchmark::State& state) {
    usint ptm = 2;

    CryptoContext<DCRTPoly> cc = GenerateBFVrnsContext(ptm);

    // KeyGen
    KeyPair<DCRTPoly> keyPair = cc->KeyGen();
    cc->EvalMultKeyGen(keyPair.secretKey);

    std::vector<int64_t> vectorOfInts = {1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    Plaintext plaintext               = cc->MakeCoefPackedPlaintext(vectorOfInts);

    std::vector<Ciphertext<DCRTPoly>> ciphertexts;
    for (int i = 0; i < (1 << mult_depth); i++)
        ciphertexts.push_back(cc->Encrypt(keyPair.publicKey, plaintext));

    Ciphertext<DCRTPoly> ciphertextMult;
    while (state.KeepRunning()) {
        ciphertextMult = cc->EvalMultMany(ciphertexts);
    }

    Plaintext plaintextDec;
    cc->Decrypt(keyPair.secretKey, ciphertextMult, &plaintextDec);
    plaintextDec->SetLength(plaintext->GetLength());

    if (plaintext != plaintextDec) {
        std::cout << "Original plaintext: " << plaintext << std::endl;
        std::cout << "Evaluated plaintext: " << plaintextDec << std::endl;
    }
}

BENCHMARK(BFVrns_EvalMultManyP2)->Unit(benchmark::kMicrosecond)->MinTime(10.0);

void BGVrns_EvalMultManyP2(benchmark::State& state) {
    usint ptm = 2;

    CryptoContext<DCRTPoly> cc = GenerateBGVrnsContext(ptm);

    // KeyGen
    KeyPair<DCRTPoly> keyPair = cc->KeyGen();
    cc->EvalMultKeyGen(keyPair.secretKey);

    std::vector<int64_t> vectorOfInts = {1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    Plaintext plaintext               = cc->MakeCoefPackedPlaintext(vectorOfInts);

    std::vector<Ciphertext<DCRTPoly>> ciphertexts;
    for (int i = 0; i < (1 << mult_depth); i++)
        ciphertexts.push_back(cc->Encrypt(keyPair.publicKey, plaintext));

    Ciphertext<DCRTPoly> ciphertextMult;
    while (state.KeepRunning()) {
        ciphertextMult = cc->EvalMultMany(ciphertexts);
    }

    Plaintext plaintextDec;
    cc->Decrypt(keyPair.secretKey, ciphertextMult, &plaintextDec);
    plaintextDec->SetLength(plaintext->GetLength());

    if (plaintext != plaintextDec) {
        std::cout << "Original plaintext: " << plaintext << std::endl;
        std::cout << "Evaluated plaintext: " << plaintextDec << std::endl;
    }
}

BENCHMARK(BGVrns_EvalMultManyP2)->Unit(benchmark::kMicrosecond)->MinTime(10.0);

/*
 * BFVrns benchmarks
 */

void BFVrns_EvalMultManyP65537(benchmark::State& state) {
    usint ptm = 65537;

    CryptoContext<DCRTPoly> cc = GenerateBFVrnsContext(ptm);

    // KeyGen
    KeyPair<DCRTPoly> keyPair = cc->KeyGen();
    cc->EvalMultKeyGen(keyPair.secretKey);

    std::vector<int64_t> vectorOfInts = {1, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 1};
    Plaintext plaintext               = cc->MakePackedPlaintext(vectorOfInts);

    std::vector<Ciphertext<DCRTPoly>> ciphertexts;
    for (int i = 0; i < (1 << mult_depth); i++)
        ciphertexts.push_back(cc->Encrypt(keyPair.publicKey, plaintext));

    Ciphertext<DCRTPoly> ciphertextMult;
    while (state.KeepRunning()) {
        ciphertextMult = cc->EvalMultMany(ciphertexts);
    }

    Plaintext plaintextDec;
    cc->Decrypt(keyPair.secretKey, ciphertextMult, &plaintextDec);
    plaintextDec->SetLength(plaintext->GetLength());

    if (plaintext != plaintextDec) {
        std::cout << "Original plaintext: " << plaintext << std::endl;
        std::cout << "Evaluated plaintext: " << plaintextDec << std::endl;
    }
}

BENCHMARK(BFVrns_EvalMultManyP65537)->Unit(benchmark::kMicrosecond)->MinTime(10.0);

void BGVrns_EvalMultManyP65537(benchmark::State& state) {
    usint ptm = 65537;

    CryptoContext<DCRTPoly> cc = GenerateBGVrnsContext(ptm);

    // KeyGen
    KeyPair<DCRTPoly> keyPair = cc->KeyGen();
    cc->EvalMultKeyGen(keyPair.secretKey);

    std::vector<int64_t> vectorOfInts = {1, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 1};
    Plaintext plaintext               = cc->MakePackedPlaintext(vectorOfInts);

    std::vector<Ciphertext<DCRTPoly>> ciphertexts;
    for (int i = 0; i < (1 << mult_depth); i++)
        ciphertexts.push_back(cc->Encrypt(keyPair.publicKey, plaintext));

    Ciphertext<DCRTPoly> ciphertextMult;
    while (state.KeepRunning()) {
        ciphertextMult = cc->EvalMultMany(ciphertexts);
    }

    Plaintext plaintextDec;
    cc->Decrypt(keyPair.secretKey, ciphertextMult, &plaintextDec);
    plaintextDec->SetLength(plaintext->GetLength());

    if (plaintext != plaintextDec) {
        std::cout << "Original plaintext: " << plaintext << std::endl;
        std::cout << "Evaluated plaintext: " << plaintextDec << std::endl;
    }
}

BENCHMARK(BGVrns_EvalMultManyP65537)->Unit(benchmark::kMicrosecond)->MinTime(10.0);

BENCHMARK_MAIN();
