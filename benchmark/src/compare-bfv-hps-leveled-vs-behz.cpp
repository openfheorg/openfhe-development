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
 * Compares the performance of BFV HPSPOVERQLEVELED with BFV BEHZ
 * using EvalMultMany operation.
 */

#define PROFILE
#define _USE_MATH_DEFINES
#include "scheme/bfvrns/gen-cryptocontext-bfvrns.h"
#include "gen-cryptocontext.h"

#include "benchmark/benchmark.h"

#include <iostream>
#include <fstream>
#include <limits>
#include <iterator>
#include <random>

using namespace lbcrypto;

usint mult_depth = 3;
static std::vector<usint> ptm_args{2, 65537};
static std::vector<usint> dcrtbit_args{30, 60};
static std::vector<usint> logn_args{12, 14};

static void MultBFVArguments(benchmark::internal::Benchmark* b) {
    for (usint ptm : ptm_args) {
        for (usint dcrtbit : dcrtbit_args) {
            b->ArgNames({"ptm", "dcrtbit"})->Args({ptm, dcrtbit})->MinTime(10.0);
        }
    }
}

static void DecBFVArguments(benchmark::internal::Benchmark* b) {
    for (usint ptm : ptm_args) {
        for (usint dcrtbit : dcrtbit_args) {
            for (usint logn : logn_args) {
                b->ArgNames({"ptm", "dcrtbit", "logn"})->Args({ptm, dcrtbit, logn});
            }
        }
    }
}

/*
 * Context setup utility methods
 */

CryptoContext<DCRTPoly> GenerateBFVrnsContext(usint ptm, usint dcrtBits) {
    CCParams<CryptoContextBFVRNS> parameters;
    parameters.SetPlaintextModulus(ptm);
    parameters.SetMultiplicativeDepth(mult_depth);
    parameters.SetScalingModSize(dcrtBits);
    parameters.SetMultiplicationTechnique(HPSPOVERQLEVELED);

    CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE);

    return cc;
}

CryptoContext<DCRTPoly> GenerateBEHZContext(usint ptm, usint dcrtBits) {
    CCParams<CryptoContextBFVRNS> parameters;
    parameters.SetPlaintextModulus(ptm);
    parameters.SetMultiplicativeDepth(mult_depth);
    parameters.SetScalingModSize(dcrtBits);
    parameters.SetMultiplicationTechnique(BEHZ);

    CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE);

    return cc;
}

CryptoContext<DCRTPoly> GenerateFlatBFVrnsContext(usint ptm, usint dcrtBits, usint n) {
    CCParams<CryptoContextBFVRNS> parameters;
    parameters.SetPlaintextModulus(ptm);
    parameters.SetMaxRelinSkDeg(0);
    parameters.SetScalingModSize(dcrtBits);
    parameters.SetRingDim(n);
    parameters.SetMultiplicationTechnique(HPSPOVERQLEVELED);

    CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    return cc;
}

CryptoContext<DCRTPoly> GenerateFlatBEHZContext(usint ptm, usint dcrtBits, usint n) {
    CCParams<CryptoContextBFVRNS> parameters;
    parameters.SetPlaintextModulus(ptm);
    parameters.SetMaxRelinSkDeg(0);
    parameters.SetScalingModSize(dcrtBits);
    parameters.SetRingDim(n);
    parameters.SetMultiplicationTechnique(BEHZ);

    CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    return cc;
}

/*
 * benchmarks
 */
void BFVrns_EvalMultMany(benchmark::State& state) {
    CryptoContext<DCRTPoly> cc = GenerateBFVrnsContext(state.range(0), state.range(1));

    // KeyGen
    KeyPair<DCRTPoly> keyPair = cc->KeyGen();
    cc->EvalMultKeyGen(keyPair.secretKey);

    std::vector<int64_t> vectorOfInts = {1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

    Plaintext plaintext;
    if (state.range(0) == 2)
        plaintext = cc->MakeCoefPackedPlaintext(vectorOfInts);
    else
        plaintext = cc->MakePackedPlaintext(vectorOfInts);

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

BENCHMARK(BFVrns_EvalMultMany)->Unit(benchmark::kMicrosecond)->Apply(MultBFVArguments);

void BEHZ_EvalMultMany(benchmark::State& state) {
    CryptoContext<DCRTPoly> cc = GenerateBEHZContext(state.range(0), state.range(1));

    // KeyGen
    KeyPair<DCRTPoly> keyPair = cc->KeyGen();
    cc->EvalMultKeyGen(keyPair.secretKey);

    std::vector<int64_t> vectorOfInts = {1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    Plaintext plaintext;
    if (state.range(0) == 2)
        plaintext = cc->MakeCoefPackedPlaintext(vectorOfInts);
    else
        plaintext = cc->MakePackedPlaintext(vectorOfInts);

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

BENCHMARK(BEHZ_EvalMultMany)->Unit(benchmark::kMicrosecond)->Apply(MultBFVArguments);

void BFVrns_Decrypt(benchmark::State& state) {
    CryptoContext<DCRTPoly> cryptoContext =
        GenerateFlatBFVrnsContext(state.range(0), state.range(1), 1 << state.range(2));

    KeyPair<DCRTPoly> keyPair = cryptoContext->KeyGen();

    std::vector<int64_t> vectorOfInts1 = {1, 0, 1, 0, 1, 1, 1, 0, 1, 1, 1, 0};
    Plaintext plaintext1;
    if (state.range(0) == 2)
        plaintext1 = cryptoContext->MakeCoefPackedPlaintext(vectorOfInts1);
    else
        plaintext1 = cryptoContext->MakePackedPlaintext(vectorOfInts1);

    auto ciphertext1 = cryptoContext->Encrypt(keyPair.publicKey, plaintext1);
    Plaintext plaintextDec1;

    while (state.KeepRunning()) {
        cryptoContext->Decrypt(keyPair.secretKey, ciphertext1, &plaintextDec1);
    }
}

BENCHMARK(BFVrns_Decrypt)->Unit(benchmark::kMicrosecond)->Apply(DecBFVArguments);

void BEHZ_Decrypt(benchmark::State& state) {
    CryptoContext<DCRTPoly> cryptoContext =
        GenerateFlatBEHZContext(state.range(0), state.range(1), 1 << state.range(2));

    KeyPair<DCRTPoly> keyPair = cryptoContext->KeyGen();

    std::vector<int64_t> vectorOfInts1 = {1, 0, 1, 0, 1, 1, 1, 0, 1, 1, 1, 0};
    Plaintext plaintext1;
    if (state.range(0) == 2)
        plaintext1 = cryptoContext->MakeCoefPackedPlaintext(vectorOfInts1);
    else
        plaintext1 = cryptoContext->MakePackedPlaintext(vectorOfInts1);

    auto ciphertext1 = cryptoContext->Encrypt(keyPair.publicKey, plaintext1);
    Plaintext plaintextDec1;

    while (state.KeepRunning()) {
        cryptoContext->Decrypt(keyPair.secretKey, ciphertext1, &plaintextDec1);
    }
}

BENCHMARK(BEHZ_Decrypt)->Unit(benchmark::kMicrosecond)->Apply(DecBFVArguments);

BENCHMARK_MAIN();
