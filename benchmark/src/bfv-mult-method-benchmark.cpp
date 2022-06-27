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
 * This file benchmarks a small number of operations in order to exercise large
 * pieces of the library
 */

#define PROFILE
#define _USE_MATH_DEFINES
#include "benchmark/benchmark.h"

#include <iostream>
#include <fstream>
#include <limits>
#include <iterator>
#include <random>

#include "openfhe.h"

#include "scheme/bfvrns/cryptocontext-bfvrns.h"
#include "gen-cryptocontext.h"

#include "utils/debug.h"

using namespace lbcrypto;

constexpr usint RING_DIM             = 1 << 15;
constexpr usint MULT_DEPTH           = 3;
constexpr usint PTM                  = 65537;
constexpr usint DCRT_BITS            = 60;
constexpr KeySwitchTechnique KS_TECH = HYBRID;
constexpr usint RELIN                = 3;

static std::vector<MultiplicationTechnique> MULT_METHOD_ARGS = {HPS, HPSPOVERQ, HPSPOVERQLEVELED};

static void MultBFVArguments(benchmark::internal::Benchmark* b) {
    for (MultiplicationTechnique multMethod : MULT_METHOD_ARGS) {
        b->ArgNames({"mult_method"})->Args({multMethod})->MinTime(10);
    }
}

/*
 * Context setup utility methods
 */

CryptoContext<DCRTPoly> GenerateBFVrnsContext(MultiplicationTechnique multMethod) {
    CCParams<CryptoContextBFVRNS> parameters;
    parameters.SetRingDim(RING_DIM);
    parameters.SetPlaintextModulus(PTM);
    parameters.SetEvalMultCount(MULT_DEPTH);
    parameters.SetScalingFactorBits(DCRT_BITS);
    parameters.SetKeySwitchTechnique(KS_TECH);
    parameters.SetRelinWindow(RELIN);
    parameters.SetMultiplicationTechnique(multMethod);
    parameters.SetSecurityLevel(HEStd_NotSet);

    CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE);

    // std::cout << "\nParameters BFVrns for depth " << mult_depth << std::endl;
    // std::cout << "p = " << cc->GetCryptoParameters()->GetPlaintextModulus() <<
    // std::endl; std::cout << "n = " <<
    // cc->GetCryptoParameters()->GetElementParams()->GetCyclotomicOrder() / 2 <<
    // std::endl; std::cout << "log2 q = " <<
    // log2(cc->GetCryptoParameters()->GetElementParams()->GetModulus().ConvertToDouble())
    // << "\n" << std::endl;

    return cc;
}

/*
 * benchmarks
 */
void BFVrns_EvalMultMany(benchmark::State& state) {
    CryptoContext<DCRTPoly> cc = GenerateBFVrnsContext(MULT_METHOD_ARGS[state.range(0) - 1]);

    // KeyGen
    KeyPair<DCRTPoly> keyPair = cc->KeyGen();
    cc->EvalMultKeyGen(keyPair.secretKey);

    std::vector<int64_t> vectorOfInts = {1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

    Plaintext plaintext;
    plaintext = cc->MakeCoefPackedPlaintext(vectorOfInts);

    std::vector<Ciphertext<DCRTPoly>> ciphertexts;
    for (int i = 0; i < (1 << MULT_DEPTH); i++)
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

BENCHMARK(BFVrns_EvalMultMany)->Unit(benchmark::kMillisecond)->Apply(MultBFVArguments);

BENCHMARK_MAIN();
