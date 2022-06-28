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

constexpr usint RING_DIM             = 16384;
constexpr usint MULT_DEPTH           = 7;
constexpr usint PTM                  = 2;
constexpr usint DCRT_BITS            = 60;
constexpr KeySwitchTechnique KS_TECH = BV;

/*
These are the results we obtained for the above parameters immediately after implementing HPSPOVERQLEVELED.
--------------------------------------------------------------------------------------------
Benchmark                                                  Time             CPU   Iterations
--------------------------------------------------------------------------------------------
BFVrns_EvalMultMany/mult_method:1/min_time:10.000       6590 ms         6578 ms            2
BFVrns_EvalMultMany/mult_method:2/min_time:10.000       5140 ms         5132 ms            3
BFVrns_EvalMultMany/mult_method:3/min_time:10.000       3382 ms         3376 ms            4
*/

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
    parameters.SetPlaintextModulus(PTM);
    parameters.SetEvalMultCount(MULT_DEPTH);
    parameters.SetScalingFactorBits(DCRT_BITS);
    parameters.SetKeySwitchTechnique(KS_TECH);
    parameters.SetRingDim(RING_DIM);
    parameters.SetMultiplicationTechnique(multMethod);
    parameters.SetSecurityLevel(HEStd_128_classic);
    parameters.SetMode(OPTIMIZED);
    parameters.SetMaxDepth(2);
    parameters.SetStandardDeviation(3.19);

    CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE);

    return cc;
}

/*
 * benchmarks
 */
void BFVrns_EvalMult(benchmark::State& state) {
    CryptoContext<DCRTPoly> cc = GenerateBFVrnsContext(MULT_METHOD_ARGS[state.range(0) - 1]);

    // KeyGen
    KeyPair<DCRTPoly> keyPair = cc->KeyGen();
    cc->EvalMultKeyGen(keyPair.secretKey);

    std::vector<int64_t> vectorOfInts = {1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

    Plaintext plaintext;
    plaintext = cc->MakeCoefPackedPlaintext(vectorOfInts);

    std::vector<Ciphertext<DCRTPoly>> ciphertexts;
    int treeSize = 1 << MULT_DEPTH;
    
    for (int i = 0; i < treeSize; i++)
        ciphertexts.push_back(cc->Encrypt(keyPair.publicKey, plaintext));

    Ciphertext<DCRTPoly> ciphertextMult;
    while (state.KeepRunning()) {
        ciphertextMult = cc->EvalMultMany(ciphertexts);
    }

    Ciphertext<DCRTPoly> cRes;
    for (usint i = (treeSize >> 1); i >= 1; i >>= 1) {
        for (usint j = 0; j < i; ++j) {
            ciphertexts[j] = cc->EvalMult(ciphertexts[j], ciphertexts[j + i]);
        }
    }

    cRes = ciphertexts[0]->Clone();
    
    Plaintext plaintextDec;
    cc->Decrypt(keyPair.secretKey, cRes, &plaintextDec);
    plaintextDec->SetLength(plaintext->GetLength());

    if (plaintext != plaintextDec) {
        std::cout << "Original plaintext: " << plaintext << std::endl;
        std::cout << "Evaluated plaintext: " << plaintextDec << std::endl;
    }
}
BENCHMARK(BFVrns_EvalMult)->Unit(benchmark::kMillisecond)->Apply(MultBFVArguments);

BENCHMARK_MAIN();
