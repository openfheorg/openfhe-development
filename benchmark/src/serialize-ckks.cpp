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
 * This code benchmarks CKKS serialization.
 */


// #define PROFILE
#define _USE_MATH_DEFINES
#include "benchmark/benchmark.h"

#include <iostream>
#include <fstream>
#include <limits>
#include <iterator>
#include <random>

#include "cryptocontext-ser.h"
#include "ciphertext-ser.h"
#include "scheme/ckksrns/ckksrns-ser.h"
#include "scheme/ckksrns/gen-cryptocontext-ckksrns.h"
#include "gen-cryptocontext.h"

using namespace lbcrypto;

void CKKS_serialize(benchmark::State& state) {
    // create a cryptocontext
    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetRingDim(512);
    parameters.SetMultiplicativeDepth(3);
    parameters.SetScalingModSize(50);
    parameters.SetDigitSize(20);
    parameters.SetSecurityLevel(HEStd_NotSet);

    CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    cc->Enable(MULTIPARTY);

    // DEBUG("step 0");
    {
        std::stringstream s;
        CryptoContext<DCRTPoly> ccNew;
        while (state.KeepRunning()) {
            Serial::Serialize(cc, s, SerType::BINARY);
            Serial::Deserialize(cc, s, SerType::BINARY);
        }
    }

    KeyPair<DCRTPoly> kp = cc->KeyGen();
    KeyPair<DCRTPoly> kpnew;

    // DEBUG("step 1");
    {
        std::stringstream s;
        while (state.KeepRunning()) {
            Serial::Serialize(kp.publicKey, s, SerType::BINARY);
            Serial::Deserialize(kpnew.publicKey, s, SerType::BINARY);
        }
    }

    // DEBUG("step 2");
    {
        std::stringstream s;
        while (state.KeepRunning()) {
            Serial::Serialize(kp.secretKey, s, SerType::BINARY);
            Serial::Deserialize(kpnew.secretKey, s, SerType::BINARY);
        }
    }

    // DEBUG("step 3");
    std::vector<std::complex<double>> vals = {1.0, 3.0, 5.0, 7.0, 9.0, 2.0, 4.0, 6.0, 8.0, 11.0};
    Plaintext plaintextShort               = cc->MakeCKKSPackedPlaintext(vals);
    Plaintext plaintextShortL2D2           = cc->MakeCKKSPackedPlaintext(vals, 2, 2);
    Ciphertext<DCRTPoly> ciphertext        = cc->Encrypt(kp.publicKey, plaintextShort);
    Ciphertext<DCRTPoly> ciphertextL2D2    = cc->Encrypt(kp.publicKey, plaintextShortL2D2);

    Ciphertext<DCRTPoly> newC;
    Ciphertext<DCRTPoly> newCL2D2;
    {
        std::stringstream s;
        std::stringstream s2;
        while (state.KeepRunning()) {
            Serial::Serialize(ciphertext, s, SerType::BINARY);
            Serial::Deserialize(newC, s, SerType::BINARY);
            Serial::Serialize(ciphertextL2D2, s2, SerType::BINARY);
            Serial::Deserialize(newCL2D2, s2, SerType::BINARY);
        }
    }
}

BENCHMARK(CKKS_serialize)->Unit(benchmark::kMicrosecond)->MinTime(10.0);

BENCHMARK_MAIN();
