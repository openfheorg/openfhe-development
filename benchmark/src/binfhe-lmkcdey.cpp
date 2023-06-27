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
 * This file benchmarks FHEW-GINX gate evaluation operations
 */

#include "benchmark/benchmark.h"
#include "binfhecontext.h"

using namespace lbcrypto;

/*
 * Context setup utility methods
 */

BinFHEContext GenerateFHEWContext(BINFHE_PARAMSET set) {
    auto cc = BinFHEContext();
    cc.GenerateBinFHEContext(set, LMKCDEY);
    return cc;
}

/*
 * FHEW benchmarks
 */

template <class ParamSet>
void FHEW_BTKEYGEN(benchmark::State& state, ParamSet param_set) {
    BINFHE_PARAMSET param(param_set);
    BinFHEContext cc = GenerateFHEWContext(param);

    for (auto _ : state) {
        LWEPrivateKey sk = cc.KeyGen();
        cc.BTKeyGen(sk);
    }
}

BENCHMARK_CAPTURE(FHEW_BTKEYGEN, MEDIUM, MEDIUM)->Unit(benchmark::kMicrosecond);
BENCHMARK_CAPTURE(FHEW_BTKEYGEN, STD128_LMKCDEY, STD128_LMKCDEY)->Unit(benchmark::kMicrosecond);

template <class ParamSet>
void FHEW_ENCRYPT(benchmark::State& state, ParamSet param_set) {
    BINFHE_PARAMSET param(param_set);
    BinFHEContext cc = GenerateFHEWContext(param);

    LWEPrivateKey sk = cc.KeyGen();
    for (auto _ : state) {
        LWECiphertext ct1 = cc.Encrypt(sk, 1, FRESH);
    }
}

BENCHMARK_CAPTURE(FHEW_ENCRYPT, MEDIUM, MEDIUM)->Unit(benchmark::kMicrosecond);
BENCHMARK_CAPTURE(FHEW_ENCRYPT, STD128_LMKCDEY, STD128_LMKCDEY)->Unit(benchmark::kMicrosecond);

template <class ParamSet>
void FHEW_NOT(benchmark::State& state, ParamSet param_set) {
    BINFHE_PARAMSET param(param_set);
    BinFHEContext cc = GenerateFHEWContext(param);

    LWEPrivateKey sk = cc.KeyGen();

    LWECiphertext ct1 = cc.Encrypt(sk, 1, FRESH);

    for (auto _ : state) {
        LWECiphertext ct11 = cc.EvalNOT(ct1);
    }
}

BENCHMARK_CAPTURE(FHEW_NOT, MEDIUM, MEDIUM)->Unit(benchmark::kMicrosecond);
BENCHMARK_CAPTURE(FHEW_NOT, STD128_LMKCDEY, STD128_LMKCDEY)->Unit(benchmark::kMicrosecond);

// benchmark for binary gates, such as AND, OR, NAND, NOR
template <class ParamSet, class BinGate>
void FHEW_BINGATE(benchmark::State& state, ParamSet param_set, BinGate bin_gate) {
    BINGATE gate(bin_gate);
    BINFHE_PARAMSET param(param_set);

    BinFHEContext cc = GenerateFHEWContext(param);

    LWEPrivateKey sk = cc.KeyGen();

    cc.BTKeyGen(sk);

    LWECiphertext ct1 = cc.Encrypt(sk, 1);
    LWECiphertext ct2 = cc.Encrypt(sk, 1);

    for (auto _ : state) {
        LWECiphertext ct11 = cc.EvalBinGate(gate, ct1, ct2);
    }
}

BENCHMARK_CAPTURE(FHEW_BINGATE, MEDIUM_OR, MEDIUM, OR)->Unit(benchmark::kMicrosecond)->MinTime(10.0);

BENCHMARK_CAPTURE(FHEW_BINGATE, MEDIUM_AND, MEDIUM, AND)->Unit(benchmark::kMicrosecond);

BENCHMARK_CAPTURE(FHEW_BINGATE, MEDIUM_NOR, MEDIUM, NOR)->Unit(benchmark::kMicrosecond);

BENCHMARK_CAPTURE(FHEW_BINGATE, MEDIUM_NAND, MEDIUM, NAND)->Unit(benchmark::kMicrosecond);

BENCHMARK_CAPTURE(FHEW_BINGATE, MEDIUM_XOR, MEDIUM, XOR)->Unit(benchmark::kMicrosecond);

BENCHMARK_CAPTURE(FHEW_BINGATE, MEDIUM_XNOR, MEDIUM, XNOR)->Unit(benchmark::kMicrosecond);

BENCHMARK_CAPTURE(FHEW_BINGATE, MEDIUM_XOR_FAST, MEDIUM, XOR_FAST)->Unit(benchmark::kMicrosecond);

BENCHMARK_CAPTURE(FHEW_BINGATE, MEDIUM_XNOR_FAST, MEDIUM, XNOR_FAST)->Unit(benchmark::kMicrosecond);

BENCHMARK_CAPTURE(FHEW_BINGATE, STD128_LMKCDEY_OR, STD128_LMKCDEY, OR)->Unit(benchmark::kMicrosecond)->MinTime(10.0);

BENCHMARK_CAPTURE(FHEW_BINGATE, STD128_LMKCDEY_AND, STD128_LMKCDEY, AND)->Unit(benchmark::kMicrosecond);

BENCHMARK_CAPTURE(FHEW_BINGATE, STD128_LMKCDEY_NOR, STD128_LMKCDEY, NOR)->Unit(benchmark::kMicrosecond);

BENCHMARK_CAPTURE(FHEW_BINGATE, STD128_LMKCDEY_NAND, STD128_LMKCDEY, NAND)->Unit(benchmark::kMicrosecond);

BENCHMARK_CAPTURE(FHEW_BINGATE, STD128_LMKCDEY_XOR, STD128_LMKCDEY, XOR)->Unit(benchmark::kMicrosecond);

BENCHMARK_CAPTURE(FHEW_BINGATE, STD128_LMKCDEY_XNOR, STD128_LMKCDEY, XNOR)->Unit(benchmark::kMicrosecond);

BENCHMARK_CAPTURE(FHEW_BINGATE, STD128_LMKCDEY_XOR_FAST, STD128_LMKCDEY, XOR_FAST)->Unit(benchmark::kMicrosecond);

BENCHMARK_CAPTURE(FHEW_BINGATE, STD128_LMKCDEY_XNOR_FAST, STD128_LMKCDEY, XNOR_FAST)->Unit(benchmark::kMicrosecond);

// benchmark for key switching
template <class ParamSet>
void FHEW_KEYSWITCH(benchmark::State& state, ParamSet param_set) {
    BINFHE_PARAMSET param(param_set);
    BinFHEContext cc = GenerateFHEWContext(param);

    LWEPrivateKey sk  = cc.KeyGen();
    LWEPrivateKey skN = cc.KeyGenN();

    auto ctQN1         = cc.Encrypt(skN, 1, FRESH);
    auto keySwitchHint = cc.KeySwitchGen(sk, skN);

    for (auto _ : state) {
        LWECiphertext eQ1 = cc.GetLWEScheme()->KeySwitch(cc.GetParams()->GetLWEParams(), keySwitchHint, ctQN1);
    }
}

BENCHMARK_CAPTURE(FHEW_KEYSWITCH, MEDIUM, MEDIUM)->Unit(benchmark::kMicrosecond)->MinTime(1.0);
BENCHMARK_CAPTURE(FHEW_KEYSWITCH, STD128_LMKCDEY, STD128_LMKCDEY)->Unit(benchmark::kMicrosecond)->MinTime(1.0);

BENCHMARK_MAIN();
