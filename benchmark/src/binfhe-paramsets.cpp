//==================================================================================
// BSD 2-Clause License
//
// Copyright (c) 2014-2024, NJIT, Duality Technologies Inc. and other contributors
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

#include "benchmark/benchmark.h"
#include "binfhecontext.h"

#include <random>

using namespace lbcrypto;

[[maybe_unused]] static void FHEW_BTKEYGEN(benchmark::State& state, BINFHE_PARAMSET s, BINFHE_METHOD m) {
    auto cc = BinFHEContext();
    cc.GenerateBinFHEContext(s, m);
    for (auto _ : state)
        cc.BTKeyGen(cc.KeyGen());
}

[[maybe_unused]] static void FHEW_ENCRYPT(benchmark::State& state, BINFHE_PARAMSET s, BINFHE_METHOD m) {
    auto cc = BinFHEContext();
    cc.GenerateBinFHEContext(s, m);
    auto sk = cc.KeyGen();
    auto x  = std::bind(std::uniform_int_distribution<LWEPlaintext>(0, 1), std::default_random_engine());
    for (auto _ : state)
        auto ct = cc.Encrypt(sk, x());
}

[[maybe_unused]] static void FHEW_NOT(benchmark::State& state, BINFHE_PARAMSET s, BINFHE_METHOD m) {
    auto cc = BinFHEContext();
    cc.GenerateBinFHEContext(s, m);
    auto sk = cc.KeyGen();
    auto x  = std::bind(std::uniform_int_distribution<LWEPlaintext>(0, 1), std::default_random_engine());
    for (auto _ : state)
        auto ct = cc.EvalNOT(cc.Encrypt(sk, x()));
}

[[maybe_unused]] static void FHEW_BINGATE2(benchmark::State& state, BINFHE_PARAMSET s, BINFHE_METHOD m, BINGATE g) {
    auto cc = BinFHEContext();
    cc.GenerateBinFHEContext(s, m);
    auto sk = cc.KeyGen();
    cc.BTKeyGen(sk);
    auto x = std::bind(std::uniform_int_distribution<LWEPlaintext>(0, 1), std::default_random_engine());
    for (auto _ : state)
        auto ct = cc.EvalBinGate(g, cc.Encrypt(sk, x(), SMALL_DIM, 4), cc.Encrypt(sk, x(), SMALL_DIM, 4));
}

[[maybe_unused]] static void FHEW_BINGATE3(benchmark::State& state, BINFHE_PARAMSET s, BINFHE_METHOD m, BINGATE g) {
    auto cc = BinFHEContext();
    cc.GenerateBinFHEContext(s, m);
    auto sk = cc.KeyGen();
    cc.BTKeyGen(sk);
    auto x = std::bind(std::uniform_int_distribution<LWEPlaintext>(0, 1), std::default_random_engine());
    for (auto _ : state)
        auto ct = cc.EvalBinGate(
            g, std::vector<LWECiphertext>{cc.Encrypt(sk, x(), SMALL_DIM, 6), cc.Encrypt(sk, x(), SMALL_DIM, 6),
                                          cc.Encrypt(sk, x(), SMALL_DIM, 6)});
}

[[maybe_unused]] static void FHEW_BINGATE4(benchmark::State& state, BINFHE_PARAMSET s, BINFHE_METHOD m, BINGATE g) {
    auto cc = BinFHEContext();
    cc.GenerateBinFHEContext(s, m);
    auto sk = cc.KeyGen();
    cc.BTKeyGen(sk);
    auto x = std::bind(std::uniform_int_distribution<LWEPlaintext>(0, 1), std::default_random_engine());
    for (auto _ : state)
        auto ct = cc.EvalBinGate(
            g, std::vector<LWECiphertext>{cc.Encrypt(sk, x(), SMALL_DIM, 8), cc.Encrypt(sk, x(), SMALL_DIM, 8),
                                          cc.Encrypt(sk, x(), SMALL_DIM, 8), cc.Encrypt(sk, x(), SMALL_DIM, 8)});
}

// clang-format off
BENCHMARK_CAPTURE(FHEW_BINGATE2, TOY_2_GINX_OR, TOY, GINX, OR)->Unit(benchmark::kMillisecond);
BENCHMARK_CAPTURE(FHEW_BINGATE2, MEDIUM_2_GINX_OR, MEDIUM, GINX, OR)->Unit(benchmark::kMillisecond);
BENCHMARK_CAPTURE(FHEW_BINGATE2, STD128_2_AP_OR, STD128_AP, AP, OR)->Unit(benchmark::kMillisecond);
BENCHMARK_CAPTURE(FHEW_BINGATE2, STD128_2_GINX_OR, STD128, GINX, OR)->Unit(benchmark::kMillisecond);
BENCHMARK_CAPTURE(FHEW_BINGATE3, STD128_3_GINX_OR, STD128_3, GINX, OR3)->Unit(benchmark::kMillisecond);
BENCHMARK_CAPTURE(FHEW_BINGATE4, STD128_4_GINX_OR, STD128_4, GINX, OR4)->Unit(benchmark::kMillisecond);
BENCHMARK_CAPTURE(FHEW_BINGATE2, STD128Q_2_GINX_OR, STD128Q, GINX, OR)->Unit(benchmark::kMillisecond);
#if NATIVEINT >= 64
BENCHMARK_CAPTURE(FHEW_BINGATE3, STD128Q_3_GINX_OR, STD128Q_3, GINX, OR3)->Unit(benchmark::kMillisecond);
BENCHMARK_CAPTURE(FHEW_BINGATE4, STD128Q_4_GINX_OR, STD128Q_4, GINX, OR4)->Unit(benchmark::kMillisecond);
BENCHMARK_CAPTURE(FHEW_BINGATE2, STD192_2_GINX_OR, STD192, GINX, OR)->Unit(benchmark::kMillisecond);
BENCHMARK_CAPTURE(FHEW_BINGATE3, STD192_3_GINX_OR, STD192_3, GINX, OR3)->Unit(benchmark::kMillisecond);
BENCHMARK_CAPTURE(FHEW_BINGATE4, STD192_4_GINX_OR, STD192_4, GINX, OR4)->Unit(benchmark::kMillisecond);
BENCHMARK_CAPTURE(FHEW_BINGATE2, STD192Q_2_GINX_OR, STD192Q, GINX, OR)->Unit(benchmark::kMillisecond);
BENCHMARK_CAPTURE(FHEW_BINGATE3, STD192Q_3_GINX_OR, STD192Q_3, GINX, OR3)->Unit(benchmark::kMillisecond);
BENCHMARK_CAPTURE(FHEW_BINGATE4, STD192Q_4_GINX_OR, STD192Q_4, GINX, OR4)->Unit(benchmark::kMillisecond);
BENCHMARK_CAPTURE(FHEW_BINGATE2, STD256_2_GINX_OR, STD256, GINX, OR)->Unit(benchmark::kMillisecond);
BENCHMARK_CAPTURE(FHEW_BINGATE3, STD256_3_GINX_OR, STD256_3, GINX, OR3)->Unit(benchmark::kMillisecond);
BENCHMARK_CAPTURE(FHEW_BINGATE4, STD256_4_GINX_OR, STD256_4, GINX, OR4)->Unit(benchmark::kMillisecond);
#endif
BENCHMARK_CAPTURE(FHEW_BINGATE2, STD256Q_2_GINX_OR, STD256Q, GINX, OR)->Unit(benchmark::kMillisecond);
BENCHMARK_CAPTURE(FHEW_BINGATE3, STD256Q_3_GINX_OR, STD256Q_3, GINX, OR3)->Unit(benchmark::kMillisecond);
BENCHMARK_CAPTURE(FHEW_BINGATE4, STD256Q_4_GINX_OR, STD256Q_4, GINX, OR4)->Unit(benchmark::kMillisecond);
BENCHMARK_CAPTURE(FHEW_BINGATE2, STD128_2_LMKCDEY_OR, STD128_LMKCDEY, LMKCDEY, OR)->Unit(benchmark::kMillisecond);
BENCHMARK_CAPTURE(FHEW_BINGATE3, STD128_3_LMKCDEY_OR, STD128_3_LMKCDEY, LMKCDEY, OR3)->Unit(benchmark::kMillisecond);
BENCHMARK_CAPTURE(FHEW_BINGATE4, STD128_4_LMKCDEY_OR, STD128_4_LMKCDEY, LMKCDEY, OR4)->Unit(benchmark::kMillisecond);
BENCHMARK_CAPTURE(FHEW_BINGATE2, STD128Q_2_LMKCDEY_OR, STD128Q_LMKCDEY, LMKCDEY, OR)->Unit(benchmark::kMillisecond);
BENCHMARK_CAPTURE(FHEW_BINGATE3, STD128Q_3_LMKCDEY_OR, STD128Q_3_LMKCDEY, LMKCDEY, OR3)->Unit(benchmark::kMillisecond);
#if NATIVEINT >= 64
BENCHMARK_CAPTURE(FHEW_BINGATE4, STD128Q_4_LMKCDEY_OR, STD128Q_4_LMKCDEY, LMKCDEY, OR4)->Unit(benchmark::kMillisecond);
BENCHMARK_CAPTURE(FHEW_BINGATE2, STD192_2_LMKCDEY_OR, STD192_LMKCDEY, LMKCDEY, OR)->Unit(benchmark::kMillisecond);
BENCHMARK_CAPTURE(FHEW_BINGATE3, STD192_3_LMKCDEY_OR, STD192_3_LMKCDEY, LMKCDEY, OR3)->Unit(benchmark::kMillisecond);
BENCHMARK_CAPTURE(FHEW_BINGATE4, STD192_4_LMKCDEY_OR, STD192_4_LMKCDEY, LMKCDEY, OR4)->Unit(benchmark::kMillisecond);
BENCHMARK_CAPTURE(FHEW_BINGATE2, STD192Q_2_LMKCDEY_OR, STD192Q_LMKCDEY, LMKCDEY, OR)->Unit(benchmark::kMillisecond);
BENCHMARK_CAPTURE(FHEW_BINGATE3, STD192Q_3_LMKCDEY_OR, STD192Q_3_LMKCDEY, LMKCDEY, OR3)->Unit(benchmark::kMillisecond);
BENCHMARK_CAPTURE(FHEW_BINGATE4, STD192Q_4_LMKCDEY_OR, STD192Q_4_LMKCDEY, LMKCDEY, OR4)->Unit(benchmark::kMillisecond);
BENCHMARK_CAPTURE(FHEW_BINGATE2, STD256_2_LMKCDEY_OR, STD256_LMKCDEY, LMKCDEY, OR)->Unit(benchmark::kMillisecond);
BENCHMARK_CAPTURE(FHEW_BINGATE3, STD256_3_LMKCDEY_OR, STD256_3_LMKCDEY, LMKCDEY, OR3)->Unit(benchmark::kMillisecond);
BENCHMARK_CAPTURE(FHEW_BINGATE4, STD256_4_LMKCDEY_OR, STD256_4_LMKCDEY, LMKCDEY, OR4)->Unit(benchmark::kMillisecond);
BENCHMARK_CAPTURE(FHEW_BINGATE2, STD256Q_2_LMKCDEY_OR, STD256Q_LMKCDEY, LMKCDEY, OR)->Unit(benchmark::kMillisecond);
BENCHMARK_CAPTURE(FHEW_BINGATE3, STD256Q_3_LMKCDEY_OR, STD256Q_3_LMKCDEY, LMKCDEY, OR3)->Unit(benchmark::kMillisecond);
BENCHMARK_CAPTURE(FHEW_BINGATE4, STD256Q_4_LMKCDEY_OR, STD256Q_4_LMKCDEY, LMKCDEY, OR4)->Unit(benchmark::kMillisecond);
#endif
BENCHMARK_CAPTURE(FHEW_BINGATE2, LPF_STD128_2_GINX_OR, LPF_STD128, GINX, OR)->Unit(benchmark::kMillisecond);
BENCHMARK_CAPTURE(FHEW_BINGATE2, LPF_STD128Q_2_GINX_OR, LPF_STD128Q, GINX, OR)->Unit(benchmark::kMillisecond);
BENCHMARK_CAPTURE(FHEW_BINGATE2, LPF_STD128_2_LMKCDEY_OR, LPF_STD128_LMKCDEY, LMKCDEY, OR)->Unit(benchmark::kMillisecond);
BENCHMARK_CAPTURE(FHEW_BINGATE2, LPF_STD128Q_2_LMKCDEY_OR, LPF_STD128Q_LMKCDEY, LMKCDEY, OR)->Unit(benchmark::kMillisecond);
// clang-format on

BENCHMARK_MAIN();
