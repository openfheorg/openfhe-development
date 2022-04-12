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
 * This file benchmarks FHEW-AP gate evaluation operations
 */

#define PROFILE
#include "benchmark/benchmark.h"

#include <fstream>
#include <iostream>
#include <iterator>
#include <limits>
#include <random>

#include "binfhecontext.h"

#include "utils/debug.h"

using namespace std;
using namespace lbcrypto;

/*
 * Context setup utility methods
 */

BinFHEContext GenerateFHEWContext(BINFHEPARAMSET set) {
  auto cc = BinFHEContext();
  cc.GenerateBinFHEContext(set, AP);
  return cc;
}

/*
 * FHEW benchmarks
 */

template <class ParamSet>
void FHEW_NOT(benchmark::State &state, ParamSet param_set) {
  BINFHEPARAMSET param(param_set);
  BinFHEContext cc = GenerateFHEWContext(param);

  LWEPrivateKey sk = cc.KeyGen();

  LWECiphertext ct1 = cc.Encrypt(sk, 1, FRESH);

  for (auto _ : state) {
    LWECiphertext ct11 = cc.EvalNOT(ct1);
  }
}

BENCHMARK_CAPTURE(FHEW_NOT, STD128, STD128)->Unit(benchmark::kMicrosecond);
BENCHMARK_CAPTURE(FHEW_NOT, STD128_AP, STD128_AP)
    ->Unit(benchmark::kMicrosecond);

// benchmark for binary gates, such as AND, OR, NAND, NOR
template <class ParamSet, class BinGate>
void FHEW_BINGATE(benchmark::State &state, ParamSet param_set,
                  BinGate bin_gate) {
  BINGATE gate(bin_gate);
  BINFHEPARAMSET param(param_set);

  BinFHEContext cc = GenerateFHEWContext(param);

  LWEPrivateKey sk = cc.KeyGen();

  cc.BTKeyGen(sk);

  LWECiphertext ct1 = cc.Encrypt(sk, 1);
  LWECiphertext ct2 = cc.Encrypt(sk, 1);

  for (auto _ : state) {
    LWECiphertext ct11 = cc.EvalBinGate(gate, ct1, ct2);
  }
}

BENCHMARK_CAPTURE(FHEW_BINGATE, STD128_OR, STD128, OR)
    ->Unit(benchmark::kMicrosecond)
    ->MinTime(10.0);

BENCHMARK_CAPTURE(FHEW_BINGATE, STD128_AND, STD128, AND)
    ->Unit(benchmark::kMicrosecond);

BENCHMARK_CAPTURE(FHEW_BINGATE, STD128_NOR, STD128, NOR)
    ->Unit(benchmark::kMicrosecond);

BENCHMARK_CAPTURE(FHEW_BINGATE, STD128_NAND, STD128, NAND)
    ->Unit(benchmark::kMicrosecond);

BENCHMARK_CAPTURE(FHEW_BINGATE, STD128_XOR, STD128, XOR)
    ->Unit(benchmark::kMicrosecond);

BENCHMARK_CAPTURE(FHEW_BINGATE, STD128_XNOR, STD128, XNOR)
    ->Unit(benchmark::kMicrosecond);

BENCHMARK_CAPTURE(FHEW_BINGATE, STD128_XOR_FAST, STD128, XOR_FAST)
    ->Unit(benchmark::kMicrosecond);

BENCHMARK_CAPTURE(FHEW_BINGATE, STD128_XNOR_FAST, STD128, XNOR_FAST)
    ->Unit(benchmark::kMicrosecond);

BENCHMARK_CAPTURE(FHEW_BINGATE, STD128_AP_OR, STD128_AP, OR)
    ->Unit(benchmark::kMicrosecond)
    ->MinTime(10.0);

BENCHMARK_CAPTURE(FHEW_BINGATE, STD128_AP_AND, STD128_AP, AND)
    ->Unit(benchmark::kMicrosecond);

BENCHMARK_CAPTURE(FHEW_BINGATE, STD128_AP_NOR, STD128_AP, NOR)
    ->Unit(benchmark::kMicrosecond);

BENCHMARK_CAPTURE(FHEW_BINGATE, STD128_AP_NAND, STD128_AP, NAND)
    ->Unit(benchmark::kMicrosecond);

BENCHMARK_CAPTURE(FHEW_BINGATE, STD128_AP_XOR, STD128_AP, XOR)
    ->Unit(benchmark::kMicrosecond);

BENCHMARK_CAPTURE(FHEW_BINGATE, STD128_AP_XNOR, STD128_AP, XNOR)
    ->Unit(benchmark::kMicrosecond);

BENCHMARK_CAPTURE(FHEW_BINGATE, STD128_AP_XOR_FAST, STD128_AP, XOR_FAST)
    ->Unit(benchmark::kMicrosecond);

BENCHMARK_CAPTURE(FHEW_BINGATE, STD128_AP_XNOR_FAST, STD128_AP, XNOR_FAST)
    ->Unit(benchmark::kMicrosecond);

// benchmark for key switching
template <class ParamSet>
void FHEW_KEYSWITCH(benchmark::State &state, ParamSet param_set) {
  BINFHEPARAMSET param(param_set);
  BinFHEContext cc = GenerateFHEWContext(param);

  LWEPrivateKey sk = cc.KeyGen();
  LWEPrivateKey skN = cc.KeyGenN();

  auto ctQN1 = cc.Encrypt(skN, 1, FRESH);
  auto keySwitchHint = cc.KeySwitchGen(sk, skN);

  for (auto _ : state) {
    std::shared_ptr<LWECiphertextImpl> eQ1 = cc.GetLWEScheme()->KeySwitch(
        cc.GetParams()->GetLWEParams(), keySwitchHint, ctQN1);
  }
}

BENCHMARK_CAPTURE(FHEW_KEYSWITCH, STD128, STD128)
    ->Unit(benchmark::kMicrosecond)
    ->MinTime(1.0);

BENCHMARK_CAPTURE(FHEW_KEYSWITCH, STD128_AP, STD128_AP)
    ->Unit(benchmark::kMicrosecond)
    ->MinTime(1.0);

BENCHMARK_MAIN();
