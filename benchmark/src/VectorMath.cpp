//==================================================================================
// BSD 2-Clause License
//
// Copyright (c) 2014-2023, NJIT, Duality Technologies Inc. and other contributors
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
  This code benchmarks vector operations.
 */

#define _USE_MATH_DEFINES

#include "benchmark/benchmark.h"
#include "math/discreteuniformgenerator.h"
#include "math/hal/basicint.h"
#include "math/math-hal.h"
#include "math/nbtheory.h"

#include <iostream>

using namespace lbcrypto;

template <typename V>
static void add_BigVec(const V& a, const V& b) {
    V c = a + b;
}

template <typename V>
static void BM_BigVec_Add(benchmark::State& state) {
    auto p = state.range(0);
    auto q = LastPrime<typename V::Integer>(MAX_MODULUS_SIZE, p);
    V a    = DiscreteUniformGeneratorImpl<V>().GenerateVector(p, q);
    V b    = DiscreteUniformGeneratorImpl<V>().GenerateVector(p, q);
    while (state.KeepRunning()) {
        add_BigVec<V>(a, b);
    }
}

template <typename V>
static void addeq_BigVec(V& a, const V& b) {
    a += b;
}

template <typename V>
static void BM_BigVec_Addeq(benchmark::State& state) {
    auto p = state.range(0);
    auto q = LastPrime<typename V::Integer>(MAX_MODULUS_SIZE, p);
    V a    = DiscreteUniformGeneratorImpl<V>().GenerateVector(p, q);
    V b    = DiscreteUniformGeneratorImpl<V>().GenerateVector(p, q);
    while (state.KeepRunning()) {
        addeq_BigVec<V>(a, b);
    }
}

template <typename V>
static void mult_BigVec(const V& a, const V& b) {
    V c = a * b;
}

template <typename V>
static void BM_BigVec_Mult(benchmark::State& state) {
    auto p = state.range(0);
    auto q = LastPrime<typename V::Integer>(MAX_MODULUS_SIZE, p);
    V a    = DiscreteUniformGeneratorImpl<V>().GenerateVector(p, q);
    V b    = DiscreteUniformGeneratorImpl<V>().GenerateVector(p, q);
    while (state.KeepRunning()) {
        mult_BigVec<V>(a, b);
    }
}

template <typename V>
static void multeq_BigVec(V& a, const V& b) {
    a *= b;
}

template <typename V>
static void BM_BigVec_Multeq(benchmark::State& state) {
    auto p = state.range(0);
    auto q = LastPrime<typename V::Integer>(MAX_MODULUS_SIZE, p);
    V a    = DiscreteUniformGeneratorImpl<V>().GenerateVector(p, q);
    V b    = DiscreteUniformGeneratorImpl<V>().GenerateVector(p, q);
    while (state.KeepRunning()) {
        multeq_BigVec<V>(a, b);
    }
}

#define DO_VECTOR_BENCHMARK(X, Y)                                                               \
    BENCHMARK_TEMPLATE(X, Y)->Unit(benchmark::kMicrosecond)->ArgName("parm_16")->Arg(16);       \
    BENCHMARK_TEMPLATE(X, Y)->Unit(benchmark::kMicrosecond)->ArgName("parm_1024")->Arg(1024);   \
    BENCHMARK_TEMPLATE(X, Y)->Unit(benchmark::kMicrosecond)->ArgName("parm_2048")->Arg(2048);   \
    BENCHMARK_TEMPLATE(X, Y)->Unit(benchmark::kMicrosecond)->ArgName("parm_4096")->Arg(4096);   \
    BENCHMARK_TEMPLATE(X, Y)->Unit(benchmark::kMicrosecond)->ArgName("parm_8192")->Arg(8192);   \
    BENCHMARK_TEMPLATE(X, Y)->Unit(benchmark::kMicrosecond)->ArgName("parm_16384")->Arg(16384); \
    BENCHMARK_TEMPLATE(X, Y)->Unit(benchmark::kMicrosecond)->ArgName("parm_32768")->Arg(32768);

DO_VECTOR_BENCHMARK(BM_BigVec_Add, NativeVector)
DO_VECTOR_BENCHMARK(BM_BigVec_Addeq, NativeVector)
DO_VECTOR_BENCHMARK(BM_BigVec_Mult, NativeVector)
DO_VECTOR_BENCHMARK(BM_BigVec_Multeq, NativeVector)

#ifdef WITH_BE2
DO_VECTOR_BENCHMARK(BM_BigVec_Add, M2Vector)
DO_VECTOR_BENCHMARK(BM_BigVec_Addeq, M2Vector)
DO_VECTOR_BENCHMARK(BM_BigVec_Mult, M2Vector)
DO_VECTOR_BENCHMARK(BM_BigVec_Multeq, M2Vector)
#endif

#ifdef WITH_BE4
DO_VECTOR_BENCHMARK(BM_BigVec_Add, M4Vector)
DO_VECTOR_BENCHMARK(BM_BigVec_Addeq, M4Vector)
DO_VECTOR_BENCHMARK(BM_BigVec_Mult, M4Vector)
DO_VECTOR_BENCHMARK(BM_BigVec_Multeq, M4Vector)
#endif

#ifdef WITH_NTL
DO_VECTOR_BENCHMARK(BM_BigVec_Add, M6Vector)
DO_VECTOR_BENCHMARK(BM_BigVec_Addeq, M6Vector)
DO_VECTOR_BENCHMARK(BM_BigVec_Mult, M6Vector)
DO_VECTOR_BENCHMARK(BM_BigVec_Multeq, M6Vector)
#endif

// execute the benchmarks
BENCHMARK_MAIN();
