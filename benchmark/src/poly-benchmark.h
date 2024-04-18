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

#ifndef LBCRYPTO_BENCHMARK_SRC_POLY_BENCMARK_H
#define LBCRYPTO_BENCHMARK_SRC_POLY_BENCMARK_H

#define _USE_MATH_DEFINES

#include "benchmark/benchmark.h"
#include "lattice/lat-hal.h"
#include "math/discreteuniformgenerator.h"

#include <map>
#include <memory>
#include <utility>
#include <vector>

using namespace lbcrypto;

constexpr size_t POLY_NUM    = 16;
constexpr size_t POLY_NUM_M1 = (POLY_NUM - 1);

std::vector<uint32_t> tow_args({1, 2, 4, 8, 16});
std::shared_ptr<std::vector<NativePoly>> NativepolysEval;
std::shared_ptr<std::vector<NativePoly>> NativepolysCoef;
std::map<uint32_t, std::shared_ptr<std::vector<DCRTPoly>>> DCRTpolysEval;
std::map<uint32_t, std::shared_ptr<std::vector<DCRTPoly>>> DCRTpolysCoef;

static void DCRTArguments(benchmark::internal::Benchmark* b) {
    for (uint32_t t : tow_args) {
        b->ArgName("towers")->Arg(t);
    }
}

static void GeneratePolys(uint32_t order, uint32_t bits, std::shared_ptr<std::vector<NativePoly>>& polyArrayEval,
                          std::shared_ptr<std::vector<NativePoly>>& polyArrayCoef) {
    auto p    = std::make_shared<ILNativeParams>(order, bits);
    auto eval = std::make_shared<std::vector<NativePoly>>();
    auto coef = std::make_shared<std::vector<NativePoly>>();
    eval->reserve(POLY_NUM);
    coef->reserve(POLY_NUM);
    DiscreteUniformGeneratorImpl<NativeVector> dug;
    for (size_t i = 0; i < POLY_NUM; ++i) {
        eval->emplace_back(dug, p, Format::EVALUATION);
        coef->emplace_back(dug, p, Format::COEFFICIENT);
    }
    polyArrayEval = std::move(eval);
    polyArrayCoef = std::move(coef);
}

static void GenerateDCRTPolys(uint32_t order, uint32_t bits,
                              std::map<uint32_t, std::shared_ptr<std::vector<DCRTPoly>>>& polyArrayEval,
                              std::map<uint32_t, std::shared_ptr<std::vector<DCRTPoly>>>& polyArrayCoef) {
    polyArrayEval.clear();
    polyArrayCoef.clear();
    DiscreteUniformGeneratorImpl<NativeVector> dug;
    for (uint32_t t : tow_args) {
        auto p    = std::make_shared<ILDCRTParams<BigInteger>>(order, t, bits);
        auto eval = std::make_shared<std::vector<DCRTPoly>>();
        auto coef = std::make_shared<std::vector<DCRTPoly>>();
        eval->reserve(POLY_NUM);
        coef->reserve(POLY_NUM);
        for (size_t i = 0; i < POLY_NUM; ++i) {
            eval->emplace_back(dug, p, Format::EVALUATION);
            coef->emplace_back(dug, p, Format::COEFFICIENT);
        }
        polyArrayEval[t] = std::move(eval);
        polyArrayCoef[t] = std::move(coef);
    }
}

// ************************************************************************************

[[maybe_unused]] static void Native_Add(benchmark::State& state) {
    std::shared_ptr<std::vector<NativePoly>> polys = NativepolysEval;
    NativePoly p;
    size_t i{0}, j{0};
    while (state.KeepRunning()) {
        i = j;
        p = (*polys)[i] + (*polys)[(j = (i + 1) & POLY_NUM_M1)];
    }
}

[[maybe_unused]] static void DCRT_Add(benchmark::State& state) {
    std::shared_ptr<std::vector<DCRTPoly>> polys = DCRTpolysEval[state.range(0)];
    DCRTPoly p;
    size_t i{0}, j{0};
    while (state.KeepRunning()) {
        i = j;
        p = (*polys)[i] + (*polys)[(j = (i + 1) & POLY_NUM_M1)];
    }
}

[[maybe_unused]] static void Native_AddEq(benchmark::State& state) {
    std::shared_ptr<std::vector<NativePoly>> polys = NativepolysEval;
    NativePoly p{(*polys)[0]};
    size_t i{0};
    while (state.KeepRunning()) {
        p += (*polys)[(i = (i + 1) & POLY_NUM_M1)];
    }
}

[[maybe_unused]] static void DCRT_AddEq(benchmark::State& state) {
    std::shared_ptr<std::vector<DCRTPoly>> polys = DCRTpolysEval[state.range(0)];
    DCRTPoly p{(*polys)[0]};
    size_t i{0};
    while (state.KeepRunning()) {
        p += (*polys)[(i = (i + 1) & POLY_NUM_M1)];
    }
}

// ************************************************************************************

[[maybe_unused]] static void Native_Sub(benchmark::State& state) {
    std::shared_ptr<std::vector<NativePoly>> polys = NativepolysEval;
    NativePoly p;
    size_t i{0}, j{0};
    while (state.KeepRunning()) {
        i = j;
        p = (*polys)[i] - (*polys)[(j = (i + 1) & POLY_NUM_M1)];
    }
}

[[maybe_unused]] static void DCRT_Sub(benchmark::State& state) {
    std::shared_ptr<std::vector<DCRTPoly>> polys = DCRTpolysEval[state.range(0)];
    DCRTPoly p;
    size_t i{0}, j{0};
    while (state.KeepRunning()) {
        i = j;
        p = (*polys)[i] - (*polys)[(j = (i + 1) & POLY_NUM_M1)];
    }
}

[[maybe_unused]] static void Native_SubEq(benchmark::State& state) {
    std::shared_ptr<std::vector<NativePoly>> polys = NativepolysEval;
    NativePoly p{(*polys)[0]};
    size_t i{0};
    while (state.KeepRunning()) {
        p -= (*polys)[(i = (i + 1) & POLY_NUM_M1)];
    }
}

[[maybe_unused]] static void DCRT_SubEq(benchmark::State& state) {
    std::shared_ptr<std::vector<DCRTPoly>> polys = DCRTpolysEval[state.range(0)];
    DCRTPoly p{(*polys)[0]};
    size_t i{0};
    while (state.KeepRunning()) {
        p -= (*polys)[(i = (i + 1) & POLY_NUM_M1)];
    }
}

// ************************************************************************************

[[maybe_unused]] static void Native_Mul(benchmark::State& state) {
    std::shared_ptr<std::vector<NativePoly>> polys = NativepolysEval;
    NativePoly p;
    size_t i{0}, j{0};
    while (state.KeepRunning()) {
        i = j;
        p = (*polys)[i] * (*polys)[(j = (i + 1) & POLY_NUM_M1)];
    }
}

[[maybe_unused]] static void DCRT_Mul(benchmark::State& state) {
    std::shared_ptr<std::vector<DCRTPoly>> polys = DCRTpolysEval[state.range(0)];
    DCRTPoly p;
    size_t i{0}, j{0};
    while (state.KeepRunning()) {
        i = j;
        p = (*polys)[i] * (*polys)[(j = (i + 1) & POLY_NUM_M1)];
    }
}

[[maybe_unused]] static void Native_MulEq(benchmark::State& state) {
    std::shared_ptr<std::vector<NativePoly>> polys = NativepolysEval;
    NativePoly p{(*polys)[0]};
    size_t i{0};
    while (state.KeepRunning()) {
        p *= (*polys)[(i = (i + 1) & POLY_NUM_M1)];
    }
}

[[maybe_unused]] static void DCRT_MulEq(benchmark::State& state) {
    std::shared_ptr<std::vector<DCRTPoly>> polys = DCRTpolysEval[state.range(0)];
    DCRTPoly p{(*polys)[0]};
    size_t i{0};
    while (state.KeepRunning()) {
        p *= (*polys)[(i = (i + 1) & POLY_NUM_M1)];
    }
}

// ************************************************************************************

[[maybe_unused]] static void Native_ntt(benchmark::State& state) {
    std::shared_ptr<std::vector<NativePoly>> polys = NativepolysCoef;
    NativePoly p;
    size_t i{POLY_NUM_M1};
    while (state.KeepRunning()) {
        p = (*polys)[(i = (i + 1) & POLY_NUM_M1)];
        p.SwitchFormat();
    }
}

[[maybe_unused]] static void DCRT_ntt(benchmark::State& state) {
    std::shared_ptr<std::vector<DCRTPoly>> polys = DCRTpolysCoef[state.range(0)];
    DCRTPoly p;
    size_t i{POLY_NUM_M1};
    while (state.KeepRunning()) {
        p = (*polys)[(i = (i + 1) & POLY_NUM_M1)];
        p.SwitchFormat();
    }
}

[[maybe_unused]] static void Native_intt(benchmark::State& state) {
    std::shared_ptr<std::vector<NativePoly>> polys = NativepolysEval;
    NativePoly p;
    size_t i{POLY_NUM_M1};
    while (state.KeepRunning()) {
        p = (*polys)[(i = (i + 1) & POLY_NUM_M1)];
        p.SwitchFormat();
    }
}

[[maybe_unused]] static void DCRT_intt(benchmark::State& state) {
    std::shared_ptr<std::vector<DCRTPoly>> polys = DCRTpolysEval[state.range(0)];
    DCRTPoly p;
    size_t i{POLY_NUM_M1};
    while (state.KeepRunning()) {
        p = (*polys)[(i = (i + 1) & POLY_NUM_M1)];
        p.SwitchFormat();
    }
}

[[maybe_unused]] static void Native_ntt_intt(benchmark::State& state) {
    std::shared_ptr<std::vector<NativePoly>> polys = NativepolysCoef;
    NativePoly* p;
    size_t i{POLY_NUM_M1};
    while (state.KeepRunning()) {
        p = &(*polys)[(i = (i + 1) & POLY_NUM_M1)];
        p->SwitchFormat();
        p->SwitchFormat();
    }
}

[[maybe_unused]] static void DCRT_ntt_intt(benchmark::State& state) {
    std::shared_ptr<std::vector<DCRTPoly>> polys = DCRTpolysCoef[state.range(0)];
    DCRTPoly* p;
    size_t i{POLY_NUM_M1};
    while (state.KeepRunning()) {
        p = &(*polys)[(i = (i + 1) & POLY_NUM_M1)];
        p->SwitchFormat();
        p->SwitchFormat();
    }
}

[[maybe_unused]] static void Native_intt_ntt(benchmark::State& state) {
    std::shared_ptr<std::vector<NativePoly>> polys = NativepolysEval;
    NativePoly* p;
    size_t i{POLY_NUM_M1};
    while (state.KeepRunning()) {
        p = &(*polys)[(i = (i + 1) & POLY_NUM_M1)];
        p->SwitchFormat();
        p->SwitchFormat();
    }
}

[[maybe_unused]] static void DCRT_intt_ntt(benchmark::State& state) {
    std::shared_ptr<std::vector<DCRTPoly>> polys = DCRTpolysEval[state.range(0)];
    DCRTPoly* p;
    size_t i{POLY_NUM_M1};
    while (state.KeepRunning()) {
        p = &(*polys)[(i = (i + 1) & POLY_NUM_M1)];
        p->SwitchFormat();
        p->SwitchFormat();
    }
}

// ************************************************************************************

[[maybe_unused]] static void Native_CRTInterpolate(benchmark::State& state) {
    std::shared_ptr<std::vector<NativePoly>> polys = NativepolysCoef;
    NativePoly p;
    size_t i{POLY_NUM_M1};
    while (state.KeepRunning()) {
        p = (*polys)[(i = (i + 1) & POLY_NUM_M1)].CRTInterpolate();
    }
}

[[maybe_unused]] static void DCRT_CRTInterpolate(benchmark::State& state) {
    std::shared_ptr<std::vector<DCRTPoly>> polys = DCRTpolysCoef[state.range(0)];
    DCRTPoly p;
    size_t i{POLY_NUM_M1};
    while (state.KeepRunning()) {
        p = (*polys)[(i = (i + 1) & POLY_NUM_M1)].CRTInterpolate();
    }
}

// ************************************************************************************

[[maybe_unused]] static void Native_DecryptionCRTInterpolate(benchmark::State& state) {
    std::shared_ptr<std::vector<NativePoly>> polys = NativepolysCoef;
    NativePoly p;
    size_t i{POLY_NUM_M1};
    PlaintextModulus ptm(1);
    while (state.KeepRunning()) {
        p = (*polys)[(i = (i + 1) & POLY_NUM_M1)].DecryptionCRTInterpolate(ptm);
    }
}

[[maybe_unused]] static void DCRT_DecryptionCRTInterpolate(benchmark::State& state) {
    std::shared_ptr<std::vector<DCRTPoly>> polys = DCRTpolysCoef[state.range(0)];
    DCRTPoly p;
    size_t i{POLY_NUM_M1};
    PlaintextModulus ptm(1);
    while (state.KeepRunning()) {
        p = (*polys)[(i = (i + 1) & POLY_NUM_M1)].DecryptionCRTInterpolate(ptm);
    }
}

// ************************************************************************************

[[maybe_unused]] static void Native_BaseDecompose(benchmark::State& state) {
    std::shared_ptr<std::vector<NativePoly>> polys = NativepolysCoef;
    std::vector<NativePoly> p;
    size_t i{POLY_NUM_M1};
    while (state.KeepRunning()) {
        p = (*polys)[(i = (i + 1) & POLY_NUM_M1)].BaseDecompose(2, true);
    }
}

[[maybe_unused]] static void DCRT_BaseDecompose(benchmark::State& state) {
    std::shared_ptr<std::vector<DCRTPoly>> polys = DCRTpolysCoef[state.range(0)];
    std::vector<DCRTPoly> p;
    size_t i{POLY_NUM_M1};
    while (state.KeepRunning()) {
        p = (*polys)[(i = (i + 1) & POLY_NUM_M1)].BaseDecompose(2, true);
    }
}

// ************************************************************************************

// BENCHMARK(Native_Add)->Unit(benchmark::kMicrosecond);
// BENCHMARK(DCRT_Add)->Unit(benchmark::kMicrosecond)->Apply(DCRTArguments);
BENCHMARK(Native_AddEq)->Unit(benchmark::kMicrosecond);
BENCHMARK(DCRT_AddEq)->Unit(benchmark::kMicrosecond)->Apply(DCRTArguments);

// BENCHMARK(Native_Sub)->Unit(benchmark::kMicrosecond);
// BENCHMARK(DCRT_Sub)->Unit(benchmark::kMicrosecond)->Apply(DCRTArguments);
BENCHMARK(Native_SubEq)->Unit(benchmark::kMicrosecond);
BENCHMARK(DCRT_SubEq)->Unit(benchmark::kMicrosecond)->Apply(DCRTArguments);

// BENCHMARK(Native_Mul)->Unit(benchmark::kMicrosecond);
// BENCHMARK(DCRT_Mul)->Unit(benchmark::kMicrosecond)->Apply(DCRTArguments);
BENCHMARK(Native_MulEq)->Unit(benchmark::kMicrosecond);
BENCHMARK(DCRT_MulEq)->Unit(benchmark::kMicrosecond)->Apply(DCRTArguments);

BENCHMARK(Native_ntt)->Unit(benchmark::kMicrosecond);
BENCHMARK(DCRT_ntt)->Unit(benchmark::kMicrosecond)->Apply(DCRTArguments);
BENCHMARK(Native_intt)->Unit(benchmark::kMicrosecond);
BENCHMARK(DCRT_intt)->Unit(benchmark::kMicrosecond)->Apply(DCRTArguments);
// BENCHMARK(Native_ntt_intt)->Unit(benchmark::kMicrosecond);
// BENCHMARK(DCRT_ntt_intt)->Unit(benchmark::kMicrosecond)->Apply(DCRTArguments);
// BENCHMARK(Native_intt_ntt)->Unit(benchmark::kMicrosecond);
// BENCHMARK(DCRT_intt_ntt)->Unit(benchmark::kMicrosecond)->Apply(DCRTArguments);

BENCHMARK(Native_CRTInterpolate)->Unit(benchmark::kMicrosecond);
BENCHMARK(DCRT_CRTInterpolate)->Unit(benchmark::kMicrosecond)->Apply(DCRTArguments);

BENCHMARK(Native_DecryptionCRTInterpolate)->Unit(benchmark::kMicrosecond);
BENCHMARK(DCRT_DecryptionCRTInterpolate)->Unit(benchmark::kMicrosecond)->Apply(DCRTArguments);

BENCHMARK(Native_BaseDecompose)->Unit(benchmark::kMicrosecond);
BENCHMARK(DCRT_BaseDecompose)->Unit(benchmark::kMicrosecond)->Apply(DCRTArguments);

#endif
