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
#include <mutex>
#include <utility>
#include <vector>

using namespace lbcrypto;

constexpr size_t POLY_NUM    = 8;
constexpr size_t POLY_NUM_M1 = (POLY_NUM - 1);

std::vector<uint32_t> tow_args({1, 2, 4, 8, 16, 32});

uint32_t g_polyOrder = 0;
uint32_t g_polyBits  = 0;

struct PolyBenchParams {
    PolyBenchParams(uint32_t order, uint32_t bits) {
        g_polyOrder = order;
        g_polyBits  = bits;
    }
};

std::shared_ptr<std::vector<NativePoly>> g_NativepolysEval;
std::shared_ptr<std::vector<NativePoly>> g_NativepolysCoef;
std::map<uint32_t, std::shared_ptr<std::vector<DCRTPoly>>> g_DCRTpolysEval;
std::map<uint32_t, std::shared_ptr<std::vector<DCRTPoly>>> g_DCRTpolysCoef;

static void DCRTArguments(benchmark::internal::Benchmark* b) {
    for (uint32_t t : tow_args) {
        b->ArgName("towers")->Arg(t);
    }
}

static void GeneratePolys(uint32_t order, uint32_t bits, std::shared_ptr<std::vector<NativePoly>>& polyArrayEval,
                          std::shared_ptr<std::vector<NativePoly>>& polyArrayCoef) {
    auto p    = std::make_shared<ILNativeParams>(order, bits);
    auto eval = std::make_shared<std::vector<NativePoly>>(POLY_NUM);
    auto coef = std::make_shared<std::vector<NativePoly>>(POLY_NUM);
#pragma omp parallel for collapse(2)
    for (size_t f = 0; f < 2; ++f) {
        for (size_t i = 0; i < POLY_NUM; ++i) {
            DiscreteUniformGeneratorImpl<NativeVector> dug;
            auto& dst = (f == 0) ? (*eval)[i] : (*coef)[i];
            dst       = NativePoly(dug, p, (f == 0) ? Format::EVALUATION : Format::COEFFICIENT);
        }
    }
    polyArrayEval = std::move(eval);
    polyArrayCoef = std::move(coef);
}

static void GenerateDCRTPolys(uint32_t order, uint32_t bits, uint32_t towers,
                              std::shared_ptr<std::vector<DCRTPoly>>& polyArrayEval,
                              std::shared_ptr<std::vector<DCRTPoly>>& polyArrayCoef) {
    auto p    = std::make_shared<ILDCRTParams<BigInteger>>(order, towers, bits);
    auto eval = std::make_shared<std::vector<DCRTPoly>>(POLY_NUM);
    auto coef = std::make_shared<std::vector<DCRTPoly>>(POLY_NUM);
#pragma omp parallel for collapse(2)
    for (size_t f = 0; f < 2; ++f) {
        for (size_t i = 0; i < POLY_NUM; ++i) {
            DiscreteUniformGeneratorImpl<NativeVector> tdug;
            auto& dst = (f == 0) ? (*eval)[i] : (*coef)[i];
            dst       = DCRTPoly(tdug, p, (f == 0) ? Format::EVALUATION : Format::COEFFICIENT);
        }
    }
    polyArrayEval = std::move(eval);
    polyArrayCoef = std::move(coef);
}

static void EnsureNativePolys() {
    static const bool generated = []() {
        GeneratePolys(g_polyOrder, g_polyBits, g_NativepolysEval, g_NativepolysCoef);
        return true;
    }();
    (void)generated;
}

static void EnsureDCRTPolys(uint32_t towers) {
    static std::mutex genMutex;
    std::lock_guard<std::mutex> lock(genMutex);
    if (g_DCRTpolysEval.find(towers) == g_DCRTpolysEval.end())
        GenerateDCRTPolys(g_polyOrder, g_polyBits, towers, g_DCRTpolysEval[towers], g_DCRTpolysCoef[towers]);
}

static const std::shared_ptr<std::vector<NativePoly>>& NativepolysEval() {
    EnsureNativePolys();
    return g_NativepolysEval;
}

static const std::shared_ptr<std::vector<NativePoly>>& NativepolysCoef() {
    EnsureNativePolys();
    return g_NativepolysCoef;
}

static const std::shared_ptr<std::vector<DCRTPoly>>& DCRTpolysEval(uint32_t towers) {
    EnsureDCRTPolys(towers);
    return g_DCRTpolysEval[towers];
}

static const std::shared_ptr<std::vector<DCRTPoly>>& DCRTpolysCoef(uint32_t towers) {
    EnsureDCRTPolys(towers);
    return g_DCRTpolysCoef[towers];
}

// ************************************************************************************

[[maybe_unused]] static void Native_Add(benchmark::State& state) {
    std::shared_ptr<std::vector<NativePoly>> polys = NativepolysEval();
    NativePoly p;
    size_t i{0}, j{0};
    while (state.KeepRunning()) {
        i = j;
        p = (*polys)[i] + (*polys)[(j = (i + 1) & POLY_NUM_M1)];
    }
}

[[maybe_unused]] static void DCRT_Add(benchmark::State& state) {
    std::shared_ptr<std::vector<DCRTPoly>> polys = DCRTpolysEval(state.range(0));
    DCRTPoly p;
    size_t i{0}, j{0};
    while (state.KeepRunning()) {
        i = j;
        p = (*polys)[i] + (*polys)[(j = (i + 1) & POLY_NUM_M1)];
    }
}

[[maybe_unused]] static void Native_AddEq(benchmark::State& state) {
    std::shared_ptr<std::vector<NativePoly>> polys = NativepolysEval();
    NativePoly p{(*polys)[0]};
    size_t i{0};
    while (state.KeepRunning()) {
        p += (*polys)[(i = (i + 1) & POLY_NUM_M1)];
    }
}

[[maybe_unused]] static void DCRT_AddEq(benchmark::State& state) {
    std::shared_ptr<std::vector<DCRTPoly>> polys = DCRTpolysEval(state.range(0));
    DCRTPoly p{(*polys)[0]};
    size_t i{0};
    while (state.KeepRunning()) {
        p += (*polys)[(i = (i + 1) & POLY_NUM_M1)];
    }
}

// ************************************************************************************

[[maybe_unused]] static void Native_Sub(benchmark::State& state) {
    std::shared_ptr<std::vector<NativePoly>> polys = NativepolysEval();
    NativePoly p;
    size_t i{0}, j{0};
    while (state.KeepRunning()) {
        i = j;
        p = (*polys)[i] - (*polys)[(j = (i + 1) & POLY_NUM_M1)];
    }
}

[[maybe_unused]] static void DCRT_Sub(benchmark::State& state) {
    std::shared_ptr<std::vector<DCRTPoly>> polys = DCRTpolysEval(state.range(0));
    DCRTPoly p;
    size_t i{0}, j{0};
    while (state.KeepRunning()) {
        i = j;
        p = (*polys)[i] - (*polys)[(j = (i + 1) & POLY_NUM_M1)];
    }
}

[[maybe_unused]] static void Native_SubEq(benchmark::State& state) {
    std::shared_ptr<std::vector<NativePoly>> polys = NativepolysEval();
    NativePoly p{(*polys)[0]};
    size_t i{0};
    while (state.KeepRunning()) {
        p -= (*polys)[(i = (i + 1) & POLY_NUM_M1)];
    }
}

[[maybe_unused]] static void DCRT_SubEq(benchmark::State& state) {
    std::shared_ptr<std::vector<DCRTPoly>> polys = DCRTpolysEval(state.range(0));
    DCRTPoly p{(*polys)[0]};
    size_t i{0};
    while (state.KeepRunning()) {
        p -= (*polys)[(i = (i + 1) & POLY_NUM_M1)];
    }
}

// ************************************************************************************

[[maybe_unused]] static void Native_Mul(benchmark::State& state) {
    std::shared_ptr<std::vector<NativePoly>> polys = NativepolysEval();
    NativePoly p;
    size_t i{0}, j{0};
    while (state.KeepRunning()) {
        i = j;
        p = (*polys)[i] * (*polys)[(j = (i + 1) & POLY_NUM_M1)];
    }
}

[[maybe_unused]] static void DCRT_Mul(benchmark::State& state) {
    std::shared_ptr<std::vector<DCRTPoly>> polys = DCRTpolysEval(state.range(0));
    DCRTPoly p;
    size_t i{0}, j{0};
    while (state.KeepRunning()) {
        i = j;
        p = (*polys)[i] * (*polys)[(j = (i + 1) & POLY_NUM_M1)];
    }
}

[[maybe_unused]] static void Native_MulEq(benchmark::State& state) {
    std::shared_ptr<std::vector<NativePoly>> polys = NativepolysEval();
    NativePoly p{(*polys)[0]};
    size_t i{0};
    while (state.KeepRunning()) {
        p *= (*polys)[(i = (i + 1) & POLY_NUM_M1)];
    }
}

[[maybe_unused]] static void DCRT_MulEq(benchmark::State& state) {
    std::shared_ptr<std::vector<DCRTPoly>> polys = DCRTpolysEval(state.range(0));
    DCRTPoly p{(*polys)[0]};
    size_t i{0};
    while (state.KeepRunning()) {
        p *= (*polys)[(i = (i + 1) & POLY_NUM_M1)];
    }
}

// ************************************************************************************

[[maybe_unused]] static void Native_Copy(benchmark::State& state) {
    auto polys = NativepolysEval();
    NativePoly p;
    size_t i{0};
    while (state.KeepRunning()) {
        benchmark::DoNotOptimize(p = (*polys)[(i = (i + 1) & POLY_NUM_M1)]);
    }
}

[[maybe_unused]] static void DCRT_Copy(benchmark::State& state) {
    auto polys = DCRTpolysEval(state.range(0));
    DCRTPoly p;
    size_t i{0};
    while (state.KeepRunning()) {
        benchmark::DoNotOptimize(p = (*polys)[(i = (i + 1) & POLY_NUM_M1)]);
    }
}

// ************************************************************************************

[[maybe_unused]] static void Native_Copy_ntt(benchmark::State& state) {
    std::shared_ptr<std::vector<NativePoly>> polys = NativepolysCoef();
    NativePoly p;
    size_t i{POLY_NUM_M1};
    while (state.KeepRunning()) {
        p = (*polys)[(i = (i + 1) & POLY_NUM_M1)];
        p.SwitchFormat();
    }
}

[[maybe_unused]] static void DCRT_Copy_ntt(benchmark::State& state) {
    std::shared_ptr<std::vector<DCRTPoly>> polys = DCRTpolysCoef(state.range(0));
    DCRTPoly p;
    size_t i{POLY_NUM_M1};
    while (state.KeepRunning()) {
        p = (*polys)[(i = (i + 1) & POLY_NUM_M1)];
        p.SwitchFormat();
    }
}

[[maybe_unused]] static void Native_Copy_intt(benchmark::State& state) {
    std::shared_ptr<std::vector<NativePoly>> polys = NativepolysEval();
    NativePoly p;
    size_t i{POLY_NUM_M1};
    while (state.KeepRunning()) {
        p = (*polys)[(i = (i + 1) & POLY_NUM_M1)];
        p.SwitchFormat();
    }
}

[[maybe_unused]] static void DCRT_Copy_intt(benchmark::State& state) {
    std::shared_ptr<std::vector<DCRTPoly>> polys = DCRTpolysEval(state.range(0));
    DCRTPoly p;
    size_t i{POLY_NUM_M1};
    while (state.KeepRunning()) {
        p = (*polys)[(i = (i + 1) & POLY_NUM_M1)];
        p.SwitchFormat();
    }
}

[[maybe_unused]] static void Native_avg_ntt_intt(benchmark::State& state) {
    auto polys = *NativepolysCoef();
    NativePoly* p;
    size_t i{POLY_NUM_M1};
    while (state.KeepRunning()) {
        p = &polys[(i = (i + 1) & POLY_NUM_M1)];
        p->SwitchFormat();
    }
}

[[maybe_unused]] static void DCRT_avg_ntt_intt(benchmark::State& state) {
    auto polys = *DCRTpolysCoef(state.range(0));
    DCRTPoly* p;
    size_t i{POLY_NUM_M1};
    while (state.KeepRunning()) {
        p = &polys[(i = (i + 1) & POLY_NUM_M1)];
        p->SwitchFormat();
    }
}

[[maybe_unused]] static void Native_ntt_intt(benchmark::State& state) {
    std::shared_ptr<std::vector<NativePoly>> polys = NativepolysCoef();
    NativePoly* p;
    size_t i{POLY_NUM_M1};
    while (state.KeepRunning()) {
        p = &(*polys)[(i = (i + 1) & POLY_NUM_M1)];
        p->SwitchFormat();
        p->SwitchFormat();
    }
}

[[maybe_unused]] static void DCRT_ntt_intt(benchmark::State& state) {
    std::shared_ptr<std::vector<DCRTPoly>> polys = DCRTpolysCoef(state.range(0));
    DCRTPoly* p;
    size_t i{POLY_NUM_M1};
    while (state.KeepRunning()) {
        p = &(*polys)[(i = (i + 1) & POLY_NUM_M1)];
        p->SwitchFormat();
        p->SwitchFormat();
    }
}

[[maybe_unused]] static void Native_intt_ntt(benchmark::State& state) {
    std::shared_ptr<std::vector<NativePoly>> polys = NativepolysEval();
    NativePoly* p;
    size_t i{POLY_NUM_M1};
    while (state.KeepRunning()) {
        p = &(*polys)[(i = (i + 1) & POLY_NUM_M1)];
        p->SwitchFormat();
        p->SwitchFormat();
    }
}

[[maybe_unused]] static void DCRT_intt_ntt(benchmark::State& state) {
    std::shared_ptr<std::vector<DCRTPoly>> polys = DCRTpolysEval(state.range(0));
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
    std::shared_ptr<std::vector<NativePoly>> polys = NativepolysCoef();
    NativePoly p;
    size_t i{POLY_NUM_M1};
    while (state.KeepRunning()) {
        p = (*polys)[(i = (i + 1) & POLY_NUM_M1)].CRTInterpolate();
    }
}

[[maybe_unused]] static void DCRT_CRTInterpolate(benchmark::State& state) {
    std::shared_ptr<std::vector<DCRTPoly>> polys = DCRTpolysCoef(state.range(0));
    DCRTPoly p;
    size_t i{POLY_NUM_M1};
    while (state.KeepRunning()) {
        p = (*polys)[(i = (i + 1) & POLY_NUM_M1)].CRTInterpolate();
    }
}

// ************************************************************************************

[[maybe_unused]] static void Native_DecryptionCRTInterpolate(benchmark::State& state) {
    std::shared_ptr<std::vector<NativePoly>> polys = NativepolysCoef();
    NativePoly p;
    size_t i{POLY_NUM_M1};
    PlaintextModulus ptm(1);
    while (state.KeepRunning()) {
        p = (*polys)[(i = (i + 1) & POLY_NUM_M1)].DecryptionCRTInterpolate(ptm);
    }
}

[[maybe_unused]] static void DCRT_DecryptionCRTInterpolate(benchmark::State& state) {
    std::shared_ptr<std::vector<DCRTPoly>> polys = DCRTpolysCoef(state.range(0));
    DCRTPoly p;
    size_t i{POLY_NUM_M1};
    PlaintextModulus ptm(1);
    while (state.KeepRunning()) {
        p = (*polys)[(i = (i + 1) & POLY_NUM_M1)].DecryptionCRTInterpolate(ptm);
    }
}

// ************************************************************************************

[[maybe_unused]] static void Native_BaseDecompose(benchmark::State& state) {
    std::shared_ptr<std::vector<NativePoly>> polys = NativepolysCoef();
    std::vector<NativePoly> p;
    size_t i{POLY_NUM_M1};
    while (state.KeepRunning()) {
        p = (*polys)[(i = (i + 1) & POLY_NUM_M1)].BaseDecompose(2, true);
    }
}

[[maybe_unused]] static void DCRT_BaseDecompose(benchmark::State& state) {
    std::shared_ptr<std::vector<DCRTPoly>> polys = DCRTpolysCoef(state.range(0));
    std::vector<DCRTPoly> p;
    size_t i{POLY_NUM_M1};
    while (state.KeepRunning()) {
        p = (*polys)[(i = (i + 1) & POLY_NUM_M1)].BaseDecompose(2, true);
    }
}

// ************************************************************************************

[[maybe_unused]] static void Native_AutomorphismTransform(benchmark::State& state) {
    std::shared_ptr<std::vector<NativePoly>> polys = NativepolysEval();
    NativePoly p;
    size_t i{POLY_NUM_M1};
    while (state.KeepRunning()) {
        p = (*polys)[(i = (i + 1) & POLY_NUM_M1)].AutomorphismTransform(5);
    }
}

[[maybe_unused]] static void DCRT_AutomorphismTransform(benchmark::State& state) {
    std::shared_ptr<std::vector<DCRTPoly>> polys = DCRTpolysEval(state.range(0));
    DCRTPoly p;
    size_t i{POLY_NUM_M1};
    while (state.KeepRunning()) {
        p = (*polys)[(i = (i + 1) & POLY_NUM_M1)].AutomorphismTransform(5);
    }
}

[[maybe_unused]] static void DCRT_DropLastElementAndScale(benchmark::State& state) {
    std::shared_ptr<std::vector<DCRTPoly>> polys = DCRTpolysEval(state.range(0));
    const auto& towers                           = (*polys)[0].GetParams()->GetParams();
    const size_t last                            = towers.size() - 1;
    if (last == 0) {
        state.SkipWithError("DropLastElementAndScale needs at least two towers");
        return;
    }
    const NativeInteger ql{towers[last]->GetModulus()};
    std::vector<NativeInteger> qlInvModq(last);
    for (size_t k = 0; k < last; ++k) {
        const NativeInteger qk{towers[k]->GetModulus()};
        qlInvModq[k] = ql.Mod(qk).ModInverse(qk);
    }
    size_t i{POLY_NUM_M1};
    while (state.KeepRunning()) {
        DCRTPoly p = (*polys)[(i = (i + 1) & POLY_NUM_M1)];
        p.DropLastElementAndScale(qlInvModq);
    }
}

// ************************************************************************************

// BENCHMARK(Native_Add)->Unit(benchmark::kMicrosecond);
// BENCHMARK(DCRT_Add)->Unit(benchmark::kMicrosecond)->Apply(DCRTArguments);

BENCHMARK(Native_AddEq)->Unit(benchmark::kMicrosecond)->MinTime(5.0);
BENCHMARK(DCRT_AddEq)->Unit(benchmark::kMicrosecond)->Apply(DCRTArguments)->MinTime(5.0);

// BENCHMARK(Native_Sub)->Unit(benchmark::kMicrosecond);
// BENCHMARK(DCRT_Sub)->Unit(benchmark::kMicrosecond)->Apply(DCRTArguments);

BENCHMARK(Native_SubEq)->Unit(benchmark::kMicrosecond)->MinTime(5.0);
BENCHMARK(DCRT_SubEq)->Unit(benchmark::kMicrosecond)->Apply(DCRTArguments)->MinTime(5.0);

// BENCHMARK(Native_Mul)->Unit(benchmark::kMicrosecond);
// BENCHMARK(DCRT_Mul)->Unit(benchmark::kMicrosecond)->Apply(DCRTArguments);

BENCHMARK(Native_MulEq)->Unit(benchmark::kMicrosecond)->MinTime(5.0);
BENCHMARK(DCRT_MulEq)->Unit(benchmark::kMicrosecond)->Apply(DCRTArguments)->MinTime(5.0);

BENCHMARK(Native_Copy)->Unit(benchmark::kMicrosecond)->MinTime(5.0);
BENCHMARK(DCRT_Copy)->Unit(benchmark::kMicrosecond)->Apply(DCRTArguments)->MinTime(5.0);

BENCHMARK(Native_Copy_ntt)->Unit(benchmark::kMicrosecond)->MinTime(5.0);
BENCHMARK(DCRT_Copy_ntt)->Unit(benchmark::kMicrosecond)->Apply(DCRTArguments)->MinTime(5.0);

BENCHMARK(Native_Copy_intt)->Unit(benchmark::kMicrosecond)->MinTime(5.0);
BENCHMARK(DCRT_Copy_intt)->Unit(benchmark::kMicrosecond)->Apply(DCRTArguments)->MinTime(5.0);

BENCHMARK(Native_avg_ntt_intt)->Unit(benchmark::kMicrosecond)->MinTime(5.0);
BENCHMARK(DCRT_avg_ntt_intt)->Unit(benchmark::kMicrosecond)->Apply(DCRTArguments)->MinTime(5.0);

// BENCHMARK(Native_ntt_intt)->Unit(benchmark::kMicrosecond);
// BENCHMARK(DCRT_ntt_intt)->Unit(benchmark::kMicrosecond)->Apply(DCRTArguments);

// BENCHMARK(Native_intt_ntt)->Unit(benchmark::kMicrosecond);
// BENCHMARK(DCRT_intt_ntt)->Unit(benchmark::kMicrosecond)->Apply(DCRTArguments);

// BENCHMARK(Native_CRTInterpolate)->Unit(benchmark::kMicrosecond)->MinTime(5.0);
// BENCHMARK(DCRT_CRTInterpolate)->Unit(benchmark::kMicrosecond)->Apply(DCRTArguments)->MinTime(5.0);

// BENCHMARK(Native_DecryptionCRTInterpolate)->Unit(benchmark::kMicrosecond);
// BENCHMARK(DCRT_DecryptionCRTInterpolate)->Unit(benchmark::kMicrosecond)->Apply(DCRTArguments);

// BENCHMARK(Native_BaseDecompose)->Unit(benchmark::kMicrosecond);
// BENCHMARK(DCRT_BaseDecompose)->Unit(benchmark::kMicrosecond)->Apply(DCRTArguments);

BENCHMARK(Native_AutomorphismTransform)->Unit(benchmark::kMicrosecond)->MinTime(5.0);
BENCHMARK(DCRT_AutomorphismTransform)->Unit(benchmark::kMicrosecond)->Apply(DCRTArguments)->MinTime(5.0);

BENCHMARK(DCRT_DropLastElementAndScale)->Unit(benchmark::kMicrosecond)->Apply(DCRTArguments)->MinTime(5.0);

#endif
