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
 * This code benchmarks polynomial operations for ring dimension of 1k.
 */

#define _USE_MATH_DEFINES
#include "vechelper.h"
#include "lattice/lat-hal.h"

#include <iostream>
#include <vector>

#include "benchmark/benchmark.h"

using namespace lbcrypto;

static std::vector<usint> tow_args({1, 2, 4, 8});

static const usint DCRTBITS     = MAX_MODULUS_SIZE;
static const usint RING_DIM_LOG = 10;
static const size_t POLY_NUM    = 16;
static const size_t POLY_NUM_M1 = (POLY_NUM - 1);

static NativePoly makeElement(std::shared_ptr<ILNativeParams> params, Format format) {
    NativeVector vec = makeVector<NativeVector>(params->GetRingDimension(), params->GetModulus());
    NativePoly elem(params);
    elem.SetValues(vec, format);
    return elem;
}

static DCRTPoly makeElement(std::shared_ptr<ILDCRTParams<BigInteger>> p, Format format) {
    auto params   = std::make_shared<ILParams>(p->GetCyclotomicOrder(), p->GetModulus(), 1);
    BigVector vec = makeVector<BigVector>(params->GetRingDimension(), params->GetModulus());

    DCRTPoly::PolyLargeType bigE(params);
    bigE.SetValues(vec, format);

    DCRTPoly elem(bigE, p);
    return elem;
}

static void GenerateNativeParms(std::shared_ptr<ILNativeParams>& parmArray) {
    uint32_t m                 = (1 << (RING_DIM_LOG + 1));
    NativeInteger firstInteger = FirstPrime<NativeInteger>(DCRTBITS, m);
    NativeInteger modulo       = PreviousPrime<NativeInteger>(firstInteger, m);
    NativeInteger root         = RootOfUnity<NativeInteger>(m, modulo);

    ChineseRemainderTransformFTT<NativeVector>().PreCompute(root, m, modulo);
    parmArray = std::make_shared<ILNativeParams>(m, modulo, root);
}

static void GenerateDCRTParms(std::map<usint, std::shared_ptr<ILDCRTParams<BigInteger>>>& parmArray) {
    for (usint t : tow_args) {
        uint32_t m = (1 << (RING_DIM_LOG + 1));

        std::vector<NativeInteger> moduli(t);
        std::vector<NativeInteger> roots(t);

        NativeInteger firstInteger = FirstPrime<NativeInteger>(DCRTBITS, m);
        moduli[0]                  = PreviousPrime<NativeInteger>(firstInteger, m);
        roots[0]                   = RootOfUnity<NativeInteger>(m, moduli[0]);

        for (size_t i = 1; i < t; i++) {
            moduli[i] = PreviousPrime<NativeInteger>(moduli[i - 1], m);
            roots[i]  = RootOfUnity<NativeInteger>(m, moduli[i]);
        }

        ChineseRemainderTransformFTT<NativeVector>().PreCompute(roots, m, moduli);

        parmArray[t] = std::make_shared<ILDCRTParams<BigInteger>>(m, moduli, roots);
    }
}

static void GeneratePolys(std::shared_ptr<ILNativeParams> parmArray,
                          std::shared_ptr<std::vector<NativePoly>>& polyArrayEval,
                          std::shared_ptr<std::vector<NativePoly>>& polyArrayCoef) {
    std::vector<NativePoly> vecEval;
    for (size_t i = 0; i < POLY_NUM; i++) {
        vecEval.push_back(makeElement(parmArray, Format::EVALUATION));
    }
    polyArrayEval = std::make_shared<std::vector<NativePoly>>(std::move(vecEval));

    std::vector<NativePoly> vecCoef;
    for (size_t i = 0; i < POLY_NUM; i++) {
        vecCoef.push_back(makeElement(parmArray, Format::COEFFICIENT));
    }
    polyArrayCoef = std::make_shared<std::vector<NativePoly>>(std::move(vecCoef));
}

static void GenerateDCRTPolys(std::map<usint, std::shared_ptr<ILDCRTParams<BigInteger>>>& parmArray,
                              std::map<usint, std::shared_ptr<std::vector<DCRTPoly>>>& polyArrayEval,
                              std::map<usint, std::shared_ptr<std::vector<DCRTPoly>>>& polyArrayCoef) {
    for (auto& pair : parmArray) {
        std::vector<DCRTPoly> vecEval;
        for (size_t i = 0; i < POLY_NUM; i++) {
            vecEval.push_back(makeElement(parmArray[pair.first], Format::EVALUATION));
        }
        polyArrayEval[pair.first] = std::make_shared<std::vector<DCRTPoly>>(std::move(vecEval));
        std::vector<DCRTPoly> vecCoef;
        for (size_t i = 0; i < POLY_NUM; i++) {
            vecCoef.push_back(makeElement(parmArray[pair.first], Format::COEFFICIENT));
        }
        polyArrayCoef[pair.first] = std::make_shared<std::vector<DCRTPoly>>(std::move(vecCoef));
    }
}

std::shared_ptr<ILNativeParams> Nativeparms;
std::map<usint, std::shared_ptr<ILDCRTParams<BigInteger>>> DCRTparms;

std::shared_ptr<std::vector<NativePoly>> NativepolysEval;
std::map<usint, std::shared_ptr<std::vector<DCRTPoly>>> DCRTpolysEval;

std::shared_ptr<std::vector<NativePoly>> NativepolysCoef;
std::map<usint, std::shared_ptr<std::vector<DCRTPoly>>> DCRTpolysCoef;

class Setup {
public:
    Setup() {
        GenerateNativeParms(Nativeparms);
        GenerateDCRTParms(DCRTparms);
        std::cerr << "Generating polynomials for the benchmark..." << std::endl;
        GeneratePolys(Nativeparms, NativepolysEval, NativepolysCoef);
        GenerateDCRTPolys(DCRTparms, DCRTpolysEval, DCRTpolysCoef);
        std::cerr << "Polynomials for the benchmark are generated" << std::endl;
    }
} TestParameters;

static void DCRTArguments(benchmark::internal::Benchmark* b) {
    for (usint t : tow_args) {
        b->ArgName("towers")->Arg(t);
    }
}

static void Native_add(benchmark::State& state) {  // benchmark
    std::shared_ptr<std::vector<NativePoly>> polys = NativepolysEval;
    NativePoly *a, *b, c;
    size_t i = 0;

    while (state.KeepRunning()) {
        a = &(polys->operator[](i));
        b = &(polys->operator[](i + 1));
        i += 2;
        i = i & POLY_NUM_M1;
        c = a->Plus(*b);
    }
}

BENCHMARK(Native_add)->Unit(benchmark::kMicrosecond);

static void DCRT_add(benchmark::State& state) {  // benchmark
    std::shared_ptr<std::vector<DCRTPoly>> polys = DCRTpolysEval[state.range(0)];
    DCRTPoly *a, *b, c;
    size_t i = 0;

    while (state.KeepRunning()) {
        a = &(polys->operator[](i));
        b = &(polys->operator[](i + 1));
        i += 2;
        i = i & POLY_NUM_M1;
        c = a->Plus(*b);
    }
}

BENCHMARK(DCRT_add)->Unit(benchmark::kMicrosecond)->Apply(DCRTArguments);

static void Native_mul(benchmark::State& state) {
    std::shared_ptr<std::vector<NativePoly>> polys = NativepolysEval;
    NativePoly *a, *b, c;
    size_t i = 0;
    while (state.KeepRunning()) {
        a = &(polys->operator[](i));
        b = &(polys->operator[](i + 1));
        i += 2;
        i = i & POLY_NUM_M1;
        c = a->Times(*b);
    }
}

BENCHMARK(Native_mul)->Unit(benchmark::kMicrosecond);

static void DCRT_mul(benchmark::State& state) {
    std::shared_ptr<std::vector<DCRTPoly>> polys = DCRTpolysEval[state.range(0)];
    DCRTPoly *a, *b, c;
    size_t i = 0;

    while (state.KeepRunning()) {
        a = &(polys->operator[](i));
        b = &(polys->operator[](i + 1));
        i += 2;
        i = i & POLY_NUM_M1;
        c = a->Times(*b);
    }
}

BENCHMARK(DCRT_mul)->Unit(benchmark::kMicrosecond)->Apply(DCRTArguments);

static void Native_ntt(benchmark::State& state) {
    std::shared_ptr<std::vector<NativePoly>> polys = NativepolysCoef;
    NativePoly a;
    size_t i = 0;

    while (state.KeepRunning()) {
        a = polys->operator[](i);
        i++;
        i = i & POLY_NUM_M1;
        a.SwitchFormat();
    }
}

BENCHMARK(Native_ntt)->Unit(benchmark::kMicrosecond);

static void DCRT_ntt(benchmark::State& state) {
    std::shared_ptr<std::vector<DCRTPoly>> polys = DCRTpolysCoef[state.range(0)];
    DCRTPoly a;
    size_t i = 0;

    while (state.KeepRunning()) {
        a = polys->operator[](i);
        i++;
        i = i & POLY_NUM_M1;
        a.SwitchFormat();
    }
}

BENCHMARK(DCRT_ntt)->Unit(benchmark::kMicrosecond)->Apply(DCRTArguments);

static void Native_intt(benchmark::State& state) {
    std::shared_ptr<std::vector<NativePoly>> polys = NativepolysEval;
    NativePoly a;
    size_t i = 0;

    while (state.KeepRunning()) {
        a = polys->operator[](i);
        i++;
        i = i & POLY_NUM_M1;
        a.SwitchFormat();
    }
}

BENCHMARK(Native_intt)->Unit(benchmark::kMicrosecond);

static void DCRT_intt(benchmark::State& state) {
    std::shared_ptr<std::vector<DCRTPoly>> polys = DCRTpolysEval[state.range(0)];
    DCRTPoly a;
    size_t i = 0;

    while (state.KeepRunning()) {
        a = polys->operator[](i);
        i++;
        i = i & POLY_NUM_M1;
        a.SwitchFormat();
    }
}

BENCHMARK(DCRT_intt)->Unit(benchmark::kMicrosecond)->Apply(DCRTArguments);

BENCHMARK_MAIN();
