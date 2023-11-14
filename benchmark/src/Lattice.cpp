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
  Description:
  This code benchmarks polynomial operations for various math backends.
 */

#define _USE_MATH_DEFINES

#include "benchmark/benchmark.h"
#include "lattice/lat-hal.h"
#include "math/discreteuniformgenerator.h"

#include <iostream>
#include <map>
#include <memory>
#include <vector>

using namespace lbcrypto;

std::vector<uint32_t> os({16, 1024, 2048, 4096, 8192, 16384, 32768});

template <typename E>
static E makeElement(std::shared_ptr<lbcrypto::ILParamsImpl<typename E::Integer>> params) {
    typename E::DugType dug;
    return E(dug, params);
}

template <typename E>
static E makeElement(std::shared_ptr<lbcrypto::ILDCRTParams<typename E::Integer>> params) {
    typename E::DugType dug;
    return E(dug, params);
}

template <typename P>
static void GenerateParms(std::map<uint32_t, std::shared_ptr<P>>& parmArray) {
    for (auto o : os)
        parmArray[o] = std::make_shared<P>(o);
}

template <typename P>
static void GenerateDCRTParms(std::map<uint32_t, std::shared_ptr<P>>& parmArray) {
    for (auto o : os)
        parmArray[o] = std::make_shared<P>(o);
}

template <typename P, typename E>
static void GeneratePolys(std::map<uint32_t, std::shared_ptr<P>>& parmArray,
                          std::map<uint32_t, std::vector<E>>& polyArray) {
    for (auto& pair : parmArray) {
        for (int i = 0; i < 16; i++)
            polyArray[pair.first].push_back(makeElement<E>(parmArray[pair.first]));
    }
}

std::map<uint32_t, std::shared_ptr<ILNativeParams>> Nativeparms;
std::map<uint32_t, std::vector<NativePoly>> Nativepolys;

#ifdef WITH_BE2
std::map<uint32_t, std::shared_ptr<M2Params>> BE2parms;
std::map<uint32_t, std::shared_ptr<M2DCRTParams>> BE2dcrtparms;
std::map<uint32_t, std::vector<M2Poly>> BE2polys;
std::map<uint32_t, std::vector<M2DCRTPoly>> BE2DCRTpolys;
#endif

#ifdef WITH_BE4
std::map<uint32_t, std::shared_ptr<M4Params>> BE4parms;
std::map<uint32_t, std::shared_ptr<M4DCRTParams>> BE4dcrtparms;
std::map<uint32_t, std::vector<M4Poly>> BE4polys;
std::map<uint32_t, std::vector<M4DCRTPoly>> BE4DCRTpolys;
#endif

#ifdef WITH_NTL
std::map<uint32_t, std::shared_ptr<M6Params>> BE6parms;
std::map<uint32_t, std::shared_ptr<M6DCRTParams>> BE6dcrtparms;
std::map<uint32_t, std::vector<M6Poly>> BE6polys;
std::map<uint32_t, std::vector<M6DCRTPoly>> BE6DCRTpolys;
#endif

class Setup {
public:
    Setup() {
        GenerateParms<ILNativeParams>(Nativeparms);
        GeneratePolys<ILNativeParams, NativePoly>(Nativeparms, Nativepolys);

#ifdef WITH_BE2
        GenerateParms<M2Params>(BE2parms);
        GenerateDCRTParms<M2DCRTParams>(BE2dcrtparms);
        GeneratePolys<M2Params, M2Poly>(BE2parms, BE2polys);
        GeneratePolys<M2DCRTParams, M2DCRTPoly>(BE2dcrtparms, BE2DCRTpolys);
#endif

#ifdef WITH_BE4
        GenerateParms<M4Params>(BE4parms);
        GenerateDCRTParms<M4DCRTParams>(BE4dcrtparms);
        GeneratePolys<M4Params, M4Poly>(BE4parms, BE4polys);
        GeneratePolys<M4DCRTParams, M4DCRTPoly>(BE4dcrtparms, BE4DCRTpolys);
#endif

#ifdef WITH_NTL
        GenerateParms<M6Params>(BE6parms);
        GenerateDCRTParms<M6DCRTParams>(BE6dcrtparms);
        GeneratePolys<M6Params, M6Poly>(BE6parms, BE6polys);
        GeneratePolys<M6DCRTParams, M6DCRTPoly>(BE6dcrtparms, BE6DCRTpolys);
#endif
    }

    template <typename P>
    std::shared_ptr<P> GetParm(uint32_t o);

    template <typename E>
    const E& GetPoly(uint32_t o, int p);
} TestParameters;

template <>
std::shared_ptr<ILNativeParams> Setup::GetParm(uint32_t o) {
    return Nativeparms[o];
}
template <>
const NativePoly& Setup::GetPoly(uint32_t o, int p) {
    return Nativepolys[o][p];
}

#ifdef WITH_BE2
template <>
std::shared_ptr<M2Params> Setup::GetParm(uint32_t o) {
    return BE2parms[o];
}
template <>
const M2Poly& Setup::GetPoly(uint32_t o, int p) {
    return BE2polys[o][p];
}
template <>
std::shared_ptr<M2DCRTParams> Setup::GetParm(uint32_t o) {
    return BE2dcrtparms[o];
}
template <>
const M2DCRTPoly& Setup::GetPoly(uint32_t o, int p) {
    return BE2DCRTpolys[o][p];
}
#endif

#ifdef WITH_BE4
template <>
std::shared_ptr<M4Params> Setup::GetParm(uint32_t o) {
    return BE4parms[o];
}
template <>
const M4Poly& Setup::GetPoly(uint32_t o, int p) {
    return BE4polys[o][p];
}
template <>
std::shared_ptr<M4DCRTParams> Setup::GetParm(uint32_t o) {
    return BE4dcrtparms[o];
}
template <>
const M4DCRTPoly& Setup::GetPoly(uint32_t o, int p) {
    return BE4DCRTpolys[o][p];
}
#endif

#ifdef WITH_NTL
template <>
std::shared_ptr<M6Params> Setup::GetParm(uint32_t o) {
    return BE6parms[o];
}
template <>
const M6Poly& Setup::GetPoly(uint32_t o, int p) {
    return BE6polys[o][p];
}
template <>
std::shared_ptr<M6DCRTParams> Setup::GetParm(uint32_t o) {
    return BE6dcrtparms[o];
}
template <>
const M6DCRTPoly& Setup::GetPoly(uint32_t o, int p) {
    return BE6DCRTpolys[o][p];
}
#endif

template <typename E>
static void make_LATTICE_empty(std::shared_ptr<typename E::Params> params) {
    E v1(params);
}

template <typename E>
void BM_LATTICE_empty(benchmark::State& state) {
    while (state.KeepRunning()) {
        make_LATTICE_empty<E>(TestParameters.GetParm<typename E::Params>(state.range(0)));
    }
}

template <typename E>
static void make_LATTICE_vector(benchmark::State& state, std::shared_ptr<typename E::Params> params) {
    E elem = makeElement<E>(params);
}

template <typename E>
void BM_LATTICE_makevector(benchmark::State& state) {
    while (state.KeepRunning()) {
        make_LATTICE_vector<E>(state, TestParameters.GetParm<typename E::Params>(state.range(0)));
    }
}

template <typename E>
static void add_LATTICE(const E& a, const E& b) {
    E c1;
    benchmark::DoNotOptimize(c1 = a + b);
}

template <typename E>
static void BM_add_LATTICE(benchmark::State& state) {
    E a;
    E b;

    if (state.thread_index == 0) {
        a = TestParameters.GetPoly<E>(state.range(0), 0);
        b = TestParameters.GetPoly<E>(state.range(0), 1);
    }

    while (state.KeepRunning()) {
        add_LATTICE<E>(a, b);
    }
}

template <typename E>
static void addeq_LATTICE(E& a, const E& b) {
    benchmark::DoNotOptimize(a += b);
}

template <typename E>
static void BM_addeq_LATTICE(benchmark::State& state) {
    E a;
    E b;

    if (state.thread_index == 0) {
        b = TestParameters.GetPoly<E>(state.range(0), 1);
        a = TestParameters.GetPoly<E>(state.range(0), 0);
    }

    while (state.KeepRunning()) {
        addeq_LATTICE<E>(a, b);
    }
}

template <class E>
static void mult_LATTICE(const E& a, const E& b) {
    E c1;
    benchmark::DoNotOptimize(c1 = a * b);
}

template <class E>
static void BM_mult_LATTICE(benchmark::State& state) {
    E a, b;

    if (state.thread_index == 0) {
        a = TestParameters.GetPoly<E>(state.range(0), 0);
        b = TestParameters.GetPoly<E>(state.range(0), 1);
    }

    while (state.KeepRunning()) {
        mult_LATTICE<E>(a, b);
    }
}

template <class E>
static void multeq_LATTICE(E& a, const E& b) {
    benchmark::DoNotOptimize(a *= b);
}

template <class E>
static void BM_multeq_LATTICE(benchmark::State& state) {
    E a, b;

    if (state.thread_index == 0) {
        b = TestParameters.GetPoly<E>(state.range(0), 1);
        a = TestParameters.GetPoly<E>(state.range(0), 0);
    }

    while (state.KeepRunning()) {
        multeq_LATTICE<E>(a, b);
    }
}

template <class E>
static void switchformat_LATTICE(benchmark::State& state, std::shared_ptr<typename E::Params> params) {
    E a = TestParameters.GetPoly<E>(state.range(0), 0);
    a.SwitchFormat();
}

template <class E>
static void BM_switchformat_LATTICE(benchmark::State& state) {
    while (state.KeepRunning()) {
        switchformat_LATTICE<E>(state, TestParameters.GetParm<typename E::Params>(state.range(0)));
    }
}

template <class E>
static void doubleswitchformat_LATTICE(benchmark::State& state, std::shared_ptr<typename E::Params> params) {
    E a = TestParameters.GetPoly<E>(state.range(0), 0);

    a.SwitchFormat();
    a.SwitchFormat();
}

template <class E>
static void BM_doubleswitchformat_LATTICE(benchmark::State& state) {
    while (state.KeepRunning()) {
        doubleswitchformat_LATTICE<E>(state, TestParameters.GetParm<typename E::Params>(state.range(0)));
    }
}

#define DO_POLY_BENCHMARK(X, Y)                                                                 \
    BENCHMARK_TEMPLATE(X, Y)->Unit(benchmark::kMicrosecond)->ArgName("parm_16")->Arg(16);       \
    BENCHMARK_TEMPLATE(X, Y)->Unit(benchmark::kMicrosecond)->ArgName("parm_1024")->Arg(1024);   \
    BENCHMARK_TEMPLATE(X, Y)->Unit(benchmark::kMicrosecond)->ArgName("parm_2048")->Arg(2048);   \
    BENCHMARK_TEMPLATE(X, Y)->Unit(benchmark::kMicrosecond)->ArgName("parm_4096")->Arg(4096);   \
    BENCHMARK_TEMPLATE(X, Y)->Unit(benchmark::kMicrosecond)->ArgName("parm_8192")->Arg(8192);   \
    BENCHMARK_TEMPLATE(X, Y)->Unit(benchmark::kMicrosecond)->ArgName("parm_16384")->Arg(16384); \
    BENCHMARK_TEMPLATE(X, Y)->Unit(benchmark::kMicrosecond)->ArgName("parm_32768")->Arg(32768);

DO_POLY_BENCHMARK(BM_LATTICE_empty, NativePoly)
DO_POLY_BENCHMARK(BM_LATTICE_makevector, NativePoly)
DO_POLY_BENCHMARK(BM_add_LATTICE, NativePoly)
DO_POLY_BENCHMARK(BM_addeq_LATTICE, NativePoly)
DO_POLY_BENCHMARK(BM_mult_LATTICE, NativePoly)
DO_POLY_BENCHMARK(BM_multeq_LATTICE, NativePoly)
DO_POLY_BENCHMARK(BM_switchformat_LATTICE, NativePoly)
DO_POLY_BENCHMARK(BM_doubleswitchformat_LATTICE, NativePoly)

#ifdef WITH_BE2
DO_POLY_BENCHMARK(BM_LATTICE_empty, M2Poly)
DO_POLY_BENCHMARK(BM_LATTICE_makevector, M2Poly)
DO_POLY_BENCHMARK(BM_add_LATTICE, M2Poly)
DO_POLY_BENCHMARK(BM_addeq_LATTICE, M2Poly)
DO_POLY_BENCHMARK(BM_mult_LATTICE, M2Poly)
DO_POLY_BENCHMARK(BM_multeq_LATTICE, M2Poly)
DO_POLY_BENCHMARK(BM_switchformat_LATTICE, M2Poly)
DO_POLY_BENCHMARK(BM_doubleswitchformat_LATTICE, M2Poly)

DO_POLY_BENCHMARK(BM_LATTICE_empty, M2DCRTPoly)
DO_POLY_BENCHMARK(BM_LATTICE_makevector, M2DCRTPoly)
DO_POLY_BENCHMARK(BM_add_LATTICE, M2DCRTPoly)
DO_POLY_BENCHMARK(BM_addeq_LATTICE, M2DCRTPoly)
DO_POLY_BENCHMARK(BM_mult_LATTICE, M2DCRTPoly)
DO_POLY_BENCHMARK(BM_multeq_LATTICE, M2DCRTPoly)
DO_POLY_BENCHMARK(BM_switchformat_LATTICE, M2DCRTPoly)
DO_POLY_BENCHMARK(BM_doubleswitchformat_LATTICE, M2DCRTPoly)
#endif

#ifdef WITH_BE4
DO_POLY_BENCHMARK(BM_LATTICE_empty, M4Poly)
DO_POLY_BENCHMARK(BM_LATTICE_makevector, M4Poly)
DO_POLY_BENCHMARK(BM_add_LATTICE, M4Poly)
DO_POLY_BENCHMARK(BM_addeq_LATTICE, M4Poly)
DO_POLY_BENCHMARK(BM_mult_LATTICE, M4Poly)
DO_POLY_BENCHMARK(BM_multeq_LATTICE, M4Poly)
DO_POLY_BENCHMARK(BM_switchformat_LATTICE, M4Poly)
DO_POLY_BENCHMARK(BM_doubleswitchformat_LATTICE, M4Poly)

DO_POLY_BENCHMARK(BM_LATTICE_empty, M4DCRTPoly)
DO_POLY_BENCHMARK(BM_LATTICE_makevector, M4DCRTPoly)
DO_POLY_BENCHMARK(BM_add_LATTICE, M4DCRTPoly)
DO_POLY_BENCHMARK(BM_addeq_LATTICE, M4DCRTPoly)
DO_POLY_BENCHMARK(BM_mult_LATTICE, M4DCRTPoly)
DO_POLY_BENCHMARK(BM_multeq_LATTICE, M4DCRTPoly)
DO_POLY_BENCHMARK(BM_switchformat_LATTICE, M4DCRTPoly)
DO_POLY_BENCHMARK(BM_doubleswitchformat_LATTICE, M4DCRTPoly)
#endif

#ifdef WITH_NTL
DO_POLY_BENCHMARK(BM_LATTICE_empty, M6Poly)
DO_POLY_BENCHMARK(BM_LATTICE_makevector, M6Poly)
DO_POLY_BENCHMARK(BM_add_LATTICE, M6Poly)
DO_POLY_BENCHMARK(BM_addeq_LATTICE, M6Poly)
DO_POLY_BENCHMARK(BM_mult_LATTICE, M6Poly)
DO_POLY_BENCHMARK(BM_multeq_LATTICE, M6Poly)
DO_POLY_BENCHMARK(BM_switchformat_LATTICE, M6Poly)
DO_POLY_BENCHMARK(BM_doubleswitchformat_LATTICE, M6Poly)

DO_POLY_BENCHMARK(BM_LATTICE_empty, M6DCRTPoly)
DO_POLY_BENCHMARK(BM_LATTICE_makevector, M6DCRTPoly)
DO_POLY_BENCHMARK(BM_add_LATTICE, M6DCRTPoly)
DO_POLY_BENCHMARK(BM_addeq_LATTICE, M6DCRTPoly)
DO_POLY_BENCHMARK(BM_mult_LATTICE, M6DCRTPoly)
DO_POLY_BENCHMARK(BM_multeq_LATTICE, M6DCRTPoly)
DO_POLY_BENCHMARK(BM_switchformat_LATTICE, M6DCRTPoly)
DO_POLY_BENCHMARK(BM_doubleswitchformat_LATTICE, M6DCRTPoly)
#endif

// execute the benchmarks
BENCHMARK_MAIN();
