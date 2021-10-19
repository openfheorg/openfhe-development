/*
 * @author TPOC: contact@palisade-crypto.org
 *
 * @copyright Copyright (c) 2019, New Jersey Institute of Technology (NJIT)
 * All rights reserved.
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution. THIS SOFTWARE IS
 * PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO
 * EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */
/*
  This code benchmarks functions of the math directory  of the PALISADE lattice
  encryption library.
 */
#define _USE_MATH_DEFINES
#include "benchmark/benchmark.h"

#include "palisade.h"

#include <iostream>

#include "vechelper.h"

#include "lattice/dcrtpoly.cpp"
#include "lattice/elemparamfactory.h"
#include "lattice/elemparams.cpp"
#include "lattice/ildcrtparams.cpp"
#include "lattice/ilparams.cpp"
#include "lattice/poly.cpp"
#include "math/discretegaussiangenerator.cpp"
#include "math/discreteuniformgenerator.cpp"
#include "math/nbtheory.cpp"
#include "math/transfrm.cpp"

using namespace std;
using namespace lbcrypto;

#define DO_NATIVEVECTOR_BENCHMARK(X)  \
  BENCHMARK_TEMPLATE(X, NativeVector) \
      ->Unit(benchmark::kMicrosecond) \
      ->ArgName("parm_16")            \
      ->Arg(16);                      \
  BENCHMARK_TEMPLATE(X, NativeVector) \
      ->Unit(benchmark::kMicrosecond) \
      ->ArgName("parm_1024")          \
      ->Arg(1024);                    \
  BENCHMARK_TEMPLATE(X, NativeVector) \
      ->Unit(benchmark::kMicrosecond) \
      ->ArgName("parm_2048")          \
      ->Arg(2048);

#define DO_VECTOR_BENCHMARK_TEMPLATE(X, Y)                                                       \
  BENCHMARK_TEMPLATE(X, Y)                                                                       \
      ->Unit(benchmark::kMicrosecond)                                                            \
      ->ArgName("parm_16")                                                                       \
      ->Arg(16);                                                                                 \
  BENCHMARK_TEMPLATE(X, Y)                                                                       \
      ->Unit(benchmark::kMicrosecond)                                                            \
      ->ArgName("parm_1024")                                                                     \
      ->Arg(1024);                                                                               \
  BENCHMARK_TEMPLATE(X, Y)                                                                       \
      ->Unit(benchmark::kMicrosecond)                                                            \
      ->ArgName("parm_2048")                                                                     \
      ->Arg(2048);                                                                               \
  /*BENCHMARK_TEMPLATE(X,Y)->Unit(benchmark::kMicrosecond)->ArgName("parm_4096")->Arg(4096);*/   \
  BENCHMARK_TEMPLATE(X, Y)                                                                       \
      ->Unit(benchmark::kMicrosecond)                                                            \
      ->ArgName("parm_8192")                                                                     \
      ->Arg(8192);                                                                               \
  /*BENCHMARK_TEMPLATE(X,Y)->Unit(benchmark::kMicrosecond)->ArgName("parm_16384")->Arg(16384);*/ \
  BENCHMARK_TEMPLATE(X, Y)                                                                       \
      ->Unit(benchmark::kMicrosecond)                                                            \
      ->ArgName("parm_32768")                                                                    \
      ->Arg(32768);

// add
template <typename V>
static void add_BigVec(const V &a, const V &b) {
  V c = a + b;
}

template <typename V>
static void BM_BigVec_Add(benchmark::State &state) {  // benchmark
  auto p = state.range(0);
  size_t idx = ElemParamFactory::GetNearestIndex(p);
  typename V::Integer q(ElemParamFactory::DefaultSet[idx].q);
  V a = makeVector<V>(p, q);
  V b = makeVector<V>(p, q);

  while (state.KeepRunning()) {
    add_BigVec<V>(a, b);
  }
}

DO_NATIVEVECTOR_BENCHMARK(BM_BigVec_Add)
DO_VECTOR_BENCHMARK_TEMPLATE(BM_BigVec_Add, M2Vector)
DO_VECTOR_BENCHMARK_TEMPLATE(BM_BigVec_Add, M4Vector)
#ifdef WITH_NTL
DO_VECTOR_BENCHMARK_TEMPLATE(BM_BigVec_Add, M6Vector)
#endif

// +=
template <typename V>
static void addeq_BigVec(V &a, const V &b) {
  a += b;
}

template <typename V>
static void BM_BigVec_Addeq(benchmark::State &state) {  // benchmark
  auto p = state.range(0);
  size_t idx = ElemParamFactory::GetNearestIndex(p);
  typename V::Integer q(ElemParamFactory::DefaultSet[idx].q);
  V b = makeVector<V>(p, q);
  V a = makeVector<V>(p, q);

  while (state.KeepRunning()) {
    // V a = makeVector<V>(p, q);
    addeq_BigVec<V>(a, b);
  }
}

DO_NATIVEVECTOR_BENCHMARK(BM_BigVec_Addeq)
DO_VECTOR_BENCHMARK_TEMPLATE(BM_BigVec_Addeq, M2Vector)
DO_VECTOR_BENCHMARK_TEMPLATE(BM_BigVec_Addeq, M4Vector)
#ifdef WITH_NTL
DO_VECTOR_BENCHMARK_TEMPLATE(BM_BigVec_Addeq, M6Vector)
#endif

// mult
template <typename V>
static void mult_BigVec(const V &a, const V &b) {  // function
  V c = a * b;
}

template <typename V>
static void BM_BigVec_Mult(benchmark::State &state) {  // benchmark
  auto p = state.range(0);
  size_t idx = ElemParamFactory::GetNearestIndex(p);
  typename V::Integer q(ElemParamFactory::DefaultSet[idx].q);
  V a = makeVector<V>(p, q);
  V b = makeVector<V>(p, q);

  while (state.KeepRunning()) {
    mult_BigVec<V>(a, b);
  }
}

DO_NATIVEVECTOR_BENCHMARK(BM_BigVec_Mult)
DO_VECTOR_BENCHMARK_TEMPLATE(BM_BigVec_Mult, M2Vector)
DO_VECTOR_BENCHMARK_TEMPLATE(BM_BigVec_Mult, M4Vector)
#ifdef WITH_NTL
DO_VECTOR_BENCHMARK_TEMPLATE(BM_BigVec_Mult, M6Vector)
#endif

// mult
template <typename V>
static void multeq_BigVec(V &a, const V &b) {
  a *= b;
}

template <typename V>
static void BM_BigVec_Multeq(benchmark::State &state) {  // benchmark
  auto p = state.range(0);
  size_t idx = ElemParamFactory::GetNearestIndex(p);
  typename V::Integer q(ElemParamFactory::DefaultSet[idx].q);
  V b = makeVector<V>(p, q);
  V a = makeVector<V>(p, q);

  while (state.KeepRunning()) {
    // V a = makeVector<V>(p, q);
    multeq_BigVec<V>(a, b);
  }
}

DO_NATIVEVECTOR_BENCHMARK(BM_BigVec_Multeq)
DO_VECTOR_BENCHMARK_TEMPLATE(BM_BigVec_Multeq, M2Vector)
DO_VECTOR_BENCHMARK_TEMPLATE(BM_BigVec_Multeq, M4Vector)
#ifdef WITH_NTL
DO_VECTOR_BENCHMARK_TEMPLATE(BM_BigVec_Multeq, M6Vector)
#endif

// execute the benchmarks
BENCHMARK_MAIN();
