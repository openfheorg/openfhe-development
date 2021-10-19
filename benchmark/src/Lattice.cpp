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

  Description:
  This code benchmarks functions of the src/lib/lattoce directory  of the
  PALISADE lattice encryption library.
 */

#define _USE_MATH_DEFINES
#include "benchmark/benchmark.h"

#include "palisade.h"

#include <iostream>
#include <vector>

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

namespace lbcrypto {

template <typename E>
static E makeElement(
    shared_ptr<lbcrypto::ILParamsImpl<typename E::Integer>> params) {
  typename E::Vector vec = makeVector<typename E::Vector>(
      params->GetRingDimension(), params->GetModulus());
  E elem(params);

  elem.SetValues(vec, elem.GetFormat());
  return elem;
}

template <typename E>
static E makeElement(
    shared_ptr<lbcrypto::ILDCRTParams<typename E::Integer>> p) {
  shared_ptr<ILParamsImpl<typename E::Integer>> params(
      new ILParamsImpl<typename E::Integer>(p->GetCyclotomicOrder(),
                                            p->GetModulus(), 1));
  typename E::Vector vec = makeVector<typename E::Vector>(
      params->GetRingDimension(), params->GetModulus());

  typename E::PolyLargeType bigE(params);
  bigE.SetValues(vec, bigE.GetFormat());

  E elem(bigE, p);
  return elem;
}

static vector<usint> o({16, 1024, 2048, 4096, 8192, 16384, 32768});
static const usint DCRTBITS = 28;

template <typename P>
static void GenerateParms(map<usint, shared_ptr<P>> &parmArray) {
  for (usint v : o) {
    shared_ptr<P> value;
    try {
      value = ElemParamFactory::GenElemParams<P>(v);
    } catch (...) {
      break;
    }
    parmArray[v] = value;
  }
}

template <typename P>
static void GenerateDCRTParms(map<usint, shared_ptr<P>> &parmArray) {
  for (usint v : o) {
    size_t idx = ElemParamFactory::GetNearestIndex(v);
    M2Integer primeq(ElemParamFactory::DefaultSet[idx].q);

    usint bits = primeq.GetMSB();
    usint ntowers = bits / DCRTBITS + 1;

    parmArray[v] = ElemParamFactory::GenElemParams<P>(v, 28, ntowers);
  }
}

template <typename P, typename E>
static void GeneratePolys(map<usint, shared_ptr<P>> &parmArray,
                          map<usint, vector<E>> &polyArray) {
  for (auto &pair : parmArray) {
    for (int i = 0; i < 2; i++)
      polyArray[pair.first].push_back(makeElement<E>(parmArray[pair.first]));
  }
}

}  // namespace lbcrypto

map<usint, shared_ptr<ILNativeParams>> Nativeparms;
map<usint, shared_ptr<M2Params>> BE2parms;
map<usint, shared_ptr<M2DCRTParams>> BE2dcrtparms;
map<usint, shared_ptr<M4Params>> BE4parms;
map<usint, shared_ptr<M4DCRTParams>> BE4dcrtparms;
#ifdef WITH_NTL
map<usint, shared_ptr<M6Params>> BE6parms;
map<usint, shared_ptr<M6DCRTParams>> BE6dcrtparms;
#endif
map<usint, vector<NativePoly>> Nativepolys;
map<usint, vector<M2Poly>> BE2polys;
map<usint, vector<M2DCRTPoly>> BE2DCRTpolys;
map<usint, vector<M4Poly>> BE4polys;
map<usint, vector<M4DCRTPoly>> BE4DCRTpolys;
#ifdef WITH_NTL
map<usint, vector<M6Poly>> BE6polys;
map<usint, vector<M6DCRTPoly>> BE6DCRTpolys;
#endif

class Setup {
 public:
  Setup() {
    GenerateParms<ILNativeParams>(Nativeparms);
    GenerateParms<M2Params>(BE2parms);
    GenerateDCRTParms<M2DCRTParams>(BE2dcrtparms);
    GenerateParms<M4Params>(BE4parms);
    GenerateDCRTParms<M4DCRTParams>(BE4dcrtparms);
#ifdef WITH_NTL
    GenerateParms<M6Params>(BE6parms);
    GenerateDCRTParms<M6DCRTParams>(BE6dcrtparms);
#endif
    GeneratePolys<ILNativeParams, NativePoly>(Nativeparms, Nativepolys);
    GeneratePolys<M2Params, M2Poly>(BE2parms, BE2polys);
    GeneratePolys<M4Params, M4Poly>(BE4parms, BE4polys);
#ifdef WITH_NTL
    GeneratePolys<M6Params, M6Poly>(BE6parms, BE6polys);
#endif
    GeneratePolys<M2DCRTParams, M2DCRTPoly>(BE2dcrtparms, BE2DCRTpolys);
    GeneratePolys<M4DCRTParams, M4DCRTPoly>(BE4dcrtparms, BE4DCRTpolys);
#ifdef WITH_NTL
    GeneratePolys<M6DCRTParams, M6DCRTPoly>(BE6dcrtparms, BE6DCRTpolys);
#endif
  }

  template <typename P>
  shared_ptr<P> GetParm(usint o);

  template <typename E>
  const E &GetPoly(usint o, int p);
} TestParameters;

template <>
shared_ptr<ILNativeParams> Setup::GetParm(usint o) {
  return Nativeparms[o];
}

template <>
shared_ptr<M2Params> Setup::GetParm(usint o) {
  return BE2parms[o];
}

template <>
shared_ptr<M2DCRTParams> Setup::GetParm(usint o) {
  return BE2dcrtparms[o];
}

template <>
shared_ptr<M4Params> Setup::GetParm(usint o) {
  return BE4parms[o];
}

template <>
shared_ptr<M4DCRTParams> Setup::GetParm(usint o) {
  return BE4dcrtparms[o];
}

#ifdef WITH_NTL
template <>
shared_ptr<M6Params> Setup::GetParm(usint o) {
  return BE6parms[o];
}

template <>
shared_ptr<M6DCRTParams> Setup::GetParm(usint o) {
  return BE6dcrtparms[o];
}
#endif

template <>
const NativePoly &Setup::GetPoly(usint o, int p) {
  return Nativepolys[o][p];
}
template <>
const M2Poly &Setup::GetPoly(usint o, int p) {
  return BE2polys[o][p];
}
template <>
const M4Poly &Setup::GetPoly(usint o, int p) {
  return BE4polys[o][p];
}
#ifdef WITH_NTL
template <>
const M6Poly &Setup::GetPoly(usint o, int p) {
  return BE6polys[o][p];
}
#endif
template <>
const M2DCRTPoly &Setup::GetPoly(usint o, int p) {
  return BE2DCRTpolys[o][p];
}
template <>
const M4DCRTPoly &Setup::GetPoly(usint o, int p) {
  return BE4DCRTpolys[o][p];
}
#ifdef WITH_NTL
template <>
const M6DCRTPoly &Setup::GetPoly(usint o, int p) {
  return BE6DCRTpolys[o][p];
}
#endif

#define DO_NATIVEPOLY_BENCHMARK(X)    \
  BENCHMARK_TEMPLATE(X, NativePoly)   \
      ->Unit(benchmark::kMicrosecond) \
      ->ArgName("parm_16")            \
      ->Arg(16);                      \
  BENCHMARK_TEMPLATE(X, NativePoly)   \
      ->Unit(benchmark::kMicrosecond) \
      ->ArgName("parm_1024")          \
      ->Arg(1024);                    \
  BENCHMARK_TEMPLATE(X, NativePoly)   \
      ->Unit(benchmark::kMicrosecond) \
      ->ArgName("parm_2048")          \
      ->Arg(2048);

#define DO_POLY_BENCHMARK_TEMPLATE(X, Y)                                                         \
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

// benchmark just a declaration of an empty
template <typename E>
static void make_LATTICE_empty(shared_ptr<typename E::Params> params) {
  E v1(params);
}

template <typename E>
void BM_LATTICE_empty(benchmark::State &state) {  // benchmark
  if (state.thread_index == 0) {
    ;
  }

  while (state.KeepRunning()) {
    make_LATTICE_empty<E>(
        TestParameters.GetParm<typename E::Params>(state.range(0)));
  }
}

DO_NATIVEPOLY_BENCHMARK(BM_LATTICE_empty)
DO_POLY_BENCHMARK_TEMPLATE(BM_LATTICE_empty, M2Poly)
DO_POLY_BENCHMARK_TEMPLATE(BM_LATTICE_empty, M4Poly)
#ifdef WITH_NTL
DO_POLY_BENCHMARK_TEMPLATE(BM_LATTICE_empty, M6Poly)
#endif
DO_POLY_BENCHMARK_TEMPLATE(BM_LATTICE_empty, M2DCRTPoly)
DO_POLY_BENCHMARK_TEMPLATE(BM_LATTICE_empty, M4DCRTPoly)
#ifdef WITH_NTL
DO_POLY_BENCHMARK_TEMPLATE(BM_LATTICE_empty, M6DCRTPoly)
#endif

template <typename E>
static void make_LATTICE_vector(
    benchmark::State &state,
    shared_ptr<typename E::Params> params) {  // function
  E elem = makeElement<E>(params);
}

template <typename E>
void BM_LATTICE_makevector(benchmark::State &state) {  // benchmark
  if (state.thread_index == 0) {
    ;
  }

  while (state.KeepRunning()) {
    make_LATTICE_vector<E>(
        state, TestParameters.GetParm<typename E::Params>(state.range(0)));
  }
}

DO_NATIVEPOLY_BENCHMARK(BM_LATTICE_makevector)
DO_POLY_BENCHMARK_TEMPLATE(BM_LATTICE_makevector, M2Poly)
DO_POLY_BENCHMARK_TEMPLATE(BM_LATTICE_makevector, M4Poly)
#ifdef WITH_NTL
DO_POLY_BENCHMARK_TEMPLATE(BM_LATTICE_makevector, M6Poly)
#endif
DO_POLY_BENCHMARK_TEMPLATE(BM_LATTICE_makevector, M2DCRTPoly)
DO_POLY_BENCHMARK_TEMPLATE(BM_LATTICE_makevector, M4DCRTPoly)
#ifdef WITH_NTL
DO_POLY_BENCHMARK_TEMPLATE(BM_LATTICE_makevector, M6DCRTPoly)
#endif

// plus
template <typename E>
static void add_LATTICE(const E &a, const E &b) {
  E c1;
  benchmark::DoNotOptimize(c1 = a + b);
}

template <typename E>
static void BM_add_LATTICE(benchmark::State &state) {  // benchmark
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

DO_NATIVEPOLY_BENCHMARK(BM_add_LATTICE)
DO_POLY_BENCHMARK_TEMPLATE(BM_add_LATTICE, M2Poly)
DO_POLY_BENCHMARK_TEMPLATE(BM_add_LATTICE, M4Poly)
#ifdef WITH_NTL
DO_POLY_BENCHMARK_TEMPLATE(BM_add_LATTICE, M6Poly)
#endif
DO_POLY_BENCHMARK_TEMPLATE(BM_add_LATTICE, M2DCRTPoly)
DO_POLY_BENCHMARK_TEMPLATE(BM_add_LATTICE, M4DCRTPoly)
#ifdef WITH_NTL
DO_POLY_BENCHMARK_TEMPLATE(BM_add_LATTICE, M6DCRTPoly)
#endif

// plus=
template <typename E>
static void addeq_LATTICE(E &a, const E &b) {
  benchmark::DoNotOptimize(a += b);
}

template <typename E>
static void BM_addeq_LATTICE(benchmark::State &state) {  // benchmark
  E a;
  E b;

  if (state.thread_index == 0) {
    b = TestParameters.GetPoly<E>(state.range(0), 1);
    a = TestParameters.GetPoly<E>(state.range(0), 0);
  }

  while (state.KeepRunning()) {
    // a = TestParameters.GetPoly<E>(state.range(0),0);
    addeq_LATTICE<E>(a, b);
  }
}

DO_NATIVEPOLY_BENCHMARK(BM_addeq_LATTICE)
DO_POLY_BENCHMARK_TEMPLATE(BM_addeq_LATTICE, M2Poly)
DO_POLY_BENCHMARK_TEMPLATE(BM_addeq_LATTICE, M4Poly)
#ifdef WITH_NTL
DO_POLY_BENCHMARK_TEMPLATE(BM_addeq_LATTICE, M6Poly)
#endif
DO_POLY_BENCHMARK_TEMPLATE(BM_addeq_LATTICE, M2DCRTPoly)
DO_POLY_BENCHMARK_TEMPLATE(BM_addeq_LATTICE, M4DCRTPoly)
#ifdef WITH_NTL
DO_POLY_BENCHMARK_TEMPLATE(BM_addeq_LATTICE, M6DCRTPoly)
#endif

template <class E>
static void mult_LATTICE(const E &a, const E &b) {  // function

  E c1;
  benchmark::DoNotOptimize(c1 = a * b);
}

template <class E>
static void BM_mult_LATTICE(benchmark::State &state) {
  E a, b;

  if (state.thread_index == 0) {
    a = TestParameters.GetPoly<E>(state.range(0), 0);
    b = TestParameters.GetPoly<E>(state.range(0), 1);
  }

  while (state.KeepRunning()) {
    mult_LATTICE<E>(a, b);
  }
}

DO_NATIVEPOLY_BENCHMARK(BM_mult_LATTICE)
DO_POLY_BENCHMARK_TEMPLATE(BM_mult_LATTICE, M2Poly)
DO_POLY_BENCHMARK_TEMPLATE(BM_mult_LATTICE, M4Poly)
#ifdef WITH_NTL
DO_POLY_BENCHMARK_TEMPLATE(BM_mult_LATTICE, M6Poly)
#endif
DO_POLY_BENCHMARK_TEMPLATE(BM_mult_LATTICE, M2DCRTPoly)
DO_POLY_BENCHMARK_TEMPLATE(BM_mult_LATTICE, M4DCRTPoly)
#ifdef WITH_NTL
DO_POLY_BENCHMARK_TEMPLATE(BM_mult_LATTICE, M6DCRTPoly)
#endif

template <class E>
static void multeq_LATTICE(E &a, const E &b) {  // function

  benchmark::DoNotOptimize(a *= b);
}

template <class E>
static void BM_multeq_LATTICE(benchmark::State &state) {  // benchmark
  E a, b;

  if (state.thread_index == 0) {
    b = TestParameters.GetPoly<E>(state.range(0), 1);
    a = TestParameters.GetPoly<E>(state.range(0), 0);
  }

  while (state.KeepRunning()) {
    // a = TestParameters.GetPoly<E>(state.range(0),0);
    multeq_LATTICE<E>(a, b);
  }
}

DO_NATIVEPOLY_BENCHMARK(BM_multeq_LATTICE)
DO_POLY_BENCHMARK_TEMPLATE(BM_multeq_LATTICE, M2Poly)
DO_POLY_BENCHMARK_TEMPLATE(BM_multeq_LATTICE, M4Poly)
#ifdef WITH_NTL
DO_POLY_BENCHMARK_TEMPLATE(BM_multeq_LATTICE, M6Poly)
#endif
DO_POLY_BENCHMARK_TEMPLATE(BM_multeq_LATTICE, M2DCRTPoly)
DO_POLY_BENCHMARK_TEMPLATE(BM_multeq_LATTICE, M4DCRTPoly)
#ifdef WITH_NTL
DO_POLY_BENCHMARK_TEMPLATE(BM_multeq_LATTICE, M6DCRTPoly)
#endif

template <class E>
static void switchformat_LATTICE(benchmark::State &state,
                                 shared_ptr<typename E::Params> params) {
  E a = TestParameters.GetPoly<E>(state.range(0), 0);
  a.SwitchFormat();
}

template <class E>
static void BM_switchformat_LATTICE(benchmark::State &state) {  // benchmark
  if (state.thread_index == 0) {
    ;
  }

  while (state.KeepRunning()) {
    switchformat_LATTICE<E>(
        state, TestParameters.GetParm<typename E::Params>(state.range(0)));
  }
}

DO_NATIVEPOLY_BENCHMARK(BM_switchformat_LATTICE)
DO_POLY_BENCHMARK_TEMPLATE(BM_switchformat_LATTICE, M2Poly)
DO_POLY_BENCHMARK_TEMPLATE(BM_switchformat_LATTICE, M4Poly)
#ifdef WITH_NTL
DO_POLY_BENCHMARK_TEMPLATE(BM_switchformat_LATTICE, M6Poly)
#endif
DO_POLY_BENCHMARK_TEMPLATE(BM_switchformat_LATTICE, M2DCRTPoly)
DO_POLY_BENCHMARK_TEMPLATE(BM_switchformat_LATTICE, M4DCRTPoly)
#ifdef WITH_NTL
DO_POLY_BENCHMARK_TEMPLATE(BM_switchformat_LATTICE, M6DCRTPoly)
#endif

template <class E>
static void doubleswitchformat_LATTICE(benchmark::State &state,
                                       shared_ptr<typename E::Params> params) {
  E a = TestParameters.GetPoly<E>(state.range(0), 0);

  a.SwitchFormat();
  a.SwitchFormat();
}

template <class E>
static void BM_doubleswitchformat_LATTICE(
    benchmark::State &state) {  // benchmark
  if (state.thread_index == 0) {
    ;
  }

  while (state.KeepRunning()) {
    doubleswitchformat_LATTICE<E>(
        state, TestParameters.GetParm<typename E::Params>(state.range(0)));
  }
}

DO_NATIVEPOLY_BENCHMARK(BM_doubleswitchformat_LATTICE)
DO_POLY_BENCHMARK_TEMPLATE(BM_doubleswitchformat_LATTICE, M2Poly)
DO_POLY_BENCHMARK_TEMPLATE(BM_doubleswitchformat_LATTICE, M4Poly)
#ifdef WITH_NTL
DO_POLY_BENCHMARK_TEMPLATE(BM_doubleswitchformat_LATTICE, M6Poly)
#endif
DO_POLY_BENCHMARK_TEMPLATE(BM_doubleswitchformat_LATTICE, M2DCRTPoly)
DO_POLY_BENCHMARK_TEMPLATE(BM_doubleswitchformat_LATTICE, M4DCRTPoly)
#ifdef WITH_NTL
DO_POLY_BENCHMARK_TEMPLATE(BM_doubleswitchformat_LATTICE, M6DCRTPoly)
#endif

// execute the benchmarks
BENCHMARK_MAIN();
