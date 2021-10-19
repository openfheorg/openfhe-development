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

#define _USE_MATH_DEFINES
#include "benchmark/benchmark.h"

#include "palisade.h"

#include <iostream>
#include <vector>

#include "vechelper.h"

using namespace std;
using namespace lbcrypto;

namespace lbcrypto {

static vector<usint> tow_args({1, 2, 4, 8});

static const usint DCRTBITS = 60;
static const usint RING_DIM_LOG = 16;
static const size_t POLY_NUM = 16;
static const size_t POLY_NUM_M1 = (POLY_NUM - 1);

static NativePoly makeElement(shared_ptr<ILNativeParams> params,
                              Format format) {
  NativeVector vec = makeVector<NativeVector>(params->GetRingDimension(),
                                              params->GetModulus());
  NativePoly elem(params);
  elem.SetValues(vec, format);
  return elem;
}

static M2DCRTPoly makeElement(shared_ptr<M2DCRTParams> p, Format format) {
  shared_ptr<M2Params> params(
      new M2Params(p->GetCyclotomicOrder(), p->GetModulus(), 1));
  M2Vector vec =
      makeVector<M2Vector>(params->GetRingDimension(), params->GetModulus());

  M2DCRTPoly::PolyLargeType bigE(params);
  bigE.SetValues(vec, format);

  M2DCRTPoly elem(bigE, p);
  return elem;
}

static void GenerateNativeParms(shared_ptr<ILNativeParams> &parmArray) {
  uint32_t m = (1 << (RING_DIM_LOG + 1));
  NativeInteger firstInteger = FirstPrime<NativeInteger>(DCRTBITS, m);
  NativeInteger modulo = PreviousPrime<NativeInteger>(firstInteger, m);
  NativeInteger root = RootOfUnity<NativeInteger>(m, modulo);

  ChineseRemainderTransformFTT<NativeVector>::PreCompute(root, m, modulo);
  parmArray = shared_ptr<ILNativeParams>(new ILNativeParams(m, modulo, root));
}

static void GenerateDCRTParms(map<usint, shared_ptr<M2DCRTParams>> &parmArray) {
  for (usint t : tow_args) {
    uint32_t m = (1 << (RING_DIM_LOG + 1));

    vector<NativeInteger> moduli(t);
    vector<NativeInteger> roots(t);

    NativeInteger firstInteger = FirstPrime<NativeInteger>(DCRTBITS, m);
    moduli[0] = PreviousPrime<NativeInteger>(firstInteger, m);
    roots[0] = RootOfUnity<NativeInteger>(m, moduli[0]);

    for (size_t i = 1; i < t; i++) {
      moduli[i] = PreviousPrime<NativeInteger>(moduli[i - 1], m);
      roots[i] = RootOfUnity<NativeInteger>(m, moduli[i]);
    }

    ChineseRemainderTransformFTT<NativeVector>::PreCompute(roots, m, moduli);

    parmArray[t] = shared_ptr<M2DCRTParams>(new M2DCRTParams(m, moduli, roots));
  }
}

static void GeneratePolys(shared_ptr<ILNativeParams> parmArray,
                          shared_ptr<vector<NativePoly>> &polyArrayEval,
                          shared_ptr<vector<NativePoly>> &polyArrayCoef) {
  vector<NativePoly> vecEval;
  for (size_t i = 0; i < POLY_NUM; i++) {
    vecEval.push_back(makeElement(parmArray, Format::EVALUATION));
  }
  polyArrayEval = make_shared<vector<NativePoly>>(std::move(vecEval));

  vector<NativePoly> vecCoef;
  for (size_t i = 0; i < POLY_NUM; i++) {
    vecCoef.push_back(makeElement(parmArray, Format::COEFFICIENT));
  }
  polyArrayCoef = make_shared<vector<NativePoly>>(std::move(vecCoef));
}

static void GenerateDCRTPolys(
    map<usint, shared_ptr<M2DCRTParams>> &parmArray,
    map<usint, shared_ptr<vector<M2DCRTPoly>>> &polyArrayEval,
    map<usint, shared_ptr<vector<M2DCRTPoly>>> &polyArrayCoef) {
  for (auto &pair : parmArray) {
    vector<M2DCRTPoly> vecEval;
    for (size_t i = 0; i < POLY_NUM; i++) {
      vecEval.push_back(makeElement(parmArray[pair.first], Format::EVALUATION));
    }
    polyArrayEval[pair.first] =
        make_shared<vector<M2DCRTPoly>>(std::move(vecEval));
    vector<M2DCRTPoly> vecCoef;
    for (size_t i = 0; i < POLY_NUM; i++) {
      vecCoef.push_back(
          makeElement(parmArray[pair.first], Format::COEFFICIENT));
    }
    polyArrayCoef[pair.first] =
        make_shared<vector<M2DCRTPoly>>(std::move(vecCoef));
  }
}

}  // namespace lbcrypto

shared_ptr<ILNativeParams> Nativeparms;
map<usint, shared_ptr<M2DCRTParams>> DCRTparms;

shared_ptr<vector<NativePoly>> NativepolysEval;
map<usint, shared_ptr<vector<M2DCRTPoly>>> DCRTpolysEval;

shared_ptr<vector<NativePoly>> NativepolysCoef;
map<usint, shared_ptr<vector<M2DCRTPoly>>> DCRTpolysCoef;

class Setup {
 public:
  Setup() {
    GenerateNativeParms(Nativeparms);
    GenerateDCRTParms(DCRTparms);
    cerr << "Generating polynomials for the benchmark..." << endl;
    GeneratePolys(Nativeparms, NativepolysEval, NativepolysCoef);
    GenerateDCRTPolys(DCRTparms, DCRTpolysEval, DCRTpolysCoef);
    cerr << "Polynomials for the benchmark are generated" << endl;
  }
} TestParameters;

static void DCRTArguments(benchmark::internal::Benchmark *b) {
  for (usint t : tow_args) {
    b->ArgName("towers")->Arg(t);
  }
}

static void Native_add(benchmark::State &state) {  // benchmark
  shared_ptr<vector<NativePoly>> polys = NativepolysEval;
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

static void DCRT_add(benchmark::State &state) {  // benchmark
  shared_ptr<vector<M2DCRTPoly>> polys = DCRTpolysEval[state.range(0)];
  M2DCRTPoly *a, *b, c;
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

static void Native_mul(benchmark::State &state) {
  shared_ptr<vector<NativePoly>> polys = NativepolysEval;
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

static void DCRT_mul(benchmark::State &state) {
  shared_ptr<vector<M2DCRTPoly>> polys = DCRTpolysEval[state.range(0)];
  M2DCRTPoly *a, *b, c;
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

static void Native_ntt(benchmark::State &state) {
  shared_ptr<vector<NativePoly>> polys = NativepolysCoef;
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

static void DCRT_ntt(benchmark::State &state) {
  shared_ptr<vector<M2DCRTPoly>> polys = DCRTpolysCoef[state.range(0)];
  M2DCRTPoly a;
  size_t i = 0;

  while (state.KeepRunning()) {
    a = polys->operator[](i);
    i++;
    i = i & POLY_NUM_M1;
    a.SwitchFormat();
  }
}

BENCHMARK(DCRT_ntt)->Unit(benchmark::kMicrosecond)->Apply(DCRTArguments);

static void Native_intt(benchmark::State &state) {
  shared_ptr<vector<NativePoly>> polys = NativepolysEval;
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

static void DCRT_intt(benchmark::State &state) {
  shared_ptr<vector<M2DCRTPoly>> polys = DCRTpolysEval[state.range(0)];
  M2DCRTPoly a;
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
