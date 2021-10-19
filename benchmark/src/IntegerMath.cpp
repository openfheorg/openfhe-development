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
  This code benchmarks functions of the math directory  of the PALISADE lattice
  encryption library.
*/
#define _USE_MATH_DEFINES
#include "benchmark/benchmark.h"

#include "palisade.h"

#include <iostream>
#include <vector>

using namespace std;
using namespace lbcrypto;

#define DO_BENCHMARK_TEMPLATE(X, Y) \
  BENCHMARK_TEMPLATE(X, Y)->Unit(benchmark::kMicrosecond);

// four simple benchmarks to test constructing BigInts
// typically the code to benchmark is in a 'function' that is then
// called within the actual benchmark.

// test BigInt constants
template <typename I>
static void make_BigInt_constants(void) {  // function
  I one(1);
}

template <typename I>
void BM_BigInt_constants(benchmark::State& state) {  // benchmark
  while (state.KeepRunning()) {
    make_BigInt_constants<I>();
  }
}

DO_BENCHMARK_TEMPLATE(BM_BigInt_constants, M2Integer)
DO_BENCHMARK_TEMPLATE(BM_BigInt_constants, M4Integer)
#ifdef WITH_NTL
DO_BENCHMARK_TEMPLATE(BM_BigInt_constants, M6Integer)
#endif
DO_BENCHMARK_TEMPLATE(BM_BigInt_constants, NativeInteger)

template <typename I>
static void make_BigInt_small_variables(void) {  // function
  I a("10403"), b("103");
}

template <typename I>
void BM_BigInt_small_variables(benchmark::State& state) {  // benchmark
  while (state.KeepRunning()) {
    make_BigInt_small_variables<I>();
  }
}

DO_BENCHMARK_TEMPLATE(BM_BigInt_small_variables, M2Integer)
DO_BENCHMARK_TEMPLATE(BM_BigInt_small_variables, M4Integer)
#ifdef WITH_NTL
DO_BENCHMARK_TEMPLATE(BM_BigInt_small_variables, M6Integer)
#endif
DO_BENCHMARK_TEMPLATE(BM_BigInt_small_variables, NativeInteger)

template <typename I>
static void make_BigInt_large_variables(void) {  // function
  I a("18446744073709551616"), b("18446744073709551617");
}

template <typename I>
void BM_BigInt_large_variables(benchmark::State& state) {  // benchmark
  while (state.KeepRunning()) {
    make_BigInt_large_variables<I>();
  }
}

DO_BENCHMARK_TEMPLATE(BM_BigInt_large_variables, M2Integer)
DO_BENCHMARK_TEMPLATE(BM_BigInt_large_variables, M4Integer)
#ifdef WITH_NTL
DO_BENCHMARK_TEMPLATE(BM_BigInt_large_variables, M6Integer)
#endif

static string smalla("10403"), smallb("103");
static string largea("18446744073709551616"), largeb("18446744073709551617");

// add
template <typename I>
static void add_BigInt(const I& a, const I& b) {  // function
  __attribute__((unused)) I c = a + b;
}

template <typename I>
static void BM_BigInt_Add(benchmark::State& state) {  // benchmark
  I a(state.range(0) == 0 ? smalla : largea);
  I b(state.range(0) == 0 ? smallb : largeb);

  while (state.KeepRunning()) {
    add_BigInt(a, b);
  }
}

BENCHMARK_TEMPLATE(BM_BigInt_Add, M2Integer)
    ->Unit(benchmark::kMicrosecond)
    ->ArgName("Small")
    ->Arg(0);
BENCHMARK_TEMPLATE(BM_BigInt_Add, M2Integer)
    ->Unit(benchmark::kMicrosecond)
    ->ArgName("Large")
    ->Arg(1);
BENCHMARK_TEMPLATE(BM_BigInt_Add, M4Integer)
    ->Unit(benchmark::kMicrosecond)
    ->ArgName("Small")
    ->Arg(0);
BENCHMARK_TEMPLATE(BM_BigInt_Add, M4Integer)
    ->Unit(benchmark::kMicrosecond)
    ->ArgName("Large")
    ->Arg(1);
#ifdef WITH_NTL
BENCHMARK_TEMPLATE(BM_BigInt_Add, M6Integer)
    ->Unit(benchmark::kMicrosecond)
    ->ArgName("Small")
    ->Arg(0);
BENCHMARK_TEMPLATE(BM_BigInt_Add, M6Integer)
    ->Unit(benchmark::kMicrosecond)
    ->ArgName("Large")
    ->Arg(1);
#endif
BENCHMARK_TEMPLATE(BM_BigInt_Add, NativeInteger)
    ->Unit(benchmark::kMicrosecond)
    ->ArgName("Small")
    ->Arg(0);

// +=
template <typename I>
static void addeq_BigInt(I& a, const I& b) {  // function
  a += b;
}

template <typename I>
static void BM_BigInt_Addeq(benchmark::State& state) {  // benchmark
  I b(state.range(0) == 0 ? smallb : largeb);

  while (state.KeepRunning()) {
    I a(state.range(0) == 0 ? smalla : largea);
    addeq_BigInt(a, b);
  }
}

BENCHMARK_TEMPLATE(BM_BigInt_Addeq, M2Integer)
    ->Unit(benchmark::kMicrosecond)
    ->ArgName("Small")
    ->Arg(0);
BENCHMARK_TEMPLATE(BM_BigInt_Addeq, M2Integer)
    ->Unit(benchmark::kMicrosecond)
    ->ArgName("Large")
    ->Arg(1);
BENCHMARK_TEMPLATE(BM_BigInt_Addeq, M4Integer)
    ->Unit(benchmark::kMicrosecond)
    ->ArgName("Small")
    ->Arg(0);
BENCHMARK_TEMPLATE(BM_BigInt_Addeq, M4Integer)
    ->Unit(benchmark::kMicrosecond)
    ->ArgName("Large")
    ->Arg(1);
#ifdef WITH_NTL
BENCHMARK_TEMPLATE(BM_BigInt_Addeq, M6Integer)
    ->Unit(benchmark::kMicrosecond)
    ->ArgName("Small")
    ->Arg(0);
BENCHMARK_TEMPLATE(BM_BigInt_Addeq, M6Integer)
    ->Unit(benchmark::kMicrosecond)
    ->ArgName("Large")
    ->Arg(1);
#endif
BENCHMARK_TEMPLATE(BM_BigInt_Addeq, NativeInteger)
    ->Unit(benchmark::kMicrosecond)
    ->ArgName("Small")
    ->Arg(0);

// mult
template <typename I>
static void mult_BigInt(const I& a, const I& b) {  // function
  __attribute__((unused)) I c1 = a * b;
}

template <typename I>
static void BM_BigInt_Mult(benchmark::State& state) {  // benchmark
  I a(state.range(0) == 0 ? smalla : largea);
  I b(state.range(0) == 0 ? smallb : largeb);

  while (state.KeepRunning()) {
    mult_BigInt(a, b);
  }
}

BENCHMARK_TEMPLATE(BM_BigInt_Mult, M2Integer)
    ->Unit(benchmark::kMicrosecond)
    ->ArgName("Small")
    ->Arg(0);
BENCHMARK_TEMPLATE(BM_BigInt_Mult, M2Integer)
    ->Unit(benchmark::kMicrosecond)
    ->ArgName("Large")
    ->Arg(1);
BENCHMARK_TEMPLATE(BM_BigInt_Mult, M4Integer)
    ->Unit(benchmark::kMicrosecond)
    ->ArgName("Small")
    ->Arg(0);
BENCHMARK_TEMPLATE(BM_BigInt_Mult, M4Integer)
    ->Unit(benchmark::kMicrosecond)
    ->ArgName("Large")
    ->Arg(1);
#ifdef WITH_NTL
BENCHMARK_TEMPLATE(BM_BigInt_Mult, M6Integer)
    ->Unit(benchmark::kMicrosecond)
    ->ArgName("Small")
    ->Arg(0);
BENCHMARK_TEMPLATE(BM_BigInt_Mult, M6Integer)
    ->Unit(benchmark::kMicrosecond)
    ->ArgName("Large")
    ->Arg(1);
#endif
BENCHMARK_TEMPLATE(BM_BigInt_Mult, NativeInteger)
    ->Unit(benchmark::kMicrosecond)
    ->ArgName("Small")
    ->Arg(0);

// *=
template <typename I>
static void multeq_BigInt(I& a, const I& b) {  // function
  a *= b;
}

template <typename I>
static void BM_BigInt_Multeq(benchmark::State& state) {  // benchmark
  I b(state.range(0) == 0 ? smallb : largeb);

  while (state.KeepRunning()) {
    I a(state.range(0) == 0 ? smalla : largea);
    multeq_BigInt(a, b);
  }
}

BENCHMARK_TEMPLATE(BM_BigInt_Multeq, M2Integer)
    ->Unit(benchmark::kMicrosecond)
    ->ArgName("Small")
    ->Arg(0);
BENCHMARK_TEMPLATE(BM_BigInt_Multeq, M2Integer)
    ->Unit(benchmark::kMicrosecond)
    ->ArgName("Large")
    ->Arg(1);
BENCHMARK_TEMPLATE(BM_BigInt_Multeq, M4Integer)
    ->Unit(benchmark::kMicrosecond)
    ->ArgName("Small")
    ->Arg(0);
BENCHMARK_TEMPLATE(BM_BigInt_Multeq, M4Integer)
    ->Unit(benchmark::kMicrosecond)
    ->ArgName("Large")
    ->Arg(1);
#ifdef WITH_NTL
BENCHMARK_TEMPLATE(BM_BigInt_Multeq, M6Integer)
    ->Unit(benchmark::kMicrosecond)
    ->ArgName("Small")
    ->Arg(0);
BENCHMARK_TEMPLATE(BM_BigInt_Multeq, M6Integer)
    ->Unit(benchmark::kMicrosecond)
    ->ArgName("Large")
    ->Arg(1);
#endif
BENCHMARK_TEMPLATE(BM_BigInt_Multeq, NativeInteger)
    ->Unit(benchmark::kMicrosecond)
    ->ArgName("Small")
    ->Arg(0);

template <typename I>
static void BM_BigInt_ModInverse(benchmark::State& state) {  // benchmark
  while (state.KeepRunning()) {
    I c = I(3017).ModInverse(I(108));
    PALISADE_UNUSED(c);
  }
}

BENCHMARK_TEMPLATE(BM_BigInt_ModInverse, M2Integer)
    ->Unit(benchmark::kMicrosecond);
BENCHMARK_TEMPLATE(BM_BigInt_ModInverse, M4Integer)
    ->Unit(benchmark::kMicrosecond);
#ifdef WITH_NTL
BENCHMARK_TEMPLATE(BM_BigInt_ModInverse, M6Integer)
    ->Unit(benchmark::kMicrosecond);
#endif
BENCHMARK_TEMPLATE(BM_BigInt_ModInverse, NativeInteger)
    ->Unit(benchmark::kMicrosecond);

template <typename I>
static void BM_BigInt_ModInverseEq(benchmark::State& state) {  // benchmark
  while (state.KeepRunning()) {
    I(3017).ModInverseEq(I(108));
  }
}

BENCHMARK_TEMPLATE(BM_BigInt_ModInverseEq, M2Integer)
    ->Unit(benchmark::kMicrosecond);
BENCHMARK_TEMPLATE(BM_BigInt_ModInverseEq, M4Integer)
    ->Unit(benchmark::kMicrosecond);
#ifdef WITH_NTL
BENCHMARK_TEMPLATE(BM_BigInt_ModInverseEq, M6Integer)
    ->Unit(benchmark::kMicrosecond);
#endif
BENCHMARK_TEMPLATE(BM_BigInt_ModInverseEq, NativeInteger)
    ->Unit(benchmark::kMicrosecond);

// execute the benchmarks
BENCHMARK_MAIN();
