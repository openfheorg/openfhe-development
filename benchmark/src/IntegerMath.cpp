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
  This code benchmarks integer operations.
*/
#define _USE_MATH_DEFINES
#include "lattice/lat-hal.h"

#include "benchmark/benchmark.h"

#include <iostream>
#include <vector>

using namespace lbcrypto;

static uint64_t smallva(10403), smallvb(103), smallvm(101101);
static std::string smalla("10403"), smallb("103"), smallm("101101");
static std::string largea("18446744073709551616"), largeb("18446744073709551617"), largem("1844674407370955471617");

template <typename I>
static void make_BigInt_small_val_ctor() {
    I a(smallva), b(smallvb), m(smallvm);
}

template <typename I>
void BM_BigInt_small_val_ctor(benchmark::State& state) {
    while (state.KeepRunning())
        make_BigInt_small_val_ctor<I>();
}

template <typename I>
static void make_BigInt_small_string_ctor() {
    I a(smalla), b(smallb), m(smallm);
}

template <typename I>
void BM_BigInt_small_string_ctor(benchmark::State& state) {
    while (state.KeepRunning())
        make_BigInt_small_string_ctor<I>();
}

template <typename I>
static void make_BigInt_large_string_ctor() {
    I a(largea), b(largeb), m(largem);
}

template <typename I>
void BM_BigInt_large_string_ctor(benchmark::State& state) {
    while (state.KeepRunning())
        make_BigInt_large_string_ctor<I>();
}

template <typename I>
static void add_BigInt(const I& a, const I& b) {
    __attribute__((unused)) I c = a + b;
}

template <typename I>
static void BM_BigInt_Add(benchmark::State& state) {
    I a(state.range(0) == 0 ? smalla : largea);
    I b(state.range(0) == 0 ? smallb : largeb);
    while (state.KeepRunning())
        add_BigInt(a, b);
}

template <typename I>
static void addeq_BigInt(I a, const I& b) {
    a += b;
}

// technically AddEq + copy ctor
// much more representative than previous AddEq + string ctor
template <typename I>
static void BM_BigInt_AddEq(benchmark::State& state) {
    I a(state.range(0) == 0 ? smalla : largea);
    I b(state.range(0) == 0 ? smallb : largeb);
    while (state.KeepRunning())
        addeq_BigInt(a, b);
}

template <typename I>
static void sub_BigInt(const I& a, const I& b) {
    __attribute__((unused)) I c = a - b;
}

template <typename I>
static void BM_BigInt_Sub(benchmark::State& state) {
    I a(state.range(0) == 0 ? smalla : largea);
    I b(state.range(0) == 0 ? smallb : largeb);
    while (state.KeepRunning())
        sub_BigInt(a, b);
}

template <typename I>
static void subeq_BigInt(I a, const I& b) {
    a -= b;
}

template <typename I>
static void BM_BigInt_SubEq(benchmark::State& state) {
    I a(state.range(0) == 0 ? smalla : largea);
    I b(state.range(0) == 0 ? smallb : largeb);
    while (state.KeepRunning())
        subeq_BigInt(a, b);
}

template <typename I>
static void mult_BigInt(const I& a, const I& b) {
    __attribute__((unused)) I c1 = a * b;
}

template <typename I>
static void BM_BigInt_Mult(benchmark::State& state) {
    I a(state.range(0) == 0 ? smalla : largea);
    I b(state.range(0) == 0 ? smallb : largeb);
    while (state.KeepRunning())
        mult_BigInt(a, b);
}

template <typename I>
static void multeq_BigInt(I a, const I& b) {
    a *= b;
}

template <typename I>
static void BM_BigInt_MultEq(benchmark::State& state) {
    I a(state.range(0) == 0 ? smalla : largea);
    I b(state.range(0) == 0 ? smallb : largeb);
    while (state.KeepRunning())
        multeq_BigInt(a, b);
}

template <typename I>
static void div_BigInt(const I& a, const I& b) {
    __attribute__((unused)) I c1 = a / b;
}

template <typename I>
static void BM_BigInt_DividedBy(benchmark::State& state) {
    I a(state.range(0) == 0 ? smalla : largea);
    I b(state.range(0) == 0 ? smallb : largeb);
    while (state.KeepRunning())
        div_BigInt(a, b);
}

template <typename I>
static void diveq_BigInt(I a, const I& b) {
    a /= b;
}

template <typename I>
static void BM_BigInt_DividedByEq(benchmark::State& state) {
    I a(state.range(0) == 0 ? smalla : largea);
    I b(state.range(0) == 0 ? smallb : largeb);
    while (state.KeepRunning())
        diveq_BigInt(a, b);
}

template <typename I>
static void exp_BigInt(const I& a, const usint& b) {
    __attribute__((unused)) I c1 = a.Exp(b);
}

template <typename I>
static void BM_BigInt_Exp(benchmark::State& state) {
    I a(state.range(0) == 0 ? smalla : largea);
    while (state.KeepRunning())
        exp_BigInt(a, 47);
}

template <typename I>
static void expeq_BigInt(I a, const usint& b) {
    a.ExpEq(b);
}

template <typename I>
static void BM_BigInt_ExpEq(benchmark::State& state) {
    I a(state.range(0) == 0 ? smalla : largea);
    while (state.KeepRunning())
        expeq_BigInt(a, 47);
}

template <typename I>
static void multround_BigInt(const I& a, const I& b, const I& m) {
    __attribute__((unused)) I c1 = a.MultiplyAndRound(b, m);
}

template <typename I>
static void BM_BigInt_MultiplyAndRound(benchmark::State& state) {
    I a(state.range(0) == 0 ? smalla : largea);
    I b(state.range(0) == 0 ? smallb : largeb);
    I m(state.range(0) == 0 ? smallm : largem);
    while (state.KeepRunning())
        multround_BigInt(a, b, m);
}

template <typename I>
static void multroundeq_BigInt(I a, const I& b, const I& m) {
    a.MultiplyAndRoundEq(b, m);
}

template <typename I>
static void BM_BigInt_MultiplyAndRoundEq(benchmark::State& state) {
    I a(state.range(0) == 0 ? smalla : largea);
    I b(state.range(0) == 0 ? smallb : largeb);
    I m(state.range(0) == 0 ? smallm : largem);
    while (state.KeepRunning())
        multroundeq_BigInt(a, b, m);
}

template <typename I>
static void lshift_BigInt(const I& a, const usshort& b) {
    __attribute__((unused)) I c1 = a.LShift(b);
}

template <typename I>
static void BM_BigInt_LShift(benchmark::State& state) {
    I a(state.range(0) == 0 ? smalla : largea);
    while (state.KeepRunning())
        lshift_BigInt(a, 11);
}

template <typename I>
static void lshifteq_BigInt(I a, const usshort& b) {
    a.LShiftEq(b);
}

template <typename I>
static void BM_BigInt_LShiftEq(benchmark::State& state) {
    I a(state.range(0) == 0 ? smalla : largea);
    while (state.KeepRunning())
        lshifteq_BigInt(a, 11);
}

template <typename I>
static void rshift_BigInt(const I& a, const usshort& b) {
    __attribute__((unused)) I c1 = a.RShift(b);
}

template <typename I>
static void BM_BigInt_RShift(benchmark::State& state) {
    I a(state.range(0) == 0 ? smalla : largea);
    while (state.KeepRunning())
        rshift_BigInt(a, 11);
}

template <typename I>
static void rshifteq_BigInt(I a, const usshort& b) {
    a.RShiftEq(b);
}

template <typename I>
static void BM_BigInt_RShiftEq(benchmark::State& state) {
    I a(state.range(0) == 0 ? smalla : largea);
    while (state.KeepRunning())
        rshifteq_BigInt(a, 11);
}

template <typename I>
static void mod_BigInt(const I& a, const I& b) {
    __attribute__((unused)) I c1 = a.Mod(b);
}

template <typename I>
static void BM_BigInt_Mod(benchmark::State& state) {
    I a(state.range(0) == 0 ? smalla : largea);
    I b(state.range(0) == 0 ? smallb : largeb);
    while (state.KeepRunning())
        mod_BigInt(a, b);
}

template <typename I>
static void modeq_BigInt(I a, const I& b) {
    a.ModEq(b);
}

template <typename I>
static void BM_BigInt_ModEq(benchmark::State& state) {
    I a(state.range(0) == 0 ? smalla : largea);
    I b(state.range(0) == 0 ? smallb : largeb);
    while (state.KeepRunning())
        modeq_BigInt(a, b);
}

template <typename I>
static void modadd_BigInt(const I& a, const I& b, const I& m) {
    __attribute__((unused)) I c1 = a.ModAdd(b, m);
}

template <typename I>
static void BM_BigInt_ModAdd(benchmark::State& state) {
    I a(state.range(0) == 0 ? smalla : largea);
    I b(state.range(0) == 0 ? smallb : largeb);
    I m(state.range(0) == 0 ? smallm : largem);
    while (state.KeepRunning())
        modadd_BigInt(a, b, m);
}

template <typename I>
static void modaddeq_BigInt(I a, const I& b, const I& m) {
    a.ModAddEq(b, m);
}

template <typename I>
static void BM_BigInt_ModAddEq(benchmark::State& state) {
    I a(state.range(0) == 0 ? smalla : largea);
    I b(state.range(0) == 0 ? smallb : largeb);
    I m(state.range(0) == 0 ? smallm : largem);
    while (state.KeepRunning())
        modaddeq_BigInt(a, b, m);
}

template <typename I>
static void modsub_BigInt(const I& a, const I& b, const I& m) {
    __attribute__((unused)) I c1 = a.ModSub(b, m);
}

template <typename I>
static void BM_BigInt_ModSub(benchmark::State& state) {
    I a(state.range(0) == 0 ? smalla : largea);
    I b(state.range(0) == 0 ? smallb : largeb);
    I m(state.range(0) == 0 ? smallm : largem);
    while (state.KeepRunning())
        modsub_BigInt(a, b, m);
}

template <typename I>
static void modsubeq_BigInt(I a, const I& b, const I& m) {
    a.ModSubEq(b, m);
}

template <typename I>
static void BM_BigInt_ModSubEq(benchmark::State& state) {
    I a(state.range(0) == 0 ? smalla : largea);
    I b(state.range(0) == 0 ? smallb : largeb);
    I m(state.range(0) == 0 ? smallm : largem);
    while (state.KeepRunning())
        modsubeq_BigInt(a, b, m);
}

template <typename I>
static void modaddfast_BigInt(const I& a, const I& b, const I& m) {
    __attribute__((unused)) I c1 = a.ModAddFast(b, m);
}

template <typename I>
static void BM_BigInt_ModAddFast(benchmark::State& state) {
    I a(state.range(0) == 0 ? smalla : largea);
    I b(state.range(0) == 0 ? smallb : largeb);
    I m(state.range(0) == 0 ? smallm : largem);
    while (state.KeepRunning())
        modaddfast_BigInt(a, b, m);
}

template <typename I>
static void modaddfasteq_BigInt(I a, const I& b, const I& m) {
    a.ModAddFastEq(b, m);
}

template <typename I>
static void BM_BigInt_ModAddFastEq(benchmark::State& state) {
    I a(state.range(0) == 0 ? smalla : largea);
    I b(state.range(0) == 0 ? smallb : largeb);
    I m(state.range(0) == 0 ? smallm : largem);
    while (state.KeepRunning())
        modaddfasteq_BigInt(a, b, m);
}

template <typename I>
static void modmult_BigInt(const I& a, const I& b, const I& m) {
    __attribute__((unused)) I c1 = a.ModMul(b, m);
}

template <typename I>
static void BM_BigInt_ModMult(benchmark::State& state) {
    I a(state.range(0) == 0 ? smalla : largea);
    I b(state.range(0) == 0 ? smallb : largeb);
    I m(state.range(0) == 0 ? smallm : largem);
    while (state.KeepRunning())
        modmult_BigInt(a, b, m);
}

template <typename I>
static void modmulteq_BigInt(I a, const I& b, const I& m) {
    a.ModMulEq(b, m);
}

template <typename I>
static void BM_BigInt_ModMultEq(benchmark::State& state) {
    I a(state.range(0) == 0 ? smalla : largea);
    I b(state.range(0) == 0 ? smallb : largeb);
    I m(state.range(0) == 0 ? smallm : largem);
    while (state.KeepRunning())
        modmulteq_BigInt(a, b, m);
}

template <typename I>
static void modexp_BigInt(const I& a, const I& b, const I& m) {
    __attribute__((unused)) I c1 = a.ModExp(b, m);
}

template <typename I>
static void BM_BigInt_ModExp(benchmark::State& state) {
    I a(state.range(0) == 0 ? smalla : largea);
    I b(state.range(0) == 0 ? smallb : largeb);
    I m(state.range(0) == 0 ? smallm : largem);
    while (state.KeepRunning())
        modexp_BigInt(a, b, m);
}

template <typename I>
static void modexpeq_BigInt(I a, const I& b, const I& m) {
    a.ModExpEq(b, m);
}

template <typename I>
static void BM_BigInt_ModExpEq(benchmark::State& state) {
    I a(state.range(0) == 0 ? smalla : largea);
    I b(state.range(0) == 0 ? smallb : largeb);
    I m(state.range(0) == 0 ? smallm : largem);
    while (state.KeepRunning())
        modexpeq_BigInt(a, b, m);
}

template <typename I>
static void modinv_BigInt(const I& a, const I& b) {
    __attribute__((unused)) I c1 = a.ModInverse(b);
}

template <typename I>
static void BM_BigInt_ModInverse(benchmark::State& state) {
    I a(state.range(0) == 0 ? smallm : largem);
    I b(state.range(0) == 0 ? smallb : largeb);
    while (state.KeepRunning())
        modinv_BigInt(a, b);
}

template <typename I>
static void modinveq_BigInt(I a, const I& b) {
    a.ModInverseEq(b);
}

template <typename I>
static void BM_BigInt_ModInverseEq(benchmark::State& state) {
    I a(state.range(0) == 0 ? smallm : largem);
    I b(state.range(0) == 0 ? smallb : largeb);
    while (state.KeepRunning())
        modinveq_BigInt(a, b);
}

#define DO_BENCHMARK_TEMPLATE(X, Y) BENCHMARK_TEMPLATE(X, Y)->Unit(benchmark::kMicrosecond);

// clang-format off
DO_BENCHMARK_TEMPLATE(BM_BigInt_small_val_ctor, NativeInteger)
DO_BENCHMARK_TEMPLATE(BM_BigInt_small_string_ctor, NativeInteger)
BENCHMARK_TEMPLATE(BM_BigInt_Add, NativeInteger)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(BM_BigInt_AddEq, NativeInteger)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(BM_BigInt_Sub, NativeInteger)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(BM_BigInt_SubEq, NativeInteger)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(BM_BigInt_Mult, NativeInteger)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(BM_BigInt_MultEq, NativeInteger)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(BM_BigInt_DividedBy, NativeInteger)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(BM_BigInt_DividedByEq, NativeInteger)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(BM_BigInt_Exp, NativeInteger)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(BM_BigInt_ExpEq, NativeInteger)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(BM_BigInt_MultiplyAndRound, NativeInteger)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(BM_BigInt_MultiplyAndRoundEq, NativeInteger)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(BM_BigInt_LShift, NativeInteger)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(BM_BigInt_LShiftEq, NativeInteger)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(BM_BigInt_RShift, NativeInteger)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(BM_BigInt_RShiftEq, NativeInteger)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(BM_BigInt_Mod, NativeInteger)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(BM_BigInt_ModEq, NativeInteger)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(BM_BigInt_ModAdd, NativeInteger)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(BM_BigInt_ModAddEq, NativeInteger)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(BM_BigInt_ModAddFast, NativeInteger)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(BM_BigInt_ModAddFastEq, NativeInteger)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(BM_BigInt_ModSub, NativeInteger)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(BM_BigInt_ModSubEq, NativeInteger)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(BM_BigInt_ModMult, NativeInteger)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(BM_BigInt_ModMultEq, NativeInteger)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(BM_BigInt_ModExp, NativeInteger)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(BM_BigInt_ModExpEq, NativeInteger)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(BM_BigInt_ModInverse, NativeInteger)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(BM_BigInt_ModInverseEq, NativeInteger)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);

#ifdef WITH_BE2
DO_BENCHMARK_TEMPLATE(BM_BigInt_small_val_ctor, M2Integer)
DO_BENCHMARK_TEMPLATE(BM_BigInt_small_string_ctor, M2Integer)
DO_BENCHMARK_TEMPLATE(BM_BigInt_large_string_ctor, M2Integer)
BENCHMARK_TEMPLATE(BM_BigInt_Add, M2Integer)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(BM_BigInt_Add, M2Integer)->Unit(benchmark::kMicrosecond)->ArgName("Large")->Arg(1);
BENCHMARK_TEMPLATE(BM_BigInt_AddEq, M2Integer)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(BM_BigInt_AddEq, M2Integer)->Unit(benchmark::kMicrosecond)->ArgName("Large")->Arg(1);
BENCHMARK_TEMPLATE(BM_BigInt_Sub, M2Integer)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(BM_BigInt_Sub, M2Integer)->Unit(benchmark::kMicrosecond)->ArgName("Large")->Arg(1);
BENCHMARK_TEMPLATE(BM_BigInt_SubEq, M2Integer)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(BM_BigInt_SubEq, M2Integer)->Unit(benchmark::kMicrosecond)->ArgName("Large")->Arg(1);
BENCHMARK_TEMPLATE(BM_BigInt_Mult, M2Integer)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(BM_BigInt_Mult, M2Integer)->Unit(benchmark::kMicrosecond)->ArgName("Large")->Arg(1);
BENCHMARK_TEMPLATE(BM_BigInt_MultEq, M2Integer)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(BM_BigInt_MultEq, M2Integer)->Unit(benchmark::kMicrosecond)->ArgName("Large")->Arg(1);
BENCHMARK_TEMPLATE(BM_BigInt_DividedBy, M2Integer)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(BM_BigInt_DividedBy, M2Integer)->Unit(benchmark::kMicrosecond)->ArgName("Large")->Arg(1);
BENCHMARK_TEMPLATE(BM_BigInt_DividedByEq, M2Integer)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(BM_BigInt_DividedByEq, M2Integer)->Unit(benchmark::kMicrosecond)->ArgName("Large")->Arg(1);
BENCHMARK_TEMPLATE(BM_BigInt_Exp, M2Integer)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(BM_BigInt_Exp, M2Integer)->Unit(benchmark::kMicrosecond)->ArgName("Large")->Arg(1);
BENCHMARK_TEMPLATE(BM_BigInt_ExpEq, M2Integer)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(BM_BigInt_ExpEq, M2Integer)->Unit(benchmark::kMicrosecond)->ArgName("Large")->Arg(1);
BENCHMARK_TEMPLATE(BM_BigInt_MultiplyAndRound, M2Integer)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(BM_BigInt_MultiplyAndRound, M2Integer)->Unit(benchmark::kMicrosecond)->ArgName("Large")->Arg(1);
BENCHMARK_TEMPLATE(BM_BigInt_MultiplyAndRoundEq, M2Integer)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(BM_BigInt_MultiplyAndRoundEq, M2Integer)->Unit(benchmark::kMicrosecond)->ArgName("Large")->Arg(1);
BENCHMARK_TEMPLATE(BM_BigInt_LShift, M2Integer)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(BM_BigInt_LShift, M2Integer)->Unit(benchmark::kMicrosecond)->ArgName("Large")->Arg(1);
BENCHMARK_TEMPLATE(BM_BigInt_LShiftEq, M2Integer)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(BM_BigInt_LShiftEq, M2Integer)->Unit(benchmark::kMicrosecond)->ArgName("Large")->Arg(1);
BENCHMARK_TEMPLATE(BM_BigInt_RShift, M2Integer)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(BM_BigInt_RShift, M2Integer)->Unit(benchmark::kMicrosecond)->ArgName("Large")->Arg(1);
BENCHMARK_TEMPLATE(BM_BigInt_RShiftEq, M2Integer)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(BM_BigInt_RShiftEq, M2Integer)->Unit(benchmark::kMicrosecond)->ArgName("Large")->Arg(1);
BENCHMARK_TEMPLATE(BM_BigInt_Mod, M2Integer)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(BM_BigInt_Mod, M2Integer)->Unit(benchmark::kMicrosecond)->ArgName("Large")->Arg(1);
BENCHMARK_TEMPLATE(BM_BigInt_ModEq, M2Integer)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(BM_BigInt_ModEq, M2Integer)->Unit(benchmark::kMicrosecond)->ArgName("Large")->Arg(1);
BENCHMARK_TEMPLATE(BM_BigInt_ModAdd, M2Integer)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(BM_BigInt_ModAdd, M2Integer)->Unit(benchmark::kMicrosecond)->ArgName("Large")->Arg(1);
BENCHMARK_TEMPLATE(BM_BigInt_ModAddEq, M2Integer)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(BM_BigInt_ModAddEq, M2Integer)->Unit(benchmark::kMicrosecond)->ArgName("Large")->Arg(1);
BENCHMARK_TEMPLATE(BM_BigInt_ModAddFast, M2Integer)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(BM_BigInt_ModAddFast, M2Integer)->Unit(benchmark::kMicrosecond)->ArgName("Large")->Arg(1);
BENCHMARK_TEMPLATE(BM_BigInt_ModAddFastEq, M2Integer)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(BM_BigInt_ModAddFastEq, M2Integer)->Unit(benchmark::kMicrosecond)->ArgName("Large")->Arg(1);
BENCHMARK_TEMPLATE(BM_BigInt_ModSub, M2Integer)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(BM_BigInt_ModSub, M2Integer)->Unit(benchmark::kMicrosecond)->ArgName("Large")->Arg(1);
BENCHMARK_TEMPLATE(BM_BigInt_ModSubEq, M2Integer)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(BM_BigInt_ModSubEq, M2Integer)->Unit(benchmark::kMicrosecond)->ArgName("Large")->Arg(1);
BENCHMARK_TEMPLATE(BM_BigInt_ModMult, M2Integer)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(BM_BigInt_ModMult, M2Integer)->Unit(benchmark::kMicrosecond)->ArgName("Large")->Arg(1);
BENCHMARK_TEMPLATE(BM_BigInt_ModMultEq, M2Integer)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(BM_BigInt_ModMultEq, M2Integer)->Unit(benchmark::kMicrosecond)->ArgName("Large")->Arg(1);
BENCHMARK_TEMPLATE(BM_BigInt_ModExp, M2Integer)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(BM_BigInt_ModExp, M2Integer)->Unit(benchmark::kMicrosecond)->ArgName("Large")->Arg(1);
BENCHMARK_TEMPLATE(BM_BigInt_ModExpEq, M2Integer)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(BM_BigInt_ModExpEq, M2Integer)->Unit(benchmark::kMicrosecond)->ArgName("Large")->Arg(1);
BENCHMARK_TEMPLATE(BM_BigInt_ModInverse, M2Integer)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(BM_BigInt_ModInverse, M2Integer)->Unit(benchmark::kMicrosecond)->ArgName("Large")->Arg(1);
BENCHMARK_TEMPLATE(BM_BigInt_ModInverseEq, M2Integer)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(BM_BigInt_ModInverseEq, M2Integer)->Unit(benchmark::kMicrosecond)->ArgName("Large")->Arg(1);
#endif
#ifdef WITH_BE4
DO_BENCHMARK_TEMPLATE(BM_BigInt_small_val_ctor, M4Integer)
DO_BENCHMARK_TEMPLATE(BM_BigInt_small_string_ctor, M4Integer)
DO_BENCHMARK_TEMPLATE(BM_BigInt_large_string_ctor, M4Integer)
BENCHMARK_TEMPLATE(BM_BigInt_Add, M4Integer)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(BM_BigInt_Add, M4Integer)->Unit(benchmark::kMicrosecond)->ArgName("Large")->Arg(1);
BENCHMARK_TEMPLATE(BM_BigInt_AddEq, M4Integer)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(BM_BigInt_AddEq, M4Integer)->Unit(benchmark::kMicrosecond)->ArgName("Large")->Arg(1);
BENCHMARK_TEMPLATE(BM_BigInt_Sub, M4Integer)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(BM_BigInt_Sub, M4Integer)->Unit(benchmark::kMicrosecond)->ArgName("Large")->Arg(1);
BENCHMARK_TEMPLATE(BM_BigInt_SubEq, M4Integer)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(BM_BigInt_SubEq, M4Integer)->Unit(benchmark::kMicrosecond)->ArgName("Large")->Arg(1);
BENCHMARK_TEMPLATE(BM_BigInt_Mult, M4Integer)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(BM_BigInt_Mult, M4Integer)->Unit(benchmark::kMicrosecond)->ArgName("Large")->Arg(1);
BENCHMARK_TEMPLATE(BM_BigInt_MultEq, M4Integer)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(BM_BigInt_MultEq, M4Integer)->Unit(benchmark::kMicrosecond)->ArgName("Large")->Arg(1);
BENCHMARK_TEMPLATE(BM_BigInt_DividedBy, M4Integer)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(BM_BigInt_DividedBy, M4Integer)->Unit(benchmark::kMicrosecond)->ArgName("Large")->Arg(1);
BENCHMARK_TEMPLATE(BM_BigInt_DividedByEq, M4Integer)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(BM_BigInt_DividedByEq, M4Integer)->Unit(benchmark::kMicrosecond)->ArgName("Large")->Arg(1);
BENCHMARK_TEMPLATE(BM_BigInt_Exp, M4Integer)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(BM_BigInt_Exp, M4Integer)->Unit(benchmark::kMicrosecond)->ArgName("Large")->Arg(1);
BENCHMARK_TEMPLATE(BM_BigInt_ExpEq, M4Integer)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(BM_BigInt_ExpEq, M4Integer)->Unit(benchmark::kMicrosecond)->ArgName("Large")->Arg(1);
BENCHMARK_TEMPLATE(BM_BigInt_MultiplyAndRound, M4Integer)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(BM_BigInt_MultiplyAndRound, M4Integer)->Unit(benchmark::kMicrosecond)->ArgName("Large")->Arg(1);
BENCHMARK_TEMPLATE(BM_BigInt_MultiplyAndRoundEq, M4Integer)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(BM_BigInt_MultiplyAndRoundEq, M4Integer)->Unit(benchmark::kMicrosecond)->ArgName("Large")->Arg(1);
BENCHMARK_TEMPLATE(BM_BigInt_LShift, M4Integer)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(BM_BigInt_LShift, M4Integer)->Unit(benchmark::kMicrosecond)->ArgName("Large")->Arg(1);
BENCHMARK_TEMPLATE(BM_BigInt_LShiftEq, M4Integer)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(BM_BigInt_LShiftEq, M4Integer)->Unit(benchmark::kMicrosecond)->ArgName("Large")->Arg(1);
BENCHMARK_TEMPLATE(BM_BigInt_RShift, M4Integer)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(BM_BigInt_RShift, M4Integer)->Unit(benchmark::kMicrosecond)->ArgName("Large")->Arg(1);
BENCHMARK_TEMPLATE(BM_BigInt_RShiftEq, M4Integer)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(BM_BigInt_RShiftEq, M4Integer)->Unit(benchmark::kMicrosecond)->ArgName("Large")->Arg(1);
BENCHMARK_TEMPLATE(BM_BigInt_Mod, M4Integer)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(BM_BigInt_Mod, M4Integer)->Unit(benchmark::kMicrosecond)->ArgName("Large")->Arg(1);
BENCHMARK_TEMPLATE(BM_BigInt_ModEq, M4Integer)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(BM_BigInt_ModEq, M4Integer)->Unit(benchmark::kMicrosecond)->ArgName("Large")->Arg(1);
BENCHMARK_TEMPLATE(BM_BigInt_ModAdd, M4Integer)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(BM_BigInt_ModAdd, M4Integer)->Unit(benchmark::kMicrosecond)->ArgName("Large")->Arg(1);
BENCHMARK_TEMPLATE(BM_BigInt_ModAddEq, M4Integer)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(BM_BigInt_ModAddEq, M4Integer)->Unit(benchmark::kMicrosecond)->ArgName("Large")->Arg(1);
BENCHMARK_TEMPLATE(BM_BigInt_ModAddFast, M4Integer)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(BM_BigInt_ModAddFast, M4Integer)->Unit(benchmark::kMicrosecond)->ArgName("Large")->Arg(1);
BENCHMARK_TEMPLATE(BM_BigInt_ModAddFastEq, M4Integer)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(BM_BigInt_ModAddFastEq, M4Integer)->Unit(benchmark::kMicrosecond)->ArgName("Large")->Arg(1);
BENCHMARK_TEMPLATE(BM_BigInt_ModSub, M4Integer)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(BM_BigInt_ModSub, M4Integer)->Unit(benchmark::kMicrosecond)->ArgName("Large")->Arg(1);
BENCHMARK_TEMPLATE(BM_BigInt_ModSubEq, M4Integer)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(BM_BigInt_ModSubEq, M4Integer)->Unit(benchmark::kMicrosecond)->ArgName("Large")->Arg(1);
BENCHMARK_TEMPLATE(BM_BigInt_ModMult, M4Integer)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(BM_BigInt_ModMult, M4Integer)->Unit(benchmark::kMicrosecond)->ArgName("Large")->Arg(1);
BENCHMARK_TEMPLATE(BM_BigInt_ModMultEq, M4Integer)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(BM_BigInt_ModMultEq, M4Integer)->Unit(benchmark::kMicrosecond)->ArgName("Large")->Arg(1);
BENCHMARK_TEMPLATE(BM_BigInt_ModExp, M4Integer)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(BM_BigInt_ModExp, M4Integer)->Unit(benchmark::kMicrosecond)->ArgName("Large")->Arg(1);
BENCHMARK_TEMPLATE(BM_BigInt_ModExpEq, M4Integer)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(BM_BigInt_ModExpEq, M4Integer)->Unit(benchmark::kMicrosecond)->ArgName("Large")->Arg(1);
BENCHMARK_TEMPLATE(BM_BigInt_ModInverse, M4Integer)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(BM_BigInt_ModInverse, M4Integer)->Unit(benchmark::kMicrosecond)->ArgName("Large")->Arg(1);
BENCHMARK_TEMPLATE(BM_BigInt_ModInverseEq, M4Integer)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(BM_BigInt_ModInverseEq, M4Integer)->Unit(benchmark::kMicrosecond)->ArgName("Large")->Arg(1);
#endif
#ifdef WITH_NTL
DO_BENCHMARK_TEMPLATE(BM_BigInt_small_val_ctor, M6Integer)
DO_BENCHMARK_TEMPLATE(BM_BigInt_small_string_ctor, M6Integer)
DO_BENCHMARK_TEMPLATE(BM_BigInt_large_string_ctor, M6Integer)
BENCHMARK_TEMPLATE(BM_BigInt_Add, M6Integer)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(BM_BigInt_Add, M6Integer)->Unit(benchmark::kMicrosecond)->ArgName("Large")->Arg(1);
BENCHMARK_TEMPLATE(BM_BigInt_AddEq, M6Integer)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(BM_BigInt_AddEq, M6Integer)->Unit(benchmark::kMicrosecond)->ArgName("Large")->Arg(1);
BENCHMARK_TEMPLATE(BM_BigInt_Sub, M6Integer)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(BM_BigInt_Sub, M6Integer)->Unit(benchmark::kMicrosecond)->ArgName("Large")->Arg(1);
BENCHMARK_TEMPLATE(BM_BigInt_SubEq, M6Integer)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(BM_BigInt_SubEq, M6Integer)->Unit(benchmark::kMicrosecond)->ArgName("Large")->Arg(1);
BENCHMARK_TEMPLATE(BM_BigInt_Mult, M6Integer)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(BM_BigInt_Mult, M6Integer)->Unit(benchmark::kMicrosecond)->ArgName("Large")->Arg(1);
BENCHMARK_TEMPLATE(BM_BigInt_MultEq, M6Integer)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(BM_BigInt_MultEq, M6Integer)->Unit(benchmark::kMicrosecond)->ArgName("Large")->Arg(1);
BENCHMARK_TEMPLATE(BM_BigInt_DividedBy, M6Integer)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(BM_BigInt_DividedBy, M6Integer)->Unit(benchmark::kMicrosecond)->ArgName("Large")->Arg(1);
BENCHMARK_TEMPLATE(BM_BigInt_DividedByEq, M6Integer)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(BM_BigInt_DividedByEq, M6Integer)->Unit(benchmark::kMicrosecond)->ArgName("Large")->Arg(1);
BENCHMARK_TEMPLATE(BM_BigInt_Exp, M6Integer)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(BM_BigInt_Exp, M6Integer)->Unit(benchmark::kMicrosecond)->ArgName("Large")->Arg(1);
BENCHMARK_TEMPLATE(BM_BigInt_ExpEq, M6Integer)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(BM_BigInt_ExpEq, M6Integer)->Unit(benchmark::kMicrosecond)->ArgName("Large")->Arg(1);
BENCHMARK_TEMPLATE(BM_BigInt_MultiplyAndRound, M6Integer)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(BM_BigInt_MultiplyAndRound, M6Integer)->Unit(benchmark::kMicrosecond)->ArgName("Large")->Arg(1);
BENCHMARK_TEMPLATE(BM_BigInt_MultiplyAndRoundEq, M6Integer)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(BM_BigInt_MultiplyAndRoundEq, M6Integer)->Unit(benchmark::kMicrosecond)->ArgName("Large")->Arg(1);
BENCHMARK_TEMPLATE(BM_BigInt_LShift, M6Integer)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(BM_BigInt_LShift, M6Integer)->Unit(benchmark::kMicrosecond)->ArgName("Large")->Arg(1);
BENCHMARK_TEMPLATE(BM_BigInt_LShiftEq, M6Integer)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(BM_BigInt_LShiftEq, M6Integer)->Unit(benchmark::kMicrosecond)->ArgName("Large")->Arg(1);
BENCHMARK_TEMPLATE(BM_BigInt_RShift, M6Integer)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(BM_BigInt_RShift, M6Integer)->Unit(benchmark::kMicrosecond)->ArgName("Large")->Arg(1);
BENCHMARK_TEMPLATE(BM_BigInt_RShiftEq, M6Integer)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(BM_BigInt_RShiftEq, M6Integer)->Unit(benchmark::kMicrosecond)->ArgName("Large")->Arg(1);
BENCHMARK_TEMPLATE(BM_BigInt_Mod, M6Integer)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(BM_BigInt_Mod, M6Integer)->Unit(benchmark::kMicrosecond)->ArgName("Large")->Arg(1);
BENCHMARK_TEMPLATE(BM_BigInt_ModEq, M6Integer)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(BM_BigInt_ModEq, M6Integer)->Unit(benchmark::kMicrosecond)->ArgName("Large")->Arg(1);
BENCHMARK_TEMPLATE(BM_BigInt_ModAdd, M6Integer)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(BM_BigInt_ModAdd, M6Integer)->Unit(benchmark::kMicrosecond)->ArgName("Large")->Arg(1);
BENCHMARK_TEMPLATE(BM_BigInt_ModAddEq, M6Integer)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(BM_BigInt_ModAddEq, M6Integer)->Unit(benchmark::kMicrosecond)->ArgName("Large")->Arg(1);
BENCHMARK_TEMPLATE(BM_BigInt_ModAddFast, M6Integer)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(BM_BigInt_ModAddFast, M6Integer)->Unit(benchmark::kMicrosecond)->ArgName("Large")->Arg(1);
BENCHMARK_TEMPLATE(BM_BigInt_ModAddFastEq, M6Integer)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(BM_BigInt_ModAddFastEq, M6Integer)->Unit(benchmark::kMicrosecond)->ArgName("Large")->Arg(1);
BENCHMARK_TEMPLATE(BM_BigInt_ModSub, M6Integer)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(BM_BigInt_ModSub, M6Integer)->Unit(benchmark::kMicrosecond)->ArgName("Large")->Arg(1);
BENCHMARK_TEMPLATE(BM_BigInt_ModSubEq, M6Integer)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(BM_BigInt_ModSubEq, M6Integer)->Unit(benchmark::kMicrosecond)->ArgName("Large")->Arg(1);
BENCHMARK_TEMPLATE(BM_BigInt_ModMult, M6Integer)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(BM_BigInt_ModMult, M6Integer)->Unit(benchmark::kMicrosecond)->ArgName("Large")->Arg(1);
BENCHMARK_TEMPLATE(BM_BigInt_ModMultEq, M6Integer)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(BM_BigInt_ModMultEq, M6Integer)->Unit(benchmark::kMicrosecond)->ArgName("Large")->Arg(1);
BENCHMARK_TEMPLATE(BM_BigInt_ModExp, M6Integer)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(BM_BigInt_ModExp, M6Integer)->Unit(benchmark::kMicrosecond)->ArgName("Large")->Arg(1);
BENCHMARK_TEMPLATE(BM_BigInt_ModExpEq, M6Integer)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(BM_BigInt_ModExpEq, M6Integer)->Unit(benchmark::kMicrosecond)->ArgName("Large")->Arg(1);
BENCHMARK_TEMPLATE(BM_BigInt_ModInverse, M6Integer)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(BM_BigInt_ModInverse, M6Integer)->Unit(benchmark::kMicrosecond)->ArgName("Large")->Arg(1);
BENCHMARK_TEMPLATE(BM_BigInt_ModInverseEq, M6Integer)->Unit(benchmark::kMicrosecond)->ArgName("Small")->Arg(0);
BENCHMARK_TEMPLATE(BM_BigInt_ModInverseEq, M6Integer)->Unit(benchmark::kMicrosecond)->ArgName("Large")->Arg(1);
#endif
// clang-format on

// execute the benchmarks
BENCHMARK_MAIN();
