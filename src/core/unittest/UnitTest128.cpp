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
  This file contains google test code that exercises the big int vector library of the OpenFHE lattice encryption library.
 */

#include "include/gtest/gtest.h"
#include <iostream>
#include <fstream>

#include "math/math-hal.h"
#include "utils/inttypes.h"
#include "math/nbtheory.h"

#include "math/distrgen.h"
#include "utils/utilities.h"
#include "lattice/lat-hal.h"

using namespace lbcrypto;

/************************************************
 *	TESTING Modular operations for 128-bit backend
 ************************************************/
#if (NATIVEINT == 128) && !defined(__EMSCRIPTEN__)
TEST(UT128, modular_operations) {
    intnat::NativeInteger modulus = ((intnat::NativeInteger(1) << 120) + intnat::NativeInteger(123456789));
    intnat::NativeInteger mu      = modulus.ComputeMu();

    intnat::NativeInteger a = (intnat::NativeInteger(1) << 110) + intnat::NativeInteger(1234);
    intnat::NativeInteger b = (intnat::NativeInteger(1) << 115) + intnat::NativeInteger(6789);

    intnat::NativeInteger c = (intnat::NativeInteger(1) << 120) + intnat::NativeInteger(6);

    intnat::NativeInteger result = a;

    result.ModMulEq(b, modulus, mu);

    EXPECT_EQ(BigInteger("784483038650039308657432244878529921"), BigInteger(result)) << "Failure in ModMulEq";

    result = a.ModMul(b, modulus, mu);

    EXPECT_EQ(BigInteger("784483038650039308657432244878529921"), BigInteger(result)) << "Failure in ModMul";

    result = a.ModMulFast(b, modulus, mu);

    EXPECT_EQ(BigInteger("784483038650039308657432244878529921"), BigInteger(result)) << "Failure in ModMulFast";

    result = a;

    result.ModMulFastEq(b, modulus, mu);

    EXPECT_EQ(BigInteger("784483038650039308657432244878529921"), BigInteger(result)) << "Failure in ModMulFastEq";

    intnat::NativeInteger precon = b.PrepModMulConst(modulus);

    result = a.ModMulFastConst(b, modulus, precon);

    EXPECT_EQ(BigInteger("784483038650039308657432244878529921"), BigInteger(result)) << "Failure in ModMulFastConst";

    result = a;

    result.ModMulFastConstEq(b, modulus, precon);

    EXPECT_EQ(BigInteger("784483038650039308657432244878529921"), BigInteger(result)) << "Failure in ModMulFastConstEq";

    result = a.ModExp(b, modulus);

    EXPECT_EQ(BigInteger("420836984722658338771647831749821018"), BigInteger(result)) << "Failure in ModExp";

    result = a;

    result.ModExpEq(b, modulus);

    EXPECT_EQ(BigInteger("420836984722658338771647831749821018"), BigInteger(result)) << "Failure in ModExpEq";

    result = a.ModAddFast(c, modulus);

    EXPECT_EQ(BigInteger("1298074214633706907132623958849475"), BigInteger(result)) << "Failure in ModAddFast";

    result = a.ModSubFast(c, modulus);

    EXPECT_EQ(BigInteger("1298074214633706907132624205763041"), BigInteger(result)) << "Failure in ModSubFast";

    result = a.ModInverse(modulus);

    EXPECT_EQ(BigInteger("859455677183853192994953853474516202"), BigInteger(result)) << "Failure in ModInverse";
}

TEST(UT128, NTT_operations) {
    usint m1   = 16;
    usint bits = 100;

    auto x1p = std::make_shared<ILNativeParams>(m1, bits);
    auto x2p = std::make_shared<ILNativeParams>(m1 / 2, bits);

    NativePoly x1(x1p, Format::COEFFICIENT);
    x1 = {431, 3414, 1234, 7845, 2145, 7415, 5471, 8452};

    NativePoly x2(x2p, Format::COEFFICIENT);
    x2 = {4127, 9647, 1987, 5410};

    NativePoly x1Clone(x1);
    NativePoly x2Clone(x2);

    x1.SwitchFormat();
    x2.SwitchFormat();
    x1.SwitchFormat();
    x2.SwitchFormat();

    EXPECT_EQ(x1, x1Clone) << "Failure in NTT test #1";
    EXPECT_EQ(x2, x2Clone) << "Failure in NTT test #2";
}

#endif
