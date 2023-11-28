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
  This code tests the transform feature of the OpenFHE lattice encryption library.

  Test cases in this file make the following assumptions:
  1. All functionatliy of plaintext (both BytePlainTextEncoding and IntPlainTextEncoding) work.
  2. Encrypt/Decrypt work
  3. Math layer operations such as functions in nbtheory
  */

#include <iostream>
#include "gtest/gtest.h"

#include "lattice/lat-hal.h"
#include "math/distrgen.h"
#include "math/nbtheory.h"
#include "testdefs.h"
#include "utils/inttypes.h"
#include "utils/utilities.h"

using namespace lbcrypto;

template <typename Element>
void switch_format_simple_single_crt(const std::string& msg) {
    using ParmType = typename Element::Params;

    usint m1   = 16;
    usint bits = 16;

    auto x1p = std::make_shared<ParmType>(m1, bits);
    auto x2p = std::make_shared<ParmType>(m1 / 2, bits);

    Element x1(x1p, Format::COEFFICIENT);
    x1 = {431, 3414, 1234, 7845, 2145, 7415, 5471, 8452};

    Element x2(x2p, Format::COEFFICIENT);
    x2 = {4127, 9647, 1987, 5410};

    Element x1Clone(x1);
    Element x2Clone(x2);

    x1.SwitchFormat();
    x2.SwitchFormat();
    x1.SwitchFormat();
    x2.SwitchFormat();

    EXPECT_EQ(x1, x1Clone) << msg;
    EXPECT_EQ(x2, x2Clone) << msg;
}

TEST(UTNTT, switch_format_simple_single_crt) {
    RUN_ALL_POLYS(switch_format_simple_single_crt, "switch_format_simple_single_crt")
}

template <typename Element>
void switch_format_simple_double_crt(const std::string& msg) {
    usint init_m    = 16;
    usint init_size = 2;
    usint init_bits = 28;

    auto params = std::make_shared<ILDCRTParams<typename Element::Integer>>(init_m, init_size, init_bits);

    Element x1(params, Format::COEFFICIENT);
    x1 = {431, 3414, 1234, 7845, 2145, 7415, 5471, 8452};

    Element x2(params, Format::COEFFICIENT);
    x2 = {4127, 9647, 1987, 5410, 6541, 7014, 9741, 1256};

    Element x1Clone(x1);
    Element x2Clone(x2);

    x1.SwitchFormat();
    x2.SwitchFormat();
    x1.SwitchFormat();
    x2.SwitchFormat();

    EXPECT_EQ(x1, x1Clone) << msg;
    EXPECT_EQ(x2, x2Clone) << msg;
}

TEST(UTNTT, switch_format_simple_double_crt) {
    RUN_BIG_DCRTPOLYS(switch_format_simple_double_crt, "switch_format_simple_double_crt")
}
