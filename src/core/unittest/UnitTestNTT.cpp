// @file
// @author TPOC: contact@palisade-crypto.org
//
// @copyright Copyright (c) 2019, New Jersey Institute of Technology (NJIT)
// All rights reserved.
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
// 1. Redistributions of source code must retain the above copyright notice,
// this list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright notice,
// this list of conditions and the following disclaimer in the documentation
// and/or other materials provided with the distribution. THIS SOFTWARE IS
// PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR
// IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO
// EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
// INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
// LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
// ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
/*
This code tests the transform feature of the PALISADE lattice encryption
library.

Test cases in this file make the following assumptions:
1. All functionatliy of plaintext (both BytePlainTextEncoding and
IntPlainTextEncoding) work.
2. Encrypt/Decrypt work
3. Math layer operations such as functions in nbtheory
*/

#include <iostream>
#include "gtest/gtest.h"

#include "lattice/backend.h"
#include "math/backend.h"
#include "math/distrgen.h"
#include "math/nbtheory.h"
#include "testdefs.h"
#include "utils/inttypes.h"
#include "utils/utilities.h"

using namespace std;
using namespace lbcrypto;

template <typename Element>
void switch_format_simple_single_crt(const string& msg) {
  using ParmType = typename Element::Params;

  usint m1 = 16;

  typename Element::Integer modulus =
      FirstPrime<typename Element::Integer>(22, m1);
  typename Element::Integer rootOfUnity(RootOfUnity(m1, modulus));
  ParmType params(m1, modulus, rootOfUnity);
  ParmType params2(m1 / 2, modulus, rootOfUnity);
  auto x1p = std::make_shared<ParmType>(params);
  auto x2p = std::make_shared<ParmType>(params2);

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
  RUN_ALL_POLYS(switch_format_simple_single_crt,
                "switch_format_simple_single_crt")
}

template <typename Element>
void switch_format_simple_double_crt(const string& msg) {
  usint init_m = 16;

  float init_stdDev = 4;

  usint init_size = 2;

  vector<NativeInteger> init_moduli(init_size);
  vector<NativeInteger> init_rootsOfUnity(init_size);

  NativeInteger q = FirstPrime<NativeInteger>(28, init_m);
  NativeInteger temp;
  typename Element::Integer modulus(1);

  for (size_t i = 0; i < init_size; i++) {
    init_moduli[i] = q;
    init_rootsOfUnity[i] = RootOfUnity(init_m, init_moduli[i]);
    modulus =
        modulus * typename Element::Integer(init_moduli[i].ConvertToInt());
    q = NextPrime(q, init_m);
  }

  DiscreteGaussianGeneratorImpl<typename Element::Vector> dgg(init_stdDev);

  auto params = std::make_shared<ILDCRTParams<typename Element::Integer>>(
      init_m, init_moduli, init_rootsOfUnity);

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
  RUN_BIG_DCRTPOLYS(switch_format_simple_double_crt,
                    "switch_format_simple_double_crt")
}
