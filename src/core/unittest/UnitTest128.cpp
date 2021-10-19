/*
 * @file
 * @author  TPOC: contact@palisade-crypto.org
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
 *  This file contains google test code that exercises the big int
 *  vector library of the PALISADE lattice encryption library.
 *
 */

#include "include/gtest/gtest.h"
#include <iostream>
#include <fstream>

#include "lattice/dcrtpoly.h"
#include "math/backend.h"
#include "utils/inttypes.h"
#include "math/nbtheory.h"

#include "math/distrgen.h"
#include "utils/utilities.h"
#include "lattice/backend.h"

using namespace std;
using namespace lbcrypto;

/************************************************
 *	TESTING Modular operations for 128-bit backend
 ************************************************/
#if (NATIVEINT == 128)
TEST(UT128, modular_operations) {
  bigintnat::NativeInteger modulus = ((bigintnat::NativeInteger(1) << 120) +
                                      bigintnat::NativeInteger(123456789));
  bigintnat::NativeInteger mu = modulus.ComputeMu();

  bigintnat::NativeInteger a =
      (bigintnat::NativeInteger(1) << 110) + bigintnat::NativeInteger(1234);
  bigintnat::NativeInteger b =
      (bigintnat::NativeInteger(1) << 115) + bigintnat::NativeInteger(6789);

  bigintnat::NativeInteger c =
      (bigintnat::NativeInteger(1) << 120) + bigintnat::NativeInteger(6);

  bigintnat::NativeInteger result = a;

  result.ModMulEq(b, modulus, mu);

  EXPECT_EQ(BigInteger("784483038650039308657432244878529921"),
            BigInteger(result))
      << "Failure in ModMulEq";

  result = a.ModMul(b, modulus, mu);

  EXPECT_EQ(BigInteger("784483038650039308657432244878529921"),
            BigInteger(result))
      << "Failure in ModMul";

  result = a.ModMulFast(b, modulus, mu);

  EXPECT_EQ(BigInteger("784483038650039308657432244878529921"),
            BigInteger(result))
      << "Failure in ModMulFast";

  result = a;

  result.ModMulFastEq(b, modulus, mu);

  EXPECT_EQ(BigInteger("784483038650039308657432244878529921"),
            BigInteger(result))
      << "Failure in ModMulFastEq";

  bigintnat::NativeInteger precon = b.PrepModMulConst(modulus);

  result = a.ModMulFastConst(b, modulus, precon);

  EXPECT_EQ(BigInteger("784483038650039308657432244878529921"),
            BigInteger(result))
      << "Failure in ModMulFastConst";

  result = a;

  result.ModMulFastConstEq(b, modulus, precon);

  EXPECT_EQ(BigInteger("784483038650039308657432244878529921"),
            BigInteger(result))
      << "Failure in ModMulFastConstEq";

  result = a.ModExp(b, modulus);

  EXPECT_EQ(BigInteger("420836984722658338771647831749821018"),
            BigInteger(result))
      << "Failure in ModExp";

  result = a;

  result.ModExpEq(b, modulus);

  EXPECT_EQ(BigInteger("420836984722658338771647831749821018"),
            BigInteger(result))
      << "Failure in ModExpEq";

  result = a.ModAddFast(c, modulus);

  EXPECT_EQ(BigInteger("1298074214633706907132623958849475"),
            BigInteger(result))
      << "Failure in ModAddFast";

  result = a.ModSubFast(c, modulus);

  EXPECT_EQ(BigInteger("1298074214633706907132624205763041"),
            BigInteger(result))
      << "Failure in ModSubFast";

  result = a.ModInverse(modulus);

  EXPECT_EQ(BigInteger("859455677183853192994953853474516202"),
            BigInteger(result))
      << "Failure in ModInverse";
}

TEST(UT128, NTT_operations) {
  usint m1 = 16;
  NativeInteger modulus = FirstPrime<NativeInteger>(100, m1);
  NativeInteger rootOfUnity(RootOfUnity(m1, modulus));

  ILNativeParams params(m1, modulus, rootOfUnity);
  ILNativeParams params2(m1 / 2, modulus, rootOfUnity);
  shared_ptr<ILNativeParams> x1p(new ILNativeParams(params));
  shared_ptr<ILNativeParams> x2p(new ILNativeParams(params2));

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
