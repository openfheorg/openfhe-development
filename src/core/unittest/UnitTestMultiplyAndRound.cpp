//==================================================================================
// BSD 2-Clause License
//
// Copyright (c) 2014-2026, NJIT, Duality Technologies Inc. and other contributors
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
  NativeInteger::MultiplyAndRound and NativeVector::MultiplyAndRound for large operands,
  checked against BigInteger
 */

#include <cstdint>
#include <random>

#include "gtest/gtest.h"
#include "math/math-hal.h"

using namespace lbcrypto;

// 64-bit native integers only: the operands below have up to 60 bits, and with NATIVEINT == 128
// there is no double-width type, so MultiplyAndRound keeps the double-precision formula there.
#if NATIVEINT == 64
// round(x*p/q), half up, computed with BigInteger
static uint64_t ExactMultiplyAndRound(uint64_t x, uint64_t p, uint64_t q) {
    BigInteger num = BigInteger(x) * BigInteger(p) + BigInteger(q >> 1);
    return num.DividedBy(BigInteger(q)).ConvertToInt<uint64_t>();
}

TEST(UTNativeInteger, MultiplyAndRound_large) {
    std::mt19937_64 rng(1);
    for (uint32_t bits : {30, 52, 53, 55, 59}) {
        for (uint32_t k = 0; k < 1000; ++k) {
            // q of 60 bits, p < q of the given size, x < q
            uint64_t q = (rng() >> 4) | (uint64_t(1) << 59) | 1;
            uint64_t p = (rng() >> (64 - bits)) | (uint64_t(1) << (bits - 1));
            uint64_t x = rng() % q;
            EXPECT_EQ(NativeInteger(x).MultiplyAndRound(NativeInteger(p), NativeInteger(q)).ConvertToInt<uint64_t>(),
                      ExactMultiplyAndRound(x, p, q))
                    << "x = " << x << ", p = " << p << ", q = " << q;
            NativeInteger y(x);
            y.MultiplyAndRoundEq(NativeInteger(p), NativeInteger(q));
            EXPECT_EQ(y.ConvertToInt<uint64_t>(), ExactMultiplyAndRound(x, p, q));
        }
    }
}

TEST(UTNativeVector, MultiplyAndRound_large) {
    // the vector variant rounds the centred value: for x > q/2 it returns q - round(p*(q-x)/q)
    const uint64_t q = 1152921504606830593ULL;  // 60-bit prime
    const uint64_t p = 9007199255658497ULL;     // > 2^53
    std::mt19937_64 rng(2);
    NativeVector v(64, q);
    for (uint32_t i = 0; i < v.GetLength(); ++i)
        v[i] = rng() % q;
    NativeVector r = v.MultiplyAndRound(NativeInteger(p), NativeInteger(q));
    for (uint32_t i = 0; i < v.GetLength(); ++i) {
        uint64_t x = v[i].ConvertToInt<uint64_t>();
        uint64_t expected = (x > (q >> 1)) ? q - ExactMultiplyAndRound(q - x, p, q) : ExactMultiplyAndRound(x, p, q);
        EXPECT_EQ(r[i].ConvertToInt<uint64_t>(), expected) << "x = " << x;
    }
}
#endif
