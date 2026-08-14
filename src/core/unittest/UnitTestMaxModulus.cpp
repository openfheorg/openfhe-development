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
// list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
// this list of conditions and the following disclaimer in the documentation
// and/or other materials provided with the distribution.
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
  Differential coverage of the NativeInteger modular-multiplication family at
  MAX_MODULUS_SIZE (and one bit below), checked against the multiprecision backend.
  Pins the maximum-modulus contract on every build configuration; in particular,
  builds without a 128-bit integer type reduce through the two-word (typeD) path,
  which is exercised here at the widths where it previously overflowed (issue #667).
*/

#include "gtest/gtest.h"
#include "math/distrgen.h"
#include "math/math-hal.h"
#include "math/nbtheory.h"
#include "utils/inttypes.h"

using namespace lbcrypto;

namespace {
BigInteger Ref(const NativeInteger& x) {
    return BigInteger(x.ToString());
}

NativeInteger FromRef(const BigInteger& x) {
    return NativeInteger(x.ToString());
}
}  // namespace

TEST(UTMaxModulus, mod_mul_family_at_max_modulus_size) {
    for (uint32_t bits : {uint32_t(MAX_MODULUS_SIZE) - 1, uint32_t(MAX_MODULUS_SIZE)}) {
        NativeInteger q{LastPrime<NativeInteger>(bits, 65536)};
        NativeInteger mu{q.ComputeMu()};
        BigInteger qRef{Ref(q)};

        DiscreteUniformGeneratorImpl<NativeVector> dug;
        constexpr uint32_t n = 512;
        NativeVector av{dug.GenerateVector(n, q)};
        NativeVector bv{dug.GenerateVector(n, q)};

        for (uint32_t i = 0; i < n; ++i) {
            NativeInteger a{av[i]};
            NativeInteger b{bv[i]};
            NativeInteger expect{FromRef((Ref(a) * Ref(b)).Mod(qRef))};

            EXPECT_EQ(a.ModMul(b, q), expect) << "ModMul bits=" << bits;
            EXPECT_EQ(a.ModMul(b, q, mu), expect) << "ModMul(mu) bits=" << bits;
            EXPECT_EQ(a.ModMulFast(b, q), expect) << "ModMulFast bits=" << bits;
            EXPECT_EQ(a.ModMulFast(b, q, mu), expect) << "ModMulFast(mu) bits=" << bits;
            NativeInteger c{a};
            c.ModMulFastEq(b, q, mu);
            EXPECT_EQ(c, expect) << "ModMulFastEq(mu) bits=" << bits;
            EXPECT_EQ(a.ModMulFastConst(b, q, b.PrepModMulConst(q)), expect) << "ModMulFastConst bits=" << bits;

            // unreduced input through the Barrett normalization path (value in [q, 2q))
            NativeInteger u{a.Add(q)};
            EXPECT_EQ(u.Mod(q, mu), a) << "Mod(mu) unreduced bits=" << bits;
            EXPECT_EQ(u.ModAdd(b, q, mu), a.ModAdd(b, q)) << "ModAdd(mu) unreduced bits=" << bits;
            EXPECT_EQ(u.ModSub(b, q, mu), a.ModSub(b, q)) << "ModSub(mu) unreduced bits=" << bits;
        }

        // vector-level multiply (hoisted-Barrett loop)
        NativeVector pv{av.ModMul(bv)};
        for (uint32_t i = 0; i < n; ++i) {
            EXPECT_EQ(pv[i], FromRef((Ref(av[i]) * Ref(bv[i])).Mod(qRef))) << "NativeVector::ModMul bits=" << bits;
        }

        // Fermat: 3^(q-1) = 1 mod q for prime q
        EXPECT_EQ(NativeInteger(3).ModExp(q - 1, q), NativeInteger(1)) << "ModExp bits=" << bits;
    }

    // FirstPrime scans candidates (and returns a prime) one bit ABOVE the cap, so
    // Miller-Rabin's ModExp/ModMul must be exact at MAX_MODULUS_SIZE + 1 bits
    NativeInteger p1{FirstPrime<NativeInteger>(MAX_MODULUS_SIZE, 65536)};
    EXPECT_EQ(p1.GetMSB(), uint32_t(MAX_MODULUS_SIZE) + 1);
    EXPECT_EQ(NativeInteger(3).ModExp(p1 - 1, p1), NativeInteger(1)) << "ModExp above cap";
}
