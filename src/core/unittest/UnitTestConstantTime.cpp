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
  Checks the branch-free helpers in utils/constanttime.h against their branching definitions, and the
  constant-time NativeInteger variants against the variable-time originals, at the edges of the input
  ranges and on random inputs.
*/

#include "gtest/gtest.h"
#include "math/distrgen.h"
#include "math/math-hal.h"
#include "math/nbtheory.h"
#include "utils/constanttime.h"
#include "utils/inttypes.h"

#include <random>
#include <vector>

using namespace lbcrypto;

namespace {
template <typename U>
U RandomWord(std::mt19937_64& rng) {
    if constexpr (sizeof(U) <= sizeof(uint64_t))
        return static_cast<U>(rng());
    else
        return (static_cast<U>(rng()) << 64) | static_cast<U>(rng());
}

template <typename U>
void CheckHelpers() {
    const uint32_t w = 8 * sizeof(U);
    const U zero{0};
    const U ones{static_cast<U>(~zero)};
    // the helpers require operands below 2^(w-1)
    const U lim{static_cast<U>(static_cast<U>(1) << (w - 1))};

    std::vector<U> values{
        zero,       U{1},           U{2},       U{3},      static_cast<U>(lim / 4), static_cast<U>(lim / 2 - 1),
        U(lim / 2), U(lim / 2 + 1), U(lim - 2), U(lim - 1)};
    std::mt19937_64 rng(1198);
    for (int i = 0; i < 64; i++)
        values.push_back(static_cast<U>(RandomWord<U>(rng) & (lim - 1)));

    for (U a : values) {
        EXPECT_TRUE(ct::TopBitMask(a) == zero) << "TopBitMask w=" << w;
        EXPECT_TRUE(ct::TopBitMask(static_cast<U>(a | lim)) == ones) << "TopBitMask w=" << w;
        for (U b : values) {
            EXPECT_TRUE(ct::LessMask(a, b) == (a < b ? ones : zero)) << "LessMask w=" << w;
            EXPECT_TRUE(ct::SubIfGE(a, b) == (a >= b ? static_cast<U>(a - b) : a)) << "SubIfGE w=" << w;
        }
    }
}
}  // namespace

TEST(UTConstantTime, helpers_match_branching_definitions) {
    CheckHelpers<uint32_t>();
    CheckHelpers<uint64_t>();
#if defined(HAVE_INT128)
    CheckHelpers<uint128_t>();
#endif
}

TEST(UTConstantTime, native_integer_ct_variants_match_originals) {
    for (uint32_t bits : {uint32_t(20), uint32_t(MAX_MODULUS_SIZE) - 1, uint32_t(MAX_MODULUS_SIZE)}) {
        NativeInteger q{LastPrime<NativeInteger>(bits, 65536)};

        auto check = [&](const NativeInteger& a, const NativeInteger& b) {
            const NativeInteger precon{b.PrepModMulConst(q)};
            EXPECT_EQ(a.ModMulFastConstCT(b, q, precon), a.ModMulFastConst(b, q, precon))
                << "ModMulFastConstCT bits=" << bits << " a=" << a << " b=" << b;

            NativeInteger sumCT{a};
            sumCT.ModAddFastEqCT(b, q);
            NativeInteger sum{a};
            sum.ModAddFastEq(b, q);
            EXPECT_EQ(sumCT, sum) << "ModAddFastEqCT bits=" << bits << " a=" << a << " b=" << b;
        };

        const std::vector<NativeInteger> edges{NativeInteger(0), NativeInteger(1), NativeInteger(q.ConvertToInt() / 2),
                                               NativeInteger(q.ConvertToInt() / 2 + 1), q - NativeInteger(1)};
        for (const auto& a : edges) {
            for (const auto& b : edges)
                check(a, b);
        }

        DiscreteUniformGeneratorImpl<NativeVector> dug;
        constexpr uint32_t n = 512;
        NativeVector av{dug.GenerateVector(n, q)};
        NativeVector bv{dug.GenerateVector(n, q)};
        for (uint32_t i = 0; i < n; ++i) {
            check(av[i], bv[i]);
            for (const auto& e : edges) {
                check(av[i], e);
                check(e, bv[i]);
            }
        }
    }
}
