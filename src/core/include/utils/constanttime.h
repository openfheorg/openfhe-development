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
  Branch-free helpers for arithmetic on secret-dependent values. Each builds an all-ones or all-zeros mask from one bit
  and selects its result with the mask instead of a branch. On GCC and clang (except Emscripten) the bit passes through
  ValueBarrier, so the optimizer cannot tell the mask is all-ones or all-zeros and turn it back into a branch. The
  helpers accept any unsigned type at least as wide as unsigned int, including uint128_t. Check the compiled code on
  the targets that matter.
 */

#ifndef LBCRYPTO_UTILS_CONSTANTTIME_H
#define LBCRYPTO_UTILS_CONSTANTTIME_H

#include <cstdint>

namespace lbcrypto {
namespace ct {

/**
 * @brief Returns x while hiding its value from the optimizer (the technique of BoringSSL's value_barrier_w).
 */
inline uint64_t ValueBarrier(uint64_t x) noexcept {
#if (defined(__GNUC__) || defined(__clang__)) && !defined(__EMSCRIPTEN__)
    __asm__("" : "+r"(x) :);
#endif
    return x;
}

/**
 * @brief Returns all-ones if the top bit of x is set and zero otherwise.
 */
template <typename U>
U TopBitMask(U x) noexcept {
    static_assert(static_cast<U>(~static_cast<U>(0)) > static_cast<U>(0) && sizeof(U) >= sizeof(unsigned int),
                  "ct::TopBitMask requires an unsigned integer type at least as wide as unsigned int");
    const uint64_t topBit = ValueBarrier(static_cast<uint64_t>(x >> (8 * sizeof(U) - 1)));
    return static_cast<U>(0) - static_cast<U>(topBit);
}

/**
 * @brief Returns all-ones if a < b and zero otherwise. Requires a, b < 2^(w-1), where w is the bit width of U.
 */
template <typename U>
U LessMask(U a, U b) noexcept {
    return TopBitMask(static_cast<U>(a - b));
}

/**
 * @brief Returns x - m if x >= m and x otherwise. Requires x, m < 2^(w-1).
 */
template <typename U>
U SubIfGE(U x, U m) noexcept {
    const U d = x - m;
    return d + (TopBitMask(d) & m);
}

}  // namespace ct
}  // namespace lbcrypto

#endif  // LBCRYPTO_UTILS_CONSTANTTIME_H
