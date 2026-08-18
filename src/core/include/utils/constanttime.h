//==================================================================================
// BSD 2-Clause License
//
// Copyright (c) 2014-2023, NJIT, Duality Technologies Inc. and other contributors
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

// Branchless modular arithmetic primitives — eliminates secret-dependent branches
// in ModAddFast/ModSubFast/ModMulFastConst to prevent timing side-channels during
// multiparty decryption. No asm barriers; vectorisation is preserved.
//
// NOTE: CT guarantees do NOT hold on WASM (__EMSCRIPTEN__) — MultD uses
// software carry-detect branches that are data-dependent on every multiply.

#ifndef LBCRYPTO_UTILS_CONSTANTTIME_H
#define LBCRYPTO_UTILS_CONSTANTTIME_H

#include <cstdint>
#include <type_traits>

namespace lbcrypto {
namespace ct {

template <typename U>
inline constexpr int kTopBit = static_cast<int>(sizeof(U) * 8 - 1);

// return x - m if x >= m, else x  (branchless; both operands must be < 2^(bits-1))
template <typename U>
inline U SubIfGE(U x, U m) noexcept {
    static_assert(std::is_unsigned_v<U>, "SubIfGE requires unsigned type");
    const U diff = x - m;
    const U mask = U(0) - (diff >> kTopBit<U>);
    return diff + (mask & m);
}

// return (a - b) mod m  (branchless; a,b must be in [0, m))
template <typename U>
inline U ModSubFast(U a, U b, U m) noexcept {
    static_assert(std::is_unsigned_v<U>, "ModSubFast requires unsigned type");
    const U diff = a - b;
    const U mask = U(0) - (diff >> kTopBit<U>);
    return diff + (mask & m);
}

// return x + m if x < 0, else x  (branchless; Barrett correction step)
// Unsigned right-shift used for well-defined behaviour in C++17.
template <typename S>
inline S AddIfNeg(S x, S m) noexcept {
    static_assert(std::is_signed_v<S>, "AddIfNeg requires signed type");
    using U = std::make_unsigned_t<S>;
    const S sign = -static_cast<S>(static_cast<U>(x) >> kTopBit<U>);
    return x + (sign & m);
}

}  // namespace ct
}  // namespace lbcrypto

#endif  // LBCRYPTO_UTILS_CONSTANTTIME_H
