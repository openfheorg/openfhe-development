//==================================================================================
// BSD 2-Clause License
//
// Copyright (c) 2014-2026, NJIT, Duality Technologies Inc. and other contributors
//
// All rights reserved.
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

#ifndef LBCRYPTO_MATH_MATRIX_UTILS_H
#define LBCRYPTO_MATH_MATRIX_UTILS_H

#include "math/math-hal.h"

#include "utils/exception.h"

#include <cstdint>
#include <limits>

namespace lbcrypto {

inline int32_t ConvertCenteredToInt32(const BigInteger& value, const BigInteger& modulus) {
    constexpr uint64_t int32MaxValue = static_cast<uint64_t>(std::numeric_limits<int32_t>::max());
    const BigInteger negativeThreshold(modulus / BigInteger(2));
    const BigInteger int32Max(int32MaxValue);
    const BigInteger int32MinMagnitude(int32MaxValue + 1);  // abs(INT32_MIN)

    if (value <= negativeThreshold) {
        if (value > int32Max)
            OPENFHE_THROW("Centered value cannot be represented as int32_t");

        return static_cast<int32_t>(value.ConvertToInt<uint32_t>());
    }

    const BigInteger magnitude(modulus - value);
    if (magnitude > int32MinMagnitude)
        OPENFHE_THROW("Centered value cannot be represented as int32_t");

    if (magnitude == int32MinMagnitude)
        return std::numeric_limits<int32_t>::min();

    return -static_cast<int32_t>(magnitude.ConvertToInt<uint32_t>());
}

}  // namespace lbcrypto

#endif  // LBCRYPTO_MATH_MATRIX_UTILS_H
