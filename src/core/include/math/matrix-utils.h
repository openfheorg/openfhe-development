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
#include <string>

namespace lbcrypto {

/**
 * @brief Converts elements of Z_q to their centered representatives in (-q/2, q/2] as int32_t.
 *
 * The modulus-dependent bounds are computed once, at construction; Convert() then performs at
 * most two comparisons and one subtraction per element and throws if the centered representative
 * does not fit in an int32_t. Every representative fits if q <= 2^32 - 1. For an even q the
 * class q/2 has the two representatives -q/2 and q/2; the representable one is returned.
 */
template <typename IntType>
class CenteredToInt32ConverterImpl {
public:
    explicit CenteredToInt32ConverterImpl(const IntType& modulus)
        : m_modulus(modulus), m_native(modulus.GetMSB() <= 64) {
        const IntType int32Max(int32MaxValue);
        const IntType negativeThreshold(modulus / IntType(2));

        // the largest value mapping to a non-negative int32_t
        m_maxPositive = (negativeThreshold > int32Max) ? int32Max : negativeThreshold;

        // the smallest value mapping to a negative int32_t
        m_minNegative = negativeThreshold + IntType(1);
        if (modulus > IntType(int32MinMagnitude)) {
            const IntType lowestNegative(modulus - IntType(int32MinMagnitude));
            if (lowestNegative > m_minNegative)
                m_minNegative = lowestNegative;
        }

        if (m_native) {
            m_modulus64     = modulus.template ConvertToInt<uint64_t>();
            m_maxPositive64 = m_maxPositive.template ConvertToInt<uint64_t>();
        }
    }

    int32_t Convert(const IntType& value) const {
        if (m_native) {
            //  q <= 2^64: both bounds and the magnitude fit in a native word, so the comparisons
            //  and the subtraction need no big-integer temporary. A value outside Z_q wraps the
            //  subtraction, which the magnitude bound then rejects
            const uint64_t v{value.template ConvertToInt<uint64_t>()};
            if (v <= m_maxPositive64)
                return static_cast<int32_t>(v);
            const uint64_t magnitude{m_modulus64 - v};
            if (magnitude <= int32MinMagnitude)
                return static_cast<int32_t>(-static_cast<int64_t>(magnitude));
        }
        else {
            if (value <= m_maxPositive)
                return static_cast<int32_t>(value.template ConvertToInt<uint64_t>());
            if (value >= m_minNegative && value < m_modulus)
                return static_cast<int32_t>(
                    -static_cast<int64_t>((m_modulus - value).template ConvertToInt<uint64_t>()));
        }
        OPENFHE_THROW("The centered representative of " + value.ToString() + " mod " + m_modulus.ToString() +
                      " cannot be represented as int32_t");
    }

private:
    static constexpr uint64_t int32MaxValue{static_cast<uint64_t>(std::numeric_limits<int32_t>::max())};
    static constexpr uint64_t int32MinMagnitude{int32MaxValue + 1};  // abs(INT32_MIN)

    IntType m_modulus;
    IntType m_maxPositive;
    IntType m_minNegative;
    uint64_t m_modulus64{0};
    uint64_t m_maxPositive64{0};
    bool m_native{false};
};

using CenteredToInt32Converter = CenteredToInt32ConverterImpl<BigInteger>;

}  // namespace lbcrypto

#endif  // LBCRYPTO_MATH_MATRIX_UTILS_H
