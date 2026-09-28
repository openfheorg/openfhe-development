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

#ifndef SRC_CORE_INCLUDE_UTILS_UTILITIES_H_
#define SRC_CORE_INCLUDE_UTILS_UTILITIES_H_

#include <climits>  // CHAR_BIT
#include <cmath>
#include <cstdint>
#include <limits>  // std::numeric_limits
#include <string>
#include <type_traits>  // std::is_integral

#include "config_core.h"
#include "utils/inttypes.h"

/**
 * @namespace lbcrypto
 * The namespace of lbcrypto
 */
namespace lbcrypto {

/**
 * Determines if a number is a power of 2.
 *
 * @param Input to test if it is a power of 2.
 * @return is true if the unsigned int is a power of 2.
 */
template <typename T, std::enable_if_t<std::is_integral_v<T> && std::is_unsigned_v<T>, bool> = true>
inline constexpr bool IsPowerOfTwo(T Input) {
    return Input && !(Input & (Input - 1));
}

/**
 * Auxiliary function to replace a specific character "in" with another
 * character "out"
 *
 * @param str string where in which characters are replaced
 * @param in character being replaced
 * @param out character to be replaced with
 * @return the modified string.
 */
// auxiliary function to replace a specific character "in" with another
// character "out"
std::string replaceChar(std::string str, char in, char out);

// Lazy Reduction functions: 64-bit multiplier and 128-bit Barrett reducer
// Originally proposed for BFVrnsB
/**
 * check if adding two 64-bit number can cause overflow
 * @param a: operand 1
 * @param b: operand 2
 * @return 1 if overflow occurs, 0 otherwise
 */
inline uint64_t IsAdditionOverflow(uint64_t a, uint64_t b) {
    return (a + b) < b;
}

/**
 * add two 64-bit number with carry out, c = a + b
 * @param a: operand 1
 * @param b: operand 2
 * @param c: c = a + b
 * @return 1 if overflow occurs, 0 otherwise
 */

inline uint64_t AdditionWithCarryOut(uint64_t a, uint64_t b, uint64_t& c) {
    return (c = a + b) < b;
}

// TODO (dsuponit): the name of this function Max64BitValue() is misleading as it returns the largest value
// that can be converted from double to int64_t and not the max value of int64_t. The function must be renamed!!!
/**
 * @brief Returns the largest magnitude, 2^63 - 2^9 - 1, that a double is allowed to have when it is converted
 * to int64_t; this is not the maximum int64_t value.
 * @return the conversion bound
 */
inline constexpr int64_t Max64BitValue() {
    return static_cast<int64_t>((uint64_t(1) << 63) - (uint64_t(1) << 9) - 1);
}

// TODO (dsuponit): the name of this function is64BitOverflow() is misleading as it checks if double can be
// converted to int64_t. The name should reflect that. Something like isConvertableToInt64(). The function must be renamed!!!
/**
 * @brief Checks whether a double is too large in magnitude to be converted to int64_t.
 * @param d value to test
 * @return true if |d| exceeds Max64BitValue()
 */
inline bool is64BitOverflow(double d) {
    return std::abs(d) > static_cast<double>(Max64BitValue());
}

#if NATIVEINT == 128
/**
 * @brief Returns the largest magnitude, 2^127 - 2^73 - 1, that a double is allowed to have when it is converted
 * to a 128-bit signed integer.
 * @return the conversion bound
 */
inline constexpr __int128 Max128BitValue() {
    return static_cast<int128_t>((static_cast<uint128_t>(1) << 127) - (static_cast<uint128_t>(1) << 73) -
                                 static_cast<uint128_t>(1));
}

/**
 * @brief Checks whether a double is too large in magnitude to be converted to a 128-bit signed integer.
 * @param d value to test
 * @return true if |d| exceeds Max128BitValue()
 */
inline bool is128BitOverflow(double d) {
    return std::abs(d) > static_cast<double>(Max128BitValue());
}

enum { MAX_DOUBLE_PRECISION = 52 };
#endif

/**
 * @brief Converts a signed integer to its residue in [0, modulus) for a modulus that fits in 64 bits.
 *
 * @param value the signed integer to convert.
 * @param modulus the modulus to reduce against, non-zero.
 * @return value modulo modulus, in [0, modulus).
 */
inline uint64_t SignedToResidue(int64_t value, uint64_t modulus) {
    const bool negative = value < 0;
    const uint64_t magnitude = negative ? uint64_t(0) - static_cast<uint64_t>(value) : static_cast<uint64_t>(value);
    const uint64_t residue = (magnitude < modulus) ? magnitude : magnitude % modulus;
    return (negative && residue != 0) ? modulus - residue : residue;
}

/**
 * @brief Converts a signed integer to its residue in [0, modulus) for a library integer type.
 *
 * @param value the signed integer to convert.
 * @param modulus the modulus to reduce against.
 * @return value modulo modulus, in [0, modulus).
 */
template <typename IntType, std::enable_if_t<!std::is_integral_v<IntType>, bool> = true>
IntType SignedToResidue(int64_t value, const IntType& modulus) {
    if (modulus.GetMSB() <= 64)
        return IntType(SignedToResidue(value, modulus.template ConvertToInt<uint64_t>()));
    if (value >= 0)
        return IntType(static_cast<uint64_t>(value));
    const uint64_t magnitude = uint64_t(0) - static_cast<uint64_t>(value);
    return modulus - IntType(magnitude);
}

/**
 * @brief Checks whether a double fits the signed range of the native integer type: int32_t max for 32-bit
 * NativeInteger, Max64BitValue() for 64-bit, Max128BitValue() for 128-bit.
 * @param d value to test
 * @return true if |d| is within the bound for the configured NATIVEINT size
 */
inline bool isConvertableToNativeInt(double d) {
    if constexpr (NATIVEINT == 32)
        return std::abs(d) <= static_cast<double>(std::numeric_limits<int32_t>::max());
    if constexpr (NATIVEINT == 64)
        return std::abs(d) <= static_cast<double>(Max64BitValue());
#if NATIVEINT == 128
    if constexpr (NATIVEINT == 128)
        return std::abs(d) <= static_cast<double>(Max128BitValue());
#endif
}

}  // namespace lbcrypto

#endif  // SRC_CORE_INCLUDE_UTILS_UTILITIES_H_
