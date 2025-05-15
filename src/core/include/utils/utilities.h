//==================================================================================
// BSD 2-Clause License
//
// Copyright (c) 2014-2022, NJIT, Duality Technologies Inc. and other contributors
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

#ifndef LBCRYPTO_UTILS_UTILITIES_H
#define LBCRYPTO_UTILS_UTILITIES_H

#include "config_core.h"
#include "utils/inttypes.h"

#include <cmath>
#include <climits>  // CHAR_BIT
#include <limits>   // std::numeric_limits
#include <string>
#include <type_traits>  // std::is_integral

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
inline constexpr int64_t Max64BitValue() {
    return static_cast<int64_t>((uint64_t(1) << 63) - (uint64_t(1) << 9) - 1);
}

// TODO (dsuponit): the name of this function is64BitOverflow() is misleading as it checks if double can be
// converted to int64_t. The name should reflect that. Something like isConvertableToInt64(). The function must be renamed!!!
inline bool is64BitOverflow(double d) {
    return std::abs(d) > static_cast<double>(Max64BitValue());
}

#if NATIVEINT == 128
inline constexpr __int128 Max128BitValue() {
    return static_cast<__int128>(((unsigned __int128)1 << 127) - ((unsigned __int128)1 << 73) - (unsigned __int128)1);
}

inline bool is128BitOverflow(double d) {
    return std::abs(d) > static_cast<double>(Max128BitValue());
}

enum { MAX_DOUBLE_PRECISION = 52 };
#endif

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

#endif
