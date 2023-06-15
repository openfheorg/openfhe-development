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

#include "utils/inttypes.h"

#include <string>
#include <climits>      // CHAR_BIT
#include <type_traits>  // std::is_integral

/**
 * @namespace lbcrypto
 * The namespace of lbcrypto
 */
namespace lbcrypto {

/**
 * Zero Padding of Elements.
 * Adds zeros to form a polynomial of length 2n  (corresponding to cyclotomic
 * order m = 2n). It is used by the forward transform of
 * ChineseRemainderTransform (a modified version of ZeroPadd will be used for
 * the non-power-of-2 case).
 *
 * @param &InputPoly is the element to perform the transform on.
 * @param target_order is the intended target ordering.
 * @return is the output of the zero padding.
 */
template <typename V>
V ZeroPadForward(const V& InputPoly, usint target_order);

/**
 * Zero Pad Inverse of Elements.
 * Adds alternating zeroes to form a polynomial of length of length 2n
 * (corresponding to cyclotomic order m = 2n). It is used by the inverse
 * transform of ChineseRemainderTransform (a modified version of ZeroPadInverse
 * will be used for the non-power-of-2 case).
 *
 * @param &InputPoly is the element to perform the transform on.
 * @param target_order is the intended target ordering.
 * @return is the output of the zero padding.
 */
template <typename V>
V ZeroPadInverse(const V& InputPoly, usint target_order);

/**
 * Determines if a number is a power of 2.
 *
 * @param Input to test if it is a power of 2.
 * @return is true if the unsigned int is a power of 2.
 */
inline bool IsPowerOfTwo(usint Input) {
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
inline uint32_t IsAdditionOverflow(uint64_t a, uint64_t b) {
    a += b;
    if (a < b)
        return 1;
    else
        return 0;
}

/**
 * add two 64-bit number with carry out, c = a + b
 * @param a: operand 1
 * @param b: operand 2
 * @param c: c = a + b
 * @return 1 if overflow occurs, 0 otherwise
 */

inline uint32_t AdditionWithCarryOut(uint64_t a, uint64_t b, uint64_t& c) {
    a += b;
    c = a;
    if (a < b)
        return 1;
    else
        return 0;
}

/**
 * GetIntegerTypeBitLength() calculates the number of all bits in type T and
 * std::enable_if<...> constrains the allowable types to primitive integers only.
 * All other types are excluded. Examples: enum, bool, floating point,
 * any class or struct (ex.: BigInteger, NativeIntegerT, etc.)
 * Ex: auto bitlen = GetIntegerTypeBitLength<short>(); bitlen == 16
 */
template <typename T,
          typename std::enable_if<std::is_integral<T>::value && !std::is_same<T, bool>::value, bool>::type = true>
constexpr usint GetIntegerTypeBitLength() {
    return sizeof(T) * CHAR_BIT;
}

// TODO (dsuponit): the name of this function Max64BitValue() is misleading as it returns the largest value
// that can be converted from double to int64_t and not the max value of int64_t. The function must be renamed!!!
constexpr int64_t Max64BitValue() {
    // (2^63-1)-(2^10-1) => 2^63-2^10 - max value that could be rounded to int64_t
    return static_cast<int64_t>((uint64_t(1) << 63) - (uint64_t(1) << 10));
}

inline bool is64BitOverflow(double d) {
    // 1. TODO (dsuponit): the name of this function is64BitOverflow() is misleading as it checks if
    // double can be converted to int64_t. The name should reflect that. something like isConvertableToInt64() The function must be renamed!!!
    // 2. TODO (dsuponit): the body of this function should probably be just 1 line as this function is asking a simple binary question if
    // there is an overflow or not:
    // return (std::abs(d) > Max64BitValue());
    // TO BE REVIEWED...
    const double EPSILON = 0.000001;

    return EPSILON < (std::abs(d) - Max64BitValue());
}

}  // namespace lbcrypto

#endif
