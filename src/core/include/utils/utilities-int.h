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

#ifndef __UTILITIES_INT_H__
#define __UTILITIES_INT_H__

#include "math/math-hal.h"
#include "utils/utilities.h"

namespace lbcrypto {

#if defined(HAVE_INT128)
/**
 * 64-bit uint multiplier, result is 128-bit
 * @param a: operand 1
 * @param b: operand 2
 * @return result: 128-bit result = a * b
 */
inline DoubleNativeInt Mul128(uint64_t a, uint64_t b) {
    return DoubleNativeInt(a) * DoubleNativeInt(b);
}

/**
 * Barrett reduction of 128-bit integer modulo 64-bit integer. Source: Menezes,
 * Alfred; Oorschot, Paul; Vanstone, Scott. Handbook of Applied Cryptography,
 * Section 14.3.3.
 * @param a: operand (128-bit)
 * @param m: modulus (64-bit)
 * @param mu: 2^128/modulus (128-bit)
 * @return result: 64-bit result = a mod m
 */
inline uint64_t BarrettUint128ModUint64(const DoubleNativeInt& a, uint64_t modulus, const DoubleNativeInt& mu) {
    // (a * mu)/2^128 // we need the upper 128-bit of (256-bit product)
    uint64_t result = 0, a_lo = 0, a_hi = 0, mu_lo = 0, mu_hi = 0, left_hi = 0, middle_lo = 0, middle_hi = 0, tmp1 = 0,
             tmp2 = 0, carry = 0;
    DoubleNativeInt middle = 0;

    a_lo  = (uint64_t)a;
    a_hi  = a >> 64;
    mu_lo = (uint64_t)mu;
    mu_hi = mu >> 64;

    left_hi = (Mul128(a_lo, mu_lo)) >> 64;  // mul left parts, discard lower word

    middle    = Mul128(a_lo, mu_hi);  // mul middle first
    middle_lo = (uint64_t)middle;
    middle_hi = middle >> 64;

    // accumulate and check carry
    carry = AdditionWithCarryOut(middle_lo, left_hi, tmp1);

    tmp2 = middle_hi + carry;  // accumulate

    middle    = Mul128(a_hi, mu_lo);  // mul middle second
    middle_lo = (uint64_t)middle;
    middle_hi = middle >> 64;

    carry = IsAdditionOverflow(middle_lo, tmp1);  // check carry

    left_hi = middle_hi + carry;  // accumulate

    // now we have the lower word of (a * mu)/2^128, no need for higher word
    tmp1 = a_hi * mu_hi + tmp2 + left_hi;

    // subtract lower words only, higher words should be the same
    result = a_lo - tmp1 * modulus;

    while (result >= modulus)
        result -= modulus;

    return result;
}
#endif

}  // namespace lbcrypto
#endif  // __UTILITIES_INT_H__
