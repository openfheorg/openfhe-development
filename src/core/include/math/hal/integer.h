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

/*
  This file contains the interfaces for the math integer data types
 */

#ifndef LBCRYPTO_MATH_INTEGER_INTERFACE_H
#define LBCRYPTO_MATH_INTEGER_INTERFACE_H

#include <string>
#include "utils/inttypes.h"

namespace lbcrypto {

template <typename T>
class BigIntegerInterface {
public:
    // CONSTRUCTORS

    // Constructors must be implemented in the derived classes
    // There are no base class constructors that need to be called

    // The derived classes should implement constructors from uint64_t,
    // NativeInteger, and strings There should be copy and move constructors, as
    // well as copy and move assignment

    // ASSIGNMENT OPERATORS

    // ACCESSORS

    /**
   * Set from a string
   *
   * @param str is the string representation of the value
   */
    void SetValue(const std::string& str);

    // ARITHMETIC OPERATIONS

    /**
   * Addition operation.
   *
   * @param &b is the value to add.
   * @return result of the addition operation.
   */
    T Add(const T& b) const;
    const T& AddEq(const T& b);

    /// inline operators for the addition operation.
    inline friend T operator+(const T& a, const T& b) {
        return a.Add(b);
    }
    inline friend const T& operator+=(T& a, const T& b) {
        return a.AddEq(b);
    }

    /**
   * Subtraction operation.
   *
   * @param &b is the value to subtract.
   * @return is the result of the subtraction operation.
   */
    T Sub(const T& b) const;
    const T& SubEq(const T& b);

    /// inline operators for the subtraction operation.
    inline friend T operator-(const T& a, const T& b) {
        return a.Sub(b);
    }
    inline friend const T& operator-=(T& a, const T& b) {
        return a.SubEq(b);
    }

    /**
   * Multiplication operation.
   *
   * @param &b is the value to multiply with.
   * @return is the result of the multiplication operation.
   */
    T Mul(const T& b) const;

    /**
   * Multiplication operation. In-place variant.
   *
   * @param &b is the value to multiply with.
   * @return is the result of the multiplication operation.
   */
    const T& MulEq(const T& b);

    /// inline operators for the multiplication operation.
    inline friend T operator*(const T& a, const T& b) {
        return a.Mul(b);
    }
    inline friend const T& operator*=(T& a, const T& b) {
        return a.MulEq(b);
    }

    /**
   * Division operation.
   *
   * @param &b is the value to divide by.
   * @return is the result of the division operation.
   */
    T DividedBy(const T& b) const;

    /**
   * Division operation. In-place variant.
   *
   * @param &b is the value to divide by.
   * @return is the result of the division operation.
   */
    const T& DividedByEq(const T& b);

    /// inline operators for the division operation.
    inline friend T operator/(const T& a, const T& b) {
        return a.DividedBy(b);
    }
    inline friend const T& operator/=(T& a, const T& b) {
        return a.DividedByEq(b);
    }

    /**
   * Multiply and Rounding operation. Returns [x*p/q] where [] is the rounding
   * operation.
   *
   * @param &p is the numerator to be multiplied.
   * @param &q is the denominator to be divided.
   * @return is the result of multiply and round operation.
   */
    T MultiplyAndRound(const T& p, const T& q) const;

    /**
   * Multiply and Rounding operation. Returns [x*p/q] where [] is the rounding
   * operation. In-place variant.
   *
   * @param &p is the numerator to be multiplied.
   * @param &q is the denominator to be divided.
   * @return is the result of multiply and round operation.
   */
    const T& MultiplyAndRoundEq(const T& p, const T& q);

    /**
   * Divide and Rounding operation. Returns [x/q] where [] is the rounding
   * operation.
   *
   * @param &q is the denominator to be divided.
   * @return is the result of divide and round operation.
   */
    T DivideAndRound(const T& q) const;

    /**
   * Divide and Rounding operation. Returns [x/q] where [] is the rounding
   * operation. In-place variant.
   *
   * @param &q is the denominator to be divided.
   * @return is the result of divide and round operation.
   */
    const T& DivideAndRoundEq(const T& q);

    // MODULAR ARITHMETIC OPERATIONS

    /**
   * Naive modulus operation.
   *
   * @param &modulus is the modulus to perform.
   * @return is the result of the modulus operation.
   */
    T Mod(const T& modulus) const;

    /**
   * Naive modulus operation. In-place variant.
   *
   * @param &modulus is the modulus to perform.
   * @return is the result of the modulus operation.
   */
    const T& ModEq(const T& modulus);

    // inline operators for the modulus operation.
    inline friend T operator%(const T& a, const T& b) {
        return a.Mod(b);
    }
    inline friend const T& operator%=(T& a, const T& b) {
        return a.ModEq(b);
    }

    /**
   * Precomputes a parameter mu for Barrett modular reduction.
   *
   * @return the precomputed parameter mu.
   */
    T ComputeMu() const;

    /**
   * Barrett modulus operation.
   * Implements generalized Barrett modular reduction algorithm. Uses one
   * precomputed value of mu.
   *
   * @param &modulus is the modulus to perform.
   * @param &mu is the Barrett value.
   * @return is the result of the modulus operation.
   */
    T Mod(const T& modulus, const T& mu) const;

    /**
   * Barrett modulus operation. In-place variant.
   * Implements generalized Barrett modular reduction algorithm. Uses one
   * precomputed value of mu.
   *
   * @param &modulus is the modulus to perform.
   * @param &mu is the Barrett value.
   * @return is the result of the modulus operation.
   */
    const T& ModEq(const T& modulus, const T& mu);

    /**
   * Modulus addition operation.
   *
   * @param &b is the scalar to add.
   * @param &modulus is the modulus to perform operations with.
   * @return is the result of the modulus addition operation.
   */
    T ModAdd(const T& b, const T& modulus) const;

    /**
   * Modulus addition operation. In-place variant.
   *
   * @param &b is the scalar to add.
   * @param &modulus is the modulus to perform operations with.
   * @return is the result of the modulus addition operation.
   */
    const T& ModAddEq(const T& b, const T& modulus);

    /**
   * Modulus addition where operands are < modulus.
   *
   * @param &b is the scalar to add.
   * @param &modulus is the modulus to perform operations with.
   * @return is the result of the modulus addition operation.
   */
    T ModAddFast(const T& b, const T& modulus) const;

    /**
   * Modulus addition where operands are < modulus. In-place variant.
   *
   * @param &b is the scalar to add.
   * @param &modulus is the modulus to perform operations with.
   * @return is the result of the modulus addition operation.
   */
    const T& ModAddFastEq(const T& b, const T& modulus);

    /**
   * Barrett modulus addition operation.
   *
   * @param &b is the scalar to add.
   * @param &modulus is the modulus to perform operations with.
   * @param &mu is the Barrett value.
   * @return is the result of the modulus addition operation.
   */
    T ModAdd(const T& b, const T& modulus, const T& mu) const;

    /**
   * Barrett modulus addition operation. In-place variant.
   *
   * @param &b is the scalar to add.
   * @param &modulus is the modulus to perform operations with.
   * @param &mu is the Barrett value.
   * @return is the result of the modulus addition operation.
   */
    const T& ModAddEq(const T& b, const T& modulus, const T& mu);

    /**
   * Modulus subtraction operation.
   *
   * @param &b is the scalar to subtract.
   * @param &modulus is the modulus to perform operations with.
   * @return is the result of the modulus subtraction operation.
   */
    T ModSub(const T& b, const T& modulus) const;

    /**
   * Modulus subtraction operation. In-place variant.
   *
   * @param &b is the scalar to subtract.
   * @param &modulus is the modulus to perform operations with.
   * @return is the result of the modulus subtraction operation.
   */
    const T& ModSubEq(const T& b, const T& modulus);

    /**
   * Modulus subtraction where operands are < modulus.
   *
   * @param &b is the scalar to subtract.
   * @param &modulus is the modulus to perform operations with.
   * @return is the result of the modulus subtraction operation.
   */
    T ModSubFast(const T& b, const T& modulus) const;

    /**
   * Modulus subtraction where operands are < modulus. In-place variant.
   *
   * @param &b is the scalar to subtract.
   * @param &modulus is the modulus to perform operations with.
   * @return is the result of the modulus subtraction operation.
   */
    const T& ModSubFastEq(const T& b, const T& modulus);

    /**
   * Barrett modulus subtraction operation.
   *
   * @param &b is the scalar to subtract.
   * @param &modulus is the modulus to perform operations with.
   * @param &mu is the Barrett value.
   * @return is the result of the modulus subtraction operation.
   */
    T ModSub(const T& b, const T& modulus, const T& mu) const;

    /**
   * Barrett modulus subtraction operation. In-place variant.
   *
   * @param &b is the scalar to subtract.
   * @param &modulus is the modulus to perform operations with.
   * @param &mu is the Barrett value.
   * @return is the result of the modulus subtraction operation.
   */
    const T& ModSubEq(const T& b, const T& modulus, const T& mu);

    /**
   * Modulus multiplication operation.
   *
   * @param &b is the scalar to multiply.
   * @param &modulus is the modulus to perform operations with.
   * @return is the result of the modulus multiplication operation.
   */
    T ModMul(const T& b, const T& modulus) const;

    /**
   * Modulus multiplication operation. In-place variant.
   *
   * @param &b is the scalar to multiply.
   * @param &modulus is the modulus to perform operations with.
   * @return is the result of the modulus multiplication operation.
   */
    const T& ModMulEq(const T& b, const T& modulus);

    /**
   * Barrett modulus multiplication.
   *
   * @param &b is the scalar to multiply.
   * @param &modulus is the modulus to perform operations with.
   * @param &mu is the Barrett value.
   * @return is the result of the modulus multiplication operation.
   */
    T ModMul(const T& b, const T& modulus, const T& mu) const;

    /**
   * Barrett modulus multiplication. In-place variant.
   *
   * @param &b is the scalar to multiply.
   * @param &modulus is the modulus to perform operations with.
   * @param &mu is the Barrett value.
   * @return is the result of the modulus multiplication operation.
   */
    const T& ModMulEq(const T& b, const T& modulus, const T& mu);

    /**
   * Modulus multiplication that assumes the operands are < modulus.
   *
   * @param &b is the scalar to multiply.
   * @param &modulus is the modulus to perform operations with.
   * @return is the result of the modulus multiplication operation.
   */
    T ModMulFast(const T& b, const T& modulus) const;

    /**
   * Modulus multiplication that assumes the operands are < modulus. In-place
   * variant.
   *
   * @param &b is the scalar to multiply.
   * @param &modulus is the modulus to perform operations with.
   * @return is the result of the modulus multiplication operation.
   */
    const T& ModMulFastEq(const T& b, const T& modulus);

    /**
   * Barrett modulus multiplication that assumes the operands are < modulus.
   *
   * @param &b is the scalar to multiply.
   * @param &modulus is the modulus to perform operations with.
   * @param &mu is the Barrett value.
   * @return is the result of the modulus multiplication operation.
   */
    T ModMulFast(const T& b, const T& modulus, const T& mu) const;

    /**
   * Barrett modulus multiplication that assumes the operands are < modulus.
   * In-place variant.
   *
   * @param &b is the scalar to multiply.
   * @param &modulus is the modulus to perform operations with.
   * @param &mu is the Barrett value.
   * @return is the result of the modulus multiplication operation.
   */
    const T& ModMulFastEq(const T& b, const T& modulus, const T& mu);

    /**
   * NTL-optimized modular multiplication using a precomputation for the
   * multiplicand. Assumes operands are < modulus.
   *
   * @param &b is the scalar to multiply.
   * @param &modulus is the modulus to perform operations with.
   * @param &bInv NTL precomputation for b.
   * @return is the result of the modulus multiplication operation.
   */
    T ModMulFastConst(const T& b, const T& modulus, const T& bInv) const;

    /**
   * NTL-optimized modular multiplication using a precomputation for the
   * multiplicand. Assumes operands are < modulus. In-place variant.
   *
   * @param &b is the scalar to multiply.
   * @param &modulus is the modulus to perform operations with.
   * @param &bInv NTL precomputation for b.
   * @return is the result of the modulus multiplication operation.
   */
    const T& ModMulFastConstEq(const T& b, const T& modulus, const T& bInv);

    /**
   * Modulus exponentiation operation.
   *
   * @param &b is the scalar to exponentiate at all locations.
   * @param &modulus is the modulus to perform operations with.
   * @return is the result of the modulus exponentiation operation.
   */
    T ModExp(const T& b, const T& modulus) const;

    /**
   * Modulus exponentiation operation. In-place variant.
   *
   * @param &b is the scalar to exponentiate at all locations.
   * @param &modulus is the modulus to perform operations with.
   * @return is the result of the modulus exponentiation operation.
   */
    const T& ModExpEq(const T& b, const T& modulus);

    /**
   * Modulus inverse operation.
   *
   * @param &modulus is the modulus to perform.
   * @return is the result of the modulus inverse operation.
   */
    T ModInverse(const T& modulus) const;

    /**
   * Modulus inverse operation. In-place variant.
   *
   * @param &modulus is the modulus to perform.
   * @return is the result of the modulus inverse operation.
   */
    const T& ModInverseEq(const T& modulus);

    // SHIFT OPERATIONS

    /**
   * Left shift operation.
   *
   * @param shift # of bits.
   * @return result of the shift operation.
   */
    T LShift(usshort shift) const;

    /**
   * Left shift operation. In-place variant.
   *
   * @param shift # of bits.
   * @return result of the shift operation.
   */
    const T& LShiftEq(usshort shift);

    /// inline operators for the left shift operations.
    inline friend T operator<<(const T& a, usshort shift) {
        return a.LShift(shift);
    }
    inline friend const T& operator<<=(T& a, usshort shift) {
        return a.LShiftEq(shift);
    }

    /**
   * Right shift operation.
   *
   * @param shift # of bits.
   * @return result of the shift operation.
   */
    T RShift(usshort shift) const;

    /**
   * Right shift operation. In-place variant.
   *
   * @param shift # of bits.
   * @return result of the shift operation.
   */
    const T& RShiftEq(usshort shift);

    /// inline operators for the right shift operations.
    inline friend T operator>>(const T& a, usshort shift) {
        return a.RShift(shift);
    }
    inline friend const T& operator>>=(T& a, usshort shift) {
        return a.RShiftEq(shift);
    }

    // COMPARE

    /**
   * Compares the current BigInteger to BigInteger a.
   *
   * @param a is the BigInteger to be compared with.
   * @return  -1 for strictly less than, 0 for equal to and 1 for strictly
   * greater than conditons.
   */
    int Compare(const T& a) const;

    //// relational operators, using Compare
    friend bool operator==(const T& a, const T& b) {
        return a.Compare(b) == 0;
    }
    friend bool operator!=(const T& a, const T& b) {
        return a.Compare(b) != 0;
    }

    friend bool operator>(const T& a, const T& b) {
        return a.Compare(b) > 0;
    }
    friend bool operator>=(const T& a, const T& b) {
        return a.Compare(b) >= 0;
    }
    friend bool operator<(const T& a, const T& b) {
        return a.Compare(b) < 0;
    }
    friend bool operator<=(const T& a, const T& b) {
        return a.Compare(b) <= 0;
    }

    // CONVERTERS

    /**
   * Convert the value to an int.
   *
   * @return the int representation of the value.
   */
    uint64_t ConvertToInt() const;

    // OTHER FUNCTIONS

    /**
   * Returns the MSB location of the value.
   *
   * @return the index of the most significant bit.
   */
    usint GetMSB() const;

    /**
   * Get the number of digits using a specific base - support for arbitrary base
   * may be needed.
   *
   * @param base is the base with which to determine length in.
   * @return the length of the representation in a specific base.
   */
    usint GetLengthForBase(usint base) const;

    /**
   * Get the number of digits using a specific base - support for arbitrary base
   * may be needed. Example: for number 83, index 2 and base 4 we have:
   *
   *                         index:0,1,2,3
   * 83 --base 4 decomposition--> (3,0,1,1) --at index 2--> 1
   *
   * The return number is 1.
   *
   * @param index is the location to return value from in the specific base.
   * @param base is the base with which to determine length in.
   * @return the length of the representation in a specific base.
   */
    usint GetDigitAtIndexForBase(usint index, usint base) const;

    // STRINGS

    // The derived classes MAY implement std::ostream& operator<< but are not
    // required to

    /**
   * Convert this integer into a std::string, for serialization
   *
   * @return the value of this T as a string.
   */
    const std::string ToString() const;

    // SERIALIZATION
};

// TODO
class BigMatrixInterface {};
}  // namespace lbcrypto

#endif
