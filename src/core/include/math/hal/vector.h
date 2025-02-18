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
  This file contains the interfaces for the math vector data types
 */

#ifndef LBCRYPTO_MATH_VECTOR_H
#define LBCRYPTO_MATH_VECTOR_H

#include "utils/inttypes.h"

#include <string>

namespace lbcrypto {

template <typename T, typename I>
class BigVectorInterface {
public:
    typedef I Integer;

    // CONSTRUCTORS

    // Constructors should be implemented in the derived classes
    // The derived classes should implement constructors from initializer lists of
    // integers and strings

    // ASSIGNMENT OPERATORS

    /**
   * Copy assignment operator.
   *
   * @param &vec is the vector to be assigned from.
   * @return assigned vector ref.
   */
    T& operator=(const T& vec);

    /**
   * Move assignment operator.
   *
   * @param &vec is the vector to be assigned from.
   * @return assigned vector ref.
   */
    T& operator=(T&& vec);

    /**
   * Assignment operator from initializer list of strings.
   *
   * @param &&strvec is the list of strings.
   * @return assigned vector ref.
   */
    T& operator=(std::initializer_list<std::string> strvec);

    /**
   * Assignment operator from initializer list of unsigned integers.
   *
   * @param &&vec is the list of integers.
   * @return assigned vector ref.
   */
    T& operator=(std::initializer_list<uint64_t> vec);

    /**
   * Assignment operator to assign value val to first entry, 0 for the rest of
   * entries.
   *
   * @param val is the unsigned integer the first entry to be assigned from.
   * @return assigned vector ref.
   */
    T& operator=(uint64_t val);

    // EQUALS OPERATORS

    /**
   * Equals to operator.
   *
   * @param &b is vector to be compared.
   * @return true if equal and false otherwise.
   */
    friend inline bool operator==(const T& a, const T& b) {
        if ((a.GetLength() != b.GetLength()) || (a.GetModulus() != b.GetModulus())) {
            return false;
        }
        for (usint i = 0; i < a.GetLength(); ++i) {
            if (a[i] != b[i]) {
                return false;
            }
        }
        return true;
    }

    /**
   * Not equal to operator.
   *
   * @param b is vector to be compared.
   * @return true if not equal and false otherwise.
   */
    friend inline bool operator!=(const T& a, const T& b) {
        return !(a == b);
    }

    // ACCESSORS

    // The derived class must implement at and operator[]
    I& at(size_t idx);
    const I& at(size_t idx) const;
    I& operator[](size_t idx);
    const I& operator[](size_t idx) const;

    /**
   * Sets the vector modulus.
   *
   * @param value is the value to set.
   * @param value is the modulus value to set.
   */
    void SetModulus(const I& value);

    /**
   * Sets the vector modulus and changes the values to match the new modulus.
   *
   * @param value is the value to set.
   */
    void SwitchModulus(const I& value);
    void LazySwitchModulus(const I& value);

    T& MultAccEqNoCheck(const T& vec, const I& value);

    /**
   * Gets the vector modulus.
   *
   * @return the vector modulus.
   */
    const I& GetModulus() const;

    /**
   * Gets the vector length.
   *
   * @return vector length.
   */
    size_t GetLength() const;

    // MODULUS ARITHMETIC OPERATIONS

    /**
   * Vector modulus operator.
   *
   * @param &modulus is the modulus to perform on the current vector entries.
   * @return is the result of the modulus operation on current vector.
   */
    T Mod(const I& modulus) const;

    /**
   * Vector modulus operator. In-place variant.
   *
   * @param &modulus is the modulus to perform on the current vector entries.
   * @return is the result of the modulus operation on current vector.
   */
    T& ModEq(const I& modulus);

    /// inline operators for the modulus operations.
    friend T operator%(const T& a, const I& b) {
        return a.Mod(b);
    }
    friend T& operator%=(T& a, const I& b) {
        return a.ModEq(b);
    }

    /**
   * Scalar-to-vector modulus addition operation.
   *
   * @param &b is the scalar to perform operation with.
   * @return is the result of the modulus addition operation.
   */
    T ModAdd(const I& b) const;

    /**
   * Scalar-to-vector modulus addition operation. In-place variant.
   *
   * @param &b is the scalar to perform operation with.
   * @return is the result of the modulus addition operation.
   */
    T& ModAddEq(const I& b);

    /// inline operators for the scara-to-vector modulus addition operations.
    friend T operator+(const T& a, const I& b) {
        return a.ModAdd(b);
    }
    friend T& operator+=(T& a, const I& b) {
        return a.ModAddEq(b);
    }

    /**
   * Scalar modulus addition at a particular index.
   *
   * @param i is the index of the entry to add.
   * @param &b is the scalar to add.
   * @return is the result of the modulus addition operation.
   */
    T ModAddAtIndex(usint i, const I& b) const;

    /**
   * Scalar modulus addition at a particular index. In-place variant.
   *
   * @param i is the index of the entry to add.
   * @param &b is the scalar to add.
   * @return is the result of the modulus addition operation.
   */
    T& ModAddAtIndexEq(usint i, const I& b);

    /**
   * Vector component wise modulus addition.
   *
   * @param &b is the vector to perform operation with.
   * @return is the result of the component wise modulus addition operation.
   */
    T ModAdd(const T& b) const;

    /**
   * Vector component wise modulus addition. In-place variant.
   *
   * @param &b is the vector to perform operation with.
   * @return is the result of the component wise modulus addition operation.
   */
    T& ModAddEq(const T& b);
    T& ModAddNoCheckEq(const T& b);

    /// inline operators for the vector component wise modulus addition
    /// operations.
    friend T operator+(const T& a, const T& b) {
        return a.ModAdd(b);
    }
    friend T& operator+=(T& a, const T& b) {
        return a.ModAddEq(b);
    }

    /**
   * Scalar-from-vector modulus subtraction operation.
   *
   * @param &b is the scalar to perform operation with.
   * @return is the result of the modulus subtraction operation.
   */
    T ModSub(const I& b) const;

    /**
   * Scalar-from-vector modulus subtraction operation. In-place variant.
   *
   * @param &b is the scalar to perform operation with.
   * @return is the result of the modulus subtraction operation.
   */
    T& ModSubEq(const I& b);

    /// inline operators for the scalar-from-vector modulus subtraction
    /// operations.
    friend T operator-(const T& a, const I& b) {
        return a.ModSub(b);
    }
    friend T& operator-=(T& a, const I& b) {
        return a.ModSubEq(b);
    }

    /**
   * Vector component wise modulus subtraction.
   *
   * @param &b is the vector to perform operation with.
   * @return is the result of the component wise modulus subtraction operation.
   */
    T ModSub(const T& b) const;

    /**
   * Vector component wise modulus subtraction. In-place variant.
   *
   * @param &b is the vector to perform operation with.
   * @return is the result of the component wise modulus subtraction operation.
   */
    T& ModSubEq(const T& b);

    /// inline operators for the vector component wise modulus subtraction
    /// operations.
    inline friend T operator-(const T& a, const T& b) {
        return a.ModSub(b);
    }
    inline friend const T& operator-=(T& a, const T& b) {
        return a.ModSubEq(b);
    }

    /// inline operator for the unary minus
    inline friend T operator-(const T& a) {
        return a.ModMul(a.GetModulus() - I(1));
    }

    /**
   * Scalar-to-vector modulus multiplication operation.
   *
   * @param &b is the scalar to perform operation with.
   * @return is the result of the modulus multiplication operation.
   */
    T ModMul(const I& b) const;

    /**
   * Scalar-to-vector modulus multiplication operation. In-place variant.
   *
   * @param &b is the scalar to perform operation with.
   * @return is the result of the modulus multiplication operation.
   */
    T& ModMulEq(const I& b);

    /// inline operators for the scalar-to-vector modulus multiplication
    /// operations.
    friend T operator*(const T& a, const I& b) {
        return a.ModMul(b);
    }
    friend T& operator*=(T& a, const I& b) {
        return a.ModMulEq(b);
    }

    /**
   * Vector component wise modulus multiplication.
   *
   * @param &b is the vector to perform operation with.
   * @return is the result of the component wise modulus multiplication
   * operation.
   */
    T ModMul(const T& b) const;

    /**
   * Vector component wise modulus multiplication. In-place variant.
   *
   * @param &b is the vector to perform operation with.
   * @return is the result of the component wise modulus multiplication
   * operation.
   */
    T& ModMulEq(const T& b);
    T& ModMulNoCheckEq(const T& b);

    /// inline operators for the vector component wise modulus multiplication
    /// operations.
    friend T operator*(const T& a, const T& b) {
        return a.ModMul(b);
    }
    friend T& operator*=(T& a, const T& b) {
        return a.ModMulEq(b);
    }

    /**
   * Scalar modulus exponentiation operation.
   *
   * @param &b is the scalar to perform operation with.
   * @return is the result of the modulus exponentiation operation.
   */
    T ModExp(const I& b) const;

    /**
   * Scalar modulus exponentiation operation. In-place variant.
   *
   * @param &b is the scalar to perform operation with.
   * @return is the result of the modulus exponentiation operation.
   */
    T& ModExpEq(const I& b);

    /**
   * Modulus inverse operation.
   *
   * @return is the result of the component wise modulus inverse operation.
   */
    T ModInverse() const;

    /**
   * Modulus inverse operation. In-place variant.
   *
   * @return is the result of the component wise modulus inverse operation.
   */
    T& ModInverseEq();

    /**
   * Modulus 2 operation, also a least significant bit.
   *
   * @return is the result of the component wise modulus 2 operation, also a
   * least significant bit.
   */
    T ModByTwo() const;

    /**
   * Modulus 2 operation, also a least significant bit. In-place variant.
   *
   * @return is the result of the component wise modulus 2 operation, also a
   * least significant bit.
   */
    T& ModByTwoEq();

    /**
   * Multiply and Rounding operation. Returns [x*p/q] where [] is the rounding
   * operation.
   *
   * @param &p is the numerator to be multiplied.
   * @param &q is the denominator to be divided.
   * @return is the result of multiply and round operation.
   */
    T MultiplyAndRound(const I& p, const I& q) const;

    /**
   * Multiply and Rounding operation. Returns [x*p/q] where [] is the rounding
   * operation. In-place variant.
   *
   * @param &p is the numerator to be multiplied.
   * @param &q is the denominator to be divided.
   * @return is the result of multiply and round operation.
   */
    T& MultiplyAndRoundEq(const I& p, const I& q);

    /**
   * Divide and Rounding operation. Returns [x/q] where [] is the rounding
   * operation.
   *
   * @param &q is the denominator to be divided.
   * @return is the result of divide and round operation.
   */
    T DivideAndRound(const I& q) const;

    /**
   * Divide and Rounding operation. Returns [x/q] where [] is the rounding
   * operation. In-place variant.
   *
   * @param &q is the denominator to be divided.
   * @return is the result of divide and round operation.
   */
    T& DivideAndRoundEq(const I& q);

    // OTHER FUNCTIONS

    /**
   * Digit vector at a specific index for all entries for a given number base.
   * Example: for vector (83, 1, 45), index 2 and base 4 we have:
   *
   *                           index:0,1,2,3
   * |83|                           |3,0,1,1|                 |1|
   * |1 | --base 4 decomposition--> |1,0,0,0| --at index 2--> |0|
   * |45|                           |1,3,2,0|                 |2|
   *
   * The return vector is (1,0,2)
   *
   * @param index is the index to return the digit from in all entries.
   * @param base is the base to use for the operation.
   * @return is the digit at a specific index for all entries for a given number
   * base
   */
    T GetDigitAtIndexForBase(usint index, usint base) const;

protected:
    ~BigVectorInterface() = default;

    // STRINGS & STREAMS

    // SERIALIZATION
};

}  // namespace lbcrypto
#endif
