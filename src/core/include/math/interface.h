// @file interface.h This file contains the interfaces for math data types
// @author TPOC: contact@palisade-crypto.org
//
// @copyright Copyright (c) 2019, New Jersey Institute of Technology (NJIT)
// All rights reserved.
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
// 1. Redistributions of source code must retain the above copyright notice,
// this list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright notice,
// this list of conditions and the following disclaimer in the documentation
// and/or other materials provided with the distribution. THIS SOFTWARE IS
// PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR
// IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO
// EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
// INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
// LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
// ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#ifndef LBCRYPTO_MATH_INTERFACE_H
#define LBCRYPTO_MATH_INTERFACE_H

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
  inline friend T operator+(const T& a, const T& b) { return a.Add(b); }
  inline friend const T& operator+=(T& a, const T& b) { return a.AddEq(b); }

  /**
   * Subtraction operation.
   *
   * @param &b is the value to subtract.
   * @return is the result of the subtraction operation.
   */
  T Sub(const T& b) const;
  const T& SubEq(const T& b);

  /// inline operators for the subtraction operation.
  inline friend T operator-(const T& a, const T& b) { return a.Sub(b); }
  inline friend const T& operator-=(T& a, const T& b) { return a.SubEq(b); }

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
  inline friend T operator*(const T& a, const T& b) { return a.Mul(b); }
  inline friend const T& operator*=(T& a, const T& b) { return a.MulEq(b); }

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
  inline friend T operator/(const T& a, const T& b) { return a.DividedBy(b); }
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
  inline friend T operator%(const T& a, const T& b) { return a.Mod(b); }
  inline friend const T& operator%=(T& a, const T& b) { return a.ModEq(b); }

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
  friend bool operator==(const T& a, const T& b) { return a.Compare(b) == 0; }
  friend bool operator!=(const T& a, const T& b) { return a.Compare(b) != 0; }

  friend bool operator>(const T& a, const T& b) { return a.Compare(b) > 0; }
  friend bool operator>=(const T& a, const T& b) { return a.Compare(b) >= 0; }
  friend bool operator<(const T& a, const T& b) { return a.Compare(b) < 0; }
  friend bool operator<=(const T& a, const T& b) { return a.Compare(b) <= 0; }

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
  const T& operator=(const T& vec);

  /**
   * Move assignment operator.
   *
   * @param &vec is the vector to be assigned from.
   * @return assigned vector ref.
   */
  const T& operator=(T&& vec);

  /**
   * Assignment operator from initializer list of strings.
   *
   * @param &&strvec is the list of strings.
   * @return assigned vector ref.
   */
  const T& operator=(std::initializer_list<std::string> strvec);

  /**
   * Assignment operator from initializer list of unsigned integers.
   *
   * @param &&vec is the list of integers.
   * @return assigned vector ref.
   */
  const T& operator=(std::initializer_list<uint64_t> vec);

  /**
   * Assignment operator to assign value val to first entry, 0 for the rest of
   * entries.
   *
   * @param val is the unsigned integer the first entry to be assigned from.
   * @return assigned vector ref.
   */
  const T& operator=(uint64_t val);

  // EQUALS OPERATORS

  /**
   * Equals to operator.
   *
   * @param &b is vector to be compared.
   * @return true if equal and false otherwise.
   */
  friend inline bool operator==(const T& a, const T& b) {
    if ((a.GetLength() != b.GetLength()) ||
        (a.GetModulus() != b.GetModulus())) {
      return false;
    }
    for (size_t i = 0; i < a.GetLength(); ++i) {
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
  friend inline bool operator!=(const T& a, const T& b) { return !(a == b); }

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
  const T& ModEq(const I& modulus);

  /// inline operators for the modulus operations.
  inline friend T operator%(const T& a, const I& b) { return a.Mod(b); }
  inline friend const T& operator%=(T& a, const I& b) { return a.ModEq(b); }

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
  const T& ModAddEq(const I& b);

  /// inline operators for the scara-to-vector modulus addition operations.
  inline friend T operator+(const T& a, const I& b) { return a.ModAdd(b); }
  inline friend const T& operator+=(T& a, const I& b) { return a.ModAddEq(b); }

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
  const T& ModAddAtIndexEq(usint i, const I& b);

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
  const T& ModAddEq(const T& b);

  /// inline operators for the vector component wise modulus addition
  /// operations.
  inline friend T operator+(const T& a, const T& b) { return a.ModAdd(b); }
  inline friend const T& operator+=(T& a, const T& b) { return a.ModAddEq(b); }

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
  const T& ModSubEq(const I& b);

  /// inline operators for the scalar-from-vector modulus subtraction
  /// operations.
  inline friend T operator-(const T& a, const I& b) { return a.ModSub(b); }
  inline friend const T& operator-=(T& a, const I& b) { return a.ModSubEq(b); }

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
  const T& ModSubEq(const T& b);

  /// inline operators for the vector component wise modulus subtraction
  /// operations.
  inline friend T operator-(const T& a, const T& b) { return a.ModSub(b); }
  inline friend const T& operator-=(T& a, const T& b) { return a.ModSubEq(b); }

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
  const T& ModMulEq(const I& b);

  /// inline operators for the scalar-to-vector modulus multiplication
  /// operations.
  inline friend T operator*(const T& a, const I& b) { return a.ModMul(b); }
  inline friend const T& operator*=(T& a, const I& b) { return a.ModMulEq(b); }

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
  const T& ModMulEq(const T& b);

  /// inline operators for the vector component wise modulus multiplication
  /// operations.
  inline friend T operator*(const T& a, const T& b) { return a.ModMul(b); }
  inline friend const T& operator*=(T& a, const T& b) { return a.ModMulEq(b); }

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
  const T& ModExpEq(const I& b);

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
  const T& ModInverseEq();

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
  const T& ModByTwoEq();

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
  const T& MultiplyAndRoundEq(const I& p, const I& q);

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
  const T& DivideAndRoundEq(const I& q);

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

  // STRINGS & STREAMS

  // SERIALIZATION
};

// TODO
class BigMatrixInterface {};
}  // namespace lbcrypto

#endif
