// @file ubintfxd.h This file contains the vector manipulation functionality.
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
/*
 * This file contains the main class for big integers: BigInteger. Big integers
 * are represented as arrays of native usigned integers. The native integer type
 * is supplied as a template parameter. Currently implementations based on
 * uint8_t, uint16_t, and uint32_t are supported. The second template parameter
 * is the maximum bitwidth for the big integer.
 */

#ifndef LBCRYPTO_MATH_BIGINTFXD_UBINTFXD_H
#define LBCRYPTO_MATH_BIGINTFXD_UBINTFXD_H

#include <cstdlib>
#include <cstring>
#include <fstream>
#include <functional>
#include <iostream>
#include <limits>
#include <memory>
#include <string>
#include <type_traits>
#include <typeinfo>
#include <vector>
#include "utils/exception.h"
#include "utils/inttypes.h"
#include "utils/memory.h"
#include "utils/palisadebase64.h"
#include "utils/serializable.h"
#include "math/backend.h"

/**
 *@namespace bigintfxd
 * The namespace of bigintfxd
 */
namespace bigintfxd {

using U64BITS = uint64_t;
#if defined(HAVE_INT128)
using U128BITS = unsigned __int128;
#endif

/**The following structs are needed for initialization of BigInteger at the
 *preprocessing stage. The structs compute certain values using template
 *metaprogramming approach and mostly follow recursion to calculate value(s).
 */

/**
 * @brief  Struct to find log value of N.
 *Needed in the preprocessing step of BigInteger to determine bitwidth.
 *
 * @tparam N bitwidth.
 */
template <usint N>
struct Log2 {
  static const usint value = 1 + Log2<N / 2>::value;
};

/**
 * @brief Struct to find log value of N.
 *Base case for recursion.
 *Needed in the preprocessing step of BigInteger to determine bitwidth.
 */
template <>
struct Log2<2> {
  static const usint value = 1;
};

/**
 * @brief Struct to find log value of U where U is a primitive datatype.
 *Needed in the preprocessing step of BigInteger to determine bitwidth.
 *
 * @tparam U primitive data type.
 */
template <typename U>
struct LogDtype {
  static const usint value = Log2<8 * sizeof(U)>::value;
};

/**
 * @brief Struct for validating if Dtype is amongst {uint8_t, uint16_t,
 * uint32_t}
 *
 * @tparam Dtype primitive datatype.
 */
template <typename Dtype>
struct DataTypeChecker {
  static const bool value = false;
};

/**
 * @brief Struct for validating if Dtype is amongst {uint8_t, uint16_t,
 * uint32_t}. sets value true if datatype is unsigned integer 8 bit.
 */
template <>
struct DataTypeChecker<uint8_t> {
  static const bool value = true;
};

/**
 * @brief Struct for validating if Dtype is amongst {uint8_t, uint16_t,
 * uint32_t}. sets value true if datatype is unsigned integer 16 bit.
 */
template <>
struct DataTypeChecker<uint16_t> {
  static const bool value = true;
};

/**
 * @brief Struct for validating if Dtype is amongst {uint8_t, uint16_t,
 * uint32_t}. sets value true if datatype is unsigned integer 32 bit.
 */
template <>
struct DataTypeChecker<uint32_t> {
  static const bool value = true;
};

/**
 * @brief Struct for validating if Dtype is amongst {uint8_t, uint16_t,
 * uint32_t}. sets value true if datatype is unsigned integer 64 bit.
 */
template <>
struct DataTypeChecker<uint64_t> {
  static const bool value = true;
};

/**
 * @brief Struct for calculating bit width from data type.
 * Sets value to the bitwidth of uint_type
 *
 * @tparam uint_type native integer data type.
 */
template <typename uint_type>
struct UIntBitWidth {
  static const int value = 8 * sizeof(uint_type);
};

/**
 * @brief Struct to determine a datatype that is twice as big(bitwise) as utype.
 * sets T as of type void for default case
 *
 * @tparam utype primitive integer data type.
 */
template <typename utype>
struct DoubleDataType {
  typedef void T;
};

/**
 * @brief Struct to determine a datatype that is twice as big(bitwise) as utype.
 * Sets T as of type unsigned integer 16 bit if integral datatype is 8bit
 */
template <>
struct DoubleDataType<uint8_t> {
  typedef uint16_t T;
};

/**
 * @brief Struct to determine a datatype that is twice as big(bitwise) as utype.
 * sets T as of type unsigned integer 32 bit if integral datatype is 16bit
 */
template <>
struct DoubleDataType<uint16_t> {
  typedef uint32_t T;
};

/**
 * @brief Struct to determine a datatype that is twice as big(bitwise) as utype.
 * sets T as of type unsigned integer 64 bit if integral datatype is 32bit
 */
template <>
struct DoubleDataType<uint32_t> {
  typedef uint64_t T;
};

/**
 * @brief Struct to determine a datatype that is twice as big(bitwise) as utype.
 * sets T as of type unsigned integer 128 bit if integral datatype is 64bit
 */
template <>
struct DoubleDataType<uint64_t> {
#if defined(HAVE_INT128)
  typedef __uint128_t T;
#else
  typedef uint64_t T;
#endif
};

const double LOG2_10 =
    3.32192809;  //!< @brief A pre-computed constant of Log base 2 of 10.

/**
 * @brief Main class for big integers represented as an array of native
 * (primitive) unsigned integers
 * @tparam uint_type native unsigned integer type
 * @tparam BITLENGTH maximum bitwidth supported for big integers
 */
template <typename uint_type, usint BITLENGTH>
class BigInteger
    : public lbcrypto::BigIntegerInterface<BigInteger<uint_type, BITLENGTH>> {
 public:
  // CONSTRUCTORS

  /**
   * Default constructor.
   */
  BigInteger();

  /**
   * Copy constructor.
   *
   * @param &val is the big binary integer to be copied.
   */
  BigInteger(const BigInteger &val);

  /**
   * Move constructor.
   *
   * @param &&val is the big binary integer to be copied.
   */
  BigInteger(BigInteger &&val);

  /**
   * Constructor from a string.
   *
   * @param &strval is the initial integer represented as a string.
   */
  explicit BigInteger(const std::string &strval);

  /**
   * Constructor from an unsigned integer.
   *
   * @param val is the initial integer represented as a uint64_t.
   */
  BigInteger(uint64_t val);
#if defined(HAVE_INT128)
  BigInteger(U128BITS val);
#endif

  /**
   * Constructors from smaller basic types
   *
   * @param val is the initial integer represented as a basic integer type.
   */
  BigInteger(int val) : BigInteger(uint64_t(val)) {}
  BigInteger(uint32_t val) : BigInteger(uint64_t(val)) {}
  BigInteger(long val) : BigInteger(uint64_t(val)) {}
  BigInteger(long long val) : BigInteger(uint64_t(val)) {}

  /**
   * Constructor from a NativeInteger
   *
   * @param &val is the initial integer represented as a native integer.
   */
  template <typename T>
  BigInteger(const bigintnat::NativeIntegerT<T> &val)
      : BigInteger(val.ConvertToInt()) {}

  /**
   * Constructor from double is not permitted
   *
   * @param val
   */
  BigInteger(double val)
      __attribute__((deprecated("Cannot construct from a double")));

  ~BigInteger() {}

  // ASSIGNMENT OPERATORS

  /**
   * Copy assignment operator
   *
   * @param &val is the big binary integer to be assigned from.
   * @return assigned BigInteger ref.
   */
  const BigInteger &operator=(const BigInteger &val);

  /**
   * Move assignment operator
   *
   * @param &val is the big binary integer to be assigned from.
   * @return assigned BigInteger ref.
   */
  const BigInteger &operator=(BigInteger &&val);

  /**
   * Assignment operator from string
   *
   * @param strval is the string to be assigned from
   * @return the assigned BigInteger ref.
   */
  const BigInteger &operator=(const std::string strval) {
    *this = BigInteger(strval);
    return *this;
  }

  /**
   * Assignment operator from unsigned integer
   *
   * @param val is the unsigned integer to be assigned from.
   * @return the assigned BigInteger ref.
   */
  const BigInteger &operator=(uint64_t val) {
    *this = BigInteger(val);
    return *this;
  }

  /**
   * Assignment operator from native integer
   *
   * @param &val is the native integer to be assigned from.
   * @return the assigned BigInteger ref.
   */
  const BigInteger &operator=(const bigintnat::NativeInteger &val) {
    *this = BigInteger(val);
    return *this;
  }

  // ACCESSORS

  /**
   * Basic set method for setting the value of a big binary integer
   *
   * @param strval is the string representation of the big binary integer to be
   * copied.
   */
  void SetValue(const std::string &strval);

  /**
   * Basic set method for setting the value of a big binary integer
   *
   * @param val is the big binary integer representation of the big binary
   * integer to be assigned.
   */
  void SetValue(const BigInteger &val);

  /**
   *  Set this int to 1.
   */
  void SetIdentity() { *this = 1; }

  /**
   * Sets the int value at the specified index.
   *
   * @param index is the index of the int to set in the uint array.
   */
  void SetIntAtIndex(usint idx, uint_type value);

  // ARITHMETIC OPERATIONS

  /**
   * Addition operation.
   *
   * @param &b is the value to add.
   * @return result of the addition operation.
   */
  BigInteger Add(const BigInteger &b) const;

  /**
   * Addition operation. In-place variant.
   *
   * @param &b is the value to add.
   * @return result of the addition operation.
   */
  const BigInteger &AddEq(const BigInteger &b);

  /**
   * Subtraction operation.
   *
   * @param &b is the value to subtract.
   * @return is the result of the subtraction operation.
   */
  BigInteger Sub(const BigInteger &b) const;

  /**
   * Subtraction operation. In-place variant.
   *
   * @param &b is the value to subtract.
   * @return is the result of the subtraction operation.
   */
  const BigInteger &SubEq(const BigInteger &b);

  /**
   * Operator for unary minus
   * @return
   */
  BigInteger operator-() const { return BigInteger(0).Sub(*this); }

  /**
   * Multiplication operation.
   *
   * @param &b is the value to multiply with.
   * @return is the result of the multiplication operation.
   */
  BigInteger Mul(const BigInteger &b) const;

  /**
   * Multiplication operation. In-place variant.
   *
   * @param &b is the value to multiply with.
   * @return is the result of the multiplication operation.
   */
  const BigInteger &MulEq(const BigInteger &b);

  /**
   * Division operation.
   *
   * @param &b is the value to divide by.
   * @return is the result of the division operation.
   */
  BigInteger DividedBy(const BigInteger &b) const;

  /**
   * Division operation. In-place variant.
   *
   * @param &b is the value to divide by.
   * @return is the result of the division operation.
   */
  const BigInteger &DividedByEq(const BigInteger &b);

  /**
   * Exponentiation operation. Returns x^p.
   *
   * @param p the exponent.
   * @return is the result of the exponentiation operation.
   */
  BigInteger Exp(usint p) const;

  /**
   * Exponentiation operation. Returns x^p. In-place variant.
   *
   * @param p the exponent.
   * @return is the result of the exponentiation operation.
   */
  const BigInteger &ExpEq(usint p);

  /**
   * Multiply and Rounding operation. Returns [x*p/q] where [] is the rounding
   * operation.
   *
   * @param &p is the numerator to be multiplied.
   * @param &q is the denominator to be divided.
   * @return is the result of multiply and round operation.
   */
  BigInteger MultiplyAndRound(const BigInteger &p, const BigInteger &q) const;

  /**
   * Multiply and Rounding operation. Returns [x*p/q] where [] is the rounding
   * operation. In-place variant.
   *
   * @param &p is the numerator to be multiplied.
   * @param &q is the denominator to be divided.
   * @return is the result of multiply and round operation.
   */
  const BigInteger &MultiplyAndRoundEq(const BigInteger &p,
                                       const BigInteger &q);

  /**
   * Divide and Rounding operation. Returns [x/q] where [] is the rounding
   * operation.
   *
   * @param &q is the denominator to be divided.
   * @return is the result of divide and round operation.
   */
  BigInteger DivideAndRound(const BigInteger &q) const;

  /**
   * Divide and Rounding operation. Returns [x/q] where [] is the rounding
   * operation. In-place variant.
   *
   * @param &q is the denominator to be divided.
   * @return is the result of divide and round operation.
   */
  const BigInteger &DivideAndRoundEq(const BigInteger &q);

  // MODULAR ARITHMETIC OPERATIONS

  /**
   * Naive modulus operation.
   *
   * @param &modulus is the modulus to perform.
   * @return is the result of the modulus operation.
   */
  BigInteger Mod(const BigInteger &modulus) const;

  /**
   * Naive modulus operation. In-place variant.
   *
   * @param &modulus is the modulus to perform.
   * @return is the result of the modulus operation.
   */
  const BigInteger &ModEq(const BigInteger &modulus);

  /**
   * Pre-computes the mu factor that is used in Barrett modulo reduction
   *
   * @return the value of mu
   */
  BigInteger ComputeMu() const;

  /**
   * Barrett modulus operation.
   * Implements generalized Barrett modular reduction algorithm. Uses one
   * precomputed value of mu.
   *
   * @param &modulus is the modulus to perform.
   * @param &mu is the Barrett value.
   * @return is the result of the modulus operation.
   */
  BigInteger Mod(const BigInteger &modulus, const BigInteger &mu) const;

  /**
   * Barrett modulus operation. In-place variant.
   * Implements generalized Barrett modular reduction algorithm. Uses one
   * precomputed value of mu.
   *
   * @param &modulus is the modulus to perform.
   * @param &mu is the Barrett value.
   * @return is the result of the modulus operation.
   */
  const BigInteger &ModEq(const BigInteger &modulus, const BigInteger &mu);

  /**
   * Modulus addition operation.
   *
   * @param &b is the scalar to add.
   * @param &modulus is the modulus to perform operations with.
   * @return is the result of the modulus addition operation.
   */
  BigInteger ModAdd(const BigInteger &b, const BigInteger &modulus) const;

  /**
   * Modulus addition operation. In-place variant.
   *
   * @param &b is the scalar to add.
   * @param &modulus is the modulus to perform operations with.
   * @return is the result of the modulus addition operation.
   */
  const BigInteger &ModAddEq(const BigInteger &b, const BigInteger &modulus);

  /**
   * Modulus addition where operands are < modulus.
   *
   * @param &b is the scalar to add.
   * @param &modulus is the modulus to perform operations with.
   * @return is the result of the modulus addition operation.
   */
  BigInteger ModAddFast(const BigInteger &b, const BigInteger &modulus) const;

  /**
   * Modulus addition where operands are < modulus. In-place variant.
   *
   * @param &b is the scalar to add.
   * @param &modulus is the modulus to perform operations with.
   * @return is the result of the modulus addition operation.
   */
  const BigInteger &ModAddFastEq(const BigInteger &b,
                                 const BigInteger &modulus);

  /**
   * Barrett modulus addition operation.
   *
   * @param &b is the scalar to add.
   * @param &modulus is the modulus to perform operations with.
   * @param &mu is the Barrett value.
   * @return is the result of the modulus addition operation.
   */
  BigInteger ModAdd(const BigInteger &b, const BigInteger &modulus,
                    const BigInteger &mu) const;

  /**
   * Barrett modulus addition operation. In-place variant.
   *
   * @param &b is the scalar to add.
   * @param &modulus is the modulus to perform operations with.
   * @param &mu is the Barrett value.
   * @return is the result of the modulus addition operation.
   */
  const BigInteger &ModAddEq(const BigInteger &b, const BigInteger &modulus,
                             const BigInteger &mu);

  /**
   * Modulus subtraction operation.
   *
   * @param &b is the scalar to subtract.
   * @param &modulus is the modulus to perform operations with.
   * @return is the result of the modulus subtraction operation.
   */
  BigInteger ModSub(const BigInteger &b, const BigInteger &modulus) const;

  /**
   * Modulus subtraction operation. In-place variant.
   *
   * @param &b is the scalar to subtract.
   * @param &modulus is the modulus to perform operations with.
   * @return is the result of the modulus subtraction operation.
   */
  const BigInteger &ModSubEq(const BigInteger &b, const BigInteger &modulus);

  /**
   * Modulus subtraction where operands are < modulus.
   *
   * @param &b is the scalar to subtract.
   * @param &modulus is the modulus to perform operations with.
   * @return is the result of the modulus subtraction operation.
   */
  BigInteger ModSubFast(const BigInteger &b, const BigInteger &modulus) const;

  /**
   * Modulus subtraction where operands are < modulus. In-place variant.
   *
   * @param &b is the scalar to subtract.
   * @param &modulus is the modulus to perform operations with.
   * @return is the result of the modulus subtraction operation.
   */
  const BigInteger &ModSubFastEq(const BigInteger &b,
                                 const BigInteger &modulus);

  /**
   * Barrett modulus subtraction operation.
   *
   * @param &b is the scalar to subtract.
   * @param &modulus is the modulus to perform operations with.
   * @param &mu is the Barrett value.
   * @return is the result of the modulus subtraction operation.
   */
  BigInteger ModSub(const BigInteger &b, const BigInteger &modulus,
                    const BigInteger &mu) const;

  /**
   * Barrett modulus subtraction operation. In-place variant.
   *
   * @param &b is the scalar to subtract.
   * @param &modulus is the modulus to perform operations with.
   * @param &mu is the Barrett value.
   * @return is the result of the modulus subtraction operation.
   */
  const BigInteger &ModSubEq(const BigInteger &b, const BigInteger &modulus,
                             const BigInteger &mu);

  /**
   * Modulus multiplication operation.
   *
   * @param &b is the scalar to multiply.
   * @param &modulus is the modulus to perform operations with.
   * @return is the result of the modulus multiplication operation.
   */
  BigInteger ModMul(const BigInteger &b, const BigInteger &modulus) const;

  /**
   * Modulus multiplication operation. In-place variant.
   *
   * @param &b is the scalar to multiply.
   * @param &modulus is the modulus to perform operations with.
   * @return is the result of the modulus multiplication operation.
   */
  const BigInteger &ModMulEq(const BigInteger &b, const BigInteger &modulus);

  /**
   * Barrett modulus multiplication.
   *
   * @param &b is the scalar to multiply.
   * @param &modulus is the modulus to perform operations with.
   * @param &mu is the Barrett value.
   * @return is the result of the modulus multiplication operation.
   */
  BigInteger ModMul(const BigInteger &b, const BigInteger &modulus,
                    const BigInteger &mu) const;

  /**
   * Barrett modulus multiplication. In-place variant.
   *
   * @param &b is the scalar to multiply.
   * @param &modulus is the modulus to perform operations with.
   * @param &mu is the Barrett value.
   * @return is the result of the modulus multiplication operation.
   */
  const BigInteger &ModMulEq(const BigInteger &b, const BigInteger &modulus,
                             const BigInteger &mu);

  /**
   * Modulus multiplication that assumes the operands are < modulus.
   *
   * @param &b is the scalar to multiply.
   * @param &modulus is the modulus to perform operations with.
   * @return is the result of the modulus multiplication operation.
   */
  BigInteger ModMulFast(const BigInteger &b, const BigInteger &modulus) const;

  /**
   * Modulus multiplication that assumes the operands are < modulus. In-place
   * variant.
   *
   * @param &b is the scalar to multiply.
   * @param &modulus is the modulus to perform operations with.
   * @return is the result of the modulus multiplication operation.
   */
  const BigInteger &ModMulFastEq(const BigInteger &b,
                                 const BigInteger &modulus);

  /**
   * Barrett modulus multiplication that assumes the operands are < modulus.
   *
   * @param &b is the scalar to multiply.
   * @param &modulus is the modulus to perform operations with.
   * @param &mu is the Barrett value.
   * @return is the result of the modulus multiplication operation.
   */
  BigInteger ModMulFast(const BigInteger &b, const BigInteger &modulus,
                        const BigInteger &mu) const;

  /**
   * Barrett modulus multiplication that assumes the operands are < modulus.
   * In-place variant.
   *
   * @param &b is the scalar to multiply.
   * @param &modulus is the modulus to perform operations with.
   * @param &mu is the Barrett value.
   * @return is the result of the modulus multiplication operation.
   */
  const BigInteger &ModMulFastEq(const BigInteger &b, const BigInteger &modulus,
                                 const BigInteger &mu);

  BigInteger ModMulFastConst(const BigInteger &b, const BigInteger &modulus,
                             const BigInteger &bInv) const {
    PALISADE_THROW(lbcrypto::not_implemented_error,
                   "ModMulFastConst is not implemented for backend 2");
  }

  const BigInteger &ModMulFastConstEq(const BigInteger &b,
                                      const BigInteger &modulus,
                                      const BigInteger &bInv) {
    PALISADE_THROW(lbcrypto::not_implemented_error,
                   "ModMulFastConstEq is not implemented for backend 2");
  }

  /**
   * Modulus exponentiation operation. Square-and-multiply algorithm is used.
   *
   * @param &b is the scalar to exponentiate at all locations.
   * @param &modulus is the modulus to perform operations with.
   * @return is the result of the modulus exponentiation operation.
   */
  BigInteger ModExp(const BigInteger &b, const BigInteger &modulus) const;

  /**
   * Modulus exponentiation operation. Square-and-multiply algorithm is used.
   * In-place variant.
   *
   * @param &b is the scalar to exponentiate at all locations.
   * @param &modulus is the modulus to perform operations with.
   * @return is the result of the modulus exponentiation operation.
   */
  const BigInteger &ModExpEq(const BigInteger &b, const BigInteger &modulus);

  /**
   * Modulus inverse operation.
   *
   * @param &modulus is the modulus to perform.
   * @return is the result of the modulus inverse operation.
   */
  BigInteger ModInverse(const BigInteger &modulus) const;

  /**
   * Modulus inverse operation. In-place variant.
   *
   * @param &modulus is the modulus to perform.
   * @return is the result of the modulus inverse operation.
   */
  const BigInteger &ModInverseEq(const BigInteger &modulus);

  // SHIFT OPERATIONS

  /**
   * Left shift operation.
   *
   * @param shift # of bits.
   * @return result of the shift operation.
   */
  BigInteger LShift(usshort shift) const;

  /**
   * Left shift operation. In-place variant.
   *
   * @param shift # of bits.
   * @return result of the shift operation.
   */
  const BigInteger &LShiftEq(usshort shift);

  /**
   * Right shift operation.
   *
   * @param shift # of bits.
   * @return result of the shift operation.
   */
  BigInteger RShift(usshort shift) const;

  /**
   * Right shift operation. In-place variant.
   *
   * @param shift # of bits.
   * @return result of the shift operation.
   */
  const BigInteger &RShiftEq(usshort shift);

  // COMPARE

  /**
   * Compares the current BigInteger to BigInteger a.
   *
   * @param a is the BigInteger to be compared with.
   * @return  -1 for strictly less than, 0 for equal to and 1 for strictly
   * greater than conditons.
   */
  int Compare(const BigInteger &a) const;

  // CONVERTERS

  /**
   * Converts the value to an int.
   *
   * @return the int representation of the value as uint64_t.
   */
  template <typename T = bigintnat::BasicInteger>
  T ConvertToInt() const {
    T result = 0;
    // set num to number of equisized chunks
    // usint num = bigintnat::NativeIntegerT<T>::MaxBits() / m_uintBitLength;
    usint num = bigintnat::NativeIntegerT<T>().MaxBits() / m_uintBitLength;
    usint ceilInt = m_nSize - ceilIntByUInt(m_MSB);
    // copy the values by shift and add
    for (usint i = 0; i < num && (m_nSize - i - 1) >= ceilInt; i++) {
      result += ((T)this->m_value[m_nSize - i - 1] << (m_uintBitLength * i));
    }
    if (this->m_MSB > bigintnat::NativeIntegerT<T>::MaxBits()) {
      PALISADE_THROW(
          lbcrypto::math_error,
          std::string("MSB cannot be bigger than ") +
              std::to_string(bigintnat::NativeIntegerT<T>::MaxBits()));
    }
    return result;
  }

  /**
   * Converts the value to an double.
   *
   * @return double representation of the value.
   */
  double ConvertToDouble() const;

  /**
   * Convert a value from an int to a BigInteger.
   *
   * @param m the value to convert from.
   * @return int represented as a big binary int.
   */
  static BigInteger intToBigInteger(usint m);

  /**
   * Convert a string representation of a binary number to a decimal BigInteger.
   *
   * @param bitString the binary num in string.
   * @return the binary number represented as a big binary int.
   */
  static BigInteger FromBinaryString(const std::string &bitString);

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
  usint GetLengthForBase(usint base) const { return GetMSB(); }

  /**
   * Get a specific digit at "digit" index; big integer is seen as an array of
   * digits, where a 0 <= digit < base Warning: only power-of-2 bases are
   * currently supported. Example: for number 83, index 2 and base 4 we have:
   *
   *                         index:0,1,2,3
   * 83 --base 4 decomposition--> (3,0,1,1) --at index 2--> 1
   *
   * The return number is 1.
   *
   * @param index is the "digit" index of the requested digit
   * @param base is the base with which to determine length in.
   * @return is the requested digit
   */
  usint GetDigitAtIndexForBase(usint index, usint base) const;

  /**
   * Tests whether the BigInteger is a power of 2.
   *
   * @param m_numToCheck is the value to check.
   * @return true if the input is a power of 2, false otherwise.
   */
  bool CheckIfPowerOfTwo(const BigInteger &m_numToCheck);

  /**
   * Gets the bit at the specified index.
   *
   * @param index is the index of the bit to get.
   * @return resulting bit.
   */
  uschar GetBitAtIndex(usint index) const;

  /**
   * A zero allocator that is called by the Matrix class. It is used to
   * initialize a Matrix of BigInteger objects.
   */
  static BigInteger Allocator() { return 0; }

  // STRINGS & STREAMS

  /**
   * Stores the based 10 equivalent/Decimal value of the BigInteger in a string
   * object and returns it.
   *
   * @return value of this BigInteger in base 10 represented as a string.
   */
  const std::string ToString() const;

  static const std::string IntegerTypeName() { return "UBFIXINT"; }

  /**
   * Delivers value of the internal limb storage
   * Used primarily for debugging
   * @return STL vector of uint_type
   */
  std::string GetInternalRepresentation(void) const {
    std::string ret("");
    size_t ceilInt = ceilIntByUInt(this->m_MSB);  // max limb used

    for (size_t i = m_nSize - 1; i >= (size_t)(m_nSize - ceilInt); i--) {
      ret += std::to_string(m_value[i]);
      if (i != (size_t)(m_nSize - ceilInt)) ret += " ";
    }
    return ret;
  }

  /**
   * Console output operation.
   *
   * @param os is the std ostream object.
   * @param ptr_obj is BigInteger to be printed.
   * @return is the ostream object.
   */
  template <typename uint_type_c, usint BITLENGTH_c>
  friend std::ostream &operator<<(
      std::ostream &os, const BigInteger<uint_type_c, BITLENGTH_c> &ptr_obj) {
    usint counter;
    // initiate to object to be printed
    auto print_obj = new BigInteger<uint_type_c, BITLENGTH_c>(ptr_obj);
    // print_VALUE array stores the decimal value in the array
    uschar *print_VALUE = new uschar[ptr_obj.m_numDigitInPrintval];
    for (size_t i = 0; i < ptr_obj.m_numDigitInPrintval; i++) {
      // reset to zero
      *(print_VALUE + i) = 0;
    }
    // starts the conversion from base r to decimal value
    for (size_t i = print_obj->m_MSB; i > 0; i--) {
      // print_VALUE = print_VALUE*2
      BigInteger<uint_type_c, BITLENGTH_c>::double_bitVal(print_VALUE);
      // adds the bit value to the print_VALUE
      BigInteger<uint_type_c, BITLENGTH_c>::add_bitVal(
          print_VALUE, print_obj->GetBitAtIndex(i));
    }
    // find the first occurence of non-zero value in print_VALUE
    for (counter = 0; counter < ptr_obj.m_numDigitInPrintval - 1; counter++) {
      if (static_cast<int>(print_VALUE[counter]) != 0) {
        break;
      }
    }
    // start inserting values into the ostream object
    for (; counter < ptr_obj.m_numDigitInPrintval; counter++) {
      os << static_cast<int>(print_VALUE[counter]);
    }
    // deallocate the memory since values are inserted into the ostream object
    delete[] print_VALUE;
    delete print_obj;
    return os;
  }

  // SERIALIZATION

  template <class Archive>
  typename std::enable_if<!cereal::traits::is_text_archive<Archive>::value,
                          void>::type
  save(Archive &ar, std::uint32_t const version) const {
    ar(::cereal::binary_data(m_value, sizeof(m_value)));
    ar(::cereal::binary_data(&m_MSB, sizeof(m_MSB)));
  }

  template <class Archive>
  typename std::enable_if<cereal::traits::is_text_archive<Archive>::value,
                          void>::type
  save(Archive &ar, std::uint32_t const version) const {
    ar(::cereal::make_nvp("v", m_value));
    ar(::cereal::make_nvp("m", m_MSB));
  }

  template <class Archive>
  typename std::enable_if<!cereal::traits::is_text_archive<Archive>::value,
                          void>::type
  load(Archive &ar, std::uint32_t const version) {
    if (version > SerializedVersion()) {
      PALISADE_THROW(lbcrypto::deserialize_error,
                     "serialized object version " + std::to_string(version) +
                         " is from a later version of the library");
    }
    ar(::cereal::binary_data(m_value, sizeof(m_value)));
    ar(::cereal::binary_data(&m_MSB, sizeof(m_MSB)));
  }

  template <class Archive>
  typename std::enable_if<cereal::traits::is_text_archive<Archive>::value,
                          void>::type
  load(Archive &ar, std::uint32_t const version) {
    if (version > SerializedVersion()) {
      PALISADE_THROW(lbcrypto::deserialize_error,
                     "serialized object version " + std::to_string(version) +
                         " is from a later version of the library");
    }
    ar(::cereal::make_nvp("v", m_value));
    ar(::cereal::make_nvp("m", m_MSB));
  }

  std::string SerializedObjectName() const { return "FXDInteger"; }

  static uint32_t SerializedVersion() { return 1; }

 protected:
  /**
   * Converts the string v into base-r integer where r is equal to 2^bitwidth of
   * integral data type.
   *
   * @param v The input string
   */
  void AssignVal(const std::string &v);

  /**
   * Sets the MSB to the correct value from the BigInteger.
   */
  void SetMSB();

  /**
   * Sets the MSB to the correct value from the BigInteger.
   * @param guessIdxChar is the hint of the MSB position.
   */
  void SetMSB(usint guessIdxChar);

 private:
  // array storing the native integers.
  // array size is the ceiling of BITLENGTH/(bits in the integral data type)
  uint_type m_value[(BITLENGTH + 8 * sizeof(uint_type) - 1) /
                    (8 * sizeof(uint_type))];

  // variable that stores the MOST SIGNIFICANT BIT position in the number.
  usshort m_MSB;

  // variable to store the bit width of the integral data type.
  static const uschar m_uintBitLength;

  // variable to store the maximum value of the integral data type.
  static const uint_type m_uintMax;

  // variable to store the log(base 2) of the number of bits in the integral
  // data type.
  static const uschar m_logUintBitLength;

  // variable to store the size of the data array.
  static const usint m_nSize;

  // The maximum number of digits in BigInteger. It is used by the cout(ostream)
  // function for printing the bigbinarynumber.
  static const usint m_numDigitInPrintval;

  /**
   * function to return the ceiling of the number divided by the number of bits
   * in the integral data type.
   * @param Number is the number to be divided.
   * @return the ceiling of Number/(bits in the integral data type)
   */
  static uint_type ceilIntByUInt(const uint_type Number);

  // currently unused array
  static const BigInteger *m_modChain;

  /**
   * function to return the MSB of number.
   * @param x is the number.
   * @return the MSB position in the number x.
   */

  static usint GetMSBUint_type(uint_type x);

  // Duint_type is the data type that has twice as many bits in the integral
  // data type.
  typedef typename DoubleDataType<uint_type>::T Duint_type;

  /**
   * function to return the MSB of number that is of type Duint_type.
   * @param x is the number.
   * @return the MSB position in the number x.
   */
  static usint GetMSBDUint_type(Duint_type x);

  /**
   * function that returns the BigInteger after multiplication by a uint.
   * @param b is the number to be multiplied.
   * @return the BigInteger after the multiplication.
   */
  BigInteger MulByUint(const uint_type b) const;

  /**
   * function that returns the BigInteger after multiplication by a uint.
   * @param b is the number to be multiplied.
   * @return the BigInteger after the multiplication.
   */
  void MulByUintToInt(const uint_type b, BigInteger *ans) const;

  /**
   * function that returns the decimal value from the binary array a.
   * @param a is a pointer to the binary array.
   * @return the decimal value.
   */
  static uint_type UintInBinaryToDecimal(uschar *a);

  /**
   * function that mutiplies by 2 to the binary array.
   * @param a is a pointer to the binary array.
   */
  static void double_bitVal(uschar *a);

  /**
   * function that adds bit b to the binary array.
   * @param a is a pointer to the binary array.
   * @param b is a bit value to be added.
   */
  static void add_bitVal(uschar *a, uschar b);
};

extern template class BigInteger<integral_dtype, BigIntegerBitLength>;

}  // namespace bigintfxd

#endif  // LBCRYPTO_MATH_BIGINTFXD_UBINTFXD_H
