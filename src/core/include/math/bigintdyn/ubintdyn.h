// @file ubintdyn.h  This file contains the main class for unsigned big
// integers: ubint. Big integers are represented as arrays of machine native
// unsigned integers. The native integer type is supplied as a template
// parameter.  Currently implementation based on uint32_t and uint64_t is
// supported. a native double the base integer size is also needed.
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

#ifndef LBCRYPTO_MATH_BIGINTDYN_UBINTDYN_H
#define LBCRYPTO_MATH_BIGINTDYN_UBINTDYN_H

#define NO_BARRETT  // currently barrett is slower than mod

#include <fstream>
#include <functional>
#include <iostream>
#include <limits>
#include <memory>
#include <string>
#include <type_traits>
#include <typeinfo>
#include <vector>
#include "math/nbtheory.h"
#include "utils/inttypes.h"
#include "utils/memory.h"
#include "utils/serializable.h"

#ifdef UBINT_64

#undef int128_t
#define int128_t our_int128_t
#undef uint128_t
#define uint128_t our_uint128_t

typedef __int128 int128_t;
typedef unsigned __int128 uint128_t;

#define UINT128_MAX ((uint128_t)-1)

#endif  // UBINT_64

/**
 *@namespace bigintdyn
 * The namespace of this code
 */
namespace bigintdyn {

/**The following structs are needed for initialization of ubint at
 *the preprocessing stage.  The structs compute certain values using
 *template metaprogramming approach and mostly follow recursion to
 *calculate value(s).
 */

/**
 * @brief  Struct to find log value of N.
 *Needed in the preprocessing step of ubint to determine bitwidth.
 *
 * @tparam N bitwidth.
 */

template <usint N>
struct Log2 {
  static const usint value = 1 + Log2<N / 2>::value;
};

/**
 * @brief Struct to find log 2 value of N.
 *Base case for recursion.
 *Needed in the preprocessing step of ubint to determine bitwidth.
 */
template <>
struct Log2<2> {
  static const usint value = 1;
};

/**
 * @brief Struct for validating if Dtype is amongst {uint8_t, uint16_t,
 * uint32_t, uint64_t, uint128_t}
 *
 * @tparam Dtype primitive datatype.
 */
template <typename Dtype>
struct DataTypeChecker {
  static const bool value = false;
};

/**
 * @brief Struct for validating if Dtype is amongst {uint8_t, uint16_t,
 * uint32_t, uint64_t, uint128_t}. sets value true if datatype is unsigned
 * integer 8 bit.
 */
template <>
struct DataTypeChecker<uint8_t> {
  static const bool value = true;
};

/**
 * @brief Struct for validating if Dtype is amongst {uint8_t, uint16_t,
 * uint32_t, uint64_t, uint128_t}. sets value true if datatype is unsigned
 * integer 16 bit.
 */
template <>
struct DataTypeChecker<uint16_t> {
  static const bool value = true;
};

/**
 * @brief Struct for validating if Dtype is amongst {uint8_t, uint16_t,
 * uint32_t, uint64_t, uint128_t}. sets value true if datatype is unsigned
 * integer 32 bit.
 */
template <>
struct DataTypeChecker<uint32_t> {
  static const bool value = true;
};

/**
 * @brief Struct for validating if Dtype is amongst {uint8_t, uint16_t,
 * uint32_t, uint64_t, uint128_t}. sets value true if datatype is unsigned
 * integer 64 bit.
 */
template <>
struct DataTypeChecker<uint64_t> {
  static const bool value = true;
};

#ifdef UBINT_64
/**
 * @brief Struct for validating if Dtype is amongst {uint8_t, uint16_t,
 * uint32_t, uint64_t, uint128_t}. sets value true if datatype is unsigned
 * integer 64 bit.
 */
template <>
struct DataTypeChecker<uint128_t> {
  static const bool value = true;
};
#endif

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
 * Sets T as of type unsigned integer 16 bit if limb datatype is 8bit
 */
template <>
struct DoubleDataType<uint8_t> {
  typedef uint16_t T;
};

/**
 * @brief Struct to determine a datatype that is twice as big(bitwise) as utype.
 * sets T as of type unsigned integer 32 bit if limb datatype is 16bit
 */
template <>
struct DoubleDataType<uint16_t> {
  typedef uint32_t T;
};

/**
 * @brief Struct to determine a datatype that is twice as big(bitwise) as utype.
 * sets T as of type unsigned integer 64 bit if limb datatype is 32bit
 */
template <>
struct DoubleDataType<uint32_t> {
  typedef uint64_t T;
};

#ifdef UBINT_64
/**
 * @brief Struct to determine a datatype that is twice as big(bitwise) as utype.
 * sets T as of type unsigned integer 128 bit if limb datatype is 64bit
 */
template <>
struct DoubleDataType<uint64_t> {
  typedef uint128_t T;
};
#endif

/**
 * @brief Struct to determine a datatype that is the signed version of utype.
 * sets T as of type void for default case
 *
 * @tparam utype primitive integer data type.
 */
template <typename utype>
struct SignedDataType {
  typedef void T;
};

/**
 * @brief Struct to determine a datatype that is the signed version of utype.
 * Sets T as of type signed integer 8 bit if limb datatype is 8bit
 */
template <>
struct SignedDataType<uint8_t> {
  typedef int8_t T;
};

/**
 * @brief Struct to determine a datatype that is the signed version of utype.
 * sets T as of type signed integer 16 bit if limb datatype is 16bit
 */
template <>
struct SignedDataType<uint16_t> {
  typedef int16_t T;
};

/**
 * @brief Struct to determine a datatype that is the signed version of utype.
 * sets T as of type signed integer 32 bit if limb datatype is 32bit
 */
template <>
struct SignedDataType<uint32_t> {
  typedef int32_t T;
};

/**
 * @brief Struct to determine a datatype that is the signed version of utype.
 * sets T as of type signed integer 64 bit if limb datatype is 64bit
 */
template <>
struct SignedDataType<uint64_t> {
  typedef int64_t T;
};

/**
 * @brief Struct to determine a signed datatype that is twice as big(bitwise) as
 * utype. sets T as of type void for default case
 *
 * @tparam utype primitive integer data type.
 */
template <typename utype>
struct SignedDoubleDataType {
  typedef void T;
};

/**
 * @brief Struct to determine a signed datatype that is twice as big(bitwise) as
 * utype. Sets T as of type unsigned integer 16 bit if limb datatype is 8bit
 */
template <>
struct SignedDoubleDataType<uint8_t> {
  typedef int16_t T;
};

/**
 * @brief Struct to determine a signed datatype that is twice as big(bitwise) as
 * utype. sets T as of type unsigned integer 32 bit if limb datatype is 16bit
 */
template <>
struct SignedDoubleDataType<uint16_t> {
  typedef int32_t T;
};

/**
 * @brief Struct to determine a signed datatype that is twice as big(bitwise) as
 * utype. sets T as of type unsigned integer 64 bit if limb datatype is 32bit
 */
template <>
struct SignedDoubleDataType<uint32_t> {
  typedef int64_t T;
};

#ifdef UBINT_64
/**
 * @brief Struct to determine a signed datatype that is twice as big(bitwise) as
 * utype. sets T as of type unsigned integer 128 bit if limb datatype is 64bit
 */
template <>
struct SignedDoubleDataType<uint64_t> {
  typedef int128_t T;
};
#endif

const double LOG2_10 =
    3.32192809;  //!< @brief A pre-computed constant of Log base 2 of 10.

//////////////////////////////////////////////////////////////////////////////////////////////////
// Definition starts here
//////////////////////////////////////////////////////////////////////////////////////////////////
template <typename limb_t>
class ubint : public lbcrypto::BigIntegerInterface<ubint<limb_t>> {
 public:
  // CONSTRUCTORS

  /**
   * Default constructor.
   */
  ubint();

  /**
   * Copy constructor.
   *
   * @param &val is the ubint to be copied.
   */
  ubint(const ubint &val);

  /**
   * Move constructor.
   *
   * @param &&val is the ubint to be copied.
   */
  ubint(ubint &&val);

  /**
   * Constructor from a string.
   *
   * @param &strval is the initial integer represented as a string.
   */
  explicit ubint(const std::string &strval);

  /**
   * Constructor from an unsigned integer.
   *
   * @param val is the initial integer represented as a uint64_t.
   */
  ubint(const uint64_t val);
#if defined(HAVE_INT128)
  ubint(unsigned __int128 val);
#endif

  /**
   * Constructors from smaller basic types
   *
   * @param val is the initial integer represented as a basic integer type.
   */
  ubint(int val) : ubint(uint64_t(val)) {}
  ubint(uint32_t val) : ubint(uint64_t(val)) {}
  ubint(long val) : ubint(uint64_t(val)) {}
  ubint(long long val) : ubint(uint64_t(val)) {}

  /**
   * Constructor from a NativeInteger
   *
   * @param &val is the initial integer represented as a native integer.
   */
  template <typename T>
  ubint(const bigintnat::NativeIntegerT<T> &val) : ubint(val.ConvertToInt()) {}

  /**
   * Constructor from double is not permitted
   *
   * @param val
   */
  ubint(double val)
      __attribute__((deprecated("Cannot construct from a double")));

  /**
   * Destructor.
   */
  ~ubint();

  // ASSIGNMENT OPERATORS

  /**
   * Copy assignment operator
   *
   * @param &val is the ubint to be assigned from.
   * @return assigned ubint ref.
   */
  const ubint &operator=(const ubint &val);

  // TODO move assignment operator?

  /**
   * Assignment operator from string
   *
   * @param strval is the string to be assigned from
   * @return the assigned ubint ref.
   */
  const ubint &operator=(const std::string strval) {
    *this = ubint(strval);
    return *this;
  }

  /**
   * Assignment operator from unsigned integer
   *
   * @param val is the unsigned integer to be assigned from.
   * @return the assigned ubint ref.
   */
  const ubint &operator=(const uint64_t val) {
    *this = ubint(val);
    return *this;
  }

  /**
   * Assignment operator from native integer
   *
   * @param &val is the native integer to be assigned from.
   * @return the assigned ubint ref.
   */
  const ubint &operator=(const bigintnat::NativeInteger &val) {
    *this = ubint(val);
    return *this;
  }

  // ACCESSORS

  /**
   * Basic set method for setting the value of a ubint
   *
   * @param strval is the string representation of the ubint to be copied.
   */
  void SetValue(const std::string &strval);

  /**
   * Basic set method for setting the value of a ubint
   *
   * @param val is the ubint representation of the ubint to be assigned.
   */
  void SetValue(const ubint &val);

  /**
   *  Set this int to 1.
   */
  inline void SetIdentity() { *this = 1; }

  // ARITHMETIC OPERATIONS

  /**
   * Addition operation.
   *
   * @param &b is the value to add.
   * @return result of the addition operation.
   */
  ubint Add(const ubint &b) const;

  /**
   * Addition operation. In-place variant.
   *
   * @param &b is the value to add.
   * @return result of the addition operation.
   */
  const ubint &AddEq(const ubint &b);

  /**
   * Subtraction operation.
   *
   * @param &b is the value to subtract.
   * @return is the result of the subtraction operation.
   */
  ubint Sub(const ubint &b) const;

  /**
   * Subtraction operation. In-place variant.
   *
   * @param &b is the value to subtract.
   * @return is the result of the subtraction operation.
   */
  const ubint &SubEq(const ubint &b);

  // this is a negation operator which really doesn't make sense for an unsinged
  ubint operator-() const { return ubint(0).Sub(*this); }

  /**
   * Multiplication operation.
   *
   * @param &b is the value to multiply with.
   * @return is the result of the multiplication operation.
   */
  ubint Mul(const ubint &b) const;

  /**
   * Multiplication operation. In-place variant.
   *
   * @param &b is the value to multiply with.
   * @return is the result of the multiplication operation.
   */
  const ubint &MulEq(const ubint &b);

  /**
   * Division operation.
   *
   * @param &b is the value to divide by.
   * @return is the result of the division operation.
   */
  ubint DividedBy(const ubint &b) const;

  /**
   * Division operation. In-place variant.
   *
   * @param &b is the value to divide by.
   * @return is the result of the division operation.
   */
  const ubint &DividedByEq(const ubint &b);

  /**
   * Exponentiation operation. Returns x^p.
   *
   * @param p the exponent.
   * @return is the result of the exponentiation operation.
   */
  ubint Exp(usint p) const;

  /**
   * Exponentiation operation. Returns x^p. In-place variant.
   *
   * @param p the exponent.
   * @return is the result of the exponentiation operation.
   */
  const ubint &ExpEq(usint p);

  /**
   * Multiply and Rounding operation. Returns [x*p/q] where [] is the rounding
   * operation.
   *
   * @param &p is the numerator to be multiplied.
   * @param &q is the denominator to be divided.
   * @return is the result of multiply and round operation.
   */
  ubint MultiplyAndRound(const ubint &p, const ubint &q) const;

  /**
   * Multiply and Rounding operation. Returns [x*p/q] where [] is the rounding
   * operation. In-place variant.
   *
   * @param &p is the numerator to be multiplied.
   * @param &q is the denominator to be divided.
   * @return is the result of multiply and round operation.
   */
  const ubint &MultiplyAndRoundEq(const ubint &p, const ubint &q);

  /**
   * Divide and Rounding operation. Returns [x/q] where [] is the rounding
   * operation.
   *
   * @param &q is the denominator to be divided.
   * @return is the result of divide and round operation.
   */
  ubint DivideAndRound(const ubint &q) const;

  /**
   * Divide and Rounding operation. Returns [x/q] where [] is the rounding
   * operation. In-place variant.
   *
   * @param &q is the denominator to be divided.
   * @return is the result of divide and round operation.
   */
  const ubint &DivideAndRoundEq(const ubint &q);

  // MODULAR ARITHMETIC OPERATIONS

  /**
   * Naive modulus operation.
   *
   * @param &modulus is the modulus to perform.
   * @return is the result of the modulus operation.
   */
  ubint Mod(const ubint &modulus) const;

  /**
   * Naive modulus operation. In-place variant.
   *
   * @param &modulus is the modulus to perform.
   * @return is the result of the modulus operation.
   */
  const ubint &ModEq(const ubint &modulus);

  /**
   * Pre-computes the mu factor that is used in Barrett modulo reduction
   *
   * @return the value of mu
   */
  ubint ComputeMu() const;

  /**
   * Barrett modulus operation.
   * Implements generalized Barrett modular reduction algorithm. Uses one
   * precomputed value of mu.
   *
   * @param &modulus is the modulus to perform.
   * @param &mu is the Barrett value.
   * @return is the result of the modulus operation.
   */
  ubint Mod(const ubint &modulus, const ubint &mu) const;

  /**
   * Barrett modulus operation. In-place variant.
   * Implements generalized Barrett modular reduction algorithm. Uses one
   * precomputed value of mu.
   *
   * @param &modulus is the modulus to perform.
   * @param &mu is the Barrett value.
   * @return is the result of the modulus operation.
   */
  const ubint &ModEq(const ubint &modulus, const ubint &mu);

  /**
   * Modulus addition operation.
   *
   * @param &b is the scalar to add.
   * @param &modulus is the modulus to perform operations with.
   * @return is the result of the modulus addition operation.
   */
  ubint ModAdd(const ubint &b, const ubint &modulus) const;

  /**
   * Modulus addition operation. In-place variant.
   *
   * @param &b is the scalar to add.
   * @param &modulus is the modulus to perform operations with.
   * @return is the result of the modulus addition operation.
   */
  const ubint &ModAddEq(const ubint &b, const ubint &modulus);

  /**
   * Modulus addition where operands are < modulus.
   *
   * @param &b is the scalar to add.
   * @param &modulus is the modulus to perform operations with.
   * @return is the result of the modulus addition operation.
   */
  ubint ModAddFast(const ubint &b, const ubint &modulus) const;

  /**
   * Modulus addition where operands are < modulus. In-place variant.
   *
   * @param &b is the scalar to add.
   * @param &modulus is the modulus to perform operations with.
   * @return is the result of the modulus addition operation.
   */
  const ubint &ModAddFastEq(const ubint &b, const ubint &modulus);

  /**
   * Barrett modulus addition operation.
   *
   * @param &b is the scalar to add.
   * @param &modulus is the modulus to perform operations with.
   * @param &mu is the Barrett value.
   * @return is the result of the modulus addition operation.
   */
  ubint ModAdd(const ubint &b, const ubint &modulus, const ubint &mu) const;

  /**
   * Barrett modulus addition operation. In-place variant.
   *
   * @param &b is the scalar to add.
   * @param &modulus is the modulus to perform operations with.
   * @param &mu is the Barrett value.
   * @return is the result of the modulus addition operation.
   */
  const ubint &ModAddEq(const ubint &b, const ubint &modulus, const ubint &mu);

  /**
   * Modulus subtraction operation.
   *
   * @param &b is the scalar to subtract.
   * @param &modulus is the modulus to perform operations with.
   * @return is the result of the modulus subtraction operation.
   */
  ubint ModSub(const ubint &b, const ubint &modulus) const;

  /**
   * Modulus subtraction operation. In-place variant.
   *
   * @param &b is the scalar to subtract.
   * @param &modulus is the modulus to perform operations with.
   * @return is the result of the modulus subtraction operation.
   */
  const ubint &ModSubEq(const ubint &b, const ubint &modulus);

  /**
   * Modulus subtraction where operands are < modulus.
   *
   * @param &b is the scalar to subtract.
   * @param &modulus is the modulus to perform operations with.
   * @return is the result of the modulus subtraction operation.
   */
  ubint ModSubFast(const ubint &b, const ubint &modulus) const;

  /**
   * Modulus subtraction where operands are < modulus. In-place variant.
   *
   * @param &b is the scalar to subtract.
   * @param &modulus is the modulus to perform operations with.
   * @return is the result of the modulus subtraction operation.
   */
  const ubint &ModSubFastEq(const ubint &b, const ubint &modulus);

  /**
   * Barrett modulus subtraction operation.
   *
   * @param &b is the scalar to subtract.
   * @param &modulus is the modulus to perform operations with.
   * @param &mu is the Barrett value.
   * @return is the result of the modulus subtraction operation.
   */
  ubint ModSub(const ubint &b, const ubint &modulus, const ubint &mu) const;

  /**
   * Barrett modulus subtraction operation. In-place variant.
   *
   * @param &b is the scalar to subtract.
   * @param &modulus is the modulus to perform operations with.
   * @param &mu is the Barrett value.
   * @return is the result of the modulus subtraction operation.
   */
  const ubint &ModSubEq(const ubint &b, const ubint &modulus, const ubint &mu);

  /**
   * Modulus multiplication operation.
   *
   * @param &b is the scalar to multiply.
   * @param &modulus is the modulus to perform operations with.
   * @return is the result of the modulus multiplication operation.
   */
  ubint ModMul(const ubint &b, const ubint &modulus) const;

  /**
   * Modulus multiplication operation. In-place variant.
   *
   * @param &b is the scalar to multiply.
   * @param &modulus is the modulus to perform operations with.
   * @return is the result of the modulus multiplication operation.
   */
  const ubint &ModMulEq(const ubint &b, const ubint &modulus);

  /**
   * Barrett modulus multiplication.
   *
   * @param &b is the scalar to multiply.
   * @param &modulus is the modulus to perform operations with.
   * @param &mu is the Barrett value.
   * @return is the result of the modulus multiplication operation.
   */
  ubint ModMul(const ubint &b, const ubint &modulus, const ubint &mu) const;

  /**
   * Barrett modulus multiplication. In-place variant.
   *
   * @param &b is the scalar to multiply.
   * @param &modulus is the modulus to perform operations with.
   * @param &mu is the Barrett value.
   * @return is the result of the modulus multiplication operation.
   */
  const ubint &ModMulEq(const ubint &b, const ubint &modulus, const ubint &mu);

  /**
   * Modulus multiplication that assumes the operands are < modulus.
   *
   * @param &b is the scalar to multiply.
   * @param &modulus is the modulus to perform operations with.
   * @return is the result of the modulus multiplication operation.
   */
  ubint ModMulFast(const ubint &b, const ubint &modulus) const;

  /**
   * Modulus multiplication that assumes the operands are < modulus. In-place
   * variant.
   *
   * @param &b is the scalar to multiply.
   * @param &modulus is the modulus to perform operations with.
   * @return is the result of the modulus multiplication operation.
   */
  const ubint &ModMulFastEq(const ubint &b, const ubint &modulus);

  /**
   * Barrett modulus multiplication that assumes the operands are < modulus.
   *
   * @param &b is the scalar to multiply.
   * @param &modulus is the modulus to perform operations with.
   * @param &mu is the Barrett value.
   * @return is the result of the modulus multiplication operation.
   */
  ubint ModMulFast(const ubint &b, const ubint &modulus, const ubint &mu) const;

  /**
   * Barrett modulus multiplication that assumes the operands are < modulus.
   * In-place variant.
   *
   * @param &b is the scalar to multiply.
   * @param &modulus is the modulus to perform operations with.
   * @param &mu is the Barrett value.
   * @return is the result of the modulus multiplication operation.
   */
  const ubint &ModMulFastEq(const ubint &b, const ubint &modulus,
                            const ubint &mu);

  ubint ModMulFastConst(const ubint &b, const ubint &modulus,
                        const ubint &bInv) const {
    PALISADE_THROW(lbcrypto::not_implemented_error,
                   "ModMulFastConst is not implemented for backend 4");
  }

  const ubint &ModMulFastConstEq(const ubint &b, const ubint &modulus,
                                 const ubint &bInv) {
    PALISADE_THROW(lbcrypto::not_implemented_error,
                   "ModMulFastConstEq is not implemented for backend 4");
  }

  /**
   * Modulus exponentiation operation. Square-and-multiply algorithm is used.
   *
   * @param &b is the scalar to exponentiate at all locations.
   * @param &modulus is the modulus to perform operations with.
   * @return is the result of the modulus exponentiation operation.
   */
  ubint ModExp(const ubint &b, const ubint &modulus) const;

  /**
   * Modulus exponentiation operation. Square-and-multiply algorithm is used.
   * In-place variant.
   *
   * @param &b is the scalar to exponentiate at all locations.
   * @param &modulus is the modulus to perform operations with.
   * @return is the result of the modulus exponentiation operation.
   */
  const ubint &ModExpEq(const ubint &b, const ubint &modulus);

  /**
   * Modulus inverse operation.
   *
   * @param &modulus is the modulus to perform.
   * @return is the result of the modulus inverse operation.
   */
  ubint ModInverse(const ubint &modulus) const;

  /**
   * Modulus inverse operation. In-place variant.
   *
   * @param &modulus is the modulus to perform.
   * @return is the result of the modulus inverse operation.
   */
  const ubint &ModInverseEq(const ubint &modulus);

  // SHIFT OPERATIONS

  /**
   * Left shift operation.
   *
   * @param shift # of bits.
   * @return result of the shift operation.
   */
  ubint LShift(usshort shift) const;

  /**
   * Left shift operation. In-place variant.
   *
   * @param shift # of bits.
   * @return result of the shift operation.
   */
  const ubint &LShiftEq(usshort shift);

  /**
   * Right shift operation.
   *
   * @param shift # of bits.
   * @return result of the shift operation.
   */
  ubint RShift(usshort shift) const;

  /**
   * Right shift operation. In-place variant.
   *
   * @param shift # of bits.
   * @return result of the shift operation.
   */
  const ubint &RShiftEq(usshort shift);

  // COMPARE

  /**
   * Compares the current ubint to ubint a.
   *
   * @param a is the ubint to be compared with.
   * @return  -1 for strictly less than, 0 for equal to and 1 for strictly
   * greater than conditons.
   */
  int Compare(const ubint &a) const;

  // CONVERTERS

  /**
   * Converts the value to a native integer.
   * @return the int representation of the value as usint.
   */
  template <typename T = bigintnat::BasicInteger>
  T ConvertToInt() const {
    T result = 0;
    if (m_value.size() == 0) {
      PALISADE_THROW(lbcrypto::not_available_error,
                     "ConvertToInt() on uninitialized bint");
    }
    if (sizeof(limb_t) >= sizeof(T)) {
      result = m_value[0];
      result = (T)m_value[0];
    } else {
      // Case where limb_t is less bits than uint64_t
      size_t msbTest = sizeof(T) * 8;
      if (msbTest > m_MSB) {
        msbTest = m_MSB;
      }
      usint ceilInt = ceilIntByUInt(msbTest);
      // copy the values by shift and add
      for (usint i = 0; i < ceilInt; i++) {
        T tmp = this->m_value[i];
        tmp <<= (m_limbBitLength * i);
        result += tmp;
      }
    }
    return result;
  }

  /**
   * Converts the value to a float
   * if the ubint is uninitialized error is thrown
   * if the ubint is larger than the max value representable
   * or if conversion fails, and error is reported to cerr
   *
   * @return float representation of the value.
   */
  float ConvertToFloat() const;

  /**
   * Converts the value to an double.
   * if the ubint is uninitialized error is thrown
   * if the ubint is larger than the max value representable
   * error is thrown
   * if conversion fails error is thrown
   *
   * @return double representation of the value.
   */
  double ConvertToDouble() const;

  /**
   * Converts the value to an long double.
   * if the ubint is uninitialized error is thrown
   * if the ubint is larger than the max value representable
   * error is thrown
   * if conversion fails error is thrown
   *
   * @return long double representation of the value.
   */
  long double ConvertToLongDouble() const;

  /**
   * Convert a value from an unsigned int to a ubint.
   *
   * @param m the value to convert from.
   * @return int represented as a ubint.
   */
  static ubint UsintToUbint(usint m);

  /**
   * Convert a string representation of a binary number to a ubint.
   * Note: needs renaming to a generic form since the variable type name is
   * embedded in the function name. Suggest FromBinaryString()
   * @param bitString the binary num in string.
   * @return the  number represented as a ubint.
   */
  static ubint FromBinaryString(const std::string &bitString);

  // OTHER FUNCTIONS

  /**
   * Returns the MSB location of the value.
   *
   * @return the index of the most significant bit.
   */
  usint GetMSB() const;

  /**
   * Returns the size of the underlying vector of Limbs
   *
   * @return the size
   */
  usint GetNumberOfLimbs() const;

  /**
   * Tests whether the ubint is a power of 2.
   *
   * @param m_numToCheck is the value to check.
   * @return true if the input is a power of 2, false otherwise.
   */
  bool isPowerOfTwo(const ubint &m_numToCheck);

  /**
   * Get the number of digits using a specific base - support for arbitrary base
   * may be needed.
   *
   * @param base is the base with which to determine length in.
   * @return the length of the representation in a specific base.
   */
  usint GetLengthForBase(usint base) const { return GetMSB(); }

  /**
   * Get the number of digits using a specific base.
   * Warning: only power-of-2 bases are currently supported.
   * Example: for number 83, index 2 and base 4 we have:
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

  /**
   * Gets the state of the ubint from the internal value.
   */
  const std::string GetState() const;

  /**
   * function that returns the ubint after multiplication by b.
   * @param b is the number to be multiplied.
   * @return the ubint after the multiplication.
   */
  inline ubint MulIntegerByLimb(limb_t b) const;  // todo rename to ubint

  /**
   * Gets the bit at the specified index.
   *
   * @param index is the index of the bit to get.
   * @return resulting bit.
   */
  uschar GetBitAtIndex(usint index) const;

  /**
   * A zero allocator that is called by the Matrix class. It is used to
   * initialize a Matrix of ubint objects.
   */
  static ubint Allocator() { return 0; }

  // STRINGS & STREAMS

  /**
   * Stores the based 10 equivalent/Decimal value of the ubint in a string
   * object and returns it.
   *
   * @return value of this ubint in base 10 represented as a string.
   */
  const std::string ToString() const;

 public:
#ifdef UBINT_32
  static const std::string IntegerTypeName() { return "UBDYNINT_32"; }
#endif
#ifdef UBINT_64
  static const std::string IntegerTypeName() { return "UBDYNINT_64"; }
#endif

  /**
   * Delivers value of the internal limb storage
   * Used primarily for debugging
   * @return STL vector of uint_type
   */
  std::string GetInternalRepresentation() const {
    std::string ret("");
    for (size_t i = 0; i < m_value.size(); i++) {
      ret += std::to_string(m_value[i]);
      if (i < (m_value.size() - 1)) {
        ret += " ";
      }
    }
    return ret;
  }

  /**
   * ostream output << operator
   * Algorithm used is double and add
   * http://www.wikihow.com/Convert-from-Binary-to-Decimal
   *
   * @param os is the std ostream object.
   * @param ptr_obj is ubint to be printed.
   * @return is the returned ostream object.
   */
  friend std::ostream &operator<<(std::ostream &os, const ubint &ptr_obj) {
    // todo: get rid of m_numDigitInPrintval and make dynamic

    // initiate to object to be printed
    // todo smartpointer
    uschar *print_VALUE = new uschar[ptr_obj.m_numDigitInPrintval]();
    // starts the conversion from base r to decimal value
    for (usint i = ptr_obj.m_MSB; i > 0; i--) {
      ubint::double_bitVal(print_VALUE);
      // adds the bit value to the print_VALUE (print_VALUE *= 2)
      ubint::add_bitVal(print_VALUE, ptr_obj.GetBitAtIndex(i));
    }

    // find the first occurence of non-zero value in print_VALUE
    bool print = false;
    for (usint counter = 0; counter < ptr_obj.m_numDigitInPrintval; counter++) {
      if (print_VALUE[counter] != 0) {
        print = true;
      }
      if (print) {
        os << static_cast<int>(print_VALUE[counter]);
      }
    }
    // Print 0 value
    if (!print) {
      os << 0;
    }
    delete[] print_VALUE;
    return os;
  }

  /**
   * documentation function, prints sizes of constats.
   */
  void PrintIntegerConstants();

  // SERIALIZATION

  template <class Archive>
  void save(Archive &ar, std::uint32_t const version) const {
    ar(::cereal::make_nvp("v", m_value));
    ar(::cereal::make_nvp("m", m_MSB));
    ar(::cereal::make_nvp("s", m_state));
  }

  template <class Archive>
  void load(Archive &ar, std::uint32_t const version) {
    if (version > SerializedVersion()) {
      PALISADE_THROW(lbcrypto::deserialize_error,
                     "serialized object version " + std::to_string(version) +
                         " is from a later version of the library");
    }
    ar(::cereal::make_nvp("v", m_value));
    ar(::cereal::make_nvp("m", m_MSB));
    ar(::cereal::make_nvp("s", m_state));
  }

  std::string SerializedObjectName() const { return "DYNInteger"; }

  static uint32_t SerializedVersion() { return 1; }

 protected:
  /**
   * Converts the string v into base-r integer where r is equal to 2^bitwidth of
   * limb data type.
   *
   * @param v The input string
   */
  void AssignVal(const std::string &v);

  /**
   * Sets the MSB to the correct value as computed from the internal value.
   */
  void SetMSB();

  /**
   * Sets the MSB to the correct value from the ubint.
   * @param guessIdxChar is the hint of the MSB position.
   */
  void SetMSB(usint guessIdxChar);

 private:
  /**
   * Normalize limb storage of the ubint by making sure the most
   * significant limb is non-zero (all higher zero limbs are
   * removed).
   *
   * @return resulting bit.
   */
  void NormalizeLimbs(void);

  /**
   * Sets the limb value at the specified index.
   *
   * @param index is the index of the limb to set in the ubint storage.
   * //todo should be renamed SetLimbAtIndex();
   */
  void SetIntAtIndex(usint idx, limb_t value);

  /**
   * helper function for Div
   * @param defined in ubint.cpp
   */

  int divqr_vect(ubint &q, ubint &r, const ubint &u, const ubint &v) const;

  int divr_vect(ubint &r, const ubint &u, const ubint &v) const;

  int divq_vect(ubint &q, const ubint &u, const ubint &v) const;

 private:
  // vector storing the native integers. stored little endian
  vector<limb_t> m_value;

 private:
  // variable that stores the MOST SIGNIFICANT BIT position in the
  size_t m_MSB;

  // variable to store the bitlength of the limb data type.
  static const usint m_limbBitLength;

  // variable to store the maximum value of the limb data type.
  static const limb_t m_MaxLimb;

  // variable to store the log(base 2) of the number of bits in the limb data
  // type.
  static const usint m_log2LimbBitLength;

  // variable to store the size of the data array.
  static const usint m_nSize;

  // The maximum number of digits in biginteger. It is used by the cout(ostream)
  // function for printing the bignumber. Todo remove this limitation
  static const usint m_numDigitInPrintval =
      1500;  // todo get rid of m_numDigitInPrintval

  /**
   * function to return the ceiling of the input number divided by
   * the number of bits in the limb data type.  DBC this is to
   * determine how many limbs are needed for an input bitsize.
   * @param Number is the number to be divided.
   * @return the ceiling of Number/(bits in the limb data type)
   */
  static usint ceilIntByUInt(
      const limb_t Number);  // todo rename to MSB2NLimbs()

  // currently unused array
  static const ubint *m_modChain;

 private:
  /**
   * function to return the MSB of number.
   * @param x is the number.
   * @return the MSB position in the number x.Note MSB(1) is 1 NOT zero!!!!!
   */

  inline static usint GetMSBlimb_t(limb_t x) { return lbcrypto::GetMSB64(x); }

  // Dlimb_t is the data type that has twice as many bits in the limb data type.
  typedef typename DoubleDataType<limb_t>::T Dlimb_t;

  // Slimb_t is the data type that as many bits in the limb data type but is
  // signed.
  typedef typename SignedDataType<limb_t>::T Slimb_t;

  // Slimb_t is the data type that as many bits in the limb data type but is
  // signed.
  typedef typename SignedDoubleDataType<limb_t>::T Sdlimb_t;

  // enum definition to represent the state of the ubint.
  enum State { INITIALIZED, GARBAGE };

  /**
   * function to return the MSB of number that is of type Dlimb_t.
   * @param x is the number.
   * @return the MSB position in the number x. Note MSB(1) is 1 NOT zero!!!!!
   */
  inline static usint GetMSBDlimb_t(Dlimb_t x) { return lbcrypto::GetMSB64(x); }

  // enum to store the state of the
  State m_state;

  /**
   * function that returns the decimal value from the binary array a.
   * @param a is a pointer to the binary array.
   * @return the decimal value.
   */
  static limb_t UintInBinaryToDecimal(uschar *a);

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

#if 0
// stream helper function for vector of objects
template <typename limb_t>
inline std::ostream &operator<<(std::ostream &os,
                                const std::vector<limb_t> &v) {
  os << "[";
  for (const auto &itr : v) {
    os << " " << itr;
  }
  os << " ]";
  return os;
}
#endif
}  // namespace bigintdyn

#endif  // LBCRYPTO_MATH_BIGINTDYN_UBINTDYN_H
