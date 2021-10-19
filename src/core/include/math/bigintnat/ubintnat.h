// @file ubintnat.h This file contains the main class for native integers.
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
 * This file contains the main class for native integers.
 * It implements the same methods as other mathematical backends.
 */

#ifndef LBCRYPTO_MATH_BIGINTNAT_UBINTNAT_H
#define LBCRYPTO_MATH_BIGINTNAT_UBINTNAT_H

#include <cstdlib>
#include <fstream>
#include <functional>
#include <iostream>
#include <limits>
#include <memory>
#include <sstream>
#include <string>
#include <type_traits>
#include <typeinfo>
#include <vector>

#include "math/interface.h"
#include "math/nbtheory.h"
#include "utils/debug.h"
#include "utils/exception.h"
#include "utils/inttypes.h"
#include "utils/memory.h"
#include "utils/palisadebase64.h"
#include "utils/serializable.h"

// the default behavior of the native integer layer is
// to assume that the user does not need bounds/range checks
// in the native integer code
// if you want them, change this #define to true
// we use a #define to resolve which to use at compile time
// sadly, making the choice according to some setting that
// is checked at runtime has awful performance; using this
// #define in a simple expression causes the compiler to
// optimize away the test
#define NATIVEINT_DO_CHECKS false

using U32BITS = uint32_t;
using U64BITS = uint64_t;
#if defined(HAVE_INT128)
using U128BITS = unsigned __int128;
#endif

namespace bigintnat {

const double LOG2_10 =
    3.32192809;  //!< @brief A pre-computed  constant of Log base 2 of 10.

const usint BARRETT_LEVELS = 8;  //!< @brief The number of levels (precomputed
                                 //!< values) used in the Barrett reductions.

/**
 * @brief Struct to determine a datatype that is twice as big(bitwise) as utype.
 * sets T as of type void for default case
 *
 * @tparam utype primitive integer data type.
 */
template <typename utype>
struct DoubleDataType {
  using DoubleType = void;
  using SignedType = void;
};

/**
 * @brief Struct to determine a datatype that is twice as big(bitwise) as utype.
 * sets T as of type unsigned integer 64 bit if integral datatype is 32bit
 */
template <>
struct DoubleDataType<uint32_t> {
  using DoubleType = uint64_t;
  using SignedType = int32_t;
};

/**
 * @brief Struct to determine a datatype that is twice as big(bitwise) as utype.
 * sets T as of type unsigned integer 128 bit if integral datatype is 64bit
 */
template <>
struct DoubleDataType<uint64_t> {
#if defined(HAVE_INT128)
  using DoubleType = __uint128_t;
#else
  using DoubleType = uint64_t;
#endif
  using SignedType = int64_t;
};

#if defined(HAVE_INT128)
template <>
struct DoubleDataType<unsigned __int128> {
  using DoubleType = __uint128_t;
  using SignedType = __int128;
};
#endif

/**
 * @brief Main class for big integers represented as an array of native
 * (primitive) unsigned integers
 * @tparam NativeInt native unsigned integer type
 */
template <typename NativeInt>
class NativeIntegerT
    : public lbcrypto::BigIntegerInterface<NativeIntegerT<NativeInt>> {
 public:
  using Integer = NativeInt;
  using DNativeInt = typename DoubleDataType<NativeInt>::DoubleType;
  using SignedNativeInt = typename DoubleDataType<NativeInt>::SignedType;

  // a data structure to represent a double-word integer as two single-word
  // integers
  struct typeD {
    NativeInt hi = 0;
    NativeInt lo = 0;
    inline std::string ConvertToString() {
      std::string ret("hi [");
      ret += toString(hi);
      ret += "], lo [";
      ret += toString(lo);
      ret += "]";
      return ret;
    }
  };

  /// CONSTRUCTORS

  /**
   * Default constructor.
   */
  NativeIntegerT() : m_value(0) {}

  /**
   * Copy constructor.
   *
   * @param &val is the native integer to be copied.
   */
  NativeIntegerT(const NativeIntegerT &val) : m_value(val.m_value) {}

  /**
   * Move constructor.
   *
   * @param &&val is the native integer to be copied.
   */
  NativeIntegerT(const NativeIntegerT &&val)
      : m_value(std::move(val.m_value)) {}

  /**
   * Constructor from a string.
   *
   * @param &strval is the initial integer represented as a string.
   */
  NativeIntegerT(const std::string &strval) { AssignVal(strval); }

  /**
   * Constructor from an unsigned integer.
   *
   * @param &val is the initial integer represented as a NativeInt.
   */
  NativeIntegerT(NativeInt val) : m_value(val) {}

  /**
   * Constructors from smaller basic types
   * @param init
   */
  template <typename T = NativeInt>
  NativeIntegerT(int16_t init,
                 typename std::enable_if<!std::is_same<T, int16_t>::value,
                                         bool>::type = true)
      : m_value(init) {}

  template <typename T = NativeInt>
  NativeIntegerT(uint16_t init,
                 typename std::enable_if<!std::is_same<T, uint16_t>::value,
                                         bool>::type = true)
      : m_value(init) {}

  template <typename T = NativeInt>
  NativeIntegerT(int32_t init,
                 typename std::enable_if<!std::is_same<T, int32_t>::value,
                                         bool>::type = true)
      : m_value(init) {}

  template <typename T = NativeInt>
  NativeIntegerT(uint32_t init,
                 typename std::enable_if<!std::is_same<T, uint32_t>::value,
                                         bool>::type = true)
      : m_value(init) {}

  template <typename T = NativeInt>
  NativeIntegerT(
      long init,
      typename std::enable_if<!std::is_same<T, long>::value, bool>::type = true)
      : m_value(init) {}

  template <typename T = NativeInt>
  NativeIntegerT(unsigned long init,
                 typename std::enable_if<!std::is_same<T, unsigned long>::value,
                                         bool>::type = true)
      : m_value(init) {}

  template <typename T = NativeInt>
  NativeIntegerT(long long init,
                 typename std::enable_if<!std::is_same<T, long long>::value,
                                         bool>::type = true)
      : m_value(init) {}

  template <typename T = NativeInt>
  NativeIntegerT(
      unsigned long long init,
      typename std::enable_if<!std::is_same<T, unsigned long long>::value,
                              bool>::type = true)
      : m_value(init) {}

#if defined(HAVE_INT128)
  template <typename T = NativeInt>
  NativeIntegerT(
      unsigned __int128 val,
      typename std::enable_if<!std::is_same<T, unsigned __int128>::value,
                              bool>::type = true)
      : m_value(val) {}

  template <typename T = NativeInt>
  NativeIntegerT(__int128 val,
                 typename std::enable_if<!std::is_same<T, __int128>::value,
                                         bool>::type = true)
      : m_value(val) {}
#endif

  /**
   * Constructor from a BigInteger
   *
   * @param &val is the initial integer represented as a big integer.
   */
  NativeIntegerT(const lbcrypto::BigInteger &val)
      : m_value(val.ConvertToInt()) {}

  /**
   * Constructor from double is not permitted
   *
   * @param val
   */
  NativeIntegerT(double val)
      __attribute__((deprecated("Cannot construct from a double")));

  /// ASSIGNMENT OPERATORS

  /**
   * Copy assignment operator
   *
   * @param &val is the native integer to be assigned from.
   * @return assigned NativeIntegerT ref.
   */
  const NativeIntegerT &operator=(const NativeIntegerT &val) {
    this->m_value = val.m_value;
    return *this;
  }

  /**
   * Move assignment operator
   *
   * @param &&val is the native integer to be assigned from.
   * @return assigned NativeIntegerT ref.
   */
  const NativeIntegerT &operator=(const NativeIntegerT &&val) {
    this->m_value = val.m_value;
    return *this;
  }

  /**
   * Assignment operator from string
   *
   * @param strval is the string to be assigned from
   * @return the assigned NativeIntegerT ref.
   */
  const NativeIntegerT &operator=(const std::string strval) {
    *this = NativeIntegerT(strval);
    return *this;
  }

  /**
   * Assignment operator from unsigned integer
   *
   * @param &val is the unsigned integer value that is assigned.
   * @return the assigned BigInteger ref.
   */
  const NativeIntegerT &operator=(const NativeInt &val) {
    this->m_value = val;
    return *this;
  }

  // ACCESSORS

  /**
   * Basic set method for setting the value of a native integer
   *
   * @param &strval is the string representation of the native integer to be
   * copied.
   */
  void SetValue(const std::string &strval) { AssignVal(strval); }

  /**
   * Basic set method for setting the value of a native integer
   *
   * @param &val is the big binary integer representation of the native
   * integer to be assigned.
   */
  void SetValue(const NativeIntegerT &val) { m_value = val.m_value; }

  /**
   *  Set this int to 1.
   *  Note some compilers don't like using the ONE constant, above :(
   */
  void SetIdentity() { this->m_value = 1; }

  // ARITHMETIC OPERATIONS

  /**
   * Addition operation.
   *
   * @param &b is the value to add.
   * @return result of the addition operation.
   */
  NativeIntegerT Add(const NativeIntegerT &b) const {
    return NATIVEINT_DO_CHECKS ? AddCheck(b) : AddFast(b);
  }

  /**
   * Addition operation. In-place variant.
   *
   * @param &b is the value to add.
   * @return result of the addition operation.
   */
  const NativeIntegerT &AddEq(const NativeIntegerT &b) {
    return NATIVEINT_DO_CHECKS ? AddEqCheck(b) : AddEqFast(b);
  }

  /**
   * AddEqCheck is the addition in place operation with bounds checking.
   * In-place variant.
   *
   * @param b is the value to add to this.
   * @return result of the addition operation.
   */
  const NativeIntegerT &AddEqCheck(const NativeIntegerT &b) {
    NativeInt oldv = m_value;
    m_value += b.m_value;
    if (m_value < oldv) {
      PALISADE_THROW(lbcrypto::math_error, "Overflow");
    }
    return *this;
  }

  /**
   * AddEqFast is the addition in place operation without bounds checking.
   * In-place variant.
   *
   * @param b is the value to add to this.
   * @return result of the addition operation.
   */
  const NativeIntegerT &AddEqFast(const NativeIntegerT &b) {
    m_value += b.m_value;
    return *this;
  }

  /**
   * Subtraction operation.
   *
   * @param &b is the value to subtract.
   * @return is the result of the subtraction operation.
   */
  NativeIntegerT Sub(const NativeIntegerT &b) const {
    return NATIVEINT_DO_CHECKS ? SubCheck(b) : SubFast(b);
  }

  /**
   * SubCheck is the subtraction operation with bounds checking.
   *
   * @param b is the value to add to this.
   * @return result of the addition operation.
   */
  NativeIntegerT SubCheck(const NativeIntegerT &b) const {
    return m_value <= b.m_value ? 0 : m_value - b.m_value;
  }

  /**
   * SubFast is the subtraction operation without bounds checking.
   *
   * @param b is the value to add to this.
   * @return result of the addition operation.
   */
  NativeIntegerT SubFast(const NativeIntegerT &b) const {
    return m_value - b.m_value;
  }

  /**
   * Subtraction operation. In-place variant.
   *
   * @param &b is the value to subtract.
   * @return is the result of the subtraction operation.
   */
  const NativeIntegerT &SubEq(const NativeIntegerT &b) {
    return NATIVEINT_DO_CHECKS ? SubEqCheck(b) : SubEqFast(b);
  }

  /**
   * SubEqCheck is the subtraction in place operation with bounds checking.
   * In-place variant.
   *
   * @param b is the value to add to this.
   * @return result of the addition operation.
   */
  const NativeIntegerT &SubEqCheck(const NativeIntegerT &b) {
    m_value = m_value <= b.m_value ? 0 : m_value - b.m_value;
    return *this;
  }

  /**
   * SubEqFast is the subtraction in place operation without bounds checking.
   * In-place variant.
   *
   * @param b is the value to add to this.
   * @return result of the addition operation.
   */
  const NativeIntegerT &SubEqFast(const NativeIntegerT &b) {
    m_value -= b.m_value;
    return *this;
  }

  // overloaded binary operators based on integer arithmetic and comparison
  // functions.
  NativeIntegerT operator-() const { return NativeIntegerT(0).Sub(*this); }

  /**
   * Multiplication operation.
   *
   * @param &b is the value to multiply with.
   * @return is the result of the multiplication operation.
   */
  NativeIntegerT Mul(const NativeIntegerT &b) const {
    return NATIVEINT_DO_CHECKS ? MulCheck(b) : MulFast(b);
  }

  /**
   * MulCheck is the multiplication operation with bounds checking.
   *
   * @param b is the value to multiply with
   * @return result of the multiplication operation
   */
  NativeIntegerT MulCheck(const NativeIntegerT &b) const {
    NativeInt prod = m_value * b.m_value;
    if (prod > 0 && (prod < m_value || prod < b.m_value))
      PALISADE_THROW(lbcrypto::math_error, "Overflow");
    return prod;
  }

  /**
   * MulFast is the multiplication operation without bounds checking.
   *
   * @param b is the value to multiply with.
   * @return result of the multiplication operation.
   */
  NativeIntegerT MulFast(const NativeIntegerT &b) const {
    return m_value * b.m_value;
  }

  /**
   * Multiplication operation. In-place variant.
   *
   * @param &b is the value to multiply with.
   * @return is the result of the multiplication operation.
   */
  const NativeIntegerT &MulEq(const NativeIntegerT &b) {
    return NATIVEINT_DO_CHECKS ? MulEqCheck(b) : MulEqFast(b);
  }

  /**
   * MulEqCheck is the multiplication in place operation with bounds checking.
   * In-place variant.
   *
   * @param b is the value to multiply with
   * @return result of the multiplication operation
   */
  const NativeIntegerT &MulEqCheck(const NativeIntegerT &b) {
    NativeInt oldval = m_value;
    m_value *= b.m_value;
    if (m_value < oldval) {
      PALISADE_THROW(lbcrypto::math_error, "Overflow");
    }
    return *this;
  }

  /**
   * MulEqFast is the multiplication in place operation without bounds
   * checking. In-place variant.
   *
   * @param b is the value to multiply with
   * @return result of the multiplication operation
   */
  const NativeIntegerT &MulEqFast(const NativeIntegerT &b) {
    m_value *= b.m_value;
    return *this;
  }

  /**
   * Division operation.
   *
   * @param &b is the value to divide by.
   * @return is the result of the division operation.
   */
  NativeIntegerT DividedBy(const NativeIntegerT &b) const {
    if (b.m_value == 0) PALISADE_THROW(lbcrypto::math_error, "Divide by zero");
    return this->m_value / b.m_value;
  }

  /**
   * Division operation. In-place variant.
   *
   * @param &b is the value to divide by.
   * @return is the result of the division operation.
   */
  const NativeIntegerT &DividedByEq(const NativeIntegerT &b) {
    if (b.m_value == 0) PALISADE_THROW(lbcrypto::math_error, "Divide by zero");
    this->m_value /= b.m_value;
    return *this;
  }

  /**
   * Exponentiation operation. Returns x^p.
   *
   * @param p the exponent.
   * @return is the result of the exponentiation operation.
   */
  NativeIntegerT Exp(usint p) const {
    if (p == 0) {
      return 1;
    }
    if (p == 1) {
      return NativeIntegerT(*this);
    }
    NativeIntegerT tmp = (*this).Exp(p / 2);
    if (p % 2 == 0) {
      return tmp * tmp;
    } else {
      return tmp * tmp * (*this);
    }
  }

  /**
   * Exponentiation operation. Returns x^p. In-place variant.
   *
   * @param p the exponent.
   * @return is the result of the exponentiation operation.
   */
  const NativeIntegerT &ExpEq(usint p) {
    if (p == 0) {
      this->m_value = 1;
      return *this;
    }
    if (p == 1) {
      return *this;
    }
    NativeIntegerT tmp = this->Exp(p / 2);
    if (p % 2 == 0) {
      *this = (tmp * tmp);
      return *this;
    } else {
      (*this) *= (tmp * tmp);
      return *this;
    }
  }

  /**
   * Multiply and Rounding operation. Returns [x*p/q] where [] is the rounding
   * operation.
   *
   * @param &p is the numerator to be multiplied.
   * @param &q is the denominator to be divided.
   * @return is the result of multiply and round operation.
   */
  NativeIntegerT MultiplyAndRound(const NativeIntegerT &p,
                                  const NativeIntegerT &q) const {
    NativeIntegerT ans = m_value * p.m_value;
    return ans.DivideAndRound(q);
  }

  /**
   * Multiply and Rounding operation. Returns [x*p/q] where [] is the rounding
   * operation. In-place variant.
   *
   * @param &p is the numerator to be multiplied.
   * @param &q is the denominator to be divided.
   * @return is the result of multiply and round operation.
   */
  const NativeIntegerT &MultiplyAndRoundEq(const NativeIntegerT &p,
                                           const NativeIntegerT &q) {
    this->MulEq(p);
    this->DivideAndRoundEq(q);
    return *this;
  }

  /**
   * Computes the quotient of x*p/q, where x,p,q are all NativeInt numbers, x
   * is the current value; uses DNativeInt arithmetic
   *
   * @param p is the multiplicand
   * @param q is the divisor
   * @return the quotient
   */
  template <typename T = NativeInt>
  NativeIntegerT MultiplyAndDivideQuotient(
      const NativeIntegerT &p, const NativeIntegerT &q,
      typename std::enable_if<!std::is_same<T, DNativeInt>::value, bool>::type =
          true) const {
    DNativeInt xD = m_value;
    DNativeInt pD = p.m_value;
    DNativeInt qD = q.m_value;
    return NativeIntegerT(xD * pD / qD);
  }

  template <typename T = NativeInt>
  NativeIntegerT MultiplyAndDivideQuotient(
      const NativeIntegerT &p, const NativeIntegerT &q,
      typename std::enable_if<std::is_same<T, DNativeInt>::value, bool>::type =
          true) const {
    NativeInt xD = m_value;
    NativeInt pD = p.m_value;
    NativeInt qD = q.m_value;
    return NativeIntegerT(xD * pD / qD);
  }

  /**
   * Computes the remainder of x*p/q, where x,p,q are all NativeInt numbers, x
   * is the current value; uses DNativeInt arithmetic. In-place variant.
   *
   * @param p is the multiplicand
   * @param q is the divisor
   * @return the remainder
   */
  template <typename T = NativeInt>
  NativeIntegerT MultiplyAndDivideRemainder(
      const NativeIntegerT &p, const NativeIntegerT &q,
      typename std::enable_if<!std::is_same<T, DNativeInt>::value, bool>::type =
          true) const {
    DNativeInt xD = m_value;
    DNativeInt pD = p.m_value;
    DNativeInt qD = q.m_value;
    return NativeIntegerT((xD * pD) % qD);
  }

  template <typename T = NativeInt>
  NativeIntegerT MultiplyAndDivideRemainder(
      const NativeIntegerT &p, const NativeIntegerT &q,
      typename std::enable_if<std::is_same<T, DNativeInt>::value, bool>::type =
          true) const {
    NativeInt xD = m_value;
    NativeInt pD = p.m_value;
    NativeInt qD = q.m_value;
    return NativeIntegerT((xD * pD) % qD);
  }

  /**
   * Divide and Rounding operation. Returns [x/q] where [] is the rounding
   * operation.
   *
   * @param &q is the denominator to be divided.
   * @return is the result of divide and round operation.
   */
  NativeIntegerT DivideAndRound(const NativeIntegerT &q) const {
    if (q == 0) {
      PALISADE_THROW(lbcrypto::math_error, "Divide by zero");
    }
    NativeInt ans = m_value / q.m_value;
    NativeInt rem = m_value % q.m_value;
    NativeInt halfQ = q.m_value >> 1;
    if (!(rem <= halfQ)) {
      ans += 1;
    }
    return ans;
  }

  /**
   * Divide and Rounding operation. Returns [x/q] where [] is the rounding
   * operation. In-place variant.
   *
   * @param &q is the denominator to be divided.
   * @return is the result of divide and round operation.
   */
  const NativeIntegerT &DivideAndRoundEq(const NativeIntegerT &q) {
    return *this = this->DivideAndRound(q);
  }

  // MODULAR ARITHMETIC OPERATIONS

  /**
   * Naive modulus operation.
   *
   * @param &modulus is the modulus to perform.
   * @return is the result of the modulus operation.
   */
  NativeIntegerT Mod(const NativeIntegerT &modulus) const {
    return m_value % modulus.m_value;
  }

  /**
   * Naive modulus operation. In-place variant.
   *
   * @param &modulus is the modulus to perform.
   * @return is the result of the modulus operation.
   */
  const NativeIntegerT &ModEq(const NativeIntegerT &modulus) {
    m_value %= modulus.m_value;
    return *this;
  }

  /**
   * Precomputes a parameter mu for Barrett modular reduction.
   *
   * @return the precomputed parameter mu.
   */
  template <typename T = NativeInt>
  NativeIntegerT ComputeMu(
      typename std::enable_if<!std::is_same<T, DNativeInt>::value, bool>::type =
          true) const {
    DNativeInt temp(1);
    temp <<= 2 * this->GetMSB() + 3;
    return NativeInt(temp / DNativeInt(this->m_value));
  }

  template <typename T = NativeInt>
  NativeIntegerT ComputeMu(
      typename std::enable_if<std::is_same<T, DNativeInt>::value, bool>::type =
          true) const {
    lbcrypto::BigInteger temp(static_cast<T>(1));
    temp <<= 2 * this->GetMSB() + 3;
    return NativeInt((temp / lbcrypto::BigInteger(*this)).ConvertToInt());
  }

  /**
   * Barrett modulus operation.
   * Implements generalized Barrett modular reduction algorithm. Uses one
   * precomputed value of mu.
   *
   * @param &modulus is the modulus to perform.
   * @param &mu is the Barrett value.
   * @return is the result of the modulus operation.
   */
  template <typename T = NativeInt>
  NativeIntegerT Mod(
      const NativeIntegerT &modulus, const NativeIntegerT &mu,
      typename std::enable_if<!std::is_same<T, DNativeInt>::value, bool>::type =
          true) const {
    typeD tmp1;
    tmp1.lo = this->m_value;
    tmp1.hi = 0;
    DNativeInt tmp(this->m_value);

    long n = modulus.GetMSB();
    long alpha = n + 3;
    long beta = -2;

    // RShiftD is more efficient than the right-shifting of DNativeInt
    NativeInt ql = RShiftD(tmp1, n + beta);
    MultD(ql, mu.m_value, tmp1);
    DNativeInt q = GetD(tmp1);

    // we cannot use RShiftD here because alpha - beta > 63
    // for q larger than 57 bits
    q >>= alpha - beta;
    tmp -= q * DNativeInt(modulus.m_value);

    NativeIntegerT ans;
    ans.m_value = NativeInt(tmp);

    // correction at the end
    if (ans.m_value > modulus.m_value) {
      ans.m_value -= modulus.m_value;
    }
    return ans;
  }

  template <typename T = NativeInt>
  NativeIntegerT Mod(const NativeIntegerT &modulus, const NativeIntegerT &mu,
                     typename std::enable_if<std::is_same<T, DNativeInt>::value,
                                             bool>::type = true) const {
    typeD prod;
    prod.lo = this->m_value;
    prod.hi = 0;
    typeD result = prod;

    long n = modulus.GetMSB();
    long alpha = n + 3;
    long beta = -2;

    NativeInt ql = RShiftD(prod, n + beta);
    MultD(ql, mu.m_value, prod);

    ql = RShiftD(prod, alpha - beta);
    MultD(ql, modulus.m_value, prod);
    SubtractD(result, prod);

    NativeIntegerT ans(result.lo);
    // correction at the end
    if (ans.m_value > modulus.m_value) {
      ans.m_value -= modulus.m_value;
    }
    return ans;
  }

  /**
   * Barrett modulus operation. In-place variant.
   * Implements generalized Barrett modular reduction algorithm. Uses one
   * precomputed value of mu.
   *
   * @param &modulus is the modulus to perform.
   * @param &mu is the Barrett value.
   * @return is the result of the modulus operation.
   */
  template <typename T = NativeInt>
  const NativeIntegerT &ModEq(
      const NativeIntegerT &modulus, const NativeIntegerT &mu,
      typename std::enable_if<!std::is_same<T, DNativeInt>::value, bool>::type =
          true) {
    typeD tmp1;
    tmp1.lo = this->m_value;
    tmp1.hi = 0;
    DNativeInt tmp(this->m_value);

    long n = modulus.GetMSB();
    long alpha = n + 3;
    long beta = -2;

    // RShiftD is more efficient than the right-shifting of DNativeInt
    NativeInt ql = RShiftD(tmp1, n + beta);
    MultD(ql, mu.m_value, tmp1);
    DNativeInt q = GetD(tmp1);

    // we cannot use RShiftD here because alpha - beta > 63
    // for q larger than 57 bits
    q >>= alpha - beta;
    tmp -= q * DNativeInt(modulus.m_value);

    this->m_value = NativeInt(tmp);

    // correction at the end
    if (this->m_value > modulus.m_value) {
      this->m_value -= modulus.m_value;
    }
    return *this;
  }

  template <typename T = NativeInt>
  const NativeIntegerT &ModEq(
      const NativeIntegerT &modulus, const NativeIntegerT &mu,
      typename std::enable_if<std::is_same<T, DNativeInt>::value, bool>::type =
          true) {
    typeD prod;
    prod.lo = this->m_value;
    prod.hi = 0;
    typeD result = prod;

    long n = modulus.GetMSB();
    long alpha = n + 3;
    long beta = -2;

    NativeInt ql = RShiftD(prod, n + beta);
    MultD(ql, mu.m_value, prod);

    ql = RShiftD(prod, alpha - beta);
    MultD(ql, modulus.m_value, prod);
    SubtractD(result, prod);

    this->m_value = result.lo;
    // correction at the end
    if (this->m_value > modulus.m_value) {
      this->m_value -= modulus.m_value;
    }
    return *this;
  }

  /**
   * Modulus addition operation.
   *
   * @param &b is the scalar to add.
   * @param &modulus is the modulus to perform operations with.
   * @return is the result of the modulus addition operation.
   */
  NativeIntegerT ModAdd(const NativeIntegerT &b,
                        const NativeIntegerT &modulus) const {
    NativeInt mod = modulus.m_value;
    NativeInt op1 = this->m_value;
    NativeInt op2 = b.m_value;
    if (op1 >= mod) {
      op1 %= mod;
    }
    if (op2 >= mod) {
      op2 %= mod;
    }
    op1 += op2;
    if (op1 >= mod) {
      op1 -= mod;
    }
    return op1;
  }

  /**
   * Modulus addition operation. In-place variant.
   *
   * @param &b is the scalar to add.
   * @param &modulus is the modulus to perform operations with.
   * @return is the result of the modulus addition operation.
   */
  const NativeIntegerT &ModAddEq(const NativeIntegerT &b,
                                 const NativeIntegerT &modulus) {
    NativeInt mod = modulus.m_value;
    NativeInt op2 = b.m_value;
    if (this->m_value >= mod) {
      this->m_value %= mod;
    }
    if (op2 >= mod) {
      op2 %= mod;
    }
    this->m_value += op2;
    if (this->m_value >= mod) {
      this->m_value -= mod;
    }
    return *this;
  }

  /**
   * Modulus addition where operands are < modulus.
   *
   * @param &b is the scalar to add.
   * @param &modulus is the modulus to perform operations with.
   * @return is the result of the modulus addition operation.
   */
  inline NativeIntegerT ModAddFast(const NativeIntegerT &b,
                                   const NativeIntegerT &modulus) const {
    NativeInt r = this->m_value + b.m_value;
    if (r >= modulus.m_value) {
      r -= modulus.m_value;
    }
    return r;
  }
  /**
   * Modulus addition where operands are < modulus. In-place variant.
   *
   * @param &b is the scalar to add.
   * @param &modulus is the modulus to perform operations with.
   * @return is the result of the modulus addition operation.
   */
  const NativeIntegerT &ModAddFastEq(const NativeIntegerT &b,
                                     const NativeIntegerT &modulus) {
    this->m_value += b.m_value;
    if (this->m_value >= modulus.m_value) {
      this->m_value -= modulus.m_value;
    }
    return *this;
  }

  /**
   * Barrett modulus addition operation.
   *
   * @param &b is the scalar to add.
   * @param &modulus is the modulus to perform operations with.
   * @param &mu is the Barrett value.
   * @return is the result of the modulus addition operation.
   */
  NativeIntegerT ModAdd(const NativeIntegerT &b, const NativeIntegerT &modulus,
                        const NativeIntegerT &mu) const {
    NativeInt mod(modulus.m_value);
    NativeIntegerT av(this->m_value);
    NativeIntegerT bv(b.m_value);
    if (av.m_value >= mod) {
      av.ModEq(modulus, mu);
    }
    if (bv.m_value >= mod) {
      bv.ModEq(modulus, mu);
    }
    av.m_value += bv.m_value;
    if (av.m_value >= mod) {
      av.m_value -= mod;
    }
    return av;
  }

  /**
   * Barrett modulus addition operation. In-place variant.
   *
   * @param &b is the scalar to add.
   * @param &modulus is the modulus to perform operations with.
   * @param &mu is the Barrett value.
   * @return is the result of the modulus addition operation.
   */
  const NativeIntegerT &ModAddEq(const NativeIntegerT &b,
                                 const NativeIntegerT &modulus,
                                 const NativeIntegerT &mu) {
    NativeInt mod(modulus.m_value);
    NativeIntegerT bv(b.m_value);
    if (this->m_value >= mod) {
      this->ModEq(modulus, mu);
    }
    if (bv.m_value >= mod) {
      bv.ModEq(modulus, mu);
    }
    this->m_value += bv.m_value;
    if (this->m_value >= mod) {
      this->m_value -= mod;
    }
    return *this;
  }

  /**
   * Modulus subtraction operation.
   *
   * @param &b is the scalar to subtract.
   * @param &modulus is the modulus to perform operations with.
   * @return is the result of the modulus subtraction operation.
   */
  NativeIntegerT ModSub(const NativeIntegerT &b,
                        const NativeIntegerT &modulus) const {
    NativeInt mod(modulus.m_value);
    NativeInt av(this->m_value);
    NativeInt bv(b.m_value);
    // reduce this to a value lower than modulus
    if (av >= mod) {
      av %= mod;
    }
    // reduce b to a value lower than modulus
    if (bv >= mod) {
      bv %= mod;
    }

    if (av >= bv) {
      av -= bv;
    } else {
      av += (mod - bv);
    }
    return av;
  }

  /**
   * Modulus subtraction operation. In-place variant.
   *
   * @param &b is the scalar to subtract.
   * @param &modulus is the modulus to perform operations with.
   * @return is the result of the modulus subtraction operation.
   */
  const NativeIntegerT &ModSubEq(const NativeIntegerT &b,
                                 const NativeIntegerT &modulus) {
    NativeInt mod(modulus.m_value);
    NativeInt bv(b.m_value);
    // reduce this to a value lower than modulus
    if (this->m_value >= mod) {
      this->m_value %= mod;
    }
    // reduce b to a value lower than modulus
    if (bv >= mod) {
      bv %= mod;
    }

    if (this->m_value >= bv) {
      this->m_value -= bv;
    } else {
      this->m_value += (mod - bv);
    }
    return *this;
  }

  /**
   * Modulus subtraction where operands are < modulus.
   *
   * @param &b is the scalar to subtract.
   * @param &modulus is the modulus to perform operations with.
   * @return is the result of the modulus subtraction operation.
   */
  inline NativeIntegerT ModSubFast(const NativeIntegerT &b,
                                   const NativeIntegerT &modulus) const {
    NativeInt mod(modulus.m_value);
    NativeInt av(this->m_value);
    NativeInt bv(b.m_value);

    if (av >= bv) {
      av -= bv;
    } else {
      av += (mod - bv);
    }
    return av;
  }

  /**
   * Modulus subtraction where operands are < modulus. In-place variant.
   *
   * @param &b is the scalar to subtract.
   * @param &modulus is the modulus to perform operations with.
   * @return is the result of the modulus subtraction operation.
   */
  const NativeIntegerT &ModSubFastEq(const NativeIntegerT &b,
                                     const NativeIntegerT &modulus) {
    if (this->m_value >= b.m_value) {
      this->m_value -= b.m_value;
    } else {
      this->m_value += (modulus.m_value - b.m_value);
    }
    return *this;
  }

  /**
   * Barrett modulus subtraction operation.
   *
   * @param &b is the scalar to subtract.
   * @param &modulus is the modulus to perform operations with.
   * @param &mu is the Barrett value.
   * @return is the result of the modulus subtraction operation.
   */
  NativeIntegerT ModSub(const NativeIntegerT &b, const NativeIntegerT &modulus,
                        const NativeIntegerT &mu) const {
    NativeInt mod(modulus.m_value);
    NativeIntegerT av(this->m_value);
    NativeIntegerT bv(b.m_value);
    if (av.m_value >= mod) {
      av.ModEq(modulus, mu);
    }
    if (bv.m_value >= mod) {
      bv.ModEq(modulus, mu);
    }

    if (av.m_value >= bv.m_value) {
      av.m_value -= bv.m_value;
    } else {
      av.m_value += (mod - bv.m_value);
    }
    return av;
  }

  /**
   * Barrett modulus subtraction operation. In-place variant.
   *
   * @param &b is the scalar to subtract.
   * @param &modulus is the modulus to perform operations with.
   * @param &mu is the Barrett value.
   * @return is the result of the modulus subtraction operation.
   */
  const NativeIntegerT &ModSubEq(const NativeIntegerT &b,
                                 const NativeIntegerT &modulus,
                                 const NativeIntegerT &mu) {
    NativeIntegerT bv(b.m_value);
    NativeInt mod(modulus.m_value);
    if (this->m_value >= mod) {
      this->ModEq(modulus, mu);
    }
    if (bv.m_value >= mod) {
      bv.ModEq(modulus, mu);
    }

    if (this->m_value >= bv.m_value) {
      this->m_value -= bv.m_value;
    } else {
      this->m_value += (mod - bv.m_value);
    }
    return *this;
  }

  /**
   * Modulus multiplication operation.
   *
   * @param &b is the scalar to multiply.
   * @param &modulus is the modulus to perform operations with.
   * @return is the result of the modulus multiplication operation.
   */
  template <typename T = NativeInt>
  NativeIntegerT ModMul(
      const NativeIntegerT &b, const NativeIntegerT &modulus,
      typename std::enable_if<!std::is_same<T, DNativeInt>::value, bool>::type =
          true) const {
    NativeInt aval = this->m_value;
    NativeInt bval = b.m_value;
    NativeInt mod = modulus.m_value;
    if (aval > mod) {
      aval %= mod;
    }
    if (bval > mod) {
      bval %= mod;
    }
    DNativeInt av(aval);
    DNativeInt bv(bval);
    DNativeInt result = av * bv;
    DNativeInt dmod(mod);
    if (result >= dmod) {
      result %= dmod;
    }
    return NativeIntegerT(result);
  }

  template <typename T = NativeInt>
  NativeIntegerT ModMul(
      const NativeIntegerT &b, const NativeIntegerT &modulus,
      typename std::enable_if<std::is_same<T, DNativeInt>::value, bool>::type =
          true) const {
    NativeIntegerT mu(modulus.ComputeMu());
    NativeIntegerT a = *this;
    NativeIntegerT bW = b;
    if (a > modulus) {
      a.ModEq(modulus, mu);
    }
    if (bW > modulus) {
      bW.ModEq(modulus, mu);
    }
    return a.ModMul(bW, modulus, mu);
  }

  /**
   * Modulus multiplication operation. In-place variant.
   *
   * @param &b is the scalar to multiply.
   * @param &modulus is the modulus to perform operations with.
   * @return is the result of the modulus multiplication operation.
   */
  template <typename T = NativeInt>
  const NativeIntegerT &ModMulEq(
      const NativeIntegerT &b, const NativeIntegerT &modulus,
      typename std::enable_if<!std::is_same<T, DNativeInt>::value, bool>::type =
          true) {
    NativeInt bval = b.m_value;
    NativeInt mod = modulus.m_value;
    if (this->m_value > mod) {
      this->m_value %= mod;
    }
    if (bval > mod) {
      bval %= mod;
    }
    DNativeInt av(m_value);
    DNativeInt bv(bval);
    DNativeInt result = av * bv;
    DNativeInt dmod(mod);
    if (result >= dmod) {
      result %= dmod;
    }
    *this = NativeIntegerT(result);
    return *this;
  }

  template <typename T = NativeInt>
  const NativeIntegerT &ModMulEq(
      const NativeIntegerT &b, const NativeIntegerT &modulus,
      typename std::enable_if<std::is_same<T, DNativeInt>::value, bool>::type =
          true) {
    NativeIntegerT mu(modulus.ComputeMu());
    NativeIntegerT bW = b;
    if (*this > modulus) {
      ModEq(modulus, mu);
    }
    if (bW > modulus) {
      bW.ModEq(modulus, mu);
    }
    ModMulEq(bW, modulus, mu);
    return *this;
  }

  /**
   * Barrett modulus multiplication.
   *
   * @param &b is the scalar to multiply.
   * @param &modulus is the modulus to perform operations with.
   * @param &mu is the Barrett value.
   * @return is the result of the modulus multiplication operation.
   */
  NativeIntegerT ModMul(const NativeIntegerT &b, const NativeIntegerT &modulus,
                        const NativeIntegerT &mu) const {
    NativeIntegerT ans(*this);
    ans.ModMulEq(b, modulus, mu);
    return ans;
  }

  /**
   * Barrett modulus multiplication. In-place variant.
   *
   * @param &b is the scalar to multiply.
   * @param &modulus is the modulus to perform operations with.
   * @param &mu is the Barrett value.
   * @return is the result of the modulus multiplication operation.
   */
  template <typename T = NativeInt>
  const NativeIntegerT &ModMulEq(
      const NativeIntegerT &b, const NativeIntegerT &modulus,
      const NativeIntegerT &mu,
      typename std::enable_if<!std::is_same<T, DNativeInt>::value, bool>::type =
          true) {
    NativeIntegerT bb(b);

    if (this->m_value > modulus.m_value) {
      this->ModEq(modulus, mu);
    }
    if (bb.m_value > modulus.m_value) {
      bb.ModEq(modulus, mu);
    }

    typeD prod1;
    MultD(this->m_value, b.m_value, prod1);
    DNativeInt prod = GetD(prod1);

    long n = modulus.GetMSB();
    long alpha = n + 3;
    long beta = -2;

    // RShiftD is more efficient than the right-shifting of DNativeInt
    NativeInt ql = RShiftD(prod1, n + beta);
    MultD(ql, mu.m_value, prod1);
    DNativeInt q = GetD(prod1);

    // we cannot use RShiftD here because alpha - beta > 63
    // for q larger than 57 bits
    q >>= alpha - beta;
    prod -= q * DNativeInt(modulus.m_value);

    this->m_value = NativeInt(prod);

    // correction at the end
    if (this->m_value > modulus.m_value) {
      this->m_value -= modulus.m_value;
    }
    return *this;
  }

  template <typename T = NativeInt>
  const NativeIntegerT &ModMulEq(
      const NativeIntegerT &b, const NativeIntegerT &modulus,
      const NativeIntegerT &mu,
      typename std::enable_if<std::is_same<T, DNativeInt>::value, bool>::type =
          true) {
    NativeIntegerT bb(b);

    if (this->m_value > modulus.m_value) {
      this->ModEq(modulus, mu);
    }
    if (bb.m_value > modulus.m_value) {
      bb.ModEq(modulus, mu);
    }

    typeD prod1;
    MultD(this->m_value, b.m_value, prod1);
    typeD prod = prod1;

    long n = modulus.GetMSB();
    long alpha = n + 3;
    long beta = -2;

    NativeInt ql = RShiftD(prod1, n + beta);
    MultD(ql, mu.m_value, prod1);

    typeD q;
    ql = RShiftD(prod1, alpha - beta);
    MultD(ql, modulus.m_value, q);
    SubtractD(prod, q);

    this->m_value = prod.lo;

    // correction at the end
    if (this->m_value > modulus.m_value) {
      this->m_value -= modulus.m_value;
    }
    return *this;
  }

  /**
   * Modulus multiplication that assumes the operands are < modulus.
   *
   * @param &b is the scalar to multiply.
   * @param &modulus is the modulus to perform operations with.
   * @return is the result of the modulus multiplication operation.
   */
  template <typename T = NativeInt>
  NativeIntegerT ModMulFast(
      const NativeIntegerT &b, const NativeIntegerT &modulus,
      typename std::enable_if<!std::is_same<T, DNativeInt>::value, bool>::type =
          true) const {
    DNativeInt av(m_value);
    DNativeInt bv(b.m_value);
    DNativeInt result = av * bv;
    DNativeInt mod(modulus.m_value);
    if (result >= mod) {
      result %= mod;
    }
    return NativeIntegerT(result);
  }

  template <typename T = NativeInt>
  NativeIntegerT ModMulFast(
      const NativeIntegerT &b, const NativeIntegerT &modulus,
      typename std::enable_if<std::is_same<T, DNativeInt>::value, bool>::type =
          true) const {
    NativeIntegerT mu(modulus.ComputeMu());
    NativeIntegerT a = *this;
    NativeIntegerT bW = b;
    if (a > modulus) {
      a.ModEq(modulus, mu);
    }
    if (bW > modulus) {
      bW.ModEq(modulus, mu);
    }
    return a.ModMulFast(bW, modulus, mu);
  }

  /**
   * Modulus multiplication that assumes the operands are < modulus. In-place
   * variant.
   *
   * @param &b is the scalar to multiply.
   * @param &modulus is the modulus to perform operations with.
   * @return is the result of the modulus multiplication operation.
   */
  const NativeIntegerT &ModMulFastEq(const NativeIntegerT &b,
                                     const NativeIntegerT &modulus) {
    return *this = this->ModMulFast(b, modulus);
  }

  /**
   * Barrett modulus multiplication that assumes the operands are < modulus.
   *
   * @param &b is the scalar to multiply.
   * @param &modulus is the modulus to perform operations with.
   * @param &mu is the Barrett value.
   * @return is the result of the modulus multiplication operation.
   */
  /* Source: http://homes.esat.kuleuven.be/~fvercaut/papers/bar_mont.pdf
    @article{knezevicspeeding,
    title={Speeding Up Barrett and Montgomery Modular Multiplications},
    author={Knezevic, Miroslav and Vercauteren, Frederik and Verbauwhede,
    Ingrid}
    }
    We use the Generalized Barrett modular reduction algorithm described in
    Algorithm 2 of the Source. The algorithm was originally proposed in J.-F.
    Dhem. Modified version of the Barrett algorithm. Technical report, 1994
    and described in more detail in the PhD thesis of the author published at
    http://users.belgacom.net/dhem/these/these_public.pdf (Section 2.2.4).
    We take \alpha equal to n + 3. So in our case, \mu = 2^(n + \alpha) =
    2^(2*n + 3). Generally speaking, the value of \alpha should be \ge \gamma
    + 1, where \gamma + n is the number of digits in the dividend. We use the
    upper bound of dividend assuming that none of the dividends will be larger
    than 2^(2*n + 3). The value of \mu is computed by NativeVector::ComputeMu.
    */
  template <typename T = NativeInt>
  NativeIntegerT ModMulFast(
      const NativeIntegerT &b, const NativeIntegerT &modulus,
      const NativeIntegerT &mu,
      typename std::enable_if<!std::is_same<T, DNativeInt>::value, bool>::type =
          true) const {
    NativeIntegerT ans(*this);

    typeD prod1;
    MultD(ans.m_value, b.m_value, prod1);
    DNativeInt prod = GetD(prod1);
    typeD q0(prod1);

    long n = modulus.GetMSB();
    long alpha = n + 3;
    long beta = -2;

    // RShiftD is more efficient than the right-shifting of DNativeInt
    NativeInt ql = RShiftD(q0, n + beta);
    MultD(ql, mu.m_value, q0);
    DNativeInt q = GetD(q0);

    // we cannot use RShiftD here because alpha - beta > 63
    // for q larger than 57 bits
    q >>= alpha - beta;
    prod -= q * DNativeInt(modulus.m_value);

    ans.m_value = NativeInt(prod);

    // correction at the end
    if (ans.m_value > modulus.m_value) {
      ans.m_value -= modulus.m_value;
    }
    return ans;
  }

  template <typename T = NativeInt>
  NativeIntegerT ModMulFast(
      const NativeIntegerT &b, const NativeIntegerT &modulus,
      const NativeIntegerT &mu,
      typename std::enable_if<std::is_same<T, DNativeInt>::value, bool>::type =
          true) const {
    NativeIntegerT ans(*this);

    typeD prod1;
    MultD(ans.m_value, b.m_value, prod1);
    typeD prod = prod1;

    long n = modulus.GetMSB();
    long alpha = n + 3;
    long beta = -2;

    NativeInt ql = RShiftD(prod1, n + beta);
    MultD(ql, mu.m_value, prod1);

    typeD q;
    ql = RShiftD(prod1, alpha - beta);
    MultD(ql, modulus.m_value, q);
    SubtractD(prod, q);

    ans.m_value = prod.lo;

    // correction at the end
    if (ans.m_value > modulus.m_value) {
      ans.m_value -= modulus.m_value;
    }
    return ans;
  }

  /**
   * Barrett modulus multiplication that assumes the operands are < modulus.
   * In-place variant.
   *
   * @param &b is the scalar to multiply.
   * @param &modulus is the modulus to perform operations with.
   * @param &mu is the Barrett value.
   * @return is the result of the modulus multiplication operation.
   */
  template <typename T = NativeInt>
  const NativeIntegerT &ModMulFastEq(
      const NativeIntegerT &b, const NativeIntegerT &modulus,
      const NativeIntegerT &mu,
      typename std::enable_if<!std::is_same<T, DNativeInt>::value, bool>::type =
          true) {
    typeD prod1;
    MultD(this->m_value, b.m_value, prod1);
    DNativeInt prod = GetD(prod1);
    typeD q0(prod1);

    long n = modulus.GetMSB();
    long alpha = n + 3;
    long beta = -2;

    // RShiftD is more efficient than the right-shifting of DNativeInt
    NativeInt ql = RShiftD(q0, n + beta);
    MultD(ql, mu.m_value, q0);
    DNativeInt q = GetD(q0);

    // we cannot use RShiftD here because alpha - beta > 63
    // for q larger than 57 bits
    q >>= alpha - beta;
    prod -= q * DNativeInt(modulus.m_value);

    this->m_value = NativeInt(prod);

    // correction at the end
    if (this->m_value > modulus.m_value) {
      this->m_value -= modulus.m_value;
    }
    return *this;
  }

  template <typename T = NativeInt>
  const NativeIntegerT &ModMulFastEq(
      const NativeIntegerT &b, const NativeIntegerT &modulus,
      const NativeIntegerT &mu,
      typename std::enable_if<std::is_same<T, DNativeInt>::value, bool>::type =
          true) {
    typeD prod1;
    MultD(this->m_value, b.m_value, prod1);
    typeD prod = prod1;

    long n = modulus.GetMSB();
    long alpha = n + 3;
    long beta = -2;

    NativeInt ql = RShiftD(prod1, n + beta);
    MultD(ql, mu.m_value, prod1);

    typeD q;
    ql = RShiftD(prod1, alpha - beta);
    MultD(ql, modulus.m_value, q);
    SubtractD(prod, q);

    this->m_value = prod.lo;

    // correction at the end
    if (this->m_value > modulus.m_value) {
      this->m_value -= modulus.m_value;
    }
    return *this;
  }

  /*  The next three subroutines implement the modular multiplication
    algorithm for the case when the multiplicand is used multiple times (known
    in advance), as in NTT. The algorithm is described in
    https://arxiv.org/pdf/1205.2926.pdf (Dave Harvey, FASTER ARITHMETIC FOR
    NUMBER-THEORETIC TRANSFORMS). The algorithm is described in lines 5-7 of
    Algorithm 2. The algorithm was originally proposed and implemented in NTL
    (https://www.shoup.net/ntl/) by Victor Shoup.
    */

  /**
   * Precomputation for a multiplicand.
   *
   * @param modulus is the modulus to perform operations with.
   * @return the precomputed factor.
   */
  template <typename T = NativeInt>
  NativeIntegerT PrepModMulConst(
      const NativeIntegerT &modulus,
      typename std::enable_if<!std::is_same<T, DNativeInt>::value, bool>::type =
          true) const {
    DNativeInt w = DNativeInt(this->m_value) << MaxBits();
    return NativeInt(w / DNativeInt(modulus.m_value));
  }

  template <typename T = NativeInt>
  NativeIntegerT PrepModMulConst(
      const NativeIntegerT &modulus,
      typename std::enable_if<std::is_same<T, DNativeInt>::value, bool>::type =
          true) const {
    lbcrypto::BigInteger w = lbcrypto::BigInteger(m_value) << MaxBits();
    return NativeInt(
        (w / lbcrypto::BigInteger(modulus.m_value)).ConvertToInt());
  }

  /**
   * Modular multiplication using a precomputation for the multiplicand.
   *
   * @param &b is the NativeIntegerT to multiply.
   * @param modulus is the modulus to perform operations with.
   * @param &bInv precomputation for b.
   * @return is the result of the modulus multiplication operation.
   */
  NativeIntegerT ModMulFastConst(const NativeIntegerT &b,
                                 const NativeIntegerT &modulus,
                                 const NativeIntegerT &bInv) const {
    NativeInt q = MultDHi(this->m_value, bInv.m_value);
    NativeInt yprime = this->m_value * b.m_value - q * modulus.m_value;
    return SignedNativeInt(yprime) - SignedNativeInt(modulus.m_value) >= 0
               ? yprime - modulus.m_value
               : yprime;
  }

  /**
   * Modular multiplication using a precomputation for the multiplicand.
   * In-place variant.
   *
   * @param &b is the NativeIntegerT to multiply.
   * @param modulus is the modulus to perform operations with.
   * @param &bInv precomputation for b.
   * @return is the result of the modulus multiplication operation.
   */
  const NativeIntegerT &ModMulFastConstEq(const NativeIntegerT &b,
                                          const NativeIntegerT &modulus,
                                          const NativeIntegerT &bInv) {
    NativeInt q = MultDHi(this->m_value, bInv.m_value);
    NativeInt yprime = this->m_value * b.m_value - q * modulus.m_value;
    this->m_value =
        SignedNativeInt(yprime) - SignedNativeInt(modulus.m_value) >= 0
            ? yprime - modulus.m_value
            : yprime;
    return *this;
  }

  /**
   * Modulus exponentiation operation.
   *
   * @param &b is the scalar to exponentiate at all locations.
   * @param &modulus is the modulus to perform operations with.
   * @return is the result of the modulus exponentiation operation.
   */
  template <typename T = NativeInt>
  NativeIntegerT ModExp(
      const NativeIntegerT &b, const NativeIntegerT &mod,
      typename std::enable_if<!std::is_same<T, DNativeInt>::value, bool>::type =
          true) const {
    DNativeInt exp(b.m_value);
    DNativeInt product(1);
    DNativeInt modulus(mod.m_value);
    DNativeInt mid(m_value % mod.m_value);
    const DNativeInt ZERO(0);
    const DNativeInt ONE(1);
    const DNativeInt TWO(2);

    while (true) {
      if (exp % TWO == ONE) {
        product = product * mid;
      }

      // running product is calculated
      if (product >= modulus) {
        product = product % modulus;
      }

      // divide by 2 and check even to odd to find bit value
      exp >>= 1;
      if (exp == ZERO) {
        break;
      }

      // mid calculates mid^2%q
      mid = mid * mid;
      mid = mid % modulus;
    }
    return NativeIntegerT(product);
  }

  template <typename T = NativeInt>
  NativeIntegerT ModExp(
      const NativeIntegerT &b, const NativeIntegerT &mod,
      typename std::enable_if<std::is_same<T, DNativeInt>::value, bool>::type =
          true) const {
    NativeInteger mu(mod.ComputeMu());
    NativeInteger exp(b.m_value);
    NativeInteger product(1);
    NativeInteger modulus(mod.m_value);
    NativeInteger mid(m_value % mod.m_value);
    const NativeInteger ZERO(0);
    const NativeInteger ONE(1);
    const NativeInteger TWO(2);

    while (true) {
      if (exp % TWO == ONE) {
        product.ModMulFastEq(mid, modulus, mu);
      }

      // divide by 2 and check even to odd to find bit value
      exp >>= 1;
      if (exp == ZERO) {
        break;
      }

      mid.ModMulFastEq(mid, modulus, mu);
    }

    return NativeIntegerT(product);
  }

  /**
   * Modulus exponentiation operation. In-place variant.
   *
   * @param &b is the scalar to exponentiate at all locations.
   * @param &modulus is the modulus to perform operations with.
   * @return is the result of the modulus exponentiation operation.
   */
  const NativeIntegerT &ModExpEq(const NativeIntegerT &b,
                                 const NativeIntegerT &mod) {
    *this = ModExp(b, mod);
    return *this;
  }

  /**
   * Modulus inverse operation.
   *
   * @param &modulus is the modulus to perform.
   * @return is the result of the modulus inverse operation.
   */
  NativeIntegerT ModInverse(const NativeIntegerT &mod) const {
    NativeInt modulus = mod.m_value;
    NativeInt a = m_value % modulus;
    if (a == 0) {
      std::string msg = toString(m_value) +
                        " does not have a ModInverse using " +
                        toString(modulus);
      PALISADE_THROW(lbcrypto::math_error, msg);
    }
    if (modulus == 1) {
      return 0;
    }

    SignedNativeInt m0 = modulus;
    SignedNativeInt y = 0;
    SignedNativeInt x = 1;
    while (a > 1) {
      // q is quotient
      SignedNativeInt q = a / modulus;

      SignedNativeInt t = modulus;
      modulus = a % modulus;
      a = t;

      // Update y and x
      t = y;
      y = x - q * y;
      x = t;
    }

    // Make x positive
    if (x < 0) x += m0;

    return NativeInt(x);
  }

  /**
   * Modulus inverse operation. In-place variant.
   *
   * @param &modulus is the modulus to perform.
   * @return is the result of the modulus inverse operation.
   */
  const NativeIntegerT &ModInverseEq(const NativeIntegerT &mod) {
    *this = ModInverse(mod);
    return *this;
  }

  // SHIFT OPERATIONS

  /**
   * Left shift operation.
   *
   * @param shift # of bits.
   * @return result of the shift operation.
   */
  NativeIntegerT LShift(usshort shift) const { return m_value << shift; }

  /**
   * Left shift operation. In-place variant.
   *
   * @param shift # of bits.
   * @return result of the shift operation.
   */
  const NativeIntegerT &LShiftEq(usshort shift) {
    m_value <<= shift;
    return *this;
  }

  /**
   * Right shift operation.
   *
   * @param shift # of bits.
   * @return result of the shift operation.
   */
  NativeIntegerT RShift(usshort shift) const { return m_value >> shift; }

  /**
   * Right shift operation. In-place variant.
   *
   * @param shift # of bits.
   * @return result of the shift operation.
   */
  const NativeIntegerT &RShiftEq(usshort shift) {
    m_value >>= shift;
    return *this;
  }

  // COMPARE

  /**
   * Compares the current NativeIntegerT to NativeIntegerT a.
   *
   * @param a is the NativeIntegerT to be compared with.
   * @return  -1 for strictly less than, 0 for equal to and 1 for strictly
   * greater than conditons.
   */
  int Compare(const NativeIntegerT &a) const {
    if (this->m_value < a.m_value)
      return -1;
    else if (this->m_value > a.m_value)
      return 1;
    return 0;
  }

  // CONVERTERS

  /**
   * Converts the value to an int.
   *
   * @return the int representation of the value as usint.
   */
  template <typename OutputType = NativeInt>
  OutputType ConvertToInt() const {
    if (sizeof(OutputType) < sizeof(m_value))
      PALISADE_THROW(lbcrypto::type_error,
                     "Invalid integer conversion: sizeof(OutputIntType) < "
                     "sizeof(InputIntType)");
    return static_cast<OutputType>(m_value);
  }

  /**
   * Converts the value to an double.
   *
   * @return double representation of the value.
   */
  double ConvertToDouble() const { return static_cast<double>(m_value); }

  /**
   * Convert a string representation of a binary number to a NativeIntegerT.
   *
   * @param bitString the binary num in string.
   * @return the binary number represented as a big binary int.
   */
  static NativeIntegerT FromBinaryString(const std::string &bitString) {
    if (bitString.length() > MaxBits()) {
      PALISADE_THROW(lbcrypto::math_error,
                     "Bit string is too long to fit in a bigintnat");
    }
    NativeInt v = 0;
    for (size_t i = 0; i < bitString.length(); i++) {
      int n = bitString[i] - '0';
      if (n < 0 || n > 1) {
        PALISADE_THROW(lbcrypto::math_error,
                       "Bit string must contain only 0 or 1");
      }
      v <<= 1;
      v |= n;
    }
    return v;
  }

  // OTHER FUNCTIONS

  /**
   * Returns the MSB location of the value.
   *
   * @return the index of the most significant bit.
   */
  usint GetMSB() const { return lbcrypto::GetMSB(this->m_value); }

  /**
   * Get the number of digits using a specific base - support for arbitrary
   * base may be needed.
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
  usint GetDigitAtIndexForBase(usint index, usint base) const {
    usint DigitLen = ceil(log2(base));
    usint digit = 0;
    usint newIndex = 1 + (index - 1) * DigitLen;
    for (usint i = 1; i < base; i = i * 2) {
      digit += GetBitAtIndex(newIndex) * i;
      newIndex++;
    }
    return digit;
  }

  /**
   * Gets the bit at the specified index.
   *
   * @param index is the index of the bit to get.
   * @return resulting bit.
   */
  uschar GetBitAtIndex(usint index) const {
    if (index == 0) {
      PALISADE_THROW(lbcrypto::math_error, "Zero index in GetBitAtIndex");
    }

    return (m_value >> (index - 1)) & 0x01;
  }

  /**
   * A zero allocator that is called by the Matrix class.
   * It is used to initialize a Matrix of NativeIntegerT objects.
   */
  static NativeIntegerT Allocator() { return 0; }

  // STRINGS & STREAMS

  /**
   * Stores the based 10 equivalent/Decimal value of the NativeIntegerT in a
   * string object and returns it.
   *
   * @return value of this NativeIntegerT in base 10 represented as a string.
   */
  const std::string ToString() const { return toString(m_value); }

  static const std::string IntegerTypeName() { return "UBNATINT"; }

  /**
   * Console output operation.
   *
   * @param os is the std ostream object.
   * @param ptr_obj is NativeIntegerT to be printed.
   * @return is the ostream object.
   */
  friend std::ostream &operator<<(std::ostream &os,
                                  const NativeIntegerT &ptr_obj) {
    os << ptr_obj.ToString();
    return os;
  }

  // SERIALIZATION

  template <class Archive, typename T = void>
  typename std::enable_if<std::is_same<NativeInt, U64BITS>::value ||
                              std::is_same<NativeInt, U32BITS>::value,
                          T>::type
  load(Archive &ar, std::uint32_t const version) {
    if (version > SerializedVersion()) {
      PALISADE_THROW(lbcrypto::deserialize_error,
                     "serialized object version " + std::to_string(version) +
                         " is from a later version of the library");
    }
    ar(::cereal::make_nvp("v", m_value));
  }

#if defined(HAVE_INT128)
  template <class Archive>
  typename std::enable_if<std::is_same<NativeInt, U128BITS>::value &&
                              !cereal::traits::is_text_archive<Archive>::value,
                          void>::type
  load(Archive &ar, std::uint32_t const version) {
    if (version > SerializedVersion()) {
      PALISADE_THROW(lbcrypto::deserialize_error,
                     "serialized object version " + std::to_string(version) +
                         " is from a later version of the library");
    }
    // get an array with 2 unint64_t values for m_value
    uint64_t vec[2];
    ar(::cereal::binary_data(vec, sizeof(vec)));  // 2*8 - size in bytes
    m_value = vec[1];                             // most significant word
    m_value <<= 64;
    m_value += vec[0];  // least significant word
  }

  template <class Archive>
  typename std::enable_if<std::is_same<NativeInt, U128BITS>::value &&
                              cereal::traits::is_text_archive<Archive>::value,
                          void>::type
  load(Archive &ar, std::uint32_t const version) {
    if (version > SerializedVersion()) {
      PALISADE_THROW(lbcrypto::deserialize_error,
                     "serialized object version " + std::to_string(version) +
                         " is from a later version of the library");
    }
    // get an array with 2 unint64_t values for m_value
    uint64_t vec[2];
    ar(::cereal::make_nvp("i", vec));
    m_value = vec[1];  // most significant word
    m_value <<= 64;
    m_value += vec[0];  // least significant word
  }
#endif

  template <class Archive, typename T = void>
  typename std::enable_if<std::is_same<NativeInt, U64BITS>::value ||
                              std::is_same<NativeInt, U32BITS>::value,
                          T>::type
  save(Archive &ar, std::uint32_t const version) const {
    ar(::cereal::make_nvp("v", m_value));
  }

#if defined(HAVE_INT128)
  template <class Archive>
  typename std::enable_if<std::is_same<NativeInt, U128BITS>::value &&
                              !cereal::traits::is_text_archive<Archive>::value,
                          void>::type
  save(Archive &ar, std::uint32_t const version) const {
    // save 2 unint64_t values instead of unsigned __int128
    constexpr U128BITS mask = (static_cast<U128BITS>(1) << 64) - 1;
    uint64_t vec[2];
    vec[0] = m_value & mask;  // least significant word
    vec[1] = m_value >> 64;   // most significant word
    ar(::cereal::binary_data(vec, sizeof(vec)));
  }

  template <class Archive>
  typename std::enable_if<std::is_same<NativeInt, U128BITS>::value &&
                              cereal::traits::is_text_archive<Archive>::value,
                          void>::type
  save(Archive &ar, std::uint32_t const version) const {
    // save 2 unint64_t values instead of unsigned __int128
    constexpr U128BITS mask = (static_cast<U128BITS>(1) << 64) - 1;
    uint64_t vec[2];
    vec[0] = m_value & mask;  // least significant word
    vec[1] = m_value >> 64;   // most significant word
    ar(::cereal::make_nvp("i", vec));
  }
#endif

  std::string SerializedObjectName() const { return "NATInteger"; }

  static uint32_t SerializedVersion() { return 1; }

  static constexpr unsigned MaxBits() { return m_uintBitLength; }

  static bool IsNativeInt() { return true; }

 protected:
  /**
   * Converts the string v into base-r integer where r is equal to 2^bitwidth
   * of integral data type.
   *
   * @param v The input string
   */
  void AssignVal(const std::string &str) {
    NativeInt test_value = 0;
    m_value = 0;
    for (size_t i = 0; i < str.length(); i++) {
      int v = str[i] - '0';
      if (v < 0 || v > 9) {
        PALISADE_THROW(lbcrypto::type_error, "String contains a non-digit");
      }
      m_value *= 10;
      m_value += v;

      if (m_value < test_value) {
        PALISADE_THROW(
            lbcrypto::math_error,
            str + " is too large to fit in this native integer object");
      }
      test_value = m_value;
    }
  }

 private:
  // representation as a
  NativeInt m_value;

  // variable to store the bit width of the integral data type.
  static constexpr unsigned m_uintBitLength = sizeof(NativeInt) * 8;
  // variable to store the maximum value of the integral data type.
  static constexpr NativeInt m_uintMax = std::numeric_limits<NativeInt>::max();

  static constexpr NativeInt NATIVEINTMASK = NativeInt(~0);

  /**
   * AddCheck is the addition operation with bounds checking.
   *
   * @param b is the value to add to this.
   * @return result of the addition operation.
   */
  inline NativeIntegerT AddCheck(const NativeIntegerT &b) const {
    NativeInt newv = m_value + b.m_value;
    if (newv < m_value || newv < b.m_value) {
      PALISADE_THROW(lbcrypto::math_error, "Overflow");
    }
    return newv;
  }

  /**
   * AddFast is the addition operation without bounds checking.
   *
   * @param b is the value to add to this.
   * @return result of the addition operation.
   */
  inline NativeIntegerT AddFast(const NativeIntegerT &b) const {
    return m_value + b.m_value;
  }

  // Computes res -= a;
  static inline void SubtractD(typeD &res, const typeD &a) {
    if (res.lo < a.lo) {
      res.lo += m_uintMax + 1 - a.lo;
      res.hi--;
    } else {
      res.lo -= a.lo;
    }

    res.hi -= a.hi;
  }

  /**
   * Right shifts a typeD integer by a specific number of bits
   * and stores the result as a single-word integer.
   *
   * @param &x double-word input
   * @param shift the number of bits to shift by
   * @return the result of right-shifting
   */
  static inline NativeInt RShiftD(const typeD &x, long shift) {
    return (x.lo >> shift) | (x.hi << (MaxBits() - shift));
  }

  /**
   * Multiplies two single-word integers and stores the result in a
   * typeD data structure. Currently this is hard-coded to 64-bit
   * words on a x86-64 or arm64 processor
   *
   * @param a multiplier
   * @param b multiplicand
   * @param &x result of multiplication
   */
  static inline void MultD(U64BITS a, U64BITS b, typeD &res) {
#if defined(__x86_64__)
    // clang-format off
    __asm__("mulq %[b]"
            : [ lo ] "=a"(res.lo), [ hi ] "=d"(res.hi)
            : [ a ] "%[lo]"(a), [ b ] "rm"(b)
            : "cc");
    // clang-format on
#elif defined(__aarch64__)
    typeD x;
    x.hi = 0;
    x.lo = a;
    U64BITS y(b);
    res.lo = x.lo * y;
    asm("umulh %0, %1, %2\n\t" : "=r"(res.hi) : "r"(x.lo), "r"(y));
    res.hi += x.hi * y;
#elif defined(__arm__) // 32 bit processor
    uint64_t wres(0), wa(a), wb(b);

    wres = wa * wb;  // should give us the lower 64 bits of 32*32
    res.hi = wres >> 32;
    res.lo = (uint32_t)wres && 0xFFFFFFFF;
#elif defined(__EMSCRIPTEN__)  // web assembly
    U64BITS a1 = a >> 32;
    U64BITS a2 = (uint32_t)a;
    U64BITS b1 = b >> 32;
    U64BITS b2 = (uint32_t)b;

    // use schoolbook multiplication
    res.hi = a1 * b1;
    res.lo = a2 * b2;
    U64BITS lowBefore = res.lo;

    U64BITS p1 = a2 * b1;
    U64BITS p2 = a1 * b2;
    U64BITS temp = p1 + p2;
    res.hi += temp >> 32;
    res.lo += U64BITS((uint32_t)temp) << 32;

    // adds the carry to the high word
    if (lowBefore > res.lo) res.hi++;

    // if there is an overflow in temp, add 2^32
    if ((temp < p1) || (temp < p2)) res.hi += (U64BITS)1 << 32;
#else
#error Architecture not supported for MultD()
#endif
  }

#if defined(HAVE_INT128)
  static inline void MultD(U128BITS a, U128BITS b, typeD &res) {
    // TODO: The performance of this function can be improved
    // Instead of 128-bit multiplication, we can use MultD from bigintnat
    // We would need to introduce a struct of 4 64-bit integers in this case
    U128BITS a1 = a >> 64;
    U128BITS a2 = (uint64_t)a;
    U128BITS b1 = b >> 64;
    U128BITS b2 = (uint64_t)b;

    // use schoolbook multiplication
    res.hi = a1 * b1;
    res.lo = a2 * b2;
    U128BITS lowBefore = res.lo;

    U128BITS p1 = a2 * b1;
    U128BITS p2 = a1 * b2;
    U128BITS temp = p1 + p2;
    res.hi += temp >> 64;
    res.lo += U128BITS((uint64_t)temp) << 64;

    // adds the carry to the high word
    if (lowBefore > res.lo) res.hi++;

    // if there is an overflow in temp, add 2^64
    if ((temp < p1) || (temp < p2)) res.hi += (U128BITS)1 << 64;
  }
#endif

  static inline void MultD(U32BITS a, U32BITS b, typeD &res) {
    DNativeInt prod = DNativeInt(a) * DNativeInt(b);
    res.hi = (prod >> MaxBits()) & NATIVEINTMASK;
    res.lo = prod & NATIVEINTMASK;
  }

  /**
   * Multiplies two single-word integers and stores the high word of the
   * result
   *
   * @param a multiplier
   * @param b multiplicand
   * @return the high word of the result
   */
  static inline NativeInt MultDHi(NativeInt a, NativeInt b) {
    typeD x;
    MultD(a, b, x);
    return x.hi;
  }

  /**
   * Converts a double-word integer from typeD representation
   * to DNativeInt.
   *
   * @param &x double-word input
   * @return the result as DNativeInt
   */
  inline DNativeInt GetD(const typeD &x) const {
    return (DNativeInt(x.hi) << MaxBits()) | x.lo;
  }

  static inline std::string toString(uint32_t value) {
    return std::to_string(value);
  }

  static inline std::string toString(uint64_t value) {
    return std::to_string(value);
  }

#if defined(HAVE_INT128)
  static inline std::string toString(unsigned __int128 value) {
    constexpr uint32_t maxChars = 15;  // max number of digits/chars we may have
                                       // in every part after division below

    const uint64_t divisor = std::llrint(pow(10, maxChars));
    uint64_t part3 = value % divisor;
    value /= divisor;
    uint64_t part2 = value % divisor;
    value /= divisor;
    uint64_t part1 = value % divisor;
    value /= divisor;

    std::string ret;
    ret.reserve(64);  // should be more than enough to store the value of a
                      // 128-bit integer

    bool appendNextPart = false;
    if (part1) {
      ret = std::to_string(part1);
      appendNextPart = true;
    }

    if (part2) {
      std::string part2str(std::to_string(part2));
      if (appendNextPart) {
        ret += std::string(maxChars - part2str.size(), '0');
        ret += part2str;
      } else {
        ret = part2str;
        appendNextPart = true;
      }
    } else if (appendNextPart) {
      ret += std::string(maxChars, '0');  // add zeroes only
    }

    if (part3) {
      std::string part3str(std::to_string(part3));
      if (appendNextPart) {
        ret += std::string(maxChars - part3str.size(), '0');
        ret += part3str;
      } else {
        ret = part3str;
      }
    } else if (appendNextPart) {
      ret += std::string(maxChars, '0');
    } else {
      ret = "0";
    }

    return ret;
    /*
     * The following implementation doesn't works as fast as the implementation
     * above, but is much shorter...:
     */
    /*
   {
   // 64 bytes should be more than enough to store the value of a 128-bit
   integer
   // and we will keep the terminating zero at the buffer end
   char retBuff[64] = {0};
   char* ptr = &retBuff[63];
   while( value ) {
    *(--ptr) = '0' + value % 10;
    value /= 10;
    }
    return std::string(ptr);
    }
    */
  }
#endif
};

}  // namespace bigintnat

#endif  // LBCRYPTO_MATH_BIGINTNAT_UBINTNAT_H
