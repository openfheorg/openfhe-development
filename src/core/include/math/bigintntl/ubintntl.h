// @file ubintntl.h  This file contains the C++ code for implementing the main
// class for big integers: gmpint which replaces BBI and uses NTL
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

#ifndef LBCRYPTO_MATH_BIGINTNTL_UBINTNTL_H
#define LBCRYPTO_MATH_BIGINTNTL_UBINTNTL_H

#include "config_core.h"
#ifdef WITH_NTL

#include <NTL/ZZ.h>
#include <NTL/ZZ_limbs.h>

#include <exception>
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

#include "utils/debug.h"

/**
 *@namespace NTL
 * The namespace of this code
 */
namespace NTL {
// log2 constants
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

class myZZ : public NTL::ZZ, public lbcrypto::BigIntegerInterface<myZZ> {
 public:
  // CONSTRUCTORS

  /**
   * Default constructor.
   */
  myZZ();

  /**
   * Copy constructor.
   *
   * @param &val is the ZZ to be copied.
   */
  myZZ(const NTL::ZZ &val);

  /**
   * Move constructor.
   *
   * @param &&val is the ZZ to be copied.
   */
  myZZ(NTL::ZZ &&val);

  // TODO: figure out how to do && for wrapper
  // myZZ(NTL::myZZ_p &&a);

  /**
   * Constructor from a string.
   *
   * @param &strval is the initial integer represented as a string.
   */
  explicit myZZ(const std::string &strval);

  /**
   * Constructor from an unsigned integer.
   *
   * @param val is the initial integer represented as a uint64_t.
   */
  myZZ(uint64_t val);
#if defined(HAVE_INT128)
  myZZ(unsigned __int128 val);
#endif

  /**
   * Constructors from smaller basic types
   *
   * @param val is the initial integer represented as a basic integer type.
   */
  myZZ(int val) : myZZ(uint64_t(val)) {}
  myZZ(uint32_t val) : myZZ(uint64_t(val)) {}
  myZZ(long val) : myZZ(uint64_t(val)) {}
  myZZ(long long val) : myZZ(uint64_t(val)) {}

  /**
   * Constructor from a NativeInteger
   *
   * @param &val is the initial integer represented as a native integer.
   */
  template <typename T>
  myZZ(const bigintnat::NativeIntegerT<T> &val) : myZZ(val.ConvertToInt()) {}

  /**
   * Constructor from double is not permitted
   *
   * @param val
   */
  myZZ(double val)
      __attribute__((deprecated("Cannot construct from a double")));

  // ASSIGNMENT OPERATORS

  /**
   * Copy assignment operator
   *
   * @param &val is the myZZ to be assigned from.
   * @return assigned myZZ ref.
   */
  const myZZ &operator=(const myZZ &val);

  // TODO move assignment operator?

  /**
   * Assignment operator from string
   *
   * @param strval is the string to be assigned from
   * @return the assigned myZZ ref.
   */
  inline const myZZ &operator=(std::string strval) {
    *this = myZZ(strval);
    return *this;
  }

  /**
   * Assignment operator from unsigned integer
   *
   * @param val is the unsigned integer to be assigned from.
   * @return the assigned myZZ ref.
   */
  const myZZ &operator=(uint64_t val) {
    *this = myZZ(val);
    return *this;
  }

  // ACCESSORS

  /**
   * Basic set method for setting the value of a myZZ
   *
   * @param strval is the string representation of the ubint to be copied.
   */
  void SetValue(const std::string &strval);

  /**
   * Basic set method for setting the value of a myZZ
   *
   * @param a is the unsigned big int representation to be assigned.
   */
  void SetValue(const myZZ &val);

  void SetIdentity() { *this = 1; }

  // ARITHMETIC OPERATIONS

  /**
   * Addition operation.
   *
   * @param &b is the value to add.
   * @return result of the addition operation.
   */
  myZZ Add(const myZZ &b) const {
    return *static_cast<const ZZ *>(this) + static_cast<const ZZ &>(b);
  }

  /**
   * Addition operation. In-place variant.
   *
   * @param &b is the value to add.
   * @return result of the addition operation.
   */
  const myZZ &AddEq(const myZZ &b) {
    *static_cast<ZZ *>(this) += static_cast<const ZZ &>(b);
    return *this;
  }

  /**
   * Subtraction operation.
   * Note that in Sub we return 0, if a<b
   *
   * @param &b is the value to subtract.
   * @return is the result of the subtraction operation.
   */
  myZZ Sub(const myZZ &b) const {
    return (*this < b)
               ? ZZ(0)
               : (*static_cast<const ZZ *>(this) - static_cast<const ZZ &>(b));
  }

  /**
   * Subtraction operation. In-place variant.
   * Note that in Sub we return 0, if a<b
   *
   * @param &b is the value to subtract.
   * @return is the result of the subtraction operation.
   */
  const myZZ &SubEq(const myZZ &b) {
    if (*this < b) {
      *this = ZZ(0);
    } else {
      *static_cast<ZZ *>(this) -= static_cast<const ZZ &>(b);
    }
    return *this;
  }

  /**
   * Multiplication operation.
   *
   * @param &b is the value to multiply with.
   * @return is the result of the multiplication operation.
   */
  myZZ Mul(const myZZ &b) const {
    return *static_cast<const ZZ *>(this) * static_cast<const ZZ &>(b);
  }

  /**
   * Multiplication operation. In-place variant.
   *
   * @param &b is the value to multiply with.
   * @return is the result of the multiplication operation.
   */
  const myZZ &MulEq(const myZZ &b) {
    *static_cast<ZZ *>(this) *= static_cast<const ZZ &>(b);
    return *this;
  }

  /**
   * Division operation.
   *
   * @param &b is the value to divide by.
   * @return is the result of the division operation.
   */
  myZZ DividedBy(const myZZ &b) const {
    return *static_cast<const ZZ *>(this) / static_cast<const ZZ &>(b);
  }

  /**
   * Division operation. In-place variant.
   *
   * @param &b is the value to divide by.
   * @return is the result of the division operation.
   */
  const myZZ &DividedByEq(const myZZ &b) {
    *static_cast<ZZ *>(this) /= static_cast<const ZZ &>(b);
    return *this;
  }

  /**
   * Exponentiation operation. Returns x^p.
   *
   * @param p the exponent.
   * @return is the result of the exponentiation operation.
   */
  myZZ Exp(const usint p) const { return power(*this, p); }

  /**
   * Exponentiation operation. Returns x^p. In-place variant.
   *
   * @param p the exponent.
   * @return is the result of the exponentiation operation.
   */
  const myZZ &ExpEq(const usint p) {
    *this = power(*this, p);
    return *this;
  }

  /**
   * Multiply and Rounding operation. Returns [x*p/q] where [] is the rounding
   * operation.
   *
   * @param &p is the numerator to be multiplied.
   * @param &q is the denominator to be divided.
   * @return is the result of multiply and round operation.
   */
  myZZ MultiplyAndRound(const myZZ &p, const myZZ &q) const;

  /**
   * Multiply and Rounding operation. Returns [x*p/q] where [] is the rounding
   * operation. In-place variant.
   *
   * @param &p is the numerator to be multiplied.
   * @param &q is the denominator to be divided.
   * @return is the result of multiply and round operation.
   */
  const myZZ &MultiplyAndRoundEq(const myZZ &p, const myZZ &q);

  /**
   * Divide and Rounding operation. Returns [x/q] where [] is the rounding
   * operation.
   *
   * @param &q is the denominator to be divided.
   * @return is the result of divide and round operation.
   */
  myZZ DivideAndRound(const myZZ &q) const;

  /**
   * Divide and Rounding operation. Returns [x/q] where [] is the rounding
   * operation. In-place variant.
   *
   * @param &q is the denominator to be divided.
   * @return is the result of divide and round operation.
   */
  const myZZ &DivideAndRoundEq(const myZZ &q);

  // MODULAR ARITHMETIC OPERATIONS

  /**
   * Naive modulus operation.
   *
   * @param &modulus is the modulus to perform.
   * @return is the result of the modulus operation.
   */
  myZZ Mod(const myZZ &modulus) const {
    return *static_cast<const ZZ *>(this) % static_cast<const ZZ &>(modulus);
  }

  /**
   * Naive modulus operation. In-place variant.
   *
   * @param &modulus is the modulus to perform.
   * @return is the result of the modulus operation.
   */
  const myZZ &ModEq(const myZZ &modulus) {
    *static_cast<ZZ *>(this) %= static_cast<const ZZ &>(modulus);
    return *this;
  }

  /**
   * Pre-computes the mu factor that is used in Barrett modulo reduction
   *
   * @return the value of mu
   */
  myZZ ComputeMu() const {
    myZZ temp(1);
    temp <<= (2 * this->GetMSB() + 3);
    return temp.DividedBy(*this);
    return temp;
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
  myZZ Mod(const myZZ &modulus, const myZZ &mu) const {
    return *static_cast<const ZZ *>(this) % static_cast<const ZZ &>(modulus);
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
  const myZZ &ModEq(const myZZ &modulus, const myZZ &mu) {
    *static_cast<ZZ *>(this) %= static_cast<const ZZ &>(modulus);
    return *this;
  }

  /**
   * Modulus addition operation.
   *
   * @param &b is the scalar to add.
   * @param &modulus is the modulus to perform operations with.
   * @return is the result of the modulus addition operation.
   */
  myZZ ModAdd(const myZZ &b, const myZZ &modulus) const {
    return AddMod(this->Mod(modulus), b.Mod(modulus), modulus);
  }

  /**
   * Modulus addition operation. In-place variant.
   *
   * @param &b is the scalar to add.
   * @param &modulus is the modulus to perform operations with.
   * @return is the result of the modulus addition operation.
   */
  const myZZ &ModAddEq(const myZZ &b, const myZZ &modulus) {
    AddMod(*this, this->Mod(modulus), b.Mod(modulus), modulus);
    return *this;
  }

  /**
   * Modulus addition where operands are < modulus.
   *
   * @param &b is the scalar to add.
   * @param &modulus is the modulus to perform operations with.
   * @return is the result of the modulus addition operation.
   */
  myZZ ModAddFast(const myZZ &b, const myZZ &modulus) const {
    return AddMod(*this, b, modulus);
  }

  /**
   * Modulus addition where operands are < modulus. In-place variant.
   *
   * @param &b is the scalar to add.
   * @param &modulus is the modulus to perform operations with.
   * @return is the result of the modulus addition operation.
   */
  const myZZ &ModAddFastEq(const myZZ &b, const myZZ &modulus) {
    *this = AddMod(*this, b, modulus);
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
  myZZ ModAdd(const myZZ &b, const myZZ &modulus, const myZZ &mu) const {
    return AddMod(*this, b, modulus);
  }

  /**
   * Barrett modulus addition operation. In-place variant.
   *
   * @param &b is the scalar to add.
   * @param &modulus is the modulus to perform operations with.
   * @param &mu is the Barrett value.
   * @return is the result of the modulus addition operation.
   */
  const myZZ &ModAddEq(const myZZ &b, const myZZ &modulus, const myZZ &mu) {
    *this = AddMod(*this, b, modulus);
    return *this;
  }

  /**
   * Modulus subtraction operation.
   * NOTE ModSub needs to return signed modulus (i.e. -1/2..q/2) in order
   * to be consistent with BE 2
   *
   * @param &b is the scalar to subtract.
   * @param &modulus is the modulus to perform operations with.
   * @return is the result of the modulus subtraction operation.
   */
  myZZ ModSub(const myZZ &b, const myZZ &modulus) const {
    myZZ newthis(*this % modulus);
    myZZ newb(b % modulus);
    if (newthis >= newb) {
      myZZ tmp(SubMod(newthis, newb, modulus));  // normal mod sub
      return tmp;
    } else {
      myZZ tmp(newthis + modulus - newb);  // signed mod
      return tmp;
    }
  }

  /**
   * Modulus subtraction operation. In-place variant.
   * NOTE ModSub needs to return signed modulus (i.e. -1/2..q/2) in order
   * to be consistent with BE 2
   *
   * @param &b is the scalar to subtract.
   * @param &modulus is the modulus to perform operations with.
   * @return is the result of the modulus subtraction operation.
   */
  const myZZ &ModSubEq(const myZZ &b, const myZZ &modulus) {
    this->ModEq(modulus);
    myZZ newb(b % modulus);
    if (*this >= newb) {
      SubMod(*this, *this, newb, modulus);  // normal mod sub
      return *this;
    } else {
      this->AddEq(modulus);
      this->SubEq(newb);  // signed mod
      return *this;
    }
  }

  /**
   * Modulus subtraction where operands are < modulus.
   *
   * @param &b is the scalar to subtract.
   * @param &modulus is the modulus to perform operations with.
   * @return is the result of the modulus subtraction operation.
   */
  myZZ ModSubFast(const myZZ &b, const myZZ &modulus) const {
    if (*this >= b) {
      return SubMod(*this, b, modulus);  // normal mod sub
    } else {
      return (*this + modulus - b);  // signed mod
    }
  }

  /**
   * Modulus subtraction where operands are < modulus. In-place variant.
   *
   * @param &b is the scalar to subtract.
   * @param &modulus is the modulus to perform operations with.
   * @return is the result of the modulus subtraction operation.
   */
  const myZZ &ModSubFastEq(const myZZ &b, const myZZ &modulus) {
    if (*this >= b) {
      return *this = SubMod(*this, b, modulus);  // normal mod sub
    } else {
      return *this = (*this + modulus - b);  // signed mod
    }
  }

  /**
   * Barrett modulus subtraction operation.
   *
   * @param &b is the scalar to subtract.
   * @param &modulus is the modulus to perform operations with.
   * @param &mu is the Barrett value.
   * @return is the result of the modulus subtraction operation.
   */
  myZZ ModSub(const myZZ &b, const myZZ &modulus, const myZZ &mu) const {
    myZZ newthis(*this % modulus);
    myZZ newb(b % modulus);
    if (newthis >= newb) {
      myZZ tmp(SubMod(newthis, newb, modulus));  // normal mod sub
      return tmp;
    } else {
      myZZ tmp(newthis + modulus - newb);  // signed mod
      return tmp;
    }
  }

  /**
   * Barrett modulus subtraction operation. In-place variant.
   *
   * @param &b is the scalar to subtract.
   * @param &modulus is the modulus to perform operations with.
   * @param &mu is the Barrett value.
   * @return is the result of the modulus subtraction operation.
   */
  const myZZ &ModSubEq(const myZZ &b, const myZZ &modulus, const myZZ &mu) {
    this->ModEq(modulus);
    myZZ newb(b % modulus);
    if (*this >= newb) {
      SubMod(*this, *this, newb, modulus);  // normal mod sub
      return *this;
    } else {
      this->AddEq(modulus);
      this->SubEq(newb);  // signed mod
      return *this;
    }
  }

  /**
   * Modulus multiplication operation.
   *
   * @param &b is the scalar to multiply.
   * @param &modulus is the modulus to perform operations with.
   * @return is the result of the modulus multiplication operation.
   */
  myZZ ModMul(const myZZ &b, const myZZ &modulus) const {
    return MulMod(this->Mod(modulus), b.Mod(modulus), modulus);
  }

  /**
   * Modulus multiplication operation. In-place variant.
   *
   * @param &b is the scalar to multiply.
   * @param &modulus is the modulus to perform operations with.
   * @return is the result of the modulus multiplication operation.
   */
  const myZZ &ModMulEq(const myZZ &b, const myZZ &modulus) {
    MulMod(*this, this->Mod(modulus), b.Mod(modulus), modulus);
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
  myZZ ModMul(const myZZ &b, const myZZ &modulus, const myZZ &mu) const {
    return MulMod(this->Mod(modulus), b.Mod(modulus), modulus);
  }

  /**
   * Barrett modulus multiplication. In-place variant.
   *
   * @param &b is the scalar to multiply.
   * @param &modulus is the modulus to perform operations with.
   * @param &mu is the Barrett value.
   * @return is the result of the modulus multiplication operation.
   */
  const myZZ &ModMulEq(const myZZ &b, const myZZ &modulus, const myZZ &mu) {
    MulMod(*this, this->Mod(modulus), b.Mod(modulus), modulus);
    return *this;
  }

  /**
   * Modulus multiplication that assumes the operands are < modulus.
   *
   * @param &b is the scalar to multiply.
   * @param &modulus is the modulus to perform operations with.
   * @return is the result of the modulus multiplication operation.
   */
  inline myZZ ModMulFast(const myZZ &b, const myZZ &modulus) const {
    return MulMod(*this, b, modulus);
  }

  /**
   * Modulus multiplication that assumes the operands are < modulus. In-place
   * variant.
   *
   * @param &b is the scalar to multiply.
   * @param &modulus is the modulus to perform operations with.
   * @return is the result of the modulus multiplication operation.
   */
  const myZZ &ModMulFastEq(const myZZ &b, const myZZ &modulus) {
    *this = MulMod(*this, b, modulus);
    return *this;
  }

  /**
   * Barrett modulus multiplication that assumes the operands are < modulus.
   *
   * @param &b is the scalar to multiply.
   * @param &modulus is the modulus to perform operations with.
   * @param &mu is the Barrett value.
   * @return is the result of the modulus multiplication operation.
   */
  inline myZZ ModMulFast(const myZZ &b, const myZZ &modulus,
                         const myZZ &mu) const {
    return MulMod(*this, b, modulus);
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
  const myZZ &ModMulFastEq(const myZZ &b, const myZZ &modulus, const myZZ &mu) {
    *this = MulMod(*this, b, modulus);
    return *this;
  }

  myZZ ModMulFastConst(const myZZ &b, const myZZ &modulus,
                       const myZZ &bInv) const {
    PALISADE_THROW(lbcrypto::not_implemented_error,
                   "ModMulFastConst is not implemented for backend 6");
  }

  const myZZ &ModMulFastConstEq(const myZZ &b, const myZZ &modulus,
                                const myZZ &bInv) {
    PALISADE_THROW(lbcrypto::not_implemented_error,
                   "ModMulFastConstEq is not implemented for backend 6");
  }

  /**
   * Modulus exponentiation operation.
   *
   * @param &b is the scalar to exponentiate at all locations.
   * @param &modulus is the modulus to perform operations with.
   * @return is the result of the modulus exponentiation operation.
   */
  inline myZZ ModExp(const myZZ &b, const myZZ &modulus) const {
    myZZ res;
    PowerMod(res, *this, b, modulus);
    return res;
  }

  /**
   * Modulus exponentiation operation. In-place variant.
   *
   * @param &b is the scalar to exponentiate at all locations.
   * @param &modulus is the modulus to perform operations with.
   * @return is the result of the modulus exponentiation operation.
   */
  const myZZ &ModExpEq(const myZZ &b, const myZZ &modulus) {
    PowerMod(*this, *this, b, modulus);
    return *this;
  }

  /**
   * Modulus inverse operation.
   *
   * @param &modulus is the modulus to perform.
   * @return is the result of the modulus inverse operation.
   */
  myZZ ModInverse(const myZZ &modulus) const {
    if (modulus == myZZ(0)) {
      PALISADE_THROW(lbcrypto::math_error, "zero has no inverse");
    }
    myZZ tmp(0);
    try {
      tmp = InvMod(*this % modulus, modulus);
    } catch (InvModErrorObject
                 &e) {  // note this code requires NTL Excptions coto be turned
                        // on. TODO: provide alternative when that is off.
      std::stringstream errmsg;
      errmsg << "ModInverse exception "
             << " this: " << *this << " modulus: " << modulus << "GCD("
             << e.get_a() << "," << e.get_n() << "!=1" << std::endl;
      PALISADE_THROW(lbcrypto::math_error, errmsg.str());
    }
    return tmp;
  }

  /**
   * Modulus inverse operation. In-place variant.
   *
   * @param &modulus is the modulus to perform.
   * @return is the result of the modulus inverse operation.
   */
  const myZZ &ModInverseEq(const myZZ &modulus) {
    if (modulus == myZZ(0)) {
      PALISADE_THROW(lbcrypto::math_error, "zero has no inverse");
    }
    try {
      *this = InvMod(*this % modulus, modulus);
    } catch (InvModErrorObject
                 &e) {  // note this code requires NTL Excptions coto be turned
                        // on. TODO: provide alternative when that is off.
      std::stringstream errmsg;
      errmsg << "ModInverse exception "
             << " this: " << *this << " modulus: " << modulus << "GCD("
             << e.get_a() << "," << e.get_n() << "!=1" << std::endl;
      PALISADE_THROW(lbcrypto::math_error, errmsg.str());
    }
    return *this;
  }

  /**
   * Left shift operation.
   *
   * @param shift # of bits.
   * @return result of the shift operation.
   */
  myZZ LShift(usshort shift) const {
    return *static_cast<const ZZ *>(this) << shift;
  }

  /**
   * Left shift operation. In-place variant.
   *
   * @param shift # of bits.
   * @return result of the shift operation.
   */
  const myZZ &LShiftEq(usshort shift) {
    *static_cast<ZZ *>(this) <<= shift;
    return *this;
  }

  /**
   * Right shift operation.
   *
   * @param shift # of bits.
   * @return result of the shift operation.
   */
  myZZ RShift(usshort shift) const {
    return *static_cast<const ZZ *>(this) >> shift;
  }

  /**
   * Right shift operation. In-place variant.
   *
   * @param shift # of bits.
   * @return result of the shift operation.
   */
  const myZZ &RShiftEq(usshort shift) {
    *static_cast<ZZ *>(this) >>= shift;
    return *this;
  }

  // COMPARE

  // comparison method inline for speed
  int Compare(const myZZ &a) const { return compare(*this, a); }

  // CONVERTING

  // palisade conversion methods
  uint64_t ConvertToInt() const;

  uint64_t ConvertToUint64() const;

  double ConvertToDouble() const;

  /**
   * Convert a string representation of a binary number to a myZZ.
   * Note: needs renaming to a generic form since the variable type name is
   * embedded in the function name. Suggest FromBinaryString()
   * @param bitString the binary num in string.
   * @return the  number represented as a ubint.
   */
  static myZZ FromBinaryString(const std::string &bitString);

  // OTHER FUNCTIONS

  // adapter kit that wraps ZZ with BACKEND 2 functionality

  static const myZZ &zero();

  usint GetMSB() const;

  /**
   * Get the number of digits using a specific base - support for
   * arbitrary base may be needed.
   *
   * @param base is the base with which to determine length in.
   * @return the length of the representation in a specific base.
   */
  usint GetLengthForBase(usint base) const { return GetMSB(); }

  /**
   * Get the integer value of the of a subfield of bits. Where the length of
   * the field is specifice by a power of two base
   * Warning: only power-of-2 bases are currently supported.
   * Example: for number 83, index 2 and base 4 we have:
   *
   *                         index:0,1,2,3
   * 83 --base 4 decomposition--> (3,0,1,1) --at index 2--> 1
   *
   * The return number is 1.
   *
   * @param index is the bit location (lsb)
   * @param base such that log2(base)+1 is the bitwidth of the subfield
   * @return the unsigned integer value of the subfield
   */
  usint GetDigitAtIndexForBase(usint index, usint base) const;

  // variable to store the log(base 2) of the number of bits in the
  // limb data type.
  static const usint m_log2LimbBitLength;

  /**
   * Gets a subset of bits of a given length with LSB at specified index.
   * optimized for speed in backend 6
   * @param index of the set of bit to get. LSB=1
   * @param length of the set of bits to get. LSB=1
   * @return resulting unsigned in formed by set of bits.
   */
  usint GetBitRangeAtIndex(usint index, usint length) const;

  /**
   * Gets the bit at the specified index.
   *
   * @param index of the bit to get. LSB=1
   * @return resulting bit.
   */
  uschar GetBitAtIndex(usint index) const;

  /**
   * A zero allocator that is called by the Matrix class. It is used to
   * initialize a Matrix of myZZ objects.
   */
  static myZZ Allocator() { return 0; }

  // STRINGS & STREAMS

  // palisade string conversion
  const std::string ToString() const;

  static const std::string IntegerTypeName() { return "UBNTLINT"; }

  // big integer stream output
  friend std::ostream &operator<<(std::ostream &os, const myZZ &ptr_obj);

  /**
   * Gets a copy of the  internal limb storage
   * Used primarily for debugging
   */
  std::string GetInternalRepresentation(void) const {
    std::string ret("");
    const ZZ_limb_t *zlp = ZZ_limbs_get(*this);

    for (size_t i = 0; i < (size_t)this->size(); i++) {
      ret += std::to_string(zlp[i]);
      if (i < ((size_t)this->size() - 1)) {
        ret += " ";
      }
    }
    return ret;
  }

  /// SERIALIZATION

  template <class Archive>
  typename std::enable_if<!cereal::traits::is_text_archive<Archive>::value,
                          void>::type
  save(Archive &ar, std::uint32_t const version) const {
    void *data = this->rep.rep;
    size_t len = 0;
    if (data == nullptr) {
      ar(::cereal::binary_data(&len, sizeof(len)));
    } else {
      len = _ntl_ALLOC(this->rep.rep);

      ar(::cereal::binary_data(&len, sizeof(len)));
      ar(::cereal::binary_data(data, len * sizeof(_ntl_gbigint)));
      ar(::cereal::make_nvp("mb", m_MSB));
    }
  }

  template <class Archive>
  typename std::enable_if<cereal::traits::is_text_archive<Archive>::value,
                          void>::type
  save(Archive &ar, std::uint32_t const version) const {
    ar(::cereal::make_nvp("v", ToString()));
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
    size_t len;
    ar(::cereal::binary_data(&len, sizeof(len)));
    if (len == 0) {
      *this = 0;
      return;
    }

    void *mem = malloc(len * sizeof(_ntl_gbigint));
    ar(::cereal::binary_data(mem, len * sizeof(_ntl_gbigint)));
    WrappedPtr<_ntl_gbigint_body, Deleter> newrep;
    newrep.rep = reinterpret_cast<_ntl_gbigint_body *>(mem);
    _ntl_gswap(&this->rep, &newrep);

    ar(::cereal::make_nvp("mb", m_MSB));
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
    std::string s;
    ar(::cereal::make_nvp("v", s));
    *this = s;
  }

  std::string SerializedObjectName() const { return "NTLInteger"; }

  static uint32_t SerializedVersion() { return 1; }

 private:
  // adapter kits
  void SetMSB();

  /**
   * function to return the ceiling of the input number divided by
   * the number of bits in the limb data type.  DBC this is to
   * determine how many limbs are needed for an input bitsize.
   * @param Number is the number to be divided.
   * @return the ceiling of Number/(bits in the limb data type)
   */
  // todo: rename to MSB2NLimbs()
  static usint ceilIntByUInt(const ZZ_limb_t Number);

  mutable size_t m_MSB;
  usint GetMSBLimb_t(ZZ_limb_t x) const;
};
// class ends

NTL_DECLARE_RELOCATABLE((myZZ *))
}  // namespace NTL

#endif

#endif  // LBCRYPTO_MATH_BIGINTNTL_UBINTNTL_H
