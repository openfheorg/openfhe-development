// @file ubintdyn.cpp  This file contains the main class for unsigned big
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

#define _SECURE_SCL 0  // to speed up VS

#include <time.h>

#include <chrono>
#include <fstream>
#include <iostream>

#include "math/backend.h"

#include "utils/debug.h"
#include "utils/serializable.h"

#define LimbReserveHint 4  // hint for reservation of limbs

namespace bigintdyn {

// MOST REQUIRED STATIC CONSTANTS INITIALIZATION

// constant static member variable initialization of m_uintBitLength which is
// equal to number of bits in the unit data type permitted values: 8,16,32
template <typename limb_t>
// const uschar ubint<limb_t>::m_uintBitLength = UIntBitWidth<limb_t>::value;
const usint ubint<limb_t>::m_limbBitLength = sizeof(limb_t) * 8;

// constant static member variable initialization of m_logUintBitLength which is
// equal to log of number of bits in the unit data type permitted values: 3,4,5
template <typename limb_t>
// const uschar ubint<limb_t>::m_log2LimbBitLength = LogDtype<limb_t>::value;
const usint ubint<limb_t>::m_log2LimbBitLength = Log2<m_limbBitLength>::value;

// constant static member variable initialization of m_uintMax which is maximum
// value of unit data type
template <typename limb_t>
const limb_t ubint<limb_t>::m_MaxLimb = std::numeric_limits<limb_t>::max();

// CONSTRUCTORS

template <typename limb_t>
ubint<limb_t>::ubint() {
  m_MSB = 0;
  m_value.reserve(LimbReserveHint);
  m_value.push_back((limb_t)0);
  m_state = INITIALIZED;
}

template <typename limb_t>
ubint<limb_t>::ubint(const ubint &val) {
  if (val.m_state == GARBAGE) {
    PALISADE_THROW(lbcrypto::type_error, "copy GARBAGE");
  }
  if (val.m_value.size() < 0) {
    PALISADE_THROW(lbcrypto::type_error, "copy size < 0");
  }
  this->m_MSB = val.m_MSB;      // copy MSB
  this->m_value = val.m_value;  // this occasionally fails may have been
  m_state = val.m_state;        // set state
}

template <typename limb_t>
ubint<limb_t>::ubint(ubint &&val) {
  m_MSB = val.m_MSB;          // copy MSB
  m_value.swap(val.m_value);  // swap (move) assignment
  m_state = val.m_state;      // set state
}

// ctor(string)
template <typename limb_t>
ubint<limb_t>::ubint(const std::string &strval) {
  AssignVal(strval);
  m_state = INITIALIZED;
}

template <typename limb_t>
ubint<limb_t>::ubint(const uint64_t val) {
  uint64_t init = val;  // non const var
  usint msb = 0;
  msb = lbcrypto::GetMSB64(init);
  if (init <= m_MaxLimb) {
    m_value.push_back((limb_t)init);
  }
#ifdef UBINT_32  // does not occur for UBINT_64
                 // NOLINTNEXTLINE
  else {
    usint ceilInt = ceilIntByUInt(msb);
    // setting the values of the array
    this->m_value.reserve(ceilInt);
    for (usint i = 0; i < ceilInt; ++i) {
      m_value.push_back((limb_t)init);
      init >>= m_limbBitLength;
    }
  }
#endif
  this->m_MSB = msb;
  m_state = INITIALIZED;
}

#if defined(HAVE_INT128)
template <typename limb_t>
ubint<limb_t>::ubint(unsigned __int128 val) {
  m_MSB = lbcrypto::GetMSB(val);
  if (val <= m_MaxLimb) {
    m_value.push_back((limb_t)val);
  } else {
    usint ceilInt = ceilIntByUInt(m_MSB);
    // setting the values of the array
    this->m_value.reserve(ceilInt);
    for (usint i = 0; i < ceilInt; ++i) {
      m_value.push_back((limb_t)val);
      val >>= m_limbBitLength;
    }
  }
  m_state = INITIALIZED;
}
#endif

template <typename limb_t>
ubint<limb_t>::~ubint() {}

// ASSIGNMENT OPERATORS

template <typename limb_t>
const ubint<limb_t> &ubint<limb_t>::operator=(const ubint &val) {
  if (this != &val) {
    this->m_MSB = val.m_MSB;
    this->m_state = val.m_state;
    this->m_value = val.m_value;
  }
  return *this;
}

// ACCESSORS

template <typename limb_t>
void ubint<limb_t>::SetValue(const std::string &strval) {
  ubint::AssignVal(strval);
}

// ARITHMETIC OPERATIONS

/** Addition operation:
 *  Algorithm used is usual school book sum and carry-over, expect for that
 * radix is 2^m_bitLength.
 */
template <typename limb_t>
ubint<limb_t> ubint<limb_t>::Add(const ubint &b) const {
  const ubint *A = nullptr;
  const ubint *B = nullptr;
  if (this->m_state == GARBAGE || b.m_state == GARBAGE) {
    PALISADE_THROW(lbcrypto::not_available_error,
                   "Add() to uninitialized bint");
  }
  // Assignment of pointers, A assigned the higher value and B assigned the
  // lower value
  if (*this > b) {
    A = this;
    B = &b;
  } else {
    A = &b;
    B = this;
  }
  if (B->m_MSB == 0) {
    return ubint(*A);
  }
  ubint result;
  result.m_value.clear();  // note make sure result has no limbs as we are
                           // adding them below.
  result.m_state = INITIALIZED;
  Dlimb_t ofl = 0;                            // overflow variable
  limb_t ceilIntA = ceilIntByUInt(A->m_MSB);  // position from A to end addition
  limb_t ceilIntB = ceilIntByUInt(B->m_MSB);  // position from B to end addition
  usint i;
  // loop over limbs low to high till you reach the end of the smaller one
  for (i = 0; i < ceilIntB; ++i) {
    // sum of the two int and the carry over
    ofl = (Dlimb_t)A->m_value[i] + (Dlimb_t)B->m_value[i] + ofl;
    result.m_value.push_back((limb_t)ofl);
    ofl >>= m_limbBitLength;  // current overflow
  }
  if (ofl) {
    // we have an overflow at the end
    // keep looping over the remainder of the larger value
    for (; i < ceilIntA; ++i) {
      // sum of the two int and the carry over
      ofl = (Dlimb_t)A->m_value[i] + ofl;
      result.m_value.push_back((limb_t)ofl);
      ofl >>= m_limbBitLength;  // current overflow
    }
    if (ofl) {  // in the end if overflow is set it indicates MSB is one greater
                // than the one we started with
      result.m_value.push_back(1);
    }
  } else {  // there is no overflow at the end
    for (; i < ceilIntA; ++i) {
      result.m_value.push_back(A->m_value[i]);
    }
  }
  result.SetMSB();  // Set the MSB.
  return result;
}

template <typename limb_t>
const ubint<limb_t> &ubint<limb_t>::AddEq(const ubint &b) {
  if (this->m_state == GARBAGE || b.m_state == GARBAGE) {
    PALISADE_THROW(lbcrypto::not_available_error,
                   "AddEq() to uninitialized bint");
  }
  if (b.m_MSB == 0) {  // b==0
    return (*this);
  }
  if (this->m_MSB == 0) {  // a==0
    *this = b;
    return (*this);
  }
  Dlimb_t ofl = 0;  // overflow variable
  size_t sizeThis = this->m_value.size();
  size_t sizeB = b.m_value.size();
  usint i;
  bool thisIsBigger = sizeThis > sizeB;
  size_t sizeSmall = (sizeThis < sizeB) ? sizeThis : sizeB;

  // loop over limbs low to high till you reach the end of the smaller one

  for (i = 0; i < sizeSmall; ++i) {
    // sum of the two int and the carry over
    ofl = (Dlimb_t)this->m_value[i] + (Dlimb_t)b.m_value[i] + ofl;
    this->m_value[i] = (limb_t)ofl;
    ofl >>= m_limbBitLength;  // current overflow
  }
  if (thisIsBigger) {
    // we have an overflow at the of the shorter word, so we need to
    if (ofl) {
      // keep looping over the remainder of the larger value
      for (; i < sizeThis; ++i) {
        // sum of the two int and the carry over
        ofl = (Dlimb_t)this->m_value[i] + ofl;
        this->m_value[i] = (limb_t)ofl;
        ofl >>= m_limbBitLength;  // current overflow
      }
      if (ofl) {  // in the end if overflow is set it indicates MSB is one
                  // greater than the one we started with
        this->m_value.push_back(1);
      }
    }
  } else {
    // B is bigger and we have an overflow at the of the shorter word, so we
    // need to
    if (ofl) {
      // keep looping over the remainder of the larger value
      for (; i < sizeB; ++i) {
        // sum of the two int and the carry over
        ofl = (Dlimb_t)b.m_value[i] + ofl;
        this->m_value.push_back((limb_t)ofl);
        ofl >>= m_limbBitLength;  // current overflow
      }
      if (ofl) {  // in the end if overflow is set it indicates MSB is one
                  // greater than the one we started with
        this->m_value.push_back(1);
      }
    } else {  // there is no overflow at the end, just copy the rest
      for (; i < sizeB; ++i) {
        this->m_value.push_back(b.m_value[i]);
      }
    }
  }
  this->SetMSB();  // Set the MSB.
  return *this;
}

/** Sub operation:
 *  Algorithm used is usual school book borrow and subtract, except for that
 * radix is 2^m_bitLength.
 */
template <typename limb_t>
ubint<limb_t> ubint<limb_t>::Sub(const ubint &b) const {
  if (this->m_state == GARBAGE || b.m_state == GARBAGE) {
    PALISADE_THROW(lbcrypto::not_available_error,
                   "Sub() to uninitialized bint");
  }
  // return 0 if b is higher than *this as there is no support for negative
  // number
  if (!(*this > b)) {
    ubint result(0);
    return result;
  }
  size_t cntr = 0, current = 0;
  ubint result(*this);
  for (size_t i = 0; i < b.m_value.size(); ++i) {
    if (result.m_value[i] < b.m_value[i]) {  // carryover condition need to
                                             // borrow from higher limbs.
      current = i;
      cntr = current + 1;
      if (cntr >= result.m_value.size()) {
        PALISADE_THROW(lbcrypto::math_error, "error seek past end of result ");
      }
      while (result.m_value[cntr] == 0) {
        // set all the zero limbs to all FFs (propagate the 1)
        result.m_value[cntr] = m_MaxLimb;
        cntr++;
      }
      // and eventually borrow 1 from the first nonzero limb we find
      result.m_value[cntr]--;
      // and add the it to the current limb
      result.m_value[i] = result.m_value[i] + (m_MaxLimb - b.m_value[i]) + 1;
    } else {  // usual subtraction condition
      result.m_value[i] = result.m_value[i] - b.m_value[i];
    }
  }
  result.NormalizeLimbs();
  result.SetMSB();
  return result;
}

/** -=
 *  Algorithm used is usual school book borrow and subtract, except for that
 * radix is 2^m_bitLength.
 */
template <typename limb_t>
const ubint<limb_t> &ubint<limb_t>::SubEq(const ubint &b) {
  if (this->m_state == GARBAGE || b.m_state == GARBAGE) {
    PALISADE_THROW(lbcrypto::not_available_error,
                   "SubEq() to uninitialized bint");
  }
  // return 0 if b is higher than *this as there is no support for negative
  // number
  if (!(*this > b)) {
    *this = 0;
    return *this;
  }
  size_t cntr = 0, current = 0;
  for (size_t i = 0; i < b.m_value.size(); ++i) {
    if (this->m_value[i] < b.m_value[i]) {  // carryover condition need to
                                            // borrow from higher limbs.
      current = i;
      cntr = current + 1;
      // find the first nonzero limb
      if (cntr >= this->m_value.size()) {
        PALISADE_THROW(lbcrypto::math_error, "error seek past end of result ");
      }
      while (this->m_value[cntr] == 0) {
        // set all the zero limbs to all FFs (propagate the 1)
        this->m_value[cntr] = m_MaxLimb;
        cntr++;
      }
      // and eventually borrow 1 from the first nonzero limb we find
      this->m_value[cntr]--;
      // and add the it to the current limb
      this->m_value[i] = this->m_value[i] + (m_MaxLimb - b.m_value[i]) + 1;
    } else {  // usual subtraction condition
      this->m_value[i] = this->m_value[i] - b.m_value[i];
    }
  }
  this->NormalizeLimbs();
  this->SetMSB();
  return *this;
}

/** Multiply operation:
 *  Algorithm used is usual school book shift and add after multiplication,
 * except for that radix is 2^m_bitLength.
 */
template <typename limb_t>
ubint<limb_t> ubint<limb_t>::Mul(const ubint &b) const {
  ubint ans(0);
  if (b.m_MSB == 0 || b.m_state == GARBAGE || this->m_state == GARBAGE ||
      this->m_MSB == 0) {
    return ans;
  }
  if (b.m_MSB == 1) {
    return ubint(*this);
  }
  if (this->m_MSB == 1) {
    // todo check this? don't think standard move is what we want.
    ubint result(b);
    return result;
  }

  // position of B in the array where the multiplication should start
  // limb_t ceilLimb = b.m_value.size();
  // Multiplication is done by getting a limb_t from b and multiplying it with
  // *this after multiplication the result is shifted and added to the final
  // answer

  size_t nSize = this->m_value.size();
  size_t bSize = b.m_value.size();
  ubint tmpans;
  ans.m_value.reserve(nSize + bSize);
  tmpans.m_value.reserve(nSize + 1);

  for (size_t i = 0; i < bSize; ++i) {
    tmpans.m_value.clear();  // make sure there are no limbs to start.
    Dlimb_t limbb(b.m_value[i]);
    Dlimb_t temp = 0;
    limb_t ofl = 0;
    usint ix = 0;
    while (ix < i) {
      tmpans.m_value.push_back(0);  // equivalent of << shift
      ++ix;
    }

    for (auto itr : m_value) {
      temp = ((Dlimb_t)itr * (Dlimb_t)limbb) + ofl;
      tmpans.m_value.push_back((limb_t)temp);
      ofl = temp >> m_limbBitLength;
    }
    if (ofl) {
      tmpans.m_value.push_back(ofl);
    }
    tmpans.m_state = INITIALIZED;
    tmpans.SetMSB();
    ans += tmpans;
  }
  return ans;
}

// TODO reconsider the method
template <typename limb_t>
const ubint<limb_t> &ubint<limb_t>::MulEq(const ubint &b) {
  return *this = this->Mul(b);
}

/* Division operation:
 *  Algorithm used is usual school book long division , except for that radix is
 * 2^m_bitLength. Optimization done: Uses bit shift operation for logarithmic
 * convergence.
 */
template <typename limb_t>
ubint<limb_t> ubint<limb_t>::DividedBy(const ubint &b) const {
  if (b.m_state == GARBAGE) {
    PALISADE_THROW(lbcrypto::not_available_error,
                   "DividedBy() Divisor uninitialized");
  }
  if (b == 0) {
    PALISADE_THROW(lbcrypto::math_error, "Divisor is zero");
  }
  if (b.m_MSB > this->m_MSB) {
    ubint result(0);
    return result;  // Note we return a zero when b>this
  }
  if (this->m_state == GARBAGE) {
    PALISADE_THROW(lbcrypto::not_available_error,
                   "DividedBy() Dividend uninitialized");
  } else if (b == *this) {
    ubint result(1);
    return result;
  }
  ubint ans;
  int f;
  f = divq_vect((ans), (*this), (b));
  if (f != 0) {
    PALISADE_THROW(lbcrypto::math_error, "DividedBy() error");
  }
  ans.NormalizeLimbs();
  ans.m_state = INITIALIZED;
  ans.SetMSB();
  return ans;
}

template <typename limb_t>
const ubint<limb_t> &ubint<limb_t>::DividedByEq(const ubint &b) {
  return *this = this->DividedBy(b);
}

// Recursive Exponentiation function
template <typename limb_t>
ubint<limb_t> ubint<limb_t>::Exp(usint p) const {
  if (p == 0) {
    return 1;
  }
  ubint x(*this);
  if (p == 1) {
    return x;
  }
  ubint tmp = x.Exp(p / 2);
  if (p % 2 == 0) {
    return tmp * tmp;
  } else {
    return tmp * tmp * x;
  }
}

template <typename limb_t>
const ubint<limb_t> &ubint<limb_t>::ExpEq(usint p) {
  if (p == 0) {
    return *this = 1;
  }
  if (p == 1) {
    return *this;
  }
  ubint tmp = this->Exp(p / 2);
  if (p % 2 == 0) {
    (*this) = tmp * tmp;
    return *this;
  } else {
    (*this) *= tmp * tmp;
    return *this;
  }
}

template <typename limb_t>
ubint<limb_t> ubint<limb_t>::MultiplyAndRound(const ubint &p,
                                              const ubint &q) const {
  ubint ans(*this);
  ans.MulEq(p);
  ans.DivideAndRoundEq(q);
  return ans;
}

template <typename limb_t>
const ubint<limb_t> &ubint<limb_t>::MultiplyAndRoundEq(const ubint &p,
                                                       const ubint &q) {
  this->MulEq(p);
  this->DivideAndRoundEq(q);
  return *this;
}

template <typename limb_t>
ubint<limb_t> ubint<limb_t>::DivideAndRound(const ubint &q) const {
  if (q.m_state == GARBAGE) {
    PALISADE_THROW(lbcrypto::not_available_error,
                   "DivideAndRound() Divisor uninitialized");
  }
  if (q == 0) {
    PALISADE_THROW(lbcrypto::math_error, "DivideAndRound() Divisor is zero");
  }
  ubint halfQ(q >> 1);
  if (*this < q) {
    if (*this <= halfQ) {
      return ubint(0);
    } else {
      return ubint(1);
    }
  }
  ubint ans(0);
  ubint rv(0);

  int f;
  f = divqr_vect(ans, rv, *this, q);
  if (f != 0) {
    PALISADE_THROW(lbcrypto::math_error, "Divqr() error in DivideAndRound");
  }

  ans.NormalizeLimbs();
  rv.NormalizeLimbs();

  ans.m_state = INITIALIZED;
  ans.SetMSB();
  rv.m_state = INITIALIZED;
  rv.SetMSB();
  if (!(rv <= halfQ)) {
    ans += 1;
  }
  return ans;
}

// TODO reconsider the method
template <typename limb_t>
const ubint<limb_t> &ubint<limb_t>::DivideAndRoundEq(const ubint &q) {
  return *this = this->DivideAndRound(q);
}

// MODULAR ARITHMETIC OPERATIONS

// Algorithm used: optimized division algorithm
template <typename limb_t>
ubint<limb_t> ubint<limb_t>::Mod(const ubint &modulus) const {
  // check for GARBAGE initialization
  if (this->m_state == GARBAGE) {
    PALISADE_THROW(lbcrypto::not_available_error,
                   "Mod() of uninitialized bint");
  }
  if (modulus.m_state == GARBAGE) {
    PALISADE_THROW(lbcrypto::not_available_error,
                   "Mod() using uninitialized bint as modulus");
  }
  if (modulus == 0) {
    PALISADE_THROW(lbcrypto::math_error, "Mod() using zero modulus");
  }
  if (modulus.m_value.size() > 1 && modulus.m_value.back() == 0) {
    PALISADE_THROW(lbcrypto::not_available_error,
                   "Mod() using unnormalized  modulus");
  }
  // return the same value if value is less than modulus
  if (this->m_MSB < modulus.m_MSB) {
    ubint result(*this);
    return result;
  }
  if ((this->m_MSB == modulus.m_MSB) && (*this < modulus)) {
    ubint result(*this);
    return result;
  }
  // use simple masking operation if modulus is 2
  if (modulus.m_MSB == 2 && modulus.m_value[0] == 2) {
    if (this->m_value[0] % 2 == 0) {
      return ubint(0);
    } else {
      return ubint(1);
    }
  }
#ifndef UBINT_64
  ubint ans(0);
  int f;
#ifndef OLD_DIV
  ans.m_value.resize(modulus.m_value.size());
#endif
  f = divr_vect(ans, *this, modulus);
  if (f != 0) {
    PALISADE_THROW(lbcrypto::math_error, "Mod() divr error");
  }
  ans.NormalizeLimbs();
  ans.SetMSB();
  ans.m_state = INITIALIZED;
  return (ans);
#else  // radically slow for 64 bit version.
  int initial_shift = 0;
  if (this->m_MSB > modulus.m_MSB) {
    initial_shift = this->m_MSB - modulus.m_MSB - 1;
  }
  ubint j = modulus << initial_shift;
  ubint result(*this);
  ubint temp;
  while (true) {
    // exit criteria
    if (result < modulus) {
      break;
    }
    if (result.m_MSB > j.m_MSB) {
      temp = j << 1;
      if (result.m_MSB == j.m_MSB + 1) {
        if (result > temp) {
          j = temp;
        }
      }
    }
    // subtracting the running remainder by a multiple of modulus
    result -= j;
    initial_shift = j.m_MSB - result.m_MSB + 1;
    if (result.m_MSB - 1 >= modulus.m_MSB) {
      j >>= initial_shift;
    } else {
      j = modulus;
    }
  }
  result.NormalizeLimbs();
  result.SetMSB();
  return result;
#endif
}

template <typename limb_t>
const ubint<limb_t> &ubint<limb_t>::ModEq(const ubint &modulus) {
  // check for GARBAGE initialization
  if (this->m_state == GARBAGE) {
    PALISADE_THROW(lbcrypto::not_available_error,
                   "ModEq() of uninitialized bint");
  }
  if (modulus.m_state == GARBAGE) {
    PALISADE_THROW(lbcrypto::math_error,
                   "ModEq() using uninitialized bint as modulus");
  }
  if (modulus == 0) {
    PALISADE_THROW(lbcrypto::not_available_error, "ModEq() using zero modulus");
  }
  if (modulus.m_value.size() > 1 && modulus.m_value.back() == 0) {
    PALISADE_THROW(lbcrypto::not_available_error,
                   "ModEq() using unnormalized  modulus");
  }
  // return the same value if value is less than modulus
  if (this->m_MSB < modulus.m_MSB) {
    return *this;
  }
  if ((this->m_MSB == modulus.m_MSB) && (*this < modulus)) {
    return *this;
  }

  // use simple masking operation if modulus is 2
  if (modulus.m_MSB == 2 && modulus.m_value[0] == 2) {
    if (this->m_value[0] % 2 == 0) {
      return *this = 0;
    } else {
      return *this = 1;
    }
  }
#ifndef UBINT_64
  // TODO do this in place!
  ubint ans(0);
  int f;
#ifndef OLD_DIV
  ans.m_value.resize(modulus.m_value.size());
#endif
  f = divr_vect(ans, *this, modulus);
  if (f != 0) {
    PALISADE_THROW(lbcrypto::math_error, "Mod() divr error");
  }
  ans.NormalizeLimbs();
  ans.SetMSB();
  ans.m_state = INITIALIZED;
  return *this = ans;
#else  // radically slow for 64 bit version.
  int initial_shift = 0;
  if (this->m_MSB > modulus.m_MSB) {
    initial_shift = this->m_MSB - modulus.m_MSB - 1;
  }
  ubint j = modulus << initial_shift;
  ubint result(*this);
  ubint temp;
  while (true) {
    // exit criteria
    if (result < modulus) {
      break;
    }
    if (result.m_MSB > j.m_MSB) {
      temp = j << 1;
      if (result.m_MSB == j.m_MSB + 1) {
        if (result > temp) {
          j = temp;
        }
      }
    }
    // subtracting the running remainder by a multiple of modulus
    result -= j;
    initial_shift = j.m_MSB - result.m_MSB + 1;
    if (result.m_MSB - 1 >= modulus.m_MSB) {
      j >>= initial_shift;
    } else {
      j = modulus;
    }
  }
  result.NormalizeLimbs();
  result.SetMSB();
  return result;
#endif
}

template <typename limb_t>
ubint<limb_t> ubint<limb_t>::ComputeMu() const {
  ubint temp(1);
  temp <<= (2 * this->GetMSB() + 3);
  return temp.DividedBy(*this);
  return temp;
}

template <typename limb_t>
ubint<limb_t> ubint<limb_t>::Mod(const ubint &modulus, const ubint &mu) const {
#ifdef NO_BARRETT
  ubint ans(*this);
  ans.ModEq(modulus);
  return ans;
#else
  if (*this < modulus) {
    ubint result(*this);
    return result;
  }
  ubint z(*this);
  ubint q(*this);

  usint n = modulus.m_MSB;
  usint alpha = n + 3;
  int beta = -2;

  q >>= n + beta;
  q *= mu;
  q >>= alpha - beta;
  z -= q * modulus;

  if (z >= modulus) {
    z -= modulus;
  }

  return z;
#endif
}

template <typename limb_t>
const ubint<limb_t> &ubint<limb_t>::ModEq(const ubint &modulus,
                                          const ubint &mu) {
#ifdef NO_BARRETT
  return *this = this->ModEq(modulus);
#else
  if ((*this) < modulus) {
    return *this;
  }
  ubint q(*this);

  usint n = modulus.m_MSB;
  usint alpha = n + 3;
  int beta = -2;

  q >>= n + beta;
  q *= mu;
  q >>= alpha - beta;
  (*this) -= q * modulus;

  if ((*this) >= modulus) {
    (*this) -= modulus;
  }

  return (*this);
#endif
}

template <typename limb_t>
ubint<limb_t> ubint<limb_t>::ModAdd(const ubint &b,
                                    const ubint &modulus) const {
  ubint a(*this);
  ubint b_op(b);
  if (*this >= modulus) {
    a.ModEq(modulus);
  }
  if (b >= modulus) {
    b_op.ModEq(modulus);
  }
  a.AddEq(b_op);
  return a.ModEq(modulus);
}

template <typename limb_t>
const ubint<limb_t> &ubint<limb_t>::ModAddEq(const ubint &b,
                                             const ubint &modulus) {
  ubint b_op(b);
  if (*this >= modulus) {
    this->ModEq(modulus);
  }
  if (b >= modulus) {
    b_op.ModEq(modulus);
  }
  this->AddEq(b_op);
  this->ModEq(modulus);
  return *this;
}

template <typename limb_t>
ubint<limb_t> ubint<limb_t>::ModAddFast(const ubint &b,
                                        const ubint &modulus) const {
  ubint ans(*this);
  return ans.ModAddFastEq(b, modulus);
}

template <typename limb_t>
const ubint<limb_t> &ubint<limb_t>::ModAddFastEq(const ubint &b,
                                                 const ubint &modulus) {
  this->AddEq(b);
  this->ModEq(modulus);
  return *this;
}

template <typename limb_t>
ubint<limb_t> ubint<limb_t>::ModAdd(const ubint &b, const ubint &modulus,
                                    const ubint &mu) const {
  ubint ans(*this);
  ans.ModAddEq(b, modulus, mu);
  return ans;
}

template <typename limb_t>
const ubint<limb_t> &ubint<limb_t>::ModAddEq(const ubint &b,
                                             const ubint &modulus,
                                             const ubint &mu) {
  this->AddEq(b);
  this->ModEq(modulus, mu);
  return *this;
}

template <typename limb_t>
ubint<limb_t> ubint<limb_t>::ModSub(const ubint &b,
                                    const ubint &modulus) const {
  ubint a(*this);
  ubint b_op(b);
  if (*this >= modulus) {
    a.ModEq(modulus);
  }
  if (b >= modulus) {
    b_op.ModEq(modulus);
  }
  if (a >= b_op) {
    a.SubEq(b_op);
    a.ModEq(modulus);
  } else {
    a.AddEq(modulus);
    a.SubEq(b_op);
  }
  return a;
}

template <typename limb_t>
const ubint<limb_t> &ubint<limb_t>::ModSubEq(const ubint &b,
                                             const ubint &modulus) {
  ubint b_op(b);
  if (*this >= modulus) {
    this->ModEq(modulus);
  }
  if (b >= modulus) {
    b_op.ModEq(modulus);
  }
  if (*this >= b_op) {
    this->SubEq(b_op);
    this->ModEq(modulus);
  } else {
    this->AddEq(modulus);
    this->SubEq(b_op);
  }
  return *this;
}

template <typename limb_t>
ubint<limb_t> ubint<limb_t>::ModSubFast(const ubint &b,
                                        const ubint &modulus) const {
  ubint a(*this);
  if (a >= b) {
    a.SubEq(b);
    a.ModEq(modulus);
  } else {
    a.AddEq(modulus);
    a.SubEq(b);
  }
  return a;
}

template <typename limb_t>
const ubint<limb_t> &ubint<limb_t>::ModSubFastEq(const ubint &b,
                                                 const ubint &modulus) {
  if (*this >= b) {
    this->SubEq(b);
    this->ModEq(modulus);
  } else {
    this->AddEq(modulus);
    this->SubEq(b);
  }
  return *this;
}

template <typename limb_t>
ubint<limb_t> ubint<limb_t>::ModSub(const ubint &b, const ubint &modulus,
                                    const ubint &mu) const {
  ubint a(*this);
  ubint b_op(b);
  if (*this >= modulus) {
    a.ModEq(modulus, mu);
  }
  if (b >= modulus) {
    b_op.ModEq(modulus, mu);
  }
  if (a >= b_op) {
    a.SubEq(b_op);
    a.ModEq(modulus, mu);
  } else {
    a.AddEq(modulus);
    a.SubEq(b_op);
  }
  return a;
}

template <typename limb_t>
const ubint<limb_t> &ubint<limb_t>::ModSubEq(const ubint &b,
                                             const ubint &modulus,
                                             const ubint &mu) {
  ubint b_op(b);
  if (*this >= modulus) {
    this->ModEq(modulus, mu);
  }
  if (b >= modulus) {
    b_op.ModEq(modulus, mu);
  }
  if (*this >= b_op) {
    this->SubEq(b_op);
    this->ModEq(modulus, mu);
  } else {
    this->AddEq(modulus);
    this->SubEq(b_op);
  }
  return *this;
}

template <typename limb_t>
ubint<limb_t> ubint<limb_t>::ModMul(const ubint &b,
                                    const ubint &modulus) const {
  ubint a(*this);
  ubint ans(0);
  // check for garbage initialized objects
  if (b.m_MSB == 0 || b.m_state == GARBAGE || a.m_state == GARBAGE ||
      a.m_MSB == 0) {
    return ans;
  }
  // check for trivial conditions
  if (b.m_MSB == 1) {
    return a;
  }

  if (a.m_MSB == 1) {
    return b;
  }

  // position of B in the array where the multiplication should start
  // limb_t ceilLimb = b.m_value.size();
  // Multiplication is done by getting a limb_t from b and multiplying it with
  // *this after multiplication the result is shifted and added to the final
  // answer

  size_t nSize = a.m_value.size();
  size_t bSize = b.m_value.size();
  ubint tmpans;
  ans.m_value.reserve(nSize + bSize);
  tmpans.m_value.reserve(nSize + bSize);

  for (size_t i = 0; i < bSize; ++i) {
    tmpans.m_value.clear();  // make sure there are no limbs to start.
    Dlimb_t limbb(b.m_value[i]);
    Dlimb_t temp = 0;
    limb_t ofl = 0;
    usint ix = 0;
    while (ix < i) {
      tmpans.m_value.push_back(0);  // equivalent of << shift
      ++ix;
    }

    for (auto itr : a.m_value) {
      temp = ((Dlimb_t)itr * (Dlimb_t)limbb) + ofl;
      tmpans.m_value.push_back((limb_t)temp);
      ofl = temp >> a.m_limbBitLength;
    }
    // check if there is any final overflow
    if (ofl) {
      tmpans.m_value.push_back(ofl);
    }
    tmpans.m_state = INITIALIZED;
    tmpans.SetMSB();
    ans += tmpans;
    ans = ans.Mod(modulus);
  }
  return ans;
}

// TODO reconsider the method
template <typename limb_t>
const ubint<limb_t> &ubint<limb_t>::ModMulEq(const ubint &b,
                                             const ubint &modulus) {
  return *this = this->ModMul(b, modulus);
}

template <typename limb_t>
ubint<limb_t> ubint<limb_t>::ModMul(const ubint &b, const ubint &modulus,
                                    const ubint &mu) const {
#ifdef NO_BARRETT
  return this->ModMul(b, modulus);
#else
  ubint a(*this);
  ubint bb(b);
  if (*this > modulus) {
    a.ModEq(modulus, mu);
  }
  if (b > modulus) {
    bb.ModEq(modulus, mu);
  }

  a.MulEq(bb);
  a.ModEq(modulus, mu);
  return a;
#endif
}

template <typename limb_t>
const ubint<limb_t> &ubint<limb_t>::ModMulEq(const ubint &b,
                                             const ubint &modulus,
                                             const ubint &mu) {
#ifdef NO_BARRETT
  return *this = this->ModMul(b, modulus);
#else
  ubint bb(b);
  if ((*this) > modulus) {
    this->ModEq(modulus, mu);
  }
  if (b > modulus) {
    bb.ModEq(modulus, mu);
  }
  this->MulEq(bb);
  this->ModEq(modulus, mu);
  return *this;
#endif
}

// TODO make this skip the mod
template <typename limb_t>
ubint<limb_t> ubint<limb_t>::ModMulFast(const ubint &b,
                                        const ubint &modulus) const {
  return this->ModMul(b, modulus);
}

// TODO reconsider the method
template <typename limb_t>
const ubint<limb_t> &ubint<limb_t>::ModMulFastEq(const ubint &b,
                                                 const ubint &modulus) {
  return *this = this->ModMul(b, modulus);
}

template <typename limb_t>
ubint<limb_t> ubint<limb_t>::ModMulFast(const ubint &b, const ubint &modulus,
                                        const ubint &mu) const {
#ifdef NO_BARRETT
  return this->ModMul(b, modulus);
#else
  ubint a(*this);
  a.MulEq(b);
  a.ModEq(modulus, mu);
  return a;
#endif
}

template <typename limb_t>
const ubint<limb_t> &ubint<limb_t>::ModMulFastEq(const ubint &b,
                                                 const ubint &modulus,
                                                 const ubint &mu) {
#ifdef NO_BARRETT
  return *this = this->ModMul(b, modulus);
#else
  this->MulEq(b);
  this->ModEq(modulus, mu);
  return *this;
#endif
}

// Extended Euclid algorithm used to find the multiplicative inverse
template <typename limb_t>
ubint<limb_t> ubint<limb_t>::ModInverse(const ubint &modulus) const {
  ubint second;
  if (*this > modulus) {
    second = Mod(modulus);
  } else {
    second = *this;
  }
  if (second == 0) {
    PALISADE_THROW(lbcrypto::math_error, "Zero has no inverse");
  }
  if (second == 1) {
    return 1;
  }

  // NORTH ALGORITHM
  ubint first(modulus);
  ubint mod_back = first.Mod(second);
  std::vector<ubint> quotient{first.DividedBy(second)};

  // the max number of iterations should be < 2^k where k ==  min(bitsize
  // (inputs))
  // TODO: consider breaking out of the loop if this limit exceeded. the only
  // issue is that the loop counter could would need to be an ubint.
  while (mod_back != 1) {
    if (mod_back == 0) {
      PALISADE_THROW(lbcrypto::math_error,
                     this->ToString() + " does not have a ModInverse using " +
                         modulus.ToString());
    }
    first = second;
    second = mod_back;
    mod_back = first.Mod(second);
    // second != 0, since we throw if mod_back == 0
    quotient.push_back(first.DividedBy(second));
  }

  // SOUTH ALGORITHM
  first = 0;
  second = 1;
  for (int i = quotient.size() - 1; i >= 0; i--) {
    mod_back = quotient[i] * second + first;
    first = second;
    second = mod_back;
  }
  if (quotient.size() % 2 == 1) {
    return modulus - mod_back;
  }
  return mod_back;
}

// Extended Euclid algorithm used to find the multiplicative inverse
template <typename limb_t>
const ubint<limb_t> &ubint<limb_t>::ModInverseEq(const ubint &modulus) {
  *this = ModInverse(modulus);
  return *this;
}

// Modular Exponentiation using Square and Multiply Algorithm
// reference:http://guan.cse.nsysu.edu.tw/note/expn.pdf
template <typename limb_t>
ubint<limb_t> ubint<limb_t>::ModExp(const ubint &b,
                                    const ubint &modulus) const {
  ubint mid = this->Mod(modulus);
  ubint product(1);
  ubint Exp(b);

  unsigned int loops = 0;
#if 1
  while (true) {
    // product is multiplied only if lsb bitvalue is 1
    if (Exp.m_value[0] % 2 == 1) {
      product = product * mid;
    }
    if (product > modulus) {
      product = product.Mod(modulus);
    }
    Exp = Exp >> 1;
    if (Exp == 0) {
      break;
    }
    mid = mid * mid;
    mid = (mid.Mod(modulus));
    loops++;
  }
#else
  while (true) {
    if ((Exp.m_value[0] & 1) == 1) {
      product = product.ModMul(mid, modulus);
    }
    Exp >>= 1;
    if (Exp == 0) {
      break;
    }
    mid = (mid.ModMul(mid, modulus));
    loops++;
  }
#endif
  return product;
}

// TODO reconsider method
template <typename limb_t>
const ubint<limb_t> &ubint<limb_t>::ModExpEq(const ubint &b,
                                             const ubint &modulus) {
  return *this = this->ModExp(b, modulus);
}

/**
 *  Left Shift is done by splitting the number of shifts into
 *1. Multiple of the bit length of limb data type.
 *  Shifting is done by the shifting the limb type numbers.
 *2. Shifts between 1 to bit length of limb data type.
 *   Shifting is done by using bit shift operations and carry over prop.
 */
template <typename limb_t>
ubint<limb_t> ubint<limb_t>::LShift(usshort shift) const {
  // garbage check
  if (m_state == GARBAGE) {
    PALISADE_THROW(lbcrypto::not_available_error, "<< on uninitialized bint");
  }
  // trivial case
  if (this->m_MSB == 0) {
    return ubint(0);
  }
  ubint ans(*this);
  // compute the number of whole limb shifts
  usint shiftByLimb = shift >> m_log2LimbBitLength;
  // ans.m_value.reserve(shiftByLimb+this->m_value.size());
  // compute the remaining number of bits to shift
  limb_t remainingShift = (shift & (m_limbBitLength - 1));
  // first shift by the # remainingShift bits
  if (remainingShift != 0) {
    limb_t oFlow = 0;
    Dlimb_t temp = 0;
    size_t i;
    for (i = 0; i < ceilIntByUInt(m_MSB); ++i) {
      temp = ans.m_value[i];
      temp <<= remainingShift;
      ans.m_value[i] = (limb_t)temp + oFlow;
      oFlow = temp >> m_limbBitLength;
    }
    if (oFlow) {  // there is an overflow set of bits.
      if (i < ans.m_value.size()) {
        ans.m_value[i] = oFlow;
      } else {
        ans.m_value.push_back(oFlow);
      }
    }
    ans.m_MSB += remainingShift;
  }

  if (shiftByLimb != 0) {
    usint currentSize = ans.m_value.size();
    ans.m_value.resize(currentSize + shiftByLimb);  // allocate more storage
    for (int i = currentSize - 1; i >= 0;
         i--) {  // shift limbs required # of indicies
      ans.m_value[i + shiftByLimb] = ans.m_value[i];
    }
    for (int i = shiftByLimb - 1; i >= 0; i--) {
      ans.m_value[i] = 0;
    }
  }
  ans.m_MSB += shiftByLimb * m_limbBitLength;
  return ans;
}

/**
 *  Left Shift is done by splitting the number of shifts into
 *1. Multiple of the bit length of limb data type.
 *  Shifting is done by the shifting the limb type numbers.
 *2. Shifts between 1 to bit length of limb data type.
 *   Shifting is done by using bit shift operations and carry over prop.
 */
template <typename limb_t>
const ubint<limb_t> &ubint<limb_t>::LShiftEq(usshort shift) {
  if (m_state == GARBAGE) {
    PALISADE_THROW(lbcrypto::not_available_error, "<<= on uninitialized bint");
  }
  if (this->m_MSB == 0) {
    return *this;
  } else {
    usint shiftByLimb =
        shift >>
        m_log2LimbBitLength;  // compute the number of whole limb shifts
    limb_t remainingShift =
        (shift & (m_limbBitLength -
                  1));  // compute the remaining number of bits to shift

    // first shift by the # remainingShift bits
    if (remainingShift != 0) {
      limb_t oFlow = 0;
      Dlimb_t temp = 0;
      size_t i;
      for (i = 0; i < ceilIntByUInt(m_MSB); ++i) {
        // can optimize here further.
        temp = m_value[i];
        temp <<= remainingShift;
        m_value[i] = (limb_t)temp + oFlow;
        oFlow = temp >> m_limbBitLength;
      }
      if (oFlow) {  // there is an overflow set of bits.
        if (i < m_value.size()) {
          m_value[i] = oFlow;
        } else {
          m_value.push_back(oFlow);
        }
      }
      m_MSB += remainingShift;
    }
    if (shiftByLimb != 0) {
      usint currentSize = m_value.size();
      m_value.resize(currentSize + shiftByLimb);  // allocate more storage
      for (int i = currentSize - 1; i >= 0;
           i--) {  // shift limbs required # of indicies
        m_value[i + shiftByLimb] = m_value[i];
      }
      // zero out the 'shifted in' limbs
      for (int i = shiftByLimb - 1; i >= 0; i--) {
        m_value[i] = 0;
      }
    }
    m_MSB += shiftByLimb * m_limbBitLength;
    return *this;
  }
}

/**Right Shift is done by splitting the number of shifts into
 *1. Multiple of the bit length of limb data type.
 *  Shifting is done by the shifting the limb type numbers in the array to
 *the right.
 *2. Shifts between 1 to bit length of limb data type.
 *   Shifting is done by using bit shift operations and carry over propagation.
 */
template <typename limb_t>
ubint<limb_t> ubint<limb_t>::RShift(usshort shift) const {
  if (m_state == GARBAGE) {
    PALISADE_THROW(lbcrypto::not_available_error, "Value not INITIALIZED");
  }
  if (this->m_MSB == 0 || this->m_MSB <= shift) {
    return ubint(0);
  }

  ubint ans(*this);
  usint shiftByLimb = shift >> m_log2LimbBitLength;
  limb_t remainingShift = (shift & (m_limbBitLength - 1));
  if (shiftByLimb != 0) {
    for (auto i = shiftByLimb; i < ans.m_value.size(); ++i) {
      ans.m_value[i - shiftByLimb] = ans.m_value[i];
    }
    // zero out upper  "shifted in" limbs
    for (usint i = 0; i < shiftByLimb; ++i) {
      ans.m_value.pop_back();
    }
    // msb adjusted to show the shifts
    ans.m_MSB -= shiftByLimb << m_log2LimbBitLength;
  }
  // remainderShift bit shifts
  if (remainingShift != 0) {
    limb_t overFlow = 0;
    limb_t oldVal;
    limb_t maskVal = (1 << (remainingShift)) - 1;
    limb_t compShiftVal = m_limbBitLength - remainingShift;
    usint startVal = ceilIntByUInt(ans.m_MSB);
    // perform shifting by bits by calculating the overflow
    // oveflow is added after the shifting operation
    for (int i = startVal - 1; i >= 0; i--) {
      oldVal = ans.m_value[i];
      ans.m_value[i] = (ans.m_value[i] >> remainingShift) + overFlow;

      overFlow = (oldVal & maskVal);
      overFlow <<= compShiftVal;
    }
    ans.m_MSB -= remainingShift;
  }
  ans.NormalizeLimbs();
  ans.SetMSB();
  return ans;
}

/**Right Shift is done by splitting the number of shifts into
 *1. Multiple of the bit length of limb data type.
 *  Shifting is done by the shifting the limb type numbers in the array to
 *the right.
 *2. Shifts between 1 to bit length of limb data type.
 *   Shifting is done by using bit shift operations and carry over propagation.
 */
template <typename limb_t>
const ubint<limb_t> &ubint<limb_t>::RShiftEq(usshort shift) {
  // garbage check
  if (m_state == GARBAGE) {
    PALISADE_THROW(lbcrypto::not_available_error, "Value not INITIALIZED");
  }
  // trivial cases
  if (this->m_MSB == 0) {
    return *this;
  }
  if (this->m_MSB <= shift) {
    this->m_value.clear();  // zero out this
    this->m_value.push_back(0);
    this->m_MSB = 0;
  }
  // compute the number of whole limb shifts
  usint shiftByLimb = shift >> m_log2LimbBitLength;
  // compute the remaining number of bits to shift
  limb_t remainingShift = (shift & (m_limbBitLength - 1));
  // first shift by the number of whole limb shifts
  if (shiftByLimb != 0) {
    for (auto i = shiftByLimb; i < this->m_value.size(); ++i) {
      this->m_value[i - shiftByLimb] = this->m_value[i];
    }
    // zero out upper  "shifted in" limbs
    for (usint i = 0; i < shiftByLimb; ++i) {
      this->m_value.pop_back();
    }
    // msb adjusted to show the shifts
    this->m_MSB -= shiftByLimb << m_log2LimbBitLength;
  }
  // remainderShift bit shifts
  if (remainingShift != 0) {
    limb_t overFlow = 0;
    limb_t oldVal;
    limb_t maskVal = (1 << (remainingShift)) - 1;
    limb_t compShiftVal = m_limbBitLength - remainingShift;

    usint startVal = ceilIntByUInt(this->m_MSB);
    for (int i = startVal - 1; i >= 0; i--) {
      oldVal = this->m_value[i];
      this->m_value[i] = (this->m_value[i] >> remainingShift) + overFlow;

      overFlow = (oldVal & maskVal);
      overFlow <<= compShiftVal;
    }
    this->m_MSB -= remainingShift;
  }
  this->NormalizeLimbs();
  this->SetMSB();
  return *this;
}

// COMPARE

// Compares the current object with the ubint a.
template <typename limb_t>
inline int ubint<limb_t>::Compare(const ubint &a) const {
  if (this->m_state == GARBAGE || a.m_state == GARBAGE) {
    PALISADE_THROW(lbcrypto::not_available_error,
                   "ERROR Compare() against uninitialized bint\n");
  }
  if (this->m_MSB < a.m_MSB) {
    return -1;
  } else if (this->m_MSB > a.m_MSB) {
    return 1;
  }
  if (this->m_MSB == a.m_MSB) {
    for (int i = m_value.size() - 1; i >= 0; i--) {
      if (this->m_value[i] > a.m_value[i]) {  // b>a
        return 1;
      } else if (this->m_value[i] < a.m_value[i]) {  // a>b
        return -1;
      }
    }
  }
  return 0;  // bottom out? then the same
}

// CONVERTERS

// the following conversions all throw
// Converts the ubint to float using the std library functions.
template <typename limb_t>
float ubint<limb_t>::ConvertToFloat() const {
  if (m_value.size() == 0) {
    PALISADE_THROW(lbcrypto::not_available_error,
                   "ConvertToFloat() on uninitialized bint");
  }
  float ans;
  try {
    ans = std::stof(this->ToString());
  } catch (const std::exception &e) {
    PALISADE_THROW(lbcrypto::type_error,
                   "ConvertToFloat() parse error converting to float");
    ans = -1.0;  // TODO: this signifies an error...
  }
  return ans;
}

// Converts the ubint to double using the std library functions.
template <typename limb_t>
inline double ubint<limb_t>::ConvertToDouble() const {
  if (m_value.size() == 0) {
    PALISADE_THROW(lbcrypto::not_available_error,
                   "ConvertToDouble() on uninitialized bint");
  }
  double ans = 0.0;
  try {
    // ans = std::stod(this->ToString());
    usint ceilInt = ceilIntByUInt(m_MSB);
    double factor = pow(2.0, m_limbBitLength);
    double power = 1.0;
    // copy the values by shift and add
    for (usint i = 0; i < ceilInt; i++) {
      ans += this->m_value[i] * power;
      power *= factor;
    }
  } catch (const std::exception &e) {
    PALISADE_THROW(lbcrypto::type_error,
                   "ConvertToDouble() parse error converting to double");
    ans = -1.0;
  }
  return ans;
}

// Converts the ubint to long double using the std library functions.
template <typename limb_t>
long double ubint<limb_t>::ConvertToLongDouble() const {
  if (m_value.size() == 0) {
    PALISADE_THROW(lbcrypto::not_available_error,
                   "ConvertToLongDouble() on uninitialized bint");
  }
  long double ans;
  try {
    ans = std::stold(this->ToString());
  } catch (const std::exception &e) {
    PALISADE_THROW(
        lbcrypto::type_error,
        "ConvertToLongDouble() parse error converting to long double");
    ans = -1.0;
  }
  return ans;
}

/*
 This method can be used to oconvert int to ubint
 */
template <typename limb_t>
ubint<limb_t> ubint<limb_t>::UsintToUbint(usint m) {
  return ubint(m);
}

// Splits the binary string to equi sized chunks and then populates the internal
// array values.
template <typename limb_t>
ubint<limb_t> ubint<limb_t>::FromBinaryString(const std::string &vin) {
  std::string v = vin;
  v.erase(0, v.find_first_not_of(
                 ' '));  // strip off leading spaces from the input string
  v.erase(0, v.find_first_not_of(
                 '0'));  // strip off leading zeros from the input string
  if (v.size() == 0) {
    v = "0";  // set to one zero
  }

  ubint value;
  value.m_value.clear();  // clear out all limbs
  usint len = v.length();
  usint cntr = ceilIntByUInt(len);
  std::string val;
  Dlimb_t partial_value = 0;

  for (usint i = 0; i < cntr; i++) {  // loop over limbs
    if (len > ((i + 1) * m_limbBitLength)) {
      val = v.substr((len - (i + 1) * m_limbBitLength), m_limbBitLength);
    } else {
      val = v.substr(0, len % m_limbBitLength);
    }
    for (usint j = 0; j < val.length(); j++) {
      partial_value += std::stoi(val.substr(j, 1));
      partial_value <<= 1;
    }
    partial_value >>= 1;
    value.m_value.push_back((limb_t)partial_value);
    partial_value = 0;
  }
  value.m_MSB = (cntr - 1) * m_limbBitLength;
  value.m_MSB += GetMSBlimb_t(value.m_value.back());
  value.m_state = INITIALIZED;
  value.SetMSB();
  return value;
}

// OTHER FUNCTIONS

template <typename limb_t>
usint ubint<limb_t>::GetMSB() const {
  return m_MSB;
}

template <typename limb_t>
usint ubint<limb_t>::GetNumberOfLimbs() const {
  return m_value.size();
}

template <typename limb_t>
bool ubint<limb_t>::isPowerOfTwo(const ubint &m_numToCheck) {
  usint m_MSB = m_numToCheck.m_MSB;
  for (int i = m_MSB - 1; i > 0; i--) {
    if (static_cast<int>(m_numToCheck.GetBitAtIndex(i)) == 1) {
      return false;
    }
  }
  return true;
}

template <typename limb_t>
usint ubint<limb_t>::GetDigitAtIndexForBase(usint index, usint base) const {
  usint DigitLen = ceil(log2(base));
  usint digit = 0;
  usint newIndex = 1 + (index - 1) * DigitLen;
  for (usint i = 1; i < base; i = i * 2) {
    digit += GetBitAtIndex(newIndex) * i;
    newIndex++;
  }
  return digit;
}

template <typename limb_t>
const std::string ubint<limb_t>::GetState() const {
  switch (m_state) {
    case INITIALIZED:
      return "INITIALIZED";
      break;
    case GARBAGE:
      return "GARBAGE";
      break;
    default:
      PALISADE_THROW(lbcrypto::not_available_error,
                     "GetState() on uninitialized bint");
  }
}

/** Multiply operation helper function:
 *  Algorithm used is usual school book multiplication.
 *  This function is used in the Multiplication of two ubint objects
 * note this function is deprecated
 */
template <typename limb_t>
inline ubint<limb_t> ubint<limb_t>::MulIntegerByLimb(limb_t b) const {
  if (this->m_state == GARBAGE) {
    PALISADE_THROW(lbcrypto::not_available_error,
                   "MulIntegerByLimb() of uninitialized bint");
  }
  if (b == 0 || this->m_MSB == 0) {
    return ubint(0);
  }

  ubint ans;
  ans.m_value.clear();  // make sure there are no limbs to start.
  size_t endVal = this->m_value.size();
  Dlimb_t temp = 0;
  limb_t ofl = 0;
  size_t i = 0;
  for (; i < endVal; ++i) {
    temp = ((Dlimb_t)m_value[i] * (Dlimb_t)b) + ofl;
    ans.m_value.push_back((limb_t)temp);
    ofl = temp >> m_limbBitLength;
  }
  if (ofl) {
    ans.m_value.push_back(ofl);
  }
  ans.m_state = INITIALIZED;
  ans.SetMSB();
  return ans;
}

// STRINGS & STREAMS

template <typename limb_t>
const std::string ubint<limb_t>::ToString() const {
  // todo get rid of m_numDigitInPrintval make dynamic
  if (m_value.size() == 0) {
    PALISADE_THROW(lbcrypto::not_available_error,
                   "ToString() on uninitialized bint");
  }
  // create reference for the object to be printed

  // print_VALUE array stores the decimal value in the array
  uschar *print_VALUE =
      new uschar[m_numDigitInPrintval]();  // todo smartpointer

  // starts the conversion from base r to decimal value
  for (size_t i = m_MSB; i > 0; i--) {
    // print_VALUE = print_VALUE*2
    ubint<limb_t>::double_bitVal(print_VALUE);
    // adds the bit value to the print_VALUE
    ubint<limb_t>::add_bitVal(print_VALUE, GetBitAtIndex(i));
  }

  // find the first occurence of non-zero value in print_VALUE
  usint counter;
  for (counter = 0; counter < m_numDigitInPrintval - 1; counter++) {
    if (static_cast<int>(print_VALUE[counter]) != 0) {
      break;
    }
  }

  // this string object will store this ubint's value
  std::string bbiString;
  // append this ubint's digits to this method's returned string object
  for (; counter < m_numDigitInPrintval; counter++) {
    bbiString += std::to_string(print_VALUE[counter]);
  }
  delete[] print_VALUE;
  return bbiString;
}

/* q[0], r[0], u[0], and v[0] contain the LEAST significant words.
 (The sequence is in little-endian order).

 This is a fairly precise implementation of Knuth's Algorithm D, for a
 binary computer with base b = 2**(32|64). The caller supplies:
 1. Space q for the quotient, m - n + 1 words (at least one).
 2. Space r for the remainder (optional), n words.
 3. The dividend u, m words, m >= 1.
 4. The divisor v, n words, n >= 2.
 The most significant digit of the divisor, v[n-1], must be nonzero.  The
 dividend u may have leading zeros; this just makes the algorithm take
 longer and makes the quotient contain more leading zeros.  A value of
 nullptr may be given for the address of the remainder to signify that the
 caller does not want the remainder.
 The program does not alter the input parameters u and v.
 The quotient and remainder returned may have leading zeros.  The
 function itself returns a value of 0 for success and 1 for invalid
 parameters (e.g., division by 0).
 For now, we must have m >= n.  Knuth's Algorithm D also requires
 that the dividend be at least as long as the divisor.  (In his terms,
 m >= 0 (unstated).  Therefore m+n >= n.) */

inline int nlz64(
    uint64_t x) {  // todo: needs to be flexible and select
                   // the appropriate nlz based on limb size..
  int n;

  if (x == 0) {
    return (64);
  }
  n = 0;
  if (x <= 0x000000FF) {
    n = n + 32;
    x = x << 32;
  }
  if (x <= 0x0000FFFF) {
    n = n + 16;
    x = x << 16;
  }
  if (x <= 0x00FFFFFF) {
    n = n + 8;
    x = x << 8;
  }
  if (x <= 0x0FFFFFFF) {
    n = n + 4;
    x = x << 4;
  }
  if (x <= 0x3FFFFFFF) {
    n = n + 2;
    x = x << 2;
  }
  if (x <= 0x7FFFFFFF) {
    n = n + 1;
  }
  return n;
}

inline int nlz32(uint32_t x) {  // todo: needs to be flexible.
  int n;

  if (x == 0) {
    return (32);
  }
  n = 0;
  if (x <= 0x0000FFFF) {
    n = n + 16;
    x = x << 16;
  }
  if (x <= 0x00FFFFFF) {
    n = n + 8;
    x = x << 8;
  }
  if (x <= 0x0FFFFFFF) {
    n = n + 4;
    x = x << 4;
  }
  if (x <= 0x3FFFFFFF) {
    n = n + 2;
    x = x << 2;
  }
  if (x <= 0x7FFFFFFF) {
    n = n + 1;
  }
  return n;
}
// todo figure out a C++ way to do this....
#ifdef UBINT_32  // 32  bit code
#undef nlz
#define nlz(x) nlz32(x)
#endif

#ifdef UBINT_64  // 64  bit code
#undef nlz
#define nlz(x) nlz64(x)
#endif

// returns quotient and remainder
template <typename limb_t>
int ubint<limb_t>::divqr_vect(ubint &qin, ubint &rin, const ubint &uin,
                              const ubint &vin) const {
  vector<limb_t> &q = (qin.m_value);
  vector<limb_t> &r = (rin.m_value);
  const vector<limb_t> &u = (uin.m_value);
  const vector<limb_t> &v = (vin.m_value);

  int m = u.size();
  int n = v.size();

  q.resize(m - n + 1);

  const Dlimb_t ffs = (Dlimb_t)m_MaxLimb;    // Number  (2**64)-1.
  const Dlimb_t b = (Dlimb_t)m_MaxLimb + 1;  // Number base (2**64).

  Dlimb_t qhat;  // Estimated quotient digit.
  Dlimb_t rhat;  // A remainder.64
  Dlimb_t p;     // Product of two digits.
  Sdlimb_t t, k;
  int s, i, j;

  if (m < n || n <= 0 || v[n - 1] == 0) {
    std::cout << "Error in divqr_vect m, n, v[n-1] " << m << ", " << n << ", "
              << v[n - 1] << std::endl;
    return 1;  // Return if invalid param.
  }
  if (n == 1) {                      // Take care of
    k = 0;                           // the case of a
    for (j = m - 1; j >= 0; j--) {   // single-digit
      q[j] = (k * b + u[j]) / v[0];  // divisor here.
      k = (k * b + u[j]) - q[j] * v[0];
    }
    if (r.size() != 0) {
      r[0] = k;
    }
    return 0;
  }

  /* Normalize by shifting v left just enough so that its high-order
   bit is on, and shift u left the same amount. We may have to append a
   high-order digit on the dividend; we do that unconditionally. */

  s = nlz(v[n - 1]);  // 0 <= s <= m_limbBitLenghth-1.
  // std::cout<< "nlz of " << v[n-1]  << " = "<<  s;
  // vn = (limb_t *)alloca(4*n);
  vector<limb_t> vn(n);
  for (i = n - 1; i > 0; i--) {
    vn[i] = (v[i] << s) | ((Dlimb_t)v[i - 1] >> (m_limbBitLength - s));
  }
  vn[0] = v[0] << s;

  // un = (limb_t *)alloca(4*(m + 1));
  vector<limb_t> un(m + 1);

  un[m] = (Dlimb_t)u[m - 1] >> (m_limbBitLength - s);
  for (i = m - 1; i > 0; i--) {
    un[i] = (u[i] << s) | ((Dlimb_t)u[i - 1] >> (m_limbBitLength - s));
  }
  un[0] = u[0] << s;

  for (j = m - n; j >= 0; j--) {  // Main loop.
    // Compute estimate qhat of q[j].
    qhat = (un[j + n] * b + un[j + n - 1]) / vn[n - 1];
    rhat = (un[j + n] * b + un[j + n - 1]) - qhat * vn[n - 1];
  again:
    if (qhat >= b || qhat * vn[n - 2] > b * rhat + un[j + n - 2]) {
      qhat = qhat - 1;
      rhat = rhat + vn[n - 1];
      if (rhat < b) {
        goto again;
      }
    }

    // Multiply and subtract.
    k = 0;
    for (i = 0; i < n; i++) {
      p = qhat * vn[i];
      // t = un[i+j] - k - (p & 0xFFFFFFFFLL);
      // t = un[i+j] - k - (p & 0xFFFFFFFFFFFFFFFFLL);
      t = un[i + j] - k - (p & ffs);
      un[i + j] = t;
      k = (p >> m_limbBitLength) - (t >> m_limbBitLength);
    }
    t = un[j + n] - k;
    un[j + n] = t;

    q[j] = qhat;        // Store quotient digit.
    if (t < 0) {        // If we subtracted too
      q[j] = q[j] - 1;  // much, add back.
      k = 0;
      for (i = 0; i < n; i++) {
        t = (Dlimb_t)un[i + j] + vn[i] + k;
        un[i + j] = t;
        k = t >> m_limbBitLength;
      }
      un[j + n] = un[j + n] + k;
    }
  }  // End j.
     // the caller wants the remainder, unnormalize
     // it and pass it back.
  r.resize(n);
  for (i = 0; i < n - 1; i++) {
    r[i] = (un[i] >> s) | ((Dlimb_t)un[i + 1] << (m_limbBitLength - s));
  }
  r[n - 1] = un[n - 1] >> s;
  return 0;
}

// quotient only
template <typename limb_t>
int ubint<limb_t>::divq_vect(ubint &qin, const ubint &uin,
                             const ubint &vin) const {
  vector<limb_t> &q = (qin.m_value);
  const vector<limb_t> &u = (uin.m_value);
  const vector<limb_t> &v = (vin.m_value);

  int m = u.size();
  int n = v.size();

  q.resize(m - n + 1);

  const Dlimb_t ffs = (Dlimb_t)m_MaxLimb;    // Number  (2**64)-1.
  const Dlimb_t b = (Dlimb_t)m_MaxLimb + 1;  // Number base (2**64).

  Dlimb_t qhat;  // Estimated quotient digit.
  Dlimb_t rhat;  // A remainder.64
  Dlimb_t p;     // Product of two digits.
  Sdlimb_t t, k;
  int s, i, j;

  if (m < n || n <= 0 || v[n - 1] == 0) {
    std::cout << "Error in divq_vect m, n, v[n-1] " << m << ", " << n << ", "
              << v[n - 1] << std::endl;
    return 1;  // Return if invalid param.
  }
  if (n == 1) {                      // Take care of
    k = 0;                           // the case of a
    for (j = m - 1; j >= 0; j--) {   // single-digit
      q[j] = (k * b + u[j]) / v[0];  // divisor here.
      k = (k * b + u[j]) - q[j] * v[0];
    }
    return 0;
  }

  /* Normalize by shifting v left just enough so that its high-order
   bit is on, and shift u left the same amount. We may have to append a
   high-order digit on the dividend; we do that unconditionally. */

  s = nlz(v[n - 1]);  // 0 <= s <= m_limbBitLenghth-1.
  // std::cout<< "nlz of " << v[n-1]  << " = "<<  s;
  // vn = (limb_t *)alloca(4*n);
  vector<limb_t> vn(n);
  for (i = n - 1; i > 0; i--) {
    vn[i] = (v[i] << s) | ((Dlimb_t)v[i - 1] >> (m_limbBitLength - s));
  }
  vn[0] = v[0] << s;

  // un = (limb_t *)alloca(4*(m + 1));
  vector<limb_t> un(m + 1);

  un[m] = (Dlimb_t)u[m - 1] >> (m_limbBitLength - s);
  for (i = m - 1; i > 0; i--) {
    un[i] = (u[i] << s) | ((Dlimb_t)u[i - 1] >> (m_limbBitLength - s));
  }
  un[0] = u[0] << s;

  for (j = m - n; j >= 0; j--) {  // Main loop.
    // Compute estimate qhat of q[j].
    qhat = (un[j + n] * b + un[j + n - 1]) / vn[n - 1];
    rhat = (un[j + n] * b + un[j + n - 1]) - qhat * vn[n - 1];
  again:
    if (qhat >= b || qhat * vn[n - 2] > b * rhat + un[j + n - 2]) {
      qhat = qhat - 1;
      rhat = rhat + vn[n - 1];
      if (rhat < b) {
        goto again;
      }
    }

    // Multiply and subtract.
    k = 0;
    for (i = 0; i < n; i++) {
      p = qhat * vn[i];
      // t = un[i+j] - k - (p & 0xFFFFFFFFLL);
      // t = un[i+j] - k - (p & 0xFFFFFFFFFFFFFFFFLL);
      t = un[i + j] - k - (p & ffs);
      un[i + j] = t;
      k = (p >> m_limbBitLength) - (t >> m_limbBitLength);
    }
    t = un[j + n] - k;
    un[j + n] = t;

    q[j] = qhat;        // Store quotient digit.
    if (t < 0) {        // If we subtracted too
      q[j] = q[j] - 1;  // much, add back.
      k = 0;
      for (i = 0; i < n; i++) {
        t = (Dlimb_t)un[i + j] + vn[i] + k;
        un[i + j] = t;
        k = t >> m_limbBitLength;
      }
      un[j + n] = un[j + n] + k;
    }
  }  // End j.
  return 0;
}
///////
// remainder only
template <typename limb_t>
int ubint<limb_t>::divr_vect(ubint &rin, const ubint &uin,
                             const ubint &vin) const {
#ifdef OLD_DIV
  vector<limb_t> &r = (rin.m_value);
  const vector<limb_t> &u = (uin.m_value);
  const vector<limb_t> &v = (vin.m_value);

  int m = u.size();
  int n = v.size();
#else
  vector<limb_t> &r = (rin.m_value);
  limb_t const *u = (uin.m_value.data());
  const vector<limb_t> &v = (vin.m_value);

  int m = uin.m_value.size();
  int n = v.size();

#endif

  const Dlimb_t ffs = (Dlimb_t)m_MaxLimb;    // Number  (2**64)-1.
  const Dlimb_t b = (Dlimb_t)m_MaxLimb + 1;  // Number base (2**64).

  Dlimb_t qhat;  // Estimated quotient digit.
  Dlimb_t rhat;  // A remainder.64
  Dlimb_t p;     // Product of two digits.
  Sdlimb_t t, k;
  int s, i, j;

  if (m < n || n <= 0 || v[n - 1] == 0) {
    std::cout << "Error in divr_vect m, n, v[n-1] " << m << ", " << n << ", "
              << v[n - 1] << std::endl;
    return 1;  // Return if invalid param.
  }
  if (n == 1) {  // Take care of
    vector<limb_t> q(m - n + 1);
    // q.resize(m-n+1);

    k = 0;                           // the case of a
    for (j = m - 1; j >= 0; j--) {   // single-digit
      q[j] = (k * b + u[j]) / v[0];  // divisor here.
      k = (k * b + u[j]) - q[j] * v[0];
    }
    r.resize(n);
    r[0] = k;
    return 0;
  }

  /* Normalize by shifting v left just enough so that its high-order
   bit is on, and shift u left the same amount. We may have to append a
   high-order digit on the dividend; we do that unconditionally. */

  s = nlz(v[n - 1]);  // 0 <= s <= m_limbBitLenghth-1.
                      // std::cout<< "nlz of " << v[n-1]  << " = "<<  s;
#ifdef OLD_DIV
  vector<limb_t> vn(n);
  vector<limb_t> un(m + 1);
#else
  auto *vn = reinterpret_cast<limb_t *>(alloca(sizeof(limb_t) * n));
  auto *un = reinterpret_cast<limb_t *>(alloca(sizeof(limb_t) * (m + 1)));
#endif
  for (i = n - 1; i > 0; i--) {
    vn[i] = (v[i] << s) | ((Dlimb_t)v[i - 1] >> (m_limbBitLength - s));
  }
  vn[0] = v[0] << s;

  un[m] = (Dlimb_t)u[m - 1] >> (m_limbBitLength - s);
  for (i = m - 1; i > 0; i--) {
    un[i] = (u[i] << s) | ((Dlimb_t)u[i - 1] >> (m_limbBitLength - s));
  }
  un[0] = u[0] << s;

  for (j = m - n; j >= 0; j--) {  // Main loop.
    // Compute estimate qhat of q[j].
    qhat = (un[j + n] * b + un[j + n - 1]) / vn[n - 1];
    rhat = (un[j + n] * b + un[j + n - 1]) - qhat * vn[n - 1];
  again:
    if (qhat >= b || qhat * vn[n - 2] > b * rhat + un[j + n - 2]) {
      qhat = qhat - 1;
      rhat = rhat + vn[n - 1];
      if (rhat < b) {
        goto again;
      }
    }

    // Multiply and subtract.
    k = 0;
    for (i = 0; i < n; i++) {
      p = qhat * vn[i];
      // t = un[i+j] - k - (p & 0xFFFFFFFFLL);
      // t = un[i+j] - k - (p & 0xFFFFFFFFFFFFFFFFLL);
      t = un[i + j] - k - (p & ffs);
      un[i + j] = t;
      k = (p >> m_limbBitLength) - (t >> m_limbBitLength);
    }
    t = un[j + n] - k;
    un[j + n] = t;

    // q[j] = qhat;              // Store quotient digit.
    if (t < 0) {  // If we subtracted too
      // q[j] = q[j] - 1;       // much, add back.
      k = 0;
      for (i = 0; i < n; i++) {
        t = (Dlimb_t)un[i + j] + vn[i] + k;
        un[i + j] = t;
        k = t >> m_limbBitLength;
      }
      un[j + n] = un[j + n] + k;
    }
  }  // End j.

  // the caller wants the remainder, unnormalize
  // it and pass it back.
#ifdef OLD_DIV
  r.resize(n);
#endif
  for (i = 0; i < n - 1; i++) {
    r[i] = (un[i] >> s) | ((Dlimb_t)un[i + 1] << (m_limbBitLength - s));
  }
  r[n - 1] = un[n - 1] >> s;

  return 0;
}

// optimized ceiling function after division by number of bits in the limb data
// type.
template <typename limb_t>
usint ubint<limb_t>::ceilIntByUInt(const limb_t Number) {
  // mask to perform bitwise AND
  static limb_t mask = m_limbBitLength - 1;

  if (!Number) {
    return 1;
  }

  if ((Number & mask) != 0) {
    return (Number >> m_log2LimbBitLength) + 1;
  } else {
    return Number >> m_log2LimbBitLength;
  }
}

// Algoritm used is shift and add
template <typename limb_t>
limb_t ubint<limb_t>::UintInBinaryToDecimal(uschar *a) {
  limb_t Val = 0;
  limb_t one = 1;
  for (int i = m_limbBitLength - 1; i >= 0; i--) {
    Val += one * *(a + i);
    one <<= 1;
    *(a + i) = 0;
  }

  return Val;
}

//&&&

//&&&
template <typename limb_t>
void ubint<limb_t>::double_bitVal(uschar *a) {
  uschar ofl = 0;
  for (int i = m_numDigitInPrintval - 1; i > -1; i--) {
    *(a + i) <<= 1;
    if (*(a + i) > 9) {
      *(a + i) = *(a + i) - 10 + ofl;
      ofl = 1;
    } else {
      *(a + i) = *(a + i) + ofl;
      ofl = 0;
    }
  }
}

template <typename limb_t>
void ubint<limb_t>::add_bitVal(uschar *a, uschar b) {
  uschar ofl = 0;
  *(a + m_numDigitInPrintval - 1) += b;
  for (int i = m_numDigitInPrintval - 1; i > -1; i--) {
    *(a + i) += ofl;
    if (*(a + i) > 9) {
      *(a + i) = 0;
      ofl = 1;
    }
  }
}

// Initializes the vector of limbs from the string equivalent of ubint
// also sets MSB
// Algorithm used is repeated division by 2
// Reference:http://pctechtips.org/convert-from-decimal-to-binary-with-recursion-in-java/
template <typename limb_t>
void ubint<limb_t>::AssignVal(const std::string &vin) {
  // Todo: eliminate m_limbBitLength, make dynamic instead
  std::string v = vin;
  // strip off leading zeros from the input string
  v.erase(0, v.find_first_not_of('0'));
  // strip off leading spaces from the input string
  v.erase(0, v.find_first_not_of(' '));
  if (v.size() == 0) {
    // caustic case of input string being all zeros
    v = "0";  // set to one zero
  }

  size_t arrSize = v.length();
  // todo smartpointer
  uschar *DecValue = new uschar[arrSize];  // array of decimal values

  for (size_t i = 0; i < arrSize; i++)  // store the string to decimal array
    DecValue[i] = (uschar)stoi(v.substr(i, 1));

  // clear the current value of m_value;
  m_value.clear();

  size_t zptr = 0;
  // index of highest non-zero number in decimal number
  // define  bit register array
  uschar *bitArr = new uschar[m_limbBitLength]();  // todo smartpointer

  int cnt = m_limbBitLength - 1;
  // cnt is a pointer to the bit position in bitArr, when bitArr is compelete it
  // is ready to be transfered to Value
  while (zptr != arrSize) {
    bitArr[cnt] = DecValue[arrSize - 1] % 2;
    // start divide by 2 in the DecValue array
    for (size_t i = zptr; i < arrSize - 1; i++) {
      DecValue[i + 1] = (DecValue[i] % 2) * 10 + DecValue[i + 1];
      DecValue[i] >>= 1;
    }
    DecValue[arrSize - 1] >>= 1;
    // division ends here
    cnt--;
    if (cnt == -1) {  // cnt = -1 indicates bitArr is ready for transfer
      cnt = m_limbBitLength - 1;
      m_value.push_back(UintInBinaryToDecimal(bitArr));
    }
    if (DecValue[zptr] == 0) {
      zptr++;  // division makes Most significant digit zero, hence we increment
               // zptr to next value
    }
    if (zptr == arrSize && DecValue[arrSize - 1] == 0) {
      m_value.push_back(UintInBinaryToDecimal(bitArr));  // Value assignment
    }
  }

  m_state = INITIALIZED;
  NormalizeLimbs();  // normalize the limbs
  SetMSB();          // sets the MSB correctly

  delete[] bitArr;
  delete[] DecValue;  // deallocate memory
}

template <typename limb_t>
void ubint<limb_t>::SetMSB() {
  m_MSB = 0;
  if (this->m_state == GARBAGE) {
    PALISADE_THROW(lbcrypto::not_available_error,
                   "SetMSB() of uninitialized bint");
  }
  m_MSB = (m_value.size() - 1) *
          m_limbBitLength;  // figure out bit location of all but last limb
  m_MSB += GetMSBlimb_t(m_value.back());  // add the value of that last limb.
}

// guessIdx is the index of largest limb_t number in array.
template <typename limb_t>
void ubint<limb_t>::SetMSB(usint guessIdxChar) {
  m_MSB = (m_value.size() - guessIdxChar - 1) * m_limbBitLength;
  m_MSB += GetMSBlimb_t(m_value[guessIdxChar]);
}

// NormalizeLimbs() function
template <typename limb_t>
void ubint<limb_t>::NormalizeLimbs(void) {
  // go through the most significant limbs and pop off any zero limbs we missed
  // note, ubint = 0 must  have one limb == 0;
  for (usint i = this->m_value.size() - 1; i >= 1; i--) {
    if (!this->m_value.back()) {
      this->m_value.pop_back();
      // std::cout<<"popped "<<std::endl;
    } else {
      break;
    }
  }
  return;
}

template <typename limb_t>
uschar ubint<limb_t>::GetBitAtIndex(usint index) const {
  if (index <= 0) {
    std::cout << "Invalid index \n";
    return 0;
  } else if (index > m_MSB) {
    return 0;
  }
  limb_t result;
  // idx is the index of the character array
  int idx = ceilIntByUInt(index) - 1;
  limb_t temp = this->m_value[idx];
  // bmask is the bit number in the 8 bit array
  limb_t bmask_counter =
      index % m_limbBitLength == 0 ? m_limbBitLength : index % m_limbBitLength;
  limb_t bmask = 1;
  for (size_t i = 1; i < bmask_counter; i++) {
    bmask <<= 1;  // generate the bitmask number
  }
  result = temp & bmask;         // finds the bit in  bit format
  result >>= bmask_counter - 1;  // shifting operation gives bit either 1 or 0
  return (uschar)result;
}

template <typename limb_t>
void ubint<limb_t>::SetIntAtIndex(usint idx, limb_t value) {
  if (idx >= m_value.size()) {
    PALISADE_THROW(lbcrypto::math_error, "Index Invalid");
  }
  this->m_value[idx] = value;
}

/* method to print out compiler constants */
template <typename limb_t>
void ubint<limb_t>::PrintIntegerConstants(void) {
  std::cout << "sizeof UINT8_C " << sizeof(UINT8_C(1)) << std::endl;
  std::cout << "sizeof UINT16_C " << sizeof(UINT16_C(1)) << std::endl;
  std::cout << "sizeof UINT32_C " << sizeof(UINT32_C(1)) << std::endl;
  std::cout << "sizeof UINT64_C " << sizeof(UINT64_C(1)) << std::endl;

  std::cout << "sizeof uint8_t " << sizeof(uint8_t) << std::endl;
  std::cout << "sizeof uint16_t " << sizeof(uint16_t) << std::endl;
  std::cout << "sizeof uint32_t " << sizeof(uint32_t) << std::endl;
  std::cout << "sizeof uint64_t " << sizeof(uint64_t) << std::endl;
#ifdef UBINT_64
  // std::cout << "sizeof UINT128_C "<< sizeof (UINT128_C(1)) << std::endl;
  // dbc commented out  unsupported on some machines
  std::cout << "sizeof uint128_t " << sizeof(uint128_t) << std::endl;
#endif
}

template class ubint<expdtype>;

#if 0
// to stream internal representation
template std::ostream &operator<<<expdtype>(std::ostream &os,
                                            const std::vector<expdtype> &v);
#endif
}  // namespace bigintdyn
