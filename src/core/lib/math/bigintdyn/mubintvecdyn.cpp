// @file This file contains the cpp implementation of  mubintvec, a <vector> of
// ubint, with associated math operators.
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

#include <chrono>

#include "math/backend.h"
#include "time.h"
#include "utils/debug.h"
#include "utils/serializable.h"

namespace bigintdyn {

// CONSTRUCTORS

// basic constructor
template <class ubint_el_t>
mubintvec<ubint_el_t>::mubintvec() {
  this->m_modulus = 0;
  m_modulus_state = GARBAGE;
}

// Basic constructor for specifying the length of the vector.
template <class ubint_el_t>
mubintvec<ubint_el_t>::mubintvec(const usint length) {
  this->m_data.resize(length);
  for (usint i = 0; i < length; i++) {
    this->m_data[i] = 0;
  }
  m_modulus = 0;
  m_modulus_state = GARBAGE;
}

// Basic constructor for specifying the length of the vector and modulus.
template <class ubint_el_t>
mubintvec<ubint_el_t>::mubintvec(const usint length, const usint &modulus) {
  this->m_data.resize(length);
  for (usint i = 0; i < length; i++) {
    this->m_data[i] = 0;
  }
  m_modulus = modulus;
  m_modulus_state = INITIALIZED;
  *this = this->Mod(ubint_el_t(modulus));
}

// Basic constructor for specifying the length of the vector and modulus.
template <class ubint_el_t>
mubintvec<ubint_el_t>::mubintvec(const usint length,
                                 const ubint_el_t &modulus) {
  this->m_data.resize(length);
  for (usint i = 0; i < length; i++) {
    this->m_data[i] = 0;
  }
  m_modulus = modulus;
  m_modulus_state = INITIALIZED;
  *this = this->Mod(modulus);
}

// Baspic constructor for specifying the length of the vector and modulus.
template <class ubint_el_t>
mubintvec<ubint_el_t>::mubintvec(const usint length,
                                 const std::string &modulus) {
  this->m_data.resize(length);
  for (usint i = 0; i < length; i++) {
    this->m_data[i] = 0;
  }
  m_modulus = modulus;
  m_modulus_state = INITIALIZED;
}

// copy constructor
template <class ubint_el_t>
mubintvec<ubint_el_t>::mubintvec(const mubintvec &in_bintvec) {
  size_t length = in_bintvec.m_data.size();
  this->m_data.resize(length);
  for (size_t i = 0; i < length; i++) {
    this->m_data[i] = in_bintvec.m_data[i];
  }
  m_modulus = in_bintvec.m_modulus;
  m_modulus_state = INITIALIZED;
}

template <class ubint_el_t>
mubintvec<ubint_el_t>::mubintvec(mubintvec &&in_bintvec) {
  this->m_data = std::move(in_bintvec.m_data);
  this->m_modulus = std::move(in_bintvec.m_modulus);
  this->m_modulus_state = std::move(in_bintvec.m_modulus_state);
}

template <class ubint_el_t>
mubintvec<ubint_el_t>::mubintvec(const usint length, const ubint_el_t &modulus,
                                 std::initializer_list<std::string> rhs) {
  this->m_data.resize(length);
  m_modulus = modulus;
  m_modulus_state = INITIALIZED;
  usint len = rhs.size();
  for (usint i = 0; i < length; i++) {  // this loops over each entry
    if (i < len) {
      this->m_data[i] = ubint_el_t(*(rhs.begin() + i)) % m_modulus;
    } else {
      this->m_data[i] = ubint_el_t(0);
    }
  }
}

template <class ubint_el_t>
mubintvec<ubint_el_t>::mubintvec(const usint length, const ubint_el_t &modulus,
                                 std::initializer_list<uint64_t> rhs) {
  this->m_data.resize(length);
  m_modulus = modulus;
  m_modulus_state = INITIALIZED;
  usint len = rhs.size();
  for (usint i = 0; i < length; i++) {  // this loops over each entry
    if (i < len) {
      this->m_data[i] = ubint_el_t(*(rhs.begin() + i)) % m_modulus;
    } else {
      this->m_data[i] = ubint_el_t(0);
    }
  }
}

// constructor specifying the mubintvec as a vector of strings and modulus
template <class ubint_el_t>
mubintvec<ubint_el_t>::mubintvec(const std::vector<std::string> &s,
                                 const ubint_el_t &modulus) {
  this->m_data.resize(s.size());
  m_modulus = ubint_el_t(modulus);
  m_modulus_state = INITIALIZED;
  for (usint i = 0; i < s.size(); i++) {
    this->m_data[i] = ubint_el_t(s[i]) % m_modulus;
  }
}

// constructor specifying the mubintvec as a vector of strings with string
// modulus
template <class ubint_el_t>
mubintvec<ubint_el_t>::mubintvec(const std::vector<std::string> &s,
                                 const std::string &modulus) {
  this->m_data.resize(s.size());
  m_modulus = ubint_el_t(modulus);
  m_modulus_state = INITIALIZED;

  for (usint i = 0; i < s.size(); i++) {
    this->m_data[i] = ubint_el_t(s[i]) % m_modulus;
  }
}

// desctructor
template <class ubint_el_t>
mubintvec<ubint_el_t>::~mubintvec() {
  this->m_data.clear();
}

// ASSIGNMENT OPERATORS

// if two vectors are different sized, then it will resize target vector
// will overwrite target modulus
template <class ubint_el_t>
const mubintvec<ubint_el_t> &mubintvec<ubint_el_t>::operator=(
    const mubintvec &rhs) {
  if (this != &rhs) {
    if (this->m_data.size() == rhs.m_data.size()) {
      for (usint i = 0; i < this->m_data.size(); i++) {
        this->m_data[i] = rhs.m_data[i];
      }
    } else {
      this->m_data.resize(rhs.m_data.size());
      for (usint i = 0; i < this->m_data.size(); i++) {
        this->m_data[i] = rhs.m_data[i];
      }
    }
    this->m_modulus = rhs.m_modulus;
    this->m_modulus_state = rhs.m_modulus_state;
  }
  return *this;
}

// move copy allocator
template <class ubint_el_t>
const mubintvec<ubint_el_t> &mubintvec<ubint_el_t>::operator=(mubintvec &&rhs) {
  if (this != &rhs) {
    this->m_data.swap(rhs.m_data);  // swap the two vector contents,
    if (rhs.m_data.size() > 0) {
      rhs.m_data.clear();
    }
    this->m_modulus = rhs.m_modulus;
    this->m_modulus_state = rhs.m_modulus_state;
  }
  return *this;
}

// Assignment with initializer list of strings
template <class ubint_el_t>
const mubintvec<ubint_el_t> &mubintvec<ubint_el_t>::operator=(
    std::initializer_list<std::string> rhs) {
  size_t len = rhs.size();
  if (this->m_data.size() < len) {
    this->m_data.resize(len);
  }
  for (usint i = 0; i < this->m_data.size();
       i++) {  // this loops over each entry
    if (i < len) {
      this->m_data[i] = ubint_el_t(*(rhs.begin() + i));
    } else {
      this->m_data[i] = 0;
    }
  }
  if (this->m_modulus_state == INITIALIZED) {
    *this = this->Mod(this->m_modulus);
  }
  return *this;
}

// Assignment with initializer list of usints
template <class ubint_el_t>
const mubintvec<ubint_el_t> &mubintvec<ubint_el_t>::operator=(
    std::initializer_list<uint64_t> rhs) {
  size_t len = rhs.size();
  if (this->m_data.size() < len) {
    this->m_data.resize(len);
  }
  for (usint i = 0; i < this->m_data.size();
       i++) {  // this loops over each entry
    if (i < len) {
      this->m_data[i] = ubint_el_t(*(rhs.begin() + i));
    } else {
      this->m_data[i] = 0;
    }
  }
  if (this->m_modulus_state == INITIALIZED) {
    *this = this->Mod(this->m_modulus);
  }
  return *this;
}

// ACCESSORS

// modulus accessors
template <class ubint_el_t>
void mubintvec<ubint_el_t>::SetModulus(const usint &value) {
  m_modulus = ubint_el_t(value);
  m_modulus_state = INITIALIZED;
}

template <class ubint_el_t>
void mubintvec<ubint_el_t>::SetModulus(const ubint_el_t &value) {
  m_modulus = value;
  m_modulus_state = INITIALIZED;
}

template <class ubint_el_t>
void mubintvec<ubint_el_t>::SetModulus(const std::string &value) {
  m_modulus = ubint_el_t(value);
  m_modulus_state = INITIALIZED;
}

template <class ubint_el_t>
void mubintvec<ubint_el_t>::SetModulus(const mubintvec &value) {
  m_modulus = ubint_el_t(value.GetModulus());
  m_modulus_state = INITIALIZED;
}

template <class ubint_el_t>
const ubint_el_t &mubintvec<ubint_el_t>::GetModulus() const {
  if (m_modulus_state != INITIALIZED) {
    PALISADE_THROW(lbcrypto::not_available_error,
                   "GetModulus() on uninitialized mubintvec");
  }
  return (m_modulus);
}

/**Switches the integers in the vector to values corresponding to the new
 * modulus Algorithm: Integer i, Old Modulus om, New Modulus nm, delta =
 * abs(om-nm): Case 1: om < nm if i > i > om/2 i' = i + delta Case 2: om > nm i
 * > om/2 i' = i-delta
 */
template <class ubint_el_t>
void mubintvec<ubint_el_t>::SwitchModulus(const ubint_el_t &newModulus) {
  ubint_el_t oldModulus(this->m_modulus);
  ubint_el_t n;
  ubint_el_t oldModulusByTwo(oldModulus >> 1);
  ubint_el_t diff((oldModulus > newModulus) ? (oldModulus - newModulus)
                                            : (newModulus - oldModulus));
  for (usint i = 0; i < this->GetLength(); i++) {
    n = this->at(i);
    if (oldModulus < newModulus) {
      if (n > oldModulusByTwo) {
        this->at(i) = n.ModAdd(diff, newModulus);
      } else {
        this->at(i) = n.Mod(newModulus);
      }
    } else {
      if (n > oldModulusByTwo) {
        this->at(i) = n.ModSub(diff, newModulus);
      } else {
        this->at(i) = n.Mod(newModulus);
      }
    }
  }
  this->SetModulus(newModulus);
}

// MODULUS ARITHMETIC OPERATIONS

template <class ubint_el_t>
mubintvec<ubint_el_t> mubintvec<ubint_el_t>::Mod(
    const ubint_el_t &modulus) const {
  mubintvec ans(*this);
  ans.ModEq(modulus);
  return ans;
}

template <class ubint_el_t>
const mubintvec<ubint_el_t> &mubintvec<ubint_el_t>::ModEq(
    const ubint_el_t &modulus) {
  if (modulus == 2) {
    return this->ModByTwoEq();
  } else {
    ubint_el_t halfQ(this->GetModulus() >> 1);
    for (usint i = 0; i < this->m_data.size(); i++) {
      if ((*this)[i] > halfQ) {
        this->m_data[i].ModSubEq(this->GetModulus(), modulus);
      } else {
        this->m_data[i].ModEq(modulus);
      }
    }
    return *this;
  }
}

template <class ubint_el_t>
mubintvec<ubint_el_t> mubintvec<ubint_el_t>::ModAdd(const ubint_el_t &b) const {
  mubintvec ans(*this);
  for (usint i = 0; i < this->m_data.size(); i++) {
    ans.m_data[i].ModAddEq(b, ans.m_modulus);
  }
  return ans;
}

// method to add scalar to vector
template <class ubint_el_t>
const mubintvec<ubint_el_t> &mubintvec<ubint_el_t>::ModAddEq(
    const ubint_el_t &b) {
  for (usint i = 0; i < this->m_data.size(); i++) {
    this->m_data[i].ModAddEq(b, this->m_modulus);
  }
  return *this;
}

template <class ubint_el_t>
mubintvec<ubint_el_t> mubintvec<ubint_el_t>::ModAddAtIndex(
    usint i, const ubint_el_t &b) const {
  if (i > this->GetLength() - 1) {
    std::string errMsg =
        "mubintvec::ModAddAtIndex. Index is out of range. i = " +
        std::to_string(i);
    PALISADE_THROW(lbcrypto::math_error, errMsg);
  }
  mubintvec ans(*this);
  ans.m_data[i].ModAddEq(b, this->m_modulus);
  return ans;
}

template <class ubint_el_t>
const mubintvec<ubint_el_t> &mubintvec<ubint_el_t>::ModAddAtIndexEq(
    usint i, const ubint_el_t &b) {
  if (i > this->GetLength() - 1) {
    std::string errMsg =
        "mubintvec::ModAddAtIndex. Index is out of range. i = " +
        std::to_string(i);
    PALISADE_THROW(lbcrypto::math_error, errMsg);
  }
  this->m_data[i].ModAddEq(b, this->m_modulus);
  return *this;
}

template <class ubint_el_t>
mubintvec<ubint_el_t> mubintvec<ubint_el_t>::ModAdd(const mubintvec &b) const {
  mubintvec ans(*this);
  ans.ModAddEq(b);
  return ans;
}

template <class ubint_el_t>
const mubintvec<ubint_el_t> &mubintvec<ubint_el_t>::ModAddEq(
    const mubintvec &b) {
  if (this->m_modulus != b.m_modulus) {
    PALISADE_THROW(lbcrypto::math_error,
                   "mubintvec adding vectors of different moduli");
  } else if (this->m_data.size() != b.m_data.size()) {
    PALISADE_THROW(lbcrypto::math_error,
                   "mubintvec adding vectors of different lengths");
  } else {
    for (usint i = 0; i < this->m_data.size(); i++) {
      this->m_data[i].ModAddEq(b.m_data[i], this->m_modulus);
    }
    return *this;
  }
}

template <class ubint_el_t>
mubintvec<ubint_el_t> mubintvec<ubint_el_t>::ModSub(const ubint_el_t &b) const {
  mubintvec ans(*this);
  ans.ModSubEq(b);
  return ans;
}

template <class ubint_el_t>
const mubintvec<ubint_el_t> &mubintvec<ubint_el_t>::ModSubEq(
    const ubint_el_t &b) {
  for (usint i = 0; i < this->m_data.size(); i++) {
    this->m_data[i].ModSubEq(b, this->m_modulus);
  }
  return *this;
}

template <class ubint_el_t>
mubintvec<ubint_el_t> mubintvec<ubint_el_t>::ModSub(const mubintvec &b) const {
  mubintvec ans(*this);
  ans.ModSubEq(b);
  return ans;
}

template <class ubint_el_t>
const mubintvec<ubint_el_t> &mubintvec<ubint_el_t>::ModSubEq(
    const mubintvec &b) {
  if (this->m_modulus != b.m_modulus) {
    PALISADE_THROW(lbcrypto::math_error,
                   "mubintvec subtracting vectors of different moduli");
  } else if (this->m_data.size() != b.m_data.size()) {
    PALISADE_THROW(lbcrypto::math_error,
                   "mubintvec subtracting vectors of different lengths");
  } else {
    for (usint i = 0; i < this->m_data.size(); i++) {
      this->m_data[i].ModSubEq(b.m_data[i], this->m_modulus);
    }
    return *this;
  }
}

// method to multiply vector by scalar
template <class ubint_el_t>
mubintvec<ubint_el_t> mubintvec<ubint_el_t>::ModMul(const ubint_el_t &b) const {
#ifdef NO_BARRETT  // non barrett way
  mubintvec ans(*this);
  for (usint i = 0; i < this->m_data.size(); i++) {
    ans.m_data[i].ModMulEq(b, ans.m_modulus);
  }
  return ans;
#else
  mubintvec ans(*this);
  // Precompute the Barrett mu parameter
  ubint_el_t temp(ubint_el_t::ONE);
  temp <<= 2 * this->GetModulus().GetMSB() + 3;
  ubint_el_t mu = temp.DividedBy(m_modulus);
  // Precompute the Barrett mu values
  /*ubint temp;
  uschar gamma;
  uschar modulusLength = this->GetModulus().GetMSB() ;
  ubint mu_arr[BARRETT_LEVELS+1];
  for(usint i=0;i<BARRETT_LEVELS+1;i++) {
          temp = ubint::ONE;
          gamma = modulusLength*i/BARRETT_LEVELS;
          temp<<=modulusLength+gamma+3;
          mu_arr[i] = temp.DividedBy(this->GetModulus());
  }*/
  for (usint i = 0; i < this->m_data.size(); i++) {
    ans.m_data[i].ModMulEq(b, this->m_modulus, mu);
  }
  return ans;
#endif
}

template <class ubint_el_t>
const mubintvec<ubint_el_t> &mubintvec<ubint_el_t>::ModMulEq(
    const ubint_el_t &b) {
  for (usint i = 0; i < this->m_data.size(); i++) {
    this->m_data[i].ModMulEq(b, this->m_modulus);
  }
  return *this;
}

template <class ubint_el_t>
mubintvec<ubint_el_t> mubintvec<ubint_el_t>::ModMul(const mubintvec &b) const {
#ifdef NO_BARRETT
  mubintvec ans(*this);
  if (this->m_modulus != b.m_modulus) {
    PALISADE_THROW(lbcrypto::math_error,
                   "mubintvec multiplying vectors of different moduli");
  } else if (this->m_data.size() != b.m_data.size()) {
    PALISADE_THROW(lbcrypto::math_error,
                   "mubintvec multiplying vectors of different lengths");
  } else {
    for (usint i = 0; i < ans.m_data.size(); i++) {
      ans.m_data[i].ModMulEq(b.m_data[i], ans.m_modulus);
    }
    return ans;
  }
#else  // bartett way
  if ((this->m_data.size() != b.m_data.size()) ||
      this->m_modulus != b.m_modulus) {
    PALISADE_THROW(lbcrypto::math_error,
                   "ModMul called on mubintvecs with different parameters.");
  }

  mubintvec ans(*this);

  // Precompute the Barrett mu parameter
  ubint_el_t temp(ubint_el_t::ONE);
  temp <<= 2 * this->GetModulus().GetMSB() + 3;
  ubint_el_t mu = temp.Div(this->GetModulus());

  for (usint i = 0; i < ans.m_data.size(); i++) {
    ans.m_data[i].ModMulEq(b.m_data[i], this->m_modulus, mu);
  }
  return ans;
#endif
}

template <class ubint_el_t>
const mubintvec<ubint_el_t> &mubintvec<ubint_el_t>::ModMulEq(
    const mubintvec &b) {
  if (this->m_modulus != b.m_modulus) {
    PALISADE_THROW(lbcrypto::math_error,
                   "mubintvec multiplying vectors of different moduli");
  } else if (this->m_data.size() != b.m_data.size()) {
    PALISADE_THROW(lbcrypto::math_error,
                   "mubintvec multiplying vectors of different lengths");
  } else {
    for (usint i = 0; i < this->m_data.size(); i++) {
      this->m_data[i].ModMulEq(b.m_data[i], this->m_modulus);
    }
    return *this;
  }
}

template <class ubint_el_t>
mubintvec<ubint_el_t> mubintvec<ubint_el_t>::ModExp(const ubint_el_t &b) const {
  mubintvec ans(*this);
  for (usint i = 0; i < this->m_data.size(); i++) {
    ans.m_data[i].ModExpEq(b, ans.m_modulus);
  }
  return ans;
}

template <class ubint_el_t>
const mubintvec<ubint_el_t> &mubintvec<ubint_el_t>::ModExpEq(
    const ubint_el_t &b) {
  for (usint i = 0; i < this->m_data.size(); i++) {
    this->m_data[i].ModExpEq(b, this->m_modulus);
  }
  return *this;
}

template <class ubint_el_t>
mubintvec<ubint_el_t> mubintvec<ubint_el_t>::ModInverse() const {
  mubintvec ans(*this);
  for (usint i = 0; i < this->m_data.size(); i++) {
    ans.m_data[i].ModInverseEq(this->m_modulus);
  }
  return ans;
}

template <class ubint_el_t>
const mubintvec<ubint_el_t> &mubintvec<ubint_el_t>::ModInverseEq() {
  for (usint i = 0; i < this->m_data.size(); i++) {
    this->m_data[i].ModInverseEq(this->m_modulus);
  }
  return *this;
}

// method to mod by two
template <class ubint_el_t>
mubintvec<ubint_el_t> mubintvec<ubint_el_t>::ModByTwo() const {
  mubintvec ans(*this);
  ans.ModByTwoEq();
  return ans;
}

template <class ubint_el_t>
const mubintvec<ubint_el_t> &mubintvec<ubint_el_t>::ModByTwoEq() {
  ubint_el_t halfQ(this->GetModulus() >> 1);
  for (usint i = 0; i < this->GetLength(); i++) {
    if (this->operator[](i) > halfQ) {
      if (this->m_data[i].Mod(2) == 1) {
        this->m_data[i] = ubint_el_t(0);
      } else {
        this->m_data[i] = ubint_el_t(1);
      }
    } else {
      if (this->m_data[i].Mod(2) == 1) {
        this->m_data[i] = ubint_el_t(1);
      } else {
        this->operator[](i) = ubint_el_t(0);
      }
    }
  }
  return *this;
}

template <class ubint_el_t>
mubintvec<ubint_el_t> mubintvec<ubint_el_t>::MultiplyAndRound(
    const ubint_el_t &p, const ubint_el_t &q) const {
  mubintvec ans(*this);
  ubint_el_t halfQ(this->m_modulus >> 1);
  for (usint i = 0; i < this->m_data.size(); i++) {
    if (ans.m_data[i] > halfQ) {
      ubint_el_t temp = this->m_modulus - ans.m_data[i];
      ans.m_data[i] = this->m_modulus - temp.MultiplyAndRound(p, q);
    } else {
      ans.m_data[i] = ans.m_data[i].MultiplyAndRound(p, q).Mod(this->m_modulus);
    }
  }
  return ans;
}

template <class ubint_el_t>
const mubintvec<ubint_el_t> &mubintvec<ubint_el_t>::MultiplyAndRoundEq(
    const ubint_el_t &p, const ubint_el_t &q) {
  ubint_el_t halfQ(this->m_modulus >> 1);
  for (usint i = 0; i < this->m_data.size(); i++) {
    if (this->m_data[i] > halfQ) {
      ubint_el_t temp = this->m_modulus - this->m_data[i];
      this->m_data[i] = this->m_modulus - temp.MultiplyAndRound(p, q);
    } else {
      this->m_data[i].MultiplyAndRoundEq(p, q);
      this->m_data[i].ModEq(this->m_modulus);
    }
  }
  return *this;
}

template <class ubint_el_t>
mubintvec<ubint_el_t> mubintvec<ubint_el_t>::DivideAndRound(
    const ubint_el_t &q) const {
  mubintvec ans(*this);
  ubint_el_t halfQ(this->m_modulus >> 1);
  for (usint i = 0; i < this->m_data.size(); i++) {
    if (ans.m_data[i] > halfQ) {
      ubint_el_t temp = this->m_modulus - ans.m_data[i];
      ans.m_data[i] = this->m_modulus - temp.DivideAndRound(q);
    } else {
      ans.m_data[i].DivideAndRoundEq(q);
    }
  }
  return ans;
}

template <class ubint_el_t>
const mubintvec<ubint_el_t> &mubintvec<ubint_el_t>::DivideAndRoundEq(
    const ubint_el_t &q) {
  ubint_el_t halfQ(this->m_modulus >> 1);
  for (usint i = 0; i < this->m_data.size(); i++) {
    if (this->m_data[i] > halfQ) {
      ubint_el_t temp = this->m_modulus - this->m_data[i];
      this->m_data[i] = this->m_modulus - temp.DivideAndRound(q);
    } else {
      this->m_data[i].DivideAndRoundEq(q);
    }
  }
  return *this;
}

// OTHER FUNCTIONS

// Gets the ind
template <class ubint_el_t>
mubintvec<ubint_el_t> mubintvec<ubint_el_t>::GetDigitAtIndexForBase(
    usint index, usint base) const {
  mubintvec ans(*this);
  for (usint i = 0; i < this->m_data.size(); i++) {
    ans.m_data[i] =
        ubint_el_t(ans.m_data[i].GetDigitAtIndexForBase(index, base));
  }
  return ans;
}
}  // namespace bigintdyn

#ifdef UBINT_32
template class bigintdyn::mubintvec<bigintdyn::ubint<uint32_t>>;
#endif
#ifdef UBINT_64
template class bigintdyn::mubintvec<bigintdyn::ubint<uint64_t>>;
#endif
