// @file mubintvecnat.cpp This code provides basic arithmetic functionality for
// vectors of native integers.
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

#include "math/backend.h"
#include "math/bigintnat/mubintvecnat.h"
#include "math/nbtheory.h"
#include "utils/debug.h"
#include "utils/serializable.h"

#ifdef WITH_INTEL_HEXL
#include "hexl/hexl.hpp"
#endif

namespace bigintnat {

// CONSTRUCTORS

template <class IntegerType>
NativeVector<IntegerType>::NativeVector() {}

template <class IntegerType>
NativeVector<IntegerType>::NativeVector(usint length) {
  this->m_data.resize(length);
}

template <class IntegerType>
NativeVector<IntegerType>::NativeVector(usint length,
                                        const IntegerType &modulus) {
  if (modulus.GetMSB() > MAX_MODULUS_SIZE) {
    PALISADE_THROW(lbcrypto::not_available_error,
                   "NativeVector supports only modulus size <=  " +
                       std::to_string(MAX_MODULUS_SIZE) + " bits");
  }
  this->SetModulus(modulus);
  this->m_data.resize(length);
}

template <class IntegerType>
NativeVector<IntegerType>::NativeVector(const NativeVector &bigVector) {
  m_modulus = bigVector.m_modulus;
  m_data = bigVector.m_data;
}

template <class IntegerType>
NativeVector<IntegerType>::NativeVector(NativeVector &&bigVector) {
  m_data = std::move(bigVector.m_data);
  m_modulus = bigVector.m_modulus;
}

template <class IntegerType>
NativeVector<IntegerType>::NativeVector(
    usint length, const IntegerType &modulus,
    std::initializer_list<std::string> rhs) {
  this->SetModulus(modulus);
  this->m_data.resize(length);
  usint len = rhs.size();
  for (usint i = 0; i < m_data.size(); i++) {  // this loops over each entry
    if (i < len) {
      m_data[i] = IntegerType(*(rhs.begin() + i)) % m_modulus;
    } else {
      m_data[i] = IntegerType(0);
    }
  }
}

template <class IntegerType>
NativeVector<IntegerType>::NativeVector(usint length,
                                        const IntegerType &modulus,
                                        std::initializer_list<uint64_t> rhs) {
  this->SetModulus(modulus);
  this->m_data.resize(length);
  usint len = rhs.size();
  for (usint i = 0; i < m_data.size(); i++) {  // this loops over each entry
    if (i < len) {
      m_data[i] = IntegerType(*(rhs.begin() + i)) % m_modulus;
    } else {
      m_data[i] = IntegerType(0);
    }
  }
}

template <class IntegerType>
NativeVector<IntegerType>::~NativeVector() {}

// ASSIGNMENT OPERATORS

template <class IntegerType>
const NativeVector<IntegerType> &NativeVector<IntegerType>::operator=(
    const NativeVector &rhs) {
  if (this != &rhs) {
    if (this->m_data.size() == rhs.m_data.size()) {
      for (usint i = 0; i < m_data.size(); i++) {
        this->m_data[i] = rhs.m_data[i];
      }
    } else {
      m_data = rhs.m_data;
    }
    m_modulus = rhs.m_modulus;
  }
  return *this;
}

template <class IntegerType>
NativeVector<IntegerType> &NativeVector<IntegerType>::operator=(
    NativeVector &&rhs) {
  if (this != &rhs) {
    m_data = std::move(rhs.m_data);
    m_modulus = rhs.m_modulus;
  }
  return *this;
}

template <class IntegerType>
const NativeVector<IntegerType> &NativeVector<IntegerType>::operator=(
    std::initializer_list<std::string> rhs) {
  usint len = rhs.size();
  for (usint i = 0; i < m_data.size(); i++) {  // this loops over each tower
    if (i < len) {
      if (m_modulus != 0) {
        m_data[i] = IntegerType(*(rhs.begin() + i)) % m_modulus;
      } else {
        m_data[i] = IntegerType(*(rhs.begin() + i));
      }
    } else {
      m_data[i] = 0;
    }
  }
  return *this;
}

template <class IntegerType>
const NativeVector<IntegerType> &NativeVector<IntegerType>::operator=(
    std::initializer_list<uint64_t> rhs) {
  usint len = rhs.size();
  for (usint i = 0; i < m_data.size(); i++) {  // this loops over each tower
    if (i < len) {
      if (m_modulus != 0) {
        m_data[i] = IntegerType(*(rhs.begin() + i)) % m_modulus;
      } else {
        m_data[i] = IntegerType(*(rhs.begin() + i));
      }
    } else {
      m_data[i] = 0;
    }
  }
  return *this;
}

// ACCESSORS

template <class IntegerType>
void NativeVector<IntegerType>::SetModulus(const IntegerType &value) {
  if (value.GetMSB() > MAX_MODULUS_SIZE) {
    PALISADE_THROW(lbcrypto::not_available_error,
                   "NativeVector supports only modulus size <=  " +
                       std::to_string(MAX_MODULUS_SIZE) + " bits");
  }
  this->m_modulus = value;
}

/**Switches the integers in the vector to values corresponding to the new
 * modulus.
 * Algorithm: Integer i, Old Modulus om, New Modulus nm,
 * delta = abs(om-nm):
 *  Case 1: om < nm
 *    if i > om/2
 *      i' = i + delta
 *  Case 2: om > nm
 *    i > om/2 i' = i-delta
 */
template <class IntegerType>
void NativeVector<IntegerType>::SwitchModulus(const IntegerType &newModulus) {
  IntegerType oldModulus(this->m_modulus);
  IntegerType oldModulusByTwo(oldModulus >> 1);
  IntegerType diff((oldModulus > newModulus) ? (oldModulus - newModulus)
                                             : (newModulus - oldModulus));

  if (newModulus > oldModulus) {
#ifdef WITH_INTEL_HEXL
    uint64_t *op1 = reinterpret_cast<uint64_t *>(&m_data[0]);
    intel::hexl::EltwiseCmpAdd(
        op1, op1, m_data.size(), intel::hexl::CMPINT::NLE,
        oldModulusByTwo.ConvertToInt(), diff.ConvertToInt());
#else
    for (usint i = 0; i < this->m_data.size(); i++) {
      IntegerType n = this->m_data[i];
      if (n > oldModulusByTwo) {
        this->m_data[i] += diff;
      }
    }
#endif
  } else {  // newModulus <= oldModulus
#ifdef WITH_INTEL_HEXL
    uint64_t *op1 = reinterpret_cast<uint64_t *>(&m_data[0]);
    intel::hexl::EltwiseCmpSubMod(
        op1, op1, m_data.size(), newModulus.ConvertToInt(),
        intel::hexl::CMPINT::NLE, oldModulusByTwo.ConvertToInt(),
        diff.ConvertToInt() % newModulus.ConvertToInt());
#else
    for (usint i = 0; i < this->m_data.size(); i++) {
      IntegerType n = this->m_data[i];
      IntegerType sub_diff = (n > oldModulusByTwo) ? diff : 0;
      this->m_data[i] = n.ModSub(sub_diff, newModulus);
    }
#endif
  }
  this->SetModulus(newModulus);
}

template <class IntegerType>
const IntegerType &NativeVector<IntegerType>::GetModulus() const {
  return this->m_modulus;
}

// MODULAR ARITHMETIC OPERATIONS

template <class IntegerType>
NativeVector<IntegerType> NativeVector<IntegerType>::Mod(
    const IntegerType &modulus) const {
  if (modulus == 2) {
    return this->ModByTwo();
  } else {
    NativeVector ans(this->GetLength(), this->GetModulus());
    IntegerType halfQ(this->GetModulus() >> 1);
    for (size_t i = 0; i < ans.GetLength(); i++) {
      if (this->m_data[i] > halfQ) {
        ans[i] = this->m_data[i].ModSub(this->GetModulus(), modulus);
      } else {
        ans[i] = this->m_data[i].Mod(modulus);
      }
    }
    return ans;
  }
}

template <class IntegerType>
const NativeVector<IntegerType> &NativeVector<IntegerType>::ModEq(
    const IntegerType &modulus) {
  if (modulus == 2) {
    return this->ModByTwoEq();
  } else {
    IntegerType halfQ(this->GetModulus() >> 1);
    for (size_t i = 0; i < this->GetLength(); i++) {
      if (this->m_data[i] > halfQ) {
        this->m_data[i].ModSubEq(this->GetModulus(), modulus);
      } else {
        this->m_data[i].ModEq(modulus);
      }
    }
    return *this;
  }
}

template <class IntegerType>
NativeVector<IntegerType> NativeVector<IntegerType>::ModAdd(
    const IntegerType &b) const {
  IntegerType modulus = this->m_modulus;
  IntegerType bLocal = b;
  NativeVector ans(*this);
  if (bLocal > m_modulus) {
    bLocal.ModEq(modulus);
  }
  for (usint i = 0; i < this->m_data.size(); i++) {
    ans.m_data[i].ModAddFastEq(bLocal, modulus);
  }
  return ans;
}

template <class IntegerType>
const NativeVector<IntegerType> &NativeVector<IntegerType>::ModAddEq(
    const IntegerType &b) {
  IntegerType modulus = this->m_modulus;
  IntegerType bLocal = b;
  if (bLocal > m_modulus) {
    bLocal.ModEq(modulus);
  }
  for (usint i = 0; i < this->m_data.size(); i++) {
    this->m_data[i].ModAddFastEq(bLocal, modulus);
  }
  return *this;
}

template <class IntegerType>
NativeVector<IntegerType> NativeVector<IntegerType>::ModAddAtIndex(
    usint i, const IntegerType &b) const {
  if (i > this->GetLength() - 1) {
    std::string errMsg =
        "ubintnat::ModAddAtIndex. Index is out of range. i = " +
        std::to_string(i);
    PALISADE_THROW(lbcrypto::math_error, errMsg);
  }
  NativeVector ans(*this);
  ans.m_data[i].ModAddEq(b, this->m_modulus);
  return ans;
}

template <class IntegerType>
const NativeVector<IntegerType> &NativeVector<IntegerType>::ModAddAtIndexEq(
    usint i, const IntegerType &b) {
  if (i > this->GetLength() - 1) {
    std::string errMsg =
        "ubintnat::ModAddAtIndex. Index is out of range. i = " +
        std::to_string(i);
    PALISADE_THROW(lbcrypto::math_error, errMsg);
  }
  this->m_data[i].ModAddEq(b, this->m_modulus);
  return *this;
}

template <class IntegerType>
NativeVector<IntegerType> NativeVector<IntegerType>::ModAdd(
    const NativeVector &b) const {
  if ((this->m_data.size() != b.m_data.size()) ||
      this->m_modulus != b.m_modulus) {
    PALISADE_THROW(
        lbcrypto::math_error,
        "ModAdd called on NativeVector's with different parameters.");
  }
  NativeVector ans(*this);
  IntegerType modulus = this->m_modulus;
  for (usint i = 0; i < ans.m_data.size(); i++) {
    ans.m_data[i].ModAddFastEq(b[i], modulus);
  }
  return ans;
}

template <class IntegerType>
const NativeVector<IntegerType> &NativeVector<IntegerType>::ModAddEq(
    const NativeVector &b) {
  if ((this->m_data.size() != b.m_data.size()) ||
      this->m_modulus != b.m_modulus) {
    PALISADE_THROW(
        lbcrypto::math_error,
        "ModAddEq called on NativeVector's with different parameters.");
  }
  IntegerType modulus = this->m_modulus;
  for (usint i = 0; i < this->m_data.size(); i++) {
    this->m_data[i].ModAddFastEq(b[i], modulus);
  }
  return *this;
}

template <class IntegerType>
NativeVector<IntegerType> NativeVector<IntegerType>::ModSub(
    const IntegerType &b) const {
  NativeVector ans(*this);
  for (usint i = 0; i < this->m_data.size(); i++) {
    ans.m_data[i].ModSubEq(b, this->m_modulus);
  }
  return ans;
}

template <class IntegerType>
const NativeVector<IntegerType> &NativeVector<IntegerType>::ModSubEq(
    const IntegerType &b) {
  for (usint i = 0; i < this->m_data.size(); i++) {
    this->m_data[i].ModSubEq(b, this->m_modulus);
  }
  return *this;
}

template <class IntegerType>
NativeVector<IntegerType> NativeVector<IntegerType>::ModSub(
    const NativeVector &b) const {
  if ((this->m_data.size() != b.m_data.size()) ||
      this->m_modulus != b.m_modulus) {
    PALISADE_THROW(
        lbcrypto::math_error,
        "ModSub called on NativeVector's with different parameters.");
  }
  NativeVector ans(*this);
  for (usint i = 0; i < ans.m_data.size(); i++) {
    ans.m_data[i].ModSubFastEq(b.m_data[i], this->m_modulus);
  }
  return ans;
}

template <class IntegerType>
const NativeVector<IntegerType> &NativeVector<IntegerType>::ModSubEq(
    const NativeVector &b) {
  if ((this->m_data.size() != b.m_data.size()) ||
      this->m_modulus != b.m_modulus) {
    PALISADE_THROW(
        lbcrypto::math_error,
        "ModSubEq called on NativeVector's with different parameters.");
  }
  for (usint i = 0; i < this->m_data.size(); i++) {
    this->m_data[i].ModSubFastEq(b.m_data[i], this->m_modulus);
  }
  return *this;
}

template <class IntegerType>
NativeVector<IntegerType> NativeVector<IntegerType>::ModMul(
    const IntegerType &b) const {
  NativeVector ans(*this);
  IntegerType modulus = this->m_modulus;
  IntegerType bLocal = b;
  if (bLocal >= modulus) {
    bLocal.ModEq(modulus);
  }
  IntegerType bPrec = bLocal.PrepModMulConst(modulus);
  for (usint i = 0; i < this->m_data.size(); i++) {
    ans.m_data[i].ModMulFastConstEq(bLocal, modulus, bPrec);
  }
  return ans;
}

template <class IntegerType>
const NativeVector<IntegerType> &NativeVector<IntegerType>::ModMulEq(
    const IntegerType &b) {
  IntegerType modulus = this->m_modulus;
  IntegerType bLocal = b;
  if (bLocal >= modulus) {
    bLocal.ModEq(modulus);
  }
  IntegerType bPrec = bLocal.PrepModMulConst(modulus);
  for (usint i = 0; i < this->m_data.size(); i++) {
    this->m_data[i].ModMulFastConstEq(bLocal, modulus, bPrec);
  }
  return *this;
}

template <class IntegerType>
NativeVector<IntegerType> NativeVector<IntegerType>::ModMul(
    const NativeVector &b) const {
  if ((this->m_data.size() != b.m_data.size()) ||
      this->m_modulus != b.m_modulus) {
    PALISADE_THROW(
        lbcrypto::math_error,
        "ModMul called on NativeVector's with different parameters.");
  }
  NativeVector ans(*this);

#ifdef WITH_INTEL_HEXL
  uint64_t *ans_data_ptr = reinterpret_cast<uint64_t *>(&ans.m_data[0]);
  const uint64_t *b_data_ptr = reinterpret_cast<const uint64_t *>(&b[0]);
  intel::hexl::EltwiseMultMod(ans_data_ptr, ans_data_ptr, b_data_ptr,
                              m_data.size(), m_modulus.ConvertToInt(), 1);
  return ans;
#endif

  IntegerType modulus = this->m_modulus;
  IntegerType mu = modulus.ComputeMu();
  for (usint i = 0; i < this->m_data.size(); i++) {
    ans.m_data[i].ModMulFastEq(b[i], modulus, mu);
  }
  return ans;
}

template <class IntegerType>
const NativeVector<IntegerType> &NativeVector<IntegerType>::ModMulEq(
    const NativeVector &b) {
  if ((this->m_data.size() != b.m_data.size()) ||
      this->m_modulus != b.m_modulus) {
    PALISADE_THROW(
        lbcrypto::math_error,
        "ModMulEq called on NativeVector's with different parameters.");
  }

#ifdef WITH_INTEL_HEXL
  uint64_t *m_data_ptr = reinterpret_cast<uint64_t *>(&m_data[0]);
  const uint64_t *b_data_ptr = reinterpret_cast<const uint64_t *>(&b[0]);
  intel::hexl::EltwiseMultMod(m_data_ptr, m_data_ptr, b_data_ptr, m_data.size(),
                              m_modulus.ConvertToInt(), 1);
  return *this;
#endif

  IntegerType modulus = this->m_modulus;
  IntegerType mu = modulus.ComputeMu();
  for (usint i = 0; i < this->m_data.size(); i++) {
    this->m_data[i].ModMulFastEq(b[i], modulus, mu);
  }
  return *this;
}

template <class IntegerType>
NativeVector<IntegerType> NativeVector<IntegerType>::ModByTwo() const {
  NativeVector ans(*this);
  ans.ModByTwoEq();
  return ans;
}

template <class IntegerType>
NativeVector<IntegerType> NativeVector<IntegerType>::ModExp(
    const IntegerType &b) const {
  NativeVector ans(*this);
  for (usint i = 0; i < this->m_data.size(); i++) {
    ans.m_data[i].ModExpEq(b, this->m_modulus);
  }
  return ans;
}

template <class IntegerType>
const NativeVector<IntegerType> &NativeVector<IntegerType>::ModExpEq(
    const IntegerType &b) {
  for (usint i = 0; i < this->m_data.size(); i++) {
    this->m_data[i].ModExpEq(b, this->m_modulus);
  }
  return *this;
}

template <class IntegerType>
NativeVector<IntegerType> NativeVector<IntegerType>::ModInverse() const {
  NativeVector ans(*this);
  for (usint i = 0; i < this->m_data.size(); i++) {
    ans.m_data[i].ModInverseEq(this->m_modulus);
  }
  return ans;
}

template <class IntegerType>
const NativeVector<IntegerType> &NativeVector<IntegerType>::ModInverseEq() {
  for (usint i = 0; i < this->m_data.size(); i++) {
    this->m_data[i].ModInverseEq(this->m_modulus);
  }
  return *this;
}

template <class IntegerType>
const NativeVector<IntegerType> &NativeVector<IntegerType>::ModByTwoEq() {
  IntegerType halfQ(this->GetModulus() >> 1);
  for (size_t i = 0; i < this->GetLength(); i++) {
    if (this->operator[](i) > halfQ) {
      if (this->m_data[i].Mod(2) == 1) {
        this->m_data[i] = IntegerType(0);
      } else {
        this->m_data[i] = 1;
      }
    } else {
      if (this->m_data[i].Mod(2) == 1) {
        this->m_data[i] = 1;
      } else {
        this->m_data[i] = IntegerType(0);
      }
    }
  }
  return *this;
}

template <class IntegerType>
NativeVector<IntegerType> NativeVector<IntegerType>::MultWithOutMod(
    const NativeVector &b) const {
  if ((this->m_data.size() != b.m_data.size()) ||
      this->m_modulus != b.m_modulus) {
    PALISADE_THROW(
        lbcrypto::math_error,
        "ModMul called on NativeVector's with different parameters.");
  }
  NativeVector ans(*this);
  for (usint i = 0; i < ans.m_data.size(); i++) {
    ans.m_data[i].MulEq(b.m_data[i]);
  }
  return ans;
}

template <class IntegerType>
NativeVector<IntegerType> NativeVector<IntegerType>::MultiplyAndRound(
    const IntegerType &p, const IntegerType &q) const {
  NativeVector ans(*this);
  IntegerType halfQ(this->m_modulus >> 1);
  for (usint i = 0; i < this->m_data.size(); i++) {
    if (ans.m_data[i] > halfQ) {
      IntegerType temp = this->m_modulus - ans.m_data[i];
      ans.m_data[i] = this->m_modulus - temp.MultiplyAndRound(p, q);
    } else {
      ans.m_data[i].MultiplyAndRoundEq(p, q);
      ans.m_data[i].ModEq(this->m_modulus);
    }
  }
  return ans;
}

template <class IntegerType>
const NativeVector<IntegerType> &NativeVector<IntegerType>::MultiplyAndRoundEq(
    const IntegerType &p, const IntegerType &q) {
  IntegerType halfQ(this->m_modulus >> 1);
  for (usint i = 0; i < this->m_data.size(); i++) {
    if (this->m_data[i] > halfQ) {
      IntegerType temp = this->m_modulus - this->m_data[i];
      this->m_data[i] = this->m_modulus - temp.MultiplyAndRound(p, q);
    } else {
      this->m_data[i].MultiplyAndRoundEq(p, q);
      this->ModEq(this->m_modulus);
    }
  }
  return *this;
}

template <class IntegerType>
NativeVector<IntegerType> NativeVector<IntegerType>::DivideAndRound(
    const IntegerType &q) const {
  NativeVector ans(*this);
  IntegerType halfQ(this->m_modulus >> 1);
  for (usint i = 0; i < this->m_data.size(); i++) {
    if (ans.m_data[i] > halfQ) {
      IntegerType temp = this->m_modulus - ans.m_data[i];
      ans.m_data[i] = this->m_modulus - temp.DivideAndRound(q);
    } else {
      ans.m_data[i].DivideAndRoundEq(q);
    }
  }
  return ans;
}

template <class IntegerType>
const NativeVector<IntegerType> &NativeVector<IntegerType>::DivideAndRoundEq(
    const IntegerType &q) {
  IntegerType halfQ(this->m_modulus >> 1);
  for (usint i = 0; i < this->m_data.size(); i++) {
    if (this->m_data[i] > halfQ) {
      IntegerType temp = this->m_modulus - this->m_data[i];
      this->m_data[i] = this->m_modulus - temp.DivideAndRound(q);
    } else {
      this->m_data[i].DivideAndRoundEq(q);
    }
  }
  return *this;
}

// OTHER FUNCTIONS

// Gets the ind
template <class IntegerType>
NativeVector<IntegerType> NativeVector<IntegerType>::GetDigitAtIndexForBase(
    usint index, usint base) const {
  NativeVector ans(*this);
  for (usint i = 0; i < this->m_data.size(); i++) {
    ans.m_data[i] =
        IntegerType(ans.m_data[i].GetDigitAtIndexForBase(index, base));
  }
  return ans;
}

template class NativeVector<NativeInteger>;

}  // namespace bigintnat
