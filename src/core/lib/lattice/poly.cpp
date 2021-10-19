// @file  poly.cpp - implementation of the integer lattice
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

#include <cmath>
#include <fstream>
#include "lattice/backend.h"

#define DEMANGLER  // used for the demangling type namefunction.

#ifdef DEMANGLER

#include <cxxabi.h>
#include <cstdlib>
#include <string>

template <typename T>
std::string type_name() {
  int status;
  std::string tname = typeid(T).name();
  char *demangled_name =
      abi::__cxa_demangle(tname.c_str(), nullptr, nullptr, &status);
  if (status == 0) {
    tname = demangled_name;
    std::free(demangled_name);
  }
  return tname;
}

#endif

namespace lbcrypto {

template <typename VecType>
PolyImpl<VecType>::PolyImpl()
    : m_values(nullptr), m_format(Format::EVALUATION) {}

template <typename VecType>
PolyImpl<VecType>::PolyImpl(const shared_ptr<PolyImpl::Params> params,
                            Format format, bool initializeElementToZero)
    : m_values(nullptr), m_format(format) {
  m_params = params;

  if (initializeElementToZero) {
    this->SetValuesToZero();
  }
}

template <typename VecType>
PolyImpl<VecType>::PolyImpl(bool initializeElementToMax,
                            const shared_ptr<PolyImpl::Params> params,
                            Format format)
    : m_values(nullptr), m_format(format) {
  m_params = params;

  if (initializeElementToMax) {
    this->SetValuesToMax();
  }
}

template <typename VecType>
PolyImpl<VecType>::PolyImpl(const DggType &dgg,
                            const shared_ptr<PolyImpl::Params> params,
                            Format format) {
  m_params = params;

  usint vectorSize = params->GetRingDimension();
  m_values = make_unique<VecType>(
      dgg.GenerateVector(vectorSize, params->GetModulus()));
  (*m_values).SetModulus(params->GetModulus());

  m_format = Format::COEFFICIENT;
  this->SetFormat(format);
}

template <typename VecType>
PolyImpl<VecType>::PolyImpl(DiscreteUniformGeneratorImpl<VecType> &dug,
                            const shared_ptr<PolyImpl::Params> params,
                            Format format) {
  m_params = params;

  usint vectorSize = params->GetRingDimension();
  dug.SetModulus(params->GetModulus());
  m_values = make_unique<VecType>(dug.GenerateVector(vectorSize));
  (*m_values).SetModulus(params->GetModulus());

  m_format = Format::COEFFICIENT;
  this->SetFormat(format);
}

template <typename VecType>
PolyImpl<VecType>::PolyImpl(const BinaryUniformGeneratorImpl<VecType> &bug,
                            const shared_ptr<PolyImpl::Params> params,
                            Format format) {
  m_params = params;

  usint vectorSize = params->GetRingDimension();
  m_values = make_unique<VecType>(
      bug.GenerateVector(vectorSize, params->GetModulus()));
  // (*m_values).SetModulus(ilParams.GetModulus());
  m_format = Format::COEFFICIENT;
  this->SetFormat(format);
}

template <typename VecType>
PolyImpl<VecType>::PolyImpl(const TernaryUniformGeneratorImpl<VecType> &tug,
                            const shared_ptr<PolyImpl::Params> params,
                            Format format, uint32_t h) {
  m_params = params;

  usint vectorSize = params->GetRingDimension();
  m_values = make_unique<VecType>(
      tug.GenerateVector(vectorSize, params->GetModulus(), h));
  (*m_values).SetModulus(params->GetModulus());

  m_format = Format::COEFFICIENT;
  this->SetFormat(format);
}

template <typename VecType>
PolyImpl<VecType>::PolyImpl(const PolyImpl &element,
                            shared_ptr<PolyImpl::Params>)
    : m_format(element.m_format), m_params(element.m_params) {
  DEBUG_FLAG(false);
  if (!IsEmpty()) {
    DEBUG("in ctor & m_values was " << *m_values);
  } else {
    DEBUG("in ctor & m_values are empty ");
  }
  if (element.m_values == nullptr) {
    DEBUG("in ctor & m_values copy nullptr ");
    m_values = nullptr;
  } else {
    m_values = make_unique<VecType>(*element.m_values);  // this is a copy
    DEBUG("in ctor & m_values now " << *m_values);
  }
}

template <typename VecType>
PolyImpl<VecType>::PolyImpl(const PolyNative &rhs, Format format) {
  m_format = rhs.GetFormat();

  m_params = std::make_shared<PolyImpl::Params>(
      rhs.GetParams()->GetCyclotomicOrder(),
      rhs.GetParams()->GetModulus().ConvertToInt(),
      rhs.GetParams()->GetRootOfUnity().ConvertToInt());

  VecType temp(m_params->GetCyclotomicOrder() / 2);
  temp.SetModulus(m_params->GetModulus());

  for (size_t i = 0; i < rhs.GetLength(); i++)
    temp[i] = (rhs.GetValues())[i].ConvertToInt();

  this->SetValues(std::move(temp), rhs.GetFormat());

  this->SetFormat(format);
}

// this is the move
template <typename VecType>
PolyImpl<VecType>::PolyImpl(PolyImpl &&element, shared_ptr<PolyImpl::Params>)
    : m_format(element.m_format), m_params(element.m_params) {
  // m_values(element.m_values) //note this becomes move below

  DEBUG_FLAG(false);
  if (!IsEmpty()) {
    DEBUG("in ctor && m_values was " << *m_values);
  } else {
    DEBUG("in ctor && m_values was empty");
  }
  if (!element.IsEmpty()) {
    m_values = std::move(element.m_values);
    DEBUG("in ctor && m_values was " << *m_values);

  } else {
    DEBUG("in ctor && m_values remains empty");
    m_values = nullptr;
  }
}

template <typename VecType>
const PolyImpl<VecType> &PolyImpl<VecType>::operator=(const PolyImpl &rhs) {
  if (this != &rhs) {
    if (m_values == nullptr && rhs.m_values != nullptr) {
      m_values = make_unique<VecType>(*rhs.m_values);
    } else if (rhs.m_values != nullptr) {
      *this->m_values = *rhs.m_values;  // this is a BBV copy
    }
    this->m_params = rhs.m_params;
    this->m_format = rhs.m_format;
  }

  return *this;
}

template <typename VecType>
const PolyImpl<VecType> &PolyImpl<VecType>::operator=(
    std::initializer_list<uint64_t> rhs) {
  static Integer ZERO(0);
  usint len = rhs.size();
  if (!IsEmpty()) {
    usint vectorLength = this->m_values->GetLength();

    for (usint j = 0; j < vectorLength; ++j) {  // loops within a tower
      if (j < len) {
        this->operator[](j) = Integer(*(rhs.begin() + j));
      } else {
        this->operator[](j) = ZERO;
      }
    }

  } else {
    VecType temp(m_params->GetCyclotomicOrder() / 2);
    temp.SetModulus(m_params->GetModulus());
    temp = rhs;
    this->SetValues(std::move(temp), m_format);
  }
  return *this;
}

template <typename VecType>
const PolyImpl<VecType> &PolyImpl<VecType>::operator=(
    std::vector<int64_t> rhs) {
  static Integer ZERO(0);
  usint len = rhs.size();
  if (!IsEmpty()) {
    usint vectorLength = this->m_values->GetLength();

    for (usint j = 0; j < vectorLength; ++j) {  // loops within a tower
      if (j < len) {
        Integer tempBI;
        uint64_t tempInteger;
        if (*(rhs.begin() + j) < 0) {
          tempInteger = -*(rhs.begin() + j);
          tempBI = m_params->GetModulus() - Integer(tempInteger);
        } else {
          tempInteger = *(rhs.begin() + j);
          tempBI = Integer(tempInteger);
        }
        operator[](j) = tempBI;
      } else {
        operator[](j) = ZERO;
      }
    }

  } else {
    usint vectorLength = m_params->GetCyclotomicOrder() / 2;
    VecType temp(vectorLength);
    temp.SetModulus(m_params->GetModulus());
    for (usint j = 0; j < vectorLength; ++j) {  // loops within a tower
      if (j < len) {
        Integer tempBI;
        uint64_t tempInteger;
        if (*(rhs.begin() + j) < 0) {
          tempInteger = -*(rhs.begin() + j);
          tempBI = m_params->GetModulus() - Integer(tempInteger);
        } else {
          tempInteger = *(rhs.begin() + j);
          tempBI = Integer(tempInteger);
        }
        temp.operator[](j) = tempBI;
      } else {
        temp.operator[](j) = ZERO;
      }
    }
    this->SetValues(std::move(temp), m_format);
  }
  m_format = Format::COEFFICIENT;
  return *this;
}

template <typename VecType>
const PolyImpl<VecType> &PolyImpl<VecType>::operator=(
    std::vector<int32_t> rhs) {
  static Integer ZERO(0);
  usint len = rhs.size();
  if (!IsEmpty()) {
    usint vectorLength = this->m_values->GetLength();

    for (usint j = 0; j < vectorLength; ++j) {  // loops within a tower
      if (j < len) {
        Integer tempBI;
        uint64_t tempInteger;
        if (*(rhs.begin() + j) < 0) {
          tempInteger = -*(rhs.begin() + j);
          tempBI = m_params->GetModulus() - Integer(tempInteger);
        } else {
          tempInteger = *(rhs.begin() + j);
          tempBI = Integer(tempInteger);
        }
        operator[](j) = tempBI;
      } else {
        operator[](j) = ZERO;
      }
    }

  } else {
    usint vectorLength = m_params->GetCyclotomicOrder() / 2;
    VecType temp(vectorLength);
    temp.SetModulus(m_params->GetModulus());
    for (usint j = 0; j < vectorLength; ++j) {  // loops within a tower
      if (j < len) {
        Integer tempBI;
        uint64_t tempInteger;
        if (*(rhs.begin() + j) < 0) {
          tempInteger = -*(rhs.begin() + j);
          tempBI = m_params->GetModulus() - Integer(tempInteger);
        } else {
          tempInteger = *(rhs.begin() + j);
          tempBI = Integer(tempInteger);
        }
        temp.operator[](j) = tempBI;
      } else {
        temp.operator[](j) = ZERO;
      }
    }
    this->SetValues(std::move(temp), m_format);
  }
  m_format = Format::COEFFICIENT;
  return *this;
}

template <typename VecType>
const PolyImpl<VecType> &PolyImpl<VecType>::operator=(
    std::initializer_list<std::string> rhs) {
  static Integer ZERO(0);
  usint len = rhs.size();
  if (!IsEmpty()) {
    usint vectorLength = this->m_values->GetLength();

    for (usint j = 0; j < vectorLength; ++j) {  // loops within a tower
      if (j < len) {
        m_values->operator[](j) = *(rhs.begin() + j);
      } else {
        m_values->operator[](j) = ZERO;
      }
    }

  } else {
    VecType temp(m_params->GetRingDimension());
    temp.SetModulus(m_params->GetModulus());
    temp = rhs;
    this->SetValues(std::move(temp), m_format);
  }
  return *this;
}

template <typename VecType>
const PolyImpl<VecType> &PolyImpl<VecType>::operator=(PolyImpl &&rhs) {
  if (this != &rhs) {
    m_values = std::move(rhs.m_values);
    m_params = rhs.m_params;
    m_format = rhs.m_format;
  }

  return *this;
}

template <typename VecType>
PolyImpl<VecType> PolyImpl<VecType>::CloneParametersOnly() const {
  PolyImpl<VecType> result(this->m_params, this->m_format);
  return result;
}

template <typename VecType>
PolyImpl<VecType> PolyImpl<VecType>::CloneWithNoise(
    const DiscreteGaussianGeneratorImpl<VecType> &dgg, Format format) const {
  PolyImpl<VecType> result(dgg, m_params, format);
  return result;
}

// If this is in Format::EVALUATION then just set all the values = val
template <typename VecType>
const PolyImpl<VecType> &PolyImpl<VecType>::operator=(uint64_t val) {
  m_format = Format::EVALUATION;
  if (m_values == nullptr) {
    m_values = make_unique<VecType>(m_params->GetRingDimension(),
                                    m_params->GetModulus());
  }
  for (size_t i = 0; i < m_values->GetLength(); ++i) {
    this->operator[](i) = Integer(val);
  }
  return *this;
}

template <typename VecType>
PolyImpl<VecType>::~PolyImpl() {}

template <typename VecType>
const VecType &PolyImpl<VecType>::GetValues() const {
  if (m_values == 0)
    PALISADE_THROW(not_available_error, "No values in PolyImpl");
  return *m_values;
}

template <typename VecType>
Format PolyImpl<VecType>::GetFormat() const {
  return m_format;
}

template <typename VecType>
typename PolyImpl<VecType>::Integer &PolyImpl<VecType>::at(usint i) {
  if (m_values == 0)
    PALISADE_THROW(not_available_error, "No values in PolyImpl");
  return m_values->at(i);
}

template <typename VecType>
const typename PolyImpl<VecType>::Integer &PolyImpl<VecType>::at(
    usint i) const {
  if (m_values == 0)
    PALISADE_THROW(not_available_error, "No values in PolyImpl");
  return m_values->at(i);
}

template <typename VecType>
typename PolyImpl<VecType>::Integer &PolyImpl<VecType>::operator[](usint i) {
  return (*m_values)[i];
}

template <typename VecType>
const typename PolyImpl<VecType>::Integer &PolyImpl<VecType>::operator[](
    usint i) const {
  return (*m_values)[i];
}

template <typename VecType>
usint PolyImpl<VecType>::GetLength() const {
  if (m_values == 0)
    PALISADE_THROW(not_available_error, "No values in PolyImpl");
  return m_values->GetLength();
}

template <typename VecType>
void PolyImpl<VecType>::SetValues(const VecType &values, Format format) {
  if (m_params->GetRootOfUnity() == Integer(0)) {
    PALISADE_THROW(type_error, "Polynomial has a 0 root of unity");
  }
  if (m_params->GetRingDimension() != values.GetLength() ||
      m_params->GetModulus() != values.GetModulus()) {
    PALISADE_THROW(type_error,
                   "Parameter mismatch on SetValues for Polynomial");
  }
  m_values = make_unique<VecType>(values);
  m_format = format;
}

template <typename VecType>
void PolyImpl<VecType>::SetValues(VecType &&values, Format format) {
  if (m_params->GetRootOfUnity() == Integer(0)) {
    PALISADE_THROW(type_error, "Polynomial has a 0 root of unity");
  }
  if (m_params->GetRingDimension() != values.GetLength() ||
      m_params->GetModulus() != values.GetModulus()) {
    PALISADE_THROW(type_error,
                   "Parameter mismatch on SetValues for Polynomial");
  }
  m_values = make_unique<VecType>(std::move(values));
  m_format = format;
}

template <typename VecType>
void PolyImpl<VecType>::SetValuesToZero() {
  m_values = make_unique<VecType>(m_params->GetRingDimension(),
                                  m_params->GetModulus());
}

template <typename VecType>
void PolyImpl<VecType>::SetValuesToMax() {
  Integer max = m_params->GetModulus() - Integer(1);
  usint size = m_params->GetRingDimension();
  m_values = make_unique<VecType>(m_params->GetRingDimension(),
                                  m_params->GetModulus());
  for (usint i = 0; i < size; i++) {
    m_values->operator[](i) = Integer(max);
  }
}

template <typename VecType>
PolyImpl<VecType> PolyImpl<VecType>::Plus(const Integer &element) const {
  PolyImpl<VecType> tmp = CloneParametersOnly();
  if (this->m_format == Format::COEFFICIENT)
    tmp.SetValues(GetValues().ModAddAtIndex(0, element), this->m_format);
  else
    tmp.SetValues(GetValues().ModAdd(element), this->m_format);
  return tmp;
}

template <typename VecType>
PolyImpl<VecType> PolyImpl<VecType>::Minus(const Integer &element) const {
  PolyImpl<VecType> tmp = CloneParametersOnly();
  tmp.SetValues(GetValues().ModSub(element), this->m_format);
  return tmp;
}

template <typename VecType>
PolyImpl<VecType> PolyImpl<VecType>::Times(const Integer &element) const {
  PolyImpl<VecType> tmp = CloneParametersOnly();
  tmp.SetValues(GetValues().ModMul(element), this->m_format);
  return tmp;
}

template <typename VecType>
PolyImpl<VecType> PolyImpl<VecType>::Times(
    bigintnat::NativeInteger::SignedNativeInt element) const {
  PolyImpl<VecType> tmp = CloneParametersOnly();
  if (element < 0) {
    Integer q = m_params->GetModulus();
    Integer elementReduced = bigintnat::NativeInteger::Integer(-element);
    if (elementReduced > q) elementReduced.ModEq(q);
    tmp.SetValues(GetValues().ModMul(q - Integer(elementReduced)),
                  this->m_format);
  } else {
    Integer q = m_params->GetModulus();
    Integer elementReduced = bigintnat::NativeInteger::Integer(element);
    if (elementReduced > q) elementReduced.ModEq(q);
    tmp.SetValues(GetValues().ModMul(Integer(elementReduced)), this->m_format);
  }
  return tmp;
}

template <typename VecType>
PolyImpl<VecType> PolyImpl<VecType>::MultiplyAndRound(const Integer &p,
                                                      const Integer &q) const {
  PolyImpl<VecType> tmp = CloneParametersOnly();
  tmp.SetValues(GetValues().MultiplyAndRound(p, q), this->m_format);
  return tmp;
}

template <typename VecType>
PolyImpl<VecType> PolyImpl<VecType>::DivideAndRound(const Integer &q) const {
  PolyImpl<VecType> tmp = CloneParametersOnly();
  tmp.SetValues(GetValues().DivideAndRound(q), this->m_format);
  return tmp;
}

template <typename VecType>
PolyImpl<VecType> PolyImpl<VecType>::Negate() const {
  //    if (m_format != Format::EVALUATION)
  //      PALISADE_THROW(not_implemented_error, "Negate for
  // PolyImpl is supported only in Format::EVALUATION format.\n");

  PolyImpl<VecType> tmp(*this);
  tmp.m_values->ModMulEq(this->m_params->GetModulus() - Integer(1));
  return tmp;
}

// VECTOR OPERATIONS

template <typename VecType>
PolyImpl<VecType> PolyImpl<VecType>::Plus(const PolyImpl &element) const {
  PolyImpl tmp = *this;
  tmp.m_values->ModAddEq(*element.m_values);
  return tmp;
}

template <typename VecType>
PolyImpl<VecType> PolyImpl<VecType>::Minus(const PolyImpl &element) const {
  PolyImpl tmp = *this;
  tmp.m_values->ModSubEq(*element.m_values);
  return tmp;
}

template <typename VecType>
PolyImpl<VecType> PolyImpl<VecType>::Times(const PolyImpl &element) const {
  if (m_format != Format::EVALUATION || element.m_format != Format::EVALUATION)
    PALISADE_THROW(not_implemented_error,
                   "operator* for PolyImpl is supported only in "
                   "Format::EVALUATION format.\n");

  if (!(*this->m_params == *element.m_params))
    PALISADE_THROW(type_error,
                   "operator* called on PolyImpl's with different params.");

  PolyImpl tmp = *this;
  tmp.m_values->ModMulEq(*element.m_values);
  return tmp;

}

// TODO: check if the parms tests here should be done in regular op as well as
// op=? or in neither place?

template <typename VecType>
const PolyImpl<VecType> &PolyImpl<VecType>::operator+=(
    const PolyImpl &element) {
  DEBUG_FLAG(false);
  if (!(*this->m_params == *element.m_params)) {
    DEBUGEXP(*this->m_params);
    DEBUGEXP(*element.m_params);
    PALISADE_THROW(type_error,
                   "operator+= called on PolyImpl's with different params.");
  }

  if (m_values == nullptr) {
    // act as tho this is 0
    m_values = make_unique<VecType>(*element.m_values);
    return *this;
  }

  m_values->ModAddEq(*element.m_values);

  return *this;
}

template <typename VecType>
const PolyImpl<VecType> &PolyImpl<VecType>::operator-=(
    const PolyImpl &element) {
  if (!(*this->m_params == *element.m_params))
    PALISADE_THROW(type_error,
                   "operator-= called on PolyImpl's with different params.");
  if (m_values == nullptr) {
    // act as tho this is 0
    m_values = make_unique<VecType>(m_params->GetRingDimension(),
                                    m_params->GetModulus());
  }
  m_values->ModSubEq(*element.m_values);
  return *this;
}

template <typename VecType>
const PolyImpl<VecType> &PolyImpl<VecType>::operator*=(
    const PolyImpl &element) {
  if (m_format != Format::EVALUATION || element.m_format != Format::EVALUATION)
    PALISADE_THROW(not_implemented_error,
                   "operator*= for PolyImpl is supported only in "
                   "Format::EVALUATION format.\n");

  if (!(*this->m_params == *element.m_params))
    PALISADE_THROW(type_error,
                   "operator*= called on PolyImpl's with different params.");

  if (m_values == nullptr) {
    // act as tho it's 0
    m_values = make_unique<VecType>(m_params->GetRingDimension(),
                                    m_params->GetModulus());
    return *this;
  }

  m_values->ModMulEq(*element.m_values);

  return *this;
}

template <typename VecType>
void PolyImpl<VecType>::AddILElementOne() {
  Integer tempValue;
  for (usint i = 0; i < m_params->GetRingDimension(); i++) {
    tempValue = GetValues().operator[](i) + Integer(1);
    tempValue = tempValue.Mod(m_params->GetModulus());
    m_values->operator[](i) = tempValue;
  }
}

template <typename VecType>
PolyImpl<VecType> PolyImpl<VecType>::AutomorphismTransform(
    const usint &k) const {
  PolyImpl result(*this);

  usint m = this->m_params->GetCyclotomicOrder();
  usint n = this->m_params->GetRingDimension();

  if (this->m_format == Format::EVALUATION) {
    if (!m_params->OrderIsPowerOfTwo()) {
      // Add a test based on the inverse totient hash table
      // if (i % 2 == 0)
      //  PALISADE_THROW(math_error, "automorphism index should be
      // odd\n");

      const auto &modulus = this->m_params->GetModulus();

      // All automorphism operations are performed for k coprime to m, which are
      // generated using GetTotientList(m)
      std::vector<usint> totientList = GetTotientList(m);

      // Temporary vector of size m is introduced
      // This step can be eliminated by using a hash table that looks up the
      // ring index (between 0 and n - 1) based on the totient index (between 0
      // and m - 1)
      VecType expanded(m, modulus);
      for (usint i = 0; i < n; i++) {
        expanded.operator[](totientList.operator[](i)) =
            m_values->operator[](i);
      }

      for (usint i = 0; i < n; i++) {
        // determines which power of primitive root unity we should switch to
        usint idx = totientList.operator[](i) * k % m;
        result.m_values->operator[](i) = expanded.operator[](idx);
      }
    } else {  // power of two cyclotomics
      if (k % 2 == 0) {
        PALISADE_THROW(math_error, "automorphism index should be odd\n");
      }
      usint logm = std::round(log2(m));
      usint logn = std::round(log2(n));
      for (usint j = 1; j < m; j += 2) {
        usint idx = (j * k) - (((j * k) >> logm) << logm);
        usint jrev = ReverseBits(j / 2, logn);
        usint idxrev = ReverseBits(idx / 2, logn);
        result.m_values->operator[](jrev) = GetValues().operator[](idxrev);
      }
    }
  } else {
    // automorphism in Format::COEFFICIENT representation
    if (!m_params->OrderIsPowerOfTwo()) {
      PALISADE_THROW(
          not_implemented_error,
          "Automorphism in Format::COEFFICIENT representation is not currently "
          "supported for non-power-of-two polynomials");
    } else {  // power of two cyclotomics
      if (k % 2 == 0) {
        PALISADE_THROW(math_error, "automorphism index should be odd\n");
      }

      for (usint j = 1; j < n; j++) {
        usint temp = j * k;
        usint newIndex = temp % n;

        if ((temp / n) % 2 == 1) {
          result.m_values->operator[](newIndex) =
              m_params->GetModulus() - m_values->operator[](j);
        } else {
          result.m_values->operator[](newIndex) = m_values->operator[](j);
        }
      }
    }
  }
  return result;
}

template <typename VecType>
PolyImpl<VecType> PolyImpl<VecType>::AutomorphismTransform(
    usint k, const std::vector<usint> &precomp) const {
  PolyImpl result(*this);
  if ((this->m_format == Format::EVALUATION)  && (m_params->OrderIsPowerOfTwo())) {
      if (k % 2 == 0) {
        PALISADE_THROW(math_error, "automorphism index should be odd\n");
      }
      usint n = this->m_params->GetRingDimension();

      for (usint j = 0; j < n; j++) {
        (*result.m_values)[j] = (*m_values)[precomp[j]];
      }

  } else {
      PALISADE_THROW(
          not_implemented_error,
          "Precomputed automorphism is implemented only for power-of-two polynomials in the EVALUATION representation");
    }
  return result;
}

template <typename VecType>
PolyImpl<VecType> PolyImpl<VecType>::Transpose() const {
  if (m_format == Format::COEFFICIENT)
    PALISADE_THROW(not_implemented_error,
                   "PolyImpl element transposition is currently implemented "
                   "only in the Format::EVALUATION representation.");

  usint m = m_params->GetCyclotomicOrder();
  return AutomorphismTransform(m - 1);
}

template <typename VecType>
PolyImpl<VecType> PolyImpl<VecType>::MultiplicativeInverse() const {
  PolyImpl tmp = CloneParametersOnly();
  if (InverseExists()) {
    tmp.SetValues(GetValues().ModInverse(), this->m_format);
    return tmp;
  }
  PALISADE_THROW(math_error, "PolyImpl has no inverse\n");
}

template <typename VecType>
PolyImpl<VecType> PolyImpl<VecType>::ModByTwo() const {
  PolyImpl tmp = CloneParametersOnly();
  tmp.SetValues(GetValues().ModByTwo(), this->m_format);
  return tmp;
}

template <typename VecType>
PolyImpl<VecType> PolyImpl<VecType>::Mod(const Integer &modulus) const {
  PolyImpl tmp = CloneParametersOnly();
  tmp.SetValues(GetValues().Mod(modulus), this->m_format);
  return tmp;
}

template <typename VecType>
void PolyImpl<VecType>::SwitchModulus(const Integer &modulus,
                                      const Integer &rootOfUnity,
                                      const Integer &modulusArb,
                                      const Integer &rootOfUnityArb) {
  if (m_values) {
    m_values->SwitchModulus(modulus);
    m_params = std::make_shared<PolyImpl::Params>(
        m_params->GetCyclotomicOrder(), modulus, rootOfUnity, modulusArb,
        rootOfUnityArb);
  }
}

template <typename VecType>
void PolyImpl<VecType>::SwitchFormat() {
  DEBUG_FLAG(false);
  if (m_values == nullptr) {
    std::string errMsg = "Poly switch format to empty values";
    PALISADE_THROW(not_available_error, errMsg);
  }

  if (m_params->OrderIsPowerOfTwo() == false) {
    ArbitrarySwitchFormat();
    return;
  }

  if (m_format == Format::COEFFICIENT) {
    m_format = Format::EVALUATION;

    DEBUG("transform to Format::EVALUATION m_values was" << *m_values);

    ChineseRemainderTransformFTT<VecType>::ForwardTransformToBitReverseInPlace(
        m_params->GetRootOfUnity(), m_params->GetCyclotomicOrder(),
        &(*m_values));
    DEBUG("m_values now in Format::COEFFICIENT " << *m_values);

  } else {
    m_format = Format::COEFFICIENT;
    DEBUG("transform to Format::COEFFICIENT m_values was" << *m_values);

    ChineseRemainderTransformFTT<VecType>::
        InverseTransformFromBitReverseInPlace(m_params->GetRootOfUnity(),
                                              m_params->GetCyclotomicOrder(),
                                              &(*m_values));
    DEBUG("m_values now in Format::EVALUATION " << *m_values);
  }
}

template <typename VecType>
void PolyImpl<VecType>::ArbitrarySwitchFormat() {
  DEBUG_FLAG(false);
  if (m_values == nullptr) {
    std::string errMsg = "Poly switch format to empty values";
    PALISADE_THROW(not_available_error, errMsg);
  }

  if (m_format == Format::COEFFICIENT) {
    m_format = Format::EVALUATION;
    // todo:: does this have an extra copy?
    DEBUG("transform to Format::EVALUATION m_values was" << *m_values);

    m_values = make_unique<VecType>(
        ChineseRemainderTransformArb<VecType>::ForwardTransform(
            *m_values, m_params->GetRootOfUnity(), m_params->GetBigModulus(),
            m_params->GetBigRootOfUnity(), m_params->GetCyclotomicOrder()));
    DEBUG("m_values now " << *m_values);
  } else {
    m_format = Format::COEFFICIENT;
    DEBUG("transform to Format::COEFFICIENT m_values was" << *m_values);

    m_values = make_unique<VecType>(
        ChineseRemainderTransformArb<VecType>::InverseTransform(
            *m_values, m_params->GetRootOfUnity(), m_params->GetBigModulus(),
            m_params->GetBigRootOfUnity(), m_params->GetCyclotomicOrder()));
    DEBUG("m_values now " << *m_values);
  }
}
template <typename VecType>
std::ostream &operator<<(std::ostream &os, const PolyImpl<VecType> &p) {
  if (p.m_values != nullptr) {
    os << *(p.m_values);
    os << " mod:" << (p.m_values)->GetModulus() << std::endl;
  }
  if (p.m_params.get() != nullptr) {
    os << " rootOfUnity: " << p.GetRootOfUnity() << std::endl;
  } else {
    os << " something's odd: null m_params?!" << std::endl;
  }
  os << std::endl;
  return os;
}

template <typename VecType>
void PolyImpl<VecType>::MakeSparse(const uint32_t &wFactor) {
  Integer modTemp;
  Integer tempValue;
  if (m_values != 0) {
    for (usint i = 0; i < m_params->GetRingDimension(); i++) {
      if (i % wFactor != 0) {
        m_values->operator[](i) = Integer(0);
      }
    }
  }
}

template <typename VecType>
bool PolyImpl<VecType>::IsEmpty() const {
  if (m_values == nullptr) return true;

  return false;
}

template <typename VecType>
bool PolyImpl<VecType>::InverseExists() const {
  for (usint i = 0; i < GetValues().GetLength(); i++) {
    if (m_values->operator[](i) == Integer(0)) return false;
  }
  return true;
}

template <typename VecType>
double PolyImpl<VecType>::Norm() const {
  Integer locVal;
  Integer retVal;
  const Integer &q = m_params->GetModulus();
  const Integer &half = m_params->GetModulus() >> 1;

  for (usint i = 0; i < GetValues().GetLength(); i++) {
    if (m_values->operator[](i) > half)
      locVal = q - (*m_values)[i];
    else
      locVal = m_values->operator[](i);

    if (locVal > retVal) retVal = locVal;
  }

  return retVal.ConvertToDouble();
}

// Write vector x(current value of the PolyImpl object) as \sum\limits{ i = 0
// }^{\lfloor{ \log q / base } \rfloor} {(base^i u_i)} and return the vector of{
// u_0, u_1,...,u_{ \lfloor{ \log q / base } \rfloor } } \in R_base^{ \lceil{
// \log q / base } \rceil }; used as a subroutine in the relinearization
// procedure baseBits is the number of bits in the base, i.e., base = 2^baseBits

template <typename VecType>
std::vector<PolyImpl<VecType>> PolyImpl<VecType>::BaseDecompose(
    usint baseBits, bool evalModeAnswer) const {
  DEBUG_FLAG(false);

  DEBUG("PolyImpl::BaseDecompose");
  usint nBits = m_params->GetModulus().GetLengthForBase(2);

  usint nWindows = nBits / baseBits;
  if (nBits % baseBits > 0) nWindows++;

  PolyImpl<VecType> xDigit(m_params);

  std::vector<PolyImpl<VecType>> result;
  result.reserve(nWindows);

  // convert the polynomial to Format::COEFFICIENT representation
  PolyImpl<VecType> x(*this);
  x.SetFormat(Format::COEFFICIENT);

  DEBUG("<x>");
  // for( auto i : x ){
  DEBUG(x);
  //}
  DEBUG("</x>");

  // TP: x is same for BACKEND 2 and 6

  for (usint i = 0; i < nWindows; ++i) {
    DEBUG("VecType is '" << type_name<VecType>() << "'");

    xDigit.SetValues(x.GetValues().GetDigitAtIndexForBase(i + 1, 1 << baseBits),
                     x.GetFormat());
    DEBUG("x.GetValue().GetDigitAtIndexForBase(i="
          << i << ")" << std::endl
          << x.GetValues().GetDigitAtIndexForBase(i * baseBits + 1,
                                                  1 << baseBits));
    DEBUG("x.GetFormat()" << x.GetFormat());
    // TP: xDigit is all zeros for BACKEND=6, but not for BACKEND-2
    // *********************************************************
    DEBUG("<xDigit." << i << ">" << std::endl
                     << xDigit << "</xDigit." << i << ">");
    if (evalModeAnswer) xDigit.SwitchFormat();
    result.push_back(xDigit);
    DEBUG("<xDigit.SwitchFormat." << i << ">" << std::endl
                                  << xDigit << "</xDigit.SwitchFormat." << i
                                  << ">");
  }

#if !defined(NDEBUG)
  DEBUG("<result>");
  for (auto i : result) {
    DEBUG(i);
  }
#endif
  DEBUG("</result>");

  return result;
}

// Generate a vector of PolyImpl's as {x, base*x, base^2*x, ..., base^{\lfloor
// {\log q/base} \rfloor}*x, where x is the current PolyImpl object; used as a
// subroutine in the relinearization procedure to get powers of a certain "base"
// for the secret key element baseBits is the number of bits in the base, i.e.,
// base = 2^baseBits

template <typename VecType>
std::vector<PolyImpl<VecType>> PolyImpl<VecType>::PowersOfBase(
    usint baseBits) const {
  static Integer TWO(2);
  std::vector<PolyImpl<VecType>> result;

  usint nBits = m_params->GetModulus().GetLengthForBase(2);

  usint nWindows = nBits / baseBits;
  if (nBits % baseBits > 0) nWindows++;

  result.reserve(nWindows);

  for (usint i = 0; i < nWindows; ++i) {
    Integer pI(TWO.ModExp(Integer(i * baseBits), m_params->GetModulus()));
    result.push_back(pI * (*this));
  }

  return result;
}

template <typename VecType>
typename PolyImpl<VecType>::PolyNative
PolyImpl<VecType>::DecryptionCRTInterpolate(PlaintextModulus ptm) const {
  auto smaller = this->Mod(ptm);

  typename PolyImpl<VecType>::PolyNative interp(
      std::make_shared<ILNativeParams>(this->GetCyclotomicOrder(), ptm, 1),
      this->GetFormat(), true);

  for (usint i = 0; i < smaller.GetLength(); i++) {
    interp[i] = smaller[i].ConvertToInt();
  }

  return interp;
}

}  // namespace lbcrypto
