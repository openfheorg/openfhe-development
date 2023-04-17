//==================================================================================
// BSD 2-Clause License
//
// Copyright (c) 2014-2023, NJIT, Duality Technologies Inc. and other contributors
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
  implementation of the integer lattice
 */

#ifndef LBCRYPTO_INC_LATTICE_HAL_DEFAULT_POLY_IMPL_H
#define LBCRYPTO_INC_LATTICE_HAL_DEFAULT_POLY_IMPL_H

#include "lattice/hal/default/poly.h"

#include "utils/debug.h"
#include "utils/exception.h"
#include "utils/inttypes.h"

#include <cmath>
// #include <fstream>
#include <limits>
#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace lbcrypto {

template <typename VecType>
PolyImpl<VecType>::PolyImpl() : m_format(Format::EVALUATION), m_params(nullptr), m_values(nullptr) {}

template <typename VecType>
PolyImpl<VecType>::PolyImpl(const std::shared_ptr<PolyImpl::Params>& params, Format format,
                            bool initializeElementToZero)
    : m_format(format), m_params(params), m_values(nullptr) {
    if (initializeElementToZero)
        this->SetValuesToZero();
}

template <typename VecType>
PolyImpl<VecType>::PolyImpl(bool initializeElementToMax, const std::shared_ptr<PolyImpl::Params>& params, Format format)
    : m_format(format), m_params(params), m_values(nullptr) {
    if (initializeElementToMax)
        this->SetValuesToMax();
}

template <typename VecType>
PolyImpl<VecType>::PolyImpl(const DggType& dgg, const std::shared_ptr<PolyImpl::Params>& params, Format format)
    : m_format(Format::COEFFICIENT),
      m_params(params),
      m_values(std::make_unique<VecType>(dgg.GenerateVector(params->GetRingDimension(), params->GetModulus()))) {
    this->SetFormat(format);
}

template <typename VecType>
PolyImpl<VecType>::PolyImpl(DugType& dug, const std::shared_ptr<PolyImpl::Params>& params, Format format)
    : m_format(Format::COEFFICIENT),
      m_params(params),
      m_values(std::make_unique<VecType>(dug.GenerateVector(params->GetRingDimension(), params->GetModulus()))) {
    this->SetFormat(format);
}

template <typename VecType>
PolyImpl<VecType>::PolyImpl(const BugType& bug, const std::shared_ptr<PolyImpl::Params>& params, Format format)
    : m_format(Format::COEFFICIENT),
      m_params(params),
      m_values(std::make_unique<VecType>(bug.GenerateVector(params->GetRingDimension(), params->GetModulus()))) {
    this->SetFormat(format);
}

template <typename VecType>
PolyImpl<VecType>::PolyImpl(const TugType& tug, const std::shared_ptr<PolyImpl::Params>& params, Format format,
                            uint32_t h)
    : m_format(Format::COEFFICIENT),
      m_params(params),
      m_values(std::make_unique<VecType>(tug.GenerateVector(params->GetRingDimension(), params->GetModulus(), h))) {
    this->SetFormat(format);
}

template <typename VecType>
PolyImpl<VecType>::PolyImpl(const PolyNative& rhs, Format format)
    : m_format(rhs.GetFormat()), m_params(nullptr), m_values(nullptr) {
    const auto c = rhs.GetParams()->GetCyclotomicOrder();
    const auto m = rhs.GetParams()->GetModulus().ConvertToInt();
    const auto r = rhs.GetParams()->GetRootOfUnity().ConvertToInt();
    m_params     = std::make_shared<PolyImpl::Params>(c, m, r);

    auto& v          = rhs.GetValues();
    const usint vlen = m_params->GetRingDimension();
    VecType temp(vlen);
    temp.SetModulus(m_params->GetModulus());

    for (usint i = 0; i < vlen; ++i)
        temp[i] = v[i].ConvertToInt();

    m_values = std::make_unique<VecType>(temp);
    this->SetFormat(format);
}

template <typename VecType>
PolyImpl<VecType>::PolyImpl(const PolyImpl& element)
    : m_format(element.m_format), m_params(element.m_params), m_values(nullptr) {
    if (element.m_values)
        m_values = std::make_unique<VecType>(*element.m_values);
}

template <typename VecType>
PolyImpl<VecType>::PolyImpl(PolyImpl&& element)
    : m_format(element.m_format), m_params(std::move(element.m_params)), m_values(nullptr) {
    if (element.m_values)
        m_values = std::move(element.m_values);
}

template <typename VecType>
const PolyImpl<VecType>& PolyImpl<VecType>::operator=(const PolyImpl& rhs) {
    if (this != &rhs) {
        m_format = rhs.m_format;
        m_params = rhs.m_params;
        if (m_values == nullptr && rhs.m_values != nullptr) {
            m_values = std::make_unique<VecType>(*rhs.m_values);
        }
        else if (rhs.m_values != nullptr) {
            *m_values = *rhs.m_values;  // this is a BBV copy
        }
    }
    return *this;
}

// assumes that elements in rhs less than modulus?
template <typename VecType>
const PolyImpl<VecType>& PolyImpl<VecType>::operator=(std::initializer_list<uint64_t> rhs) {
    static const Integer ZERO(0);
    const size_t llen = rhs.size();
    const size_t vlen = m_params->GetRingDimension();
    if (m_values == nullptr) {
        VecType temp(vlen);
        temp.SetModulus(m_params->GetModulus());
        this->SetValues(std::move(temp), m_format);
    }
    for (size_t j = 0; j < vlen; ++j)
        (*m_values)[j] = (j < llen) ? *(rhs.begin() + j) : ZERO;
    return *this;
}

template <typename VecType>
const PolyImpl<VecType>& PolyImpl<VecType>::operator=(const std::vector<int64_t>& rhs) {
    static const Integer ZERO(0);
    const size_t llen = rhs.size();
    const size_t vlen = m_params->GetRingDimension();
    const auto m      = m_params->GetModulus();
    if (m_values == nullptr) {
        VecType temp(vlen);
        temp.SetModulus(m_params->GetModulus());
        this->SetValues(std::move(temp), m_format);
    }
    for (size_t j = 0; j < vlen; ++j) {
        if (j < llen) {
            int64_t k      = rhs[j];
            (*m_values)[j] = (k < 0) ? m - Integer(static_cast<uint64_t>(-k)) : Integer(static_cast<uint64_t>(k));
        }
        else {
            (*m_values)[j] = ZERO;
        }
    }
    m_format = Format::COEFFICIENT;  // why?
    return *this;
}

template <typename VecType>
const PolyImpl<VecType>& PolyImpl<VecType>::operator=(const std::vector<int32_t>& rhs) {
    static const Integer ZERO(0);
    const size_t llen = rhs.size();
    const size_t vlen = m_params->GetRingDimension();
    const auto m      = m_params->GetModulus();
    if (m_values == nullptr) {
        VecType temp(vlen);
        temp.SetModulus(m_params->GetModulus());
        this->SetValues(std::move(temp), m_format);
    }
    for (size_t j = 0; j < vlen; ++j) {
        if (j < llen) {
            int32_t k      = rhs[j];
            (*m_values)[j] = (k < 0) ? m - Integer(static_cast<uint64_t>(-k)) : Integer(static_cast<uint64_t>(k));
        }
        else {
            (*m_values)[j] = ZERO;
        }
    }
    m_format = Format::COEFFICIENT;
    return *this;
}

template <typename VecType>
const PolyImpl<VecType>& PolyImpl<VecType>::operator=(std::initializer_list<std::string> rhs) {
    const size_t vlen = m_params->GetRingDimension();
    if (m_values == nullptr) {
        VecType temp(vlen);
        temp.SetModulus(m_params->GetModulus());
        this->SetValues(std::move(temp), m_format);
    }
    *m_values = rhs;
    return *this;
}

template <typename VecType>
const PolyImpl<VecType>& PolyImpl<VecType>::operator=(PolyImpl&& rhs) {
    if (this != &rhs) {
        m_format = rhs.m_format;
        m_params = std::move(rhs.m_params);
        m_values = std::move(rhs.m_values);
    }
    return *this;
}

template <typename VecType>
const PolyImpl<VecType>& PolyImpl<VecType>::operator=(uint64_t val) {
    m_format = Format::EVALUATION;  // why?
    if (m_values == nullptr) {
        auto d   = m_params->GetRingDimension();
        auto m   = m_params->GetModulus();
        m_values = std::make_unique<VecType>(d, m);
    }
    for (usint i = 0; i < m_values->GetLength(); ++i)
        (*m_values)[i] = Integer(val);
    return *this;
}

template <typename VecType>
void PolyImpl<VecType>::SetValues(const VecType& values, Format format) {
    if (m_params->GetRootOfUnity() == Integer(0))
        OPENFHE_THROW(type_error, "Polynomial has a 0 root of unity");
    if (m_params->GetRingDimension() != values.GetLength() || m_params->GetModulus() != values.GetModulus())
        OPENFHE_THROW(type_error, "Parameter mismatch on SetValues for Polynomial");
    m_format = format;
    m_values = std::make_unique<VecType>(values);
}

template <typename VecType>
void PolyImpl<VecType>::SetValues(VecType&& values, Format format) {
    if (m_params->GetRootOfUnity() == Integer(0))
        OPENFHE_THROW(type_error, "Polynomial has a 0 root of unity");
    if (m_params->GetRingDimension() != values.GetLength() || m_params->GetModulus() != values.GetModulus())
        OPENFHE_THROW(type_error, "Parameter mismatch on SetValues for Polynomial");
    m_format = format;
    m_values = std::make_unique<VecType>(std::move(values));
}

template <typename VecType>
void PolyImpl<VecType>::SetValuesToZero() {
    const auto r = m_params->GetRingDimension();
    const auto m = m_params->GetModulus();
    m_values     = std::make_unique<VecType>(r, m);
}

template <typename VecType>
void PolyImpl<VecType>::SetValuesToMax() {
    const auto max   = m_params->GetModulus() - 1;
    const usint size = m_params->GetRingDimension();
    m_values         = std::make_unique<VecType>(size, m_params->GetModulus());
    for (usint i = 0; i < size; ++i) {
        (*m_values)[i] = max;
    }
}

template <typename VecType>
PolyImpl<VecType> PolyImpl<VecType>::Plus(const typename VecType::Integer& element) const {
    PolyImpl<VecType> tmp(m_params, m_format);
    if (m_format == Format::COEFFICIENT)
        tmp.SetValues((*m_values).ModAddAtIndex(0, element), m_format);
    else
        tmp.SetValues((*m_values).ModAdd(element), m_format);
    return tmp;
}

template <typename VecType>
PolyImpl<VecType> PolyImpl<VecType>::Minus(const typename VecType::Integer& element) const {
    PolyImpl<VecType> tmp(m_params, m_format);
    tmp.SetValues((*m_values).ModSub(element), m_format);
    return tmp;
}

template <typename VecType>
PolyImpl<VecType> PolyImpl<VecType>::Times(const typename VecType::Integer& element) const {
    PolyImpl<VecType> tmp(m_params, m_format);
    tmp.SetValues((*m_values).ModMul(element), m_format);
    return tmp;
}

template <typename VecType>
PolyImpl<VecType> PolyImpl<VecType>::Times(NativeInteger::SignedNativeInt element) const {
    PolyImpl<VecType> tmp(m_params, m_format);
    Integer q(m_params->GetModulus());
    if (element < 0) {
        Integer elementReduced = NativeInteger::Integer(-element);
        if (elementReduced > q)
            elementReduced.ModEq(q);
        tmp.SetValues((*m_values).ModMul(q - Integer(elementReduced)), m_format);
    }
    else {
        Integer elementReduced = NativeInteger::Integer(element);
        if (elementReduced > q)
            elementReduced.ModEq(q);
        tmp.SetValues((*m_values).ModMul(Integer(elementReduced)), m_format);
    }
    return tmp;
}

template <typename VecType>
PolyImpl<VecType> PolyImpl<VecType>::Plus(const PolyImpl& element) const {
    PolyImpl tmp(*this);
    tmp.m_values->ModAddEq(*element.m_values);
    return tmp;
}

template <typename VecType>
PolyImpl<VecType> PolyImpl<VecType>::Minus(const PolyImpl& element) const {
    PolyImpl tmp(*this);
    tmp.m_values->ModSubEq(*element.m_values);
    return tmp;
}

template <typename VecType>
PolyImpl<VecType> PolyImpl<VecType>::Times(const PolyImpl& element) const {
    if (m_format != Format::EVALUATION || element.m_format != Format::EVALUATION)
        OPENFHE_THROW(not_implemented_error,
                      "operator* for PolyImpl is supported only in "
                      "Format::EVALUATION format.\n");
    if (!(*m_params == *element.m_params))
        OPENFHE_THROW(type_error, "operator* called on PolyImpl's with different params.");
    PolyImpl tmp(*this);
    tmp.m_values->ModMulEq(*element.m_values);
    return tmp;
}

template <typename VecType>
PolyImpl<VecType> PolyImpl<VecType>::MultiplyAndRound(const typename VecType::Integer& p,
                                                      const typename VecType::Integer& q) const {
    PolyImpl<VecType> tmp(m_params, m_format);
    tmp.SetValues((*m_values).MultiplyAndRound(p, q), m_format);
    return tmp;
}

template <typename VecType>
PolyImpl<VecType> PolyImpl<VecType>::DivideAndRound(const typename VecType::Integer& q) const {
    PolyImpl<VecType> tmp(m_params, m_format);
    tmp.SetValues((*m_values).DivideAndRound(q), m_format);
    return tmp;
}

template <typename VecType>
PolyImpl<VecType> PolyImpl<VecType>::Negate() const {
    //  UnitTestBFVrnsCRTOperations.cpp line 316 throws with this uncommented
    //    if (m_format != Format::EVALUATION)
    //        OPENFHE_THROW(not_implemented_error, "Negate for PolyImpl is supported only in Format::EVALUATION format.\n");

    //    PolyImpl<VecType> tmp(*this);
    //    tmp.m_values->ModMulEq(m_params->GetModulus() - Integer(1));
    //    return tmp;

    return PolyImpl<VecType>(m_params, m_format, true) -= *this;
}

template <typename VecType>
const PolyImpl<VecType>& PolyImpl<VecType>::operator+=(const PolyImpl& element) {
    if (!(*m_params == *element.m_params))
        OPENFHE_THROW(type_error, "operator+= called on PolyImpl's with different params.");
    if (m_values == nullptr) {
        m_values = std::make_unique<VecType>(*element.m_values);
    }
    else {
        m_values->ModAddEq(*element.m_values);
    }
    return *this;
}

template <typename VecType>
const PolyImpl<VecType>& PolyImpl<VecType>::operator-=(const PolyImpl& element) {
    if (!(*m_params == *element.m_params))
        OPENFHE_THROW(type_error, "operator-= called on PolyImpl's with different params.");
    if (m_values == nullptr)
        m_values = std::make_unique<VecType>(m_params->GetRingDimension(), m_params->GetModulus());
    m_values->ModSubEq(*element.m_values);
    return *this;
}

template <typename VecType>
const PolyImpl<VecType>& PolyImpl<VecType>::operator*=(const PolyImpl& element) {
    if (m_format != Format::EVALUATION || element.m_format != Format::EVALUATION)
        OPENFHE_THROW(not_implemented_error, "operator*= for PolyImpl is supported only in Format::EVALUATION format.");
    if (!(*m_params == *element.m_params))
        OPENFHE_THROW(type_error, "operator*= called on PolyImpl's with different params.");
    if (m_values == nullptr) {
        m_values = std::make_unique<VecType>(m_params->GetRingDimension(), m_params->GetModulus());
    }
    else {
        m_values->ModMulEq(*element.m_values);
    }
    return *this;
}

template <typename VecType>
void PolyImpl<VecType>::AddILElementOne() {
    static const Integer ONE(1);
    const usint vlen = m_params->GetRingDimension();
    const auto m     = m_params->GetModulus();
    //    Integer tempValue;
    for (usint i = 0; i < vlen; ++i) {
        //        tempValue      = (*m_values)[i] + ONE;
        //        (*m_values)[i] = tempValue.Mod(m);
        (*m_values)[i] += ONE;
        (*m_values)[i].ModEq(m);
    }
}

// TODO: optimize this
template <typename VecType>
PolyImpl<VecType> PolyImpl<VecType>::AutomorphismTransform(const usint& k) const {
    PolyImpl<VecType> result(*this);
    usint m = m_params->GetCyclotomicOrder();
    usint n = m_params->GetRingDimension();

    if (m_format == Format::EVALUATION) {
        if (!m_params->OrderIsPowerOfTwo()) {
            // Add a test based on the inverse totient hash table
            // if (i % 2 == 0)
            //  OPENFHE_THROW(math_error, "automorphism index should be
            // odd\n");

            const auto& modulus = m_params->GetModulus();

            // All automorphism operations are performed for k coprime to m, which are
            // generated using GetTotientList(m)
            std::vector<usint> totientList = GetTotientList(m);

            // Temporary vector of size m is introduced
            // This step can be eliminated by using a hash table that looks up the
            // ring index (between 0 and n - 1) based on the totient index (between 0
            // and m - 1)
            VecType expanded(m, modulus);
            for (usint i = 0; i < n; i++) {
                expanded.operator[](totientList.operator[](i)) = m_values->operator[](i);
            }

            for (usint i = 0; i < n; i++) {
                // determines which power of primitive root unity we should switch to
                usint idx                      = totientList.operator[](i) * k % m;
                result.m_values->operator[](i) = expanded.operator[](idx);
            }
        }
        else {  // power of two cyclotomics
            if (k % 2 == 0)
                OPENFHE_THROW(math_error, "automorphism index should be odd\n");

            usint logm = std::round(log2(m));
            usint logn = std::round(log2(n));
            for (usint j = 1; j < m; j += 2) {
                usint idx                         = (j * k) - (((j * k) >> logm) << logm);
                usint jrev                        = ReverseBits(j / 2, logn);
                usint idxrev                      = ReverseBits(idx / 2, logn);
                result.m_values->operator[](jrev) = (*m_values).operator[](idxrev);
            }
        }
    }
    else {
        // automorphism in Format::COEFFICIENT representation
        if (!m_params->OrderIsPowerOfTwo()) {
            OPENFHE_THROW(not_implemented_error,
                          "Automorphism in Format::COEFFICIENT representation is not currently "
                          "supported for non-power-of-two polynomials");
        }
        else {  // power of two cyclotomics
            if (k % 2 == 0)
                OPENFHE_THROW(math_error, "automorphism index should be odd\n");

            for (usint j = 1; j < n; j++) {
                usint temp     = j * k;
                usint newIndex = temp % n;

                if ((temp / n) % 2 == 1) {
                    result.m_values->operator[](newIndex) = m_params->GetModulus() - m_values->operator[](j);
                }
                else {
                    result.m_values->operator[](newIndex) = m_values->operator[](j);
                }
            }
        }
    }
    return result;
}

template <typename VecType>
PolyImpl<VecType> PolyImpl<VecType>::AutomorphismTransform(usint k, const std::vector<usint>& precomp) const {
    PolyImpl<VecType> result(*this);
    if ((m_format == Format::EVALUATION) && (m_params->OrderIsPowerOfTwo())) {
        if (k % 2 == 0)
            OPENFHE_THROW(math_error, "automorphism index should be odd\n");

        usint n = m_params->GetRingDimension();

        for (usint j = 0; j < n; j++) {
            (*result.m_values)[j] = (*m_values)[precomp[j]];
        }
    }
    else {
        OPENFHE_THROW(
            not_implemented_error,
            "Precomputed automorphism is implemented only for power-of-two polynomials in the EVALUATION representation");
    }
    return result;
}

template <typename VecType>
PolyImpl<VecType> PolyImpl<VecType>::MultiplicativeInverse() const {
    //    static const Integer ZERO(0);
    //    PolyImpl<VecType> tmp(*this);
    //    auto& v = tmp.GetValues();
    //    const usint vlen = m_params->GetRingDimension();
    //    for (usint i = 0; i < vlen; ++i) {
    //        if (v[i] == ZERO)
    //            OPENFHE_THROW(math_error, "PolyImpl has no inverse\n");
    //        v[i] = v[i].ModInverse();  // element-level ModInverse()?
    //    }
    //    return tmp;

    PolyImpl<VecType> tmp(m_params, m_format);
    if (this->InverseExists()) {
        tmp.SetValues((*m_values).ModInverse(), m_format);
        return tmp;
    }
    OPENFHE_THROW(math_error, "PolyImpl has no inverse\n");
}

template <typename VecType>
PolyImpl<VecType> PolyImpl<VecType>::ModByTwo() const {
    PolyImpl<VecType> tmp(m_params, m_format);
    tmp.SetValues((*m_values).ModByTwo(), m_format);
    return tmp;
}

template <typename VecType>
PolyImpl<VecType> PolyImpl<VecType>::Mod(const Integer& modulus) const {
    PolyImpl<VecType> tmp(m_params, m_format);
    tmp.SetValues((*m_values).Mod(modulus), m_format);
    return tmp;
}

template <typename VecType>
void PolyImpl<VecType>::SwitchModulus(const Integer& modulus, const Integer& rootOfUnity, const Integer& modulusArb,
                                      const Integer& rootOfUnityArb) {
    if (m_values != nullptr) {
        m_values->SwitchModulus(modulus);
        const auto c = m_params->GetCyclotomicOrder();
        m_params     = std::make_shared<PolyImpl::Params>(c, modulus, rootOfUnity, modulusArb, rootOfUnityArb);
    }
}

template <typename VecType>
void PolyImpl<VecType>::SwitchFormat() {
    if (m_values == nullptr)
        OPENFHE_THROW(not_available_error, "Poly switch format to empty values");

    if (!m_params->OrderIsPowerOfTwo()) {
        ArbitrarySwitchFormat();
        return;
    }

    const auto r = m_params->GetRootOfUnity();
    const auto c = m_params->GetCyclotomicOrder();
    if (m_format == Format::COEFFICIENT) {
        m_format = Format::EVALUATION;
        ChineseRemainderTransformFTT<VecType>().ForwardTransformToBitReverseInPlace(r, c, &(*m_values));
    }
    else {
        m_format = Format::COEFFICIENT;
        ChineseRemainderTransformFTT<VecType>().InverseTransformFromBitReverseInPlace(r, c, &(*m_values));
    }
}

template <typename VecType>
void PolyImpl<VecType>::ArbitrarySwitchFormat() {
    if (m_values == nullptr)
        OPENFHE_THROW(not_available_error, "Poly switch format to empty values");

    const auto lr = m_params->GetRootOfUnity();
    const auto bm = m_params->GetBigModulus();
    const auto br = m_params->GetBigRootOfUnity();
    const auto co = m_params->GetCyclotomicOrder();
    if (m_format == Format::COEFFICIENT) {
        m_format = Format::EVALUATION;
        auto v   = ChineseRemainderTransformArb<VecType>().ForwardTransform(*m_values, lr, bm, br, co);
        m_values = std::make_unique<VecType>(v);
    }
    else {
        m_format = Format::COEFFICIENT;
        auto v   = ChineseRemainderTransformArb<VecType>().InverseTransform(*m_values, lr, bm, br, co);
        m_values = std::make_unique<VecType>(v);
    }
}
template <typename VecType>
std::ostream& operator<<(std::ostream& os, const PolyImpl<VecType>& p) {
    if (p.m_values != nullptr) {
        os << *(p.m_values);
        os << " mod:" << (p.m_values)->GetModulus() << std::endl;
    }
    if (p.m_params.get() != nullptr) {
        os << " rootOfUnity: " << p.GetRootOfUnity() << std::endl;
    }
    else {
        os << " something's odd: null m_params?!" << std::endl;
    }
    os << std::endl;
    return os;
}

template <typename VecType>
void PolyImpl<VecType>::MakeSparse(const uint32_t& wFactor) {
    static const Integer ZERO(0);
    if (m_values != nullptr) {
        for (usint i = 0; i < m_params->GetRingDimension(); i++) {
            if (i % wFactor != 0)
                (*m_values)[i] = ZERO;
        }
    }
}

template <typename VecType>
bool PolyImpl<VecType>::InverseExists() const {
    static const Integer ZERO(0);
    const usint vlen = m_params->GetRingDimension();
    for (usint i = 0; i < vlen; i++) {
        if ((*m_values)[i] == ZERO)
            return false;
    }
    return true;
}

template <typename VecType>
double PolyImpl<VecType>::Norm() const {
    const Integer& q    = m_params->GetModulus();
    const Integer& half = m_params->GetModulus() >> 1;
    const usint vlen    = m_params->GetRingDimension();

    Integer locVal;
    Integer retVal;
    for (usint i = 0; i < vlen; i++) {
        locVal = (*m_values)[i];
        if (locVal > half)
            locVal = q - locVal;
        if (locVal > retVal)
            retVal = locVal;
    }
    return retVal.ConvertToDouble();
}

// Write vector x(current value of the PolyImpl object) as \sum\limits{ i = 0
// }^{\lfloor{ \log q / base } \rfloor} {(base^i u_i)} and return the vector of{
// u_0, u_1,...,u_{ \lfloor{ \log q / base } \rfloor } } \in R_base^{ \lceil{
// \log q / base } \rceil }; used as a subroutine in the relinearization
// procedure baseBits is the number of bits in the base, i.e., base = 2^baseBits

template <typename VecType>
std::vector<PolyImpl<VecType>> PolyImpl<VecType>::BaseDecompose(usint baseBits, bool evalModeAnswer) const {
    usint nBits = m_params->GetModulus().GetLengthForBase(2);

    usint nWindows = nBits / baseBits;
    if (nBits % baseBits > 0)
        nWindows++;

    PolyImpl<VecType> xDigit(m_params);

    std::vector<PolyImpl<VecType>> result;
    result.reserve(nWindows);

    PolyImpl<VecType> x(*this);
    x.SetFormat(Format::COEFFICIENT);

    // TP: x is same for BACKEND 2 and 6
    for (usint i = 0; i < nWindows; ++i) {
        xDigit.SetValues(x.GetValues().GetDigitAtIndexForBase(i + 1, 1 << baseBits), x.GetFormat());

        // TP: xDigit is all zeros for BACKEND=6, but not for BACKEND-2
        // *********************************************************
        if (evalModeAnswer)
            xDigit.SwitchFormat();
        result.push_back(xDigit);
    }
    return result;
}

// Generate a vector of PolyImpl's as {x, base*x, base^2*x, ..., base^{\lfloor
// {\log q/base} \rfloor}*x, where x is the current PolyImpl object; used as a
// subroutine in the relinearization procedure to get powers of a certain "base"
// for the secret key element baseBits is the number of bits in the base, i.e.,
// base = 2^baseBits

// TODO: verify this
template <typename VecType>
std::vector<PolyImpl<VecType>> PolyImpl<VecType>::PowersOfBase(usint baseBits) const {
    static const Integer TWO(2);
    std::vector<PolyImpl<VecType>> result;

    usint nBits = m_params->GetModulus().GetLengthForBase(2);

    usint nWindows = nBits / baseBits;
    if (nBits % baseBits > 0)
        nWindows++;

    result.reserve(nWindows);

    for (usint i = 0; i < nWindows; ++i) {
        Integer pI(TWO.ModExp(Integer(i * baseBits), m_params->GetModulus()));
        result.push_back(pI * (*this));
    }
    return result;
}

template <typename VecType>
typename PolyImpl<VecType>::PolyNative PolyImpl<VecType>::DecryptionCRTInterpolate(PlaintextModulus ptm) const {
    const PolyImpl<VecType> smaller(this->Mod(ptm));
    const auto c = m_params->GetCyclotomicOrder();
    auto params  = std::make_shared<ILNativeParams>(c, ptm, 1);
    typename PolyImpl<VecType>::PolyNative interp(params, m_format, true);
    for (usint i = 0; i < smaller.GetLength(); i++)
        interp[i] = (*smaller.m_values)[i].ConvertToInt();
    return interp;
}

template <typename VecType>
typename PolyImpl<VecType>::PolyNative PolyImpl<VecType>::ToNativePoly() const {
    const usint vlen = m_params->GetRingDimension();
    const auto c     = m_params->GetCyclotomicOrder();
    const auto m     = std::numeric_limits<uint64_t>::max();
    auto params      = std::make_shared<ILParamsImpl<NativeInteger>>(c, m, 1);
    typename PolyImpl<VecType>::PolyNative interp(params, m_format, true);
    for (usint i = 0; i < vlen; i++)
        interp[i] = (*m_values)[i].ConvertToInt();
    return interp;
}

template <>
inline PolyImpl<NativeVector> PolyImpl<NativeVector>::ToNativePoly() const {
    return *this;
}

}  // namespace lbcrypto

#endif
