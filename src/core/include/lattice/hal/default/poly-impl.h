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
#include <iostream>
#include <limits>
#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace lbcrypto {

template <typename VecType>
PolyImpl<VecType>::PolyImpl(const DggType& dgg, const std::shared_ptr<PolyImpl::Params>& params, Format format)
    : m_format{Format::COEFFICIENT},
      m_params{params},
      m_values{std::make_unique<VecType>(dgg.GenerateVector(params->GetRingDimension(), params->GetModulus()))} {
    PolyImpl<VecType>::SetFormat(format);
}

template <typename VecType>
PolyImpl<VecType>::PolyImpl(DugType& dug, const std::shared_ptr<PolyImpl::Params>& params, Format format)
    : m_format{format},
      m_params{params},
      m_values{std::make_unique<VecType>(dug.GenerateVector(params->GetRingDimension(), params->GetModulus()))} {}

template <typename VecType>
PolyImpl<VecType>::PolyImpl(const BugType& bug, const std::shared_ptr<PolyImpl::Params>& params, Format format)
    : m_format{Format::COEFFICIENT},
      m_params{params},
      m_values{std::make_unique<VecType>(bug.GenerateVector(params->GetRingDimension(), params->GetModulus()))} {
    PolyImpl<VecType>::SetFormat(format);
}

template <typename VecType>
PolyImpl<VecType>::PolyImpl(const TugType& tug, const std::shared_ptr<PolyImpl::Params>& params, Format format,
                            uint32_t h)
    : m_format{Format::COEFFICIENT},
      m_params{params},
      m_values{std::make_unique<VecType>(tug.GenerateVector(params->GetRingDimension(), params->GetModulus(), h))} {
    PolyImpl<VecType>::SetFormat(format);
}

template <typename VecType>
PolyImpl<VecType>& PolyImpl<VecType>::operator=(const PolyImpl& rhs) noexcept {
    m_format = rhs.m_format;
    m_params = rhs.m_params;
    if (!rhs.m_values) {
        m_values = nullptr;
        return *this;
    }
    if (m_values) {
        *m_values = *rhs.m_values;
        return *this;
    }
    m_values = std::make_unique<VecType>(*rhs.m_values);
    return *this;
}

// assumes that elements in rhs less than modulus?
template <typename VecType>
PolyImpl<VecType>& PolyImpl<VecType>::operator=(std::initializer_list<uint64_t> rhs) {
    static const Integer ZERO(0);
    const size_t llen = rhs.size();
    const size_t vlen = m_params->GetRingDimension();
    if (!m_values) {
        VecType temp(vlen);
        temp.SetModulus(m_params->GetModulus());
        PolyImpl<VecType>::SetValues(std::move(temp), m_format);
    }
    for (size_t j = 0; j < vlen; ++j)
        (*m_values)[j] = (j < llen) ? *(rhs.begin() + j) : ZERO;
    return *this;
}

// TODO: template with enable_if int64_t/int32_t
template <typename VecType>
PolyImpl<VecType>& PolyImpl<VecType>::operator=(const std::vector<int64_t>& rhs) {
    static const Integer ZERO(0);
    m_format = Format::COEFFICIENT;
    const size_t llen{rhs.size()};
    const size_t vlen{m_params->GetRingDimension()};
    const auto& m = m_params->GetModulus();
    if (!m_values) {
        VecType tmp(vlen);
        tmp.SetModulus(m);
        PolyImpl<VecType>::SetValues(std::move(tmp), m_format);
    }
    for (size_t j = 0; j < vlen; ++j) {
        if (j < llen)
            (*m_values)[j] =
                (rhs[j] < 0) ? m - Integer(static_cast<uint64_t>(-rhs[j])) : Integer(static_cast<uint64_t>(rhs[j]));
        else
            (*m_values)[j] = ZERO;
    }
    return *this;
}

template <typename VecType>
PolyImpl<VecType>& PolyImpl<VecType>::operator=(const std::vector<int32_t>& rhs) {
    static const Integer ZERO(0);
    m_format = Format::COEFFICIENT;
    const size_t llen{rhs.size()};
    const size_t vlen{m_params->GetRingDimension()};
    const auto& m = m_params->GetModulus();
    if (!m_values) {
        VecType tmp(vlen);
        tmp.SetModulus(m);
        PolyImpl<VecType>::SetValues(std::move(tmp), m_format);
    }
    for (size_t j = 0; j < vlen; ++j) {
        if (j < llen)
            (*m_values)[j] =
                (rhs[j] < 0) ? m - Integer(static_cast<uint64_t>(-rhs[j])) : Integer(static_cast<uint64_t>(rhs[j]));
        else
            (*m_values)[j] = ZERO;
    }
    return *this;
}

template <typename VecType>
PolyImpl<VecType>& PolyImpl<VecType>::operator=(std::initializer_list<std::string> rhs) {
    const size_t vlen = m_params->GetRingDimension();
    if (!m_values) {
        VecType temp(vlen);
        temp.SetModulus(m_params->GetModulus());
        PolyImpl<VecType>::SetValues(std::move(temp), m_format);
    }
    *m_values = rhs;
    return *this;
}

template <typename VecType>
PolyImpl<VecType>& PolyImpl<VecType>::operator=(uint64_t val) {
    m_format = Format::EVALUATION;
    if (!m_values) {
        auto d{m_params->GetRingDimension()};
        const auto& m{m_params->GetModulus()};
        m_values = std::make_unique<VecType>(d, m);
    }
    size_t vlen{m_values->GetLength()};
    Integer ival{val};
    for (size_t i = 0; i < vlen; ++i)
        (*m_values)[i] = ival;
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
    Integer q{m_params->GetModulus()};
    if (element < 0) {
        Integer elementReduced{NativeInteger::Integer(-element)};
        if (elementReduced > q)
            elementReduced.ModEq(q);
        tmp.SetValues((*m_values).ModMul(q - elementReduced), m_format);
    }
    else {
        Integer elementReduced{NativeInteger::Integer(element)};
        if (elementReduced > q)
            elementReduced.ModEq(q);
        tmp.SetValues((*m_values).ModMul(elementReduced), m_format);
    }
    return tmp;
}

template <typename VecType>
PolyImpl<VecType> PolyImpl<VecType>::Minus(const PolyImpl& rhs) const {
    PolyImpl<VecType> tmp(m_params, m_format);
    tmp.SetValues((*m_values).ModSub(*rhs.m_values), m_format);
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

// TODO: this will return vec of 0s for BigIntegers
template <typename VecType>
PolyImpl<VecType> PolyImpl<VecType>::Negate() const {
    //  UnitTestBFVrnsCRTOperations.cpp line 316 throws with this uncommented
    //    if (m_format != Format::EVALUATION)
    //        OPENFHE_THROW(not_implemented_error, "Negate for PolyImpl is supported only in Format::EVALUATION format.\n");
    return PolyImpl<VecType>(m_params, m_format, true) -= *this;
}

template <typename VecType>
PolyImpl<VecType>& PolyImpl<VecType>::operator+=(const PolyImpl& element) {
    if (!m_values)
        m_values = std::make_unique<VecType>(m_params->GetRingDimension(), m_params->GetModulus());
    m_values->ModAddEq(*element.m_values);
    return *this;
}

template <typename VecType>
PolyImpl<VecType>& PolyImpl<VecType>::operator-=(const PolyImpl& element) {
    if (!m_values)
        m_values = std::make_unique<VecType>(m_params->GetRingDimension(), m_params->GetModulus());
    m_values->ModSubEq(*element.m_values);
    return *this;
}

template <typename VecType>
void PolyImpl<VecType>::AddILElementOne() {
    static const Integer ONE(1);
    usint vlen{m_params->GetRingDimension()};
    const auto& m{m_params->GetModulus()};
    for (usint i = 0; i < vlen; ++i)
        (*m_values)[i].ModAddFastEq(ONE, m);
}

template <typename VecType>
PolyImpl<VecType> PolyImpl<VecType>::AutomorphismTransform(uint32_t k) const {
    uint32_t n{m_params->GetRingDimension()};
    uint32_t m{m_params->GetCyclotomicOrder()};
    bool bp{n == (m >> 1)};
    bool bf{m_format == Format::EVALUATION};

    // if (!bf && !bp)
    if (!bp)
        OPENFHE_THROW(not_implemented_error, "Automorphism Poly Format not EVALUATION or not power-of-two");
    /*
    // TODO: is this branch ever called?

    PolyImpl<VecType> result(m_params, m_format, true);
    if (bf && !bp) {
        // TODO: Add a test based on the inverse totient hash table?

        // All automorphism operations are performed for k coprime to m
        auto totientList = GetTotientList(m);

        // This step can be eliminated by using a hash table that looks up the
        // ring index (between 0 and n - 1) based on the totient index (between 0 and m - 1)
        VecType expanded(m, m_params->GetModulus());
        for (uint32_t i = 0; i < n; ++i)
            expanded[totientList[i]] = (*m_values)[i];

        for (uint32_t i = 0; i < n; ++i) {
            // determines which power of primitive root unity we should switch to
            (*result.m_values)[i] = expanded[totientList[i] * k % m];
        }
        return result;
    }
*/
    if (k % 2 == 0)
        OPENFHE_THROW(math_error, "Automorphism index not odd\n");

    PolyImpl<VecType> result(m_params, m_format, true);
    uint32_t logm{lbcrypto::GetMSB(m) - 1};
    uint32_t logn{logm - 1};
    uint32_t mask{(uint32_t(1) << logn) - 1};

    if (bf) {
        for (uint32_t j{0}, jk{k}; j < n; ++j, jk += (2 * k)) {
            auto&& jrev{lbcrypto::ReverseBits(j, logn)};
            auto&& idxrev{lbcrypto::ReverseBits((jk >> 1) & mask, logn)};
            (*result.m_values)[jrev] = (*m_values)[idxrev];
        }
        return result;
    }

    auto q{m_params->GetModulus()};
    for (uint32_t j{0}, jk{0}; j < n; ++j, jk += k)
        (*result.m_values)[jk & mask] = ((jk >> logn) & 0x1) ? q - (*m_values)[j] : (*m_values)[j];
    return result;
}

template <typename VecType>
PolyImpl<VecType> PolyImpl<VecType>::AutomorphismTransform(uint32_t k, const std::vector<uint32_t>& precomp) const {
    if ((m_format != Format::EVALUATION) || (m_params->GetRingDimension() != (m_params->GetCyclotomicOrder() >> 1)))
        OPENFHE_THROW(not_implemented_error, "Automorphism Poly Format not EVALUATION or not power-of-two");
    if (k % 2 == 0)
        OPENFHE_THROW(math_error, "Automorphism index not odd\n");
    PolyImpl<VecType> tmp(m_params, m_format, true);
    uint32_t n = m_params->GetRingDimension();
    for (uint32_t j = 0; j < n; ++j)
        (*tmp.m_values)[j] = (*m_values)[precomp[j]];
    return tmp;
}

template <typename VecType>
PolyImpl<VecType> PolyImpl<VecType>::MultiplicativeInverse() const {
    PolyImpl<VecType> tmp(m_params, m_format);
    tmp.SetValues((*m_values).ModInverse(), m_format);
    return tmp;
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
        auto c{m_params->GetCyclotomicOrder()};
        m_params = std::make_shared<PolyImpl::Params>(c, modulus, rootOfUnity, modulusArb, rootOfUnityArb);
    }
}

template <typename VecType>
void PolyImpl<VecType>::SwitchFormat() {
    const auto& co{m_params->GetCyclotomicOrder()};
    const auto& rd{m_params->GetRingDimension()};
    const auto& ru{m_params->GetRootOfUnity()};

    if (rd != (co >> 1)) {
        PolyImpl<VecType>::ArbitrarySwitchFormat();
        return;
    }

    if (!m_values)
        OPENFHE_THROW(not_available_error, "Poly switch format to empty values");

    if (m_format != Format::COEFFICIENT) {
        m_format = Format::COEFFICIENT;
        ChineseRemainderTransformFTT<VecType>().InverseTransformFromBitReverseInPlace(ru, co, &(*m_values));
        return;
    }
    m_format = Format::EVALUATION;
    ChineseRemainderTransformFTT<VecType>().ForwardTransformToBitReverseInPlace(ru, co, &(*m_values));
}

template <typename VecType>
void PolyImpl<VecType>::ArbitrarySwitchFormat() {
    if (m_values == nullptr)
        OPENFHE_THROW(not_available_error, "Poly switch format to empty values");
    const auto& lr = m_params->GetRootOfUnity();
    const auto& bm = m_params->GetBigModulus();
    const auto& br = m_params->GetBigRootOfUnity();
    const auto& co = m_params->GetCyclotomicOrder();
    if (m_format == Format::COEFFICIENT) {
        m_format = Format::EVALUATION;
        auto&& v = ChineseRemainderTransformArb<VecType>().ForwardTransform(*m_values, lr, bm, br, co);
        m_values = std::make_unique<VecType>(v);
    }
    else {
        m_format = Format::COEFFICIENT;
        auto&& v = ChineseRemainderTransformArb<VecType>().InverseTransform(*m_values, lr, bm, br, co);
        m_values = std::make_unique<VecType>(v);
    }
}

template <typename VecType>
std::ostream& operator<<(std::ostream& os, const PolyImpl<VecType>& p) {
    if (p.m_values != nullptr) {
        os << *(p.m_values);
        os << " mod:" << (p.m_values)->GetModulus() << std::endl;
    }
    if (p.m_params.get() != nullptr)
        os << " rootOfUnity: " << p.GetRootOfUnity() << std::endl;
    else
        os << " something's odd: null m_params?!" << std::endl;
    os << std::endl;
    return os;
}

template <typename VecType>
void PolyImpl<VecType>::MakeSparse(uint32_t wFactor) {
    static const Integer ZERO(0);
    if (m_values != nullptr) {
        uint32_t vlen{m_params->GetRingDimension()};
        for (uint32_t i = 0; i < vlen; ++i) {
            if (i % wFactor != 0)
                (*m_values)[i] = ZERO;
        }
    }
}

template <typename VecType>
bool PolyImpl<VecType>::InverseExists() const {
    static const Integer ZERO(0);
    usint vlen{m_params->GetRingDimension()};
    for (usint i = 0; i < vlen; ++i) {
        if ((*m_values)[i] == ZERO)
            return false;
    }
    return true;
}

template <typename VecType>
double PolyImpl<VecType>::Norm() const {
    usint vlen{m_params->GetRingDimension()};
    const auto& q{m_params->GetModulus()};
    const auto& half{q >> 1};
    Integer maxVal{}, minVal{q};
    for (usint i = 0; i < vlen; i++) {
        auto& val = (*m_values)[i];
        if (val > half)
            minVal = val < minVal ? val : minVal;
        else
            maxVal = val > maxVal ? val : maxVal;
    }
    minVal = q - minVal;
    return (minVal > maxVal ? minVal : maxVal).ConvertToDouble();
}

// Write vector x(current value of the PolyImpl object) as \sum\limits{ i = 0
// }^{\lfloor{ \log q / base } \rfloor} {(base^i u_i)} and return the vector of{
// u_0, u_1,...,u_{ \lfloor{ \log q / base } \rfloor } } \in R_base^{ \lceil{
// \log q / base } \rceil }; used as a subroutine in the relinearization
// procedure baseBits is the number of bits in the base, i.e., base = 2^baseBits

// TODO: optimize this
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

template <typename VecType>
std::vector<PolyImpl<VecType>> PolyImpl<VecType>::PowersOfBase(usint baseBits) const {
    static const Integer TWO(2);
    const auto& m{m_params->GetModulus()};
    usint nBits{m.GetLengthForBase(2)};
    usint nWindows{nBits / baseBits};
    if (nBits % baseBits > 0)
        ++nWindows;
    std::vector<PolyImpl<VecType>> result(nWindows);
    Integer shift{0}, bbits{baseBits};
    for (usint i = 0; i < nWindows; ++i, shift += bbits)
        result[i] = (*this) * TWO.ModExp(shift, m);
    return result;
}

template <typename VecType>
typename PolyImpl<VecType>::PolyNative PolyImpl<VecType>::DecryptionCRTInterpolate(PlaintextModulus ptm) const {
    const PolyImpl<VecType> smaller(PolyImpl<VecType>::Mod(ptm));
    usint vlen{m_params->GetRingDimension()};
    auto c{m_params->GetCyclotomicOrder()};
    auto params{std::make_shared<ILNativeParams>(c, NativeInteger(ptm), 1)};
    typename PolyImpl<VecType>::PolyNative tmp(params, m_format, true);
    for (usint i = 0; i < vlen; ++i)
        tmp[i] = NativeInteger((*smaller.m_values)[i]);
    return tmp;
}

template <>
inline PolyImpl<NativeVector> PolyImpl<NativeVector>::ToNativePoly() const {
    return *this;
}

}  // namespace lbcrypto

#endif
