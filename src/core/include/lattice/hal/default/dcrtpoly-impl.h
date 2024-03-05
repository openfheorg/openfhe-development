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
  Implementation of the integer lattice using double-CRT representations
 */

#ifndef LBCRYPTO_INC_LATTICE_HAL_DEFAULT_DCRTPOLY_IMPL_H
#define LBCRYPTO_INC_LATTICE_HAL_DEFAULT_DCRTPOLY_IMPL_H

#include "config_core.h"

#include "lattice/hal/default/poly-impl.h"
#include "lattice/hal/default/dcrtpoly.h"

#include "utils/exception.h"
#include "utils/inttypes.h"
#include "utils/parallel.h"
#include "utils/utilities.h"
#include "utils/utilities-int.h"

#include <ostream>
#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace lbcrypto {

template <typename VecType>
DCRTPolyImpl<VecType>::DCRTPolyImpl(const PolyLargeType& rhs,
                                    const std::shared_ptr<DCRTPolyImpl::Params>& params) noexcept
    : DCRTPolyImpl<VecType>::DCRTPolyImpl(params, rhs.GetFormat(), true) {
    m_params->SetOriginalModulus(rhs.GetModulus());
    size_t size{m_vectors.size()};
    uint32_t rdim{rhs.GetLength()};
    for (size_t i{0}; i < size; ++i) {
        auto& v{m_vectors[i]};
        const auto& m{v.GetParams()->GetModulus()};
        for (uint32_t j{0}; j < rdim; ++j)
            v[j] = rhs[j].Mod(m);
    }
}

template <typename VecType>
DCRTPolyImpl<VecType>& DCRTPolyImpl<VecType>::operator=(const PolyLargeType& rhs) noexcept {
    m_params->SetOriginalModulus(rhs.GetModulus());
    m_vectors.clear();
    m_vectors.reserve(m_params->GetParams().size());
    uint32_t rdim{rhs.GetLength()};
    for (const auto& p : m_params->GetParams()) {
        m_vectors.emplace_back(p, m_format, true);
        const auto& m = p->GetModulus();
        for (uint32_t e = 0; e < rdim; ++e)
            m_vectors.back()[e] = rhs[e].Mod(m);
    }
    return *this;
}

template <typename VecType>
DCRTPolyImpl<VecType>::DCRTPolyImpl(const PolyType& rhs, const std::shared_ptr<DCRTPolyImpl::Params>& params) noexcept
    : m_params{params}, m_format{rhs.GetFormat()}, m_vectors(params->GetParams().size(), rhs) {
    size_t size{m_vectors.size()};
    const auto& p{params->GetParams()};
    for (size_t i{1}; i < size; ++i)
        m_vectors[i].SwitchModulus(p[i]->GetModulus(), p[i]->GetRootOfUnity(), 0, 0);
}

template <typename VecType>
DCRTPolyImpl<VecType>& DCRTPolyImpl<VecType>::operator=(const PolyType& rhs) noexcept {
    m_vectors.clear();
    m_vectors.reserve(m_params->GetParams().size());
    bool first{true};
    for (const auto& p : m_params->GetParams()) {
        m_vectors.emplace_back(rhs);
        if (!first)
            m_vectors.back().SwitchModulus(p->GetModulus(), p->GetRootOfUnity(), 0, 0);
        first = false;
    }
    return *this;
}

/* Construct using a tower of vectors.
 * The params and format for the DCRTPolyImpl will be derived from the towers */
template <typename VecType>
DCRTPolyImpl<VecType>::DCRTPolyImpl(const std::vector<DCRTPolyImpl::PolyType>& towers)
    : m_params{nullptr}, m_format{towers[0].GetFormat()}, m_vectors(towers) {
    std::vector<std::shared_ptr<ILNativeParams>> parms;
    const auto cyclotomicOrder = m_vectors[0].GetCyclotomicOrder();
    for (auto& v : m_vectors) {
        if (v.GetCyclotomicOrder() != cyclotomicOrder)
            OPENFHE_THROW(math_error, "Polys provided to constructor must have the same ring dimension");
        parms.emplace_back(v.GetParams());
    }
    m_params = std::make_shared<DCRTPolyImpl::Params>(cyclotomicOrder, parms);
}

/*The dgg will be the seed to populate the towers of the DCRTPolyImpl with
 * random numbers. The algorithm to populate the towers can be seen below. */
template <typename VecType>
DCRTPolyImpl<VecType>::DCRTPolyImpl(const DggType& dgg, const std::shared_ptr<DCRTPolyImpl::Params>& dcrtParams,
                                    Format format)
    : m_params{dcrtParams}, m_format{format} {
    const usint rdim     = m_params->GetRingDimension();
    const auto dggValues = dgg.GenerateIntVector(rdim);
    m_vectors.reserve(m_params->GetParams().size());
    for (auto& p : m_params->GetParams()) {
        NativeVector ildv(rdim, p->GetModulus());
        for (usint j = 0; j < rdim; j++) {
            NativeInteger::SignedNativeInt k = (dggValues.get())[j];
            auto m                           = p->GetModulus().ConvertToInt();
            auto dcrt_qmodulus               = static_cast<NativeInteger::SignedNativeInt>(m);
            auto dgg_stddev                  = dgg.GetStd();
            if (dgg_stddev > dcrt_qmodulus) {
                // rescale k to dcrt_qmodulus
                k = static_cast<NativeInteger::Integer>(k % dcrt_qmodulus);
            }
            if (k < 0) {
                k *= (-1);
                ildv[j] = static_cast<NativeInteger::Integer>(dcrt_qmodulus) - static_cast<NativeInteger::Integer>(k);
            }
            else {
                ildv[j] = static_cast<NativeInteger::Integer>(k);
            }
        }
        DCRTPolyImpl::PolyType ilvector(p);
        ilvector.SetValues(std::move(ildv), Format::COEFFICIENT);
        ilvector.SetFormat(m_format);
        m_vectors.push_back(std::move(ilvector));
    }
}

template <typename VecType>
DCRTPolyImpl<VecType>::DCRTPolyImpl(DugType& dug, const std::shared_ptr<Params>& dcrtParams, Format format)
    : m_params{dcrtParams}, m_format{format} {
    m_vectors.reserve(m_params->GetParams().size());
    for (auto& p : m_params->GetParams()) {
        NativeVector vals(dug.GenerateVector(p->GetRingDimension(), p->GetModulus()));
        DCRTPolyImpl::PolyType ilvector(p);
        ilvector.SetValues(std::move(vals), m_format);
        m_vectors.push_back(std::move(ilvector));
    }
}

template <typename VecType>
DCRTPolyImpl<VecType>::DCRTPolyImpl(const BugType& bug, const std::shared_ptr<Params>& dcrtParams, Format format)
    : m_params{dcrtParams}, m_format{format} {
    m_vectors.reserve(m_params->GetParams().size());
    bool first = true;
    DCRTPolyImpl<VecType>::PolyType ilvector(bug, m_params->GetParams()[0], Format::COEFFICIENT);
    for (auto& p : m_params->GetParams()) {
        if (!first)
            ilvector.SwitchModulus(p->GetModulus(), p->GetRootOfUnity(), 0, 0);
        auto newVector = ilvector;
        newVector.SetFormat(m_format);
        m_vectors.push_back(std::move(newVector));
        first = false;
    }
}

template <typename VecType>
DCRTPolyImpl<VecType>::DCRTPolyImpl(const TugType& tug, const std::shared_ptr<Params>& dcrtParams, Format format,
                                    uint32_t h)
    : m_params{dcrtParams}, m_format{format} {
    const usint rdim     = m_params->GetRingDimension();
    const auto tugValues = tug.GenerateIntVector(rdim, h);
    m_vectors.reserve(m_params->GetParams().size());
    for (auto& p : m_params->GetParams()) {
        NativeVector iltvs(rdim, p->GetModulus());
        for (usint j = 0; j < rdim; j++) {
            NativeInteger::SignedNativeInt k = (tugValues.get())[j];
            if (k < 0) {
                k *= (-1);
                iltvs[j] = static_cast<NativeInteger::Integer>(p->GetModulus().ConvertToInt()) -
                           static_cast<NativeInteger::Integer>(k);
            }
            else {
                iltvs[j] = static_cast<NativeInteger::Integer>(k);
            }
        }
        DCRTPolyImpl<VecType>::PolyType ilvector(p);
        ilvector.SetValues(std::move(iltvs), Format::COEFFICIENT);
        ilvector.SetFormat(m_format);
        m_vectors.push_back(std::move(ilvector));
    }
}

template <typename VecType>
DCRTPolyImpl<VecType> DCRTPolyImpl<VecType>::CloneWithNoise(const DiscreteGaussianGeneratorImpl<VecType>& dgg,
                                                            Format format) const {
    DCRTPolyImpl res(m_params, m_format);
    auto c{m_params->GetCyclotomicOrder()};
    const auto& m{m_params->GetModulus()};
    auto parm{std::make_shared<ILParamsImpl<Integer>>(c, m, 1)};
    DCRTPolyImpl<VecType>::PolyLargeType element(parm);
    element.SetValues(dgg.GenerateVector(c / 2, m), m_format);
    return res = element;
}

template <typename VecType>
DCRTPolyImpl<VecType> DCRTPolyImpl<VecType>::CloneTowers(uint32_t startTower, uint32_t endTower) const {
    std::vector<NativeInteger> m(endTower - startTower + 1);
    std::vector<NativeInteger> r(endTower - startTower + 1);

    for (uint32_t i = startTower; i <= endTower; i++) {
        m[i - startTower] = m_params->GetParams()[i]->GetModulus();
        r[i - startTower] = m_params->GetParams()[i]->GetRootOfUnity();
    }

    const auto co = m_params->GetCyclotomicOrder();
    auto params   = std::make_shared<Params>(co, m, r);
    auto res      = DCRTPolyImpl(params, Format::EVALUATION, false);

    for (uint32_t i = startTower; i <= endTower; i++) {
        res.SetElementAtIndex(i - startTower, this->GetElementAtIndex(i));
    }
    return res;
}

template <typename VecType>
std::vector<DCRTPolyImpl<VecType>> DCRTPolyImpl<VecType>::BaseDecompose(usint baseBits, bool evalModeAnswer) const {
    auto bdV(CRTInterpolate().BaseDecompose(baseBits, false));
    std::vector<DCRTPolyImpl<VecType>> result;
    result.reserve(bdV.size());
    for (auto& dv : bdV) {
        result.emplace_back(dv, m_params);
        if (evalModeAnswer)
            result.back().SwitchFormat();
    }
    return result;
}

// TODO: usint
template <typename VecType>
std::vector<DCRTPolyImpl<VecType>> DCRTPolyImpl<VecType>::CRTDecompose(uint32_t baseBits) const {
    DCRTPolyImpl<VecType> cp(*this);
    cp.SwitchFormat();
    const DCRTPolyImpl<VecType>* coef = (m_format == Format::COEFFICIENT) ? this : &cp;
    const DCRTPolyImpl<VecType>* eval = (m_format == Format::COEFFICIENT) ? &cp : this;
    size_t size{m_vectors.size()};

    if (baseBits == 0) {
        std::vector<DCRTPolyType> result(size, *eval);

#pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(size))
        for (size_t i = 0; i < size; ++i) {
            for (size_t k = 0; k < size; ++k) {
                if (i != k) {
                    DCRTPolyImpl::PolyType tmp((*coef).m_vectors[i]);
                    tmp.SwitchModulus((*coef).m_vectors[k].GetModulus(), (*coef).m_vectors[k].GetRootOfUnity(), 0, 0);
                    tmp.SetFormat(Format::EVALUATION);
                    result[i].m_vectors[k] = std::move(tmp);
                }
            }
        }
        return result;
    }

    uint32_t nWindows{0};
    // used to store the number of digits for each small modulus
    std::vector<usint> arrWindows(size);
    // creates an array of digits up to a certain tower
    for (size_t i = 0; i < size; ++i) {
        usint nBits{m_vectors[i].GetModulus().GetLengthForBase(2)};
        usint curWindows{nBits / baseBits};
        if (nBits % baseBits != 0)
            curWindows++;
        arrWindows[i] = nWindows;
        nWindows += curWindows;
    }
    std::vector<DCRTPolyType> result(nWindows);

#pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(size))
    for (size_t i = 0; i < size; ++i) {
        auto decomposed = (*coef).m_vectors[i].BaseDecompose(baseBits, false);
        for (size_t j = 0; j < decomposed.size(); j++) {
            DCRTPolyImpl<VecType> currentDCRTPoly(*coef);
            for (size_t k = 0; k < size; ++k) {
                DCRTPolyImpl::PolyType tmp(decomposed[j]);
                if (i != k)
                    tmp.SwitchModulus((*coef).m_vectors[k].GetModulus(), (*coef).m_vectors[k].GetRootOfUnity(), 0, 0);
                currentDCRTPoly.m_vectors[k] = std::move(tmp);
            }
            currentDCRTPoly.SwitchFormat();
            result[j + arrWindows[i]] = std::move(currentDCRTPoly);
        }
    }
    return result;
}

template <typename VecType>
std::vector<DCRTPolyImpl<VecType>> DCRTPolyImpl<VecType>::PowersOfBase(usint baseBits) const {
    // prepare for the calculations by gathering a big integer version of each of the little moduli
    std::vector<Integer> mods;
    mods.reserve(m_params->GetParams().size());
    for (auto& p : m_params->GetParams())
        mods.emplace_back(p->GetModulus());

    usint nBits    = m_params->GetModulus().GetLengthForBase(2);
    usint nWindows = nBits / baseBits;
    if (nBits % baseBits != 0)
        nWindows++;

    std::vector<DCRTPolyImpl<VecType>> result;
    result.reserve(nWindows);
    Integer twoPow(1);
    size_t size{m_vectors.size()};
    for (usint i = 0; i < nWindows; ++i) {
        DCRTPolyImpl<VecType> x(m_params, m_format);
        twoPow.LShiftEq(baseBits);
        for (size_t t = 0; t < size; ++t)
            x.m_vectors[t] = m_vectors[t] * twoPow.Mod(mods[t]).ConvertToInt();
        result.push_back(std::move(x));
    }
    return result;
}

template <typename VecType>
DCRTPolyImpl<VecType> DCRTPolyImpl<VecType>::AutomorphismTransform(uint32_t i) const {
    DCRTPolyImpl<VecType> result;
    result.m_format = m_format;
    result.m_params = m_params;
    result.m_vectors.reserve(m_vectors.size());
    for (auto& v : m_vectors)
        result.m_vectors.emplace_back(v.AutomorphismTransform(i));
    return result;
}

template <typename VecType>
DCRTPolyImpl<VecType> DCRTPolyImpl<VecType>::AutomorphismTransform(uint32_t i, const std::vector<uint32_t>& vec) const {
    DCRTPolyImpl<VecType> result;
    result.m_format = m_format;
    result.m_params = m_params;
    result.m_vectors.reserve(m_vectors.size());
    for (auto& v : m_vectors)
        result.m_vectors.emplace_back(v.AutomorphismTransform(i, vec));
    return result;
}

template <typename VecType>
DCRTPolyImpl<VecType> DCRTPolyImpl<VecType>::MultiplicativeInverse() const {
    DCRTPolyImpl<VecType> tmp(m_params, m_format);
    size_t size{m_vectors.size()};
    // TODO: figure out why this segfaults
    // #pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(size))
    for (size_t i = 0; i < size; ++i)
        tmp.m_vectors[i] = m_vectors[i].MultiplicativeInverse();
    return tmp;
}

template <typename VecType>
DCRTPolyImpl<VecType> DCRTPolyImpl<VecType>::Negate() const {
    DCRTPolyImpl<VecType> tmp(m_params, m_format);
    size_t size{m_vectors.size()};
#pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(size))
    for (size_t i = 0; i < size; ++i)
        tmp.m_vectors[i] = m_vectors[i].Negate();
    return tmp;
}

template <typename VecType>
DCRTPolyImpl<VecType> DCRTPolyImpl<VecType>::operator-() const {
    return DCRTPolyImpl<VecType>(m_params, m_format, true) -= *this;
}

template <typename VecType>
DCRTPolyImpl<VecType> DCRTPolyImpl<VecType>::Minus(const DCRTPolyImpl& rhs) const {
    if (m_vectors.size() != rhs.m_vectors.size())
        OPENFHE_THROW(math_error, "tower size mismatch; cannot subtract");
    DCRTPolyImpl<VecType> tmp(m_params, m_format);
    size_t size{m_vectors.size()};
#pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(size))
    for (size_t i = 0; i < size; ++i)
        tmp.m_vectors[i] = m_vectors[i].Minus(rhs.m_vectors[i]);
    return tmp;
}

template <typename VecType>
DCRTPolyImpl<VecType>& DCRTPolyImpl<VecType>::operator+=(const DCRTPolyImpl& rhs) {
    size_t size{m_vectors.size()};
#pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(size))
    for (size_t i = 0; i < size; ++i)
        m_vectors[i] += rhs.m_vectors[i];
    return *this;
}

template <typename VecType>
DCRTPolyImpl<VecType>& DCRTPolyImpl<VecType>::operator+=(const Integer& rhs) {
    NativeInteger val{rhs};
    size_t size{m_vectors.size()};
#pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(size))
    for (size_t i = 0; i < size; ++i)
        m_vectors[i] += val;
    return *this;
}

template <typename VecType>
DCRTPolyImpl<VecType>& DCRTPolyImpl<VecType>::operator+=(const NativeInteger& rhs) {
    size_t size{m_vectors.size()};
#pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(size))
    for (size_t i = 0; i < size; ++i)
        m_vectors[i] += rhs;
    return *this;
}

template <typename VecType>
DCRTPolyImpl<VecType>& DCRTPolyImpl<VecType>::operator-=(const DCRTPolyImpl& rhs) {
    size_t size{m_vectors.size()};
#pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(size))
    for (size_t i = 0; i < size; ++i)
        m_vectors[i] -= rhs.m_vectors[i];
    return *this;
}

template <typename VecType>
DCRTPolyImpl<VecType>& DCRTPolyImpl<VecType>::operator-=(const Integer& rhs) {
    NativeInteger val{rhs};
    size_t size{m_vectors.size()};
#pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(size))
    for (size_t i = 0; i < size; ++i)
        m_vectors[i] -= val;
    return *this;
}

template <typename VecType>
DCRTPolyImpl<VecType>& DCRTPolyImpl<VecType>::operator-=(const NativeInteger& rhs) {
    size_t size{m_vectors.size()};
#pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(size))
    for (size_t i = 0; i < size; ++i)
        m_vectors[i] -= rhs;
    return *this;
}

template <typename VecType>
bool DCRTPolyImpl<VecType>::operator==(const DCRTPolyImpl& rhs) const {
    return ((m_format == rhs.m_format) && (m_params->GetCyclotomicOrder() == rhs.m_params->GetCyclotomicOrder()) &&
            (m_params->GetModulus() == rhs.m_params->GetModulus()) && (m_vectors.size() == rhs.m_vectors.size()) &&
            (m_vectors == rhs.m_vectors));
}

template <typename VecType>
DCRTPolyImpl<VecType>& DCRTPolyImpl<VecType>::operator=(std::initializer_list<uint64_t> rhs) noexcept {
    static constexpr DCRTPolyImpl::PolyType::Integer ZERO(0);
    const size_t llen = rhs.size();
    const size_t vlen = m_params->GetRingDimension();
    for (auto& v : m_vectors) {
        if (v.IsEmpty()) {
            NativeVector temp(vlen);
            temp.SetModulus(v.GetModulus());
            v.SetValues(std::move(temp), m_format);
        }
        for (size_t j = 0; j < vlen; ++j)
            v[j] = (j < llen) ? *(rhs.begin() + j) : ZERO;
    }
    return *this;
}

template <typename VecType>
DCRTPolyImpl<VecType>& DCRTPolyImpl<VecType>::operator=(std::initializer_list<std::string> rhs) noexcept {
    static constexpr DCRTPolyImpl::PolyType::Integer ZERO(0);
    const size_t llen = rhs.size();
    const size_t vlen = m_params->GetRingDimension();
    for (auto& v : m_vectors) {
        if (v.IsEmpty()) {
            NativeVector temp(vlen);
            temp.SetModulus(v.GetModulus());
            v.SetValues(std::move(temp), m_format);
        }
        for (size_t j = 0; j < vlen; ++j)
            v[j] = (j < llen) ? *(rhs.begin() + j) : ZERO;
    }
    return *this;
}

// Used only inside a Matrix object; so an allocator already initializes the values
template <typename VecType>
DCRTPolyImpl<VecType>& DCRTPolyImpl<VecType>::operator=(uint64_t val) noexcept {
    for (auto& v : m_vectors)
        v = val;
    return *this;
}

// Used only inside a Matrix object; so an allocator already initializes the values
template <typename VecType>
DCRTPolyImpl<VecType>& DCRTPolyImpl<VecType>::operator=(const std::vector<int64_t>& val) noexcept {
    for (auto& v : m_vectors) {
        if (v.IsEmpty()) {
            NativeVector temp(m_params->GetRingDimension());
            temp.SetModulus(v.GetModulus());
            v.SetValues(std::move(temp), m_format);
        }
        v = val;
    }
    m_format = Format::COEFFICIENT;
    return *this;
}

// Used only inside a Matrix object; so an allocator already initializes the values
template <typename VecType>
DCRTPolyImpl<VecType>& DCRTPolyImpl<VecType>::operator=(const std::vector<int32_t>& val) noexcept {
    for (auto& v : m_vectors) {
        if (v.IsEmpty()) {
            NativeVector temp(m_params->GetRingDimension());
            temp.SetModulus(v.GetModulus());
            v.SetValues(std::move(temp), m_format);
        }
        v = val;
    }
    m_format = Format::COEFFICIENT;
    return *this;
}

template <typename VecType>
DCRTPolyImpl<VecType> DCRTPolyImpl<VecType>::Plus(const Integer& rhs) const {
    NativeInteger val{rhs};
    DCRTPolyImpl<VecType> tmp(m_params, m_format);
    size_t size{m_vectors.size()};
#pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(size))
    for (size_t i = 0; i < size; ++i)
        tmp.m_vectors[i] = m_vectors[i].Plus(val);
    return tmp;
}

template <typename VecType>
DCRTPolyImpl<VecType> DCRTPolyImpl<VecType>::Plus(const std::vector<Integer>& crtElement) const {
    DCRTPolyImpl<VecType> tmp(m_params, m_format);
    size_t size{m_vectors.size()};
#pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(size))
    for (size_t i = 0; i < size; ++i)
        tmp.m_vectors[i] = m_vectors[i].Plus(NativeInteger(crtElement[i]));
    return tmp;
}

template <typename VecType>
DCRTPolyImpl<VecType> DCRTPolyImpl<VecType>::Minus(const Integer& rhs) const {
    NativeInteger val{rhs};
    DCRTPolyImpl<VecType> tmp(m_params, m_format);
    size_t size{m_vectors.size()};
#pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(size))
    for (size_t i = 0; i < size; ++i)
        tmp.m_vectors[i] = m_vectors[i].Minus(val);
    return tmp;
}

template <typename VecType>
DCRTPolyImpl<VecType> DCRTPolyImpl<VecType>::Minus(const std::vector<Integer>& crtElement) const {
    DCRTPolyImpl<VecType> tmp(m_params, m_format);
    size_t size{m_vectors.size()};
#pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(size))
    for (size_t i = 0; i < size; ++i)
        tmp.m_vectors[i] = m_vectors[i].Minus(NativeInteger(crtElement[i]));
    return tmp;
}

template <typename VecType>
DCRTPolyImpl<VecType> DCRTPolyImpl<VecType>::Times(const Integer& rhs) const {
    NativeInteger val{rhs};
    DCRTPolyImpl<VecType> tmp(m_params, m_format);
    size_t size{m_vectors.size()};
#pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(size))
    for (size_t i = 0; i < size; ++i)
        tmp.m_vectors[i] = m_vectors[i].Times(val);
    return tmp;
}

template <typename VecType>
DCRTPolyImpl<VecType> DCRTPolyImpl<VecType>::Times(NativeInteger::SignedNativeInt rhs) const {
    DCRTPolyImpl<VecType> tmp(m_params, m_format);
    size_t size{m_vectors.size()};
#pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(size))
    for (size_t i = 0; i < size; ++i)
        tmp.m_vectors[i] = m_vectors[i].Times(rhs);
    return tmp;
}

template <typename VecType>
DCRTPolyImpl<VecType> DCRTPolyImpl<VecType>::Times(const std::vector<Integer>& crtElement) const {
    DCRTPolyImpl<VecType> tmp(m_params, m_format);
    size_t size{m_vectors.size()};
#pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(size))
    for (size_t i = 0; i < size; ++i)
        tmp.m_vectors[i] = m_vectors[i].Times(NativeInteger(crtElement[i]));
    return tmp;
}

template <typename VecType>
DCRTPolyImpl<VecType> DCRTPolyImpl<VecType>::Times(const std::vector<NativeInteger>& rhs) const {
    if (m_vectors.size() != rhs.size())
        OPENFHE_THROW(math_error, "tower size mismatch; cannot multiply");
    DCRTPolyImpl<VecType> tmp(m_params, m_format);
    size_t size{m_vectors.size()};
#pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(size))
    for (size_t i = 0; i < size; ++i)
        tmp.m_vectors[i] = m_vectors[i].Times(rhs[i]);
    return tmp;
}

template <typename VecType>
DCRTPolyImpl<VecType> DCRTPolyImpl<VecType>::TimesNoCheck(const std::vector<NativeInteger>& rhs) const {
    size_t vecSize = m_vectors.size() < rhs.size() ? m_vectors.size() : rhs.size();
    DCRTPolyImpl<VecType> tmp(m_params, m_format);
#pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(vecSize))
    for (size_t i = 0; i < vecSize; ++i)
        tmp.m_vectors[i] = m_vectors[i].Times(rhs[i]);
    return tmp;
}

template <typename VecType>
DCRTPolyImpl<VecType>& DCRTPolyImpl<VecType>::operator*=(const Integer& rhs) {
    NativeInteger val{rhs};
    size_t size{m_vectors.size()};
#pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(size))
    for (size_t i = 0; i < size; ++i)
        m_vectors[i] *= val;
    return *this;
}

template <typename VecType>
DCRTPolyImpl<VecType>& DCRTPolyImpl<VecType>::operator*=(const NativeInteger& rhs) {
    size_t size{m_vectors.size()};
#pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(size))
    for (size_t i = 0; i < size; ++i)
        m_vectors[i] *= rhs;
    return *this;
}

template <typename VecType>
void DCRTPolyImpl<VecType>::SetValuesToZero() {
    size_t size{m_vectors.size()};
    for (size_t i = 0; i < size; ++i)
        m_vectors[i].SetValuesToZero();
}

template <typename VecType>
void DCRTPolyImpl<VecType>::SetValuesModSwitch(const DCRTPolyImpl& element, const NativeInteger& modulus) {
    if (element.GetNumOfElements() != 1) {
        OPENFHE_THROW(not_implemented_error, "SetValuesModSwitch is implemented only for a DCRTPoly with one tower.");
    }

    auto Q             = element.GetModulus();
    double Qmod_double = modulus.ConvertToDouble() / Q.ConvertToDouble();
    this->m_params->SetOriginalModulus(modulus);

    auto input{element.GetElementAtIndex(0)};
    input.SetFormat(Format::COEFFICIENT);

    size_t size{m_vectors.size()};
    size_t N_elem(element.m_params->GetRingDimension());
    size_t N(this->GetRingDimension());

    if (N_elem > N)
        OPENFHE_THROW(
            not_available_error,
            "The ring dimension of the element to copy is larger than the ring dimension of the element to copy to.");

    for (size_t i = 0; i < size; ++i) {
        NativeVector tmp(N);
        tmp.SetModulus(modulus);

        for (size_t j = 0; j < N_elem; ++j) {
            tmp[j] =
                Integer(static_cast<uint64_t>(std::floor(0.5 + input[j].ConvertToDouble() * Qmod_double))).Mod(modulus);
        }
        m_vectors[i].SetValues(std::move(tmp), Format::COEFFICIENT);
    }
}

template <typename VecType>
void DCRTPolyImpl<VecType>::AddILElementOne() {
    if (m_format != Format::EVALUATION)
        OPENFHE_THROW(not_available_error, "Cannot call AddILElementOne() on DCRTPoly in COEFFICIENT format.");
    size_t size{m_vectors.size()};
#pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(size))
    for (size_t i = 0; i < size; ++i)
        m_vectors[i].AddILElementOne();
}

template <typename VecType>
bool DCRTPolyImpl<VecType>::IsEmpty() const {
    for (auto& v : m_vectors) {
        if (!v.IsEmpty())
            return false;
    }
    return true;
}

template <typename VecType>
void DCRTPolyImpl<VecType>::DropLastElement() {
    if (m_vectors.size() == 0)
        OPENFHE_THROW(config_error, "Input has no elements to drop!");
    if (m_vectors.size() == 1)
        OPENFHE_THROW(config_error, "Removing last element of DCRTPoly object renders it invalid!");
    m_vectors.resize(m_vectors.size() - 1);
    DCRTPolyImpl::Params* newP = new DCRTPolyImpl::Params(*m_params);
    newP->PopLastParam();
    m_params.reset(newP);
}

template <typename VecType>
void DCRTPolyImpl<VecType>::DropLastElements(size_t i) {
    if (m_vectors.size() <= i) {
        OPENFHE_THROW(config_error,
                      "There are not enough towers in the current ciphertext to "
                      "perform the modulus reduction");
    }
    m_vectors.resize(m_vectors.size() - i);
    DCRTPolyImpl::Params* newP = new DCRTPolyImpl::Params(*m_params);
    for (size_t j = 0; j < i; j++)
        newP->PopLastParam();
    m_params.reset(newP);
}

// used for CKKS rescaling
template <typename VecType>
void DCRTPolyImpl<VecType>::DropLastElementAndScale(const std::vector<NativeInteger>& QlQlInvModqlDivqlModq,
                                                    const std::vector<NativeInteger>& QlQlInvModqlDivqlModqPrecon,
                                                    const std::vector<NativeInteger>& qlInvModq,
                                                    const std::vector<NativeInteger>& qlInvModqPrecon) {
    // TODO: move this inside loop if omp enabled
    auto lastPoly(m_vectors.back());
    lastPoly.SetFormat(Format::COEFFICIENT);
    this->DropLastElement();
    size_t size{m_vectors.size()};

#pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(size))
    for (size_t i = 0; i < size; ++i) {
        auto tmp = lastPoly;
        tmp.SwitchModulus(m_vectors[i].GetModulus(), m_vectors[i].GetRootOfUnity(), 0, 0);
        tmp *= QlQlInvModqlDivqlModq[i];
        if (m_format == Format::EVALUATION)
            tmp.SwitchFormat();
        m_vectors[i] *= qlInvModq[i];
        m_vectors[i] += tmp;
        if (m_format == Format::COEFFICIENT)
            m_vectors[i].SwitchFormat();
    }
}

/**
* Used for BGVrns modulus switching
* This function performs ModReduce on ciphertext element and private key
element. The algorithm computes ct' <- round( ct/qt ).

* Modulus reduction reduces a ciphertext from modulus q to a smaller modulus
q/qt where qt is generally the last moduli of the tower.
* ModReduce is written for DCRTPolyImpl and it drops the last tower while
updating the necessary parameters.

* The rounding is actually computed as a flooring by computing delta such that
delta = -ct mod qt and delta = 0 [t]

* The steps taken here are as follows:
* 1. compute delta <- -ct/ptm mod qt
* 2. compute delta <- ptm*delta in Z. E.g., all of delta's integer coefficients
can be in the range [-ptm*qt/2, ptm*qt/2).
* 3. let d' = c + delta mod q/qt. By construction, d' is divisible by qt and
congruent to 0 mod ptm.
* 4. output (d'/q') in R(q/q').
*/
template <typename VecType>
void DCRTPolyImpl<VecType>::ModReduce(const NativeInteger& t, const std::vector<NativeInteger>& tModqPrecon,
                                      const NativeInteger& negtInvModq, const NativeInteger& negtInvModqPrecon,
                                      const std::vector<NativeInteger>& qlInvModq,
                                      const std::vector<NativeInteger>& qlInvModqPrecon) {
    // TODO: move this inside loop if omp enabled
    DCRTPolyImpl::PolyType delta(m_vectors.back());
    delta.SetFormat(Format::COEFFICIENT);
    delta *= negtInvModq;
    this->DropLastElement();
    size_t size{m_vectors.size()};

#pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(size))
    for (size_t i = 0; i < size; ++i) {
        auto tmp{delta};
        tmp.SwitchModulus(m_vectors[i].GetModulus(), m_vectors[i].GetRootOfUnity(), 0, 0);
        if (m_format == Format::EVALUATION)
            tmp.SwitchFormat();
        m_vectors[i] += (tmp *= t);
        m_vectors[i] *= qlInvModq[i];
    }
}

/* methods to access individual members of the DCRTPolyImpl. Result is
 * Interpolated value at that point.  Note this is a very costly compute
 * intensive operation meant basically for debugging code.
 */
template <typename VecType>
typename VecType::Integer& DCRTPolyImpl<VecType>::at(usint i) {
    if (0 == m_vectors.size())
        OPENFHE_THROW(math_error, "No values in DCRTPolyImpl");
    if (i >= m_vectors.size())
        OPENFHE_THROW(math_error, "out of range in  DCRTPolyImpl.at()");
    return CRTInterpolateIndex(i)[i];
}

template <typename VecType>
const typename VecType::Integer& DCRTPolyImpl<VecType>::at(usint i) const {
    if (0 == m_vectors.size())
        OPENFHE_THROW(math_error, "No values in DCRTPolyImpl");
    if (i >= m_vectors.size())
        OPENFHE_THROW(math_error, "out of range in  DCRTPolyImpl.at()");
    return CRTInterpolateIndex(i)[i];
}

/*
 * This method applies the Chinese Remainder Interpolation on an DCRTPolyImpl
 * and produces an Poly How the Algorithm works: Consider the DCRTPolyImpl as
 * a 2-dimensional matrix M, with dimension ringDimension * Number of Towers.
 * For brevity , lets say this is r * t Let qt denote the bigModulus (all the
 * towers' moduli multiplied together) and qi denote the modulus of a
 * particular tower. Let V be a BigVector of size tower (tower size). Each
 * coefficient of V is calculated as follows: for every r calculate: V[j]=
 * {Sigma(i = 0 --> t-1) ValueOf M(r,i) * qt/qi *[ (qt/qi)^(-1) mod qi ]}mod
 * qt
 *
 * Once we have the V values, we construct an Poly from V, use qt as it's
 * modulus, and calculate a root of unity for parameter selection of the Poly.
 */
template <typename VecType>
typename DCRTPolyImpl<VecType>::PolyLargeType DCRTPolyImpl<VecType>::CRTInterpolate() const {
    usint ringDimension = m_params->GetRingDimension();
    usint nTowers       = m_vectors.size();

    Integer bigModulus(m_params->GetModulus());  // qT

    // this is the resulting vector of coefficients
    VecType coefficients(ringDimension, bigModulus);

    // this will finally be  V[j]= {Sigma(i = 0 --> t-1) ValueOf M(r,i) * qt/qj
    // *[ (qt/qj)^(-1) mod qj ]}modqt

    // first, precompute qt/qj factors
    std::vector<Integer> multiplier(nTowers);
    for (usint vi = 0; vi < nTowers; vi++) {
        Integer qj(m_vectors[vi].GetModulus().ConvertToInt());
        Integer divBy  = bigModulus / qj;
        Integer modInv = divBy.ModInverse(qj).Mod(qj);
        multiplier[vi] = divBy * modInv;
    }

    // if the vectors are not in COEFFICIENT form, they need to be, so we will
    // need to make a copy of them and switchformat on them... otherwise we can
    // just use what we have

    const std::vector<DCRTPolyImpl::PolyType>* vecs = &m_vectors;
    std::vector<DCRTPolyImpl::PolyType> coeffVecs;
    if (m_format == Format::EVALUATION) {
        for (size_t i = 0; i < m_vectors.size(); i++) {
            DCRTPolyImpl::PolyType vecCopy(m_vectors[i]);
            vecCopy.SetFormat(Format::COEFFICIENT);
            coeffVecs.push_back(std::move(vecCopy));
        }
        vecs = std::move(&coeffVecs);
    }

    // Precompute the Barrett mu parameter
    Integer mu = bigModulus.ComputeMu();

    // now, compute the values for the vector
    for (usint ri = 0; ri < ringDimension; ri++) {
        coefficients[ri] = 0;
        for (usint vi = 0; vi < nTowers; vi++) {
            coefficients[ri] += (Integer((*vecs)[vi].GetValues()[ri].ConvertToInt()) * multiplier[vi]);
        }
        coefficients[ri].ModEq(bigModulus, mu);
    }

    // Setting the root of unity to ONE as the calculation is expensive and not required.
    DCRTPolyImpl<VecType>::PolyLargeType polynomialReconstructed(
        std::make_shared<ILParamsImpl<Integer>>(m_params->GetCyclotomicOrder(), bigModulus, 1));
    polynomialReconstructed.SetValues(std::move(coefficients), Format::COEFFICIENT);

    return polynomialReconstructed;
}

/*
 * This method applies the Chinese Remainder Interpolation on a
 * single element across all towers of a DCRTPolyImpl and produces an Poly
 * with zeros except at that single element
 * How the Algorithm works:
 * Consider the DCRTPolyImpl as a 2-dimensional matrix M, with dimension
 * ringDimension * Number of Towers. For brevity , lets say this is r * t Let
 * qt denote the bigModulus (all the towers' moduli multiplied together) and
 * qi denote the modulus of a particular tower. Let V be a BigVector of size
 * tower (tower size). Each coefficient of V is calculated as follows: for
 * every r calculate: V[j]= {Sigma(i = 0 --> t-1) ValueOf M(r,i) * qt/qi *[
 * (qt/qi)^(-1) mod qi ]}mod qt
 *
 * Once we have the V values, we construct an Poly from V, use qt as it's
 * modulus, and calculate a root of unity for parameter selection of the Poly.
 */
template <typename VecType>
typename DCRTPolyImpl<VecType>::PolyLargeType DCRTPolyImpl<VecType>::CRTInterpolateIndex(usint i) const {
    usint ringDimension = m_params->GetRingDimension();
    usint nTowers       = m_vectors.size();
    Integer bigModulus(m_params->GetModulus());  // qT

    VecType coefficients(ringDimension, bigModulus);

    std::vector<Integer> multiplier(nTowers);
    for (usint vi = 0; vi < nTowers; vi++) {
        Integer qj(m_vectors[vi].GetModulus().ConvertToInt());
        Integer divBy  = bigModulus / qj;
        Integer modInv = divBy.ModInverse(qj).Mod(qj);
        multiplier[vi] = divBy * modInv;
    }

    // if the vectors are not in COEFFICIENT form, they need to be, so we will
    // need to make a copy of them and switchformat on them... otherwise we can
    // just use what we have
    const std::vector<DCRTPolyImpl::PolyType>* vecs = &m_vectors;
    std::vector<DCRTPolyImpl::PolyType> coeffVecs;
    if (m_format == Format::EVALUATION) {
        for (size_t ii = 0; ii < m_vectors.size(); ii++) {
            PolyType vecCopy(m_vectors[ii]);
            vecCopy.SetFormat(Format::COEFFICIENT);
            coeffVecs.push_back(std::move(vecCopy));
        }
        vecs = &coeffVecs;
    }

    // Precompute the Barrett mu parameter
    Integer mu = bigModulus.ComputeMu();

    // now, compute the value for the vector at element i

    for (usint ri = 0; ri < ringDimension; ri++) {
        coefficients[ri] = 0;
        if (ri == i) {
            for (usint vi = 0; vi < nTowers; vi++) {
                coefficients[ri] += (Integer((*vecs)[vi].GetValues()[ri].ConvertToInt()) * multiplier[vi]);
            }
            coefficients[ri].ModEq(bigModulus, mu);
        }
    }

    DCRTPolyImpl<VecType>::PolyLargeType polynomialReconstructed(
        std::make_shared<ILParamsImpl<Integer>>(m_params->GetCyclotomicOrder(), bigModulus, 1));
    polynomialReconstructed.SetValues(std::move(coefficients), Format::COEFFICIENT);
    return polynomialReconstructed;
}

// todo can we be smarter with this method?
template <typename VecType>
typename DCRTPolyImpl<VecType>::PolyType DCRTPolyImpl<VecType>::DecryptionCRTInterpolate(PlaintextModulus ptm) const {
    return this->CRTInterpolate().DecryptionCRTInterpolate(ptm);
}

// todo can we be smarter with this method?
template <typename VecType>
typename DCRTPolyImpl<VecType>::PolyType DCRTPolyImpl<VecType>::ToNativePoly() const {
    return this->CRTInterpolate().ToNativePoly();
}

template <typename VecType>
typename VecType::Integer DCRTPolyImpl<VecType>::GetWorkingModulus() const {
    typename VecType::Integer modulusQ = 1;
    for (auto& p : m_params->GetParams())
        modulusQ.MulEq(p->GetModulus());
    return modulusQ;
}

template <typename VecType>
std::shared_ptr<typename DCRTPolyImpl<VecType>::Params> DCRTPolyImpl<VecType>::GetExtendedCRTBasis(
    const std::shared_ptr<Params>& paramsP) const {
    usint sizeQ  = m_vectors.size();
    usint sizeP  = paramsP->GetParams().size();
    usint sizeQP = sizeQ + sizeP;

    std::vector<NativeInteger> moduliQP(sizeQP);
    std::vector<NativeInteger> rootsQP(sizeQP);
    for (usint i = 0; i < sizeQ; i++) {
        moduliQP[i] = m_params->GetParams()[i]->GetModulus();
        rootsQP[i]  = m_params->GetParams()[i]->GetRootOfUnity();
    }
    for (usint i = sizeQ, j = 0; i < sizeQP; i++, j++) {
        moduliQP[i] = paramsP->GetParams()[j]->GetModulus();
        rootsQP[i]  = paramsP->GetParams()[j]->GetRootOfUnity();
    }
    return std::make_shared<Params>(2 * m_params->GetRingDimension(), moduliQP, rootsQP);
}

template <typename VecType>
void DCRTPolyImpl<VecType>::TimesQovert(const std::shared_ptr<Params>& paramsQ,
                                        const std::vector<NativeInteger>& tInvModq, const NativeInteger& t,
                                        const NativeInteger& NegQModt, const NativeInteger& NegQModtPrecon) {
    if (tInvModq.size() < m_vectors.size())
        OPENFHE_THROW(math_error, "Sizes of vectors do not match.");
    uint32_t size(m_vectors.size());
    uint32_t ringDim(m_params->GetRingDimension());
#pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(size))
    for (size_t i = 0; i < size; ++i) {
        for (uint32_t ri = 0; ri < ringDim; ++ri) {
            NativeInteger& xi = m_vectors[i][ri];
            xi.ModMulFastConstEq(NegQModt, t, NegQModtPrecon);
        }
        // TODO: move this inside ri loop
        m_vectors[i] = m_vectors[i].Times(tInvModq[i]);
    }
}

template <typename VecType>
DCRTPolyImpl<VecType> DCRTPolyImpl<VecType>::ApproxSwitchCRTBasis(
    const std::shared_ptr<Params>& paramsQ, const std::shared_ptr<Params>& paramsP,
    const std::vector<NativeInteger>& QHatInvModq, const std::vector<NativeInteger>& QHatInvModqPrecon,
    const std::vector<std::vector<NativeInteger>>& QHatModp, const std::vector<DoubleNativeInt>& modpBarrettMu) const {
#if defined(HAVE_INT128) && NATIVEINT == 64
    DCRTPolyImpl<VecType> ans(paramsP, m_format, true);

    usint ringDim = m_params->GetRingDimension();
    usint sizeQ   = (m_vectors.size() > paramsQ->GetParams().size()) ? paramsQ->GetParams().size() : m_vectors.size();
    usint sizeP   = ans.m_vectors.size();

    #pragma omp parallel for
    for (usint ri = 0; ri < ringDim; ri++) {
        std::vector<DoubleNativeInt> sum(sizeP);
        for (usint i = 0; i < sizeQ; i++) {
            const NativeInteger& xi     = m_vectors[i][ri];
            const NativeInteger& qi     = m_vectors[i].GetModulus();
            NativeInteger xQHatInvModqi = xi.ModMulFastConst(QHatInvModq[i], qi, QHatInvModqPrecon[i]);
            for (usint j = 0; j < sizeP; j++) {
                sum[j] += Mul128(xQHatInvModqi.ConvertToInt(), QHatModp[i][j].ConvertToInt());
            }
        }

        for (usint j = 0; j < sizeP; j++) {
            const NativeInteger& pj = ans.m_vectors[j].GetModulus();
            ans.m_vectors[j][ri]    = BarrettUint128ModUint64(sum[j], pj.ConvertToInt(), modpBarrettMu[j]);
        }
    }
    return ans;
}

#else
    DCRTPolyImpl<VecType> ans(paramsP, m_format, true);

    usint sizeQ = (m_vectors.size() > paramsQ->GetParams().size()) ? paramsQ->GetParams().size() : m_vectors.size();
    usint sizeP = ans.m_vectors.size();

    for (usint i = 0; i < sizeQ; i++) {
        auto xQHatInvModqi = m_vectors[i] * QHatInvModq[i];
    #pragma omp parallel for
        for (usint j = 0; j < sizeP; j++) {
            auto temp = xQHatInvModqi;
            temp.SwitchModulus(ans.m_vectors[j].GetModulus(), ans.m_vectors[j].GetRootOfUnity(), 0, 0);
            ans.m_vectors[j] += (temp *= QHatModp[i][j]);
        }
    }
    return ans;
}
#endif

template <typename VecType>
void DCRTPolyImpl<VecType>::ApproxModUp(const std::shared_ptr<Params>& paramsQ, const std::shared_ptr<Params>& paramsP,
                                        const std::shared_ptr<Params>& paramsQP,
                                        const std::vector<NativeInteger>& QHatInvModq,
                                        const std::vector<NativeInteger>& QHatInvModqPrecon,
                                        const std::vector<std::vector<NativeInteger>>& QHatModp,
                                        const std::vector<DoubleNativeInt>& modpBarrettMu) {
    std::vector<DCRTPolyImpl::PolyType> polyInNTT;
    // if the input polynomial is in evaluation representation, store it for
    // later use to reduce the number of NTTs
    if (m_format == Format::EVALUATION) {
        polyInNTT = m_vectors;
        this->SetFormat(Format::COEFFICIENT);
    }

    usint sizeQ  = m_vectors.size();
    usint sizeP  = paramsP->GetParams().size();
    usint sizeQP = paramsQP->GetParams().size();

    DCRTPolyType partP =
        ApproxSwitchCRTBasis(paramsQ, paramsP, QHatInvModq, QHatInvModqPrecon, QHatModp, modpBarrettMu);

    m_vectors.resize(sizeQP);

#pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(sizeP))
    // populate the towers corresponding to CRT basis P and convert them to
    // evaluation representation
    for (size_t j = 0; j < sizeP; j++) {
        m_vectors[sizeQ + j] = partP.m_vectors[j];
        m_vectors[sizeQ + j].SetFormat(Format::EVALUATION);
    }
    // if the input polynomial was in evaluation representation, use the towers
    // for Q from it
    if (polyInNTT.size() > 0) {
        for (size_t i = 0; i < sizeQ; i++) {
            m_vectors[i] = polyInNTT[i];
        }
    }
    else {
// else call NTT for the towers for Q
#pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(sizeQ))
        for (size_t i = 0; i < sizeQ; ++i) {
            m_vectors[i].SwitchFormat();
        }
    }
    m_format = Format::EVALUATION;
    m_params = paramsQP;
}

template <typename VecType>
DCRTPolyImpl<VecType> DCRTPolyImpl<VecType>::ApproxModDown(
    const std::shared_ptr<Params>& paramsQ, const std::shared_ptr<Params>& paramsP,
    const std::vector<NativeInteger>& PInvModq, const std::vector<NativeInteger>& PInvModqPrecon,
    const std::vector<NativeInteger>& PHatInvModp, const std::vector<NativeInteger>& PHatInvModpPrecon,
    const std::vector<std::vector<NativeInteger>>& PHatModq, const std::vector<DoubleNativeInt>& modqBarrettMu,
    const std::vector<NativeInteger>& tInvModp, const std::vector<NativeInteger>& tInvModpPrecon,
    const NativeInteger& t, const std::vector<NativeInteger>& tModqPrecon) const {
    usint sizeQP = m_vectors.size();
    usint sizeP  = paramsP->GetParams().size();
    usint sizeQ  = sizeQP - sizeP;

    DCRTPolyImpl<VecType> partP(paramsP, m_format, true);

#pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(sizeP))
    for (usint j = 0; j < sizeP; ++j) {
        partP.m_vectors[j] = m_vectors[sizeQ + j];
        partP.m_vectors[j].SetFormat(Format::COEFFICIENT);
        // Multiply everything by -t^(-1) mod P (BGVrns only)
        if (t > 0)
            partP.m_vectors[j] *= tInvModp[j];
    }
    partP.OverrideFormat(Format::COEFFICIENT);

    DCRTPolyImpl<VecType> partPSwitchedToQ =
        partP.ApproxSwitchCRTBasis(paramsP, paramsQ, PHatInvModp, PHatInvModpPrecon, PHatModq, modqBarrettMu);

    // Combine the switched DCRTPoly with the Q part of this to get the result
    DCRTPolyImpl<VecType> ans(paramsQ, Format::EVALUATION, true);
    uint32_t diffQ = paramsQ->GetParams().size() - sizeQ;
    if (diffQ > 0)
        ans.DropLastElements(diffQ);

#pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(sizeQ))
    for (usint i = 0; i < sizeQ; ++i) {
        // Multiply everything by t mod Q (BGVrns only)
        if (t > 0)
            partPSwitchedToQ.m_vectors[i] *= t;
        partPSwitchedToQ.m_vectors[i].SetFormat(Format::EVALUATION);
        ans.m_vectors[i] = (m_vectors[i] - partPSwitchedToQ.m_vectors[i]) * PInvModq[i];
    }
    return ans;
}

template <typename VecType>
DCRTPolyImpl<VecType> DCRTPolyImpl<VecType>::SwitchCRTBasis(const std::shared_ptr<Params>& paramsP,
                                                            const std::vector<NativeInteger>& QHatInvModq,
                                                            const std::vector<NativeInteger>& QHatInvModqPrecon,
                                                            const std::vector<std::vector<NativeInteger>>& QHatModp,
                                                            const std::vector<std::vector<NativeInteger>>& alphaQModp,
                                                            const std::vector<DoubleNativeInt>& modpBarrettMu,
                                                            const std::vector<double>& qInv) const {
#if defined(HAVE_INT128) && NATIVEINT == 64
    DCRTPolyImpl<VecType> ans(paramsP, m_format, true);
    usint ringDim = m_params->GetRingDimension();
    usint sizeQ   = m_vectors.size();
    usint sizeP   = ans.m_vectors.size();

    #pragma omp parallel for
    for (usint ri = 0; ri < ringDim; ri++) {
        std::vector<NativeInteger> xQHatInvModq(sizeQ);
        double nu{0.5};

        // Compute alpha and vector of x_i terms
        for (usint i = 0; i < sizeQ; i++) {
            const NativeInteger& qi = m_vectors[i].GetModulus();
            // computes [x_i (Q/q_i)^{-1}]_{q_i}
            xQHatInvModq[i] = m_vectors[i][ri].ModMulFastConst(QHatInvModq[i], qi, QHatInvModqPrecon[i]);
            // computes [x_i (Q/q_i)^{-1}]_{q_i} / q_i
            // to keep track of the number of q-overflows
            nu += xQHatInvModq[i].ConvertToDouble() * qInv[i];
        }

        // alpha corresponds to the number of overflows, 0 <= alpha <= sizeQ
        usint alpha = static_cast<usint>(nu);

        const std::vector<NativeInteger>& alphaQModpri = alphaQModp[alpha];

        for (usint j = 0; j < sizeP; j++) {
            DoubleNativeInt curValue = 0;

            const NativeInteger& pj                     = ans.m_vectors[j].GetModulus();
            const std::vector<NativeInteger>& QHatModpj = QHatModp[j];
            // first round - compute "fast conversion"
            for (usint i = 0; i < sizeQ; i++) {
                curValue += Mul128(xQHatInvModq[i].ConvertToInt(), QHatModpj[i].ConvertToInt());
            }

            const NativeInteger& curNativeValue =
                NativeInteger(BarrettUint128ModUint64(curValue, pj.ConvertToInt(), modpBarrettMu[j]));

            // second round - remove q-overflows
            ans.m_vectors[j][ri] = curNativeValue.ModSubFast(alphaQModpri[j], pj);
        }
    }

    return ans;
}

#else
    DCRTPolyImpl<VecType> ans(paramsP, m_format, true);

    usint ringDim = m_params->GetRingDimension();
    usint sizeQ   = m_vectors.size();
    usint sizeP   = ans.m_vectors.size();

    if (sizeQ == 0)
        OPENFHE_THROW(config_error, "sizeQ must be positive");
    if (sizeP == 0)
        OPENFHE_THROW(config_error, "sizeP must be positive");
    if (QHatInvModq.size() < sizeQ)
        OPENFHE_THROW(config_error, "Size of QHatInvModq " + std::to_string(QHatInvModq.size()) +
                                        " is less than sizeQ " + std::to_string(sizeQ));
    if (QHatInvModqPrecon.size() < sizeQ)
        OPENFHE_THROW(config_error, "Size of QHatInvModqPrecon " + std::to_string(QHatInvModqPrecon.size()) +
                                        " is less than sizeQ " + std::to_string(sizeQ));
    if (qInv.size() < sizeQ)
        OPENFHE_THROW(config_error,
                      "Size of qInv " + std::to_string(qInv.size()) + " is less than sizeQ " + std::to_string(sizeQ));
    if (alphaQModp.size() < sizeQ + 1)
        OPENFHE_THROW(config_error, "Size of alphaQModp " + std::to_string(alphaQModp.size()) +
                                        " is less than sizeQ + 1 " + std::to_string(sizeQ + 1));
    if (alphaQModp[0].size() < sizeP)
        OPENFHE_THROW(config_error, "Size of alphaQModp[0] " + std::to_string(alphaQModp[0].size()) +
                                        " is less than sizeP " + std::to_string(sizeP));
    if (QHatModp.size() < sizeP)
        OPENFHE_THROW(config_error, "Size of QHatModp " + std::to_string(QHatModp.size()) + " is less than sizeP " +
                                        std::to_string(sizeP));
    if (QHatModp[0].size() < sizeQ)
        OPENFHE_THROW(config_error, "Size of QHatModp[0] " + std::to_string(QHatModp[0].size()) +
                                        " is less than sizeQ " + std::to_string(sizeQ));

    #pragma omp parallel for
    for (usint ri = 0; ri < ringDim; ri++) {
        std::vector<NativeInteger> xQHatInvModq(sizeQ);
        double nu = 0.5;

        // Compute alpha and vector of x_i terms
        for (usint i = 0; i < sizeQ; i++) {
            //      const NativeInteger &xi = m_vectors[i][ri];
            const NativeInteger& qi = m_vectors[i].GetModulus();

            // computes [x_i (Q/q_i)^{-1}]_{q_i}
            xQHatInvModq[i] = m_vectors[i][ri].ModMulFastConst(QHatInvModq[i], qi, QHatInvModqPrecon[i]);

            // computes [x_i (Q/q_i)^{-1}]_{q_i} / q_i
            // to keep track of the number of q-overflows
            nu += xQHatInvModq[i].ConvertToDouble() * qInv[i];
        }

        // alpha corresponds to the number of overflows, 0 <= alpha <= sizeQ
        usint alpha = static_cast<usint>(nu);

        const std::vector<NativeInteger>& alphaQModpri = alphaQModp[alpha];

        std::vector<NativeInteger> mu(sizeP);
        for (usint j = 0; j < sizeP; j++) {
            mu[j] = ans.m_vectors[j].GetModulus().ComputeMu();
        }

        for (usint j = 0; j < sizeP; j++) {
            const NativeInteger& pj                     = ans.m_vectors[j].GetModulus();
            const std::vector<NativeInteger>& QHatModpj = QHatModp[j];
            // first round - compute "fast conversion"
            for (usint i = 0; i < sizeQ; i++) {
                ans.m_vectors[j][ri].ModAddFastEq(xQHatInvModq[i].ModMulFast(QHatModpj[i], pj, mu[j]), pj);
            }

            // second round - remove q-overflows
            ans.m_vectors[j][ri].ModSubFastEq(alphaQModpri[j], pj);
        }
    }

    return ans;
}
#endif

template <typename VecType>
void DCRTPolyImpl<VecType>::ExpandCRTBasis(
    const std::shared_ptr<Params>& paramsQP, const std::shared_ptr<Params>& paramsP,
    const std::vector<NativeInteger>& QHatInvModq, const std::vector<NativeInteger>& QHatInvModqPrecon,
    const std::vector<std::vector<NativeInteger>>& QHatModp, const std::vector<std::vector<NativeInteger>>& alphaQModp,
    const std::vector<DoubleNativeInt>& modpBarrettMu, const std::vector<double>& qInv, Format resultFormat) {
    std::vector<DCRTPolyImpl::PolyType> polyInNTT;

    // if the input polynomial is in evaluation representation, store it for
    // later use to reduce the number of NTTs
    if (m_format == Format::EVALUATION) {
        polyInNTT = m_vectors;
        this->SetFormat(Format::COEFFICIENT);
    }

    DCRTPolyImpl<VecType> partP =
        SwitchCRTBasis(paramsP, QHatInvModq, QHatInvModqPrecon, QHatModp, alphaQModp, modpBarrettMu, qInv);

    size_t sizeQ  = m_vectors.size();
    size_t sizeP  = partP.m_vectors.size();
    size_t sizeQP = sizeP + sizeQ;

    m_vectors.resize(sizeQP);

#pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(sizeP))
    // populate the towers corresponding to CRT basis P and convert them to
    // evaluation representation
    for (size_t j = 0; j < sizeP; j++) {
        m_vectors[sizeQ + j] = partP.m_vectors[j];
        m_vectors[sizeQ + j].SetFormat(resultFormat);
    }

    if (resultFormat == Format::EVALUATION) {
        // if the input polynomial was in evaluation representation, use the towers
        // for Q from it
        if (polyInNTT.size() > 0) {
            for (size_t i = 0; i < sizeQ; i++)
                m_vectors[i] = polyInNTT[i];
        }
        else {
            // else call NTT for the towers for Q
#pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(sizeQ))
            for (size_t i = 0; i < sizeQ; i++)
                m_vectors[i].SetFormat(Format::EVALUATION);
        }
    }
    m_format = resultFormat;
    m_params = paramsQP;
}

template <typename VecType>
void DCRTPolyImpl<VecType>::ExpandCRTBasisReverseOrder(
    const std::shared_ptr<Params>& paramsQP, const std::shared_ptr<Params>& paramsP,
    const std::vector<NativeInteger>& QHatInvModq, const std::vector<NativeInteger>& QHatInvModqPrecon,
    const std::vector<std::vector<NativeInteger>>& QHatModp, const std::vector<std::vector<NativeInteger>>& alphaQModp,
    const std::vector<DoubleNativeInt>& modpBarrettMu, const std::vector<double>& qInv, Format resultFormat) {
    std::vector<DCRTPolyImpl::PolyType> polyInNTT;

    // if the input polynomial is in evaluation representation, store it for
    // later use to reduce the number of NTTs
    if (m_format == Format::EVALUATION) {
        polyInNTT = m_vectors;
        this->SetFormat(Format::COEFFICIENT);
    }

    DCRTPolyImpl<VecType> partP =
        SwitchCRTBasis(paramsP, QHatInvModq, QHatInvModqPrecon, QHatModp, alphaQModp, modpBarrettMu, qInv);

    size_t sizeQ  = m_vectors.size();
    size_t sizeP  = partP.m_vectors.size();
    size_t sizeQP = sizeP + sizeQ;

    std::vector<PolyType> temp;
    temp.reserve(sizeQP);
    temp.insert(temp.end(), std::make_move_iterator(partP.m_vectors.begin()),
                std::make_move_iterator(partP.m_vectors.end()));
    temp.insert(temp.end(), std::make_move_iterator(m_vectors.begin()), std::make_move_iterator(m_vectors.end()));

#pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(sizeQP))
    for (size_t i = 0; i < sizeQP; i++) {
        temp[i].SetFormat(resultFormat);
    }

    if (resultFormat == Format::EVALUATION) {
        // if the input polynomial was in evaluation representation, use the towers
        // for Q from it
        if (polyInNTT.size() > 0) {
            for (size_t i = 0; i < sizeQ; i++)
                temp[sizeP + i] = polyInNTT[i];
        }
        else {
            // else call NTT for the towers for Q
#pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(sizeQ))
            for (size_t i = 0; i < sizeQ; i++)
                temp[sizeP + i].SetFormat(Format::EVALUATION);
        }
    }
    m_format  = resultFormat;
    m_params  = paramsQP;
    m_vectors = temp;
}

template <typename VecType>
void DCRTPolyImpl<VecType>::FastExpandCRTBasisPloverQ(const Precomputations& precomputed) {
    usint ringDim = m_params->GetRingDimension();
    size_t sizeQ  = m_vectors.size();
    DCRTPolyImpl<VecType> partPl(precomputed.paramsPl, m_format, true);
    const size_t sizePl = partPl.m_vectors.size();

#if defined(HAVE_INT128) && NATIVEINT == 64
    // (k + kl)n
    #pragma omp parallel for
    for (usint ri = 0; ri < ringDim; ri++) {
        std::vector<DoubleNativeInt> sum(sizePl);
        for (usint i = 0; i < sizeQ; i++) {
            const NativeInteger& xi                     = m_vectors[i][ri];
            const NativeInteger& qi                     = m_vectors[i].GetModulus();
            const std::vector<NativeInteger>& qInvModpi = precomputed.qInvModp[i];
            NativeInteger xQHatInvModqi =
                xi.ModMulFastConst(precomputed.mPlQHatInvModq[i], qi, precomputed.mPlQHatInvModqPrecon[i]);
            for (usint j = 0; j < sizePl; j++) {
                auto a = xQHatInvModqi.ConvertToInt();
                auto b = qInvModpi[j].ConvertToInt();
                sum[j] += Mul128(a, b);
            }
        }

        for (usint j = 0; j < sizePl; j++) {
            const NativeInteger& pj = partPl.m_vectors[j].GetModulus();
            partPl.m_vectors[j][ri] = BarrettUint128ModUint64(sum[j], pj.ConvertToInt(), precomputed.modpBarrettMu[j]);
        }
    }

    // EMM: (l + ll)n
    // EFP: ln
    DCRTPolyImpl<VecType> partQl = partPl.SwitchCRTBasis(
        precomputed.paramsQl, precomputed.PlHatInvModp, precomputed.PlHatInvModpPrecon, precomputed.PlHatModq,
        precomputed.alphaPlModq, precomputed.modqBarrettMu, precomputed.pInv);

    const size_t sizeQl   = sizePl;
    const size_t sizeQlPl = sizePl + sizeQl;
    // Expand with zeros as should be
    m_vectors.resize(sizeQlPl);

    #pragma omp parallel for
    for (size_t i = 0; i < sizeQl; i++) {
        m_vectors[i] = partQl.m_vectors[i];
    }

    // We cannot use two indices in one for loop with omp parallel for.
    #pragma omp parallel for
    for (size_t j = 0; j < sizePl; j++) {
        m_vectors[sizeQl + j] = partPl.m_vectors[j];
    }

    m_params = precomputed.paramsQlPl;
}

#else
    // (k + kl)n
    #pragma omp parallel for
    for (usint ri = 0; ri < ringDim; ri++) {
        std::vector<DoubleNativeInt> sum(sizePl);
        for (usint i = 0; i < sizeQ; i++) {
            const NativeInteger& xi                     = m_vectors[i][ri];
            const NativeInteger& qi                     = m_vectors[i].GetModulus();
            const std::vector<NativeInteger>& qInvModpi = precomputed.qInvModp[i];
            NativeInteger xQHatInvModqi =
                xi.ModMulFastConst(precomputed.mPlQHatInvModq[i], qi, precomputed.mPlQHatInvModqPrecon[i]);
            for (usint j = 0; j < sizePl; j++) {
                const NativeInteger& pj  = partPl.m_vectors[j].GetModulus();
                const NativeInteger mu_j = pj.ComputeMu();
                partPl.m_vectors[j][ri].ModAddFastEq(xQHatInvModqi.ModMulFast(qInvModpi[j], pj, mu_j), pj);
            }
        }
    }

    // EMM: (l + ll)n
    // EFP: ln
    DCRTPolyImpl<VecType> partQl = partPl.SwitchCRTBasis(
        precomputed.paramsQl, precomputed.PlHatInvModp, precomputed.PlHatInvModpPrecon, precomputed.PlHatModq,
        precomputed.alphaPlModq, precomputed.modqBarrettMu, precomputed.pInv);

    const size_t sizeQl   = sizePl;
    const size_t sizeQlPl = sizePl + sizeQl;
    // Expand with zeros as should be
    m_vectors.resize(sizeQlPl);

    #pragma omp parallel for
    for (size_t i = 0; i < sizeQl; i++) {
        m_vectors[i] = partQl.m_vectors[i];
    }

    // We cannot use two indices in one for loop with omp parallel for.
    #pragma omp parallel for
    for (size_t j = 0; j < sizePl; j++) {
        m_vectors[sizeQl + j] = partPl.m_vectors[j];
    }

    m_params = precomputed.paramsQlPl;
}
#endif

template <typename VecType>
void DCRTPolyImpl<VecType>::ExpandCRTBasisQlHat(const std::shared_ptr<Params>& paramsQ,
                                                const std::vector<NativeInteger>& QlHatModq,
                                                const std::vector<NativeInteger>& QlHatModqPrecon, const usint sizeQ) {
    size_t sizeQl(m_vectors.size());
    usint ringDim(m_params->GetRingDimension());
#pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(sizeQl))
    for (size_t i = 0; i < sizeQl; i++) {
        const NativeInteger& qi               = m_vectors[i].GetModulus();
        const NativeInteger& QlHatModqi       = QlHatModq[i];
        const NativeInteger& QlHatModqiPrecon = QlHatModqPrecon[i];
        for (usint ri = 0; ri < ringDim; ri++) {
            m_vectors[i][ri].ModMulFastConstEq(QlHatModqi, qi, QlHatModqiPrecon);
        }
    }
    m_vectors.resize(sizeQ);
    for (size_t i = sizeQl; i < sizeQ; i++) {
        typename DCRTPolyImpl<VecType>::PolyType newvec(paramsQ->GetParams()[i], m_format, true);
        m_vectors[i] = std::move(newvec);
    }
    m_params = paramsQ;
}

template <typename VecType>
typename DCRTPolyImpl<VecType>::PolyType DCRTPolyImpl<VecType>::ScaleAndRound(
    const NativeInteger& t, const std::vector<NativeInteger>& tQHatInvModqDivqModt,
    const std::vector<NativeInteger>& tQHatInvModqDivqModtPrecon,
    const std::vector<NativeInteger>& tQHatInvModqBDivqModt,
    const std::vector<NativeInteger>& tQHatInvModqBDivqModtPrecon, const std::vector<double>& tQHatInvModqDivqFrac,
    const std::vector<double>& tQHatInvModqDivqBFrac) const {
    usint ringDim = m_params->GetRingDimension();
    usint sizeQ   = m_vectors.size();

    // MSB of q_i
    usint qMSB = m_vectors[0].GetModulus().GetMSB();
    // MSB of t
    usint tMSB = t.GetMSB();
    // MSB of sizeQ
    usint sizeQMSB = GetMSB64(sizeQ);

    DCRTPolyImpl::PolyType::Vector coefficients(ringDim, t.ConvertToInt());
    // For power of two t we can do modulo reduction easily
    if (IsPowerOfTwo(t.ConvertToInt())) {
        uint64_t tMinus1 = t.ConvertToInt() - 1;
        // We try to keep floating point error of
        // \sum x_i*tQHatInvModqDivqFrac[i] small.
        if (qMSB + sizeQMSB < 52) {
            // In our settings x_i <= q_i/2 and for double type floating point
            // error is bounded by 2^{-53}. Thus the floating point error is bounded
            // by sizeQ * q_i/2 * 2^{-53}. In case of qMSB + sizeQMSB < 52 the error
            // is bounded by 1/4, and the rounding will be correct.
            if ((qMSB + tMSB + sizeQMSB) < 63) {
                // No intermediate modulo reductions are needed in this case
                // we fit in 63 bits, so we can do multiplications and
                // additions without modulo reduction, and do modulo reduction
                // only once
#pragma omp parallel for
                for (usint ri = 0; ri < ringDim; ri++) {
                    double floatSum      = 0.5;
                    NativeInteger intSum = 0, tmp;
                    for (usint i = 0; i < sizeQ; i++) {
                        tmp = m_vectors[i][ri];

                        floatSum += tmp.ConvertToDouble() * tQHatInvModqDivqFrac[i];

                        // No intermediate modulo reductions are needed in this case
                        tmp.MulEqFast(tQHatInvModqDivqModt[i]);
                        intSum.AddEqFast(tmp);
                    }
                    intSum += static_cast<uint64_t>(floatSum);
                    // mod a power of two
                    coefficients[ri] = intSum.ConvertToInt() & tMinus1;
                }
            }
            else {
                // In case of qMSB + sizeQMSB >= 52 we decompose x_i in the basis
                // B=2^{qMSB/2} And split the sum \sum x_i*tQHatInvModqDivqFrac[i] to
                // the sum \sum xLo_i*tQHatInvModqDivqFrac[i] +
                // xHi_i*tQHatInvModqBDivqFrac[i] with also precomputed
                // tQHatInvModqBDivqFrac = Frac{t*QHatInv_i*B/q_i} In our settings q_i <
                // 2^60, so xLo_i, xHi_i < 2^30 and for double type floating point error
                // is bounded by 2^{-53}. Thus the floating point error is bounded by
                // sizeQ * 2^30 * 2^{-53}. We always have sizeQ < 2^11, which means the
                // error is bounded by 1/4, and the rounding will be correct.
#pragma omp parallel for
                for (usint ri = 0; ri < ringDim; ri++) {
                    double floatSum      = 0.5;
                    NativeInteger intSum = 0, tmp;
                    for (usint i = 0; i < sizeQ; i++) {
                        tmp = m_vectors[i][ri];

                        floatSum += tmp.ConvertToDouble() * tQHatInvModqDivqFrac[i];

                        tmp.ModMulFastConstEq(tQHatInvModqDivqModt[i], t, tQHatInvModqDivqModtPrecon[i]);
                        intSum.AddEqFast(tmp);
                    }
                    intSum += static_cast<uint64_t>(floatSum);
                    // mod a power of two
                    coefficients[ri] = intSum.ConvertToInt() & tMinus1;
                }
            }
        }
        else {
            usint qMSBHf = qMSB >> 1;
            if ((qMSBHf + tMSB + sizeQMSB) < 62) {
                // No intermediate modulo reductions are needed in this case
                // we fit in 62 bits, so we can do multiplications and
                // additions without modulo reduction, and do modulo reduction
                // only once
#pragma omp parallel for
                for (usint ri = 0; ri < ringDim; ri++) {
                    double floatSum      = 0.5;
                    NativeInteger intSum = 0;
                    NativeInteger tmpHi, tmpLo;
                    for (usint i = 0; i < sizeQ; i++) {
                        tmpLo = m_vectors[i][ri];
                        tmpHi = tmpLo.RShift(qMSBHf);
                        tmpLo.SubEqFast(tmpHi.LShift(qMSBHf));

                        floatSum += tmpLo.ConvertToDouble() * tQHatInvModqDivqFrac[i];
                        floatSum += tmpHi.ConvertToDouble() * tQHatInvModqDivqBFrac[i];

                        // No intermediate modulo reductions are needed in this case
                        tmpLo.MulEqFast(tQHatInvModqDivqModt[i]);
                        tmpHi.MulEqFast(tQHatInvModqBDivqModt[i]);
                        intSum.AddEqFast(tmpLo);
                        intSum.AddEqFast(tmpHi);
                    }
                    intSum += static_cast<uint64_t>(floatSum);
                    // mod a power of two
                    coefficients[ri] = intSum.ConvertToInt() & tMinus1;
                }
            }
            else {
#pragma omp parallel for
                for (usint ri = 0; ri < ringDim; ri++) {
                    double floatSum      = 0.5;
                    NativeInteger intSum = 0;
                    NativeInteger tmpHi, tmpLo;
                    for (usint i = 0; i < sizeQ; i++) {
                        tmpLo = m_vectors[i][ri];
                        tmpHi = tmpLo.RShift(qMSBHf);
                        tmpLo.SubEqFast(tmpHi.LShift(qMSBHf));

                        floatSum += tmpLo.ConvertToDouble() * tQHatInvModqDivqFrac[i];
                        floatSum += tmpHi.ConvertToDouble() * tQHatInvModqDivqBFrac[i];

                        tmpLo.ModMulFastConstEq(tQHatInvModqDivqModt[i], t, tQHatInvModqDivqModtPrecon[i]);
                        tmpHi.ModMulFastConstEq(tQHatInvModqBDivqModt[i], t, tQHatInvModqBDivqModtPrecon[i]);
                        intSum.AddEqFast(tmpLo);
                        intSum.AddEqFast(tmpHi);
                    }
                    intSum += static_cast<uint64_t>(floatSum);
                    // mod a power of two
                    coefficients[ri] = intSum.ConvertToInt() & tMinus1;
                }
            }
        }
    }
    else {
        // non-power of two: modular reduction is more expensive
        double td   = t.ConvertToInt();
        double tInv = 1. / td;
        // We try to keep floating point error of
        // \sum x_i*tQHatInvModqDivqFrac[i] small.
        if (qMSB + sizeQMSB < 52) {
            // In our settings x_i <= q_i/2 and for double type floating point
            // error is bounded by 2^{-53}. Thus the floating point error is bounded
            // by sizeQ * q_i/2 * 2^{-53}. In case of qMSB + sizeQMSB < 52 the error
            // is bounded by 1/4, and the rounding will be correct.
            if ((qMSB + tMSB + sizeQMSB) < 52) {
                // No intermediate modulo reductions are needed in this case
                // we fit in 52 bits, so we can do multiplications and
                // additions without modulo reduction, and do modulo reduction
                // only once using floating point techniques
#pragma omp parallel for
                for (usint ri = 0; ri < ringDim; ri++) {
                    double floatSum      = 0.0;
                    NativeInteger intSum = 0, tmp;
                    for (usint i = 0; i < sizeQ; i++) {
                        tmp = m_vectors[i][ri];

                        floatSum += tmp.ConvertToDouble() * tQHatInvModqDivqFrac[i];

                        // No intermediate modulo reductions are needed in this case
                        tmp.MulEqFast(tQHatInvModqDivqModt[i]);
                        intSum.AddEqFast(tmp);
                    }
                    // compute modulo reduction by finding the quotient using doubles
                    // and then substracting quotient * t
                    floatSum += intSum.ConvertToInt();
                    uint64_t quot = static_cast<uint64_t>(floatSum * tInv);
                    floatSum -= td * quot;
                    // rounding
                    coefficients[ri] = static_cast<uint64_t>(floatSum + 0.5);
                }
            }
            else {
                // In case of qMSB + sizeQMSB >= 52 we decompose x_i in the basis
                // B=2^{qMSB/2} And split the sum \sum x_i*tQHatInvModqDivqFrac[i] to
                // the sum \sum xLo_i*tQHatInvModqDivqFrac[i] +
                // xHi_i*tQHatInvModqBDivqFrac[i] with also precomputed
                // tQHatInvModqBDivqFrac = Frac{t*QHatInv_i*B/q_i} In our settings q_i <
                // 2^60, so xLo_i, xHi_i < 2^30 and for double type floating point error
                // is bounded by 2^{-53}. Thus the floating point error is bounded by
                // sizeQ * 2^30 * 2^{-53}. We always have sizeQ < 2^11, which means the
                // error is bounded by 1/4, and the rounding will be correct.
#pragma omp parallel for
                for (usint ri = 0; ri < ringDim; ri++) {
                    double floatSum{0.0};
                    NativeInteger intSum{0};
                    for (usint i = 0; i < sizeQ; i++) {
                        const auto& tmp = m_vectors[i][ri];
                        floatSum += tmp.ConvertToDouble() * tQHatInvModqDivqFrac[i];
                        intSum.AddEqFast(
                            tmp.ModMulFastConst(tQHatInvModqDivqModt[i], t, tQHatInvModqDivqModtPrecon[i]));
                    }
                    // compute modulo reduction by finding the quotient using doubles
                    // and then substracting quotient * t
                    floatSum += intSum.ConvertToDouble();
                    uint64_t quot = static_cast<uint64_t>(floatSum * tInv);
                    floatSum -= td * quot;
                    // rounding
                    coefficients[ri] = static_cast<uint64_t>(floatSum + 0.5);
                }
            }
        }
        else {
            usint qMSBHf = qMSB >> 1;
            if ((qMSBHf + tMSB + sizeQMSB) < 52) {
                // No intermediate modulo reductions are needed in this case
                // we fit in 52 bits, so we can do multiplications and
                // additions without modulo reduction, and do modulo reduction
                // only once using floating point techniques
#pragma omp parallel for
                for (usint ri = 0; ri < ringDim; ri++) {
                    double floatSum      = 0.0;
                    NativeInteger intSum = 0;
                    NativeInteger tmpHi, tmpLo;
                    for (usint i = 0; i < sizeQ; i++) {
                        tmpLo = m_vectors[i][ri];
                        tmpHi = tmpLo.RShift(qMSBHf);
                        tmpLo.SubEqFast(tmpHi.LShift(qMSBHf));

                        floatSum += tmpLo.ConvertToDouble() * tQHatInvModqDivqFrac[i];
                        floatSum += tmpHi.ConvertToDouble() * tQHatInvModqDivqBFrac[i];

                        // No intermediate modulo reductions are needed in this case
                        tmpLo.MulEqFast(tQHatInvModqDivqModt[i]);
                        tmpHi.MulEqFast(tQHatInvModqBDivqModt[i]);
                        intSum.AddEqFast(tmpLo);
                        intSum.AddEqFast(tmpHi);
                    }
                    // compute modulo reduction by finding the quotient using doubles
                    // and then substracting quotient * t
                    floatSum += intSum.ConvertToInt();
                    uint64_t quot = static_cast<uint64_t>(floatSum * tInv);
                    floatSum -= td * quot;
                    // rounding
                    coefficients[ri] = static_cast<uint64_t>(floatSum + 0.5);
                }
            }
            else {
#pragma omp parallel for
                for (usint ri = 0; ri < ringDim; ri++) {
                    double floatSum      = 0.0;
                    NativeInteger intSum = 0;
                    NativeInteger tmpHi, tmpLo;
                    for (usint i = 0; i < sizeQ; i++) {
                        tmpLo = m_vectors[i][ri];
                        tmpHi = tmpLo.RShift(qMSBHf);
                        tmpLo.SubEqFast(tmpHi.LShift(qMSBHf));

                        floatSum += tmpLo.ConvertToDouble() * tQHatInvModqDivqFrac[i];
                        floatSum += tmpHi.ConvertToDouble() * tQHatInvModqDivqBFrac[i];

                        tmpLo.ModMulFastConstEq(tQHatInvModqDivqModt[i], t, tQHatInvModqDivqModtPrecon[i]);
                        tmpHi.ModMulFastConstEq(tQHatInvModqBDivqModt[i], t, tQHatInvModqBDivqModtPrecon[i]);
                        intSum.AddEqFast(tmpLo);
                        intSum.AddEqFast(tmpHi);
                    }
                    // compute modulo reduction by finding the quotient using doubles
                    // and then substracting quotient * t
                    floatSum += intSum.ConvertToInt();
                    uint64_t quot = static_cast<uint64_t>(floatSum * tInv);
                    floatSum -= td * quot;
                    // rounding
                    coefficients[ri] = static_cast<uint64_t>(floatSum + 0.5);
                }
            }
        }
    }

    // Setting the root of unity to ONE as the calculation is expensive
    // It is assumed that no polynomial multiplications in evaluation
    // representation are performed after this
    DCRTPolyImpl::PolyType result(
        std::make_shared<DCRTPolyImpl::PolyType::Params>(m_params->GetCyclotomicOrder(), t.ConvertToInt(), 1));
    result.SetValues(std::move(coefficients), Format::COEFFICIENT);

    return result;
}

template <typename VecType>
DCRTPolyImpl<VecType> DCRTPolyImpl<VecType>::ApproxScaleAndRound(
    const std::shared_ptr<Params>& paramsP, const std::vector<std::vector<NativeInteger>>& tPSHatInvModsDivsModp,
    const std::vector<DoubleNativeInt>& modpBarretMu) const {
    DCRTPolyImpl<VecType> ans(paramsP, m_format, true);
    usint ringDim = m_params->GetRingDimension();
    size_t sizeQP = m_vectors.size();
    size_t sizeP  = ans.m_vectors.size();
    size_t sizeQ  = sizeQP - sizeP;

#if defined(HAVE_INT128) && NATIVEINT == 64
    #pragma omp parallel for
    for (usint ri = 0; ri < ringDim; ri++) {
        for (usint j = 0; j < sizeP; j++) {
            DoubleNativeInt curValue = 0;

            const NativeInteger& pj                                  = paramsP->GetParams()[j]->GetModulus();
            const std::vector<NativeInteger>& tPSHatInvModsDivsModpj = tPSHatInvModsDivsModp[j];

            for (usint i = 0; i < sizeQ; i++) {
                const NativeInteger& xi = m_vectors[i][ri];
                curValue += Mul128(xi.ConvertToInt(), tPSHatInvModsDivsModpj[i].ConvertToInt());
            }

            const NativeInteger& xi = m_vectors[sizeQ + j][ri];
            curValue += Mul128(xi.ConvertToInt(), tPSHatInvModsDivsModpj[sizeQ].ConvertToInt());

            ans.m_vectors[j][ri] = BarrettUint128ModUint64(curValue, pj.ConvertToInt(), modpBarretMu[j]);
        }
    }
    return ans;
}

#else
    std::vector<NativeInteger> mu(sizeP);
    for (usint j = 0; j < sizeP; j++) {
        mu[j] = (paramsP->GetParams()[j]->GetModulus()).ComputeMu();
    }

    #pragma omp parallel for
    for (usint ri = 0; ri < ringDim; ri++) {
        for (usint j = 0; j < sizeP; j++) {
            const NativeInteger& pj                                  = paramsP->GetParams()[j]->GetModulus();
            const std::vector<NativeInteger>& tPSHatInvModsDivsModpj = tPSHatInvModsDivsModp[j];

            for (usint i = 0; i < sizeQ; i++) {
                const NativeInteger& xi = m_vectors[i][ri];
                const NativeInteger& pj = ans.m_vectors[j].GetModulus();
                ans.m_vectors[j][ri].ModAddFastEq(xi.ModMulFast(tPSHatInvModsDivsModpj[i], pj, mu[j]), pj);
            }

            const NativeInteger& xi = m_vectors[sizeQ + j][ri];
            ans.m_vectors[j][ri].ModAddFastEq(xi.ModMulFast(tPSHatInvModsDivsModpj[sizeQ], pj, mu[j]), pj);
        }
    }
    return ans;
}
#endif

template <typename VecType>
DCRTPolyImpl<VecType> DCRTPolyImpl<VecType>::ScaleAndRound(
    const std::shared_ptr<Params>& paramsOutput, const std::vector<std::vector<NativeInteger>>& tOSHatInvModsDivsModo,
    const std::vector<double>& tOSHatInvModsDivsFrac, const std::vector<DoubleNativeInt>& modoBarretMu) const {
    if constexpr (NATIVEINT == 32)
        OPENFHE_THROW(math_error, "Use of ScaleAndRound with NATIVEINT == 32 may lead to overflow");

    DCRTPolyImpl<VecType> ans(paramsOutput, m_format, true);
    usint ringDim      = m_params->GetRingDimension();
    size_t sizeQP      = m_vectors.size();
    size_t sizeO       = ans.m_vectors.size();
    size_t sizeI       = sizeQP - sizeO;
    size_t inputIndex  = 0;
    size_t outputIndex = 0;

    if (paramsOutput->GetParams()[0]->GetModulus() == m_params->GetParams()[0]->GetModulus()) {
        // If the output modulus is Q, then the input index refers to the values (mod p_j), shifted by sizeQ.
        inputIndex = sizeO;
    }
    else {
        // If the output modulus is P, then the output index refers to the values (mod p_j), shifted by sizeQ.
        outputIndex = sizeI;
    }

    std::vector<NativeInteger> mu(sizeO);
    for (size_t j = 0; j < sizeO; ++j)
        mu[j] = (paramsOutput->GetParams()[j]->GetModulus()).ComputeMu();

#if defined(HAVE_INT128) && NATIVEINT == 64
    #pragma omp parallel for
    for (usint ri = 0; ri < ringDim; ++ri) {
        double nu = 0.5;
        for (size_t i = 0; i < sizeI; ++i) {
            // possible loss of precision if modulus greater than 2^53 + 1
            const NativeInteger& xi = m_vectors[i + inputIndex][ri];
            nu += tOSHatInvModsDivsFrac[i] * xi.ConvertToDouble();
        }
        if (isConvertableToNativeInt(nu)) {
            NativeInteger alpha = static_cast<BasicInteger>(nu);
            for (size_t j = 0; j < sizeO; ++j) {
                const auto& tOSHatInvModsDivsModoj = tOSHatInvModsDivsModo[j];
                DoubleNativeInt curValue{0};
                for (size_t i = 0; i < sizeI; ++i) {
                    const NativeInteger& xi = m_vectors[i + inputIndex][ri];
                    curValue += Mul128(xi.ConvertToInt(), tOSHatInvModsDivsModoj[i].ConvertToInt());
                }
                const NativeInteger& xi = m_vectors[outputIndex + j][ri];
                curValue += Mul128(xi.ConvertToInt(), tOSHatInvModsDivsModoj[sizeI].ConvertToInt());

                const NativeInteger& oj = paramsOutput->GetParams()[j]->GetModulus();
                auto&& curNativeValue   = BarrettUint128ModUint64(curValue, oj.ConvertToInt(), modoBarretMu[j]);

                auto curAlpha{alpha};
                if (alpha >= oj)
                    curAlpha = alpha.Mod(oj, mu[j]);
                ans.m_vectors[j][ri] = NativeInteger(curNativeValue).ModAddFast(curAlpha, oj);
            }
        }
        else {
            auto alpha = static_cast<DoubleNativeInt>(nu);
            for (size_t j = 0; j < sizeO; ++j) {
                const auto& tOSHatInvModsDivsModoj = tOSHatInvModsDivsModo[j];
                DoubleNativeInt curValue{0};
                for (size_t i = 0; i < sizeI; ++i) {
                    const NativeInteger& xi = m_vectors[i + inputIndex][ri];
                    curValue += Mul128(xi.ConvertToInt(), tOSHatInvModsDivsModoj[i].ConvertToInt());
                }
                const NativeInteger& xi = m_vectors[outputIndex + j][ri];
                curValue += Mul128(xi.ConvertToInt(), tOSHatInvModsDivsModoj[sizeI].ConvertToInt());

                const NativeInteger& oj = paramsOutput->GetParams()[j]->GetModulus();
                auto&& curNativeValue   = BarrettUint128ModUint64(curValue, oj.ConvertToInt(), modoBarretMu[j]);

                ans.m_vectors[j][ri] =
                    NativeInteger(curNativeValue)
                        .ModAddFast(BarrettUint128ModUint64(alpha, oj.ConvertToInt(), modoBarretMu[j]), oj);
            }
        }
    }
    return ans;
}

#else
    #pragma omp parallel for
    for (usint ri = 0; ri < ringDim; ++ri) {
        double nu = 0.5;
        for (size_t i = 0; i < sizeI; ++i) {
            // possible loss of precision if modulus greater than 2^53 + 1
            const NativeInteger& xi = m_vectors[i + inputIndex][ri];
            nu += tOSHatInvModsDivsFrac[i] * xi.ConvertToDouble();
        }
        if (isConvertableToNativeInt(nu)) {
            NativeInteger alpha = static_cast<BasicInteger>(nu);
            for (size_t j = 0; j < sizeO; j++) {
                const auto& tOSHatInvModsDivsModoj = tOSHatInvModsDivsModo[j];
                const auto& oj                     = ans.m_vectors[j].GetModulus();
                auto& curValue                     = ans.m_vectors[j][ri];
                for (size_t i = 0; i < sizeI; i++) {
                    const auto& xi = m_vectors[i + inputIndex][ri];
                    curValue.ModAddFastEq(xi.ModMulFast(tOSHatInvModsDivsModoj[i], oj, mu[j]), oj);
                }
                const auto& xi = m_vectors[outputIndex + j][ri];
                curValue.ModAddFastEq(xi.ModMulFast(tOSHatInvModsDivsModoj[sizeI], oj, mu[j]), oj);
                curValue.ModAddFastEq(alpha >= oj ? alpha.Mod(oj, mu[j]) : alpha, oj);
            }
        }
        else {
            int exp;
            double mant            = std::frexp(nu, &exp);
            NativeInteger mantissa = static_cast<BasicInteger>(mant * (1ULL << 53));
            NativeInteger exponent = static_cast<BasicInteger>(1ULL << (exp - 53));
            for (size_t j = 0; j < sizeO; j++) {
                const auto& tOSHatInvModsDivsModoj = tOSHatInvModsDivsModo[j];
                const auto& oj                     = ans.m_vectors[j].GetModulus();
                auto& curValue                     = ans.m_vectors[j][ri];
                for (size_t i = 0; i < sizeI; i++) {
                    const auto& xi = m_vectors[i + inputIndex][ri];
                    curValue.ModAddFastEq(xi.ModMulFast(tOSHatInvModsDivsModoj[i], oj, mu[j]), oj);
                }
                const auto& xi = m_vectors[outputIndex + j][ri];
                curValue.ModAddFastEq(xi.ModMulFast(tOSHatInvModsDivsModoj[sizeI], oj, mu[j]), oj);
                curValue.ModAddFastEq(exponent.ModMul(mantissa, oj, mu[j]), oj);
            }
        }
    }
    return ans;
}
#endif

template <typename VecType>
typename DCRTPolyImpl<VecType>::PolyType DCRTPolyImpl<VecType>::ScaleAndRound(
    const std::vector<NativeInteger>& moduliQ, const NativeInteger& t, const NativeInteger& tgamma,
    const std::vector<NativeInteger>& tgammaQHatModq, const std::vector<NativeInteger>& tgammaQHatModqPrecon,
    const std::vector<NativeInteger>& negInvqModtgamma,
    const std::vector<NativeInteger>& negInvqModtgammaPrecon) const {
    usint n     = m_params->GetRingDimension();
    usint sizeQ = m_vectors.size();

    const uint64_t gammaMinus1 = (1 << 26) - 1;

    DCRTPolyImpl::PolyType::Vector coefficients(n, t.ConvertToInt());

#pragma omp parallel for
    for (usint k = 0; k < n; k++) {
        // TODO: use 64 bit words in case NativeInteger uses smaller word size
        NativeInteger s = 0, tmp;
        for (usint i = 0; i < sizeQ; i++) {
            const NativeInteger& qi = moduliQ[i];
            tmp                     = m_vectors[i][k];

            // xi*t*gamma*(q/qi)^-1 mod qi
            tmp.ModMulFastConstEq(tgammaQHatModq[i], qi, tgammaQHatModqPrecon[i]);

            // -tmp/qi mod gamma*t < 2^58
            tmp = tmp.ModMulFastConst(negInvqModtgamma[i], tgamma, negInvqModtgammaPrecon[i]);

            s.ModAddFastEq(tmp, tgamma);
        }

        // Compute s + s & (gamma-1)
        s += NativeInteger(s.ConvertToInt() & gammaMinus1);

        // shift by log(gamma) to get the result
        coefficients[k] = s >> 26;
    }

    // Setting the root of unity to ONE as the calculation is expensive
    // It is assumed that no polynomial multiplications in evaluation
    // representation are performed after this
    DCRTPolyImpl::PolyType result(
        std::make_shared<DCRTPolyImpl::PolyType::Params>(m_params->GetCyclotomicOrder(), t.ConvertToInt(), 1));
    result.SetValues(std::move(coefficients), Format::COEFFICIENT);

    return result;
}

template <typename VecType>
void DCRTPolyImpl<VecType>::ScaleAndRoundPOverQ(const std::shared_ptr<Params>& paramsQ,
                                                const std::vector<NativeInteger>& pInvModq) {
    const usint sizeQ   = m_vectors.size() - 1;
    const usint ringDim = m_params->GetRingDimension();
    for (usint i = 0; i < sizeQ; i++) {
        const NativeInteger& qi = paramsQ->GetParams()[i]->GetModulus();
        for (usint ri = 0; ri < ringDim; ri++) {
            m_vectors[i][ri].ModSubEq(m_vectors[sizeQ][ri], qi);
        }
    }
    m_vectors.resize(sizeQ);
    m_params = paramsQ;
    *this    = this->Times(pInvModq);
}

// TODO: tune omp performance
template <typename VecType>
void DCRTPolyImpl<VecType>::FastBaseConvqToBskMontgomery(
    const std::shared_ptr<Params>& paramsQBsk, const std::vector<NativeInteger>& moduliQ,
    const std::vector<NativeInteger>& moduliBsk, const std::vector<DoubleNativeInt>& modbskBarrettMu,
    const std::vector<NativeInteger>& mtildeQHatInvModq, const std::vector<NativeInteger>& mtildeQHatInvModqPrecon,
    const std::vector<std::vector<NativeInteger>>& QHatModbsk, const std::vector<uint64_t>& QHatModmtilde,
    const std::vector<NativeInteger>& QModbsk, const std::vector<NativeInteger>& QModbskPrecon,
    const uint64_t& negQInvModmtilde, const std::vector<NativeInteger>& mtildeInvModbsk,
    const std::vector<NativeInteger>& mtildeInvModbskPrecon) {
    // Input: dcrtpoly in basis Q
    // Output: dcrtpoly in base QBsk = {B U msk}

    // computing steps 0 and 1 in Algorithm 3 in source paper.

    std::vector<DCRTPolyImpl::PolyType> polyInNTT;

    // if the input polynomial is in evaluation representation, store it for
    // later use to reduce the number of NTTs
    if (m_format == Format::EVALUATION) {
        polyInNTT = m_vectors;
        this->SetFormat(Format::COEFFICIENT);
    }

    m_params = paramsQBsk;
    m_vectors.resize(m_params->GetParams().size());

    uint32_t numQ(moduliQ.size());
    uint32_t numBsk(moduliBsk.size());
    uint32_t n(m_params->GetRingDimension());

    // ----------------------- step 0 -----------------------

    // first we twist xi by mtilde*(q/qi)^-1 mod qi
    NativeInteger* ximtildeQHatModqi = new NativeInteger[n * numQ];
    for (uint32_t i = 0; i < numQ; i++) {
        const NativeInteger& currentmtildeQHatInvModq       = mtildeQHatInvModq[i];
        const NativeInteger& currentmtildeQHatInvModqPrecon = mtildeQHatInvModqPrecon[i];
        for (uint32_t k = 0; k < n; k++) {
            ximtildeQHatModqi[i * n + k] =
                m_vectors[i][k].ModMulFastConst(currentmtildeQHatInvModq, moduliQ[i], currentmtildeQHatInvModqPrecon);
        }
    }

#if defined(HAVE_INT128) && NATIVEINT == 64
    // mod Bsk
    for (uint32_t j = 0; j < numBsk; j++) {
        DCRTPolyImpl::PolyType newvec(m_params->GetParams()[numQ + j], m_format, true);
        m_vectors[numQ + j] = std::move(newvec);
        for (uint32_t k = 0; k < n; k++) {
            DoubleNativeInt result = 0;
            for (uint32_t i = 0; i < numQ; i++) {
                const NativeInteger& QHatModbskij = QHatModbsk[i][j];
                result += Mul128(ximtildeQHatModqi[i * n + k].ConvertToInt(), QHatModbskij.ConvertToInt());
            }
            m_vectors[numQ + j][k] = BarrettUint128ModUint64(result, moduliBsk[j].ConvertToInt(), modbskBarrettMu[j]);
        }
    }
#else
    std::vector<NativeInteger> mu(numBsk);
    for (usint j = 0; j < numBsk; j++) {
        mu[j] = moduliBsk[j].ComputeMu();
    }

    // mod Bsk
    for (uint32_t j = 0; j < numBsk; j++) {
        DCRTPolyImpl::PolyType newvec(m_params->GetParams()[numQ + j], m_format, true);
        m_vectors[numQ + j] = std::move(newvec);
        for (uint32_t k = 0; k < n; k++) {
            for (uint32_t i = 0; i < numQ; i++) {
                const NativeInteger& QHatModbskij = QHatModbsk[i][j];
                m_vectors[numQ + j][k].ModAddFastEq(
                    ximtildeQHatModqi[i * n + k].ModMulFast(QHatModbskij, moduliBsk[j], mu[j]), moduliBsk[j]);
            }
        }
    }
#endif

    // mod mtilde = 2^16
    const uint64_t mtilde         = (uint64_t)1 << 16;
    const uint64_t mtilde_half    = mtilde >> 1;
    const uint64_t mtilde_minus_1 = mtilde - 1;

    std::vector<uint64_t> result_mtilde(n, 0);
#pragma omp parallel for
    for (uint32_t k = 0; k < n; k++) {
        for (uint32_t i = 0; i < numQ; i++) {
            result_mtilde[k] += ximtildeQHatModqi[i * n + k].ConvertToInt() * QHatModmtilde[i];
        }
        result_mtilde[k] &= mtilde_minus_1;
    }

    // now we have input in Basis (q U Bsk U mtilde)
    // next we perform Small Motgomery Reduction mod q
    // ----------------------- step 1 -----------------------
    // NativeInteger *r_m_tildes = new NativeInteger[n];

#pragma omp parallel for
    for (uint32_t k = 0; k < n; k++) {
        result_mtilde[k] *= negQInvModmtilde;
        result_mtilde[k] &= mtilde_minus_1;
    }

    for (uint32_t i = 0; i < numBsk; i++) {
        const NativeInteger& currentqModBski       = QModbsk[i];
        const NativeInteger& currentqModBskiPrecon = QModbskPrecon[i];

#pragma omp parallel for
        for (uint32_t k = 0; k < n; k++) {
            NativeInteger r_m_tilde = NativeInteger(result_mtilde[k]);  // mtilde = 2^16 < all moduli of Bsk
            if (result_mtilde[k] >= mtilde_half)
                r_m_tilde += moduliBsk[i] - mtilde;  // centred remainder

            r_m_tilde.ModMulFastConstEq(currentqModBski, moduliBsk[i],
                                        currentqModBskiPrecon);  // (r_mtilde) * q mod Bski
            r_m_tilde.ModAddFastEq(m_vectors[numQ + i][k],
                                   moduliBsk[i]);  // (c``_m + (r_mtilde* q)) mod Bski
            m_vectors[numQ + i][k] =
                r_m_tilde.ModMulFastConst(mtildeInvModbsk[i], moduliBsk[i], mtildeInvModbskPrecon[i]);
        }
    }

    // if the input polynomial was in evaluation representation, use the towers
    // for Q from it
    if (polyInNTT.size() > 0) {
        for (size_t i = 0; i < numQ; i++)
            m_vectors[i] = polyInNTT[i];
    }
    else {  // else call NTT for the towers for q
#pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(numQ))
        for (size_t i = 0; i < numQ; i++)
            m_vectors[i].SwitchFormat();
    }

#pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(numBsk))
    for (uint32_t i = 0; i < numBsk; i++)
        m_vectors[numQ + i].SwitchFormat();

    m_format = EVALUATION;

    delete[] ximtildeQHatModqi;
    ximtildeQHatModqi = nullptr;
}

template <typename VecType>
void DCRTPolyImpl<VecType>::FastRNSFloorq(
    const NativeInteger& t, const std::vector<NativeInteger>& moduliQ, const std::vector<NativeInteger>& moduliBsk,
    const std::vector<DoubleNativeInt>& modbskBarrettMu, const std::vector<NativeInteger>& tQHatInvModq,
    const std::vector<NativeInteger>& tQHatInvModqPrecon, const std::vector<std::vector<NativeInteger>>& QHatModbsk,
    const std::vector<std::vector<NativeInteger>>& qInvModbsk, const std::vector<NativeInteger>& tQInvModbsk,
    const std::vector<NativeInteger>& tQInvModbskPrecon) {
    // Input: poly in basis {q U Bsk}
    // Output: approximateFloor(t/q*poly) in basis Bsk

    // --------------------- step 3 ---------------------
    // approximate rounding

    size_t numQ   = moduliQ.size();
    size_t numBsk = moduliBsk.size();

    uint32_t n = this->GetLength();

    // Twist xi by t*(q/qi)^-1 mod qi
    NativeInteger* txiqiDivqModqi = new NativeInteger[n * numBsk];

    for (uint32_t i = 0; i < numQ; i++) {
        const NativeInteger& currenttqDivqiModqi       = tQHatInvModq[i];
        const NativeInteger& currenttqDivqiModqiPrecon = tQHatInvModqPrecon[i];

#pragma omp parallel for
        for (uint32_t k = 0; k < n; k++) {
            // multiply by t*(q/qi)^-1 mod qi
            m_vectors[i][k].ModMulFastConstEq(currenttqDivqiModqi, moduliQ[i], currenttqDivqiModqiPrecon);
        }
    }

#if defined(HAVE_INT128) && NATIVEINT == 64
    for (uint32_t j = 0; j < numBsk; j++) {
    #pragma omp parallel for
        for (uint32_t k = 0; k < n; k++) {
            DoubleNativeInt aq = 0;
            for (uint32_t i = 0; i < numQ; i++) {
                const NativeInteger& InvqiModBjValue = qInvModbsk[i][j];
                NativeInteger& xi                    = m_vectors[i][k];
                aq += Mul128(xi.ConvertToInt(), InvqiModBjValue.ConvertToInt());
            }
            txiqiDivqModqi[j * n + k] = BarrettUint128ModUint64(aq, moduliBsk[j].ConvertToInt(), modbskBarrettMu[j]);
        }
    }

    // now we have FastBaseConv( |t*ct|q, q, Bsk ) in txiqiDivqModqi

    for (uint32_t i = 0; i < numBsk; i++) {
        const NativeInteger& currenttDivqModBski       = tQInvModbsk[i];
        const NativeInteger& currenttDivqModBskiPrecon = tQInvModbskPrecon[i];
    #pragma omp parallel for
        for (uint32_t k = 0; k < n; k++) {
            // Not worthy to use lazy reduction here
            m_vectors[i + numQ][k].ModMulFastConstEq(currenttDivqModBski, moduliBsk[i], currenttDivqModBskiPrecon);
            m_vectors[i + numQ][k].ModSubFastEq(txiqiDivqModqi[i * n + k], moduliBsk[i]);
        }
    }
    delete[] txiqiDivqModqi;
    txiqiDivqModqi = nullptr;
}

#else
    std::vector<NativeInteger> mu(numBsk);
    for (usint j = 0; j < numBsk; j++) {
        mu[j] = moduliBsk[j].ComputeMu();
    }

    for (uint32_t j = 0; j < numBsk; j++) {
    #pragma omp parallel for
        for (uint32_t k = 0; k < n; k++) {
            for (uint32_t i = 0; i < numQ; i++) {
                const NativeInteger& InvqiModBjValue = qInvModbsk[i][j];
                NativeInteger& xi                    = m_vectors[i][k];
                txiqiDivqModqi[j * n + k].ModAddFastEq(xi.ModMulFast(InvqiModBjValue, moduliBsk[j], mu[j]),
                                                       moduliBsk[j]);
            }
        }
    }

    // now we have FastBaseConv( |t*ct|q, q, Bsk ) in txiqiDivqModqi

    for (uint32_t i = 0; i < numBsk; i++) {
        const NativeInteger& currenttDivqModBski       = tQInvModbsk[i];
        const NativeInteger& currenttDivqModBskiPrecon = tQInvModbskPrecon[i];
    #pragma omp parallel for
        for (uint32_t k = 0; k < n; k++) {
            // Not worthy to use lazy reduction here
            m_vectors[i + numQ][k].ModMulFastConstEq(currenttDivqModBski, moduliBsk[i], currenttDivqModBskiPrecon);
            m_vectors[i + numQ][k].ModSubFastEq(txiqiDivqModqi[i * n + k], moduliBsk[i]);
        }
    }
    delete[] txiqiDivqModqi;
    txiqiDivqModqi = nullptr;
}
#endif

template <typename VecType>
void DCRTPolyImpl<VecType>::FastBaseConvSK(
    const std::shared_ptr<Params>& paramsQ, const std::vector<DoubleNativeInt>& modqBarrettMu,
    const std::vector<NativeInteger>& moduliBsk, const std::vector<DoubleNativeInt>& modbskBarrettMu,
    const std::vector<NativeInteger>& BHatInvModb, const std::vector<NativeInteger>& BHatInvModbPrecon,
    const std::vector<NativeInteger>& BHatModmsk, const NativeInteger& BInvModmsk,
    const NativeInteger& BInvModmskPrecon, const std::vector<std::vector<NativeInteger>>& BHatModq,
    const std::vector<NativeInteger>& BModq, const std::vector<NativeInteger>& BModqPrecon) {
    // Input: poly in basis Bsk
    // Output: poly in basis q

#if defined(HAVE_INT128) && NATIVEINT == 64
    m_params     = paramsQ;
    size_t sizeQ = paramsQ->GetParams().size();

    std::vector<NativeInteger> moduliQ(sizeQ);
    for (size_t i = 0; i < sizeQ; i++) {
        moduliQ[i] = paramsQ->GetParams()[i]->GetModulus();
    }
    // FastBaseconv(x, B, q)
    size_t sizeBsk = moduliBsk.size();

    uint32_t n = this->GetLength();

    for (uint32_t i = 0; i < sizeBsk - 1; i++) {  // exclude msk residue
        const NativeInteger& currentBDivBiModBi       = BHatInvModb[i];
        const NativeInteger& currentBDivBiModBiPrecon = BHatInvModbPrecon[i];
    #pragma omp parallel for
        for (uint32_t k = 0; k < n; k++) {
            m_vectors[sizeQ + i][k].ModMulFastConstEq(currentBDivBiModBi, moduliBsk[i], currentBDivBiModBiPrecon);
        }
    }

    for (uint32_t j = 0; j < sizeQ; j++) {
    #pragma omp parallel for
        for (uint32_t k = 0; k < n; k++) {
            DoubleNativeInt result = 0;
            for (uint32_t i = 0; i < sizeBsk - 1; i++) {  // exclude msk residue
                const NativeInteger& currentBDivBiModqj = BHatModq[i][j];
                const NativeInteger& xi                 = m_vectors[sizeQ + i][k];
                result += Mul128(xi.ConvertToInt(), currentBDivBiModqj.ConvertToInt());
            }
            m_vectors[j][k] = BarrettUint128ModUint64(result, moduliQ[j].ConvertToInt(), modqBarrettMu[j]);
        }
    }

    // calculate alphaskx
    // FastBaseConv(x, B, msk)
    NativeInteger* alphaskxVector = new NativeInteger[n];
    #pragma omp parallel for
    for (uint32_t k = 0; k < n; k++) {
        DoubleNativeInt result = 0;
        for (uint32_t i = 0; i < sizeBsk - 1; i++) {
            const NativeInteger& currentBDivBiModmsk = BHatModmsk[i];
            result += Mul128(m_vectors[sizeQ + i][k].ConvertToInt(), currentBDivBiModmsk.ConvertToInt());
        }
        alphaskxVector[k] =
            BarrettUint128ModUint64(result, moduliBsk[sizeBsk - 1].ConvertToInt(), modbskBarrettMu[sizeBsk - 1]);
    }

    // subtract xsk
    #pragma omp parallel for
    for (uint32_t k = 0; k < n; k++) {
        alphaskxVector[k] = alphaskxVector[k].ModSubFast(m_vectors[sizeQ + sizeBsk - 1][k], moduliBsk[sizeBsk - 1]);
        alphaskxVector[k].ModMulFastConstEq(BInvModmsk, moduliBsk[sizeBsk - 1], BInvModmskPrecon);
    }

    // do (m_vector - alphaskx*M) mod q
    NativeInteger mskDivTwo = moduliBsk[sizeBsk - 1] / 2;
    for (uint32_t i = 0; i < sizeQ; i++) {
        const NativeInteger& currentBModqi       = BModq[i];
        const NativeInteger& currentBModqiPrecon = BModqPrecon[i];

    #pragma omp parallel for
        for (uint32_t k = 0; k < n; k++) {
            NativeInteger alphaskBModqi = alphaskxVector[k];
            if (alphaskBModqi > mskDivTwo)
                alphaskBModqi = alphaskBModqi.ModSubFast(moduliBsk[sizeBsk - 1], moduliQ[i]);

            alphaskBModqi.ModMulFastConstEq(currentBModqi, moduliQ[i], currentBModqiPrecon);
            m_vectors[i][k] = m_vectors[i][k].ModSubFast(alphaskBModqi, moduliQ[i]);
        }
    }

    // drop extra vectors

    // this code died on mac;
    // need to be smarter about use of erase, and bounds...
    //  for (uint32_t i = 0; i < numBsk; i++)
    //      m_vectors.erase (m_vectors.begin() + numq + i);

    // erase vectors from begin() + numq to begin() + numq + numBsk
    // make sure beginning and end are inside the vector :)
    if (sizeQ < m_vectors.size()) {
        auto starti = m_vectors.begin() + sizeQ;
        if (starti + sizeBsk >= m_vectors.end())
            m_vectors.erase(starti, m_vectors.end());
        else
            m_vectors.erase(starti, starti + sizeBsk);
    }

    delete[] alphaskxVector;
    alphaskxVector = nullptr;
}

#else
    m_params = paramsQ;

    size_t sizeQ = paramsQ->GetParams().size();

    std::vector<NativeInteger> moduliQ(sizeQ);
    for (size_t i = 0; i < sizeQ; i++) {
        moduliQ[i] = paramsQ->GetParams()[i]->GetModulus();
    }

    // FastBaseconv(x, B, q)
    size_t sizeBsk = moduliBsk.size();

    uint32_t n = this->GetLength();

    for (uint32_t i = 0; i < sizeBsk - 1; i++) {  // exclude msk residue
        const NativeInteger& currentBDivBiModBi       = BHatInvModb[i];
        const NativeInteger& currentBDivBiModBiPrecon = BHatInvModbPrecon[i];
    #pragma omp parallel for
        for (uint32_t k = 0; k < n; k++) {
            m_vectors[sizeQ + i][k].ModMulFastConstEq(currentBDivBiModBi, moduliBsk[i], currentBDivBiModBiPrecon);
        }
    }

    std::vector<NativeInteger> mu(sizeQ);
    for (usint j = 0; j < sizeQ; j++) {
        mu[j] = moduliQ[j].ComputeMu();
    }

    for (uint32_t j = 0; j < sizeQ; j++) {
    #pragma omp parallel for
        for (uint32_t k = 0; k < n; k++) {
            m_vectors[j][k] = NativeInteger(0);
            for (uint32_t i = 0; i < sizeBsk - 1; i++) {  // exclude msk residue
                const NativeInteger& currentBDivBiModqj = BHatModq[i][j];
                const NativeInteger& xi                 = m_vectors[sizeQ + i][k];
                m_vectors[j][k].ModAddFastEq(xi.ModMulFast(currentBDivBiModqj, moduliQ[j], mu[j]), moduliQ[j]);
            }
        }
    }

    NativeInteger muBsk = moduliBsk[sizeBsk - 1].ComputeMu();

    // calculate alphaskx
    // FastBaseConv(x, B, msk)
    NativeInteger* alphaskxVector = new NativeInteger[n];
    #pragma omp parallel for
    for (uint32_t k = 0; k < n; k++) {
        for (uint32_t i = 0; i < sizeBsk - 1; i++) {
            const NativeInteger& currentBDivBiModmsk = BHatModmsk[i];
            // changed from ModAddFastEq to ModAddEq
            alphaskxVector[k].ModAddEq(
                m_vectors[sizeQ + i][k].ModMul(currentBDivBiModmsk, moduliBsk[sizeBsk - 1], muBsk),
                moduliBsk[sizeBsk - 1]);
        }
    }

    // subtract xsk
    #pragma omp parallel for
    for (uint32_t k = 0; k < n; k++) {
        alphaskxVector[k] = alphaskxVector[k].ModSubFast(m_vectors[sizeQ + sizeBsk - 1][k], moduliBsk[sizeBsk - 1]);
        alphaskxVector[k].ModMulFastConstEq(BInvModmsk, moduliBsk[sizeBsk - 1], BInvModmskPrecon);
    }

    // do (m_vector - alphaskx*M) mod q
    NativeInteger mskDivTwo = moduliBsk[sizeBsk - 1] / 2;
    for (uint32_t i = 0; i < sizeQ; i++) {
        const NativeInteger& currentBModqi       = BModq[i];
        const NativeInteger& currentBModqiPrecon = BModqPrecon[i];

    #pragma omp parallel for
        for (uint32_t k = 0; k < n; k++) {
            NativeInteger alphaskBModqi = alphaskxVector[k];
            if (alphaskBModqi > mskDivTwo)
                alphaskBModqi = alphaskBModqi.ModSubFast(moduliBsk[sizeBsk - 1], moduliQ[i]);

            alphaskBModqi.ModMulFastConstEq(currentBModqi, moduliQ[i], currentBModqiPrecon);
            m_vectors[i][k] = m_vectors[i][k].ModSubFast(alphaskBModqi, moduliQ[i]);
        }
    }

    // drop extra vectors

    // this code died on mac;
    // need to be smarter about use of erase, and bounds...
    //  for (uint32_t i = 0; i < numBsk; i++)
    //      m_vectors.erase (m_vectors.begin() + numq + i);

    // erase vectors from begin() + numq to begin() + numq + numBsk
    // make sure beginning and end are inside the vector :)
    if (sizeQ < m_vectors.size()) {
        auto starti = m_vectors.begin() + sizeQ;
        if (starti + sizeBsk >= m_vectors.end())
            m_vectors.erase(starti, m_vectors.end());
        else
            m_vectors.erase(starti, starti + sizeBsk);
    }

    delete[] alphaskxVector;
    alphaskxVector = nullptr;
}
#endif

/*Switch format calls IlVector2n's switchformat*/
template <typename VecType>
void DCRTPolyImpl<VecType>::SwitchFormat() {
    m_format = (m_format == Format::COEFFICIENT) ? Format::EVALUATION : Format::COEFFICIENT;
    size_t size{m_vectors.size()};
#pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(size))
    for (size_t i = 0; i < size; ++i)
        m_vectors[i].SwitchFormat();
}

template <typename VecType>
void DCRTPolyImpl<VecType>::SwitchModulusAtIndex(size_t index, const Integer& modulus, const Integer& rootOfUnity) {
    if (index >= m_vectors.size()) {
        std::string errMsg;
        errMsg = "DCRTPolyImpl is of size = " + std::to_string(m_vectors.size()) +
                 " but SwitchModulus for tower at index " + std::to_string(index) + "is called.";
        OPENFHE_THROW(math_error, errMsg);
    }

    m_vectors[index].SwitchModulus(PolyType::Integer(modulus.ConvertToInt()),
                                   PolyType::Integer(rootOfUnity.ConvertToInt()), 0, 0);
    m_params->RecalculateModulus();
}

template <typename VecType>
bool DCRTPolyImpl<VecType>::InverseExists() const {
    for (auto& v : m_vectors) {
        if (!v.InverseExists())
            return false;
    }
    return true;
}

template <typename VecType>
std::ostream& operator<<(std::ostream& os, const DCRTPolyImpl<VecType>& p) {
    // TODO(gryan): Standardize this printing so it is like other poly's
    os << "---START PRINT DOUBLE CRT-- WITH SIZE" << p.m_vectors.size() << std::endl;
    for (usint i = 0; i < p.m_vectors.size(); i++) {
        os << "VECTOR " << i << std::endl;
        os << p.m_vectors[i];
    }
    os << "---END PRINT DOUBLE CRT--" << std::endl;
    return os;
}

}  // namespace lbcrypto

#endif
