//==================================================================================
// BSD 2-Clause License
//
// Copyright (c) 2014-2024, NJIT, Duality Technologies Inc. and other contributors
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

#include <algorithm>
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
    parms.reserve(m_vectors.size());
    const auto cyclotomicOrder = m_vectors[0].GetCyclotomicOrder();
    for (const auto& v : m_vectors) {
        if (v.GetCyclotomicOrder() != cyclotomicOrder)
            OPENFHE_THROW("Polys provided to constructor must have the same ring dimension");
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
    auto cycorder = m_params->GetCyclotomicOrder();
    auto params   = std::make_shared<Params>(cycorder, m_params->GetParamPartition(startTower, endTower));
    auto res      = DCRTPolyImpl(params, Format::EVALUATION, false);
    for (uint32_t i = startTower; i <= endTower; i++)
        res.SetElementAtIndex(i - startTower, this->GetElementAtIndex(i));
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
    std::vector<uint32_t> arrWindows(size);
    // creates an array of digits up to a certain tower
    for (size_t i = 0; i < size; ++i) {
        uint32_t nBits{m_vectors[i].GetModulus().GetLengthForBase(2)};
        uint32_t curWindows{nBits / baseBits};
        if (nBits % baseBits != 0)
            curWindows++;
        arrWindows[i] = nWindows;
        nWindows += curWindows;
    }
    std::vector<DCRTPolyType> result(nWindows);

#pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(size))
    for (size_t i = 0; i < size; ++i) {
        auto decomposed = (*coef).m_vectors[i].BaseDecompose(baseBits, false);
        for (size_t j = 0; j < decomposed.size(); ++j) {
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
        ++nWindows;

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
    result.m_params = m_params;
    result.m_format = m_format;
    result.m_vectors.reserve(m_vectors.size());
    for (const auto& v : m_vectors)
        result.m_vectors.emplace_back(v.AutomorphismTransform(i));
    return result;
}

template <typename VecType>
DCRTPolyImpl<VecType> DCRTPolyImpl<VecType>::AutomorphismTransform(uint32_t i, const std::vector<uint32_t>& vec) const {
    DCRTPolyImpl<VecType> result;
    result.m_params = m_params;
    result.m_format = m_format;
    result.m_vectors.reserve(m_vectors.size());
    for (const auto& v : m_vectors)
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
        OPENFHE_THROW("tower size mismatch; cannot subtract");
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
        OPENFHE_THROW("tower size mismatch; cannot multiply");
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
    size_t N(m_params->GetRingDimension());
    if (N != element.GetRingDimension())
        OPENFHE_THROW(std::string(__func__) + ": Ring dimension mismatch.");
    if (element.m_vectors.size() != 1 || m_vectors.size() != 1)
        OPENFHE_THROW(std::string(__func__) + ": Only implemented for DCRTPoly with one tower.");

    auto input{element.m_vectors[0]};
    input.SetFormat(Format::COEFFICIENT);
    NativeVector tmp(N);
    tmp.SetModulus(modulus);
    auto Qmod_double{modulus.ConvertToDouble() / element.GetModulus().ConvertToDouble()};
    for (size_t j = 0; j < N; ++j) {
        tmp[j] = NativeInteger(static_cast<BasicInteger>(std::floor(0.5 + input[j].ConvertToDouble() * Qmod_double)))
                     .Mod(modulus);
    }
    m_vectors[0].SetValues(std::move(tmp), Format::COEFFICIENT);
    m_params->SetOriginalModulus(modulus);
}

template <typename VecType>
void DCRTPolyImpl<VecType>::AddILElementOne() {
    if (m_format != Format::EVALUATION)
        OPENFHE_THROW(std::string(__func__) + ": only available in COEFFICIENT format.");
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
        OPENFHE_THROW(std::string(__func__) + ": Input has no elements to drop.");
    if (m_vectors.size() == 1)
        OPENFHE_THROW(std::string(__func__) + ": Removing last element of DCRTPoly renders it invalid.");
    m_vectors.resize(m_vectors.size() - 1);
    DCRTPolyImpl::Params* newP = new DCRTPolyImpl::Params(*m_params);
    newP->PopLastParam();
    m_params.reset(newP);
}

template <typename VecType>
void DCRTPolyImpl<VecType>::DropLastElements(size_t i) {
    if (m_vectors.size() <= i)
        OPENFHE_THROW(std::string(__func__) + ": Too few towers in input.");
    m_vectors.resize(m_vectors.size() - i);
    DCRTPolyImpl::Params* newP = new DCRTPolyImpl::Params(*m_params);
    for (size_t j = 0; j < i; ++j)
        newP->PopLastParam();
    m_params.reset(newP);
}

// used for CKKS rescaling
template <typename VecType>
void DCRTPolyImpl<VecType>::DropLastElementAndScale(const std::vector<NativeInteger>& QlQlInvModqlDivqlModq,
                                                    const std::vector<NativeInteger>& qlInvModq) {
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

/*
 * This method applies Chinese Remainder Interpolation on a DCRTPoly
 * How the Algorithm works:
 * View the DCRTPoly as a (t = Number of Towers) x (r = ring Dimension) Matrix M.
 * Let qt denote the bigModulus (product of each tower moduli), qi denote the
 * modulus of a particular tower, and V be a BigVector of length r.
 * For j = 0 --> r-1, calculate
 * V[j] = Sigma(i = 0 --> t-1) { M(i,j) * qt/qi * [(qt/qi)^(-1) mod qi] } mod qt
 */
template <typename VecType>
typename DCRTPolyImpl<VecType>::PolyLargeType DCRTPolyImpl<VecType>::CRTInterpolate() const {
    if (m_format != Format::COEFFICIENT)
        OPENFHE_THROW(std::string(__func__) + ": Only available in COEFFICIENT format.");

    const uint32_t t(m_vectors.size());
    const uint32_t r{m_params->GetRingDimension()};
    const Integer qt{m_params->GetModulus()};
    Integer tmp1, tmp2;

    std::vector<Integer> multiplier;
    multiplier.reserve(t);
    for (uint32_t i = 0; i < t; ++i) {
        tmp1 = m_vectors[i].GetModulus().ConvertToInt();  // qi
        tmp2 = qt / tmp1;
        multiplier.emplace_back(tmp2.ModInverse(tmp1) * tmp2);  // qt/qi * [(qt/qi)^(-1) mod qi]
    }

    VecType V(r, qt);

#pragma omp parallel for private(tmp1) num_threads(OpenFHEParallelControls.GetThreadLimit(8))
    for (uint32_t j = 0; j < r; ++j) {
        for (uint32_t i = 0; i < t; ++i)
            V[j] += (tmp1 = m_vectors[i].GetValues()[j].ConvertToInt()) * multiplier[i];
        V[j].ModEq(qt);
    }

    // Setting the root of unity to ONE as the calculation is expensive and not required.
    DCRTPolyImpl<VecType>::PolyLargeType poly(std::make_shared<ILParamsImpl<Integer>>(2 * r, qt, 1));
    poly.SetValues(std::move(V), Format::COEFFICIENT);
    return poly;
}

/*
 * This method applies Chinese Remainder Interpolation on a
 * single element across all towers of a DCRTPolyImpl and produces
 * an Poly with zeros except at that single element
 */
template <typename VecType>
typename DCRTPolyImpl<VecType>::PolyLargeType DCRTPolyImpl<VecType>::CRTInterpolateIndex(usint i) const {
    if (m_format != Format::COEFFICIENT)
        OPENFHE_THROW(std::string(__func__) + ": Only available in COEFFICIENT format.");

    uint32_t r{m_params->GetRingDimension()};
    const Integer qt{m_params->GetModulus()};
    Integer tmp1, tmp2;
    VecType V(r, qt, 0);
    for (const auto& npoly : m_vectors) {
        tmp1           = npoly.GetModulus().ConvertToInt();  // qi
        tmp2           = qt / tmp1;
        tmp1           = tmp2.ModInverse(tmp1) * tmp2;  // qt/qi * [(qt/qi)^(-1) mod qi]
        const auto& Mi = npoly.GetValues();
        V[i] += tmp1 * (tmp2 = Mi[i].ConvertToInt());
    }

    V[i].ModEq(qt, qt.ComputeMu());

    // Setting the root of unity to ONE as the calculation is expensive and not required.
    DCRTPolyImpl<VecType>::PolyLargeType poly(std::make_shared<ILParamsImpl<Integer>>(2 * r, qt, 1));
    poly.SetValues(std::move(V), Format::COEFFICIENT);
    return poly;
}

template <typename VecType>
typename DCRTPolyImpl<VecType>::PolyType DCRTPolyImpl<VecType>::DecryptionCRTInterpolate(PlaintextModulus ptm) const {
    return this->CRTInterpolate().DecryptionCRTInterpolate(ptm);
}

template <typename VecType>
typename DCRTPolyImpl<VecType>::PolyType DCRTPolyImpl<VecType>::ToNativePoly() const {
    return this->CRTInterpolate().ToNativePoly();
}

template <typename VecType>
typename VecType::Integer DCRTPolyImpl<VecType>::GetWorkingModulus() const {
    typename VecType::Integer modulusQ = 1;
    for (const auto& p : m_params->GetParams())
        modulusQ.MulEq(p->GetModulus());
    return modulusQ;
}

template <typename VecType>
std::shared_ptr<typename DCRTPolyImpl<VecType>::Params> DCRTPolyImpl<VecType>::GetExtendedCRTBasis(
    const std::shared_ptr<Params>& paramsP) const {
    size_t sizeQ  = m_vectors.size();
    size_t sizeQP = sizeQ + paramsP->GetParams().size();
    std::vector<NativeInteger> moduliQP(sizeQP);
    std::vector<NativeInteger> rootsQP(sizeQP);
    const auto& parq = m_params->GetParams();
    for (size_t i = 0; i < sizeQ; ++i) {
        moduliQP[i] = parq[i]->GetModulus();
        rootsQP[i]  = parq[i]->GetRootOfUnity();
    }
    const auto& parp = paramsP->GetParams();
    for (size_t i = sizeQ, j = 0; i < sizeQP; ++i, ++j) {
        moduliQP[i] = parp[j]->GetModulus();
        rootsQP[i]  = parp[j]->GetRootOfUnity();
    }
    return std::make_shared<Params>(2 * m_params->GetRingDimension(), moduliQP, rootsQP);
}

template <typename VecType>
void DCRTPolyImpl<VecType>::TimesQovert(const std::shared_ptr<Params>& paramsQ,
                                        const std::vector<NativeInteger>& tInvModq, const NativeInteger& t,
                                        const NativeInteger& NegQModt, const NativeInteger& NegQModtPrecon) {
    if (tInvModq.size() < m_vectors.size())
        OPENFHE_THROW("Sizes of vectors do not match.");
    uint32_t size(m_vectors.size());
    uint32_t ringDim(m_params->GetRingDimension());
#pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(size))
    for (size_t i = 0; i < size; ++i) {
        auto q{m_vectors[i].GetModulus()};
        auto mu{q.ComputeMu()};
        for (uint32_t ri = 0; ri < ringDim; ++ri) {
            NativeInteger& xi = m_vectors[i][ri];
            xi.ModMulFastConstEq(NegQModt, t, NegQModtPrecon);
            xi.ModMulFastEq(tInvModq[i], q, mu);
        }
    }
}

template <typename VecType>
DCRTPolyImpl<VecType> DCRTPolyImpl<VecType>::ApproxSwitchCRTBasis(
    const std::shared_ptr<Params>& paramsQ, const std::shared_ptr<Params>& paramsP,
    const std::vector<NativeInteger>& QHatInvModq, const std::vector<NativeInteger>& QHatInvModqPrecon,
    const std::vector<std::vector<NativeInteger>>& QHatModp, const std::vector<DoubleNativeInt>& modpBarrettMu) const {
    DCRTPolyImpl<VecType> ans(paramsP, m_format, true);
    uint32_t sizeQ = (m_vectors.size() > paramsQ->GetParams().size()) ? paramsQ->GetParams().size() : m_vectors.size();
    uint32_t sizeP = ans.m_vectors.size();
#if defined(HAVE_INT128) && NATIVEINT == 64
    uint32_t ringDim = m_params->GetRingDimension();
    std::vector<DoubleNativeInt> sum(sizeP);
    #pragma omp parallel for firstprivate(sum) num_threads(OpenFHEParallelControls.GetThreadLimit(8))
    for (uint32_t ri = 0; ri < ringDim; ++ri) {
        std::fill(sum.begin(), sum.end(), 0);
        for (uint32_t i = 0; i < sizeQ; ++i) {
            const auto& qi        = m_vectors[i].GetModulus();
            const auto& xi        = m_vectors[i][ri];
            const auto& QHatModpi = QHatModp[i];
            const auto xQHatInvModqi =
                xi.ModMulFastConst(QHatInvModq[i], qi, QHatInvModqPrecon[i]).template ConvertToInt<uint64_t>();
            for (uint32_t j = 0; j < sizeP; ++j)
                sum[j] += Mul128(xQHatInvModqi, QHatModpi[j].ConvertToInt<uint64_t>());
        }
        for (uint32_t j = 0; j < sizeP; ++j) {
            const auto& pj       = ans.m_vectors[j].GetModulus();
            ans.m_vectors[j][ri] = BarrettUint128ModUint64(sum[j], pj.ConvertToInt(), modpBarrettMu[j]);
        }
    }
#else
    for (uint32_t i = 0; i < sizeQ; ++i) {
        auto xQHatInvModqi = m_vectors[i] * QHatInvModq[i];
        for (uint32_t j = 0; j < sizeP; ++j) {
            auto temp = xQHatInvModqi;
            temp.SwitchModulus(ans.m_vectors[j].GetModulus(), ans.m_vectors[j].GetRootOfUnity(), 0, 0);
            ans.m_vectors[j] += (temp *= QHatModp[i][j]);
        }
    }
#endif
    return ans;
}

template <typename VecType>
void DCRTPolyImpl<VecType>::ApproxModUp(const std::shared_ptr<Params>& paramsQ, const std::shared_ptr<Params>& paramsP,
                                        const std::shared_ptr<Params>& paramsQP,
                                        const std::vector<NativeInteger>& QHatInvModq,
                                        const std::vector<NativeInteger>& QHatInvModqPrecon,
                                        const std::vector<std::vector<NativeInteger>>& QHatModp,
                                        const std::vector<DoubleNativeInt>& modpBarrettMu) {
    // if input polynomial in evaluation representation, store for later use to reduce number of NTTs
    std::vector<DCRTPolyImpl::PolyType> polyInNTT;
    if (m_format == Format::EVALUATION) {
        polyInNTT = m_vectors;
        this->SetFormat(Format::COEFFICIENT);
    }

    auto partP = ApproxSwitchCRTBasis(paramsQ, paramsP, QHatInvModq, QHatInvModqPrecon, QHatModp, modpBarrettMu);

    if (polyInNTT.size() > 0)
        m_vectors = std::move(polyInNTT);

    size_t sizeQP = paramsQP->GetParams().size();
    m_vectors.reserve(sizeQP);
    m_vectors.insert(m_vectors.end(), std::make_move_iterator(partP.m_vectors.begin()),
                     std::make_move_iterator(partP.m_vectors.end()));

#pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(sizeQP))
    for (size_t i = 0; i < sizeQP; ++i)
        m_vectors[i].SetFormat(Format::EVALUATION);
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
    DCRTPolyImpl<VecType> partP(paramsP, m_format, true);
    size_t sizeP = paramsP->GetParams().size();
    size_t sizeQ = m_vectors.size() - sizeP;

#pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(sizeP))
    for (size_t j = 0; j < sizeP; ++j) {
        partP.m_vectors[j] = m_vectors[sizeQ + j];
        partP.m_vectors[j].SetFormat(Format::COEFFICIENT);
        // Multiply everything by -t^(-1) mod P (BGVrns only)
        if (t > 0)
            partP.m_vectors[j] *= tInvModp[j];
    }
    partP.OverrideFormat(Format::COEFFICIENT);

    auto partPSwitchedToQ =
        partP.ApproxSwitchCRTBasis(paramsP, paramsQ, PHatInvModp, PHatInvModpPrecon, PHatModq, modqBarrettMu);

    // Combine the switched DCRTPoly with the Q part of this to get the result
    DCRTPolyImpl<VecType> ans(paramsQ, Format::EVALUATION, true);
    uint32_t diffQ = paramsQ->GetParams().size() - sizeQ;
    if (diffQ > 0)
        ans.DropLastElements(diffQ);

#pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(sizeQ))
    for (size_t i = 0; i < sizeQ; ++i) {
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
    size_t sizeQ = m_vectors.size();
    size_t sizeP = paramsP->GetParams().size();
    /*
    // TODO: do we really want/need all of these checks?
    if (sizeQ == 0)
        OPENFHE_THROW("sizeQ must be positive");
    if (sizeP == 0)
        OPENFHE_THROW("sizeP must be positive");
    if (QHatInvModq.size() < sizeQ)
        OPENFHE_THROW("Size of QHatInvModq " + std::to_string(QHatInvModq.size()) +
                                        " is less than sizeQ " + std::to_string(sizeQ));
    if (QHatInvModqPrecon.size() < sizeQ)
        OPENFHE_THROW("Size of QHatInvModqPrecon " + std::to_string(QHatInvModqPrecon.size()) +
                                        " is less than sizeQ " + std::to_string(sizeQ));
    if (qInv.size() < sizeQ)
        OPENFHE_THROW("Size of qInv " + std::to_string(qInv.size()) + " is less than sizeQ " + std::to_string(sizeQ));
    if (alphaQModp.size() < sizeQ + 1)
        OPENFHE_THROW("Size of alphaQModp " + std::to_string(alphaQModp.size()) +
                                        " is less than sizeQ + 1 " + std::to_string(sizeQ + 1));
    if (alphaQModp[0].size() < sizeP)
        OPENFHE_THROW("Size of alphaQModp[0] " + std::to_string(alphaQModp[0].size()) +
                                        " is less than sizeP " + std::to_string(sizeP));
    if (QHatModp.size() < sizeP)
        OPENFHE_THROW("Size of QHatModp " + std::to_string(QHatModp.size()) + " is less than sizeP " +
                                        std::to_string(sizeP));
    if (QHatModp[0].size() < sizeQ)
        OPENFHE_THROW("Size of QHatModp[0] " + std::to_string(QHatModp[0].size()) +
                                        " is less than sizeQ " + std::to_string(sizeQ));
*/

    std::vector<NativeInteger> xQHatInvModq(sizeQ);
    [[maybe_unused]] std::vector<NativeInteger> mu;
    mu.reserve(sizeP);
    for (const auto& p : paramsP->GetParams())
        mu.push_back(p->GetModulus().ComputeMu());

    DCRTPolyImpl<VecType> ans(paramsP, m_format, true);
    uint32_t ringDim = m_params->GetRingDimension();

#pragma omp parallel for firstprivate(xQHatInvModq) num_threads(OpenFHEParallelControls.GetThreadLimit(8))
    for (uint32_t ri = 0; ri < ringDim; ++ri) {
        double nu{0.5};
        for (size_t i = 0; i < sizeQ; ++i) {
            const auto& qi = m_vectors[i].GetModulus();
            // computes [x_i (Q/q_i)^{-1}]_{q_i}
            xQHatInvModq[i] = m_vectors[i][ri].ModMulFastConst(QHatInvModq[i], qi, QHatInvModqPrecon[i]);
            // to keep track of the number of q-overflows
            nu += xQHatInvModq[i].ConvertToDouble() * qInv[i];
        }
        // alpha corresponds to the number of overflows, 0 <= static_cast<size_t>(nu) <= sizeQ
        const auto& alphaQModpri = alphaQModp[static_cast<size_t>(nu)];

        for (size_t j = 0; j < sizeP; ++j) {
            const auto& pj        = ans.m_vectors[j].GetModulus();
            const auto& QHatModpj = QHatModp[j];
#if defined(HAVE_INT128) && NATIVEINT == 64
            DoubleNativeInt curValue = 0;
            for (size_t i = 0; i < sizeQ; ++i)
                curValue += Mul128(xQHatInvModq[i].ConvertToInt(), QHatModpj[i].ConvertToInt());
            const auto& curNativeValue =
                NativeInteger(BarrettUint128ModUint64(curValue, pj.ConvertToInt(), modpBarrettMu[j]));
            ans.m_vectors[j][ri] = curNativeValue.ModSubFast(alphaQModpri[j], pj);
#else
            for (size_t i = 0; i < sizeQ; ++i)
                ans.m_vectors[j][ri].ModAddFastEq(xQHatInvModq[i].ModMul(QHatModpj[i], pj, mu[j]), pj);
            ans.m_vectors[j][ri].ModSubFastEq(alphaQModpri[j], pj);
#endif
        }
    }
    return ans;
}

template <typename VecType>
void DCRTPolyImpl<VecType>::ExpandCRTBasis(
    const std::shared_ptr<Params>& paramsQP, const std::shared_ptr<Params>& paramsP,
    const std::vector<NativeInteger>& QHatInvModq, const std::vector<NativeInteger>& QHatInvModqPrecon,
    const std::vector<std::vector<NativeInteger>>& QHatModp, const std::vector<std::vector<NativeInteger>>& alphaQModp,
    const std::vector<DoubleNativeInt>& modpBarrettMu, const std::vector<double>& qInv, Format resultFormat) {
    // if input polynomial in evaluation representation, store for later use to reduce number of NTTs
    std::vector<DCRTPolyImpl::PolyType> polyInNTT;
    if (m_format == Format::EVALUATION) {
        polyInNTT = m_vectors;
        this->SetFormat(Format::COEFFICIENT);
    }

    auto partP = SwitchCRTBasis(paramsP, QHatInvModq, QHatInvModqPrecon, QHatModp, alphaQModp, modpBarrettMu, qInv);

    if ((resultFormat == Format::EVALUATION) && (polyInNTT.size() > 0))
        m_vectors = std::move(polyInNTT);

    size_t sizeQP = paramsQP->GetParams().size();
    m_vectors.reserve(sizeQP);
    m_vectors.insert(m_vectors.end(), std::make_move_iterator(partP.m_vectors.begin()),
                     std::make_move_iterator(partP.m_vectors.end()));

#pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(sizeQP))
    for (size_t i = 0; i < sizeQP; ++i)
        m_vectors[i].SetFormat(resultFormat);
    m_format = resultFormat;
    m_params = paramsQP;
}

template <typename VecType>
void DCRTPolyImpl<VecType>::ExpandCRTBasisReverseOrder(
    const std::shared_ptr<Params>& paramsQP, const std::shared_ptr<Params>& paramsP,
    const std::vector<NativeInteger>& QHatInvModq, const std::vector<NativeInteger>& QHatInvModqPrecon,
    const std::vector<std::vector<NativeInteger>>& QHatModp, const std::vector<std::vector<NativeInteger>>& alphaQModp,
    const std::vector<DoubleNativeInt>& modpBarrettMu, const std::vector<double>& qInv, Format resultFormat) {
    // if input polynomial in evaluation representation, store for later use to reduce number of NTTs
    std::vector<DCRTPolyImpl::PolyType> polyInNTT;
    if (m_format == Format::EVALUATION) {
        polyInNTT = m_vectors;
        this->SetFormat(Format::COEFFICIENT);
    }

    auto partP = SwitchCRTBasis(paramsP, QHatInvModq, QHatInvModqPrecon, QHatModp, alphaQModp, modpBarrettMu, qInv);

    if ((resultFormat == Format::EVALUATION) && (polyInNTT.size() > 0))
        m_vectors = std::move(polyInNTT);

    size_t sizeQP = paramsQP->GetParams().size();
    partP.m_vectors.reserve(sizeQP);
    partP.m_vectors.insert(partP.m_vectors.end(), std::make_move_iterator(m_vectors.begin()),
                           std::make_move_iterator(m_vectors.end()));
    m_vectors = std::move(partP.m_vectors);

#pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(sizeQP))
    for (size_t i = 0; i < sizeQP; ++i)
        m_vectors[i].SetFormat(resultFormat);
    m_format = resultFormat;
    m_params = paramsQP;
}

// TODO: revisit after issue #237 is resolved
template <typename VecType>
void DCRTPolyImpl<VecType>::FastExpandCRTBasisPloverQ(const Precomputations& precomputed) {
#if defined(HAVE_INT128) && NATIVEINT == 64
    auto partPl =
        ApproxSwitchCRTBasis(m_params, precomputed.paramsPl, precomputed.mPlQHatInvModq,
                             precomputed.mPlQHatInvModqPrecon, precomputed.qInvModp, precomputed.modpBarrettMu);
#else
    DCRTPolyImpl<VecType> partPl(precomputed.paramsPl, m_format, true);
    size_t sizeQ  = m_vectors.size();
    size_t sizePl = partPl.m_vectors.size();
    #if 0
    for (size_t i = 0; i < sizeQ; ++i) {
        auto xQHatInvModqi = m_vectors[i] * precomputed.mPlQHatInvModq[i];
        for (size_t j = 0; j < sizePl; ++j) {
            auto temp = xQHatInvModqi;
            temp.SwitchModulus(partPl.m_vectors[j].GetModulus(), partPl.m_vectors[j].GetRootOfUnity(), 0, 0);
            partPl.m_vectors[j] += (temp *= precomputed.qInvModp[i][j]);
        }
    }
    #else
    std::vector<NativeInteger> mu;
    mu.reserve(sizePl);
    for (const auto& p : precomputed.paramsPl->GetParams())
        mu.push_back(p->GetModulus().ComputeMu());

    uint32_t ringDim = m_params->GetRingDimension();
        #pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(8))
    for (uint32_t ri = 0; ri < ringDim; ++ri) {
        for (size_t i = 0; i < sizeQ; ++i) {
            const auto& qInvModpi = precomputed.qInvModp[i];
            const auto& qi        = m_vectors[i].GetModulus();
            const auto& xi        = m_vectors[i][ri];
            auto xQHatInvModqi =
                xi.ModMulFastConst(precomputed.mPlQHatInvModq[i], qi, precomputed.mPlQHatInvModqPrecon[i]);
            for (size_t j = 0; j < sizePl; ++j) {
                const auto& pj = partPl.m_vectors[j].GetModulus();
                partPl.m_vectors[j][ri].ModAddFastEq(xQHatInvModqi.ModMul(qInvModpi[j], pj, mu[j]), pj);
            }
        }
    }
    #endif
#endif
    auto partQl = partPl.SwitchCRTBasis(precomputed.paramsQl, precomputed.PlHatInvModp, precomputed.PlHatInvModpPrecon,
                                        precomputed.PlHatModq, precomputed.alphaPlModq, precomputed.modqBarrettMu,
                                        precomputed.pInv);
    m_vectors   = std::move(partQl.m_vectors);
    m_vectors.reserve(partQl.m_vectors.size() + partPl.m_vectors.size());
    m_vectors.insert(m_vectors.end(), std::make_move_iterator(partPl.m_vectors.begin()),
                     std::make_move_iterator(partPl.m_vectors.end()));
    m_params = precomputed.paramsQlPl;
}

template <typename VecType>
void DCRTPolyImpl<VecType>::ExpandCRTBasisQlHat(const std::shared_ptr<Params>& paramsQ,
                                                const std::vector<NativeInteger>& QlHatModq,
                                                const std::vector<NativeInteger>& QlHatModqPrecon, const usint sizeQ) {
    size_t sizeQl(m_vectors.size());
    uint32_t ringDim(m_params->GetRingDimension());
#pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(sizeQl))
    for (size_t i = 0; i < sizeQl; ++i) {
        const NativeInteger& qi               = m_vectors[i].GetModulus();
        const NativeInteger& QlHatModqi       = QlHatModq[i];
        const NativeInteger& QlHatModqiPrecon = QlHatModqPrecon[i];
        for (usint ri = 0; ri < ringDim; ri++)
            m_vectors[i][ri].ModMulFastConstEq(QlHatModqi, qi, QlHatModqiPrecon);
    }
    m_vectors.resize(sizeQ);
    for (size_t i = sizeQl; i < sizeQ; ++i) {
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
#pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(4))
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
#pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(4))
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
#pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(4))
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
#pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(4))
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
#pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(4))
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
#pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(4))
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
#pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(4))
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
#pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(4))
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
    size_t sizeQP = m_vectors.size();
    size_t sizeP  = ans.m_vectors.size();
    size_t sizeQ  = sizeQP - sizeP;

    [[maybe_unused]] std::vector<NativeInteger> mu;
    mu.reserve(sizeP);
    for (const auto& p : paramsP->GetParams())
        mu.push_back(p->GetModulus().ComputeMu());

    uint32_t ringDim = m_params->GetRingDimension();
#pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(8))
    for (uint32_t ri = 0; ri < ringDim; ++ri) {
        for (size_t j = 0; j < sizeP; ++j) {
            const auto& pj                     = ans.m_vectors[j].GetModulus();
            const auto& tPSHatInvModsDivsModpj = tPSHatInvModsDivsModp[j];
#if defined(HAVE_INT128) && NATIVEINT == 64
            DoubleNativeInt curValue = 0;
            for (size_t i = 0; i < sizeQ; ++i) {
                const NativeInteger& xi = m_vectors[i][ri];
                curValue += Mul128(xi.ConvertToInt(), tPSHatInvModsDivsModpj[i].ConvertToInt());
            }
            const NativeInteger& xi = m_vectors[sizeQ + j][ri];
            curValue += Mul128(xi.ConvertToInt(), tPSHatInvModsDivsModpj[sizeQ].ConvertToInt());

            ans.m_vectors[j][ri] = BarrettUint128ModUint64(curValue, pj.ConvertToInt(), modpBarretMu[j]);
#else
            for (size_t i = 0; i < sizeQ; ++i) {
                const NativeInteger& xi = m_vectors[i][ri];
                ans.m_vectors[j][ri].ModAddFastEq(xi.ModMul(tPSHatInvModsDivsModpj[i], pj, mu[j]), pj);
            }
            const NativeInteger& xi = m_vectors[sizeQ + j][ri];
            ans.m_vectors[j][ri].ModAddFastEq(xi.ModMul(tPSHatInvModsDivsModpj[sizeQ], pj, mu[j]), pj);
#endif
        }
    }
    return ans;
}

template <typename VecType>
DCRTPolyImpl<VecType> DCRTPolyImpl<VecType>::ScaleAndRound(
    const std::shared_ptr<Params>& paramsOutput, const std::vector<std::vector<NativeInteger>>& tOSHatInvModsDivsModo,
    const std::vector<double>& tOSHatInvModsDivsFrac, const std::vector<DoubleNativeInt>& modoBarretMu) const {
    if constexpr (NATIVEINT == 32)
        OPENFHE_THROW("Use of ScaleAndRound with NATIVEINT == 32 may lead to overflow");

    DCRTPolyImpl<VecType> ans(paramsOutput, m_format, true);
    uint32_t ringDim   = m_params->GetRingDimension();
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

    std::vector<NativeInteger> mu;
    mu.reserve(sizeO);
    for (const auto& p : paramsOutput->GetParams())
        mu.push_back(p->GetModulus().ComputeMu());

#pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(8))
    for (uint32_t ri = 0; ri < ringDim; ++ri) {
        double nu = 0.5;
        for (size_t i = 0; i < sizeI; ++i) {
            // possible loss of precision if modulus greater than 2^53 + 1
            const NativeInteger& xi = m_vectors[i + inputIndex][ri];
            nu += tOSHatInvModsDivsFrac[i] * xi.ConvertToDouble();
        }
#if defined(HAVE_INT128) && NATIVEINT == 64
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
#else
        if (isConvertableToNativeInt(nu)) {
            NativeInteger alpha = static_cast<BasicInteger>(nu);
            for (size_t j = 0; j < sizeO; ++j) {
                const auto& tOSHatInvModsDivsModoj = tOSHatInvModsDivsModo[j];
                const auto& oj                     = ans.m_vectors[j].GetModulus();
                auto& curValue                     = ans.m_vectors[j][ri];
                for (size_t i = 0; i < sizeI; i++) {
                    const auto& xi = m_vectors[i + inputIndex][ri];
                    curValue.ModAddFastEq(xi.ModMul(tOSHatInvModsDivsModoj[i], oj, mu[j]), oj);
                }
                const auto& xi = m_vectors[outputIndex + j][ri];
                curValue.ModAddFastEq(xi.ModMul(tOSHatInvModsDivsModoj[sizeI], oj, mu[j]), oj);
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
                    curValue.ModAddFastEq(xi.ModMul(tOSHatInvModsDivsModoj[i], oj, mu[j]), oj);
                }
                const auto& xi = m_vectors[outputIndex + j][ri];
                curValue.ModAddFastEq(xi.ModMul(tOSHatInvModsDivsModoj[sizeI], oj, mu[j]), oj);
                curValue.ModAddFastEq(exponent.ModMul(mantissa, oj, mu[j]), oj);
            }
        }
#endif
    }
    return ans;
}

template <typename VecType>
typename DCRTPolyImpl<VecType>::PolyType DCRTPolyImpl<VecType>::ScaleAndRound(
    const std::vector<NativeInteger>& moduliQ, const NativeInteger& t, const NativeInteger& tgamma,
    const std::vector<NativeInteger>& tgammaQHatModq, const std::vector<NativeInteger>& tgammaQHatModqPrecon,
    const std::vector<NativeInteger>& negInvqModtgamma,
    const std::vector<NativeInteger>& negInvqModtgammaPrecon) const {
    constexpr uint64_t gammaMinus1 = (1 << 26) - 1;

    uint32_t ringDim = m_params->GetRingDimension();
    uint32_t sizeQ   = m_vectors.size();
    DCRTPolyImpl::PolyType::Vector coefficients(ringDim, t.ConvertToInt());

#pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(8))
    for (uint32_t k = 0; k < ringDim; ++k) {
        // TODO: use 64 bit words in case NativeInteger uses smaller word size
        NativeInteger s = 0;
        for (uint32_t i = 0; i < sizeQ; ++i) {
            // xi*t*gamma*(q/qi)^-1 mod qi
            // -tmp/qi mod gamma*t < 2^58
            const NativeInteger& qi = moduliQ[i];
            s.ModAddFastEq(m_vectors[i][k]
                               .ModMulFastConst(tgammaQHatModq[i], qi, tgammaQHatModqPrecon[i])
                               .ModMulFastConst(negInvqModtgamma[i], tgamma, negInvqModtgammaPrecon[i]),
                           tgamma);
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
    m_params = paramsQ;

    const uint32_t sizeQ   = m_vectors.size() - 1;
    const auto& q          = m_params->GetParams();
    const uint32_t ringDim = m_params->GetRingDimension();

#pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(sizeQ))
    for (uint32_t i = 0; i < sizeQ; ++i) {
        const auto& qi = q[i]->GetModulus();
        for (uint32_t ri = 0; ri < ringDim; ++ri)
            m_vectors[i][ri].ModSubEq(m_vectors[sizeQ][ri], qi);
        m_vectors[i] *= pInvModq[i];
    }
    m_vectors.resize(sizeQ);
}

// Input: dcrtpoly in basis Q
// Output: dcrtpoly in base QBsk = {B U msk}
template <typename VecType>
void DCRTPolyImpl<VecType>::FastBaseConvqToBskMontgomery(
    const std::shared_ptr<Params>& paramsQBsk, const std::vector<NativeInteger>& moduliQ,
    const std::vector<NativeInteger>& moduliBsk, const std::vector<DoubleNativeInt>& modbskBarrettMu,
    const std::vector<NativeInteger>& mtildeQHatInvModq, const std::vector<NativeInteger>& mtildeQHatInvModqPrecon,
    const std::vector<std::vector<NativeInteger>>& QHatModbsk, const std::vector<uint64_t>& QHatModmtilde,
    const std::vector<NativeInteger>& QModbsk, const std::vector<NativeInteger>& QModbskPrecon,
    const uint64_t& negQInvModmtilde, const std::vector<NativeInteger>& mtildeInvModbsk,
    const std::vector<NativeInteger>& mtildeInvModbskPrecon) {
    constexpr uint64_t mtilde         = (uint64_t)1 << 16;
    constexpr uint64_t mtilde_half    = mtilde >> 1;
    constexpr uint64_t mtilde_minus_1 = mtilde - 1;

    // if input polynomial in evaluation representation, store for later use to reduce number of NTTs
    std::vector<DCRTPolyImpl::PolyType> polyInNTT;
    if (m_format == Format::EVALUATION) {
        polyInNTT = m_vectors;
        this->SetFormat(Format::COEFFICIENT);
    }

    m_params = paramsQBsk;
    uint32_t numQ(moduliQ.size());
    uint32_t numBsk(moduliBsk.size());
    uint32_t numQBsk(m_params->GetParams().size());
    uint32_t n(m_params->GetRingDimension());

    m_vectors.reserve(numQBsk);
    for (uint32_t j = 0; j < numBsk; ++j)
        m_vectors.emplace_back(m_params->GetParams()[numQ + j], m_format, true);

    [[maybe_unused]] std::vector<NativeInteger> mu;
    mu.reserve(numBsk);
    for (const auto& q : moduliBsk)
        mu.push_back(q.ComputeMu());

    // first we twist xi by mtilde*(q/qi)^-1 mod qi
    std::vector<NativeInteger> ximtildeQHatModqi(n * numQ);
    std::vector<uint64_t> result_mtilde(n, 0);
    for (uint32_t i = 0; i < numQ; ++i) {
        const auto& mtildeQHatInvModqi       = mtildeQHatInvModq[i];
        const auto& mtildeQHatInvModqPreconi = mtildeQHatInvModqPrecon[i];
        const auto& qHatModmtildei           = QHatModmtilde[i];
        for (uint32_t k = 0; k < n; ++k) {
            ximtildeQHatModqi[i * n + k] =
                m_vectors[i][k].ModMulFastConst(mtildeQHatInvModqi, moduliQ[i], mtildeQHatInvModqPreconi);
            result_mtilde[k] += ximtildeQHatModqi[i * n + k].ConvertToInt<uint64_t>() * qHatModmtildei;
        }
    }
    for (uint32_t k = 0; k < n; ++k) {
        result_mtilde[k] &= mtilde_minus_1;
        result_mtilde[k] *= negQInvModmtilde;
        result_mtilde[k] &= mtilde_minus_1;
    }

#pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(numBsk))
    for (uint32_t j = 0; j < numBsk; ++j) {
        const auto& moduliBskj             = moduliBsk[j];
        const auto& mtildeInvModbskj       = mtildeInvModbsk[j];
        const auto& mtildeInvModbskPreconj = mtildeInvModbskPrecon[j];
        const auto& qModBskj               = QModbsk[j];
        const auto& qModBskjPrecon         = QModbskPrecon[j];
        for (uint32_t k = 0; k < n; ++k) {
#if defined(HAVE_INT128) && NATIVEINT == 64
            DoubleNativeInt result = 0;
            for (uint32_t i = 0; i < numQ; ++i)
                result += Mul128(ximtildeQHatModqi[i * n + k].ConvertToInt<uint64_t>(),
                                 QHatModbsk[i][j].ConvertToInt<uint64_t>());
            m_vectors[numQ + j][k] = BarrettUint128ModUint64(result, moduliBskj.ConvertToInt(), modbskBarrettMu[j]);
#else
            for (uint32_t i = 0; i < numQ; ++i)
                m_vectors[numQ + j][k].ModAddFastEq(
                    ximtildeQHatModqi[i * n + k].ModMul(QHatModbsk[i][j], moduliBskj, mu[j]), moduliBskj);
#endif
            NativeInteger r_m_tilde(result_mtilde[k]);  // mtilde = 2^16 < all moduli of Bsk
            if (result_mtilde[k] >= mtilde_half)
                r_m_tilde += moduliBskj - mtilde;                               // centred remainder
            r_m_tilde.ModMulFastConstEq(qModBskj, moduliBskj, qModBskjPrecon);  // (r_mtilde) * q mod Bski
            r_m_tilde.ModAddFastEq(m_vectors[numQ + j][k], moduliBskj);         // (c``_m + (r_mtilde* q)) mod Bski
            m_vectors[numQ + j][k] = r_m_tilde.ModMulFastConst(mtildeInvModbskj, moduliBskj, mtildeInvModbskPreconj);
        }
        m_vectors[numQ + j].SetFormat(Format::EVALUATION);
    }

    m_format = Format::EVALUATION;
    if (polyInNTT.size() > 0) {
        // if input polynomial was in evaluation representation, use towers for Q from it
        std::move(polyInNTT.begin(), polyInNTT.end(), m_vectors.begin());
    }
    else {
#pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(numQ))
        for (uint32_t i = 0; i < numQ; ++i)
            m_vectors[i].SetFormat(Format::EVALUATION);
    }
}

// Input: poly in basis {q U Bsk}
// Output: approximateFloor(t/q*poly) in basis Bsk
template <typename VecType>
void DCRTPolyImpl<VecType>::FastRNSFloorq(
    const NativeInteger& t, const std::vector<NativeInteger>& moduliQ, const std::vector<NativeInteger>& moduliBsk,
    const std::vector<DoubleNativeInt>& modbskBarrettMu, const std::vector<NativeInteger>& tQHatInvModq,
    const std::vector<NativeInteger>& tQHatInvModqPrecon, const std::vector<std::vector<NativeInteger>>& QHatModbsk,
    const std::vector<std::vector<NativeInteger>>& qInvModbsk, const std::vector<NativeInteger>& tQInvModbsk,
    const std::vector<NativeInteger>& tQInvModbskPrecon) {
    uint32_t numQ(moduliQ.size());
    uint32_t numBsk(moduliBsk.size());
    uint32_t n(m_params->GetRingDimension());

    [[maybe_unused]] std::vector<NativeInteger> mu;
    mu.reserve(numBsk);
    for (const auto& q : moduliBsk)
        mu.push_back(q.ComputeMu());

    // Twist xi by t*(q/qi)^-1 mod qi
    for (uint32_t i = 0; i < numQ; ++i) {
        const auto& tqDivqiModqi       = tQHatInvModq[i];
        const auto& tqDivqiModqiPrecon = tQHatInvModqPrecon[i];
        const auto& moduliQi           = moduliQ[i];
        for (uint32_t k = 0; k < n; ++k)
            m_vectors[i][k].ModMulFastConstEq(tqDivqiModqi, moduliQi, tqDivqiModqiPrecon);
    }

    std::vector<NativeInteger> txiqiDivqModqi(n * numBsk);
#pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(numBsk))
    for (uint32_t j = 0; j < numBsk; ++j) {
        const auto& moduliBskj         = moduliBsk[j];
        const auto& tDivqModBskj       = tQInvModbsk[j];
        const auto& tDivqModBskjPrecon = tQInvModbskPrecon[j];
        for (uint32_t k = 0; k < n; ++k) {
#if defined(HAVE_INT128) && NATIVEINT == 64
            DoubleNativeInt aq = 0;
            for (uint32_t i = 0; i < numQ; ++i) {
                const auto& xi = m_vectors[i][k];
                aq += Mul128(xi.template ConvertToInt<uint64_t>(), qInvModbsk[i][j].ConvertToInt<uint64_t>());
            }
            txiqiDivqModqi[j * n + k] = BarrettUint128ModUint64(aq, moduliBskj.ConvertToInt(), modbskBarrettMu[j]);
#else
            for (uint32_t i = 0; i < numQ; ++i) {
                const auto& xi = m_vectors[i][k];
                txiqiDivqModqi[j * n + k].ModAddFastEq(xi.ModMul(qInvModbsk[i][j], moduliBskj, mu[j]), moduliBskj);
            }
#endif
            // now we have FastBaseConv( |t*ct|q, q, Bsk ) in txiqiDivqModqi
            m_vectors[numQ + j][k].ModMulFastConstEq(tDivqModBskj, moduliBskj, tDivqModBskjPrecon);
            m_vectors[numQ + j][k].ModSubFastEq(txiqiDivqModqi[j * n + k], moduliBskj);
        }
    }
}

// Input: poly in basis Bsk
// Output: poly in basis q
template <typename VecType>
void DCRTPolyImpl<VecType>::FastBaseConvSK(
    const std::shared_ptr<Params>& paramsQ, const std::vector<DoubleNativeInt>& modqBarrettMu,
    const std::vector<NativeInteger>& moduliBsk, const std::vector<DoubleNativeInt>& modbskBarrettMu,
    const std::vector<NativeInteger>& BHatInvModb, const std::vector<NativeInteger>& BHatInvModbPrecon,
    const std::vector<NativeInteger>& BHatModmsk, const NativeInteger& BInvModmsk,
    const NativeInteger& BInvModmskPrecon, const std::vector<std::vector<NativeInteger>>& BHatModq,
    const std::vector<NativeInteger>& BModq, const std::vector<NativeInteger>& BModqPrecon) {
    uint32_t sizeQ(paramsQ->GetParams().size());

    std::vector<NativeInteger> moduliQ;
    moduliQ.reserve(sizeQ);

    [[maybe_unused]] std::vector<NativeInteger> mu;
    mu.reserve(sizeQ);

    for (const auto& p : paramsQ->GetParams()) {
        moduliQ.push_back(p->GetModulus());
        mu.push_back(p->GetModulus().ComputeMu());
    }

    uint32_t sizeBsk(moduliBsk.size());
    uint32_t sizeBskm1(sizeBsk - 1);
    uint32_t n(m_params->GetRingDimension());

    std::vector<NativeInteger> alphaskxVector(n, 0);
    [[maybe_unused]] NativeInteger muBsk(moduliBsk[sizeBskm1].ComputeMu());
    NativeInteger mskDivTwo(moduliBsk[sizeBskm1] >> 1);

    for (uint32_t i = 0; i < sizeBskm1; i++) {  // exclude msk residue
        const auto& moduliBski        = moduliBsk[i];
        const auto& bHatModmski       = BHatModmsk[i];
        const auto& bDivBiModBi       = BHatInvModb[i];
        const auto& bDivBiModBiPrecon = BHatInvModbPrecon[i];
        for (uint32_t k = 0; k < n; ++k) {
            m_vectors[sizeQ + i][k].ModMulFastConstEq(bDivBiModBi, moduliBski, bDivBiModBiPrecon);
            alphaskxVector[k].ModAddEq(m_vectors[sizeQ + i][k].ModMul(bHatModmski, moduliBsk[sizeBskm1], muBsk),
                                       moduliBsk[sizeBskm1]);
        }
    }
    for (uint32_t k = 0; k < n; ++k) {
        alphaskxVector[k] = alphaskxVector[k].ModSubFast(m_vectors[sizeQ + sizeBskm1][k], moduliBsk[sizeBskm1]);
        alphaskxVector[k].ModMulFastConstEq(BInvModmsk, moduliBsk[sizeBskm1], BInvModmskPrecon);
    }

#pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(sizeQ))
    for (uint32_t j = 0; j < sizeQ; ++j) {
        const auto& moduliQj     = moduliQ[j];
        const auto& bModqj       = BModq[j];
        const auto& bModqjPrecon = BModqPrecon[j];
        for (uint32_t k = 0; k < n; ++k) {
#if defined(HAVE_INT128) && NATIVEINT == 64
            DoubleNativeInt result = 0;
            for (uint32_t i = 0; i < sizeBskm1; ++i) {  // exclude msk residue
                const auto& xi = m_vectors[sizeQ + i][k];
                result += Mul128(xi.template ConvertToInt<uint64_t>(), BHatModq[i][j].ConvertToInt<uint64_t>());
            }
            m_vectors[j][k] = BarrettUint128ModUint64(result, moduliQj.ConvertToInt(), modqBarrettMu[j]);
#else
            NativeInteger result(0);
            for (uint32_t i = 0; i < sizeBskm1; ++i) {  // exclude msk residue
                const auto& xi = m_vectors[sizeQ + i][k];
                result.ModAddFastEq(xi.ModMul(BHatModq[i][j], moduliQj, mu[j]), moduliQ[j]);
            }
            m_vectors[j][k] = result;
#endif
            // do (m_vector - alphaskx*M) mod q
            NativeInteger alphaskBModqj = alphaskxVector[k];
            if (alphaskBModqj > mskDivTwo)
                alphaskBModqj = alphaskBModqj.ModSubFast(moduliBsk[sizeBskm1], moduliQ[j]);
            alphaskBModqj.ModMulFastConstEq(bModqj, moduliQ[j], bModqjPrecon);
            m_vectors[j][k] = m_vectors[j][k].ModSubFast(alphaskBModqj, moduliQ[j]);
        }
    }

    m_params = paramsQ;

    // drop extra vectors
    if (sizeQ < m_vectors.size()) {
        auto starti = m_vectors.begin() + sizeQ;
        if (starti + sizeBsk >= m_vectors.end())
            m_vectors.erase(starti, m_vectors.end());
        else
            m_vectors.erase(starti, starti + sizeBsk);
    }
}

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
        OPENFHE_THROW(errMsg);
    }

    m_vectors[index].SwitchModulus(PolyType::Integer(modulus.ConvertToInt()),
                                   PolyType::Integer(rootOfUnity.ConvertToInt()), 0, 0);
    m_params->RecalculateModulus();
}

template <typename VecType>
bool DCRTPolyImpl<VecType>::InverseExists() const {
    for (const auto& v : m_vectors) {
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
