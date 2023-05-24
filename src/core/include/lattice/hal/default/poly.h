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
  Creates Represents integer lattice elements
 */

#ifndef LBCRYPTO_INC_LATTICE_HAL_DEFAULT_POLY_H
#define LBCRYPTO_INC_LATTICE_HAL_DEFAULT_POLY_H

#include "lattice/hal/poly-interface.h"
#include "lattice/ildcrtparams.h"
#include "lattice/ilparams.h"

#include "math/distrgen.h"
#include "math/hal.h"
#include "math/nbtheory.h"

#include "utils/exception.h"
#include "utils/inttypes.h"

#include <functional>
#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace lbcrypto {

/**
 * @class PolyImpl
 * @file poly.h
 * @brief Ideal lattice using a vector representation
 */
template <typename VecType>
class PolyImpl final : public PolyInterface<PolyImpl<VecType>, VecType, PolyImpl> {
public:
    using Vector            = VecType;
    using Integer           = typename VecType::Integer;
    using Params            = ILParamsImpl<Integer>;
    using PolyNative        = PolyImpl<NativeVector>;
    using PolyType          = PolyImpl<VecType>;
    using PolyLargeType     = PolyImpl<VecType>;
    using PolyInterfaceType = PolyInterface<PolyImpl<VecType>, VecType, PolyImpl>;
    using DggType           = typename PolyInterfaceType::DggType;
    using DugType           = typename PolyInterfaceType::DugType;
    using TugType           = typename PolyInterfaceType::TugType;
    using BugType           = typename PolyInterfaceType::BugType;

    static const std::string GetElementName() {
        return "PolyImpl";
    }

    ~PolyImpl() override = default;

    PolyImpl();
    PolyImpl(const std::shared_ptr<Params>& params, Format format = Format::EVALUATION,
             bool initializeElementToZero = false);
    PolyImpl(const std::shared_ptr<ILDCRTParams<Integer>>& params, Format format = Format::EVALUATION,
             bool initializeElementToZero = false);
    PolyImpl(bool initializeElementToMax, const std::shared_ptr<Params>& params, Format format = Format::EVALUATION);
    PolyImpl(const DggType& dgg, const std::shared_ptr<Params>& params, Format format = Format::EVALUATION);
    PolyImpl(DugType& dug, const std::shared_ptr<Params>& params, Format format = Format::EVALUATION);
    PolyImpl(const BugType& bug, const std::shared_ptr<Params>& params, Format format = Format::EVALUATION);
    PolyImpl(const TugType& tug, const std::shared_ptr<Params>& params, Format format = Format::EVALUATION,
             uint32_t h = 0);
    PolyImpl(const PolyType& element);
    PolyImpl(const PolyNative& element, Format format);
    PolyImpl(PolyType&& element);

    const PolyType& operator=(const PolyType& rhs) override;
    const PolyType& operator=(const std::vector<int32_t>& rhs) override;
    const PolyType& operator=(const std::vector<int64_t>& rhs) override;
    const PolyType& operator=(std::initializer_list<uint64_t> rhs) override;
    const PolyType& operator=(std::initializer_list<std::string> rhs) override;
    const PolyType& operator=(uint64_t val) override;
    const PolyType& operator=(PolyType&& rhs) override;

    PolyNative DecryptionCRTInterpolate(PlaintextModulus ptm) const override;
    PolyNative ToNativePoly() const final;

    void SetValues(const VecType& values, Format format) override;
    void SetValues(VecType&& values, Format format) override;
    void SetValuesToZero() override;
    void SetValuesToMax() override;

    inline Format GetFormat() const final {
        return m_format;
    }

    inline const std::shared_ptr<Params>& GetParams() const final {
        return m_params;
    }

    inline const VecType& GetValues() const final {
        if (m_values == nullptr)
            OPENFHE_THROW(not_available_error, "No values in PolyImpl");
        return *m_values;
    }

    inline bool IsEmpty() const final {
        return m_values == nullptr;
    }

    inline Integer& at(usint i) final {
        if (m_values == nullptr)
            OPENFHE_THROW(not_available_error, "No values in PolyImpl");
        return m_values->at(i);
    }

    inline const Integer& at(usint i) const final {
        if (m_values == nullptr)
            OPENFHE_THROW(not_available_error, "No values in PolyImpl");
        return m_values->at(i);
    }

    inline Integer& operator[](usint i) final {
        return (*m_values)[i];
    }

    inline const Integer& operator[](usint i) const final {
        return (*m_values)[i];
    }

    PolyImpl Plus(const PolyImpl& element) const override;
    const PolyImpl& operator+=(const PolyImpl& element) override;

    PolyImpl Plus(const Integer& element) const override;
    inline const PolyImpl& operator+=(const Integer& element) override {
        return *this = this->Plus(element);
    }

    PolyImpl Minus(const PolyImpl& element) const override;
    const PolyImpl& operator-=(const PolyImpl& element) override;

    PolyImpl Minus(const Integer& element) const override;
    inline const PolyImpl& operator-=(const Integer& element) override {
        m_values->ModSubEq(element);
        return *this;
    }

    PolyImpl Times(const PolyImpl& element) const override;
    const PolyImpl& operator*=(const PolyImpl& element) override;

    PolyImpl Times(const Integer& element) const override;
    inline const PolyImpl& operator*=(const Integer& element) override {
        m_values->ModMulEq(element);
        return *this;
    }

    PolyImpl Times(NativeInteger::SignedNativeInt element) const override;
#if NATIVEINT != 64
    inline PolyImpl Times(int64_t element) const override {
        return this->Times(static_cast<NativeInteger::SignedNativeInt>(element));
    }
#endif

    PolyImpl MultiplyAndRound(const Integer& p, const Integer& q) const override;
    PolyImpl DivideAndRound(const Integer& q) const override;

    PolyImpl Negate() const override;
    PolyImpl operator-() const override {
        return PolyImpl(m_params, m_format, true) -= *this;
    }

    inline bool operator==(const PolyImpl& rhs) const override {
        return ((m_format == rhs.GetFormat()) && (m_params->GetRootOfUnity() == rhs.GetRootOfUnity()) &&
                (this->GetValues() == rhs.GetValues()));
    }

    void AddILElementOne() override;
    PolyImpl AutomorphismTransform(const usint& k) const override;
    PolyImpl AutomorphismTransform(usint i, const std::vector<usint>& vec) const override;
    PolyImpl MultiplicativeInverse() const override;
    PolyImpl ModByTwo() const override;
    PolyImpl Mod(const Integer& modulus) const override;

    void SwitchModulus(const Integer& modulus, const Integer& rootOfUnity, const Integer& modulusArb,
                       const Integer& rootOfUnityArb) override;
    void SwitchFormat() override;
    void MakeSparse(const uint32_t& wFactor) override;
    bool InverseExists() const override;
    double Norm() const override;
    std::vector<PolyImpl> BaseDecompose(usint baseBits, bool evalModeAnswer) const override;
    std::vector<PolyImpl> PowersOfBase(usint baseBits) const override;

    template <class Archive>
    void save(Archive& ar, std::uint32_t const version) const {
        ar(::cereal::make_nvp("v", m_values));
        ar(::cereal::make_nvp("f", m_format));
        ar(::cereal::make_nvp("p", m_params));
    }

    template <class Archive>
    void load(Archive& ar, std::uint32_t const version) {
        if (version > SerializedVersion()) {
            OPENFHE_THROW(deserialize_error, "serialized object version " + std::to_string(version) +
                                                 " is from a later version of the library");
        }
        ar(::cereal::make_nvp("v", m_values));
        ar(::cereal::make_nvp("f", m_format));
        ar(::cereal::make_nvp("p", m_params));
    }

    std::string SerializedObjectName() const override {
        return "Poly";
    }
    static uint32_t SerializedVersion() {
        return 1;
    }

protected:
    Format m_format;
    std::shared_ptr<Params> m_params;
    std::unique_ptr<VecType> m_values;
    void ArbitrarySwitchFormat();
};

// TODO: fix issue with pke build system so this can be moved back to implementation file
template <>
inline PolyImpl<BigVector>::PolyImpl(const std::shared_ptr<ILDCRTParams<BigInteger>>& params, Format format,
                                     bool initializeElementToZero)
    : m_format(format), m_params(nullptr), m_values(nullptr) {
    const auto c = params->GetCyclotomicOrder();
    const auto m = params->GetModulus();
    m_params     = std::make_shared<ILParams>(c, m, 1);
    if (initializeElementToZero)
        this->SetValuesToZero();
}

}  // namespace lbcrypto

#endif
