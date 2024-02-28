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
  Represents integer lattice elements with double-CRT
 */

#ifndef LBCRYPTO_INC_LATTICE_HAL_DEFAULT_DCRTPOLY_H
#define LBCRYPTO_INC_LATTICE_HAL_DEFAULT_DCRTPOLY_H

#include "lattice/hal/default/ildcrtparams.h"
#include "lattice/hal/default/poly.h"
#include "lattice/hal/dcrtpoly-interface.h"

#include "math/math-hal.h"
#include "math/distrgen.h"

#include "utils/exception.h"
#include "utils/inttypes.h"
#include "utils/parallel.h"

#include <functional>
#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace lbcrypto {

template <typename VecType>
class DCRTPolyImpl final : public DCRTPolyInterface<DCRTPolyImpl<VecType>, VecType, NativeVector, PolyImpl> {
public:
    using Vector                = VecType;
    using Integer               = typename VecType::Integer;
    using Params                = ILDCRTParams<Integer>;
    using PolyType              = PolyImpl<NativeVector>;
    using PolyLargeType         = PolyImpl<VecType>;
    using DCRTPolyType          = DCRTPolyImpl<VecType>;
    using DCRTPolyInterfaceType = DCRTPolyInterface<DCRTPolyImpl<VecType>, VecType, NativeVector, PolyImpl>;
    using Precomputations       = typename DCRTPolyInterfaceType::CRTBasisExtensionPrecomputations;
    using DggType               = typename DCRTPolyInterfaceType::DggType;
    using DugType               = typename DCRTPolyInterfaceType::DugType;
    using TugType               = typename DCRTPolyInterfaceType::TugType;
    using BugType               = typename DCRTPolyInterfaceType::BugType;

    DCRTPolyImpl() = default;

    DCRTPolyImpl(const DCRTPolyType& e) noexcept : m_params{e.m_params}, m_format{e.m_format}, m_vectors{e.m_vectors} {}
    DCRTPolyType& operator=(const DCRTPolyType& rhs) noexcept override {
        m_params  = rhs.m_params;
        m_format  = rhs.m_format;
        m_vectors = rhs.m_vectors;
        return *this;
    }

    DCRTPolyImpl(const PolyLargeType& e, const std::shared_ptr<Params>& params) noexcept;
    DCRTPolyType& operator=(const PolyLargeType& rhs) noexcept;

    DCRTPolyImpl(const PolyType& e, const std::shared_ptr<Params>& params) noexcept;
    DCRTPolyType& operator=(const PolyType& rhs) noexcept;

    DCRTPolyImpl(DCRTPolyType&& e) noexcept
        : m_params{std::move(e.m_params)}, m_format{e.m_format}, m_vectors{std::move(e.m_vectors)} {}
    DCRTPolyType& operator=(DCRTPolyType&& rhs) noexcept override {
        m_params  = std::move(rhs.m_params);
        m_format  = std::move(rhs.m_format);
        m_vectors = std::move(rhs.m_vectors);
        return *this;
    }

    explicit DCRTPolyImpl(const std::vector<PolyType>& elements);

    DCRTPolyImpl(const std::shared_ptr<Params>& params, Format format = Format::EVALUATION,
                 bool initializeElementToZero = false) noexcept
        : m_params{params}, m_format{format} {
        m_vectors.reserve(m_params->GetParams().size());
        for (const auto& p : m_params->GetParams())
            m_vectors.emplace_back(p, m_format, initializeElementToZero);
    }

    DCRTPolyImpl(const DggType& dgg, const std::shared_ptr<Params>& p, Format f = Format::EVALUATION);
    DCRTPolyImpl(const BugType& bug, const std::shared_ptr<Params>& p, Format f = Format::EVALUATION);
    DCRTPolyImpl(const TugType& tug, const std::shared_ptr<Params>& p, Format f = Format::EVALUATION, uint32_t h = 0);
    DCRTPolyImpl(DugType& dug, const std::shared_ptr<Params>& p, Format f = Format::EVALUATION);

    DCRTPolyType& operator=(std::initializer_list<uint64_t> rhs) noexcept override;
    DCRTPolyType& operator=(uint64_t val) noexcept;
    DCRTPolyType& operator=(const std::vector<int64_t>& rhs) noexcept;
    DCRTPolyType& operator=(const std::vector<int32_t>& rhs) noexcept;
    DCRTPolyType& operator=(std::initializer_list<std::string> rhs) noexcept;

    DCRTPolyType CloneWithNoise(const DiscreteGaussianGeneratorImpl<VecType>& dgg, Format format) const override;
    DCRTPolyType CloneTowers(uint32_t startTower, uint32_t endTower) const;

    bool operator==(const DCRTPolyType& rhs) const override;

    DCRTPolyType& operator+=(const DCRTPolyType& rhs) override;
    DCRTPolyType& operator+=(const Integer& rhs) override;
    DCRTPolyType& operator+=(const NativeInteger& rhs) override;
    DCRTPolyType& operator-=(const DCRTPolyType& rhs) override;
    DCRTPolyType& operator-=(const Integer& rhs) override;
    DCRTPolyType& operator-=(const NativeInteger& rhs) override;
    DCRTPolyType& operator*=(const DCRTPolyType& rhs) override {
        size_t size{m_vectors.size()};
#pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(size))
        for (size_t i = 0; i < size; ++i)
            m_vectors[i] *= rhs.m_vectors[i];
        return *this;
    }
    DCRTPolyType& operator*=(const Integer& rhs) override;
    DCRTPolyType& operator*=(const NativeInteger& rhs) override;

    DCRTPolyType Negate() const override;
    DCRTPolyType operator-() const override;

    std::vector<DCRTPolyType> BaseDecompose(usint baseBits, bool evalModeAnswer) const override;
    std::vector<DCRTPolyType> PowersOfBase(usint baseBits) const override;
    std::vector<DCRTPolyType> CRTDecompose(uint32_t baseBits) const;

    DCRTPolyType AutomorphismTransform(uint32_t i) const override;
    DCRTPolyType AutomorphismTransform(uint32_t i, const std::vector<uint32_t>& vec) const override;

    DCRTPolyType Plus(const Integer& rhs) const override;
    DCRTPolyType Plus(const std::vector<Integer>& rhs) const;
    DCRTPolyType Plus(const DCRTPolyType& rhs) const override {
        if (m_params->GetRingDimension() != rhs.m_params->GetRingDimension())
            OPENFHE_THROW("RingDimension missmatch");
        if (m_format != rhs.m_format)
            OPENFHE_THROW("Format missmatch");
        size_t size{m_vectors.size()};
        if (size != rhs.m_vectors.size())
            OPENFHE_THROW("tower size mismatch; cannot add");
        if (m_vectors[0].GetModulus() != rhs.m_vectors[0].GetModulus())
            OPENFHE_THROW("Modulus missmatch");
        DCRTPolyType tmp(m_params, m_format);
#pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(size))
        for (size_t i = 0; i < size; ++i)
            tmp.m_vectors[i] = m_vectors[i].PlusNoCheck(rhs.m_vectors[i]);
        return tmp;
    }

    DCRTPolyType Minus(const DCRTPolyType& rhs) const override;
    DCRTPolyType Minus(const Integer& rhs) const override;
    DCRTPolyType Minus(const std::vector<Integer>& rhs) const;

    DCRTPolyType Times(const DCRTPolyType& rhs) const override {
        if (m_params->GetRingDimension() != rhs.m_params->GetRingDimension())
            OPENFHE_THROW("RingDimension missmatch");
        if (m_format != Format::EVALUATION || rhs.m_format != Format::EVALUATION)
            OPENFHE_THROW("operator* for DCRTPolyImpl supported only in Format::EVALUATION");
        size_t size{m_vectors.size()};
        if (size != rhs.m_vectors.size())
            OPENFHE_THROW("tower size mismatch; cannot multiply");
        if (m_vectors[0].GetModulus() != rhs.m_vectors[0].GetModulus())
            OPENFHE_THROW("Modulus missmatch");
        DCRTPolyType tmp(m_params, m_format);
#pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(size))
        for (size_t i = 0; i < size; ++i)
            tmp.m_vectors[i] = m_vectors[i].TimesNoCheck(rhs.m_vectors[i]);
        return tmp;
    }
    DCRTPolyType Times(const Integer& rhs) const override;
    DCRTPolyType Times(const std::vector<Integer>& rhs) const;
    DCRTPolyType Times(NativeInteger::SignedNativeInt rhs) const override;
#if NATIVEINT != 64
    DCRTPolyType Times(int64_t rhs) const {
        return Times(static_cast<NativeInteger::SignedNativeInt>(rhs));
    }
#endif
    DCRTPolyType Times(const std::vector<NativeInteger>& rhs) const;
    DCRTPolyType TimesNoCheck(const std::vector<NativeInteger>& rhs) const;

    DCRTPolyType MultiplicativeInverse() const override;
    bool InverseExists() const override;
    bool IsEmpty() const override;

    void SetValuesToZero() override;
    void AddILElementOne() override;
    void DropLastElement() override;
    void DropLastElements(size_t i) override;
    void DropLastElementAndScale(const std::vector<NativeInteger>& QlQlInvModqlDivqlModq,
                                 const std::vector<NativeInteger>& qlInvModq) override;

    void ModReduce(const NativeInteger& t, const std::vector<NativeInteger>& tModqPrecon,
                   const NativeInteger& negtInvModq, const NativeInteger& negtInvModqPrecon,
                   const std::vector<NativeInteger>& qlInvModq,
                   const std::vector<NativeInteger>& qlInvModqPrecon) override;

    PolyLargeType CRTInterpolate() const override;
    PolyType DecryptionCRTInterpolate(PlaintextModulus ptm) const override;
    PolyType ToNativePoly() const override;
    PolyLargeType CRTInterpolateIndex(usint i) const override;
    Integer GetWorkingModulus() const override;

    void SetValuesModSwitch(const DCRTPolyType& element, const NativeInteger& modulus) override;

    std::shared_ptr<Params> GetExtendedCRTBasis(const std::shared_ptr<Params>& paramsP) const override;

    void TimesQovert(const std::shared_ptr<Params>& paramsQ, const std::vector<NativeInteger>& tInvModq,
                     const NativeInteger& t, const NativeInteger& NegQModt,
                     const NativeInteger& NegQModtPrecon) override;

    DCRTPolyType ApproxSwitchCRTBasis(const std::shared_ptr<Params>& paramsQ, const std::shared_ptr<Params>& paramsP,
                                      const std::vector<NativeInteger>& QHatInvModq,
                                      const std::vector<NativeInteger>& QHatInvModqPrecon,
                                      const std::vector<std::vector<NativeInteger>>& QHatModp,
                                      const std::vector<DoubleNativeInt>& modpBarrettMu) const override;

    void ApproxModUp(const std::shared_ptr<Params>& paramsQ, const std::shared_ptr<Params>& paramsP,
                     const std::shared_ptr<Params>& paramsQP, const std::vector<NativeInteger>& QHatInvModq,
                     const std::vector<NativeInteger>& QHatInvModqPrecon,
                     const std::vector<std::vector<NativeInteger>>& QHatModp,
                     const std::vector<DoubleNativeInt>& modpBarrettMu) override;

    DCRTPolyType ApproxModDown(
        const std::shared_ptr<Params>& paramsQ, const std::shared_ptr<Params>& paramsP,
        const std::vector<NativeInteger>& PInvModq, const std::vector<NativeInteger>& PInvModqPrecon,
        const std::vector<NativeInteger>& PHatInvModp, const std::vector<NativeInteger>& PHatInvModpPrecon,
        const std::vector<std::vector<NativeInteger>>& PHatModq, const std::vector<DoubleNativeInt>& modqBarrettMu,
        const std::vector<NativeInteger>& tInvModp, const std::vector<NativeInteger>& tInvModpPrecon,
        const NativeInteger& t, const std::vector<NativeInteger>& tModqPrecon) const override;

    DCRTPolyType SwitchCRTBasis(const std::shared_ptr<Params>& paramsP, const std::vector<NativeInteger>& QHatInvModq,
                                const std::vector<NativeInteger>& QHatInvModqPrecon,
                                const std::vector<std::vector<NativeInteger>>& QHatModp,
                                const std::vector<std::vector<NativeInteger>>& alphaQModp,
                                const std::vector<DoubleNativeInt>& modpBarrettMu,
                                const std::vector<double>& qInv) const override;

    void ExpandCRTBasis(const std::shared_ptr<Params>& paramsQP, const std::shared_ptr<Params>& paramsP,
                        const std::vector<NativeInteger>& QHatInvModq,
                        const std::vector<NativeInteger>& QHatInvModqPrecon,
                        const std::vector<std::vector<NativeInteger>>& QHatModp,
                        const std::vector<std::vector<NativeInteger>>& alphaQModp,
                        const std::vector<DoubleNativeInt>& modpBarrettMu, const std::vector<double>& qInv,
                        Format resultFormat) override;

    void ExpandCRTBasisReverseOrder(const std::shared_ptr<Params>& paramsQP, const std::shared_ptr<Params>& paramsP,
                                    const std::vector<NativeInteger>& QHatInvModq,
                                    const std::vector<NativeInteger>& QHatInvModqPrecon,
                                    const std::vector<std::vector<NativeInteger>>& QHatModp,
                                    const std::vector<std::vector<NativeInteger>>& alphaQModp,
                                    const std::vector<DoubleNativeInt>& modpBarrettMu, const std::vector<double>& qInv,
                                    Format resultFormat) override;

    void FastExpandCRTBasisPloverQ(const Precomputations& precomputed) override;

    void ExpandCRTBasisQlHat(const std::shared_ptr<Params>& paramsQ, const std::vector<NativeInteger>& QlHatModq,
                             const std::vector<NativeInteger>& QlHatModqPrecon, const usint sizeQ) override;

    PolyType ScaleAndRound(const NativeInteger& t, const std::vector<NativeInteger>& tQHatInvModqDivqModt,
                           const std::vector<NativeInteger>& tQHatInvModqDivqModtPrecon,
                           const std::vector<NativeInteger>& tQHatInvModqBDivqModt,
                           const std::vector<NativeInteger>& tQHatInvModqBDivqModtPrecon,
                           const std::vector<double>& tQHatInvModqDivqFrac,
                           const std::vector<double>& tQHatInvModqBDivqFrac) const override;

    DCRTPolyType ApproxScaleAndRound(const std::shared_ptr<Params>& paramsP,
                                     const std::vector<std::vector<NativeInteger>>& tPSHatInvModsDivsModp,
                                     const std::vector<DoubleNativeInt>& modpBarretMu) const override;

    DCRTPolyType ScaleAndRound(const std::shared_ptr<Params>& paramsOutput,
                               const std::vector<std::vector<NativeInteger>>& tOSHatInvModsDivsModo,
                               const std::vector<double>& tOSHatInvModsDivsFrac,
                               const std::vector<DoubleNativeInt>& modoBarretMu) const override;

    PolyType ScaleAndRound(const std::vector<NativeInteger>& moduliQ, const NativeInteger& t,
                           const NativeInteger& tgamma, const std::vector<NativeInteger>& tgammaQHatModq,
                           const std::vector<NativeInteger>& tgammaQHatModqPrecon,
                           const std::vector<NativeInteger>& negInvqModtgamma,
                           const std::vector<NativeInteger>& negInvqModtgammaPrecon) const override;

    void ScaleAndRoundPOverQ(const std::shared_ptr<Params>& paramsQ,
                             const std::vector<NativeInteger>& pInvModq) override;

    void FastBaseConvqToBskMontgomery(
        const std::shared_ptr<Params>& paramsQBsk, const std::vector<NativeInteger>& moduliQ,
        const std::vector<NativeInteger>& moduliBsk, const std::vector<DoubleNativeInt>& modbskBarrettMu,
        const std::vector<NativeInteger>& mtildeQHatInvModq, const std::vector<NativeInteger>& mtildeQHatInvModqPrecon,
        const std::vector<std::vector<NativeInteger>>& QHatModbsk, const std::vector<uint64_t>& QHatModmtilde,
        const std::vector<NativeInteger>& QModbsk, const std::vector<NativeInteger>& QModbskPrecon,
        const uint64_t& negQInvModmtilde, const std::vector<NativeInteger>& mtildeInvModbsk,
        const std::vector<NativeInteger>& mtildeInvModbskPrecon) override;

    void FastRNSFloorq(const NativeInteger& t, const std::vector<NativeInteger>& moduliQ,
                       const std::vector<NativeInteger>& moduliBsk, const std::vector<DoubleNativeInt>& modbskBarrettMu,
                       const std::vector<NativeInteger>& tQHatInvModq,
                       const std::vector<NativeInteger>& tQHatInvModqPrecon,
                       const std::vector<std::vector<NativeInteger>>& QHatModbsk,
                       const std::vector<std::vector<NativeInteger>>& qInvModbsk,
                       const std::vector<NativeInteger>& tQInvModbsk,
                       const std::vector<NativeInteger>& tQInvModbskPrecon) override;

    void FastBaseConvSK(const std::shared_ptr<Params>& paramsQ, const std::vector<DoubleNativeInt>& modqBarrettMu,
                        const std::vector<NativeInteger>& moduliBsk,
                        const std::vector<DoubleNativeInt>& modbskBarrettMu,
                        const std::vector<NativeInteger>& BHatInvModb,
                        const std::vector<NativeInteger>& BHatInvModbPrecon,
                        const std::vector<NativeInteger>& BHatModmsk, const NativeInteger& BInvModmsk,
                        const NativeInteger& BInvModmskPrecon, const std::vector<std::vector<NativeInteger>>& BHatModq,
                        const std::vector<NativeInteger>& BModq,
                        const std::vector<NativeInteger>& BModqPrecon) override;

    void SwitchFormat() override;

    void SwitchModulusAtIndex(size_t index, const Integer& modulus, const Integer& rootOfUnity) override;

    template <class Archive>
    void save(Archive& ar, std::uint32_t const version) const {
        ar(::cereal::make_nvp("v", m_vectors));
        ar(::cereal::make_nvp("f", m_format));
        ar(::cereal::make_nvp("p", m_params));
    }

    template <class Archive>
    void load(Archive& ar, std::uint32_t const version) {
        if (version > SerializedVersion()) {
            OPENFHE_THROW("serialized object version " + std::to_string(version) +
                          " is from a later version of the library");
        }
        ar(::cereal::make_nvp("v", m_vectors));
        ar(::cereal::make_nvp("f", m_format));
        ar(::cereal::make_nvp("p", m_params));
    }

    static const std::string GetElementName() {
        return "DCRTPolyImpl";
    }

    std::string SerializedObjectName() const override {
        return "DCRTPoly";
    }

    static uint32_t SerializedVersion() {
        return 1;
    }

    inline Format GetFormat() const final {
        return m_format;
    }

    void OverrideFormat(const Format f) final {
        m_format = f;
    }

    inline const std::shared_ptr<Params>& GetParams() const {
        return m_params;
    }

    const std::vector<PolyType>& GetAllElements() const {
        return m_vectors;
    }

    std::vector<PolyType>& GetAllElements() {
        return m_vectors;
    }

    void SetElementAtIndex(usint index, const PolyType& element) {
        m_vectors[index] = element;
    }

    void SetElementAtIndex(usint index, PolyType&& element) {
        m_vectors[index] = std::move(element);
    }

protected:
    std::shared_ptr<Params> m_params{std::make_shared<DCRTPolyImpl::Params>()};
    Format m_format{Format::EVALUATION};
    std::vector<PolyType> m_vectors;
};

}  // namespace lbcrypto

#endif
