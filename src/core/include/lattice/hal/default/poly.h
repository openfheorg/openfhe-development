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

#ifndef SRC_CORE_INCLUDE_LATTICE_HAL_DEFAULT_POLY_H_
#define SRC_CORE_INCLUDE_LATTICE_HAL_DEFAULT_POLY_H_

#include <cstdint>
#include <functional>
#include <initializer_list>
#include <limits>
#include <memory>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>

#include "lattice/hal/default/ildcrtparams.h"
#include "lattice/hal/default/ilparams.h"
#include "lattice/hal/poly-interface.h"
#include "math/distrgen.h"
#include "math/math-hal.h"
#include "math/nbtheory.h"
#include "utils/exception.h"
#include "utils/inttypes.h"

namespace lbcrypto {

/**
 * @class PolyImpl
 * @brief Ideal lattice using a vector representation: a polynomial with coefficients modulo one integer modulus,
 * stored as a single vector of values in COEFFICIENT or EVALUATION format.
 *
 * @tparam VecType the vector type holding the values, e.g. BigVector or NativeVector.
 */
template <typename VecType>
class PolyImpl final : public PolyInterface<PolyImpl<VecType>, VecType, PolyImpl> {
  public:
    using Vector = VecType;
    using Integer = typename VecType::Integer;
    using Params = ILParamsImpl<Integer>;
    using PolyNative = PolyImpl<NativeVector>;
    using PolyType = PolyImpl<VecType>;
    using PolyLargeType = PolyImpl<VecType>;
    using PolyInterfaceType = PolyInterface<PolyImpl<VecType>, VecType, PolyImpl>;
    using DggType = typename PolyInterfaceType::DggType;
    using DugType = typename PolyInterfaceType::DugType;
    using TugType = typename PolyInterfaceType::TugType;
    using BugType = typename PolyInterfaceType::BugType;

    constexpr PolyImpl() = default;

    /**
   * @brief Constructs an element with the given parameters and format; the values are set to zero if requested and
   * left unallocated otherwise.
   *
   * @param params the element parameters (cyclotomic order, modulus, root of unity).
   * @param format the format of the element (COEFFICIENT or EVALUATION).
   * @param initializeElementToZero if true, the values are allocated and set to zero.
   */
    PolyImpl(const std::shared_ptr<Params>& params, Format format = Format::EVALUATION,
             bool initializeElementToZero = false)
        : m_format{format}, m_params{params} {
        if (initializeElementToZero)
            PolyImpl::SetValuesToZero();
    }
    /**
   * @brief Constructs an element from double-CRT parameters: a single-modulus parameter set with the same cyclotomic
   * order, the composite modulus and a root of unity of 1 is created; the values are set to zero if requested and
   * left unallocated otherwise.
   *
   * @param params the double-CRT parameters.
   * @param format the format of the element (COEFFICIENT or EVALUATION).
   * @param initializeElementToZero if true, the values are allocated and set to zero.
   */
    PolyImpl(const std::shared_ptr<ILDCRTParams<Integer>>& params, Format format = Format::EVALUATION,
             bool initializeElementToZero = false)
        : m_format(format), m_params(std::make_shared<Params>(params->GetCyclotomicOrder(), params->GetModulus(), 1)) {
        if (initializeElementToZero)
            this->SetValuesToZero();
    }

    /**
   * @brief Constructs an element with the given parameters and format whose values are all set to modulus - 1 if
   * requested and left unallocated otherwise.
   *
   * @param initializeElementToMax if true, the values are allocated and set to modulus - 1.
   * @param params the element parameters (cyclotomic order, modulus, root of unity).
   * @param format the format of the element (COEFFICIENT or EVALUATION).
   */
    PolyImpl(bool initializeElementToMax, const std::shared_ptr<Params>& params, Format format = Format::EVALUATION)
        : m_format{format}, m_params{params} {
        if (initializeElementToMax)
            PolyImpl::SetValuesToMax();
    }
    /**
   * @brief Constructs an element whose coefficients are sampled from a discrete Gaussian distribution and converted
   * to the requested format.
   *
   * @param dgg the discrete Gaussian generator.
   * @param params the element parameters.
   * @param format the format of the resulting element.
   */
    PolyImpl(const DggType& dgg, const std::shared_ptr<Params>& params, Format format = Format::EVALUATION);
    /**
   * @brief Constructs an element with values sampled uniformly modulo the modulus, recorded as already being in the
   * requested format (no transform is applied).
   *
   * @param dug the discrete uniform generator.
   * @param params the element parameters.
   * @param format the format recorded for the resulting element.
   */
    PolyImpl(DugType& dug, const std::shared_ptr<Params>& params, Format format = Format::EVALUATION);
    /**
   * @brief Constructs an element whose coefficients are sampled from the binary uniform distribution and converted
   * to the requested format.
   *
   * @param bug the binary uniform generator.
   * @param params the element parameters.
   * @param format the format of the resulting element.
   */
    PolyImpl(const BugType& bug, const std::shared_ptr<Params>& params, Format format = Format::EVALUATION);
    /**
   * @brief Constructs an element whose coefficients are sampled from the ternary uniform distribution and converted
   * to the requested format.
   *
   * @param tug the ternary uniform generator.
   * @param params the element parameters.
   * @param format the format of the resulting element.
   * @param h the Hamming weight (number of nonzero coefficients) for the sparse distribution; 0 samples every
   * coefficient uniformly.
   */
    PolyImpl(const TugType& tug, const std::shared_ptr<Params>& params, Format format = Format::EVALUATION,
             uint32_t h = 0);

    /**
   * @brief Copy-converts a native polynomial when this instantiation is itself the native polynomial: the
   * parameters and values are copied and the element is converted to the requested format.
   *
   * @param rhs the native polynomial to copy.
   * @param format the format of the resulting element.
   */
    template <typename T = VecType>
    PolyImpl(const PolyNative& rhs, Format format,
             typename std::enable_if_t<std::is_same_v<T, NativeVector>, bool> = true)
        : m_format{rhs.m_format},
          m_params{rhs.m_params},
          m_values{rhs.m_values ? std::make_unique<VecType>(*rhs.m_values) : nullptr} {
        PolyImpl<VecType>::SetFormat(format);
    }

    /**
   * @brief Converts a native polynomial to this instantiation: new parameters are built from the cyclotomic order,
   * modulus and root of unity of rhs, every value is converted to Integer and the element is converted to the
   * requested format.
   *
   * @param rhs the native polynomial to convert.
   * @param format the format of the resulting element.
   */
    template <typename T = VecType>
    PolyImpl(const PolyNative& rhs, Format format,
             typename std::enable_if_t<!std::is_same_v<T, NativeVector>, bool> = true)
        : m_format{rhs.GetFormat()} {
        auto c{rhs.GetParams()->GetCyclotomicOrder()};
        auto m{rhs.GetParams()->GetModulus().ConvertToInt()};
        auto r{rhs.GetParams()->GetRootOfUnity().ConvertToInt()};
        m_params = std::make_shared<PolyImpl::Params>(c, m, r);

        const auto& v{rhs.GetValues()};
        uint32_t vlen{m_params->GetRingDimension()};
        VecType tmp(vlen);
        tmp.SetModulus(m_params->GetModulus());
        for (uint32_t i{0}; i < vlen; ++i)
            tmp[i] = Integer(v[i]);
        m_values = std::make_unique<VecType>(tmp);
        PolyImpl<VecType>::SetFormat(format);
    }

    PolyImpl(const PolyType& p) noexcept
        : m_format{p.m_format},
          m_params{p.m_params},
          m_values{p.m_values ? std::make_unique<VecType>(*p.m_values) : nullptr} {}

    PolyImpl(PolyType&& p) noexcept
        : m_format{p.m_format}, m_params{std::move(p.m_params)}, m_values{std::move(p.m_values)} {}

    PolyType& operator=(const PolyType& rhs) noexcept override;
    PolyType& operator=(PolyType&& rhs) noexcept override {
        m_format = std::move(rhs.m_format);
        m_params = std::move(rhs.m_params);
        m_values = std::move(rhs.m_values);
        return *this;
    }
    /**
   * @brief Assigns signed coefficients reduced modulo the modulus (including the most negative values), used for
   * trapdoor sampling; missing trailing coefficients are zero and the format becomes COEFFICIENT.
   *
   * @param rhs the signed coefficients.
   * @return the resulting element.
   */
    PolyType& operator=(const std::vector<int32_t>& rhs);
    /**
   * @brief Assigns signed coefficients reduced modulo the modulus (including the most negative values), used for
   * trapdoor sampling; missing trailing coefficients are zero and the format becomes COEFFICIENT.
   *
   * @param rhs the signed coefficients.
   * @return the resulting element.
   */
    PolyType& operator=(const std::vector<int64_t>& rhs);
    /**
   * @brief Assigns unsigned coefficients as given (they are assumed to be less than the modulus); missing trailing
   * coefficients are zero and the format is kept.
   *
   * @param rhs the coefficients.
   * @return the resulting element.
   */
    PolyType& operator=(std::initializer_list<uint64_t> rhs) override;
    /**
   * @brief Assigns coefficients given as decimal strings, reduced modulo the modulus; missing trailing coefficients
   * are zero and the format is kept.
   *
   * @param rhs the coefficients as decimal strings.
   * @return the resulting element.
   */
    PolyType& operator=(std::initializer_list<std::string> rhs);
    /**
   * @brief Assigns the constant polynomial: every entry is set to val (allocating the values if needed) and the
   * format becomes EVALUATION.
   *
   * @param val the constant to assign.
   * @return the resulting element.
   */
    PolyType& operator=(uint64_t val);

    PolyNative DecryptionCRTInterpolate(PlaintextModulus ptm) const override;
    PolyNative ToNativePoly() const final {
        uint32_t vlen{m_params->GetRingDimension()};
        auto c{m_params->GetCyclotomicOrder()};
        NativeInteger m{std::numeric_limits<BasicInteger>::max()};
        auto params{std::make_shared<ILParamsImpl<NativeInteger>>(c, m, 1)};
        typename PolyImpl<VecType>::PolyNative tmp(params, m_format, true);
        for (uint32_t i = 0; i < vlen; ++i)
            tmp[i] = NativeInteger((*m_values)[i]);
        return tmp;
    }

    void SetValues(const VecType& values, Format format) override;
    void SetValues(VecType&& values, Format format) override;

    void SetValuesToZero() override {
        uint32_t r{m_params->GetRingDimension()};
        m_values = std::make_unique<VecType>(r, m_params->GetModulus());
    }

    void SetValuesToMax() override {
        uint32_t r{m_params->GetRingDimension()};
        auto max{m_params->GetModulus() - Integer(1)};
        m_values = std::make_unique<VecType>(r, m_params->GetModulus(), max);
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

    inline const VecType& GetValues() const final {
        if (m_values == nullptr)
            OPENFHE_THROW("No values in PolyImpl");
        return *m_values;
    }

    inline bool IsEmpty() const final {
        return m_values == nullptr;
    }

    inline Integer& at(uint32_t i) final {
        if (m_values == nullptr)
            OPENFHE_THROW("No values in PolyImpl");
        return m_values->at(i);
    }

    inline const Integer& at(uint32_t i) const final {
        if (m_values == nullptr)
            OPENFHE_THROW("No values in PolyImpl");
        return m_values->at(i);
    }

    inline Integer& operator[](uint32_t i) final {
        return (*m_values)[i];
    }

    inline const Integer& operator[](uint32_t i) const final {
        return (*m_values)[i];
    }

    /**
   * @brief Adds rhs entry-wise after checking that the ring dimension, modulus and format match.
   *
   * @param rhs the element to add.
   * @return the result of the addition.
   */
    PolyImpl Plus(const PolyImpl& rhs) const override {
        if (m_params->GetRingDimension() != rhs.m_params->GetRingDimension())
            OPENFHE_THROW("RingDimension mismatch");
        if (m_params->GetModulus() != rhs.m_params->GetModulus())
            OPENFHE_THROW("Modulus mismatch");
        if (m_format != rhs.m_format)
            OPENFHE_THROW("Format mismatch");
        auto tmp(*this);
        tmp.m_values->ModAddNoCheckEq(*rhs.m_values);
        return tmp;
    }
    /**
   * @brief Adds rhs entry-wise without checking the parameters.
   *
   * @param rhs the element to add.
   * @return the result of the addition.
   */
    PolyImpl PlusNoCheck(const PolyImpl& rhs) const {
        auto tmp(*this);
        tmp.m_values->ModAddNoCheckEq(*rhs.m_values);
        return tmp;
    }
    /**
   * @brief Adds rhs entry-wise in place without checking the parameters.
   *
   * @param rhs the element to add.
   * @return the resulting element.
   */
    PolyImpl& PlusNoCheckEq(const PolyImpl& rhs) {
        m_values->ModAddNoCheckEq(*rhs.m_values);
        return *this;
    }
    PolyImpl& operator+=(const PolyImpl& element) override;

    /**
   * @brief Element addition reusing the storage of the rvalue operand a, after checking that the ring dimension,
   * modulus and format match.
   *
   * @param a the element to add to, consumed.
   * @param b the element to add.
   * @return a, holding the sum.
   */
    friend PolyImpl operator+(PolyImpl&& a, const PolyImpl& b) {
        if (a.m_params->GetRingDimension() != b.m_params->GetRingDimension())
            OPENFHE_THROW("RingDimension mismatch");
        if (a.m_params->GetModulus() != b.m_params->GetModulus())
            OPENFHE_THROW("Modulus mismatch");
        if (a.m_format != b.m_format)
            OPENFHE_THROW("Format mismatch");
        a.m_values->ModAddNoCheckEq(*b.m_values);
        return std::move(a);
    }
    /**
   * @brief Element addition reusing the storage of the rvalue operand b.
   *
   * @param a the element to add.
   * @param b the element to add to, consumed.
   * @return b, holding the sum.
   */
    friend PolyImpl operator+(const PolyImpl& a, PolyImpl&& b) {
        return std::move(b) + a;
    }
    /**
   * @brief Element addition of two rvalues, reusing the storage of a.
   *
   * @param a the element to add to, consumed.
   * @param b the element to add.
   * @return a, holding the sum.
   */
    friend PolyImpl operator+(PolyImpl&& a, PolyImpl&& b) {
        return std::move(a) + static_cast<const PolyImpl&>(b);
    }

    PolyImpl Plus(const Integer& element) const override;
    PolyImpl& operator+=(const Integer& element) override {
        return *this = this->Plus(element);  // don't change this
    }

    PolyImpl Minus(const PolyImpl& element) const override;
    PolyImpl& operator-=(const PolyImpl& element) override;

    PolyImpl Minus(const Integer& element) const override;
    PolyImpl& operator-=(const Integer& element) override {
        m_values->ModSubEq(element);
        return *this;
    }

    PolyImpl Times(const PolyImpl& rhs) const override {
        if (m_params->GetRingDimension() != rhs.m_params->GetRingDimension())
            OPENFHE_THROW("RingDimension mismatch");
        if (m_params->GetModulus() != rhs.m_params->GetModulus())
            OPENFHE_THROW("Modulus mismatch");
        if (m_format != Format::EVALUATION || rhs.m_format != Format::EVALUATION)
            OPENFHE_THROW("operator* for PolyImpl supported only in Format::EVALUATION");
        auto tmp(*this);
        tmp.m_values->ModMulNoCheckEq(*rhs.m_values);
        return tmp;
    }
    /**
   * @brief Multiplies by rhs entry-wise (EVALUATION format) without checking the parameters.
   *
   * @param rhs the element to multiply by.
   * @return the result of the multiplication.
   */
    PolyImpl TimesNoCheck(const PolyImpl& rhs) const {
        auto tmp(*this);
        tmp.m_values->ModMulNoCheckEq(*rhs.m_values);
        return tmp;
    }
    /**
   * @brief Multiplies by rhs entry-wise (EVALUATION format) in place without checking the parameters.
   *
   * @param rhs the element to multiply by.
   * @return the resulting element.
   */
    PolyImpl& TimesNoCheckEq(const PolyImpl& rhs) {
        m_values->ModMulNoCheckEq(*rhs.m_values);
        return *this;
    }

    /**
   * @brief Element multiplication (EVALUATION format only) reusing the storage of the rvalue operand a, after
   * checking that the ring dimension, modulus and format match.
   *
   * @param a the element to multiply, consumed.
   * @param b the element to multiply by.
   * @return a, holding the product.
   */
    friend PolyImpl operator*(PolyImpl&& a, const PolyImpl& b) {
        if (a.m_params->GetRingDimension() != b.m_params->GetRingDimension())
            OPENFHE_THROW("RingDimension mismatch");
        if (a.m_params->GetModulus() != b.m_params->GetModulus())
            OPENFHE_THROW("Modulus mismatch");
        if (a.m_format != Format::EVALUATION || b.m_format != Format::EVALUATION)
            OPENFHE_THROW("operator* for PolyImpl supported only in Format::EVALUATION");
        a.m_values->ModMulNoCheckEq(*b.m_values);
        return std::move(a);
    }
    /**
   * @brief Element multiplication (EVALUATION format only) reusing the storage of the rvalue operand b.
   *
   * @param a the element to multiply by.
   * @param b the element to multiply, consumed.
   * @return b, holding the product.
   */
    friend PolyImpl operator*(const PolyImpl& a, PolyImpl&& b) {
        return std::move(b) * a;
    }
    /**
   * @brief Element multiplication (EVALUATION format only) of two rvalues, reusing the storage of a.
   *
   * @param a the element to multiply, consumed.
   * @param b the element to multiply by.
   * @return a, holding the product.
   */
    friend PolyImpl operator*(PolyImpl&& a, PolyImpl&& b) {
        return std::move(a) * static_cast<const PolyImpl&>(b);
    }
    /**
   * @brief Element subtraction reusing the storage of the rvalue operand a, without checking the parameters.
   *
   * @param a the element to subtract from, consumed.
   * @param b the element to subtract.
   * @return a, holding the difference.
   */
    friend PolyImpl operator-(PolyImpl&& a, const PolyImpl& b) {
        a.m_values->ModSubEq(*b.m_values);
        return std::move(a);
    }
    PolyImpl& operator*=(const PolyImpl& rhs) override {
        if (m_params->GetRingDimension() != rhs.m_params->GetRingDimension())
            OPENFHE_THROW("RingDimension mismatch");
        if (m_params->GetModulus() != rhs.m_params->GetModulus())
            OPENFHE_THROW("Modulus mismatch");
        if (m_format != Format::EVALUATION || rhs.m_format != Format::EVALUATION)
            OPENFHE_THROW("operator* for PolyImpl supported only in Format::EVALUATION");
        if (m_values) {
            m_values->ModMulNoCheckEq(*rhs.m_values);
            return *this;
        }
        m_values = std::make_unique<VecType>(m_params->GetRingDimension(), m_params->GetModulus());
        return *this;
    }

    PolyImpl Times(const Integer& element) const override;
    PolyImpl& operator*=(const Integer& element) override {
        m_values->ModMulEq(element);
        return *this;
    }

    PolyImpl Times(NativeInteger::SignedNativeInt element) const override;
#if NATIVEINT != 64
    /**
   * @brief Scalar multiplication by a 64-bit signed integer, forwarded to Times(NativeInteger::SignedNativeInt);
   * provided for builds with 128-bit native integers.
   *
   * @param element the signed integer to multiply by.
   * @return the result of the multiplication.
   */
    inline PolyImpl Times(int64_t element) const {
        return this->Times(static_cast<NativeInteger::SignedNativeInt>(element));
    }
#endif

    PolyImpl MultiplyAndRound(const Integer& p, const Integer& q) const override;
    PolyImpl DivideAndRound(const Integer& q) const override;

    PolyImpl Negate() const override;
    inline PolyImpl operator-() const override {
        return PolyImpl(m_params, m_format, true) -= *this;
    }

    inline bool operator==(const PolyImpl& rhs) const override {
        return ((m_format == rhs.GetFormat()) && (m_params->GetRootOfUnity() == rhs.GetRootOfUnity()) &&
                (this->GetValues() == rhs.GetValues()));
    }

    void AddILElementOne() override;
    PolyImpl AutomorphismTransform(uint32_t k) const override;
    PolyImpl AutomorphismTransform(uint32_t k, const std::vector<uint32_t>& vec) const override;
    PolyImpl MultiplicativeInverse() const override;
    PolyImpl ModByTwo() const override;
    PolyImpl Mod(const Integer& modulus) const override;

    void SwitchModulus(const Integer& modulus, const Integer& rootOfUnity, const Integer& modulusArb,
                       const Integer& rootOfUnityArb) override;
    void LazySwitchModulus(const Integer& modulus, const Integer& rootOfUnity, const Integer& modulusArb,
                           const Integer& rootOfUnityArb) override;

    /**
   * @brief Fused multiply-accumulate: *this += a * b (mod the modulus) entry-wise, without parameter validation;
   * all three operands must hold reduced values.
   *
   * @param a the element to multiply.
   * @param b the element to multiply a by.
   * @return the resulting element.
   */
    PolyImpl& MultAccEqNoCheck(const PolyImpl& a, const PolyImpl& b) {
        m_values->MultAccEqNoCheck(*a.m_values, *b.m_values);
        return *this;
    }
    PolyImpl& MultAccEqNoCheck(const PolyImpl& V, const Integer& I) override {
        m_values->MultAccEqNoCheck(*V.m_values, I);
        return *this;
    }

    void SwitchFormat(uint32_t thread_limit = 0) override;
    void MakeSparse(uint32_t wFactor) override;
    bool InverseExists() const override;
    double Norm() const override;
    std::vector<PolyImpl> BaseDecompose(uint32_t baseBits, bool evalModeAnswer) const override;
    std::vector<PolyImpl> PowersOfBase(uint32_t baseBits) const override;

    template <class Archive>
    void save(Archive& ar, std::uint32_t const version) const {
        ar(::cereal::make_nvp("v", m_values));
        ar(::cereal::make_nvp("f", m_format));
        ar(::cereal::make_nvp("p", m_params));
    }

    template <class Archive>
    void load(Archive& ar, std::uint32_t const version) {
        if (version > SerializedVersion()) {
            OPENFHE_THROW("serialized object version " + std::to_string(version) +
                          " is from a later version of the library");
        }
        ar(::cereal::make_nvp("v", m_values));
        ar(::cereal::make_nvp("f", m_format));
        ar(::cereal::make_nvp("p", m_params));
    }

    static const std::string GetElementName() {
        return "PolyImpl";
    }

    std::string SerializedObjectName() const override {
        return "Poly";
    }

    static uint32_t SerializedVersion() {
        return 1;
    }

  protected:
    Format m_format{Format::EVALUATION};
    std::shared_ptr<Params> m_params{nullptr};
    std::unique_ptr<VecType> m_values{nullptr};
    /**
   * @brief Switches the format of an element over an arbitrary (non-power-of-two) cyclotomic ring with the
   * Bluestein-based transform, using the root of unity, big modulus and big root of unity of the parameters;
   * throws if the values are unallocated.
   */
    void ArbitrarySwitchFormat();
};

}  // namespace lbcrypto

#endif  // SRC_CORE_INCLUDE_LATTICE_HAL_DEFAULT_POLY_H_
