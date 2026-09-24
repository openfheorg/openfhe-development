//==================================================================================
// BSD 2-Clause License
//
// Copyright (c) 2014-2026, NJIT, Duality Technologies Inc. and other contributors
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

#ifndef SRC_CORE_INCLUDE_LATTICE_HAL_DEFAULT_DCRTPOLY_H_
#define SRC_CORE_INCLUDE_LATTICE_HAL_DEFAULT_DCRTPOLY_H_

#include <cstdint>
#include <functional>
#include <initializer_list>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "lattice/hal/dcrtpoly-interface.h"
#include "lattice/hal/default/ildcrtparams.h"
#include "lattice/hal/default/poly.h"
#include "math/distrgen.h"
#include "math/math-hal.h"
#include "utils/exception.h"
#include "utils/inttypes.h"
#include "utils/parallel.h"

namespace lbcrypto {

/**
 * @brief Default double-CRT polynomial: an element of the cyclotomic ring modulo a composite modulus
 * Q = q_1 * ... * q_l stored as one native polynomial (tower) per CRT modulus q_i, all towers in the same format.
 *
 * @tparam VecType the big-integer vector type of the interpolated single-modulus polynomial, e.g. BigVector.
 */
template <typename VecType>
class DCRTPolyImpl final : public DCRTPolyInterface<DCRTPolyImpl<VecType>, VecType, NativeVector, PolyImpl> {
  public:
    using Vector = VecType;
    using Integer = typename VecType::Integer;
    using Params = ILDCRTParams<Integer>;
    using PolyType = PolyImpl<NativeVector>;
    using PolyLargeType = PolyImpl<VecType>;
    using DCRTPolyType = DCRTPolyImpl<VecType>;
    using DCRTPolyInterfaceType = DCRTPolyInterface<DCRTPolyImpl<VecType>, VecType, NativeVector, PolyImpl>;
    using Precomputations = typename DCRTPolyInterfaceType::CRTBasisExtensionPrecomputations;
    using DggType = typename DCRTPolyInterfaceType::DggType;
    using DugType = typename DCRTPolyInterfaceType::DugType;
    using TugType = typename DCRTPolyInterfaceType::TugType;
    using BugType = typename DCRTPolyInterfaceType::BugType;

    using DCRTPolyInterfaceType::ApproxSwitchCRTBasisThreads;
    using DCRTPolyInterfaceType::THREADS_CRT_BASIS_SWITCH;
    using DCRTPolyInterfaceType::THREADS_SCALE_TO_POLY;

    DCRTPolyImpl() = default;

    DCRTPolyImpl(const DCRTPolyType& e) noexcept : m_params{e.m_params}, m_format{e.m_format}, m_vectors{e.m_vectors} {}
    DCRTPolyType& operator=(const DCRTPolyType& rhs) noexcept override {
        m_params = rhs.m_params;
        m_format = rhs.m_format;
        m_vectors = rhs.m_vectors;
        return *this;
    }

    /**
   * @brief Constructs the double-CRT representation of a big-integer polynomial: every coefficient of e is reduced
   * modulo each tower modulus of params; the format of e is kept.
   *
   * @param e the polynomial with coefficients modulo the composite modulus.
   * @param params the double-CRT parameters defining the towers.
   */
    DCRTPolyImpl(const PolyLargeType& e, const std::shared_ptr<Params>& params) noexcept;
    /**
   * @brief Assigns a big-integer polynomial: the towers are rebuilt from this element's parameters and every
   * coefficient of rhs is reduced modulo each tower modulus; this element's format is kept.
   *
   * @param rhs the polynomial with coefficients modulo the composite modulus.
   * @return the resulting element.
   */
    DCRTPolyType& operator=(const PolyLargeType& rhs) noexcept;

    /**
   * @brief Constructs an element whose first tower is the native polynomial e and whose other towers are copies of e
   * switched (centered) to the remaining tower moduli of params; if e is empty, all towers are empty.
   *
   * @param e the native polynomial, with the modulus of the first tower.
   * @param params the double-CRT parameters defining the towers.
   */
    DCRTPolyImpl(const PolyType& e, const std::shared_ptr<Params>& params) noexcept;
    /**
   * @brief Assigns a native polynomial: rhs becomes the first tower and copies of it switched (centered) to each
   * remaining tower modulus become the other towers; if rhs is empty, all towers are empty.
   *
   * @param rhs the native polynomial, with the modulus of the first tower.
   * @return the resulting element.
   */
    DCRTPolyType& operator=(const PolyType& rhs) noexcept;

    DCRTPolyImpl(DCRTPolyType&& e) noexcept
        : m_params{std::move(e.m_params)}, m_format{e.m_format}, m_vectors{std::move(e.m_vectors)} {}
    DCRTPolyType& operator=(DCRTPolyType&& rhs) noexcept override {
        m_params = std::move(rhs.m_params);
        m_format = std::move(rhs.m_format);
        m_vectors = std::move(rhs.m_vectors);
        return *this;
    }

    /**
   * @brief Constructs an element from its towers; the parameters (cyclotomic order and the tower moduli) and the
   * format are taken from the towers, which must all have the same cyclotomic order.
   *
   * @param elements the towers, one native polynomial per CRT modulus.
   */
    explicit DCRTPolyImpl(const std::vector<PolyType>& elements);

    /**
   * @brief Constructs an element with one tower per modulus of params, in the given format.
   *
   * @param params the double-CRT parameters defining the towers.
   * @param format the format of the element (COEFFICIENT or EVALUATION).
   * @param initializeElementToZero if true, the towers are allocated and set to zero; otherwise their values are
   * left unallocated.
   */
    DCRTPolyImpl(const std::shared_ptr<Params>& params, Format format = Format::EVALUATION,
                 bool initializeElementToZero = false) noexcept
        : m_params{params}, m_format{format} {
        m_vectors.reserve(m_params->GetParams().size());
        for (const auto& p : m_params->GetParams())
            m_vectors.emplace_back(p, m_format, initializeElementToZero);
    }

    /**
   * @brief Constructs an element with coefficients sampled from a discrete Gaussian distribution: one integer vector
   * is sampled and reduced modulo each tower modulus, then the towers are converted to the requested format.
   *
   * @param dgg the discrete Gaussian generator.
   * @param p the double-CRT parameters defining the towers.
   * @param f the format of the resulting element.
   */
    DCRTPolyImpl(const DggType& dgg, const std::shared_ptr<Params>& p, Format f = Format::EVALUATION);
    /**
   * @brief Constructs an element with binary uniform coefficients: one polynomial is sampled with the first tower's
   * parameters and switched to the modulus of every other tower, then the towers are converted to the requested
   * format.
   *
   * @param bug the binary uniform generator.
   * @param p the double-CRT parameters defining the towers.
   * @param f the format of the resulting element.
   */
    DCRTPolyImpl(const BugType& bug, const std::shared_ptr<Params>& p, Format f = Format::EVALUATION);
    /**
   * @brief Constructs an element with ternary uniform coefficients: one integer vector with entries in {-1, 0, 1} is
   * sampled and reduced modulo each tower modulus, then the towers are converted to the requested format.
   *
   * @param tug the ternary uniform generator.
   * @param p the double-CRT parameters defining the towers.
   * @param f the format of the resulting element.
   * @param h the Hamming weight (number of nonzero coefficients) for the sparse distribution; 0 samples every
   * coefficient uniformly.
   */
    DCRTPolyImpl(const TugType& tug, const std::shared_ptr<Params>& p, Format f = Format::EVALUATION, uint32_t h = 0);
    /**
   * @brief Constructs an element with uniformly random coefficients: each tower is sampled independently and
   * uniformly modulo its own modulus and is recorded as already being in the requested format (no transform).
   *
   * @param dug the discrete uniform generator.
   * @param p the double-CRT parameters defining the towers.
   * @param f the format recorded for the resulting element.
   */
    DCRTPolyImpl(DugType& dug, const std::shared_ptr<Params>& p, Format f = Format::EVALUATION);

    DCRTPolyType& operator=(std::initializer_list<uint64_t> rhs) noexcept override;
    /**
   * @brief Assigns the constant val to every entry of every tower (each tower's format becomes EVALUATION, as in
   * PolyImpl::operator=(uint64_t)).
   *
   * @param val the value to assign.
   * @return the resulting element.
   */
    DCRTPolyType& operator=(uint64_t val) noexcept;
    /**
   * @brief Assigns signed coefficients (used for trapdoor sampling): every tower receives the coefficients reduced
   * modulo its own modulus, missing trailing coefficients are zero and the format becomes COEFFICIENT.
   *
   * @param rhs the signed coefficients.
   * @return the resulting element.
   */
    DCRTPolyType& operator=(const std::vector<int64_t>& rhs) noexcept;
    /**
   * @brief Assigns signed coefficients (used for trapdoor sampling): every tower receives the coefficients reduced
   * modulo its own modulus, missing trailing coefficients are zero and the format becomes COEFFICIENT.
   *
   * @param rhs the signed coefficients.
   * @return the resulting element.
   */
    DCRTPolyType& operator=(const std::vector<int32_t>& rhs) noexcept;
    /**
   * @brief Assigns coefficients given as decimal strings to every tower, as given (without modular reduction);
   * missing trailing coefficients are zero. Towers with unallocated values are allocated first.
   *
   * @param rhs the coefficients as decimal strings.
   * @return the resulting element.
   */
    DCRTPolyType& operator=(std::initializer_list<std::string> rhs) noexcept;

    DCRTPolyType CloneWithNoise(const DiscreteGaussianGeneratorImpl<VecType>& dgg, Format format) const override;
    /**
   * @brief Makes a copy holding only the towers startTower to endTower (inclusive), with parameters restricted to
   * those moduli and the same format.
   *
   * @param startTower the index of the first tower to copy.
   * @param endTower the index of the last tower to copy.
   * @return the new element.
   */
    DCRTPolyType CloneTowers(uint32_t startTower, uint32_t endTower) const;

    bool operator==(const DCRTPolyType& rhs) const override;

    DCRTPolyType& operator+=(const DCRTPolyType& rhs) override;
    DCRTPolyType& operator+=(const Integer& rhs) override;
    /**
   * @brief Adds a native integer to every tower in place: to the first coefficient of each tower in COEFFICIENT
   * format, or to all entries of each tower in EVALUATION format.
   *
   * @param rhs the native integer to add.
   * @return the resulting element.
   */
    DCRTPolyType& operator+=(const NativeInteger& rhs) override;
    DCRTPolyType& operator-=(const DCRTPolyType& rhs) override;
    DCRTPolyType& operator-=(const Integer& rhs) override;
    /**
   * @brief Subtracts a native integer from all entries of every tower in place.
   *
   * @param rhs the native integer to subtract.
   * @return the resulting element.
   */
    DCRTPolyType& operator-=(const NativeInteger& rhs) override;
    DCRTPolyType& operator*=(const DCRTPolyType& rhs) override {
        size_t size{m_vectors.size()};
        if (size > rhs.m_vectors.size())
            OPENFHE_THROW("tower size mismatch; cannot multiply");
#pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(size))
        for (size_t i = 0; i < size; ++i)
            m_vectors[i] *= rhs.m_vectors[i];
        return *this;
    }
    DCRTPolyType& operator*=(const Integer& rhs) override;
    /**
   * @brief Multiplies all entries of every tower by a native integer in place.
   *
   * @param rhs the native integer to multiply by.
   * @return the resulting element.
   */
    DCRTPolyType& operator*=(const NativeInteger& rhs) override;

    DCRTPolyType Negate() const override;
    DCRTPolyType operator-() const override;

    std::vector<DCRTPolyType> BaseDecompose(uint32_t baseBits, bool evalModeAnswer) const override;
    std::vector<DCRTPolyType> PowersOfBase(uint32_t baseBits) const override;
    /**
   * @brief Decomposes the element for key switching: element i of the result holds the residue of this element
   * modulo q_i, as an integer in [0, q_i), represented in every tower; when baseBits > 0 each residue is further
   * split into digits of baseBits bits, one element per digit. The result is in EVALUATION format.
   *
   * @param baseBits the number of bits of the digit base for the additional decomposition; 0 for none.
   * @return the vector of decomposed elements.
   */
    std::vector<DCRTPolyType> CRTDecompose(uint32_t baseBits) const;

    DCRTPolyType AutomorphismTransform(uint32_t i) const override;
    DCRTPolyType AutomorphismTransform(uint32_t i, const std::vector<uint32_t>& vec) const override;

    DCRTPolyType Plus(const Integer& rhs) const override;
    /**
   * @brief Adds an integer given in CRT form (one value per tower, converted to a native integer) to each tower: to
   * the first coefficient in COEFFICIENT format, or to all entries in EVALUATION format.
   *
   * @param rhs the CRT representation of the integer to add, in tower order.
   * @return the result of the addition.
   */
    DCRTPolyType Plus(const std::vector<Integer>& rhs) const;
    DCRTPolyType Plus(const DCRTPolyType& rhs) const override {
        if (m_params->GetRingDimension() != rhs.m_params->GetRingDimension())
            OPENFHE_THROW("RingDimension mismatch");
        if (m_format != rhs.m_format)
            OPENFHE_THROW("Format mismatch");
        size_t size{m_vectors.size()};
        if (size != rhs.m_vectors.size())
            OPENFHE_THROW("tower size mismatch; cannot add");
        if (m_vectors[0].GetModulus() != rhs.m_vectors[0].GetModulus())
            OPENFHE_THROW("Modulus mismatch");
        DCRTPolyType tmp(m_params, m_format);
#pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(size))
        for (size_t i = 0; i < size; ++i)
            tmp.m_vectors[i] = m_vectors[i].PlusNoCheck(rhs.m_vectors[i]);
        return tmp;
    }

    /**
   * @brief Element addition reusing the storage of the rvalue operand a: after checking the ring dimension, format,
   * number of towers and modulus, the towers of b are added into those of a.
   *
   * @param a the element to add to, consumed.
   * @param b the element to add.
   * @return a, holding the sum.
   */
    friend DCRTPolyType operator+(DCRTPolyType&& a, const DCRTPolyType& b) {
        if (a.m_params->GetRingDimension() != b.m_params->GetRingDimension())
            OPENFHE_THROW("RingDimension mismatch");
        if (a.m_format != b.m_format)
            OPENFHE_THROW("Format mismatch");
        size_t size{a.m_vectors.size()};
        if (size != b.m_vectors.size())
            OPENFHE_THROW("tower size mismatch; cannot add");
        if (a.m_vectors[0].GetModulus() != b.m_vectors[0].GetModulus())
            OPENFHE_THROW("Modulus mismatch");
#pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(size))
        for (size_t i = 0; i < size; ++i)
            a.m_vectors[i].PlusNoCheckEq(b.m_vectors[i]);
        return std::move(a);
    }
    /**
   * @brief Element addition reusing the storage of the rvalue operand b.
   *
   * @param a the element to add.
   * @param b the element to add to, consumed.
   * @return b, holding the sum.
   */
    friend DCRTPolyType operator+(const DCRTPolyType& a, DCRTPolyType&& b) {
        return std::move(b) + a;
    }
    /**
   * @brief Element addition of two rvalues, reusing the storage of a.
   *
   * @param a the element to add to, consumed.
   * @param b the element to add.
   * @return a, holding the sum.
   */
    friend DCRTPolyType operator+(DCRTPolyType&& a, DCRTPolyType&& b) {
        return std::move(a) + static_cast<const DCRTPolyType&>(b);
    }

    DCRTPolyType Minus(const DCRTPolyType& rhs) const override;

    /**
   * @brief Element subtraction reusing the storage of the rvalue operand a; only the number of towers is checked.
   *
   * @param a the element to subtract from, consumed.
   * @param b the element to subtract.
   * @return a, holding the difference.
   */
    friend DCRTPolyType operator-(DCRTPolyType&& a, const DCRTPolyType& b) {
        size_t size{a.m_vectors.size()};
        if (size != b.m_vectors.size())
            OPENFHE_THROW("tower size mismatch; cannot subtract");
#pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(size))
        for (size_t i = 0; i < size; ++i)
            a.m_vectors[i] -= b.m_vectors[i];
        return std::move(a);
    }
    DCRTPolyType Minus(const Integer& rhs) const override;
    /**
   * @brief Subtracts an integer given in CRT form (one value per tower, converted to a native integer) from all
   * entries of each tower.
   *
   * @param rhs the CRT representation of the integer to subtract, in tower order.
   * @return the result of the subtraction.
   */
    DCRTPolyType Minus(const std::vector<Integer>& rhs) const;

    DCRTPolyType Times(const DCRTPolyType& rhs) const override {
        if (m_params->GetRingDimension() != rhs.m_params->GetRingDimension())
            OPENFHE_THROW("RingDimension mismatch");
        if (m_format != Format::EVALUATION || rhs.m_format != Format::EVALUATION)
            OPENFHE_THROW("operator* for DCRTPolyImpl supported only in Format::EVALUATION");
        size_t size{m_vectors.size()};
        if (size != rhs.m_vectors.size())
            OPENFHE_THROW("tower size mismatch; cannot multiply");
        if (m_vectors[0].GetModulus() != rhs.m_vectors[0].GetModulus())
            OPENFHE_THROW("Modulus mismatch");
        DCRTPolyType tmp(m_params, m_format);
#pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(size))
        for (size_t i = 0; i < size; ++i)
            tmp.m_vectors[i] = m_vectors[i].TimesNoCheck(rhs.m_vectors[i]);
        return tmp;
    }

    /**
   * @brief Element multiplication (EVALUATION format only) reusing the storage of the rvalue operand a: after
   * checking the ring dimension, format, number of towers and modulus, the towers of a are multiplied by those of b.
   *
   * @param a the element to multiply, consumed.
   * @param b the element to multiply by.
   * @return a, holding the product.
   */
    friend DCRTPolyType operator*(DCRTPolyType&& a, const DCRTPolyType& b) {
        if (a.m_params->GetRingDimension() != b.m_params->GetRingDimension())
            OPENFHE_THROW("RingDimension mismatch");
        if (a.m_format != Format::EVALUATION || b.m_format != Format::EVALUATION)
            OPENFHE_THROW("operator* for DCRTPolyImpl supported only in Format::EVALUATION");
        size_t size{a.m_vectors.size()};
        if (size != b.m_vectors.size())
            OPENFHE_THROW("tower size mismatch; cannot multiply");
        if (a.m_vectors[0].GetModulus() != b.m_vectors[0].GetModulus())
            OPENFHE_THROW("Modulus mismatch");
#pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(size))
        for (size_t i = 0; i < size; ++i)
            a.m_vectors[i].TimesNoCheckEq(b.m_vectors[i]);
        return std::move(a);
    }
    /**
   * @brief Element multiplication (EVALUATION format only) reusing the storage of the rvalue operand b.
   *
   * @param a the element to multiply by.
   * @param b the element to multiply, consumed.
   * @return b, holding the product.
   */
    friend DCRTPolyType operator*(const DCRTPolyType& a, DCRTPolyType&& b) {
        return std::move(b) * a;
    }
    /**
   * @brief Element multiplication (EVALUATION format only) of two rvalues, reusing the storage of a.
   *
   * @param a the element to multiply, consumed.
   * @param b the element to multiply by.
   * @return a, holding the product.
   */
    friend DCRTPolyType operator*(DCRTPolyType&& a, DCRTPolyType&& b) {
        return std::move(a) * static_cast<const DCRTPolyType&>(b);
    }
    DCRTPolyType Times(const Integer& rhs) const override;
    /**
   * @brief Multiplies all entries of each tower by an integer given in CRT form (one value per tower, converted to a
   * native integer).
   *
   * @param rhs the CRT representation of the integer to multiply by, in tower order.
   * @return the result of the multiplication.
   */
    DCRTPolyType Times(const std::vector<Integer>& rhs) const;
    DCRTPolyType Times(NativeInteger::SignedNativeInt rhs) const override;
#if NATIVEINT != 64
    /**
   * @brief Scalar multiplication by a 64-bit signed integer, forwarded to Times(NativeInteger::SignedNativeInt);
   * provided for builds with 128-bit native integers.
   *
   * @param rhs the signed integer to multiply by.
   * @return the result of the multiplication.
   */
    DCRTPolyType Times(int64_t rhs) const {
        return Times(static_cast<NativeInteger::SignedNativeInt>(rhs));
    }
#endif
    /**
   * @brief Multiplies tower i by rhs[i]; throws if the number of towers differs from the size of rhs.
   *
   * @param rhs the CRT representation of the integer to multiply by, in tower order.
   * @return the result of the multiplication.
   */
    DCRTPolyType Times(const std::vector<NativeInteger>& rhs) const;
    /**
   * @brief Multiplies tower i by rhs[i] for the first min(number of towers, rhs.size()) towers without a size check;
   * any remaining towers of the result are left unallocated.
   *
   * @param rhs the CRT representation of the integer to multiply by, in tower order.
   * @return the result of the multiplication.
   */
    DCRTPolyType TimesNoCheck(const std::vector<NativeInteger>& rhs) const;

    /**
   * @brief Fused multiply-accumulate: *this += a * b (mod each tower modulus), without
   * parameter validation. All three operands must hold reduced values (see the
   * NativeVectorT overload). Saves the full-element temporary of *this += a * b.
   *
   * @param a the element to multiply.
   * @param b the element to multiply a by.
   * @return the resulting element.
   */
    DCRTPolyType& MultAccEqNoCheck(const DCRTPolyType& a, const DCRTPolyType& b) {
        size_t size{m_vectors.size()};
        if (size > a.m_vectors.size() || size > b.m_vectors.size())
            OPENFHE_THROW("tower size mismatch; cannot multiply-accumulate");
#pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(size))
        for (size_t i = 0; i < size; ++i)
            m_vectors[i].MultAccEqNoCheck(a.m_vectors[i], b.m_vectors[i]);
        return *this;
    }

    DCRTPolyType MultiplicativeInverse() const override;
    bool InverseExists() const override;
    bool IsEmpty() const override;

    void SetValuesToZero() override;
    void AddILElementOne() override;
    void DropLastElement() override;
    void DropLastElements(size_t i) override;
    void DropLastElementAndScale(const std::vector<NativeInteger>& qlInvModq) override;

    void ModReduce(const NativeInteger& t, const std::vector<NativeInteger>& tModqPrecon,
                   const NativeInteger& negtInvModq, const NativeInteger& negtInvModqPrecon,
                   const std::vector<NativeInteger>& qlInvModq,
                   const std::vector<NativeInteger>& qlInvModqPrecon) override;

    PolyLargeType CRTInterpolate() const override;
    PolyType DecryptionCRTInterpolate(PlaintextModulus ptm) const override;
    PolyType ToNativePoly() const override;
    PolyLargeType CRTInterpolateIndex(uint32_t i) const override;
    Integer GetWorkingModulus() const override;

    void SetValuesModSwitch(const DCRTPolyType& element, const NativeInteger& modulus) override;

    /**
   * @brief Builds the parameters of the extended basis {Q, P}: the moduli and roots of unity of this element's
   * current towers followed by those of paramsP, with this element's cyclotomic order.
   *
   * @param paramsP element parameters for the moduli to append to the current towers.
   * @return element parameters of the extended basis.
   */
    std::shared_ptr<Params> GetExtendedCRTBasis(const std::shared_ptr<Params>& paramsP) const override;

    /**
   * @brief Scales the element by Q/t in place (BFV plaintext encoding); see DCRTPolyInterface::TimesQovert. Every
   * coefficient m of tower i becomes [[m*(-Q)]_t * t^{-1}]_{q_i}.
   *
   * @param paramsQ element parameters of the basis Q; not used, the current towers define the basis.
   * @param tInvModq precomputed values for [t^{-1}]_{q_i}; throws if fewer than the number of towers.
   * @param t the plaintext modulus.
   * @param NegQModt precomputed value for [-Q]_t.
   * @param NegQModtPrecon NTL-specific precomputation for NegQModt.
   */
    void TimesQovert(const std::shared_ptr<Params>& paramsQ, const std::vector<NativeInteger>& tInvModq,
                     const NativeInteger& t, const NativeInteger& NegQModt,
                     const NativeInteger& NegQModtPrecon) override;

    /**
   * @brief Approximate CRT basis switching {X}_Q -> {X + alpha*Q}_P for a small alpha; see
   * DCRTPolyInterface::ApproxSwitchCRTBasis for the algorithm.
   *
   * @param paramsQ parameters for the CRT basis {q_1,...,q_l}.
   * @param paramsP parameters for the CRT basis {p_1,...,p_k}.
   * @param QHatInvModq precomputed values for [(Q/q_i)^{-1}]_{q_i}.
   * @param QHatInvModqPrecon NTL-specific precomputations for QHatInvModq.
   * @param QHatModp precomputed values for [Q/q_i]_{p_j}.
   * @param modpBarrettMu 128-bit Barrett reduction precomputed values for p_j.
   * @return the representation of X + alpha*Q in the basis P.
   */
    DCRTPolyType ApproxSwitchCRTBasis(const std::shared_ptr<Params>& paramsQ, const std::shared_ptr<Params>& paramsP,
                                      const std::vector<NativeInteger>& QHatInvModq,
                                      const std::vector<NativeInteger>& QHatInvModqPrecon,
                                      const std::vector<std::vector<NativeInteger>>& QHatModp,
                                      const std::vector<DoubleNativeInt>& modpBarrettMu) const override;

    /**
   * @brief Approximate modulus raising in place, {X}_Q -> {X + alpha*Q}_{Q,P}: the P towers are computed with
   * ApproxSwitchCRTBasis and appended; see DCRTPolyInterface::ApproxModUp.
   *
   * @param paramsQ parameters for the CRT basis {q_1,...,q_l}.
   * @param paramsP parameters for the CRT basis {p_1,...,p_k}.
   * @param paramsQP parameters for the CRT basis {q_1,...,q_l,p_1,...,p_k}.
   * @param QHatInvModq precomputed values for [(Q/q_i)^{-1}]_{q_i}.
   * @param QHatInvModqPrecon NTL-specific precomputations for QHatInvModq.
   * @param QHatModp precomputed values for [Q/q_i]_{p_j}.
   * @param modpBarrettMu 128-bit Barrett reduction precomputed values for p_j.
   */
    void ApproxModUp(const std::shared_ptr<Params>& paramsQ, const std::shared_ptr<Params>& paramsP,
                     const std::shared_ptr<Params>& paramsQP, const std::vector<NativeInteger>& QHatInvModq,
                     const std::vector<NativeInteger>& QHatInvModqPrecon,
                     const std::vector<std::vector<NativeInteger>>& QHatModp,
                     const std::vector<DoubleNativeInt>& modpBarrettMu) override;

    /**
   * @brief Approximate modulus reduction {X}_{Q,P} -> {approximately X/P}_Q (with the multiplication by t used by
   * BGV); see DCRTPolyInterface::ApproxModDown for the algorithm.
   *
   * @param paramsQ parameters for the CRT basis {q_1,...,q_l}.
   * @param paramsP parameters for the CRT basis {p_1,...,p_k}.
   * @param PInvModq precomputed values for [P^{-1}]_{q_i}.
   * @param PInvModqPrecon NTL-specific precomputations for PInvModq.
   * @param PHatInvModp precomputed values for [(P/p_j)^{-1}]_{p_j}.
   * @param PHatInvModpPrecon NTL-specific precomputations for PHatInvModp.
   * @param PHatModq precomputed values for [P/p_j]_{q_i}.
   * @param modqBarrettMu 128-bit Barrett reduction precomputed values for q_i.
   * @param tInvModp precomputed values for [t^{-1}]_{p_j} (BGV only).
   * @param tInvModpPrecon NTL-specific precomputations for tInvModp.
   * @param t the plaintext modulus (BGV only).
   * @param tModqPrecon NTL-specific precomputations for t modulo q_i.
   * @return the representation of approximately X/P in the basis Q.
   */
    DCRTPolyType ApproxModDown(
            const std::shared_ptr<Params>& paramsQ, const std::shared_ptr<Params>& paramsP,
            const std::vector<NativeInteger>& PInvModq, const std::vector<NativeInteger>& PInvModqPrecon,
            const std::vector<NativeInteger>& PHatInvModp, const std::vector<NativeInteger>& PHatInvModpPrecon,
            const std::vector<std::vector<NativeInteger>>& PHatModq, const std::vector<DoubleNativeInt>& modqBarrettMu,
            const std::vector<NativeInteger>& tInvModp, const std::vector<NativeInteger>& tInvModpPrecon,
            const NativeInteger& t, const std::vector<NativeInteger>& tModqPrecon) const override;

    /**
   * @brief Exact CRT basis switching {X}_Q -> {X}_P; see DCRTPolyInterface::SwitchCRTBasis for the algorithm.
   *
   * @param paramsP parameters for the CRT basis {p_1,...,p_k}.
   * @param QHatInvModq precomputed values for [(Q/q_i)^{-1}]_{q_i}.
   * @param QHatInvModqPrecon NTL-specific precomputations for QHatInvModq.
   * @param QHatModp precomputed values for [Q/q_i]_{p_j}.
   * @param alphaQModp precomputed values for [alpha*Q]_{p_j}.
   * @param modpBarrettMu 128-bit Barrett reduction precomputed values for p_j.
   * @param qInv precomputed values for 1/q_i.
   * @return the representation of X in the basis P.
   */
    DCRTPolyType SwitchCRTBasis(const std::shared_ptr<Params>& paramsP, const std::vector<NativeInteger>& QHatInvModq,
                                const std::vector<NativeInteger>& QHatInvModqPrecon,
                                const std::vector<std::vector<NativeInteger>>& QHatModp,
                                const std::vector<std::vector<NativeInteger>>& alphaQModp,
                                const std::vector<DoubleNativeInt>& modpBarrettMu,
                                const std::vector<double>& qInv) const override;

    /**
   * @brief Exact modulus raising in place, {X}_Q -> {X}_{Q,P}: the P towers are computed with SwitchCRTBasis and
   * appended; see DCRTPolyInterface::ExpandCRTBasis.
   *
   * @param paramsQP parameters for the CRT basis {q_1,...,q_l,p_1,...,p_k}.
   * @param paramsP parameters for the CRT basis {p_1,...,p_k}.
   * @param QHatInvModq precomputed values for [(Q/q_i)^{-1}]_{q_i}.
   * @param QHatInvModqPrecon NTL-specific precomputations for QHatInvModq.
   * @param QHatModp precomputed values for [Q/q_i]_{p_j}.
   * @param alphaQModp precomputed values for [alpha*Q]_{p_j}.
   * @param modpBarrettMu 128-bit Barrett reduction precomputed values for p_j.
   * @param qInv precomputed values for 1/q_i.
   * @param resultFormat the format of the resulting element.
   */
    void ExpandCRTBasis(const std::shared_ptr<Params>& paramsQP, const std::shared_ptr<Params>& paramsP,
                        const std::vector<NativeInteger>& QHatInvModq,
                        const std::vector<NativeInteger>& QHatInvModqPrecon,
                        const std::vector<std::vector<NativeInteger>>& QHatModp,
                        const std::vector<std::vector<NativeInteger>>& alphaQModp,
                        const std::vector<DoubleNativeInt>& modpBarrettMu, const std::vector<double>& qInv,
                        Format resultFormat) override;

    /**
   * @brief Exact modulus raising in place with the new towers first, {X}_Q -> {X}_{P,Q}; see
   * DCRTPolyInterface::ExpandCRTBasisReverseOrder.
   *
   * @param paramsQP parameters for the CRT basis {p_1,...,p_k,q_1,...,q_l}.
   * @param paramsP parameters for the CRT basis {p_1,...,p_k}.
   * @param QHatInvModq precomputed values for [(Q/q_i)^{-1}]_{q_i}.
   * @param QHatInvModqPrecon NTL-specific precomputations for QHatInvModq.
   * @param QHatModp precomputed values for [Q/q_i]_{p_j}.
   * @param alphaQModp precomputed values for [alpha*Q]_{p_j}.
   * @param modpBarrettMu 128-bit Barrett reduction precomputed values for p_j.
   * @param qInv precomputed values for 1/q_i.
   * @param resultFormat the format of the resulting element.
   */
    void ExpandCRTBasisReverseOrder(const std::shared_ptr<Params>& paramsQP, const std::shared_ptr<Params>& paramsP,
                                    const std::vector<NativeInteger>& QHatInvModq,
                                    const std::vector<NativeInteger>& QHatInvModqPrecon,
                                    const std::vector<std::vector<NativeInteger>>& QHatModp,
                                    const std::vector<std::vector<NativeInteger>>& alphaQModp,
                                    const std::vector<DoubleNativeInt>& modpBarrettMu, const std::vector<double>& qInv,
                                    Format resultFormat) override;

    /**
   * @brief Scales the element by P_l/Q and expands it to the basis {Q_l, P_l} in place: ApproxSwitchCRTBasis to
   * P_l with the folded constants, then SwitchCRTBasis back to Q_l; see DCRTPolyInterface::FastExpandCRTBasisPloverQ.
   *
   * @param precomputed the precomputed constants for the bases Q, Q_l and P_l.
   */
    void FastExpandCRTBasisPloverQ(const Precomputations& precomputed) override;

    /**
   * @brief Multiplies the element by Q/Q_l and expands it from the basis Q_l to the full basis Q in place; the towers
   * for the moduli not in Q_l are zero. See DCRTPolyInterface::ExpandCRTBasisQlHat.
   *
   * @param paramsQ element parameters of the full basis Q.
   * @param QlHatModq precomputed values for [Q/Q_l]_{q_i} for the towers in Q_l.
   * @param QlHatModqPrecon NTL-specific precomputations for QlHatModq.
   * @param sizeQ the number of towers in the full basis Q.
   */
    void ExpandCRTBasisQlHat(const std::shared_ptr<Params>& paramsQ, const std::vector<NativeInteger>& QlHatModq,
                             const std::vector<NativeInteger>& QlHatModqPrecon, const uint32_t sizeQ) override;

    PolyType ScaleAndRound(const NativeInteger& t, const std::vector<NativeInteger>& tQHatInvModqDivqModt,
                           const std::vector<NativeInteger>& tQHatInvModqDivqModtPrecon,
                           const std::vector<NativeInteger>& tQHatInvModqBDivqModt,
                           const std::vector<NativeInteger>& tQHatInvModqBDivqModtPrecon,
                           const std::vector<double>& tQHatInvModqDivqFrac,
                           const std::vector<double>& tQHatInvModqBDivqFrac) const override;

    /**
   * @brief Approximate scale and round {X}_{Q,P} -> {approximately t/Q * X}_P; see
   * DCRTPolyInterface::ApproxScaleAndRound for the algorithm.
   *
   * @param paramsP parameters for the CRT basis {p_1,...,p_k}.
   * @param tPSHatInvModsDivsModp precomputed values for [floor(t*P*[(S/s_k)^{-1}]_{s_k}/s_k)]_{p_j}, S = {Q,P}.
   * @param modpBarretMu 128-bit Barrett reduction precomputed values for p_j.
   * @return the representation of approximately t/Q * X in the basis P.
   */
    DCRTPolyType ApproxScaleAndRound(const std::shared_ptr<Params>& paramsP,
                                     const std::vector<std::vector<NativeInteger>>& tPSHatInvModsDivsModp,
                                     const std::vector<DoubleNativeInt>& modpBarretMu) const override;

    /**
   * @brief Exact scale and round {X}_{I,O} -> {round(t/I * X)}_O, where O is the output basis (P or Q) and I is
   * the other one; see DCRTPolyInterface::ScaleAndRound for the algorithm.
   *
   * @param paramsOutput parameters for the output CRT basis {o_1,...,o_k}.
   * @param tOSHatInvModsDivsModo precomputed values for [floor(t*O*[(S/s_k)^{-1}]_{s_k}/s_k)]_{o_j}, S = {I,O}.
   * @param tOSHatInvModsDivsFrac precomputed fractional parts of t*O*[(S/s_k)^{-1}]_{s_k}/s_k.
   * @param modoBarretMu 128-bit Barrett reduction precomputed values for o_j.
   * @return the representation of round(t/I * X) in the basis O.
   */
    DCRTPolyType ScaleAndRound(const std::shared_ptr<Params>& paramsOutput,
                               const std::vector<std::vector<NativeInteger>>& tOSHatInvModsDivsModo,
                               const std::vector<double>& tOSHatInvModsDivsFrac,
                               const std::vector<DoubleNativeInt>& modoBarretMu) const override;

    PolyType ScaleAndRound(const std::vector<NativeInteger>& moduliQ, const NativeInteger& t,
                           const NativeInteger& tgamma, const std::vector<NativeInteger>& tgammaQHatModq,
                           const std::vector<NativeInteger>& tgammaQHatModqPrecon,
                           const std::vector<NativeInteger>& negInvqModtgamma,
                           const std::vector<NativeInteger>& negInvqModtgammaPrecon) const override;

    /**
   * @brief Computes round(X/p) in place for an element in the basis {Q, p} (BFV EXTENDED encryption): the last
   * tower, modulo p, is switched (centered) to each q_i and subtracted, the difference is multiplied by
   * [p^{-1}]_{q_i}, the p tower is dropped and the parameters become paramsQ.
   *
   * @param paramsQ parameters for the CRT basis {q_1,...,q_l}.
   * @param pInvModq precomputed values for [p^{-1}]_{q_i}.
   */
    void ScaleAndRoundPOverQ(const std::shared_ptr<Params>& paramsQ,
                             const std::vector<NativeInteger>& pInvModq) override;

    /**
   * @brief Expands the element from the basis Q to {Q, Bsk, mtilde} in place using the Montgomery-style fast base
   * conversion of the BEHZ BFV variant; see DCRTPolyInterface::FastBaseConvqToBskMontgomery.
   *
   * @param paramsQBsk parameters for the CRT basis {Q, Bsk}.
   * @param moduliQ the moduli {q_1,...,q_l}.
   * @param moduliBsk the moduli {bsk_1,...,bsk_k} of the auxiliary basis.
   * @param modbskBarrettMu 128-bit Barrett reduction precomputed values for bsk_j.
   * @param mtildeQHatInvModq precomputed values for [mtilde*(Q/q_i)^{-1}]_{q_i}.
   * @param mtildeQHatInvModqPrecon NTL-specific precomputations for mtildeQHatInvModq.
   * @param QHatModbsk precomputed values for [Q/q_i]_{bsk_j}.
   * @param QHatModmtilde precomputed values for [Q/q_i]_{mtilde}.
   * @param QModbsk precomputed values for [Q]_{bsk_j}.
   * @param QModbskPrecon NTL-specific precomputations for QModbsk.
   * @param negQInvModmtilde precomputed value for [-Q^{-1}]_{mtilde}.
   * @param mtildeInvModbsk precomputed values for [mtilde^{-1}]_{bsk_j}.
   * @param mtildeInvModbskPrecon NTL-specific precomputations for mtildeInvModbsk.
   */
    void FastBaseConvqToBskMontgomery(
            const std::shared_ptr<Params>& paramsQBsk, const std::vector<NativeInteger>& moduliQ,
            const std::vector<NativeInteger>& moduliBsk, const std::vector<DoubleNativeInt>& modbskBarrettMu,
            const std::vector<NativeInteger>& mtildeQHatInvModq,
            const std::vector<NativeInteger>& mtildeQHatInvModqPrecon,
            const std::vector<std::vector<NativeInteger>>& QHatModbsk, const std::vector<uint64_t>& QHatModmtilde,
            const std::vector<NativeInteger>& QModbsk, const std::vector<NativeInteger>& QModbskPrecon,
            uint64_t negQInvModmtilde, const std::vector<NativeInteger>& mtildeInvModbsk,
            const std::vector<NativeInteger>& mtildeInvModbskPrecon) override;

    void FastRNSFloorq(const NativeInteger& t, const std::vector<NativeInteger>& moduliQ,
                       const std::vector<NativeInteger>& moduliBsk, const std::vector<DoubleNativeInt>& modbskBarrettMu,
                       const std::vector<NativeInteger>& tQHatInvModq,
                       const std::vector<NativeInteger>& tQHatInvModqPrecon,
                       const std::vector<std::vector<NativeInteger>>& QHatModbsk,
                       const std::vector<std::vector<NativeInteger>>& qInvModbsk,
                       const std::vector<NativeInteger>& tQInvModbsk,
                       const std::vector<NativeInteger>& tQInvModbskPrecon) override;

    /**
   * @brief Converts the element from the basis {Q, Bsk} back to Q in place with the Shenoy-Kumaresan method: the Q
   * towers are recomputed from the Bsk towers, which are then dropped; see DCRTPolyInterface::FastBaseConvSK.
   *
   * @param paramsQ parameters for the CRT basis Q.
   * @param modqBarrettMu 128-bit Barrett reduction precomputed values for q_i.
   * @param moduliBsk the moduli {bsk_1,...,bsk_k} of the auxiliary basis.
   * @param modbskBarrettMu 128-bit Barrett reduction precomputed values for bsk_j.
   * @param BHatInvModb precomputed values for [(B/b_j)^{-1}]_{b_j}.
   * @param BHatInvModbPrecon NTL-specific precomputations for BHatInvModb.
   * @param BHatModmsk precomputed values for [B/b_j]_{msk}.
   * @param BInvModmsk precomputed value for [B^{-1}]_{msk}.
   * @param BInvModmskPrecon NTL-specific precomputation for BInvModmsk.
   * @param BHatModq precomputed values for [B/b_j]_{q_i}.
   * @param BModq precomputed values for [B]_{q_i}.
   * @param BModqPrecon NTL-specific precomputations for BModq.
   */
    void FastBaseConvSK(const std::shared_ptr<Params>& paramsQ, const std::vector<DoubleNativeInt>& modqBarrettMu,
                        const std::vector<NativeInteger>& moduliBsk,
                        const std::vector<DoubleNativeInt>& modbskBarrettMu,
                        const std::vector<NativeInteger>& BHatInvModb,
                        const std::vector<NativeInteger>& BHatInvModbPrecon,
                        const std::vector<NativeInteger>& BHatModmsk, const NativeInteger& BInvModmsk,
                        const NativeInteger& BInvModmskPrecon, const std::vector<std::vector<NativeInteger>>& BHatModq,
                        const std::vector<NativeInteger>& BModq,
                        const std::vector<NativeInteger>& BModqPrecon) override;

    void SwitchFormat(uint32_t thread_limit = 0) override;

    /**
   * @brief Switches the tower at index to a new modulus and root of unity (values converted to native integers and
   * switched with centering) and recalculates the composite modulus of the shared parameters.
   *
   * @param index the index of the tower; throws if out of range.
   * @param modulus the new modulus of the tower.
   * @param rootOfUnity the root of unity for the new modulus.
   */
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

    void SetElementAtIndex(uint32_t index, const PolyType& element) {
        m_vectors[index] = element;
    }

    void SetElementAtIndex(uint32_t index, PolyType&& element) {
        m_vectors[index] = std::move(element);
    }

  protected:
    std::shared_ptr<Params> m_params{std::make_shared<DCRTPolyImpl::Params>()};
    Format m_format{Format::EVALUATION};
    std::vector<PolyType> m_vectors;
};

}  // namespace lbcrypto

#endif  // SRC_CORE_INCLUDE_LATTICE_HAL_DEFAULT_DCRTPOLY_H_
