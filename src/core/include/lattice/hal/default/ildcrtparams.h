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
  Wraps parameters for integer lattice operations using double-CRT representation. Inherits from ElemParams
 */

#ifndef LBCRYPTO_INC_LATTICE_ILDCRTPARAMS_H
#define LBCRYPTO_INC_LATTICE_ILDCRTPARAMS_H

#include "lattice/hal/elemparams.h"
#include "lattice/hal/default/ilparams.h"

#include "math/hal/basicint.h"
#include "math/math-hal.h"
#include "math/nbtheory-impl.h"

#include "utils/exception.h"
#include "utils/inttypes.h"

#include <iomanip>
#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace lbcrypto {

/**
 * @brief Parameters for array of ideal lattices (used for Double-CRT).
 *
 * The double-CRT representation of polynomials is a common optimization for
 * lattice encryption operations. Basically, it allows large-modulus polynamials
 * to be represented as multiple smaller-modulus polynomials. The double-CRT
 * representations are discussed theoretically here:
 *   - Gentry C., Halevi S., Smart N.P. (2012) Homomorphic Evaluation of the AES
 * Circuit. In: Safavi-Naini R., Canetti R. (eds) Advances in Cryptology -
 * CRYPTO 2012. Lecture Notes in Computer Science, vol 7417. Springer, Berlin,
 * Heidelberg
 */
template <typename IntType>
class ILDCRTParams final : public ElemParams<IntType> {
public:
    using Integer        = IntType;
    using ILNativeParams = ILParamsImpl<NativeInteger>;

    ILDCRTParams(uint32_t corder, const IntType& modulus, const IntType& rootOfUnity = IntType(0))
        : ElemParams<IntType>(corder, modulus), m_originalModulus(modulus) {
        // NOTE params generation uses this constructor to make an empty params that
        // it will later populate during the gen process. For that special case...
        // we don't populate, and we just return
        if (corder == 0)
            return;

        auto q{LastPrime<NativeInteger>(MAX_MODULUS_SIZE, corder)};
        m_params.reserve(32);
        m_params.push_back(std::make_shared<ILNativeParams>(corder, q));

        IntType compositeModulus(1);
        while ((compositeModulus *= IntType(q.template ConvertToInt<BasicInteger>())) < modulus)
            m_params.push_back(std::make_shared<ILNativeParams>(corder, (q = PreviousPrime(q, corder))));
        ElemParams<IntType>::m_ciphertextModulus = compositeModulus;
    }

    /**
   * @brief Constructor with basic parameter set.
   * q is selected as LastPrime(bits, order)
   * @param corder the order of the ciphertext.
   * @param depth is the size of the tower.
   * @param bits is the number of bits of each tower's moduli.
   */
    explicit ILDCRTParams(uint32_t corder = 0, uint32_t depth = 1, uint32_t bits = MAX_MODULUS_SIZE)
        : ElemParams<IntType>(corder, 0) {
        if (corder == 0)
            return;
        if (bits > MAX_MODULUS_SIZE)
            OPENFHE_THROW("Invalid bits for ILDCRTParams");

        auto q{LastPrime<NativeInteger>(bits, corder)};
        m_params.reserve(depth);
        m_params.push_back(std::make_shared<ILNativeParams>(corder, q));

        IntType compositeModulus(q.template ConvertToInt<BasicInteger>());
        for (uint32_t _ = 1; _ < depth; ++_) {
            m_params.push_back(std::make_shared<ILNativeParams>(corder, (q = PreviousPrime(q, corder))));
            compositeModulus *= IntType(q.template ConvertToInt<BasicInteger>());
        }
        ElemParams<IntType>::m_ciphertextModulus = compositeModulus;
    }

    /**
   * @brief Constructor with some pre-computed parameters provided as input.
   * @param corder the order of the ciphertext
   * @param moduli the list of the smaller moduli of the component polynomials.
   * @param rootsOfUnity the list of the smaller roots of unity of the component
   * polynomials.
   * @param moduliBig the list of the big moduli of the component polynomials
   * (arbitrary cyclotomics).
   * @param rootsOfUnityBig the list of the roots of unity of the component
   * polynomials for big moduli (arbitrary cyclotomics).
   * @return
   */
    ILDCRTParams(uint32_t corder, const std::vector<NativeInteger>& moduli,
                 const std::vector<NativeInteger>& rootsOfUnity)
        : ElemParams<IntType>(corder, 0) {
        size_t limbs{moduli.size()};
        if (limbs != rootsOfUnity.size())
            OPENFHE_THROW("sizes of moduli and roots of unity do not match 1");

        m_params.reserve(limbs);
        IntType compositeModulus(1);
        for (size_t i = 0; i < limbs; ++i) {
            m_params.push_back(std::make_shared<ILNativeParams>(corder, moduli[i], rootsOfUnity[i]));
            compositeModulus *= IntType(moduli[i].template ConvertToInt<BasicInteger>());
        }
        ElemParams<IntType>::m_ciphertextModulus = compositeModulus;
    }

    ILDCRTParams(uint32_t corder, const std::vector<NativeInteger>& moduli,
                 const std::vector<NativeInteger>& rootsOfUnity, const std::vector<NativeInteger>& moduliBig,
                 const std::vector<NativeInteger>& rootsOfUnityBig, const IntType& inputOriginalModulus = IntType(0))
        : ElemParams<IntType>(corder, 0), m_originalModulus(inputOriginalModulus) {
        size_t limbs{moduli.size()};
        if (limbs != rootsOfUnity.size() || limbs != moduliBig.size() || limbs != rootsOfUnityBig.size())
            OPENFHE_THROW("sizes of moduli and roots of unity do not match 2");

        m_params.reserve(limbs);
        IntType compositeModulus(1);
        for (size_t i = 0; i < limbs; ++i) {
            m_params.push_back(
                std::make_shared<ILNativeParams>(corder, moduli[i], rootsOfUnity[i], moduliBig[i], rootsOfUnityBig[i]));
            compositeModulus *= IntType(moduli[i].template ConvertToInt<BasicInteger>());
        }
        ElemParams<IntType>::m_ciphertextModulus = compositeModulus;
    }

    /**
   * @brief Constructor with only cylotomic order and chain of moduli.
   * Multiplied values of the chain of moduli is automatically calculated. Root
   * of unity of the modulus is also calculated.
   *
   * @param corder the order of the ciphertext
   * @param &moduli is the tower of moduli
   */
    ILDCRTParams(uint32_t corder, const std::vector<NativeInteger>& moduli,
                 const IntType& inputOriginalModulus = IntType(0))
        : ElemParams<IntType>(corder, 0), m_originalModulus(inputOriginalModulus) {
        size_t limbs{moduli.size()};
        m_params.reserve(limbs);
        IntType compositeModulus(1);
        for (size_t i = 0; i < limbs; ++i) {
            m_params.push_back(std::make_shared<ILNativeParams>(corder, moduli[i]));
            compositeModulus *= IntType(moduli[i].template ConvertToInt<BasicInteger>());
        }
        ElemParams<IntType>::m_ciphertextModulus = compositeModulus;
    }

    /**
   * @brief Constructor that takes in the cyclotomic order and the component
   * parameters of the component moduli.
   * @param corder the primary cyclotomic order.  This is not checked
   * against the component moduli.
   * @param params the componet parameters.
   * @return
   */
    ILDCRTParams(uint32_t corder, const std::vector<std::shared_ptr<ILNativeParams>>& params,
                 const IntType& inputOriginalModulus = IntType(0))
        : ElemParams<IntType>(corder, 0), m_params(params), m_originalModulus(inputOriginalModulus) {
        RecalculateModulus();
    }

    ILDCRTParams(const ILDCRTParams& rhs)
        : ElemParams<IntType>(rhs), m_params(rhs.m_params), m_originalModulus(rhs.m_originalModulus) {}

    ILDCRTParams(ILDCRTParams&& rhs) noexcept
        : ElemParams<IntType>(rhs),
          m_params(std::move(rhs.m_params)),
          m_originalModulus(std::move(rhs.m_originalModulus)) {}

    /**
   * Assignment Operator.
   *
   * @param &rhs the copied ILDCRTParams.
   * @return the resulting ILDCRTParams.
   */
    ILDCRTParams& operator=(const ILDCRTParams& rhs) {
        ElemParams<IntType>::operator=(rhs);
        m_params          = rhs.m_params;
        m_originalModulus = rhs.m_originalModulus;
        return *this;
    }

    ILDCRTParams& operator=(ILDCRTParams&& rhs) noexcept {
        ElemParams<IntType>::operator=(rhs);
        m_params          = std::move(rhs.m_params);
        m_originalModulus = std::move(rhs.m_originalModulus);
        return *this;
    }

    // ACCESSORS
    /**
   * @brief Getter method for the component parameters.
   * @return A vector of the component polynomial parameters.
   */
    const std::vector<std::shared_ptr<ILNativeParams>>& GetParams() const {
        return m_params;
    }

    /**
   * @brief Getter method that returns a subset of the component parameters.
   *
   * @param start The index of the first tower to include in the result.
   * @param end The index of the last tower to include.
   * @return A vector of the component polynomial parameters.
   */
    std::vector<std::shared_ptr<ILNativeParams>> GetParamPartition(uint32_t start, uint32_t end) const {
        if (end < start || end > m_params.size())
            OPENFHE_THROW("Incorrect parameters for GetParamPartition - (start: " + std::to_string(start) +
                          ", end:" + std::to_string(end) + ")");
        return std::vector<std::shared_ptr<ILNativeParams>>(m_params.begin() + start, m_params.begin() + end + 1);
    }

    /**
   * @brief Simple getter method for the original modulus, not the ciphertex
   * modulus.
   * @return The original  modulus, not the big ciphertext modulus.
   */
    const IntType& GetOriginalModulus() const {
        return m_originalModulus;
    }
    /**
   * @brief Simple setter method for the original modulus, not the ciphertex
   * modulus.
   * @return void
   */
    void SetOriginalModulus(const IntType& inputOriginalModulus) {
        m_originalModulus = inputOriginalModulus;
    }
    /**
   * @brief Getter method for the component parameters of a specific index.
   * @param i the index of the parameters to return.  Note this this call is
   * unguarded if the index is out of bounds.
   * @return the parameters at index i.
   */
    std::shared_ptr<ILNativeParams>& operator[](size_t i) {
        return m_params[i];
    }
    const std::shared_ptr<ILNativeParams>& operator[](size_t i) const {
        return m_params[i];
    }

    /**
   * @brief Removes the last parameter set and adjust the multiplied moduli.
   *
   */

    void PopLastParam() {
        ElemParams<IntType>::m_ciphertextModulus /=
            IntType(m_params.back()->GetModulus().template ConvertToInt<BasicInteger>());
        m_params.pop_back();
    }

    /**
   * @brief Removes the first parameter set and adjust the multiplied moduli.
   *
   */
    void PopFirstParam() {
        ElemParams<IntType>::m_ciphertextModulus /=
            IntType(m_params[0]->GetModulus().template ConvertToInt<BasicInteger>());
        m_params.erase(m_params.begin());
    }

    /**
   * Destructor.
   */
    ~ILDCRTParams() override = default;

    /**
   * @brief Equality operator checks if the ElemParams are the same.
   *
   * @param &other ElemParams to compare against.
   * @return the equality check results.
   */
    bool operator==(const ElemParams<IntType>& other) const override {
        const auto* dcrtParams = dynamic_cast<const ILDCRTParams*>(&other);
        if (!dcrtParams)
            return false;
        if (ElemParams<IntType>::operator==(other) == false)
            return false;
        if (m_params.size() != dcrtParams->m_params.size())
            return false;
        for (size_t i = 0; i < m_params.size(); ++i) {
            if (*m_params[i] != *dcrtParams->m_params[i])
                return false;
        }
        return (m_originalModulus == dcrtParams->GetOriginalModulus());
    }

    /**
   * @brief Method to recalculate the composite modulus from the component
   * moduli.
   */
    void RecalculateModulus() {
        ElemParams<IntType>::m_ciphertextModulus = 1;
        for (size_t i = 0; i < m_params.size(); ++i)
            ElemParams<IntType>::m_ciphertextModulus *=
                IntType(m_params[i]->GetModulus().template ConvertToInt<BasicInteger>());
    }

    /**
   * @brief Method to recalculate the big composite modulus from the component
   * moduli.
   */
    void RecalculateBigModulus() {
        ElemParams<IntType>::m_bigCiphertextModulus = 1;
        for (size_t i = 0; i < m_params.size(); ++i)
            ElemParams<IntType>::m_bigCiphertextModulus *=
                IntType(m_params[i]->GetBigModulus().template ConvertToInt<BasicInteger>());
    }

    template <class Archive>
    void save(Archive& ar, std::uint32_t const version) const {
        ar(::cereal::base_class<ElemParams<IntType>>(this));
        ar(::cereal::make_nvp("p", m_params));
        ar(::cereal::make_nvp("m", m_originalModulus));
    }

    template <class Archive>
    void load(Archive& ar, std::uint32_t const version) {
        if (version > SerializedVersion()) {
            OPENFHE_THROW("serialized object version " + std::to_string(version) +
                          " is from a later version of the library");
        }
        ar(::cereal::base_class<ElemParams<IntType>>(this));
        ar(::cereal::make_nvp("p", m_params));
        ar(::cereal::make_nvp("m", m_originalModulus));
    }

    std::string SerializedObjectName() const override {
        return "DCRTParams";
    }
    static uint32_t SerializedVersion() {
        return 1;
    }

private:
    std::ostream& doprint(std::ostream& out) const override {
        out << "ILDCRTParams ";
        ElemParams<IntType>::doprint(out);
        out << std::endl << "  m_params:" << std::endl;
        for (size_t i = 0; i < m_params.size(); ++i)
            out << "    " << i << ": " << *m_params[i];
        return out << "  m_originalModulus: " << m_originalModulus << std::endl;
    }

    // array of smaller ILParams
    std::vector<std::shared_ptr<ILNativeParams>> m_params;

    // original modulus when being constructed from a Poly or when
    // ctor is passed that parameter
    // note orignalModulus will be <= composite modules
    //   i.e. \Prod_i=0^k-1 m_params[i]->GetModulus()
    // note not using ElemParams::ciphertextModulus due to object stripping
    IntType m_originalModulus;
};

}  // namespace lbcrypto

#endif
