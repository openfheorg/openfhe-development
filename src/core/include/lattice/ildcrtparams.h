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

#include "lattice/elemparams.h"
#include "lattice/ilparams.h"

#include "math/math-hal.h"
#include "math/nbtheory-impl.h"

#include "utils/exception.h"
#include "utils/inttypes.h"

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
 * Circuit. In: Safavi-Naini R., Canetti R. (eds) Advances in Cryptology –
 * CRYPTO 2012. Lecture Notes in Computer Science, vol 7417. Springer, Berlin,
 * Heidelberg
 */
template <typename IntType>
class ILDCRTParams final : public ElemParams<IntType> {
public:
    static constexpr usint DEFAULT_NBITS = 20;

    using Integer        = IntType;
    using ILNativeParams = ILParamsImpl<NativeInteger>;

    /**
   * @brief Constructor with basic parameter set.
   * q is selected as FirstPrime(bits, order)
   * @param order the order of the ciphertext.
   * @param depth is the size of the tower.
   * @param bits is the number of bits of each tower's moduli.
   */
    explicit ILDCRTParams(usint order = 0, usint depth = 1, usint bits = DEFAULT_NBITS)
        : ElemParams<IntType>(order, 0), m_params(depth) {
        if (order == 0)
            return;
        if (depth == 0)
            OPENFHE_THROW(config_error, "Invalid depth for ILDCRTParams");
        if (bits == 0 || bits > 64)
            OPENFHE_THROW(config_error, "Invalid bits for ILDCRTParams");
        auto q{FirstPrime<NativeInteger>(bits, order)};
        for (usint j = 0; j < depth; ++j, q = NextPrime<NativeInteger>(q, order))
            m_params[j] = std::make_shared<ILNativeParams>(order, q, RootOfUnity<NativeInteger>(order, q));
        RecalculateModulus();
    }

    /**
   * @brief Constructor with basic parameters
   *
   * @param cyclotomic_order the order of the ciphertext
   * @param &modulus is the modulus for the primary ciphertext.
   * @param rootsOfUnity is unused
   */

    // root of unity unused?
    ILDCRTParams(usint cyclotomic_order, const IntType& modulus, const IntType& rootOfUnity)
        : ElemParams<IntType>(cyclotomic_order, modulus, 0, 0, 0), m_originalModulus(modulus) {
        // NOTE params generation uses this constructor to make an empty params that
        // it will later populate during the gen process. For that special case...
        // we don't populate, and we just return
        if (cyclotomic_order == 0)
            return;
        std::vector<NativeInteger> moduli;
        std::vector<NativeInteger> rootsOfUnity;
        auto q{FirstPrime<NativeInteger>(DEFAULT_NBITS, cyclotomic_order)};
        IntType compositeModulus(1);
        while (true) {
            moduli.push_back(q);
            rootsOfUnity.push_back(RootOfUnity(cyclotomic_order, q));
            m_params.push_back(std::make_shared<ILNativeParams>(cyclotomic_order, q, rootsOfUnity.back()));
            compositeModulus = compositeModulus * IntType(q.ConvertToInt());
            if (compositeModulus >= modulus)
                break;
            q = NextPrime(q, cyclotomic_order);
        }
        RecalculateModulus();
    }

    /**
   * @brief Constructor with some pre-computed parameters provided as input.
   * @param cyclotomic_order the order of the ciphertext
   * @param moduli the list of the smaller moduli of the component polynomials.
   * @param rootsOfUnity the list of the smaller roots of unity of the component
   * polynomials.
   * @param moduliBig the list of the big moduli of the component polynomials
   * (arbitrary cyclotomics).
   * @param rootsOfUnityBig the list of the roots of unity of the component
   * polynomials for big moduli (arbitrary cyclotomics).
   * @return
   */
    ILDCRTParams(usint cyclotomic_order, const std::vector<NativeInteger>& moduli,
                 const std::vector<NativeInteger>& rootsOfUnity, const std::vector<NativeInteger>& moduliBig = {},
                 const std::vector<NativeInteger>& rootsOfUnityBig = {},
                 const IntType& inputOriginalModulus               = IntType(0))
        : ElemParams<IntType>(cyclotomic_order, 0, 0, 0, 0),
          m_originalModulus(inputOriginalModulus),
          m_params(moduli.size()) {
        if (moduli.size() != rootsOfUnity.size())
            OPENFHE_THROW(math_error, "sizes of moduli and roots of unity do not match");
        size_t size{moduli.size()};
        if (moduliBig.size() == size) {
            for (size_t i = 0; i < size; ++i)
                m_params[i] = std::make_shared<ILNativeParams>(cyclotomic_order, moduli[i], rootsOfUnity[i],
                                                               moduliBig[i], rootsOfUnityBig[i]);
        }
        else {
            for (size_t i = 0; i < size; ++i)
                m_params[i] = std::make_shared<ILNativeParams>(cyclotomic_order, moduli[i], rootsOfUnity[i]);
        }
        RecalculateModulus();
    }

    /**
   * @brief Constructor with only cylotomic order and chain of moduli.
   * Multiplied values of the chain of moduli is automatically calculated. Root
   * of unity of the modulus is also calculated.
   *
   * @param cyclotomic_order the order of the ciphertext
   * @param &moduli is the tower of moduli
   */
    ILDCRTParams(usint cyclotomic_order, const std::vector<NativeInteger>& moduli,
                 const IntType& inputOriginalModulus = IntType(0))
        : ElemParams<IntType>(cyclotomic_order, 0, 0, 0, 0),
          m_originalModulus(inputOriginalModulus),
          m_params(moduli.size()) {
        for (size_t i = 0; i < moduli.size(); i++)
            m_params[i] = std::make_shared<ILNativeParams>(cyclotomic_order, moduli[i], 0, 0, 0);
        RecalculateModulus();
    }

    /**
   * @brief Constructor that takes in the cyclotomic order and the component
   * parameters of the component moduli.
   * @param cyclotomic_order the primary cyclotomic order.  This is not checked
   * against the component moduli.
   * @param params the componet parameters.
   * @return
   */
    ILDCRTParams(usint cyclotomic_order, std::vector<std::shared_ptr<ILNativeParams>>& params,
                 const IntType& inputOriginalModulus = IntType(0))
        : ElemParams<IntType>(cyclotomic_order, 0, 0, 0, 0), m_originalModulus(inputOriginalModulus), m_params(params) {
        RecalculateModulus();
    }

    ILDCRTParams(const ILDCRTParams& rhs)
        : ElemParams<IntType>(rhs), m_originalModulus(rhs.m_originalModulus), m_params(rhs.m_params) {}

    ILDCRTParams(ILDCRTParams&& rhs) noexcept
        : ElemParams<IntType>(rhs),
          m_originalModulus(std::move(rhs.m_originalModulus)),
          m_params(std::move(rhs.m_params)) {}

    /**
   * Assignment Operator.
   *
   * @param &rhs the copied ILDCRTParams.
   * @return the resulting ILDCRTParams.
   */
    ILDCRTParams& operator=(const ILDCRTParams& rhs) {
        ElemParams<IntType>::operator=(rhs);
        m_originalModulus = rhs.m_originalModulus;
        m_params          = rhs.m_params;
        return *this;
    }

    ILDCRTParams& operator=(ILDCRTParams&& rhs) noexcept {
        ElemParams<IntType>::operator=(rhs);
        m_originalModulus = std::move(rhs.m_originalModulus);
        m_params          = std::move(rhs.m_params);
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
        if (end < start || end >= m_params.size()) {
            OPENFHE_THROW(math_error, "Incorrect parameters for GetParamPartition - (start: " + std::to_string(start) +
                                          ", end:" + std::to_string(end) + ")");
        }

        std::vector<std::shared_ptr<ILNativeParams>> resParams;
        for (uint32_t i = start; i <= end; ++i)
            resParams.push_back(m_params[i]);
        return resParams;
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
    std::shared_ptr<ILNativeParams>& operator[](usint i) {
        return m_params[i];
    }

    /**
   * @brief Removes the last parameter set and adjust the multiplied moduli.
   *
   */
    void PopLastParam() {
        ElemParams<IntType>::m_ciphertextModulus /= IntType(m_params.back()->GetModulus().ConvertToInt());
        m_params.pop_back();
    }

    /**
   * @brief Removes the first parameter set and adjust the multiplied moduli.
   *
   */
    void PopFirstParam() {
        ElemParams<IntType>::m_ciphertextModulus /= IntType(m_params[0]->GetModulus().ConvertToInt());
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

        if (dcrtParams == nullptr)
            return false;

        if (ElemParams<IntType>::operator==(other) == false)
            return false;

        if (m_params.size() != dcrtParams->m_params.size())
            return false;

        for (size_t i = 0; i < m_params.size(); i++) {
            if (*m_params[i] != *dcrtParams->m_params[i])
                return false;
        }

        //    if (originalModulus != dcrtParams->originalModulus)
        //      return false;

        return true;
    }

    /**
   * @brief Method to recalculate the composite modulus from the component
   * moduli.
   */
    void RecalculateModulus() {
        ElemParams<IntType>::m_ciphertextModulus = 1;
        for (size_t i = 0; i < m_params.size(); i++)
            ElemParams<IntType>::m_ciphertextModulus =
                ElemParams<IntType>::m_ciphertextModulus * IntType(m_params[i]->GetModulus().ConvertToInt());
    }

    /**
   * @brief Method to recalculate the big composite modulus from the component
   * moduli.
   */
    void RecalculateBigModulus() {
        ElemParams<IntType>::m_bigCiphertextModulus = 1;
        for (size_t i = 0; i < m_params.size(); i++)
            ElemParams<IntType>::m_bigCiphertextModulus =
                ElemParams<IntType>::m_bigCiphertextModulus * IntType(m_params[i]->GetBigModulus().ConvertToInt());
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
            OPENFHE_THROW(deserialize_error, "serialized object version " + std::to_string(version) +
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
        out << std::endl << " Params:" << std::endl;
        for (size_t i = 0; i < m_params.size(); i++) {
            out << "   " << i << ":" << *m_params[i] << std::endl;
        }
        out << "OriginalModulus " << m_originalModulus << std::endl;
        return out;
    }

    // original modulus when being constructed from a Poly or when
    // ctor is passed that parameter
    // note orignalModulus will be <= composite modules
    //   i.e. \Prod_i=0^k-1 m_params[i]->GetModulus()
    // note not using ElemParams::ciphertextModulus due to object stripping
    IntType m_originalModulus{};

    // array of smaller ILParams
    std::vector<std::shared_ptr<ILNativeParams>> m_params;
};

}  // namespace lbcrypto

#endif
