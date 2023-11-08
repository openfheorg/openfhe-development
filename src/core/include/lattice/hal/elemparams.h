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
  base class for parameters for a lattice element
 */

#ifndef LBCRYPTO_LATTICE_ELEMPARAMS_H
#define LBCRYPTO_LATTICE_ELEMPARAMS_H

#include "math/math-hal.h"
#include "math/nbtheory.h"

#include "utils/exception.h"
#include "utils/inttypes.h"
#include "utils/serializable.h"

#include <iostream>
#include <string>
#include <utility>

namespace lbcrypto {

/**
 * @class ElemParams
 * @file elemparams.h
 * @brief Wrapper class to hold the parameters for Element types and their
 * inheritors.
 */
template <typename IntegerType>
class ElemParams : public Serializable {
public:
    constexpr ElemParams() = default;
    virtual ~ElemParams()  = default;

    /**
   * @brief Simple constructor method that takes as input root of unity, big
   * root of unity, cyclotomic order and the ciphertext modulus and big
   * ciphertext Modulus.  This is used for bit-packing operations.
   * @param order the cyclotomic order wrapped by the parameter set.
   * @param ctModulus the ciphertext modulus wrapped by the parameter set.
   * @param rUnity the root of unity.
   * @param bigCtModulus the big ciphertext modulus used for bit packing
   * operations.
   * @param bigRUnity the big root of unity used for bit packing operations.
   */

    // TODO: uint32_t version of GetTotient

    ElemParams(uint32_t order, const IntegerType& ctModulus)
        : m_ringDimension(GetTotient(order)), m_cyclotomicOrder(order), m_ciphertextModulus(ctModulus) {}

    ElemParams(uint32_t order, const IntegerType& ctModulus, const IntegerType& rUnity)
        : m_ringDimension(GetTotient(order)),
          m_cyclotomicOrder(order),
          m_ciphertextModulus(ctModulus),
          m_rootOfUnity(rUnity) {}

    ElemParams(uint32_t order, const IntegerType& ctModulus, const IntegerType& rUnity, const IntegerType& bigCtModulus,
               const IntegerType& bigRUnity)
        : m_ringDimension(GetTotient(order)),
          m_cyclotomicOrder(order),
          m_ciphertextModulus(ctModulus),
          m_rootOfUnity(rUnity),
          m_bigCiphertextModulus(bigCtModulus),
          m_bigRootOfUnity(bigRUnity) {}

    /**
   * @brief Copy constructor using assignment to copy wrapped elements.
   * @param rhs the input ElemParams copied.
   * @return the resulting parameter set with parameters copied.
   */
    ElemParams(const ElemParams& rhs)
        : m_ringDimension(rhs.m_ringDimension),
          m_cyclotomicOrder(rhs.m_cyclotomicOrder),
          m_ciphertextModulus(rhs.m_ciphertextModulus),
          m_rootOfUnity(rhs.m_rootOfUnity),
          m_bigCiphertextModulus(rhs.m_bigCiphertextModulus),
          m_bigRootOfUnity(rhs.m_bigRootOfUnity) {}

    /**
   * @brief Copy constructor using move semnantics to copy wrapped elements.
   * @param rhs the input ElemParams copied.
   * @return the resulting copy of the parameter set.
   */
    ElemParams(ElemParams&& rhs) noexcept
        : m_ringDimension(rhs.m_ringDimension),
          m_cyclotomicOrder(rhs.m_cyclotomicOrder),
          m_ciphertextModulus(std::move(rhs.m_ciphertextModulus)),
          m_rootOfUnity(std::move(rhs.m_rootOfUnity)),
          m_bigCiphertextModulus(std::move(rhs.m_bigCiphertextModulus)),
          m_bigRootOfUnity(std::move(rhs.m_bigRootOfUnity)) {}

    /**
   * @brief Assignment operator using assignment operations of wrapped elements.
   * @param rhs the ElemParams instance to copy.
   */
    ElemParams& operator=(const ElemParams& rhs) {
        m_ringDimension        = rhs.m_ringDimension;
        m_cyclotomicOrder      = rhs.m_cyclotomicOrder;
        m_ciphertextModulus    = rhs.m_ciphertextModulus;
        m_rootOfUnity          = rhs.m_rootOfUnity;
        m_bigCiphertextModulus = rhs.m_bigCiphertextModulus;
        m_bigRootOfUnity       = rhs.m_bigRootOfUnity;
        return *this;
    }

    ElemParams& operator=(ElemParams&& rhs) noexcept {
        m_ringDimension        = rhs.m_ringDimension;
        m_cyclotomicOrder      = rhs.m_cyclotomicOrder;
        m_ciphertextModulus    = std::move(rhs.m_ciphertextModulus);
        m_rootOfUnity          = std::move(rhs.m_rootOfUnity);
        m_bigCiphertextModulus = std::move(rhs.m_bigCiphertextModulus);
        m_bigRootOfUnity       = std::move(rhs.m_bigRootOfUnity);
        return *this;
    }

    /**
   * @brief Simple getter method for cyclotomic order.
   * @return The cyclotomic order.
   */
    uint32_t GetCyclotomicOrder() const {
        return m_cyclotomicOrder;
    }

    /**
   * @brief Simple ring dimension getter method.  The ring dimension is the
   * evaluation of the totient function of the cyclotomic order.
   * @return the ring dimension.
   */
    uint32_t GetRingDimension() const {
        return m_ringDimension;
    }

    /**
   * @brief Simple getter method for the ciphertext modulus, not the big
   * ciphertext modulus.
   * @return The ciphertext modulus, not the big ciphertext modulus.
   */
    const IntegerType& GetModulus() const {
        return m_ciphertextModulus;
    }

    /**
   * @brief Simpler getter method for the big ciphertext modulus.
   * This is not relevant for all applications.
   * @return The big ciphertext modulus.
   */
    const IntegerType& GetBigModulus() const {
        return m_bigCiphertextModulus;
    }

    /**
   * @brief Simple getter method for the root of unity, not the big root of
   * unity.
   * @return The root of unity, not the big root of unity.
   */
    const IntegerType& GetRootOfUnity() const {
        return m_rootOfUnity;
    }

    /**
   * @brief Simple getter method for the big root of unity.
   * @return The the big root of unity.
   */
    const IntegerType& GetBigRootOfUnity() const {
        return m_bigRootOfUnity;
    }

    /**
   * @brief Output strem operator.
   * @param out the preceding output stream.
   * @param item what to add to the output stream.
   * @return the appended output stream.
   */
    friend std::ostream& operator<<(std::ostream& out, const ElemParams& item) {
        return item.doprint(out);
    }

    /**
   * @brief Equality operator that tests the equality of all wrapped values.
   * @param other the other ElemenParams to compare to.
   * @return True if all elements are equal, and False otherwise.
   */
    virtual bool operator==(const ElemParams<IntegerType>& other) const {
        return m_ringDimension == other.m_ringDimension && m_cyclotomicOrder == other.m_cyclotomicOrder &&
               m_ciphertextModulus == other.m_ciphertextModulus && m_rootOfUnity == other.m_rootOfUnity &&
               m_bigCiphertextModulus == other.m_bigCiphertextModulus && m_bigRootOfUnity == other.m_bigRootOfUnity;
    }

    /**
   * @brief Inequality operator that tests the equality of all wrapped values.
   * @param other the other ElemenParams to compare to.
   * @return False if all elements are equal, and True otherwise.
   */
    bool operator!=(const ElemParams<IntegerType>& other) const {
        return !(*this == other);
    }

    template <class Archive>
    void save(Archive& ar, std::uint32_t const version) const {
        ar(::cereal::make_nvp("co", m_cyclotomicOrder));
        ar(::cereal::make_nvp("rd", m_ringDimension));
        ar(::cereal::make_nvp("cm", m_ciphertextModulus));
        ar(::cereal::make_nvp("ru", m_rootOfUnity));
        ar(::cereal::make_nvp("bm", m_bigCiphertextModulus));
        ar(::cereal::make_nvp("br", m_bigRootOfUnity));
    }

    template <class Archive>
    void load(Archive& ar, std::uint32_t const version) {
        if (version > SerializedVersion())
            OPENFHE_THROW(deserialize_error, "serialized object version " + std::to_string(version) +
                                                 " is from a later version of the library");
        ar(::cereal::make_nvp("co", m_cyclotomicOrder));
        ar(::cereal::make_nvp("rd", m_ringDimension));
        ar(::cereal::make_nvp("cm", m_ciphertextModulus));
        ar(::cereal::make_nvp("ru", m_rootOfUnity));
        ar(::cereal::make_nvp("bm", m_bigCiphertextModulus));
        ar(::cereal::make_nvp("br", m_bigRootOfUnity));
    }

    std::string SerializedObjectName() const override {
        return "ElemParams";
    }
    static uint32_t SerializedVersion() {
        return 1;
    }

protected:
    uint32_t m_ringDimension{0};
    uint32_t m_cyclotomicOrder{0};
    IntegerType m_ciphertextModulus{0};
    IntegerType m_rootOfUnity{0};
    IntegerType m_bigCiphertextModulus{0};  // Used for only some applications.
    IntegerType m_bigRootOfUnity{0};        // Used for only some applications.

    /**
   * @brief Pretty print operator for the ElemParams type.
   * @param out the ElemParams to output
   * @return the resulting output stream.
   */
    virtual std::ostream& doprint(std::ostream& out) const {
        out << "[m=" << m_cyclotomicOrder << " n=" << m_ringDimension << " q=" << m_ciphertextModulus
            << " ru=" << m_rootOfUnity << " bigq=" << m_bigCiphertextModulus << " bigru=" << m_bigRootOfUnity << "]";
        return out;
    }
};

}  // namespace lbcrypto

#endif
