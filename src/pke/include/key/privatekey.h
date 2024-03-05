//==================================================================================
// BSD 2-Clause License
//
// Copyright (c) 2014-2022, NJIT, Duality Technologies Inc. and other contributors
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
  Private key type for lattice crypto operations
 */

#ifndef LBCRYPTO_CRYPTO_KEY_PRIVATEKEY_H
#define LBCRYPTO_CRYPTO_KEY_PRIVATEKEY_H

#include "key/privatekey-fwd.h"
#include "key/key.h"

#include <iomanip>
#include <memory>
#include <limits>
#include <string>
#include <utility>

/**
 * @namespace lbcrypto
 * The namespace of lbcrypto
 */
namespace lbcrypto {

/**
 * Generates a random 128-bit hash
 */
inline std::string GenerateUniqueKeyID() {
    const size_t intsInID = 128 / (sizeof(uint32_t) * 8);
    std::uniform_int_distribution<uint32_t> distribution(0, std::numeric_limits<uint32_t>::max());
    std::stringstream s;
    s.fill('0');
    s << std::hex;
    for (size_t i = 0; i < intsInID; i++)
        s << std::setw(8) << distribution(PseudoRandomNumberGenerator::GetPRNG());
    return s.str();
}

/**
 * @brief Class for private key
 * @tparam Element a ring element.
 */
template <class Element>
class PrivateKeyImpl : public Key<Element> {
public:
    /**
   * Construct in context
   */
    explicit PrivateKeyImpl(CryptoContext<Element> cc = 0) : Key<Element>(cc, GenerateUniqueKeyID()) {}

    /**
   * Copy constructor
   *@param &rhs the PrivateKeyImpl to copy from
   */
    explicit PrivateKeyImpl(const PrivateKeyImpl<Element>& rhs)
        : Key<Element>(rhs.GetCryptoContext(), rhs.GetKeyTag()) {
        this->m_sk = rhs.m_sk;
    }

    /**
   * Move constructor
   *@param &rhs the PrivateKeyImpl to move from
   */
    explicit PrivateKeyImpl(PrivateKeyImpl<Element>&& rhs) : Key<Element>(rhs.GetCryptoContext(), rhs.GetKeyTag()) {
        this->m_sk = std::move(rhs.m_sk);
    }

    operator bool() const {
        return static_cast<bool>(this->context);
    }

    /**
   * Assignment Operator.
   *
   * @param &rhs PrivateKeyto assign from.
   * @return the resulting PrivateKeyImpl
   */
    const PrivateKeyImpl<Element>& operator=(const PrivateKeyImpl<Element>& rhs) {
        CryptoObject<Element>::operator=(rhs);
        this->m_sk = rhs.m_sk;
        return *this;
    }

    /**
   * Move Assignment Operator.
   *
   * @param &rhs PrivateKeyImpl to assign from.
   * @return the resulting PrivateKeyImpl
   */
    const PrivateKeyImpl<Element>& operator=(PrivateKeyImpl<Element>&& rhs) {
        CryptoObject<Element>::operator=(rhs);
        this->m_sk = std::move(rhs.m_sk);
        return *this;
    }

    /**
   * Implementation of the Get accessor for private element.
   * @return the private element.
   */
    const Element& GetPrivateElement() const {
        return m_sk;
    }

    /**
   * Set accessor for private element.
   * @private &x private element to set to.
   */
    void SetPrivateElement(const Element& x) {
        m_sk = x;
    }

    /**
   * Set accessor for private element.
   * @private &x private element to set to.
   */
    void SetPrivateElement(Element&& x) {
        m_sk = std::move(x);
    }

    bool operator==(const PrivateKeyImpl& other) const {
        return CryptoObject<Element>::operator==(other) && m_sk == other.m_sk;
    }

    bool operator!=(const PrivateKeyImpl& other) const {
        return !(*this == other);
    }

    template <class Archive>
    void save(Archive& ar, std::uint32_t const version) const {
        ar(::cereal::base_class<Key<Element>>(this));
        ar(::cereal::make_nvp("s", m_sk));
    }

    template <class Archive>
    void load(Archive& ar, std::uint32_t const version) {
        if (version > SerializedVersion()) {
            OPENFHE_THROW("serialized object version " + std::to_string(version) +
                          " is from a later version of the library");
        }
        ar(::cereal::base_class<Key<Element>>(this));
        ar(::cereal::make_nvp("s", m_sk));
    }

    std::string SerializedObjectName() const {
        return "PrivateKey";
    }
    static uint32_t SerializedVersion() {
        return 1;
    }

private:
    Element m_sk;
};

}  // namespace lbcrypto

#endif
