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
  Public key type for lattice crypto operations
 */

#ifndef LBCRYPTO_CRYPTO_KEY_PUBLICKEY_H
#define LBCRYPTO_CRYPTO_KEY_PUBLICKEY_H

#include "key/publickey-fwd.h"
#include "key/key.h"

#include <memory>
#include <vector>
#include <string>
#include <utility>

/**
 * @namespace lbcrypto
 * The namespace of lbcrypto
 */
namespace lbcrypto {

/**
 * @brief Class for public key
 * @tparam Element a ring element.
 */
template <typename Element>
class PublicKeyImpl : public Key<Element> {
public:
    /**
   * Basic constructor
   *
   * @param cc - CryptoContext
   * @param id - key identifier
   */
    explicit PublicKeyImpl(CryptoContext<Element> cc = 0, const std::string& id = "") : Key<Element>(cc, id) {}

    /**
   * Copy constructor
   *
   *@param &rhs PublicKeyImpl to copy from
   */
    explicit PublicKeyImpl(const PublicKeyImpl<Element>& rhs)
        : Key<Element>(rhs.GetCryptoContext(), rhs.GetKeyTag()), m_h(rhs.m_h) {}

    /**
   * Move constructor
   *
   *@param &rhs PublicKeyImpl to move from
   */
    explicit PublicKeyImpl(PublicKeyImpl<Element>&& rhs) noexcept
        : Key<Element>(rhs.GetCryptoContext(), rhs.GetKeyTag()), m_h(std::move(rhs.m_h)) {}

    operator bool() const {
        return static_cast<bool>(this->context) && m_h.size() != 0;
    }

    /**
   * Assignment Operator.
   *
   * @param &rhs PublicKeyImpl to copy from
   */
    PublicKeyImpl<Element>& operator=(const PublicKeyImpl<Element>& rhs) {
        CryptoObject<Element>::operator=(rhs);
        this->m_h = rhs.m_h;
        return *this;
    }

    /**
   * Move Assignment Operator.
   *
   * @param &rhs PublicKeyImpl to copy from
   */
    PublicKeyImpl<Element>& operator=(PublicKeyImpl<Element>&& rhs) {
        CryptoObject<Element>::operator=(rhs);
        m_h = std::move(rhs.m_h);
        return *this;
    }

    // @Get Properties

    /**
   * Gets the computed public key
   * @return the public key element.
   */
    const std::vector<Element>& GetPublicElements() const {
        return this->m_h;
    }

    // @Set Properties

    /**
   * Sets the public key vector of Element.
   * @param &element is the public key Element vector to be copied.
   */
    void SetPublicElements(const std::vector<Element>& element) {
        m_h = element;
    }

    /**
   * Sets the public key vector of Element.
   * @param &&element is the public key Element vector to be moved.
   */
    void SetPublicElements(std::vector<Element>&& element) {
        m_h = std::move(element);
    }

    /**
   * Sets the public key Element at index idx.
   * @param &element is the public key Element to be copied.
   */
    void SetPublicElementAtIndex(usint idx, const Element& element) {
        m_h.insert(m_h.begin() + idx, element);
    }

    /**
   * Sets the public key Element at index idx.
   * @param &&element is the public key Element to be moved.
   */
    void SetPublicElementAtIndex(usint idx, Element&& element) {
        m_h.insert(m_h.begin() + idx, std::move(element));
    }

    bool operator==(const PublicKeyImpl& other) const {
        if (!CryptoObject<Element>::operator==(other)) {
            return false;
        }

        if (m_h.size() != other.m_h.size()) {
            return false;
        }

        for (size_t i = 0; i < m_h.size(); i++) {
            if (m_h[i] != other.m_h[i]) {
                return false;
            }
        }

        return true;
    }

    bool operator!=(const PublicKeyImpl& other) const {
        return !(*this == other);
    }

    template <class Archive>
    void save(Archive& ar, std::uint32_t const version) const {
        ar(::cereal::base_class<Key<Element>>(this));
        ar(::cereal::make_nvp("h", m_h));
    }

    template <class Archive>
    void load(Archive& ar, std::uint32_t const version) {
        if (version > SerializedVersion()) {
            OPENFHE_THROW("serialized object version " + std::to_string(version) +
                          " is from a later version of the library");
        }
        ar(::cereal::base_class<Key<Element>>(this));
        ar(::cereal::make_nvp("h", m_h));
    }

    std::string SerializedObjectName() const {
        return "PublicKey";
    }
    static uint32_t SerializedVersion() {
        return 1;
    }

private:
    std::vector<Element> m_h;
};

}  // namespace lbcrypto

#endif
